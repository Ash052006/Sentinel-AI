"""Detection-as-Code fixture + manifest generator (V2.17).

Regenerates the controlled per-rule fixture files and the deterministic
``manifest.yaml`` for the shipped rule repository from the single fixture
source of truth (``app/services/detection/batch1_content.py``).

The generated artifacts are **committed** alongside the rule sources so the
validation pipeline, the onboarding baseline and the quality report all run
against the same deterministic inventory.  Re-running is idempotent: the
output is byte-deterministic for a given checkout.

Behaviour:
* every shipped rule must be covered by batch1 fixtures (positive + negative)
  or the script fails loud — an uncovered rule can never be validated;
* rule sources are read for metadata exactly like the rule loader does
  (parsed dict for Sigma, raw source for YARA), so the manifest matches the
  runtime registry's rule ids/severities/statuses;
* the manifest is validated against the closed contract
  (``RuleSourceManifest``) before anything is written.

Usage:
    python scripts/detection_as_code_generate_fixtures_manifest.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.schemas.detection_as_code import (
    INITIAL_VERSION,
    RuleSourceManifest,
)
from app.services.detection.batch1_content import (
    SIGMA_BATCH1_CATEGORY,
    SIGMA_POSITIVES,
    YARA_BENIGN_BYTES,
    YARA_POSITIVES,
    benign_event,
    positive_sigma_event,
)
from app.services.detection.rule_loader import (
    DEFAULT_RULES_DIR,
    load_detection_rules,
)
from app.services.detection_as_code.fixtures import (
    default_fixture_refs,
    dump_sigma_event,
    write_sigma_fixture,
    write_yara_fixture,
)
from app.services.detection_as_code.hashing import sha256_file
from app.services.detection_as_code.manifest import (
    build_entry,
    dumps_manifest,
    find_orphan_sources,
    write_manifest,
)

_YARA_META_RE = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\"([^\"]*)\"",
    re.MULTILINE,
)


def _yara_tags(content: str) -> list[str]:
    meta: dict[str, str] = {}
    for match in _YARA_META_RE.finditer(content):
        if match.group(1) not in meta:
            meta[match.group(1)] = match.group(2)
    raw = meta.get("tags") or ""
    return [tag.strip() for tag in raw.split(",") if tag.strip()]


def generate(rules_root: Path) -> Path:
    rules = load_detection_rules(
        rules_root / "sigma", rules_root / "yara"
    )
    if not rules:
        raise SystemExit(f"no rules found under {rules_root}")

    entries = []
    for rule in sorted(rules, key=lambda r: r.rule_id):
        extra = rule.metadata.extra or {}
        source_file = extra.get("source_file") or ""
        rel_source = f"{rule.rule_type.value}/{source_file}"
        source_path = rules_root / rel_source
        if not source_path.is_file():
            raise SystemExit(f"source not readable: {source_path}")

        positive_ref, negative_ref = default_fixture_refs(
            rule.rule_id, rule.rule_type.value
        )

        if rule.rule_type.value == "sigma":
            if rule.rule_id not in SIGMA_POSITIVES or rule.rule_id not in SIGMA_BATCH1_CATEGORY:
                raise SystemExit(
                    f"sigma rule {rule.rule_id} has no batch1 fixtures"
                )
            write_sigma_fixture(
                rules_root, rule.rule_id, "positive.json",
                dump_sigma_event(positive_sigma_event(rule.rule_id)),
            )
            write_sigma_fixture(
                rules_root, rule.rule_id, "negative.json",
                dump_sigma_event(benign_event(rule.rule_id)),
            )
            tags = list((rule.content or {}).get("tags") or [])
        else:
            if rule.rule_id not in YARA_POSITIVES:
                raise SystemExit(
                    f"yara rule {rule.rule_id} has no batch1 fixtures"
                )
            write_yara_fixture(
                rules_root, rule.rule_id, "positive.bin",
                YARA_POSITIVES[rule.rule_id],
            )
            write_yara_fixture(
                rules_root, rule.rule_id, "negative.bin",
                YARA_BENIGN_BYTES,
            )
            tags = _yara_tags(rule.content or "")

        entries.append(
            build_entry(
                rule_id=rule.rule_id,
                rule_type=rule.rule_type.value,
                version=INITIAL_VERSION,
                severity=rule.severity.value,
                source=rel_source,
                source_hash=sha256_file(source_path),
                positive_fixture=positive_ref,
                negative_fixture=negative_ref,
                tags=tags,
                status=extra.get("status"),
            )
        )

    manifest = RuleSourceManifest(rules=entries)
    manifest_path = write_manifest(rules_root, manifest)

    orphans = find_orphan_sources(rules_root, manifest)
    if orphans:
        raise SystemExit(f"orphan rule sources detected: {orphans}")

    print(
        f"wrote fixtures + manifest with {len(entries)} governed rules "
        f"to {manifest_path}"
    )
    stat = {"sigma": 0, "yara": 0}
    for entry in entries:
        stat[entry.rule_type.value] += 1
    print(f"inventory: sigma={stat['sigma']} yara={stat['yara']}")
    return manifest_path


if __name__ == "__main__":
    root = Path(
        sys.argv[1] if len(sys.argv) > 1 else DEFAULT_RULES_DIR
    ).resolve()
    generate(root)