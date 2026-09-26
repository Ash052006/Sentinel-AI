"""Shared helpers for detection-as-code governance tests (V2.17).

Builds a temporary governed rules root cloned from the shipped inventory
plus one synthetic YARA rule (``<prefix>-<uuid8>-beacon``), never touching
``DEFAULT_RULES_DIR``.  Cleans up the governed DB rows (FK-ordered) that the
lifecycle writes.
"""

import shutil
import uuid
from pathlib import Path

from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.models.detection_rule_change import DetectionRuleChangeRow
from app.models.detection_rule_release import DetectionRuleReleaseRow
from app.models.detection_rule_version import DetectionRuleVersionRow
from app.schemas.detection import RuleType
from app.schemas.detection_as_code import INITIAL_VERSION, RuleSourceManifest
from app.services.detection.rule_loader import DEFAULT_RULES_DIR
from app.services.detection_as_code.fixtures import (
    default_fixture_refs,
    write_yara_fixture,
)
from app.services.detection_as_code.hashing import sha256_file
from app.services.detection_as_code.manifest import (
    build_entry,
    load_manifest,
    write_manifest,
)

MARKER = b"SENTINEL_DAC_TEST_BEACON"


def yara_v1(rule_id: str) -> str:
    return f"""\
rule Sentry_DAC_Test_{rule_id.replace('-', '_')[:24]}
{{
    meta:
        id = "{rule_id}"
        title = "DAC Test Beacon Marker"
        description = "Detects the synthetic DAC test beacon marker string in artifact content."
        author = "SentinelAI Detection Team"
        date = "2026-09-23"
        severity = "critical"
        tags = "dac synthetic"
    strings:
        $beacon = "SENTINEL_DAC_TEST_BEACON"
    condition:
        $beacon
}}
"""


def positive_v1() -> bytes:
    return b"MZ\x90\x00\x03\x00\x00\x00" + MARKER + b"|dac-test-positive"


def negative_v1() -> bytes:
    return b"benign artifact without any marker payload inside"


def make_governed_root(
    tmp_path: Path,
    rule_id: str,
    *,
    source_content: str | None = None,
    positive: bytes | None = None,
    negative: bytes | None = None,
) -> tuple[Path, RuleSourceManifest]:
    """Clone the shipped root and add a synthetic YARA rule + fixtures."""
    root = tmp_path / "rules"
    shutil.copytree(
        DEFAULT_RULES_DIR,
        root,
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns("*__pycache__*"),
    )
    source = root / "yara" / "dac_test_beacon.yar"
    source.write_text(source_content or yara_v1(rule_id), encoding="utf-8")
    positive_ref, negative_ref = default_fixture_refs(rule_id, "yara")
    write_yara_fixture(
        root, rule_id, "positive.bin", positive if positive is not None else positive_v1()
    )
    write_yara_fixture(
        root, rule_id, "negative.bin", negative if negative is not None else negative_v1()
    )
    manifest = load_manifest(root)
    manifest.rules = [entry for entry in manifest.rules if entry.rule_id != rule_id]
    manifest.rules.append(
        build_entry(
            rule_id=rule_id,
            rule_type=RuleType.YARA.value,
            version=INITIAL_VERSION,
            severity="critical",
            source=f"yara/dac_test_beacon.yar",
            source_hash=sha256_file(source),
            positive_fixture=positive_ref,
            negative_fixture=negative_ref,
            tags=["dac", "synthetic", "test"],
            status="stable",
        )
    )
    write_manifest(root, manifest)
    return root, manifest


def unique_rule_id(prefix: str = "yara-dac-test") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def cleanup_rule(db: Session, rule_id: str) -> None:
    """Delete the governed rows for *rule_id* (FK-ordered)."""
    db.execute(delete(DetectionRuleChangeRow).where(DetectionRuleChangeRow.rule_id == rule_id))
    db.execute(delete(DetectionRuleReleaseRow).where(DetectionRuleReleaseRow.rule_id == rule_id))
    db.execute(delete(DetectionRuleVersionRow).where(DetectionRuleVersionRow.rule_id == rule_id))
    db.commit()