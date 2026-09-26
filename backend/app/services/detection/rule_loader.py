"""Detection rule file loader — Step 26.

Loads the repository rule set (Sigma YAML + YARA source) from disk into
:class:`DetectionRule` definitions that the existing
:class:`~app.services.detection.registry.DetectionRuleRegistry` registers
verbatim.

This is **not** a second rule-loading mechanism and it does **not**
modify the registry or the detection engines:

* Rules are read as static files and converted exactly into the existing
  Step 9A ``DetectionRule`` schema (the same object type the engines and
  the registry already consume).
* The registry still owns duplicate-ID rejection, listing, and
  enable/disable semantics through its existing ``register`` API.
* The engines are untouched; the loader only constructs the rule
  definitions they evaluate.

Design principles:

* **Deterministic** — for a given repository checkout the loader always
  produces the same rule set, in file-order within each engine dir, with
  no network access, no randomness, and no secrets.
* **Fail loud on malformed rules** — a genuine repository rule that does
  not parse is an authoring error and becomes an explicit exception
  (never a silently skipped rule).
* **Follows the existing architecture** — Sigma ``content`` is passed as
  the parsed dict (the engine parses it via ``SigmaCollection.from_dicts``
  exactly like the test fixtures), and YARA ``content`` is the raw source
  string the YARA engine compiles with ``yara.compile(source=...)``.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from app.schemas.detection import (
    DetectionMetadata,
    DetectionRule,
    DetectionSeverity,
    RuleType,
)
from app.services.detection.registry import DetectionRuleRegistry

#: Gradient of the shipped rule set on disk.
DEFAULT_RULES_DIR = Path(__file__).resolve().parent / "rules"

#: YAML statuses that mark a rule as disabled at load time.
_DISABLED_STATUSES = frozenset({"deprecated"})

#: Severity key -> contract enum.  Unknown keys fall back to MEDIUM
#: deterministically rather than raising on a well-formed but exotic rule.
_SEVERITY_MAP = {
    "low": DetectionSeverity.LOW,
    "medium": DetectionSeverity.MEDIUM,
    "high": DetectionSeverity.HIGH,
    "critical": DetectionSeverity.CRITICAL,
}

#: YARA rule-name extraction: ``rule Sentinel_Name {``
_YARA_RULE_NAME_RE = re.compile(
    r"^\s*rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{",
    re.MULTILINE,
)
#: YARA meta entries ``key = "value"`` (bounded, non-secret string values).
_YARA_META_RE = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\"([^\"]*)\"",
    re.MULTILINE,
)


def _resolve_severity(value: object) -> DetectionSeverity:
    if isinstance(value, str):
        return _SEVERITY_MAP.get(value.strip().lower(), DetectionSeverity.MEDIUM)
    return DetectionSeverity.MEDIUM


def _rule_metadata(extra: dict) -> DetectionMetadata:
    """Build the rule's DetectionMetadata with the loader-only extras.

    Extra fields carry author/date/status/category/source provenance for
    the management UI.  YAML timestamps are coerced to ISO strings so the
    metadata stays JSON-compatible; everything is secret-free by
    construction (it comes from the repository rule files).
    """
    import datetime as _dt

    json_safe: dict = {}
    for key, value in extra.items():
        if isinstance(value, (_dt.date, _dt.datetime)):
            json_safe[key] = value.isoformat()
        elif value is not None and not isinstance(value, (str, int, float, bool)):
            json_safe[key] = str(value)
        else:
            json_safe[key] = value
    return DetectionMetadata(extra=json_safe)


# ---------------------------------------------------------------------------
# Sigma loading
# ---------------------------------------------------------------------------


def load_sigma_rules(rule_dir: Path | None = None) -> list[DetectionRule]:
    """Load every Sigma YAML rule under *rule_dir* as a DetectionRule.

    Each ``.yml``/``.yaml`` file holds one Sigma rule.  ``rule_id`` is the
    Sigma ``id`` (a unique UUID), and ``content`` is the parsed mapping —
    the exact form ``SigmaCollection.from_dicts`` consumes in the engine.
    """
    sigma_dir = Path(rule_dir) if rule_dir is not None else (
        DEFAULT_RULES_DIR / "sigma"
    )
    if not sigma_dir.is_dir():
        return []

    rules: list[DetectionRule] = []
    for path in sorted(sigma_dir.glob("*.*")):
        if path.suffix.lower() not in {".yml", ".yaml"}:
            continue
        with path.open("r", encoding="utf-8") as handle:
            raw = yaml.safe_load(handle.read())
        if not isinstance(raw, dict):
            raise ValueError(f"Sigma rule {path.name} is not a mapping")
        content = dict(raw)

        logsource = content.get("logsource") or {}
        category = logsource.get("category")
        if not isinstance(category, str) or not category:
            category = None

        rule_id = content.get("id")
        if not isinstance(rule_id, str) or not rule_id:
            raise ValueError(f"Sigma rule {path.name} has no id")

        rules.append(
            DetectionRule(
                rule_id=rule_id,
                name=str(content.get("title") or path.stem),
                description=str(
                    content.get("description") or content.get("title") or path.stem
                ),
                rule_type=RuleType.SIGMA,
                severity=_resolve_severity(content.get("level")),
                enabled=str(content.get("status") or "stable")
                not in _DISABLED_STATUSES,
                version=str(content.get("version") or "1.0.0"),
                metadata=_rule_metadata(
                    {
                        "source_file": str(path.relative_to(sigma_dir)),
                        "author": content.get("author"),
                        "date": content.get("date"),
                        "status": content.get("status") or "stable",
                        "category": category,
                    }
                ),
                content=content,
            )
        )
    return rules


# ---------------------------------------------------------------------------
# YARA loading
# ---------------------------------------------------------------------------


def load_yara_rules(rule_dir: Path | None = None) -> list[DetectionRule]:
    """Load every YARA ``.yar`` rule under *rule_dir* as a DetectionRule.

    One rule per file.  ``rule_id`` comes from the rule ``meta.id`` when
    present (else ``yara-<rule name>``), and ``content`` is the verbatim
    source string the YARA engine compiles.  Meta values are reported
    through ``DetectionMetadata.extra`` for the management UI.
    """
    yara_dir = Path(rule_dir) if rule_dir is not None else (
        DEFAULT_RULES_DIR / "yara"
    )
    if not yara_dir.is_dir():
        return []

    rules: list[DetectionRule] = []
    for path in sorted(yara_dir.glob("*.*")):
        if path.suffix.lower() not in {".yar", ".yara"}:
            continue
        source = path.read_text(encoding="utf-8")

        name_match = _YARA_RULE_NAME_RE.search(source)
        rule_name = name_match.group(1) if name_match else path.stem

        meta: dict[str, str] = {}
        for match in _YARA_META_RE.finditer(source):
            key = match.group(1)
            if key not in meta:
                meta[key] = match.group(2)

        meta_id = meta.get("id")
        if not meta_id:
            meta_id = f"yara-{rule_name}"
        severity = _resolve_severity(meta.get("severity"))

        rules.append(
            DetectionRule(
                rule_id=meta_id,
                name=meta.get("title") or rule_name,
                description=meta.get("description") or meta.get("title") or rule_name,
                rule_type=RuleType.YARA,
                severity=severity,
                enabled=meta.get("status", "stable") not in _DISABLED_STATUSES,
                version="1.0.0",
                metadata=_rule_metadata(
                    {
                        "source_file": str(path.relative_to(yara_dir)),
                        "author": meta.get("author"),
                        "date": meta.get("date"),
                        "status": meta.get("status") or "stable",
                        "category": "file",
                        "yara_rule_name": rule_name,
                    }
                ),
                content=source,
            )
        )
    return rules


# ---------------------------------------------------------------------------
# Combined loading
# ---------------------------------------------------------------------------


def load_detection_rules(
    sigma_dir: Path | None = None,
    yara_dir: Path | None = None,
) -> list[DetectionRule]:
    """Load the entire repository rule set (Sigma + YARA)."""
    return load_sigma_rules(sigma_dir) + load_yara_rules(yara_dir)


def build_registry(
    sigma_dir: Path | None = None,
    yara_dir: Path | None = None,
) -> DetectionRuleRegistry:
    """Build a :class:`DetectionRuleRegistry` from the repository rule set.

    Reuses the existing registry ``register`` path, so duplicate rule IDs
    across or within rule types raise ``DuplicateDetectionRuleError`` just
    like any other registration.
    """
    registry = DetectionRuleRegistry()
    for rule in load_detection_rules(sigma_dir, yara_dir):
        registry.register(rule)
    return registry