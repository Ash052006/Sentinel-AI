"""Detection Content Expansion — Batch 1 quality tests (additive.

Verifies the 40 new repository rules (20 Sigma + 20 YARA) added in the
Detection Content Expansion Batch 1:

* counts: 28 Sigma / 25 YARA / 53 total, unique rule ids, unique YARA rule
  names, no disabled rules;
* every new Sigma rule loads, is metadata-complete, compiles through the
  Sigma engine, fires on its intended positive synthetic event, and stays
  silent on a benign event of the same category;
* every new YARA rule compiles through ``yara.compile``, fires on its
  intended positive synthetic bytes, and stays silent on benign bytes.

Pure unit tests — no database, no network, no LLM.
"""

from __future__ import annotations

import pytest

from app.schemas.detection import DetectionSeverity, RuleType
from app.services.detection.batch1_content import (
    SIGMA_BATCH1_IDS,
    SIGMA_POSITIVES,
    YARA_BATCH1_IDS,
    YARA_BENIGN_BYTES,
    YARA_POSITIVES,
    benign_event,
    positive_sigma_event,
)
from app.services.detection.rule_loader import (
    load_detection_rules,
    load_sigma_rules,
    load_yara_rules,
)
from app.services.detection.sigma.engine import SigmaDetectionEngine
from app.services.detection.yara.engine import YaraDetectionEngine
from app.services.detection.yara.target_adapter import YaraTarget

_VALID_SEVERITIES = {
    DetectionSeverity.LOW,
    DetectionSeverity.MEDIUM,
    DetectionSeverity.HIGH,
    DetectionSeverity.CRITICAL,
}


def _sigma_by_id() -> dict[str, object]:
    return {r.rule_id: r for r in load_sigma_rules()}


def _yara_by_id() -> dict[str, object]:
    return {r.rule_id: r for r in load_yara_rules()}


# ---------------------------------------------------------------------------
# Counts + uniqueness (deterministic rule-set validation)
# ---------------------------------------------------------------------------


def test_batch1_expanded_rule_counts() -> None:
    """The expanded shipped set is 28 Sigma + 25 YARA = 53 unique rules."""
    rules = load_detection_rules()
    assert len(rules) == 53
    sigma = [r for r in rules if r.rule_type is RuleType.SIGMA]
    yara = [r for r in rules if r.rule_type is RuleType.YARA]
    assert len(sigma) == 28
    assert len(yara) == 25
    ids = [r.rule_id for r in rules]
    assert len(ids) == len(set(ids))


def test_batch1_ids_are_all_present() -> None:
    by_id = _sigma_by_id()
    assert set(SIGMA_BATCH1_IDS) == set(by_id) - {
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
        "33333333-3333-4333-8333-333333333333",
        "44444444-4444-4444-8444-444444444444",
        "55555555-5555-4555-8555-555555555555",
        "66666666-6666-4666-8666-666666666666",
        "77777777-7777-4777-8777-777777777777",
        "88888888-8888-4888-8888-888888888888",
    }
    yara_ids = set(_yara_by_id()) - {
        "yara-suspicious-script-v1",
        "yara-web-shell-v1",
        "yara-credential-stealing-v1",
        "yara-powershell-artifact-v1",
        "yara-ransomware-marker-v1",
    }
    assert set(YARA_BATCH1_IDS) == yara_ids


def test_batch1_new_rules_are_enabled_and_well_formed() -> None:
    sigma = _sigma_by_id()
    yara = _yara_by_id()
    for rule_id in SIGMA_BATCH1_IDS:
        rule = sigma[rule_id]
        assert rule.enabled is True
        assert rule.severity in _VALID_SEVERITIES
        assert rule.name.strip()
        assert rule.description.strip()
        assert rule.version.strip()
        assert isinstance(rule.content, dict) and rule.content.get("id") == rule_id
        assert rule.metadata.extra.get("category") is not None
    for rule_id in YARA_BATCH1_IDS:
        rule = yara[rule_id]
        assert rule.enabled is True
        assert rule.severity in _VALID_SEVERITIES
        assert rule.name.strip()
        assert rule.description.strip()
        assert rule.version.strip()
        assert isinstance(rule.content, str) and rule.content.strip().startswith("rule ")


# ---------------------------------------------------------------------------
# Sigma: positive + negative engine evaluation
# ---------------------------------------------------------------------------


def test_batch1_sigma_rules_fire_on_intended_positive_events() -> None:
    by_id = _sigma_by_id()
    engine = SigmaDetectionEngine()
    for rule_id in SIGMA_BATCH1_IDS:
        event = positive_sigma_event(rule_id)
        report = engine.evaluate(event, rules=[by_id[rule_id]])
        assert not report.failures, f"{rule_id} failed to evaluate cleanly"
        assert report.results and report.results[0].rule_id == rule_id, (
            f"{rule_id} did not fire on its intended positive event"
        )


def test_batch1_sigma_rules_ignore_benign_events() -> None:
    by_id = _sigma_by_id()
    engine = SigmaDetectionEngine()
    for rule_id in SIGMA_BATCH1_IDS:
        event = benign_event(rule_id)
        report = engine.evaluate(event, rules=[by_id[rule_id]])
        assert not report.results, f"{rule_id} fired on its benign event"
        assert not report.failures, f"{rule_id} failed on its benign event"


def test_batch1_positive_events_do_not_fail_the_full_sigma_set() -> None:
    """Every Batch-1 positive event evaluates without a single failure."""
    by_id = _sigma_by_id()
    all_sigma = list(by_id.values())
    engine = SigmaDetectionEngine()
    for rule_id in SIGMA_BATCH1_IDS:
        report = engine.evaluate(positive_sigma_event(rule_id), rules=all_sigma)
        assert not report.failures, f"{rule_id} positive caused a rule failure"


# ---------------------------------------------------------------------------
# YARA: positive + negative engine evaluation
# ---------------------------------------------------------------------------


def test_batch1_yara_rules_compile_and_match_intended_bytes() -> None:
    by_id = _yara_by_id()
    engine = YaraDetectionEngine()
    for rule_id in YARA_BATCH1_IDS:
        target = YaraTarget(content=YARA_POSITIVES[rule_id], file_name="hit.bin")
        report = engine.evaluate_target(target, rules=[by_id[rule_id]])
        assert not report.failures, f"{rule_id} failed to compile or match"
        matched = {r.rule_id for r in report.results}
        assert rule_id in matched, f"{rule_id} did not match its intended bytes"


def test_batch1_yara_rules_ignore_benign_bytes() -> None:
    by_id = _yara_by_id()
    engine = YaraDetectionEngine()
    report = engine.evaluate_target(
        YaraTarget(content=YARA_BENIGN_BYTES, file_name="app.log"),
        rules=list(by_id.values()),
    )
    assert not report.results
    assert not report.failures