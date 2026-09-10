"""Tests for the Detection Agent (Step 9E).

Covers unified orchestration of the Sigma and YARA detection engines:
result aggregation, failure isolation, disabled-rule handling,
traceability, immutability, determinism, no-match semantics,
invalid-target semantics, and metadata accounting.

Pure unit tests — no database, no network, no LLM.
"""

import base64
import uuid
from datetime import datetime, timezone
from typing import Any

from app.schemas.detection import (
    DetectionRule,
    DetectionSeverity,
    RuleType,
)
from app.schemas.detection_agent import (
    DetectionAnalysis,
    DetectionFailure,
)
from app.schemas.normalized_event import (
    EventCategory,
    EventOutcome,
    NormalizedSecurityEvent,
    ProcessInfo,
)
from app.schemas.security_event import Provenance, SourceType
from app.services.detection.registry import DetectionRuleRegistry

from app.agents.detection import DetectionAgent
from app.services.detection.sigma.engine import (
    SigmaDetectionEngine,
    SigmaDetectionReport,
)
from app.services.detection.yara.engine import (
    YaraDetectionEngine,
    YaraDetectionReport,
)

_FIXED_TS = datetime(2025, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
_FIXED_EVENT_ID = uuid.UUID("aaaa1111-bbbb-cccc-dddd-eeeeeeeeeeee")


# ─────────────────────────────────────────────────────────────────────
# Fixtures — YARA rule sources
# ─────────────────────────────────────────────────────────────────────

YARA_PAYLOAD_MATCH = """\
rule PayloadMatch
{
    meta:
        description = "Matches the word suspicious_payload"
    strings:
        $a = "suspicious_payload"
    condition:
        $a
}
"""

YARA_ALPHA_MATCH = """\
rule AlphaMatch
{
    strings:
        $a = "alpha_token"
    condition:
        $a
}
"""

YARA_NO_MATCH = """\
rule NoMatch
{
    strings:
        $a = "this_will_never_appear_in_test_data_xyz"
    condition:
        $a
}
"""

YARA_MALFORMED = """\
rule Malformed {
    strings:
        $a = "test"
    condition:
        $a AND
}
"""


# ─────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────

def _b64(data: bytes) -> str:
    """Base64-encode bytes for JSON-compatible normalized_data."""
    return base64.b64encode(data).decode("ascii")


def _sigma_content(
    *, detection: dict | None = None, logsource: dict | None = None,
) -> dict:
    if detection is None:
        detection = {"sel": {"Image": "*.exe"}, "condition": "sel"}
    if logsource is None:
        logsource = {"category": "process_creation", "product": "windows"}
    return {
        "title": "Test Rule", "id": str(uuid.uuid4()), "status": "test",
        "logsource": logsource, "detection": detection, "level": "high",
    }


def _sigma_rule(
    rule_id: str = "sigma-001", *,
    severity: DetectionSeverity = DetectionSeverity.HIGH,
    enabled: bool = True, content: Any = None,
    version: str = "1.0.0",
) -> DetectionRule:
    if content is None:
        content = _sigma_content()
    return DetectionRule(
        rule_id=rule_id, name=f"Rule {rule_id}", description=f"Detects {rule_id}",
        rule_type=RuleType.SIGMA, severity=severity, enabled=enabled,
        version=version, content=content,
    )


def _yara_rule(
    rule_id: str = "yara-001", *,
    severity: DetectionSeverity = DetectionSeverity.HIGH,
    enabled: bool = True, content: Any = None,
    version: str = "1.0.0",
) -> DetectionRule:
    if content is None:
        content = YARA_PAYLOAD_MATCH
    return DetectionRule(
        rule_id=rule_id, name=f"Rule {rule_id}", description=f"Detects {rule_id}",
        rule_type=RuleType.YARA, severity=severity, enabled=enabled,
        version=version, content=content,
    )


def _event(
    *, event_id: uuid.UUID | None = None,
    process: ProcessInfo | None = None,
    normalized_data: dict | None = None,
    provenance: Provenance = Provenance.OBSERVED,
) -> NormalizedSecurityEvent:
    """Create a normalised event with optional YARA file content."""
    return NormalizedSecurityEvent(
        event_id=event_id or _FIXED_EVENT_ID, timestamp=_FIXED_TS,
        event_category=EventCategory.PROCESS, action="process_create",
        outcome=EventOutcome.SUCCESS, source="windows-sysmon",
        source_type=SourceType.OPERATING_SYSTEM, process=process,
        normalized_data=normalized_data or {},
        provenance=provenance,
    )


def _content_event(**kwargs: Any) -> NormalizedSecurityEvent:
    """Event whose normalized_data carries base64 file content."""
    nd = dict(kwargs.get("normalized_data") or {})
    nd.setdefault("file_content", _b64(b"benign content"))
    kwargs["normalized_data"] = nd
    return _event(**kwargs)


def _sigma_match_event() -> NormalizedSecurityEvent:
    """Event that matches a Sigma rule on Image == powershell.exe."""
    return _event(
        process=ProcessInfo(
            name="ps", executable="powershell.exe",
            command_line="powershell -enc AQ==", pid=123,
        ),
    )


def _sigma_match_content() -> dict:
    return _sigma_content(
        detection={"sel": {"Image": "powershell.exe"}, "condition": "sel"},
    )


def _sigma_no_match_content() -> dict:
    return _sigma_content(
        detection={
            "sel": {"Image": "definitely_not_present.exe"},
            "condition": "sel",
        },
    )


def _build_agent(
    rules: list[DetectionRule],
) -> DetectionAgent:
    registry = DetectionRuleRegistry(rules)
    return DetectionAgent(registry=registry)


def _sigma_report(
    *,
    results: list[Any] | None = None,
    failures: list[Any] | None = None,
    rules_evaluated: int = 0,
    rules_ignored: int = 0,
    event_id: Any = _FIXED_EVENT_ID,
) -> SigmaDetectionReport:
    return SigmaDetectionReport(
        results=results or [],
        failures=failures or [],
        rules_total=rules_evaluated + rules_ignored,
        rules_evaluated=rules_evaluated,
        rules_ignored=rules_ignored,
        evaluated_rule_ids=(),
        event_id=event_id,
    )


def _yara_report(
    *,
    results: list[Any] | None = None,
    failures: list[Any] | None = None,
    rules_evaluated: int = 0,
    rules_ignored: int = 0,
    target_event_id: Any = _FIXED_EVENT_ID,
) -> YaraDetectionReport:
    return YaraDetectionReport(
        results=results or [],
        failures=failures or [],
        rules_total=rules_evaluated + rules_ignored,
        rules_evaluated=rules_evaluated,
        rules_ignored=rules_ignored,
        evaluated_rule_ids=(),
        target_event_id=target_event_id,
    )


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_default_engines_created(self):
        reg = DetectionRuleRegistry()
        agent = DetectionAgent(registry=reg)
        assert agent._registry is reg
        assert isinstance(agent._sigma_engine, SigmaDetectionEngine)
        assert isinstance(agent._yara_engine, YaraDetectionEngine)

    def test_injected_engines_used(self):
        reg = DetectionRuleRegistry()
        sigma = SigmaDetectionEngine()
        yara = YaraDetectionEngine()
        agent = DetectionAgent(
            registry=reg, sigma_engine=sigma, yara_engine=yara,
        )
        assert agent._sigma_engine is sigma
        assert agent._yara_engine is yara

    def test_no_registry_ok(self):
        agent = DetectionAgent()
        assert agent._registry is None

    def test_returns_detection_analysis(self):
        agent = DetectionAgent()
        ev = _event()
        result = agent.evaluate(ev, clock=_FIXED_TS)
        assert isinstance(result, DetectionAnalysis)


# ---------------------------------------------------------------------------
# Sigma-only match
# ---------------------------------------------------------------------------


class TestSigmaOnlyMatch:
    def test_sigma_match_with_yara_no_match(self):
        rules = [
            _sigma_rule("sigma-match", content=_sigma_match_content()),
            _yara_rule("yara-nomatch", content=YARA_NO_MATCH),
        ]
        ev = _sigma_match_event()
        ev = ev.model_copy(
            update={"normalized_data": {"file_content": _b64(b"benign")}},
        )
        result = _build_agent(rules).evaluate(ev, clock=_FIXED_TS)
        assert len(result.results) == 1
        assert result.results[0].rule_id == "sigma-match"
        assert result.results[0].rule_type == RuleType.SIGMA
        assert result.metadata.sigma_results == 1
        assert result.metadata.yara_results == 0
        assert result.metadata.total_results == 1

    def test_sigma_match_reports_matched_true(self):
        rules = [_sigma_rule("sigma-match", content=_sigma_match_content())]
        ev = _sigma_match_event()
        result = _build_agent(rules).evaluate(ev, clock=_FIXED_TS)
        assert result.results[0].matched is True


# ---------------------------------------------------------------------------
# YARA-only match
# ---------------------------------------------------------------------------


class TestYaraOnlyMatch:
    def test_yara_match_with_sigma_no_match(self):
        rules = [
            _sigma_rule("sigma-nomatch", content=_sigma_no_match_content()),
            _yara_rule("yara-match"),
        ]
        ev = _content_event(
            process=ProcessInfo(name="x", executable="x.exe"),
            normalized_data={
                "file_content": _b64(b"prefix suspicious_payload suffix"),
            },
        )
        result = _build_agent(rules).evaluate(ev, clock=_FIXED_TS)
        assert len(result.results) == 1
        assert result.results[0].rule_id == "yara-match"
        assert result.results[0].rule_type == RuleType.YARA
        assert result.metadata.sigma_results == 0
        assert result.metadata.yara_results == 1
        assert result.metadata.total_results == 1

    def test_yara_match_reports_matched_true(self):
        rules = [_yara_rule("yara-match")]
        ev = _content_event(
            normalized_data={"file_content": _b64(b"suspicious_payload")},
        )
        result = _build_agent(rules).evaluate(ev, clock=_FIXED_TS)
        assert result.results[0].matched is True


# ---------------------------------------------------------------------------
# Both engines match
# ---------------------------------------------------------------------------


class TestBothMatch:
    def test_sigma_and_yara_both_match(self):
        rules = [
            _yara_rule("yara-match"),
            _sigma_rule("sigma-match", content=_sigma_match_content()),
        ]
        nd = {"file_content": _b64(b"suspicious_payload")}
        ev = _event(
            process=ProcessInfo(name="ps", executable="powershell.exe"),
            normalized_data=nd,
        )
        result = _build_agent(rules).evaluate(ev, clock=_FIXED_TS)
        assert len(result.results) == 2
        # Engine ordering: Sigma first, then YARA.
        assert result.results[0].rule_id == "sigma-match"
        assert result.results[0].rule_type == RuleType.SIGMA
        assert result.results[1].rule_id == "yara-match"
        assert result.results[1].rule_type == RuleType.YARA
        assert result.metadata.sigma_results == 1
        assert result.metadata.yara_results == 1
        assert result.metadata.total_results == 2


# ---------------------------------------------------------------------------
# No match
# ---------------------------------------------------------------------------


class TestNoMatch:
    def test_empty_results_and_failures(self):
        rules = [
            _sigma_rule("sigma-nomatch", content=_sigma_no_match_content()),
            _yara_rule("yara-nomatch", content=YARA_NO_MATCH),
        ]
        ev = _content_event(process=ProcessInfo(name="x", executable="x.exe"))
        result = _build_agent(rules).evaluate(ev, clock=_FIXED_TS)
        assert result.results == []
        assert result.failures == []
        assert result.metadata.total_results == 0
        assert result.metadata.total_failures == 0

    def test_empty_registry_no_match(self):
        # An empty registry with a valid event: no results and no
        # failures, because no rules exist to evaluate.
        result = _build_agent([]).evaluate(
            _content_event(), clock=_FIXED_TS,
        )
        assert result.results == []
        assert result.failures == []
        assert result.metadata.engines_executed == 2
        assert result.metadata.total_results == 0
        assert result.metadata.total_failures == 0

    def test_empty_registry_missing_yara_target_fails(self):
        # Even with an empty rule list, the YARA engine still validates
        # the event target; an event without usable file content keeps
        # its invalid-target failure.  This behaviour is preserved from
        # the YARA engine contract (INVALID TARGET != NO MATCH).
        ev = _event(
            process=ProcessInfo(name="x", executable="x.exe"),
            normalized_data={},
        )
        result = _build_agent([]).evaluate(ev, clock=_FIXED_TS)
        assert result.results == []
        assert len(result.failures) == 1
        assert result.failures[0].engine == "yara"
        assert result.failures[0].error_type == "invalid_target"


# ---------------------------------------------------------------------------
# Failure isolation
# ---------------------------------------------------------------------------


class TestFailureIsolation:
    def test_sigma_failure_preserves_yara_result(self):
        malformed = _sigma_rule(
            "sigma-bad", content={"not": "a valid sigma rule"},
        )
        # Force a content type the Sigma engine cannot parse.
        malformed.__dict__["content"] = 12345  # type: ignore[assignment]
        rules = [
            malformed,
            _yara_rule("yara-match"),
        ]
        ev = _content_event(
            normalized_data={"file_content": _b64(b"suspicious_payload")},
        )
        result = _build_agent(rules).evaluate(ev, clock=_FIXED_TS)
        # YARA result preserved.
        assert len(result.results) == 1
        assert result.results[0].rule_id == "yara-match"
        # Sigma failure preserved.
        assert len(result.failures) == 1
        fail = result.failures[0]
        assert fail.engine == "sigma"
        assert fail.rule_id == "sigma-bad"
        assert fail.error_type == "malformed_rule"

    def test_yara_failure_preserves_sigma_result(self):
        rules = [
            _sigma_rule("sigma-match", content=_sigma_match_content()),
            _yara_rule("yara-bad", content=YARA_MALFORMED),
        ]
        nd = {"file_content": _b64(b"suspicious_payload")}
        ev = _event(
            process=ProcessInfo(name="ps", executable="powershell.exe"),
            normalized_data=nd,
        )
        result = _build_agent(rules).evaluate(ev, clock=_FIXED_TS)
        # Sigma result preserved.
        assert len(result.results) == 1
        assert result.results[0].rule_id == "sigma-match"
        # YARA failure preserved.
        assert len(result.failures) == 1
        fail = result.failures[0]
        assert fail.engine == "yara"
        assert fail.rule_id == "yara-bad"
        assert fail.error_type == "malformed_rule"

    def test_both_engines_fail(self):
        bad_sigma = _sigma_rule("sigma-bad", content={"oops": 1})
        bad_sigma.__dict__["content"] = "not a dict"  # type: ignore[assignment]
        rules = [
            bad_sigma,
            _yara_rule("yara-bad", content=YARA_MALFORMED),
        ]
        ev = _content_event()
        result = _build_agent(rules).evaluate(ev, clock=_FIXED_TS)
        assert result.results == []
        assert len(result.failures) == 2
        assert [f.engine for f in result.failures] == ["sigma", "yara"]

    def test_successful_no_match_is_not_a_failure(self):
        rules = [
            _sigma_rule("sigma-nomatch", content=_sigma_no_match_content()),
        ]
        ev = _content_event()
        result = _build_agent(rules).evaluate(ev, clock=_FIXED_TS)
        assert result.results == []
        assert result.failures == []

    def test_mixed_sigma_failure_and_match(self):
        # One Sigma rule matches, another is malformed.  Both must be
        # reflected: the match is kept, and the failure is recorded.
        good = _sigma_rule("sigma-good", content=_sigma_match_content())
        bad = _sigma_rule("sigma-bad", content={"invalid": True})
        bad.__dict__["content"] = 3.14  # type: ignore[assignment]
        rules = [good, bad]
        ev = _event(
            process=ProcessInfo(name="ps", executable="powershell.exe"),
            normalized_data={"file_content": _b64(b"benign content")},
        )
        result = _build_agent(rules).evaluate(ev, clock=_FIXED_TS)
        assert len(result.results) == 1
        assert result.results[0].rule_id == "sigma-good"
        assert len(result.failures) == 1
        assert result.failures[0].rule_id == "sigma-bad"
        assert result.failures[0].error_type == "malformed_rule"


# ---------------------------------------------------------------------------
# Multiple results per engine
# ---------------------------------------------------------------------------


class TestMultipleResults:
    def test_multiple_sigma_results(self):
        r1 = _sigma_rule("sigma-b", content=_sigma_match_content())
        r2 = _sigma_rule("sigma-a", content=_sigma_match_content())
        rules = [r1, r2]
        result = _build_agent(rules).evaluate(
            _sigma_match_event(), clock=_FIXED_TS,
        )
        assert len(result.results) == 2
        # Deterministic ordering by rule_id.
        assert [r.rule_id for r in result.results] == ["sigma-a", "sigma-b"]

    def test_multiple_yara_results(self):
        r1 = _yara_rule("yara-omega", content=YARA_ALPHA_MATCH)
        r2 = _yara_rule("yara-alpha", content=YARA_PAYLOAD_MATCH)
        rules = [r1, r2]
        nd = {"file_content": _b64(b"alpha_token and suspicious_payload")}
        ev = _event(normalized_data=nd)
        result = _build_agent(rules).evaluate(ev, clock=_FIXED_TS)
        assert len(result.results) == 2
        assert [r.rule_id for r in result.results] == [
            "yara-alpha", "yara-omega",
        ]

    def test_multiple_failures_both_engines(self):
        bad_s1 = _sigma_rule("sigma-z", content={"bad": 1})
        bad_s1.__dict__["content"] = 1  # type: ignore[assignment]
        bad_s2 = _sigma_rule("sigma-a", content={"b": 2})
        bad_s2.__dict__["content"] = 2  # type: ignore[assignment]
        rules = [
            bad_s1,
            bad_s2,
            _yara_rule("yara-mal", content=YARA_MALFORMED),
            _yara_rule("yara-bad", content=YARA_MALFORMED),
        ]
        ev = _content_event()
        result = _build_agent(rules).evaluate(ev, clock=_FIXED_TS)
        assert len(result.failures) == 4
        assert [f.rule_id for f in result.failures] == [
            "sigma-a", "sigma-z", "yara-bad", "yara-mal",
        ]


# ---------------------------------------------------------------------------
# Disabled rules
# ---------------------------------------------------------------------------


class TestDisabledRules:
    def test_disabled_sigma_rules_not_evaluated(self):
        rules = [
            _sigma_rule(
                "sigma-disabled",
                content=_sigma_match_content(),
                enabled=False,
            ),
        ]
        result = _build_agent(rules).evaluate(
            _content_event(
                process=ProcessInfo(name="ps", executable="powershell.exe"),
            ),
            clock=_FIXED_TS,
        )
        assert result.results == []
        assert result.failures == []
        assert result.metadata.sigma_rules_evaluated == 0

    def test_disabled_yara_rules_not_evaluated(self):
        rules = [
            _yara_rule("yara-disabled", enabled=False),
        ]
        ev = _content_event()
        result = _build_agent(rules).evaluate(ev, clock=_FIXED_TS)
        assert result.results == []
        assert result.failures == []
        assert result.metadata.yara_rules_evaluated == 0

    def test_disabled_rule_with_failing_content_still_skipped(self):
        # A disabled Sigma rule must not be evaluated even if its
        # content is malformed.
        bad = _sigma_rule(
            "sigma-bad-disabled", content={"bad": 1}, enabled=False,
        )
        bad.__dict__["content"] = 0  # type: ignore[assignment]
        rules = [
            bad,
            _yara_rule("yara-ok", content=YARA_PAYLOAD_MATCH),
        ]
        ev = _content_event(
            normalized_data={"file_content": _b64(b"suspicious_payload")},
        )
        result = _build_agent(rules).evaluate(ev, clock=_FIXED_TS)
        assert len(result.results) == 1
        assert result.results[0].rule_id == "yara-ok"
        assert result.failures == []


# ---------------------------------------------------------------------------
# Traceability
# ---------------------------------------------------------------------------


class TestTraceability:
    def test_event_id_preserved(self):
        ev = _event(event_id=_FIXED_EVENT_ID)
        result = _build_agent([]).evaluate(ev, clock=_FIXED_TS)
        assert result.event_id == _FIXED_EVENT_ID

    def test_event_provenance_preserved_on_event(self):
        ev = _event(provenance=Provenance.OBSERVED)
        _build_agent([]).evaluate(ev, clock=_FIXED_TS)
        assert ev.provenance == Provenance.OBSERVED

    def test_detection_ids_intact(self):
        rules = [
            _sigma_rule("sigma-a", content=_sigma_match_content()),
            _yara_rule("yara-a"),
        ]
        ev = _event(
            process=ProcessInfo(name="ps", executable="powershell.exe"),
            normalized_data={"file_content": _b64(b"suspicious_payload")},
        )
        result = _build_agent(rules).evaluate(ev, clock=_FIXED_TS)
        detection_ids = {r.detection_id for r in result.results}
        assert len(detection_ids) == 2
        assert all(isinstance(d, uuid.UUID) for d in detection_ids)

    def test_rule_ids_intact(self):
        rules = [
            _sigma_rule("sigma-111", content=_sigma_match_content()),
            _yara_rule("yara-222"),
        ]
        ev = _event(
            process=ProcessInfo(name="ps", executable="powershell.exe"),
            normalized_data={"file_content": _b64(b"suspicious_payload")},
        )
        result = _build_agent(rules).evaluate(ev, clock=_FIXED_TS)
        rule_ids = {r.rule_id for r in result.results}
        assert rule_ids == {"sigma-111", "yara-222"}

    def test_severity_intact(self):
        rules = [
            _sigma_rule(
                "sigma-low", content=_sigma_match_content(),
                severity=DetectionSeverity.LOW,
            ),
            _yara_rule(
                "yara-crit", severity=DetectionSeverity.CRITICAL,
            ),
        ]
        ev = _event(
            process=ProcessInfo(name="ps", executable="powershell.exe"),
            normalized_data={"file_content": _b64(b"suspicious_payload")},
        )
        result = _build_agent(rules).evaluate(ev, clock=_FIXED_TS)
        by_rule = {r.rule_id: r.severity for r in result.results}
        assert by_rule["sigma-low"] == DetectionSeverity.LOW
        assert by_rule["yara-crit"] == DetectionSeverity.CRITICAL

    def test_confidence_intact(self):
        rules = [
            _sigma_rule("sigma-a", content=_sigma_match_content()),
            _yara_rule("yara-a"),
        ]
        ev = _event(
            process=ProcessInfo(name="ps", executable="powershell.exe"),
            normalized_data={"file_content": _b64(b"suspicious_payload")},
        )
        result = _build_agent(rules).evaluate(ev, clock=_FIXED_TS)
        by_rule = {r.rule_id: r.confidence for r in result.results}
        # HIGH severity maps to 0.9 in both engines.
        assert by_rule["sigma-a"] == 0.9
        assert by_rule["yara-a"] == 0.9

    def test_evidence_intact(self):
        rules = [
            _sigma_rule("sigma-a", content=_sigma_match_content()),
            _yara_rule("yara-a"),
        ]
        ev = _event(
            process=ProcessInfo(name="ps", executable="powershell.exe"),
            normalized_data={"file_content": _b64(b"suspicious_payload")},
        )
        result = _build_agent(rules).evaluate(ev, clock=_FIXED_TS)
        by_rule = {r.rule_id: r for r in result.results}
        sigma_ctx = by_rule["sigma-a"].evidence.detection_context
        assert sigma_ctx["engine"] == "sigma"
        yara_extra = by_rule["yara-a"].metadata.extra
        assert yara_extra["engine"] == "yara"

    def test_provenance_is_detected_on_analysis_and_results(self):
        rules = [
            _sigma_rule("sigma-a", content=_sigma_match_content()),
            _yara_rule("yara-a"),
        ]
        ev = _event(
            process=ProcessInfo(name="ps", executable="powershell.exe"),
            normalized_data={"file_content": _b64(b"suspicious_payload")},
        )
        result = _build_agent(rules).evaluate(ev, clock=_FIXED_TS)
        assert result.provenance == Provenance.DETECTED
        assert all(
            r.provenance == Provenance.DETECTED for r in result.results
        )

    def test_timestamp_preserved_from_clock(self):
        fixed = datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        result = _build_agent([]).evaluate(_event(), clock=fixed)
        assert result.timestamp == fixed
        assert result.results == []

    def test_engine_failure_is_structured(self):
        rules = [_yara_rule("yara-bad", content=YARA_MALFORMED)]
        result = _build_agent(rules).evaluate(
            _content_event(), clock=_FIXED_TS,
        )
        assert len(result.failures) == 1
        fail = result.failures[0]
        assert isinstance(fail, DetectionFailure)
        assert fail.engine == "yara"
        assert fail.error_type == "malformed_rule"


# ---------------------------------------------------------------------------
# Immutability
# ---------------------------------------------------------------------------


class TestImmutability:
    def test_input_event_not_mutated(self):
        rules = [_sigma_rule("sigma-a", content=_sigma_match_content())]
        ev = _sigma_match_event()
        before = ev.model_dump()
        _build_agent(rules).evaluate(ev, clock=_FIXED_TS)
        assert ev.model_dump() == before

    def test_event_normalized_data_not_mutated(self):
        rules = [_yara_rule("yara-a")]
        nd = {"file_content": _b64(b"suspicious_payload"), "extra_key": "keep"}
        ev = _event(normalized_data=nd)
        before = dict(ev.normalized_data)
        _build_agent(rules).evaluate(ev, clock=_FIXED_TS)
        assert ev.normalized_data == before

    def test_detection_rules_not_mutated(self):
        rules = [
            _sigma_rule("sigma-a", content=_sigma_match_content()),
            _yara_rule("yara-a"),
        ]
        before = [r.model_copy(deep=True) for r in rules]
        ev = _event(
            process=ProcessInfo(name="ps", executable="powershell.exe"),
            normalized_data={"file_content": _b64(b"suspicious_payload")},
        )
        _build_agent(rules).evaluate(ev, clock=_FIXED_TS)
        for rule, snap in zip(rules, before):
            assert rule.model_dump() == snap.model_dump()

    def test_engines_do_not_mutate_registry_rules(self):
        rules = [
            _yara_rule("yara-a", enabled=True),
            _sigma_rule(
                "sigma-a", enabled=True, content=_sigma_match_content(),
            ),
        ]
        before = {r.rule_id: r.model_dump() for r in rules}
        ev = _event(
            process=ProcessInfo(name="ps", executable="powershell.exe"),
            normalized_data={"file_content": _b64(b"suspicious_payload")},
        )
        _build_agent(rules).evaluate(ev, clock=_FIXED_TS)
        for rule in rules:
            assert rule.model_dump() == before[rule.rule_id]


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_result_ordering_sigma_before_yara(self):
        rules = [
            _yara_rule("yara-a"),
            _sigma_rule("sigma-a", content=_sigma_match_content()),
        ]
        ev = _event(
            process=ProcessInfo(name="ps", executable="powershell.exe"),
            normalized_data={"file_content": _b64(b"suspicious_payload")},
        )
        result = _build_agent(rules).evaluate(ev, clock=_FIXED_TS)
        assert [r.rule_type for r in result.results] == [
            RuleType.SIGMA, RuleType.YARA,
        ]

    def test_failure_ordering_sigma_before_yara(self):
        bad_s = _sigma_rule("sigma-a", content={"b": 1})
        bad_s.__dict__["content"] = 3  # type: ignore[assignment]
        rules = [
            bad_s,
            _yara_rule("yara-b", content=YARA_MALFORMED),
        ]
        result = _build_agent(rules).evaluate(
            _content_event(), clock=_FIXED_TS,
        )
        assert [f.engine for f in result.failures] == ["sigma", "yara"]

    def test_repeated_eval_same_outcome(self):
        rules = [
            _sigma_rule("sigma-a", content=_sigma_match_content()),
            _yara_rule("yara-a"),
        ]
        ev = _event(
            process=ProcessInfo(name="ps", executable="powershell.exe"),
            normalized_data={"file_content": _b64(b"suspicious_payload")},
        )
        agent = _build_agent(rules)
        a1 = agent.evaluate(ev, clock=_FIXED_TS)
        a2 = agent.evaluate(ev, clock=_FIXED_TS)

        # detection_ids, per-result timestamps, and execution_time_ms
        # are intentionally dynamic (uuid4 / now / wall-clock); compare
        # the deterministic parts.
        def stable(analysis):
            md = analysis.metadata.model_dump()
            md.pop("execution_time_ms", None)
            return (
                analysis.event_id,
                tuple(
                    (r.rule_id, r.rule_type.value, r.matched,
                     r.severity.value, r.confidence, r.provenance.value)
                    for r in analysis.results
                ),
                tuple(
                    (f.engine, f.rule_id, f.error_type)
                    for f in analysis.failures
                ),
                md,
                analysis.provenance.value,
            )

        assert stable(a1) == stable(a2)


# ---------------------------------------------------------------------------
# Invalid YARA target
# ---------------------------------------------------------------------------


class TestInvalidTarget:
    def _event_without_content(self) -> NormalizedSecurityEvent:
        return _event(
            process=ProcessInfo(name="ps", executable="powershell.exe"),
            normalized_data={},
        )

    def test_invalid_target_preserved_as_failure(self):
        # Event without file content: YARA cannot evaluate, and the
        # invalid-target situation MUST be preserved as a failure, not
        # silently converted to "no match".
        rules = [
            _sigma_rule("sigma-a", content=_sigma_match_content()),
            _yara_rule("yara-a"),
        ]
        ev = self._event_without_content()
        result = _build_agent(rules).evaluate(ev, clock=_FIXED_TS)
        # Sigma result is preserved.
        assert len(result.results) == 1
        assert result.results[0].rule_id == "sigma-a"
        # YARA invalid-target failure is preserved.
        assert len(result.failures) == 1
        fail = result.failures[0]
        assert fail.engine == "yara"
        assert fail.error_type == "invalid_target"
        assert fail.rule_id == "<event>"
        # No fabricated YARA result.
        assert result.metadata.yara_results == 0
        assert result.metadata.yara_failures == 1

    def test_invalid_target_is_not_no_match(self):
        rules = [_yara_rule("yara-a")]
        ev = self._event_without_content()
        result = _build_agent(rules).evaluate(ev, clock=_FIXED_TS)
        # If it were treated as "no match", failures would be empty.
        assert result.results == []
        assert len(result.failures) == 1
        assert result.failures[0].error_type == "invalid_target"


# ---------------------------------------------------------------------------
# Unexpected engine exception
# ---------------------------------------------------------------------------


class _ExplodingSigmaEngine:
    """Fake Sigma engine that always raises."""

    def evaluate(self, event, *args, **kwargs):
        raise RuntimeError("sigma boom")


class _ExplodingYaraEngine:
    """Fake YARA engine that always raises."""

    def evaluate(self, event, rules, *args, **kwargs):
        raise RuntimeError("yara boom")


class TestEngineExceptionIsolation:
    def test_sigma_exception_does_not_block_yara(self):
        rules = [_yara_rule("yara-a")]
        registry = DetectionRuleRegistry(rules)
        agent = DetectionAgent(
            registry=registry,
            sigma_engine=_ExplodingSigmaEngine(),  # type: ignore[arg-type]
        )
        ev = _content_event(
            normalized_data={"file_content": _b64(b"suspicious_payload")},
        )
        result = agent.evaluate(ev, clock=_FIXED_TS)
        # YARA still ran and matched.
        assert len(result.results) == 1
        assert result.results[0].rule_id == "yara-a"
        # Sigma failure is structured and secret-safe.
        assert len(result.failures) == 1
        fail = result.failures[0]
        assert fail.engine == "sigma"
        assert fail.error_type == "engine_error"
        assert fail.message == "Sigma engine error: RuntimeError"

    def test_yara_exception_does_not_block_sigma(self):
        rules = [_sigma_rule("sigma-a", content=_sigma_match_content())]
        registry = DetectionRuleRegistry(rules)
        agent = DetectionAgent(
            registry=registry,
            yara_engine=_ExplodingYaraEngine(),  # type: ignore[arg-type]
        )
        ev = _content_event(
            process=ProcessInfo(name="ps", executable="powershell.exe"),
        )
        result = agent.evaluate(ev, clock=_FIXED_TS)
        assert len(result.results) == 1
        assert result.results[0].rule_id == "sigma-a"
        assert len(result.failures) == 1
        fail = result.failures[0]
        assert fail.engine == "yara"
        assert fail.error_type == "engine_error"

    def test_both_engines_explode_no_results(self):
        registry = DetectionRuleRegistry([])
        agent = DetectionAgent(
            registry=registry,
            sigma_engine=_ExplodingSigmaEngine(),  # type: ignore[arg-type]
            yara_engine=_ExplodingYaraEngine(),  # type: ignore[arg-type]
        )
        ev = _event()
        result = agent.evaluate(ev, clock=_FIXED_TS)
        assert result.results == []
        assert len(result.failures) == 2
        assert [f.engine for f in result.failures] == ["sigma", "yara"]
        assert all(
            f.error_type == "engine_error" for f in result.failures
        )
        assert result.metadata.total_failures == 2
        assert result.metadata.engines_executed == 0


# ---------------------------------------------------------------------------
# Metadata accounting
# ---------------------------------------------------------------------------


class TestMetadata:
    def test_metadata_counts_match_engine_reports(self):
        rules = [
            _yara_rule("yara-a"),
            _sigma_rule("sigma-a", content=_sigma_match_content()),
            _sigma_rule("sigma-b", content=_sigma_no_match_content()),
        ]
        ev = _event(
            process=ProcessInfo(name="ps", executable="powershell.exe"),
            normalized_data={"file_content": _b64(b"suspicious_payload")},
        )
        result = _build_agent(rules).evaluate(ev, clock=_FIXED_TS)
        md = result.metadata
        assert md.engines_executed == 2
        assert md.sigma_rules_evaluated == 2
        assert md.yara_rules_evaluated == 1
        assert md.sigma_results == 1
        assert md.yara_results == 1
        assert md.total_results == 2
        assert md.total_failures == 0
        assert md.execution_time_ms is not None
        assert md.execution_time_ms >= 0

    def test_metadata_counts_with_failures(self):
        bad_s = _sigma_rule("sigma-bad", content={"x": 1})
        bad_s.__dict__["content"] = 5  # type: ignore[assignment]
        rules = [
            bad_s,
            _yara_rule("yara-bad", content=YARA_MALFORMED),
            _sigma_rule("sigma-nomatch", content=_sigma_no_match_content()),
        ]
        result = _build_agent(rules).evaluate(
            _content_event(), clock=_FIXED_TS,
        )
        md = result.metadata
        assert md.sigma_rules_evaluated == 2
        assert md.yara_rules_evaluated == 1
        assert md.sigma_failures == 1
        assert md.yara_failures == 1
        assert md.total_failures == 2
        assert md.sigma_results == 0
        assert md.yara_results == 0
        assert md.total_results == 0

    def test_metadata_counts_without_registry(self):
        agent = DetectionAgent()
        result = agent.evaluate(_content_event(), clock=_FIXED_TS)
        assert result.metadata.engines_executed == 2
        assert result.metadata.sigma_rules_evaluated == 0
        assert result.metadata.yara_rules_evaluated == 0
        assert result.metadata.total_results == 0
        assert result.metadata.total_failures == 0