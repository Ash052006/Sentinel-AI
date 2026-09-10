"""Tests for the Sigma Detection Engine (Step 9C).

Covers event-to-dict mapping, rule parsing, condition evaluation,
wildcard matching, case sensitivity, unsupported-feature rejection,
evidence generation, failure recording, caching, and boundary enforcement.

Pure unit tests — no database, no network, no LLM.
"""

import uuid
from datetime import datetime, timezone
from typing import Any

import pytest

from app.schemas.detection import (
    DetectionRule,
    DetectionSeverity,
    RuleType,
)
from app.schemas.normalized_event import (
    Actor,
    Endpoint,
    EventCategory,
    EventOutcome,
    FileInfo,
    NormalizedSecurityEvent,
    ProcessInfo,
)
from app.schemas.security_event import SourceType
from app.services.detection.registry import DetectionRuleRegistry
from app.services.detection.sigma.engine import (
    SigmaDetectionEngine,
    SigmaDetectionReport,
    SigmaRuleFailure,
    _wildcard_match,
    _severity_to_confidence,
)
from app.services.detection.sigma.event_adapter import to_evaluation_dict
from app.services.detection.sigma.exceptions import (
    InvalidEventDataError,
    MalformedSigmaRuleError,
    SigmaDetectionError,
    UnsupportedSigmaFeatureError,
)

_FIXED_TS = datetime(2025, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
_FIXED_EVENT_ID = uuid.UUID("aaaa1111-bbbb-cccc-dddd-eeeeeeeeeeee")


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
    rule_id: str = "sigma-001", *, severity: DetectionSeverity = DetectionSeverity.HIGH,
    enabled: bool = True, content: Any = None, version: str = "1.0.0",
) -> DetectionRule:
    if content is None:
        content = _sigma_content()
    return DetectionRule(
        rule_id=rule_id, name=f"Rule {rule_id}", description=f"Detects {rule_id}",
        rule_type=RuleType.SIGMA, severity=severity, enabled=enabled,
        version=version, content=content,
    )


def _event(
    *, event_id: uuid.UUID | None = None, category: EventCategory = EventCategory.PROCESS,
    action: str | None = "process_create", actor: Actor | None = None,
    process: ProcessInfo | None = None, source_endpoint: Endpoint | None = None,
    destination_endpoint: Endpoint | None = None, file: FileInfo | None = None,
    normalized_data: dict | None = None,
) -> NormalizedSecurityEvent:
    return NormalizedSecurityEvent(
        event_id=event_id or _FIXED_EVENT_ID, timestamp=_FIXED_TS,
        event_category=category, action=action, outcome=EventOutcome.SUCCESS,
        source="windows-sysmon", source_type=SourceType.OPERATING_SYSTEM,
        actor=actor, process=process, source_endpoint=source_endpoint,
        destination_endpoint=destination_endpoint, file=file,
        normalized_data=normalized_data or {},
    )


# =========================================================================
# A. Event Adapter
# =========================================================================


class TestEventAdapter:
    def test_returns_tuple(self):
        result = to_evaluation_dict(_event())
        assert isinstance(result, tuple) and len(result) == 2

    def test_basic_fields(self):
        d, collisions = to_evaluation_dict(_event())
        assert d["event_category"] == "process"
        assert d["outcome"] == "success"
        assert collisions == ()

    def test_actor_fields(self):
        a = Actor(user_id="S-1-5-21", username="admin", domain="CORP")
        d, _ = to_evaluation_dict(_event(actor=a))
        assert d["User"] == "admin"
        assert d["UserSid"] == "S-1-5-21"
        assert d["actor.username"] == "admin"

    def test_process_fields(self):
        p = ProcessInfo(name="ps.exe", executable="C:\\ps.exe",
                        command_line="powershell", pid=123, parent_process="cmd.exe")
        d, _ = to_evaluation_dict(_event(process=p))
        assert d["Image"] == "C:\\ps.exe"
        assert d["CommandLine"] == "powershell"
        assert d["ProcessId"] == 123
        assert d["ParentImage"] == "cmd.exe"

    def test_source_endpoint(self):
        ep = Endpoint(ip="10.0.0.1", hostname="ws1")
        d, _ = to_evaluation_dict(_event(source_endpoint=ep))
        assert d["IpAddress"] == "10.0.0.1"
        assert d["source_endpoint.ip"] == "10.0.0.1"

    def test_destination_endpoint(self):
        ep = Endpoint(ip="192.168.1.1", hostname="srv")
        d, _ = to_evaluation_dict(_event(destination_endpoint=ep))
        assert d["DestinationAddress"] == "192.168.1.1"

    def test_file_fields(self):
        f = FileInfo(name="a.exe", path="C:\\a.exe")
        d, _ = to_evaluation_dict(_event(file=f))
        assert d["FileName"] == "a.exe"
        assert d["file.name"] == "a.exe"

    def test_none_fields_omitted(self):
        d, _ = to_evaluation_dict(_event())
        assert "User" not in d and "Image" not in d and "FileName" not in d

    def test_collision_recorded(self):
        ev = _event(process=ProcessInfo(name="test", executable="val1"),
                    normalized_data={"Image": "val2"})
        d, collisions = to_evaluation_dict(ev)
        assert d["Image"] == "val1"
        assert "Image" in collisions

    def test_normalized_data_merged(self):
        d, _ = to_evaluation_dict(_event(normalized_data={"x": "y"}))
        assert d["x"] == "y"


# =========================================================================
# B. Wildcard Match
# =========================================================================


class TestWildcardMatch:
    def test_exact(self):
        assert _wildcard_match("test.exe", "test.exe", False)

    def test_star(self):
        assert _wildcard_match("*.exe", "test.exe", False)

    def test_star_empty(self):
        assert _wildcard_match("test*", "test", False)

    def test_question_mark(self):
        assert _wildcard_match("t?st.exe", "test.exe", False)

    def test_question_mark_no_match_two(self):
        assert not _wildcard_match("t?.exe", "t.exe", False)

    def test_case_insensitive(self):
        assert _wildcard_match("test.exe", "TEST.EXE", False)

    def test_case_sensitive_match(self):
        assert _wildcard_match("TEST.EXE", "TEST.EXE", True)

    def test_case_sensitive_no_match(self):
        assert not _wildcard_match("TEST.EXE", "test.exe", True)

    def test_contains(self):
        assert _wildcard_match("*powershell*", "C:\\powershell.exe", False)

    def test_no_match(self):
        assert not _wildcard_match("*.exe", "test.txt", False)


# =========================================================================
# C. Severity → Confidence
# =========================================================================


class TestSeverityConfidence:
    def test_critical(self):
        assert _severity_to_confidence(DetectionSeverity.CRITICAL) == 1.0

    def test_high(self):
        assert _severity_to_confidence(DetectionSeverity.HIGH) == 0.9

    def test_medium(self):
        assert _severity_to_confidence(DetectionSeverity.MEDIUM) == 0.7

    def test_low(self):
        assert _severity_to_confidence(DetectionSeverity.LOW) == 0.5


# =========================================================================
# D. Engine Instantiation
# =========================================================================


class TestEngineInit:
    def test_no_registry(self):
        e = SigmaDetectionEngine()
        assert e._registry is None
        assert e._engine_version == "1.0.0"

    def test_with_registry(self):
        reg = DetectionRuleRegistry()
        e = SigmaDetectionEngine(reg)
        assert e._registry is reg

    def test_custom_version(self):
        e = SigmaDetectionEngine(engine_version="2.0.0")
        assert e._engine_version == "2.0.0"


# =========================================================================
# E. Basic Match / No-Match
# =========================================================================


class TestBasicEvaluation:
    def test_simple_match(self):
        c = _sigma_content(detection={"sel": {"Image": "powershell.exe"}, "condition": "sel"})
        rule = _sigma_rule(content=c)
        ev = _event(process=ProcessInfo(name="ps", executable="powershell.exe"))
        report = SigmaDetectionEngine().evaluate(ev, [rule])
        assert len(report.results) == 1
        assert report.results[0].matched is True

    def test_simple_no_match(self):
        c = _sigma_content(detection={"sel": {"Image": "powershell.exe"}, "condition": "sel"})
        rule = _sigma_rule(content=c)
        ev = _event(process=ProcessInfo(name="ps", executable="cmd.exe"))
        report = SigmaDetectionEngine().evaluate(ev, [rule])
        assert len(report.results) == 0

    def test_wildcard_match(self):
        c = _sigma_content(detection={"sel": {"Image": "*.exe"}, "condition": "sel"})
        rule = _sigma_rule(content=c)
        ev = _event(process=ProcessInfo(name="t", executable="test.exe"))
        assert len(SigmaDetectionEngine().evaluate(ev, [rule]).results) == 1

    def test_contains_modifier(self):
        c = _sigma_content(detection={"sel": {"CommandLine|contains": "power"}, "condition": "sel"})
        rule = _sigma_rule(content=c)
        ev = _event(process=ProcessInfo(name="t", executable="t", command_line="powershell -enc X"))
        assert len(SigmaDetectionEngine().evaluate(ev, [rule]).results) == 1

    def test_cased_match(self):
        c = _sigma_content(detection={"sel": {"Image|cased": "CMD.EXE"}, "condition": "sel"})
        rule = _sigma_rule(content=c)
        ev = _event(process=ProcessInfo(name="t", executable="CMD.EXE"))
        assert len(SigmaDetectionEngine().evaluate(ev, [rule]).results) == 1

    def test_cased_no_match(self):
        c = _sigma_content(detection={"sel": {"Image|cased": "CMD.EXE"}, "condition": "sel"})
        rule = _sigma_rule(content=c)
        ev = _event(process=ProcessInfo(name="t", executable="cmd.exe"))
        assert len(SigmaDetectionEngine().evaluate(ev, [rule]).results) == 0

    def test_and_condition(self):
        c = _sigma_content(detection={
            "sel": {"Image|contains": "power", "CommandLine|contains": "Get-Proc"},
            "condition": "sel",
        })
        rule = _sigma_rule(content=c)
        e = SigmaDetectionEngine()
        ev1 = _event(process=ProcessInfo(name="t", executable="C:\\power.exe", command_line="Get-Proc"))
        assert len(e.evaluate(ev1, [rule]).results) == 1
        ev2 = _event(process=ProcessInfo(name="t", executable="C:\\power.exe", command_line="Get-Svc"))
        assert len(e.evaluate(ev2, [rule]).results) == 0

    def test_or_condition(self):
        c = _sigma_content(detection={
            "sel_a": {"Image": "powershell.exe"}, "sel_b": {"Image": "cmd.exe"},
            "condition": "sel_a or sel_b",
        })
        rule = _sigma_rule(content=c)
        e = SigmaDetectionEngine()
        assert len(e.evaluate(_event(process=ProcessInfo(name="t", executable="powershell.exe")), [rule]).results) == 1
        assert len(e.evaluate(_event(process=ProcessInfo(name="t", executable="cmd.exe")), [rule]).results) == 1

    def test_not_condition(self):
        c = _sigma_content(detection={
            "sel_a": {"Image|contains": "power"}, "sel_b": {"User": "admin"},
            "condition": "sel_a and not sel_b",
        })
        rule = _sigma_rule(content=c)
        e = SigmaDetectionEngine()
        ev = _event(process=ProcessInfo(name="t", executable="power.exe", command_line="x"),
                    actor=Actor(username="regular"))
        assert len(e.evaluate(ev, [rule]).results) == 1
        ev2 = _event(process=ProcessInfo(name="t", executable="power.exe", command_line="x"),
                     actor=Actor(username="admin"))
        assert len(e.evaluate(ev2, [rule]).results) == 0


# =========================================================================
# F. Unsupported Features
# =========================================================================


class TestUnsupported:
    def test_regex_rejected(self):
        c = _sigma_content(detection={"sel": {"CommandLine|re": ".*test.*"}, "condition": "sel"})
        rule = _sigma_rule(content=c)
        ev = _event(process=ProcessInfo(name="t", executable="t", command_line="test"))
        report = SigmaDetectionEngine().evaluate(ev, [rule])
        assert len(report.results) == 0
        assert len(report.failures) == 1
        assert report.failures[0].error_type == "unsupported_feature"
        assert "regex" in report.failures[0].message.lower()

    def test_unsupported_logsource(self):
        c = _sigma_content(logsource={"category": "test", "service": "sysmon"})
        rule = _sigma_rule(content=c)
        report = SigmaDetectionEngine().evaluate(_event(), [rule])
        assert len(report.failures) == 1
        assert "service" in report.failures[0].message.lower()


# =========================================================================
# G. Malformed Rules
# =========================================================================


class TestMalformed:
    def test_no_content(self):
        rule = DetectionRule(
            rule_id="r1", name="R", description="R",
            rule_type=RuleType.SIGMA, severity=DetectionSeverity.HIGH, content=None,
        )
        report = SigmaDetectionEngine().evaluate(_event(), [rule])
        assert len(report.failures) == 1
        assert report.failures[0].error_type == "malformed_rule"

    def test_invalid_yaml(self):
        rule = DetectionRule(
            rule_id="r1", name="R", description="R",
            rule_type=RuleType.SIGMA, severity=DetectionSeverity.HIGH,
            content="not: valid: [yaml",
        )
        report = SigmaDetectionEngine().evaluate(_event(), [rule])
        assert len(report.failures) == 1
        assert report.failures[0].error_type == "malformed_rule"


# =========================================================================
# H. Report Structure
# =========================================================================


class TestReport:
    def test_attributes(self):
        report = SigmaDetectionEngine().evaluate(_event(), [])
        assert hasattr(report, "results")
        assert hasattr(report, "failures")
        assert hasattr(report, "rules_total")

    def test_empty(self):
        report = SigmaDetectionEngine().evaluate(_event(), [])
        assert report.results == []
        assert report.rules_evaluated == 0
        assert report.event_id == _FIXED_EVENT_ID

    def test_disabled_ignored(self):
        rule = _sigma_rule(enabled=False)
        report = SigmaDetectionEngine().evaluate(_event(), [rule])
        assert report.rules_ignored == 1

    def test_yara_ignored(self):
        rule = DetectionRule(
            rule_id="y1", name="Y", description="Y",
            rule_type=RuleType.YARA, severity=DetectionSeverity.HIGH,
        )
        report = SigmaDetectionEngine().evaluate(_event(), [rule])

# =========================================================================
# I. Result & Evidence
# =========================================================================


class TestResultEvidence:
    def _match(self, **kwargs):
        c = _sigma_content(detection={"sel": {"Image": "powershell.exe"}, "condition": "sel"})
        rule = _sigma_rule(content=c, **kwargs)
        ev = _event(process=ProcessInfo(name="t", executable="powershell.exe"))
        return SigmaDetectionEngine().evaluate(ev, [rule]).results[0]

    def test_provenance(self):
        assert self._match().provenance.value == "detected"

    def test_rule_type(self):
        assert self._match().rule_type == RuleType.SIGMA

    def test_matched_fields(self):
        assert self._match().evidence.matched_fields["Image"] == "powershell.exe"

    def test_matched_conditions(self):
        assert "sel" in self._match().evidence.matched_conditions

    def test_detection_context(self):
        assert self._match().evidence.detection_context["engine"] == "sigma"

    def test_engine_version_in_metadata(self):
        c = _sigma_content(detection={"sel": {"Image": "powershell.exe"}, "condition": "sel"})
        r = SigmaDetectionEngine(engine_version="3.0.0").evaluate(
            _event(process=ProcessInfo(name="t", executable="powershell.exe")),
            [_sigma_rule(content=c)],
        ).results[0]
        assert r.metadata.engine_version == "3.0.0"

    def test_severity_from_rule(self):
        r = self._match(severity=DetectionSeverity.CRITICAL)
        assert r.severity == DetectionSeverity.CRITICAL
        assert r.confidence == 1.0

    def test_event_id_preserved(self):
        target = uuid.UUID("bbbb2222-cccc-dddd-eeee-ffffffffffff")
        ev = _event(event_id=target, process=ProcessInfo(name="t", executable="powershell.exe"))
        c = _sigma_content(detection={"sel": {"Image": "powershell.exe"}, "condition": "sel"})
        r = SigmaDetectionEngine().evaluate(ev, [_sigma_rule(content=c)]).results[0]
        assert r.event_id == target


# =========================================================================
# J. Invalid Event Data
# =========================================================================


class TestInvalidEvent:
    def test_none_raises(self):
        with pytest.raises(InvalidEventDataError):
            SigmaDetectionEngine().evaluate(None, [])  # type: ignore[arg-type]


# =========================================================================
# K. Registry Integration
# =========================================================================


class TestRegistry:
    def test_uses_registry(self):
        reg = DetectionRuleRegistry()
        c = _sigma_content(detection={"sel": {"Image": "test"}, "condition": "sel"})
        reg.register(_sigma_rule(content=c))
        engine = SigmaDetectionEngine(reg)
        ev = _event(process=ProcessInfo(name="t", executable="test"))
        assert len(engine.evaluate(ev).results) == 1

    def test_empty_registry(self):
        report = SigmaDetectionEngine(DetectionRuleRegistry()).evaluate(_event())
        assert report.rules_evaluated == 0
        assert report.rules_total == 0
        assert report.rules_ignored == 0

    def test_sorted_ids(self):
        r1 = _sigma_rule("sigma-zzz")
        r2 = _sigma_rule("sigma-aaa")
        report = SigmaDetectionEngine().evaluate(_event(), [r1, r2])
        assert report.evaluated_rule_ids == ("sigma-aaa", "sigma-zzz")


# =========================================================================
# L. Parsed Cache
# =========================================================================


class TestCache:
    def test_cache_populated(self):
        c = _sigma_content(detection={"sel": {"Image": "test"}, "condition": "sel"})
        rule = _sigma_rule(content=c)
        engine = SigmaDetectionEngine()
        engine.evaluate(_event(process=ProcessInfo(name="t", executable="test")), [rule])
        assert (rule.rule_id, rule.version) in engine._parsed_cache

    def test_cache_reused(self):
        c = _sigma_content(detection={"sel": {"Image": "test"}, "condition": "sel"})
        rule = _sigma_rule(content=c)
        engine = SigmaDetectionEngine()
        ev = _event(process=ProcessInfo(name="t", executable="test"))
        engine.evaluate(ev, [rule])
        p1 = engine._parsed_cache[(rule.rule_id, rule.version)]
        engine.evaluate(ev, [rule])
        p2 = engine._parsed_cache[(rule.rule_id, rule.version)]
        assert p1 is p2


# =========================================================================
# M. SigmaRuleFailure
# =========================================================================


class TestFailure:
    def test_attributes(self):
        f = SigmaRuleFailure("r1", "malformed_rule", "bad")
        assert f.rule_id == "r1"
        assert f.error_type == "malformed_rule"

    def test_repr(self):
        f = SigmaRuleFailure("r1", "err", "msg")
        assert "r1" in repr(f)


# =========================================================================
# N. Boundary Enforcement
# =========================================================================


class TestBoundary:
    def test_no_execution_helpers(self):
        import inspect
        import app.services.detection.sigma.engine as mod
        source = inspect.getsource(mod)
        assert "eval(" not in source
        assert "exec(" not in source
        assert "subprocess" not in source
        assert "os.system" not in source


# =========================================================================
# O. Edge Cases
# =========================================================================


class TestEdgeCases:
    def test_dot_path_match(self):
        c = _sigma_content(detection={
            "sel": {"process.name|contains": "power"}, "condition": "sel",
        })
        rule = _sigma_rule(content=c)
        ev = _event(process=ProcessInfo(name="powershell.exe"))
        assert len(SigmaDetectionEngine().evaluate(ev, [rule]).results) == 1

    def test_yaml_string_content(self):
        yaml = (
            "title: YAML Rule\nid: 11111111-2222-3333-4444-555555555555\n"
            "status: test\nlogsource:\n  category: process_creation\n"
            "  product: windows\ndetection:\n  sel:\n"
            "    Image: powershell.exe\n  condition: sel\nlevel: high\n"
        )
        rule = _sigma_rule(content=yaml)
        ev = _event(process=ProcessInfo(name="t", executable="powershell.exe"))
        assert len(SigmaDetectionEngine().evaluate(ev, [rule]).results) == 1

    def test_unsupported_content_type(self):
        """Rule with unsupported content type fails at parse time."""
        rule = _sigma_rule(content="not a sigma rule")
        # Override the content after creation to simulate wrong type
        rule.__dict__["content"] = 12345  # type: ignore[assignment]
        report = SigmaDetectionEngine().evaluate(_event(), [rule])
        assert len(report.failures) == 1
        assert report.failures[0].error_type == "malformed_rule"

    def test_startswith_modifier(self):
        c = _sigma_content(detection={
            "sel": {"Image|startswith": "C:\\Windows"}, "condition": "sel",
        })
        rule = _sigma_rule(content=c)
        ev = _event(process=ProcessInfo(name="t", executable="C:\\Windows\\test.exe"))
        assert len(SigmaDetectionEngine().evaluate(ev, [rule]).results) == 1

    def test_endswith_modifier(self):
        c = _sigma_content(detection={"sel": {"Image|endswith": ".exe"}, "condition": "sel"})
        rule = _sigma_rule(content=c)
        ev = _event(process=ProcessInfo(name="t", executable="powershell.exe"))
        assert len(SigmaDetectionEngine().evaluate(ev, [rule]).results) == 1

    def test_partial_rules_match_and_fail(self):
        r_match = _sigma_rule("sigma-match",
            content=_sigma_content(detection={
                "sel": {"Image": "powershell.exe"}, "condition": "sel",
            }))
        r_fail = _sigma_rule("sigma-fail",
            content=_sigma_content(detection={
                "sel": {"CommandLine|re": ".*"}, "condition": "sel",
            }))
        ev = _event(process=ProcessInfo(name="t", executable="powershell.exe"))
        report = SigmaDetectionEngine().evaluate(ev, [r_match, r_fail])
        assert len(report.results) == 1
        assert report.results[0].rule_id == "sigma-match"
        assert len(report.failures) == 1
        assert report.failures[0].rule_id == "sigma-fail"

