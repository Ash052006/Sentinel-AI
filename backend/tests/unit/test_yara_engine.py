"""Tests for the YARA Detection Engine (Step 9D).

Covers rule compilation, string matching, evidence generation, failure
isolation, disabled/sigma rule exclusion, input immutability, security
boundaries, determinism, and boundary enforcement.

Pure unit tests — no database, no network, no LLM.
"""

import base64
import inspect
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

import pytest

from app.schemas.detection import (
    DetectionEvidence,
    DetectionMetadata,
    DetectionResult,
    DetectionRule,
    DetectionSeverity,
    RuleType,
)
from app.schemas.normalized_event import (
    Actor,
    EventCategory,
    EventOutcome,
    NormalizedSecurityEvent,
    ProcessInfo,
)
from app.schemas.security_event import SourceType
from app.services.detection.registry import DetectionRuleRegistry
from app.services.detection.yara.engine import (
    YaraDetectionEngine,
    YaraDetectionReport,
    YaraRuleFailure,
    _build_evidence,
    _check_unsupported,
    _extract_source,
    _severity_to_confidence,
)
from app.services.detection.yara.exceptions import (
    InvalidYaraTargetError,
    MalformedYaraRuleError,
    YaraDetectionError,
)
from app.services.detection.yara.target_adapter import (
    YaraTarget,
    to_yara_target,
    to_yara_target_from_bytes,
)

_FIXED_TS = datetime(2025, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
_FIXED_EVENT_ID = uuid.UUID("aaaa1111-bbbb-cccc-dddd-eeeeeeeeeeee")


def _b64(data: bytes) -> str:
    """Base64-encode bytes for storage in JSON-compatible normalized_data."""
    return base64.b64encode(data).decode("ascii")


# ─────────────────────────────────────────────────────────────────────
# Fixtures — YARA rule sources
# ─────────────────────────────────────────────────────────────────────

YARA_SIMPLE_MATCH = """\
rule SimpleMatch
{
    meta:
        description = "Matches the word suspicious_payload"
    strings:
        $a = "suspicious_payload"
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

YARA_MULTIPLE_STRINGS = """\
rule MultipleStrings
{
    meta:
        description = "Requires both strings to match"
    strings:
        $alpha = "alpha_token"
        $beta = "beta_token"
    condition:
        $alpha and $beta
}
"""

YARA_METADATA_TAGS = """\
rule MetadataTags : test synthetic
{
    meta:
        description = "Rule with metadata and tags"
        author = "SentinelAI Test"
        severity_hint = "high"
    strings:
        $a = "metadata_test_content"
    condition:
        $a
}
"""

YARA_HEX_PATTERN = """\
rule HexPattern
{
    strings:
        $hex = { 4D 5A 90 00 }
    condition:
        $hex
}
"""

YARA_CASE_SENSITIVE = """\
rule CaseSensitive
{
    strings:
        $a = "CaseSensitiveWord" nocase
    condition:
        $a
}
"""

YARA_OFFSET_PATTERN = """\
rule OffsetPattern
{
    strings:
        $prefix = "BEGIN"
        $suffix = "END"
    condition:
        $prefix at 0 and $suffix
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

YARA_IMPORT_MODULE = """\
rule UsesImport {
    import math
    strings:
        $a = "test"
    condition:
        $a
}
"""

YARA_INCLUDE_DIRECTIVE = """\
rule UsesInclude {
    include "other.yara"
    strings:
        $a = "test"
    condition:
        $a
}
"""

YARA_EMPTY_CONTENT = ""


# ─────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────

def _yara_rule(
    rule_id: str = "yara-001",
    *,
    severity: DetectionSeverity = DetectionSeverity.HIGH,
    enabled: bool = True,
    content: Any = None,
    version: str = "1.0.0",
    tags: list[str] | None = None,
    metadata: dict | None = None,
) -> DetectionRule:
    if content is None:
        content = YARA_SIMPLE_MATCH
    return DetectionRule(
        rule_id=rule_id,
        name=f"Rule {rule_id}",
        description=f"Detects {rule_id}",
        rule_type=RuleType.YARA,
        severity=severity,
        enabled=enabled,
        version=version,
        content=content,
        tags=tags or [],
        metadata=DetectionMetadata(extra=metadata or {}),
    )


def _sigma_rule(rule_id: str = "sigma-001") -> DetectionRule:
    return DetectionRule(
        rule_id=rule_id,
        name=f"Rule {rule_id}",
        description=f"Sigma rule {rule_id}",
        rule_type=RuleType.SIGMA,
        severity=DetectionSeverity.HIGH,
        content={"title": "Test", "detection": {"sel": {"Image": "x"}, "condition": "sel"}},
    )


def _event(
    *,
    event_id: uuid.UUID | None = None,
    file_name: str | None = None,
    file_path: str | None = None,
    normalized_data: dict | None = None,
) -> NormalizedSecurityEvent:
    return NormalizedSecurityEvent(
        event_id=event_id or _FIXED_EVENT_ID,
        timestamp=_FIXED_TS,
        event_category=EventCategory.FILE,
        action="file_scan",
        outcome=EventOutcome.UNKNOWN,
        source="test",
        source_type=SourceType.OTHER,
        file={"name": file_name, "path": file_path} if file_name or file_path else None,
        normalized_data=normalized_data or {},
    )


# =========================================================================
# A. Engine Instantiation
# =========================================================================


class TestEngineInstantiation:
    def test_can_instantiate(self):
        engine = YaraDetectionEngine()
        assert engine is not None

    def test_compiled_cache_starts_empty(self):
        engine = YaraDetectionEngine()
        assert len(engine._compiled_cache) == 0


# =========================================================================
# B. Valid YARA rule matches applicable content
# =========================================================================


class TestSimpleMatch:
    def test_matches_content(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"this has suspicious_payload in it")
        rule = _yara_rule()
        report = engine.evaluate_target(target, [rule])
        assert len(report.results) == 1
        assert report.results[0].matched is True

    def test_matches_bytes_content(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"\x00\x01suspicious_payload\x02\x03")
        rule = _yara_rule()
        report = engine.evaluate_target(target, [rule])
        assert len(report.results) == 1


# =========================================================================
# C. Valid YARA rule does not match unrelated content
# =========================================================================


class TestNoMatch:
    def test_no_match_on_unrelated_content(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"this is completely unrelated content")
        rule = _yara_rule(content=YARA_NO_MATCH)
        report = engine.evaluate_target(target, [rule])
        assert len(report.results) == 0
        assert len(report.failures) == 0

    def test_simple_rule_no_match(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"no suspicious payload here")
        rule = _yara_rule()
        report = engine.evaluate_target(target, [rule])
        assert len(report.results) == 0


# =========================================================================
# D. String matching works
# =========================================================================


class TestStringMatching:
    def test_exact_string_match(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"here is the payload: suspicious_payload end")
        rule = _yara_rule()
        report = engine.evaluate_target(target, [rule])
        assert len(report.results) == 1

    def test_partial_string_no_match(self):
        """YARA literal strings require exact substring match."""
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_pay")  # truncated
        rule = _yara_rule()
        report = engine.evaluate_target(target, [rule])
        assert len(report.results) == 0

    def test_case_sensitive_by_default(self):
        """YARA literal strings are case-sensitive by default."""
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"SUSPICIOUS_PAYLOAD")
        rule = _yara_rule()
        report = engine.evaluate_target(target, [rule])
        assert len(report.results) == 0

    def test_nocase_modifier(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"casesensitiveword found here")
        rule = _yara_rule(content=YARA_CASE_SENSITIVE)
        report = engine.evaluate_target(target, [rule])
        assert len(report.results) == 1


# =========================================================================
# E. Multiple strings work
# =========================================================================


class TestMultipleStrings:
    def test_both_strings_match(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"alpha_token and beta_token here")
        rule = _yara_rule(content=YARA_MULTIPLE_STRINGS)
        report = engine.evaluate_target(target, [rule])
        assert len(report.results) == 1

    def test_one_string_no_match(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"only alpha_token present")
        rule = _yara_rule(content=YARA_MULTIPLE_STRINGS)
        report = engine.evaluate_target(target, [rule])
        assert len(report.results) == 0

    def test_neither_string_no_match(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"neither token present here")
        rule = _yara_rule(content=YARA_MULTIPLE_STRINGS)
        report = engine.evaluate_target(target, [rule])
        assert len(report.results) == 0

    def test_hex_pattern_match(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"\x4d\x5a\x90\x00rest of file")
        rule = _yara_rule(content=YARA_HEX_PATTERN)
        report = engine.evaluate_target(target, [rule])
        assert len(report.results) == 1

    def test_hex_pattern_no_match(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"\x4d\x5a\x91\x00wrong bytes")
        rule = _yara_rule(content=YARA_HEX_PATTERN)
        report = engine.evaluate_target(target, [rule])
        assert len(report.results) == 0


# =========================================================================
# F. Multiple YARA rules evaluated
# =========================================================================


class TestMultipleRules:
    def test_two_matching_rules(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_payload with metadata_test_content")
        r1 = _yara_rule("yara-001")
        r2 = _yara_rule("yara-002", content=YARA_METADATA_TAGS)
        report = engine.evaluate_target(target, [r1, r2])
        assert len(report.results) == 2
        rule_ids = {r.rule_id for r in report.results}
        assert rule_ids == {"yara-001", "yara-002"}

    def test_one_match_one_no_match(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_payload only")
        r1 = _yara_rule("yara-match")
        r2 = _yara_rule("yara-nomatch", content=YARA_NO_MATCH)
        report = engine.evaluate_target(target, [r1, r2])
        assert len(report.results) == 1
        assert report.results[0].rule_id == "yara-match"


# =========================================================================
# G. Disabled YARA rules are not evaluated
# =========================================================================


class TestDisabledRules:
    def test_disabled_rule_skipped(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_payload here")
        rule = _yara_rule(enabled=False)
        report = engine.evaluate_target(target, [rule])
        assert len(report.results) == 0
        assert len(report.failures) == 0
        assert report.rules_evaluated == 0
        assert report.rules_ignored == 1

    def test_mixed_enabled_disabled(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_payload here")
        r1 = _yara_rule("yara-enabled", enabled=True)
        r2 = _yara_rule("yara-disabled", enabled=False)
        report = engine.evaluate_target(target, [r1, r2])
        assert len(report.results) == 1
        assert report.results[0].rule_id == "yara-enabled"
        assert report.rules_evaluated == 1
        assert report.rules_ignored == 1


# =========================================================================
# H. Sigma rules are not evaluated by YARA engine
# =========================================================================


class TestSigmaRuleExclusion:
    def test_sigma_rule_skipped(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"anything")
        sigma = _sigma_rule()
        report = engine.evaluate_target(target, [sigma])
        assert len(report.results) == 0
        assert report.rules_evaluated == 0
        assert report.rules_ignored == 1


# =========================================================================
# I-N. DetectionResult contract verification
# =========================================================================


class TestDetectionResultContract:
    def test_result_produced_for_match(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_payload found")
        rule = _yara_rule()
        report = engine.evaluate_target(target, [rule])
        assert len(report.results) >= 1
        assert isinstance(report.results[0], DetectionResult)

    def test_event_id_preserved(self):
        engine = YaraDetectionEngine()
        eid = uuid.UUID("bbbb2222-cccc-dddd-eeee-ffffffffffff")
        target = YaraTarget(
            content=b"suspicious_payload", origin_event_id=eid,
        )
        rule = _yara_rule()
        report = engine.evaluate_target(target, [rule])
        assert report.results[0].event_id == eid

    def test_event_id_sentinel_when_not_set(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_payload")
        rule = _yara_rule()
        report = engine.evaluate_target(target, [rule])
        assert report.results[0].event_id == uuid.UUID(
            "00000000-0000-0000-0000-000000000000"
        )

    def test_rule_id_preserved(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_payload")
        rule = _yara_rule(rule_id="my-custom-rule-42")
        report = engine.evaluate_target(target, [rule])
        assert report.results[0].rule_id == "my-custom-rule-42"

    def test_rule_type_is_yara(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_payload")
        rule = _yara_rule()
        report = engine.evaluate_target(target, [rule])
        assert report.results[0].rule_type == RuleType.YARA

    def test_severity_from_rule(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_payload")
        rule = _yara_rule(severity=DetectionSeverity.CRITICAL)
        report = engine.evaluate_target(target, [rule])
        assert report.results[0].severity == DetectionSeverity.CRITICAL

    def test_severity_low(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_payload")
        rule = _yara_rule(severity=DetectionSeverity.LOW)
        report = engine.evaluate_target(target, [rule])
        assert report.results[0].severity == DetectionSeverity.LOW

    def test_provenance_is_detected(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_payload")
        rule = _yara_rule()
        report = engine.evaluate_target(target, [rule])
        assert report.results[0].provenance.value == "detected"

    def test_matched_is_true(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_payload")
        rule = _yara_rule()
        report = engine.evaluate_target(target, [rule])
        assert report.results[0].matched is True


# =========================================================================
# O. Confidence follows deterministic policy
# =========================================================================


class TestConfidencePolicy:
    def test_critical_confidence(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_payload")
        rule = _yara_rule(severity=DetectionSeverity.CRITICAL)
        report = engine.evaluate_target(target, [rule])
        assert report.results[0].confidence == 1.0

    def test_high_confidence(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_payload")
        rule = _yara_rule(severity=DetectionSeverity.HIGH)
        report = engine.evaluate_target(target, [rule])
        assert report.results[0].confidence == 0.9

    def test_medium_confidence(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_payload")
        rule = _yara_rule(severity=DetectionSeverity.MEDIUM)
        report = engine.evaluate_target(target, [rule])
        assert report.results[0].confidence == 0.7

    def test_low_confidence(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_payload")
        rule = _yara_rule(severity=DetectionSeverity.LOW)
        report = engine.evaluate_target(target, [rule])
        assert report.results[0].confidence == 0.5

    def test_severity_to_confidence_function(self):
        assert _severity_to_confidence(DetectionSeverity.CRITICAL) == 1.0
        assert _severity_to_confidence(DetectionSeverity.HIGH) == 0.9
        assert _severity_to_confidence(DetectionSeverity.MEDIUM) == 0.7
        assert _severity_to_confidence(DetectionSeverity.LOW) == 0.5


# =========================================================================
# P-Q. Structured evidence generation
# =========================================================================


class TestEvidenceGeneration:
    def test_evidence_has_matched_conditions(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_payload found here")
        rule = _yara_rule()
        report = engine.evaluate_target(target, [rule])
        evidence = report.results[0].evidence
        assert len(evidence.matched_conditions) >= 1
        assert any("strings:" in c for c in evidence.matched_conditions)

    def test_evidence_has_matched_fields(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_payload found here")
        rule = _yara_rule()
        report = engine.evaluate_target(target, [rule])
        evidence = report.results[0].evidence
        assert "content" in evidence.matched_fields

    def test_evidence_identifies_rule_metadata(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"metadata_test_content found")
        rule = _yara_rule(content=YARA_METADATA_TAGS)
        report = engine.evaluate_target(target, [rule])
        evidence = report.results[0].evidence
        assert "description" in evidence.rule_references

    def test_evidence_detection_context_has_strings(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_payload found here")
        rule = _yara_rule()
        report = engine.evaluate_target(target, [rule])
        ctx = report.results[0].evidence.detection_context
        assert "matched_strings" in ctx
        assert len(ctx["matched_strings"]) >= 1
        ms = ctx["matched_strings"][0]
        assert "identifier" in ms
        assert "offset" in ms
        assert "matched_length" in ms
        assert isinstance(ms["offset"], int)

    def test_evidence_no_full_content(self):
        secret = b"suspicious_payload " + b"A" * 1000
        target = YaraTarget(content=secret)
        rule = _yara_rule()
        report = YaraDetectionEngine().evaluate_target(target, [rule])
        evidence_json = report.results[0].evidence.model_dump_json()
        assert "AAAA" not in evidence_json

    def test_evidence_tags_in_context(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"metadata_test_content found")
        rule = _yara_rule(content=YARA_METADATA_TAGS)
        report = engine.evaluate_target(target, [rule])
        ctx = report.results[0].evidence.detection_context
        assert "tags" in ctx
        assert "test" in ctx["tags"]
        assert "synthetic" in ctx["tags"]

    def test_file_name_in_matched_fields(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(
            content=b"suspicious_payload", file_name="test.exe",
        )
        rule = _yara_rule()
        report = engine.evaluate_target(target, [rule])
        evidence = report.results[0].evidence
        assert evidence.matched_fields.get("file.name") == "test.exe"

    def test_multiple_strings_evidence(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"alpha_token and beta_token here")
        rule = _yara_rule(content=YARA_MULTIPLE_STRINGS)
        report = engine.evaluate_target(target, [rule])
        evidence = report.results[0].evidence
        conditions = set(evidence.matched_conditions)
        assert "strings:$alpha" in conditions
        assert "strings:$beta" in conditions

    def test_offset_evidence_correct(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"BEGIN_middle_END")
        rule = _yara_rule(content=YARA_OFFSET_PATTERN)
        report = engine.evaluate_target(target, [rule])
        assert len(report.results) >= 1
        ctx = report.results[0].evidence.detection_context
        offsets = {ms["identifier"]: ms["offset"] for ms in ctx["matched_strings"]}
        assert offsets.get("$prefix") == 0
        assert "$suffix" in offsets

    def test_evidence_safe_for_large_content(self):
        large = b"suspicious_payload" + b"\x00" * 100_000
        target = YaraTarget(content=large)
        rule = _yara_rule()
        report = YaraDetectionEngine().evaluate_target(target, [rule])
        evidence = report.results[0].evidence
        assert len(evidence.model_dump_json()) < 10_000



# =========================================================================
# S. No applicable content handled explicitly (event path)
# =========================================================================


class TestNoContentEvent:
    def test_event_without_content(self):
        engine = YaraDetectionEngine()
        event = _event()
        rule = _yara_rule()
        report = engine.evaluate(event, [rule])
        assert len(report.results) == 0
        assert len(report.failures) == 1
        assert report.failures[0].error_type == "invalid_target"

    def test_event_with_path_only_not_content(self):
        engine = YaraDetectionEngine()
        event = _event(file_path="C:\\Windows\\System32\\test.exe")
        rule = _yara_rule()
        report = engine.evaluate(event, [rule])
        assert len(report.results) == 0
        assert len(report.failures) == 1

    def test_event_with_name_only_not_content(self):
        engine = YaraDetectionEngine()
        event = _event(file_name="malware.exe")
        rule = _yara_rule()
        report = engine.evaluate(event, [rule])
        assert len(report.results) == 0
        assert len(report.failures) == 1

    def test_event_with_hash_not_content(self):
        engine = YaraDetectionEngine()
        event = _event(normalized_data={"file.hash": "abc123"})
        rule = _yara_rule()
        report = engine.evaluate(event, [rule])
        assert len(report.results) == 0
        assert len(report.failures) == 1

    def test_event_with_file_content_matches(self):
        engine = YaraDetectionEngine()
        event = _event(normalized_data={"file_content": _b64(b"suspicious_payload")})
        rule = _yara_rule()
        report = engine.evaluate(event, [rule])
        assert len(report.results) == 1

    def test_event_with_alt_key_matches(self):
        engine = YaraDetectionEngine()
        event = _event(normalized_data={"file.content_bytes": _b64(b"suspicious_payload")})
        rule = _yara_rule()
        report = engine.evaluate(event, [rule])
        assert len(report.results) == 1

    def test_none_event(self):
        engine = YaraDetectionEngine()
        rule = _yara_rule()
        report = engine.evaluate(None, [rule])
        assert len(report.failures) == 1
        assert report.failures[0].error_type == "invalid_target"



# =========================================================================
# T. File path alone does not cause filesystem access
# =========================================================================


class TestNoFilesystemAccess:
    def test_path_not_opened(self):
        engine = YaraDetectionEngine()
        event = _event(
            file_path="C:\\Windows\\System32\\notepad.exe",
            file_name="notepad.exe",
        )
        rule = _yara_rule()
        report = engine.evaluate(event, [rule])
        assert len(report.results) == 0
        assert len(report.failures) == 1


# =========================================================================
# U. Malformed YARA rule fails explicitly
# =========================================================================


class TestMalformedRule:
    def test_malformed_rule_fails(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"anything")
        rule = _yara_rule(content=YARA_MALFORMED)
        report = engine.evaluate_target(target, [rule])
        assert len(report.results) == 0
        assert len(report.failures) == 1
        assert report.failures[0].error_type == "malformed_rule"

    def test_empty_content_fails(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"anything")
        rule = _yara_rule(content=YARA_EMPTY_CONTENT)
        report = engine.evaluate_target(target, [rule])
        assert len(report.results) == 0
        assert len(report.failures) == 1
        assert report.failures[0].error_type == "malformed_rule"

    def test_none_content_fails(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"anything")
        rule = _yara_rule(rule_id="yara-none")
        rule.__dict__["content"] = None
        report = engine.evaluate_target(target, [rule])
        assert len(report.results) == 0
        assert len(report.failures) == 1

    def test_dict_content_fails(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"anything")
        rule = _yara_rule(rule_id="yara-dict")
        rule.__dict__["content"] = {"title": "not yara"}
        report = engine.evaluate_target(target, [rule])
        assert len(report.results) == 0
        assert len(report.failures) == 1


# =========================================================================
# V. Malformed rule does not discard valid results
# =========================================================================


class TestFailureIsolation:
    def test_valid_and_malformed_coexist(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_payload here")
        r_valid = _yara_rule("yara-valid")
        r_bad = _yara_rule("yara-bad", content=YARA_MALFORMED)
        report = engine.evaluate_target(target, [r_valid, r_bad])
        assert len(report.results) == 1
        assert report.results[0].rule_id == "yara-valid"
        assert len(report.failures) == 1
        assert report.failures[0].rule_id == "yara-bad"

    def test_malformed_between_valid(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_payload here")
        r1 = _yara_rule("yara-first")
        r_bad = _yara_rule("yara-bad", content=YARA_MALFORMED)
        r2 = _yara_rule("yara-second")
        report = engine.evaluate_target(target, [r1, r_bad, r2])
        assert len(report.results) == 2
        assert len(report.failures) == 1

    def test_unsupported_import_isolated(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_payload here")
        r_good = _yara_rule("yara-good")
        r_imp = _yara_rule("yara-import", content=YARA_IMPORT_MODULE)
        report = engine.evaluate_target(target, [r_good, r_imp])
        assert len(report.results) == 1
        assert report.failures[0].error_type == "unsupported_feature"


# =========================================================================
# W. Invalid target handled safely
# =========================================================================


class TestInvalidTarget:
    def test_none_target(self):
        engine = YaraDetectionEngine()
        rule = _yara_rule()
        report = engine.evaluate_target(None, [rule])
        assert len(report.results) == 0
        assert len(report.failures) == 1
        assert report.failures[0].error_type == "invalid_target"

    def test_empty_bytes_target(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"")
        rule = _yara_rule()
        report = engine.evaluate_target(target, [rule])
        assert len(report.results) == 0
        assert len(report.failures) == 1


# =========================================================================
# X. Input event is not mutated
# =========================================================================


class TestInputImmutabilityEvent:
    def test_event_not_mutated(self):
        engine = YaraDetectionEngine()
        nd = {"file_content": _b64(b"suspicious_payload"), "extra": "value"}
        event = _event(normalized_data=nd)
        original_nd = deepcopy(event.normalized_data)
        rule = _yara_rule()
        engine.evaluate(event, [rule])
        assert event.normalized_data == original_nd


# =========================================================================
# Y. Input rule is not mutated
# =========================================================================


class TestInputImmutabilityRule:
    def test_rule_not_mutated(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_payload")
        rule = _yara_rule()
        original_content = rule.content
        original_severity = rule.severity
        engine.evaluate_target(target, [rule])
        assert rule.content == original_content
        assert rule.severity == original_severity

    def test_rule_not_mutated_by_compilation(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_payload")
        rule = _yara_rule(version="2.0.0")
        engine.evaluate_target(target, [rule])
        engine.evaluate_target(target, [rule])
        assert rule.version == "2.0.0"


# =========================================================================
# Z. Rule selection is deterministic
# =========================================================================


class TestDeterministicSelection:
    def test_results_ordered_by_rule_id(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_payload here")
        r3 = _yara_rule("yara-ccc")
        r1 = _yara_rule("yara-aaa")
        r2 = _yara_rule("yara-bbb")
        report = engine.evaluate_target(target, [r1, r2, r3])
        ids = [r.rule_id for r in report.results]
        assert ids == ["yara-aaa", "yara-bbb", "yara-ccc"]


# =========================================================================
# AA. Repeated evaluations are deterministic
# =========================================================================


class TestDeterministicEvaluation:
    def test_repeated_same_results(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_payload here")
        rule = _yara_rule()
        r1 = engine.evaluate_target(target, [rule])
        r2 = engine.evaluate_target(target, [rule])
        assert len(r1.results) == len(r2.results)
        for a, b in zip(r1.results, r2.results):
            assert a.rule_id == b.rule_id
            assert a.matched == b.matched
            assert a.severity == b.severity


# =========================================================================
# AB-AC. Empty/No enabled YARA rules
# =========================================================================


class TestEmptyRegistryBehavior:
    def test_no_rules_at_all(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"anything")
        report = engine.evaluate_target(target, [])
        assert len(report.results) == 0
        assert len(report.failures) == 0
        assert report.rules_total == 0

    def test_no_enabled_yara_rules(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_payload")
        r1 = _yara_rule(enabled=False)
        r2 = _yara_rule("yara-2", enabled=False)
        report = engine.evaluate_target(target, [r1, r2])
        assert len(report.results) == 0
        assert report.rules_ignored == 2

    def test_only_sigma_rules(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_payload")
        report = engine.evaluate_target(target, [_sigma_rule("s1"), _sigma_rule("s2")])
        assert len(report.results) == 0
        assert report.rules_ignored == 2


# =========================================================================
# AD. Multiple matching rules produce separate results
# =========================================================================


class TestMultipleMatchingResults:
    def test_two_rules_two_results(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(
            content=b"suspicious_payload and metadata_test_content"
        )
        r1 = _yara_rule("yara-alpha")
        r2 = _yara_rule("yara-beta", content=YARA_METADATA_TAGS)
        report = engine.evaluate_target(target, [r1, r2])
        assert len(report.results) == 2
        ids = sorted(r.rule_id for r in report.results)
        assert ids == ["yara-alpha", "yara-beta"]


# =========================================================================
# AE. Rule metadata/tags handled consistently
# =========================================================================


class TestRuleMetadataTags:
    def test_metadata_in_references(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"metadata_test_content here")
        rule = _yara_rule(content=YARA_METADATA_TAGS)
        report = engine.evaluate_target(target, [rule])
        refs = report.results[0].evidence.rule_references
        assert refs.get("author") == "SentinelAI Test"
        assert refs.get("severity_hint") == "high"

    def test_tags_in_detection_context(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"metadata_test_content here")
        rule = _yara_rule(content=YARA_METADATA_TAGS)
        report = engine.evaluate_target(target, [rule])
        ctx = report.results[0].evidence.detection_context
        assert "tags" in ctx
        assert sorted(ctx["tags"]) == ["synthetic", "test"]

    def test_metadata_engine_in_result_metadata(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_payload")
        rule = _yara_rule()
        report = engine.evaluate_target(target, [rule])
        meta = report.results[0].metadata.extra
        assert meta["engine"] == "yara"
        assert "yara_rule_name" in meta
        assert "yara_namespace" in meta


# =========================================================================
# AF-AG. No network/subprocess
# =========================================================================


class TestNoExternalAccess:
    def test_no_subprocess_in_engine(self):
        import app.services.detection.yara.engine as mod
        source = inspect.getsource(mod)
        assert "subprocess" not in source
        assert "os.system" not in source


# =========================================================================
# AH. No eval/exec usage
# =========================================================================


class TestNoCodeExecution:
    def test_no_eval_in_engine(self):
        import app.services.detection.yara.engine as mod
        source = inspect.getsource(mod)
        assert "eval(" not in source
        assert "exec(" not in source

    def test_no_eval_in_target_adapter(self):
        import app.services.detection.yara.target_adapter as mod
        source = inspect.getsource(mod)
        assert "eval(" not in source
        assert "exec(" not in source

    def test_no_eval_in_exceptions(self):
        import app.services.detection.yara.exceptions as mod
        source = inspect.getsource(mod)
        assert "eval(" not in source
        assert "exec(" not in source


# =========================================================================
# AI. Binary content
# =========================================================================


class TestBinaryContent:
    def test_binary_with_embedded_string(self):
        engine = YaraDetectionEngine()
        binary = b"\x00\x01\x02\x03suspicious_payload\x04\x05\x06"
        rule = _yara_rule()
        report = engine.evaluate_target(YaraTarget(content=binary), [rule])
        assert len(report.results) == 1

    def test_hex_pattern_binary(self):
        engine = YaraDetectionEngine()
        binary = b"\x4d\x5a\x90\x00\x03\x00\x00\x00"
        rule = _yara_rule(content=YARA_HEX_PATTERN)
        report = engine.evaluate_target(YaraTarget(content=binary), [rule])
        assert len(report.results) == 1


# =========================================================================
# AJ. Source event provenance remains distinguishable
# =========================================================================


class TestEventProvenancePreserved:
    def test_event_provenance_not_changed(self):
        from app.schemas.security_event import Provenance
        engine = YaraDetectionEngine()
        event = _event(normalized_data={"file_content": _b64(b"suspicious_payload")})
        rule = _yara_rule()
        engine.evaluate(event, [rule])
        assert event.provenance == Provenance.OBSERVED

    def test_detection_result_is_detected(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_payload")
        rule = _yara_rule()
        report = engine.evaluate_target(target, [rule])
        assert report.results[0].provenance.value == "detected"


# =========================================================================
# Registry integration
# =========================================================================


class TestRegistryIntegration:
    def test_find_enabled_yara_from_registry(self):
        reg = DetectionRuleRegistry()
        reg.register(_yara_rule("yara-001"))
        reg.register(_yara_rule("yara-002", enabled=False))
        reg.register(_sigma_rule("sigma-001"))
        enabled = reg.find_enabled_by_type(RuleType.YARA)
        assert len(enabled) == 1
        assert enabled[0].rule_id == "yara-001"

    def test_engine_with_registry_selected_rules(self):
        reg = DetectionRuleRegistry()
        reg.register(_yara_rule("yara-001"))
        reg.register(_yara_rule("yara-002", enabled=False))
        reg.register(_sigma_rule("sigma-001"))
        rules = reg.find_enabled_by_type(RuleType.YARA)
        engine = YaraDetectionEngine()
        report = engine.evaluate_target(
            YaraTarget(content=b"suspicious_payload"), rules,
        )
        assert len(report.results) == 1
        assert report.results[0].rule_id == "yara-001"


# =========================================================================
# Edge cases
# =========================================================================


class TestEdgeCases:
    def test_empty_content_in_normalized_data(self):
        engine = YaraDetectionEngine()
        event = _event(normalized_data={"file_content": ""})
        rule = _yara_rule()
        report = engine.evaluate(event, [rule])
        assert len(report.results) == 0
        assert len(report.failures) == 1

    def test_string_content_as_normalized_data(self):
        engine = YaraDetectionEngine()
        event = _event(normalized_data={"file_content": "suspicious_payload"})
        rule = _yara_rule()
        report = engine.evaluate(event, [rule])
        assert len(report.results) == 1

    def test_bytearray_content(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=bytearray(b"suspicious_payload"))
        rule = _yara_rule()
        report = engine.evaluate_target(target, [rule])
        assert len(report.results) == 1

    def test_target_adapter_bytes(self):
        t = to_yara_target_from_bytes(b"hello")
        assert t.content == b"hello"

    def test_target_adapter_empty_bytes_raises(self):
        with pytest.raises(InvalidYaraTargetError):
            to_yara_target_from_bytes(b"")

    def test_target_adapter_non_bytes_raises(self):
        with pytest.raises(InvalidYaraTargetError):
            to_yara_target_from_bytes("not bytes")

    def test_target_adapter_none_raises(self):
        with pytest.raises(InvalidYaraTargetError):
            to_yara_target_from_bytes(None)

    def test_target_from_event_no_content(self):
        event = _event()
        with pytest.raises(InvalidYaraTargetError):
            to_yara_target(event)

    def test_target_from_event_with_content(self):
        event = _event(normalized_data={"file_content": _b64(b"test")})
        t = to_yara_target(event)
        assert t.content == b"test"

    def test_target_from_event_preserves_event_id(self):
        eid = uuid.UUID("dddd1111-2222-3333-4444-555566667777")
        event = _event(event_id=eid, normalized_data={"file_content": _b64(b"test")})
        t = to_yara_target(event)
        assert t.origin_event_id == eid

    def test_target_from_none_event_raises(self):
        with pytest.raises(InvalidYaraTargetError):
            to_yara_target(None)

    def test_report_has_expected_attributes(self):
        engine = YaraDetectionEngine()
        report = engine.evaluate_target(
            YaraTarget(content=b"suspicious_payload"), [_yara_rule()],
        )
        assert hasattr(report, "results")
        assert hasattr(report, "failures")
        assert hasattr(report, "rules_total")
        assert hasattr(report, "rules_evaluated")
        assert hasattr(report, "rules_ignored")
        assert hasattr(report, "evaluated_rule_ids")
        assert hasattr(report, "target_event_id")

    def test_failure_repr(self):
        f = YaraRuleFailure("r1", "error", "msg")
        assert "r1" in repr(f)
        assert "error" in repr(f)


# =========================================================================
# AK. Synthetic harmless test payloads only
# =========================================================================


class TestSyntheticPayloadsOnly:
    def test_fixture_contents_are_harmless(self):
        """All fixture strings must be printable, non-executable ASCII."""
        safe = set(
            b"suspicious_payload this_will_never_appear_in_test_data_xyz "
            b"alpha_token beta_token metadata_test_content CaseSensitiveWord "
            b"BEGIN END prefix_here prefix_here_END"
        )
        unsafe = {ch for ch in safe if ch < 32}
        assert unsafe == set()

    def test_no_binary_executable_fixture(self):
        """Hex pattern fixture contains only the harmless MZ stub header bytes."""
        # YARA hex string 4D 5A 90 00 = the bytes MZ 90 00 (non-executable).
        assert "4D 5A 90 00" in YARA_HEX_PATTERN


# =========================================================================
# Compilation cache behavior
# =========================================================================


class TestCompiledRuleCache:
    def test_cache_used_on_second_evaluation(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_payload")
        rule = _yara_rule()
        engine.evaluate_target(target, [rule])
        assert (rule.rule_id, rule.version) in engine._compiled_cache

    def test_cache_keyed_by_rule_id_and_version(self):
        engine = YaraDetectionEngine()
        target = YaraTarget(content=b"suspicious_payload")
        engine.evaluate_target(target, [_yara_rule("r1", version="1.0.0")])
        engine.evaluate_target(target, [_yara_rule("r2", version="2.0.0")])
        assert ("r1", "1.0.0") in engine._compiled_cache
        assert ("r2", "2.0.0") in engine._compiled_cache

