"""Tests for the Detection Contract (Step 9A).

Covers DetectionRule and DetectionResult schema validation, enum
coverage, structured evidence, metadata, provenance, secret-safety,
serialisation round-trips, and contract boundary enforcement.

These are pure unit tests of the **contract** — no database connection,
no Sigma/YARA engine invocation, and no network calls are made.
"""

import uuid
from datetime import datetime, timezone

import pytest

from app.schemas.detection import (
    DetectionEvidence,
    DetectionMetadata,
    DetectionResult,
    DetectionRule,
    DetectionSeverity,
    RuleType,
)
from app.schemas.security_event import Provenance


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FIXED_TS = datetime(2025, 8, 1, 12, 0, 0, tzinfo=timezone.utc)


def _minimal_rule(**overrides) -> dict:
    """Return a minimal valid DetectionRule payload."""
    base: dict = {
        "rule_id": "sigma-credential-access-001",
        "name": "Credential Access via PowerShell",
        "description": "Detects credential dumping via PowerShell",
        "rule_type": RuleType.SIGMA,
        "severity": DetectionSeverity.HIGH,
    }
    base.update(overrides)
    return base


def _minimal_evidence(**overrides) -> DetectionEvidence:
    """Return a minimal valid DetectionEvidence instance."""
    base: dict = {
        "matched_conditions": ["condition_1"],
        "matched_fields": {"CommandLine": "powershell -enc AABC"},
        "rule_references": {"attack": "T1059.001"},
        "detection_context": {"engine": "es-dsl"},
    }
    base.update(overrides)
    return DetectionEvidence(**base)


def _minimal_result(**overrides) -> dict:
    """Return a minimal valid DetectionResult payload."""
    base: dict = {
        "event_id": uuid.UUID("11111111-1111-1111-1111-111111111111"),
        "rule_id": "sigma-credential-access-001",
        "rule_type": RuleType.SIGMA,
        "matched": True,
        "severity": DetectionSeverity.HIGH,
        "confidence": 0.9,
        "timestamp": _FIXED_TS,
        "evidence": _minimal_evidence(),
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# A. RuleType enum values
# ---------------------------------------------------------------------------


class TestRuleTypeEnum:
    """A: RuleType enum covers the expected detection engine types."""

    def test_sigma_value(self):
        assert RuleType.SIGMA.value == "sigma"

    def test_yara_value(self):
        assert RuleType.YARA.value == "yara"

    def test_all_values(self):
        assert {rt.value for rt in RuleType} == {"sigma", "yara"}


# ---------------------------------------------------------------------------
# B. DetectionSeverity enum values
# ---------------------------------------------------------------------------


class TestDetectionSeverityEnum:
    """B: DetectionSeverity covers the standard SIEM/SOAR levels."""

    def test_low_value(self):
        assert DetectionSeverity.LOW.value == "low"

    def test_medium_value(self):
        assert DetectionSeverity.MEDIUM.value == "medium"

    def test_high_value(self):
        assert DetectionSeverity.HIGH.value == "high"

    def test_critical_value(self):
        assert DetectionSeverity.CRITICAL.value == "critical"

    def test_all_values(self):
        assert {s.value for s in DetectionSeverity} == {
            "low", "medium", "high", "critical",
        }


# ---------------------------------------------------------------------------
# C. DetectionEvidence valid construction
# ---------------------------------------------------------------------------


class TestDetectionEvidenceConstruction:
    """C: DetectionEvidence holds all four structured sections."""

    def test_valid_evidence(self):
        ev = _minimal_evidence()
        assert ev.matched_conditions == ["condition_1"]
        assert ev.matched_fields == {"CommandLine": "powershell -enc AABC"}
        assert ev.rule_references == {"attack": "T1059.001"}
        assert ev.detection_context == {"engine": "es-dsl"}

    def test_empty_sections_accepted(self):
        ev = DetectionEvidence(
            matched_conditions=[],
            matched_fields={},
            rule_references={},
            detection_context={},
        )
        assert ev.matched_conditions == []
        assert ev.matched_fields == {}


# ---------------------------------------------------------------------------
# D. DetectionEvidence JSON serialization round-trip
# ---------------------------------------------------------------------------


class TestDetectionEvidenceSerialization:
    """D: DetectionEvidence round-trips through JSON cleanly."""

    def test_json_round_trip(self):
        original = _minimal_evidence()
        dumped = original.model_dump()
        restored = DetectionEvidence.model_validate(dumped)
        assert restored.matched_conditions == original.matched_conditions
        assert restored.matched_fields == original.matched_fields
        assert restored.rule_references == original.rule_references
        assert restored.detection_context == original.detection_context

    def test_json_string_round_trip(self):
        original = _minimal_evidence()
        json_str = original.model_dump_json()
        restored = DetectionEvidence.model_validate_json(json_str)
        assert restored == original


# ---------------------------------------------------------------------------
# E. DetectionEvidence rejects non-JSON-serializable values
# ---------------------------------------------------------------------------


class TestDetectionEvidenceRejectsNonSerializable:
    """E: DetectionEvidence does not accept non-JSON-serializable data."""

    def test_object_in_matched_fields_rejected(self):
        with pytest.raises(Exception):
            DetectionEvidence(matched_fields={"bad": object()})

    def test_object_in_detection_context_rejected(self):
        with pytest.raises(Exception):
            DetectionEvidence(detection_context={"bad": object()})


# ---------------------------------------------------------------------------
# F. DetectionMetadata valid construction and defaults
# ---------------------------------------------------------------------------


class TestDetectionMetadataConstruction:
    """F: DetectionMetadata accepts valid inputs and uses sensible defaults."""

    def test_valid_metadata(self):
        md = DetectionMetadata(
            rule_version="2.1.0",
            engine_version="1.5.0",
            execution_time_ms=42.5,
            total_rules_evaluated=10,
        )
        assert md.rule_version == "2.1.0"
        assert md.engine_version == "1.5.0"
        assert md.execution_time_ms == 42.5
        assert md.total_rules_evaluated == 10

    def test_defaults_applied(self):
        md = DetectionMetadata()
        assert md.rule_version is None
        assert md.engine_version is None
        assert md.execution_time_ms is None
        assert md.total_rules_evaluated is None
        assert md.extra == {}

    def test_zero_execution_time_accepted(self):
        md = DetectionMetadata(execution_time_ms=0.0)
        assert md.execution_time_ms == 0.0


# ---------------------------------------------------------------------------
# G. DetectionMetadata rejects negative execution_time_ms
# ---------------------------------------------------------------------------


class TestDetectionMetadataNegativeTime:
    """G: Negative execution_time_ms is not allowed."""

    def test_negative_execution_time_rejected(self):
        with pytest.raises(Exception):
            DetectionMetadata(execution_time_ms=-1.0)

    def test_large_positive_accepted(self):
        md = DetectionMetadata(execution_time_ms=999999.9)
        assert md.execution_time_ms == 999999.9


# ---------------------------------------------------------------------------
# H. DetectionRule valid construction and defaults
# ---------------------------------------------------------------------------


class TestDetectionRuleConstruction:
    """H: DetectionRule creates valid instances with defaults."""

    def test_valid_rule(self):
        rule = DetectionRule(**_minimal_rule())
        assert rule.rule_id == "sigma-credential-access-001"
        assert rule.name == "Credential Access via PowerShell"
        assert rule.description == "Detects credential dumping via PowerShell"
        assert rule.rule_type == RuleType.SIGMA
        assert rule.severity == DetectionSeverity.HIGH

    def test_defaults_applied(self):
        rule = DetectionRule(**_minimal_rule())
        assert rule.enabled is True
        assert rule.version == "1.0.0"
        assert isinstance(rule.metadata, DetectionMetadata)

    def test_disabled_rule_accepted(self):
        rule = DetectionRule(**_minimal_rule(enabled=False))
        assert rule.enabled is False

    def test_custom_version_accepted(self):
        rule = DetectionRule(**_minimal_rule(version="3.2.1"))
        assert rule.version == "3.2.1"


# ---------------------------------------------------------------------------
# I. DetectionRule blank rule_id rejected
# ---------------------------------------------------------------------------


class TestDetectionRuleBlankId:
    """I: Blank or whitespace-only rule_id is rejected."""

    def test_empty_rule_id_rejected(self):
        with pytest.raises(Exception):
            DetectionRule(**_minimal_rule(rule_id=""))

    def test_whitespace_only_rule_id_rejected(self):
        with pytest.raises(Exception):
            DetectionRule(**_minimal_rule(rule_id="   "))


# ---------------------------------------------------------------------------
# J. DetectionRule blank name rejected
# ---------------------------------------------------------------------------


class TestDetectionRuleBlankName:
    """J: Blank or whitespace-only name is rejected."""

    def test_empty_name_rejected(self):
        with pytest.raises(Exception):
            DetectionRule(**_minimal_rule(name=""))

    def test_whitespace_only_name_rejected(self):
        with pytest.raises(Exception):
            DetectionRule(**_minimal_rule(name="   "))


# ---------------------------------------------------------------------------
# K. DetectionResult valid construction with auto detection_id
# ---------------------------------------------------------------------------


class TestDetectionResultConstruction:
    """K: DetectionResult creates valid instances with auto-generated ID."""

    def test_valid_result(self):
        res = DetectionResult(**_minimal_result())
        assert isinstance(res.detection_id, uuid.UUID)
        assert res.event_id == uuid.UUID("11111111-1111-1111-1111-111111111111")
        assert res.rule_id == "sigma-credential-access-001"
        assert res.rule_type == RuleType.SIGMA
        assert res.matched is True
        assert res.severity == DetectionSeverity.HIGH
        assert res.confidence == 0.9

    def test_explicit_detection_id_accepted(self):
        explicit = uuid.uuid4()
        res = DetectionResult(**_minimal_result(detection_id=explicit))
        assert res.detection_id == explicit

    def test_unmatched_result_accepted(self):
        res = DetectionResult(**_minimal_result(matched=False))
        assert res.matched is False


# ---------------------------------------------------------------------------
# L. DetectionResult provenance defaults to DETECTED
# ---------------------------------------------------------------------------


class TestDetectionResultProvenance:
    """L: Detection results carry DETECTED provenance by default."""

    def test_provenance_defaults_to_detected(self):
        res = DetectionResult(**_minimal_result())
        assert res.provenance == Provenance.DETECTED

    def test_provenance_serialises_as_string(self):
        res = DetectionResult(**_minimal_result())
        dumped = res.model_dump()
        assert dumped["provenance"] == "detected"

    def test_detected_provenance_explicitly_accepted(self):
        res = DetectionResult(**_minimal_result(provenance=Provenance.DETECTED))
        assert res.provenance == Provenance.DETECTED


# ---------------------------------------------------------------------------
# M. Naive timestamp rejected
# ---------------------------------------------------------------------------


class TestDetectionResultTimezoneAwareTimestamp:
    """M: Naive (timezone-unaware) timestamps are rejected."""

    def test_naive_timestamp_rejected(self):
        with pytest.raises(Exception):
            DetectionResult(**_minimal_result(
                timestamp=datetime(2025, 1, 1),
            ))

    def test_utc_timestamp_accepted(self):
        ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        res = DetectionResult(**_minimal_result(timestamp=ts))
        assert res.timestamp == ts

    def test_offset_timestamp_accepted(self):
        from datetime import timedelta
        tz_plus2 = timezone(timedelta(hours=2))
        ts = datetime(2025, 6, 15, 14, 0, 0, tzinfo=tz_plus2)
        res = DetectionResult(**_minimal_result(timestamp=ts))
        assert res.timestamp.utcoffset() == timedelta(hours=2)


# ---------------------------------------------------------------------------
# N. Confidence bounds enforcement
# ---------------------------------------------------------------------------


class TestDetectionResultConfidenceBounds:
    """N: Confidence is constrained to [0.0, 1.0]."""

    def test_zero_confidence_accepted(self):
        res = DetectionResult(**_minimal_result(confidence=0.0))
        assert res.confidence == 0.0

    def test_one_confidence_accepted(self):
        res = DetectionResult(**_minimal_result(confidence=1.0))
        assert res.confidence == 1.0

    def test_midpoint_confidence_accepted(self):
        res = DetectionResult(**_minimal_result(confidence=0.5))
        assert res.confidence == 0.5

    def test_above_one_rejected(self):
        with pytest.raises(Exception):
            DetectionResult(**_minimal_result(confidence=1.1))

    def test_below_zero_rejected(self):
        with pytest.raises(Exception):
            DetectionResult(**_minimal_result(confidence=-0.1))


# ---------------------------------------------------------------------------
# O. Secrets in evidence are rejected
# ---------------------------------------------------------------------------


class TestDetectionResultEvidenceSecrets:
    """O: Evidence containing secret-like patterns is rejected."""

    @pytest.mark.parametrize("pattern", [
        "api_key",
        "authorization",
        "bearer",
        "secret",
    ])
    def test_secret_pattern_in_evidence_rejected(self, pattern):
        with pytest.raises(Exception):
            DetectionResult(**_minimal_result(
                evidence=DetectionEvidence(detection_context={pattern: "xxx"}),
            ))


# ---------------------------------------------------------------------------
# P. Secrets in metadata are rejected
# ---------------------------------------------------------------------------


class TestDetectionResultMetadataSecrets:
    """P: Metadata containing secret-like patterns is rejected."""

    @pytest.mark.parametrize("pattern", [
        "api_key",
        "authorization",
        "bearer",
        "secret",
    ])
    def test_secret_pattern_in_metadata_rejected(self, pattern):
        with pytest.raises(Exception):
            DetectionResult(**_minimal_result(
                metadata=DetectionMetadata(extra={pattern: "xxx"}),
            ))


# ---------------------------------------------------------------------------
# Q. Serialisation round-trip for DetectionResult
# ---------------------------------------------------------------------------


class TestDetectionResultSerialization:
    """Q: DetectionResult round-trips through model_dump/model_validate."""

    def test_model_dump_round_trip(self):
        original = DetectionResult(**_minimal_result())
        dumped = original.model_dump()
        restored = DetectionResult.model_validate(dumped)
        assert restored.detection_id == original.detection_id
        assert restored.event_id == original.event_id
        assert restored.rule_id == original.rule_id
        assert restored.matched == original.matched
        assert restored.severity == original.severity
        assert restored.confidence == original.confidence
        assert restored.provenance == original.provenance

    def test_json_string_round_trip(self):
        original = DetectionResult(**_minimal_result())
        json_str = original.model_dump_json()
        restored = DetectionResult.model_validate_json(json_str)
        assert restored == original


# ---------------------------------------------------------------------------
# R. Event ID preserved from source event
# ---------------------------------------------------------------------------


class TestDetectionResultEventIdPreservation:
    """R: event_id is preserved exactly and never regenerated."""

    def test_event_id_preserved(self):
        source_id = uuid.uuid4()
        res = DetectionResult(**_minimal_result(event_id=source_id))
        assert res.event_id == source_id

    def test_event_id_not_changed_on_copy(self):
        source_id = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        res = DetectionResult(**_minimal_result(event_id=source_id))
        dumped = res.model_dump()
        restored = DetectionResult.model_validate(dumped)
        assert restored.event_id == source_id


# ---------------------------------------------------------------------------
# S. Unique detection IDs across multiple results
# ---------------------------------------------------------------------------


class TestDetectionResultUniqueIds:
    """S: Each DetectionResult receives a unique detection_id."""

    def test_different_results_different_ids(self):
        results = [DetectionResult(**_minimal_result()) for _ in range(20)]
        ids = {r.detection_id for r in results}
        assert len(ids) == 20, (
            f"Expected 20 unique IDs, got {len(ids)} — "
            "default_factory may not be generating unique values"
        )


# ---------------------------------------------------------------------------
# T. No verdict / risk_score fields (no fabrication)
# ---------------------------------------------------------------------------


class TestDetectionResultNoFabrication:
    """T: The schema has no verdict, risk_score, or alert_level fields."""

    def test_no_verdict_field(self):
        fields = set(DetectionResult.model_fields.keys())
        assert "verdict" not in fields
        assert "risk_score" not in fields
        assert "alert_level" not in fields
        assert "threat_score" not in fields
        assert "overall_score" not in fields


# ---------------------------------------------------------------------------
# U. Structured evidence holds all four sections
# ---------------------------------------------------------------------------


class TestStructuredEvidenceSections:
    """U: DetectionEvidence has all four structured data sections."""

    def test_matched_conditions_populated(self):
        ev = _minimal_evidence(matched_conditions=["cond_a", "cond_b"])
        assert ev.matched_conditions == ["cond_a", "cond_b"]

    def test_matched_fields_populated(self):
        ev = _minimal_evidence(matched_fields={"Path": "/tmp/x"})
        assert ev.matched_fields == {"Path": "/tmp/x"}

    def test_rule_references_populated(self):
        ev = _minimal_evidence(rule_references={"cve": "CVE-2024-1234"})
        assert ev.rule_references == {"cve": "CVE-2024-1234"}

    def test_detection_context_populated(self):
        ev = _minimal_evidence(detection_context={"rule_hash": "abc123"})
        assert ev.detection_context == {"rule_hash": "abc123"}

    def test_all_sections_hold_independent_data(self):
        ev = DetectionEvidence(
            matched_conditions=["c1", "c2"],
            matched_fields={"A": "1", "B": "2"},
            rule_references={"ref1": "val1"},
            detection_context={"ctx": "data"},
        )
        json_str = ev.model_dump_json()
        restored = DetectionEvidence.model_validate_json(json_str)
        assert len(restored.matched_conditions) == 2
        assert len(restored.matched_fields) == 2
        assert len(restored.rule_references) == 1
        assert len(restored.detection_context) == 1


# ---------------------------------------------------------------------------
# V. DetectionRule serialisation round-trip
# ---------------------------------------------------------------------------


class TestDetectionRuleSerialization:
    """V: DetectionRule round-trips through model_dump/model_validate."""

    def test_model_dump_round_trip(self):
        original = DetectionRule(**_minimal_rule())
        dumped = original.model_dump()
        restored = DetectionRule.model_validate(dumped)
        assert restored.rule_id == original.rule_id
        assert restored.name == original.name
        assert restored.severity == original.severity
        assert restored.rule_type == original.rule_type
        assert restored.version == original.version
        assert restored.enabled == original.enabled

    def test_json_string_round_trip(self):
        original = DetectionRule(**_minimal_rule())
        json_str = original.model_dump_json()
        restored = DetectionRule.model_validate_json(json_str)
        assert restored == original


# ---------------------------------------------------------------------------
# W. Evidence and metadata keys are secret-safe at schema level
# ---------------------------------------------------------------------------


class TestSchemaLevelSecretSafety:
    """W: No contract model has api_key, authorization, or token fields."""

    def test_detection_result_no_secret_fields(self):
        fields = set(DetectionResult.model_fields.keys())
        assert "api_key" not in fields
        assert "authorization" not in fields
        assert "token" not in fields
        assert "secret" not in fields
        assert "headers" not in fields
        assert "raw_response" not in fields

    def test_detection_rule_no_secret_fields(self):
        fields = set(DetectionRule.model_fields.keys())
        assert "api_key" not in fields
        assert "authorization" not in fields
        assert "token" not in fields
        assert "secret" not in fields

    def test_detection_evidence_no_secret_fields(self):
        fields = set(DetectionEvidence.model_fields.keys())
        assert "api_key" not in fields
        assert "authorization" not in fields
        assert "token" not in fields
        assert "secret" not in fields