"""Tests for the Risk Assessment Domain Contract (Step 11A).

Covers RiskAssessment / RiskLevel / RiskFactor / RiskEvidence, the
independent risk-vs-confidence semantics, bounded score and confidence,
the additive ``RISK_ASSESSED`` provenance marker, correlation
referencing (never duplication), structured secret-safe evidence and
metadata, JSON compatibility, immutability, deterministic serialization,
and contract-boundary enforcement (no scoring, no weights, no thresholds,
no persistence/query/API/MITRE/attribution/AI/incident concepts).

These are pure unit tests of the **contract** — no database connection,
no repository, no API, and no network calls are made.  They never test
risk *calculation* (no "this correlation must be rated HIGH" rules);
11A tests the contract, not the algorithm.
"""

import copy
import inspect
import json
import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

import app.schemas.risk as risk_module
from app.schemas.correlation import CorrelationMember, CorrelationResult
from app.schemas.risk import (
    RiskAssessment,
    RiskEvidence,
    RiskFactor,
    RiskLevel,
)
from app.schemas.security_event import Provenance


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FIXED_TS = datetime(2025, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
_CORRELATION_ID = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
_DETECTION_1 = uuid.UUID("11111111-1111-1111-1111-111111111111")
_EVENT_1 = uuid.UUID("44444444-4444-4444-4444-444444444444")


def _evidence(**overrides) -> RiskEvidence:
    base = {
        "observation_type": "correlation_confidence",
        "metadata": {"value": 0.9},
    }
    base.update(overrides)
    return RiskEvidence(**base)


def _factor(**overrides) -> RiskFactor:
    base = {
        "factor_type": "severity_impact",
        "contribution": 0.6,
        "evidence": [_evidence()],
    }
    base.update(overrides)
    return RiskFactor(**base)


def _assessment_payload(**overrides) -> dict:
    """Return a minimal valid RiskAssessment payload dict (kwargs win)."""
    base = {
        "correlation_id": _CORRELATION_ID,
        "score": 0.75,
        "level": RiskLevel.HIGH,
        "confidence": 0.8,
        "factors": [_factor()],
        "evidence": [_evidence()],
        "metadata": {"region": "eu"},
        "timestamp": _FIXED_TS,
    }
    base.update(overrides)
    return base
# ---------------------------------------------------------------------------
# 1. RiskAssessment construction
# ---------------------------------------------------------------------------


class TestValidRiskAssessment:
    """Requirement 1: a valid RiskAssessment is accepted."""

    def test_valid_assessment_constructs(self):
        assessment = RiskAssessment(**_assessment_payload())
        assert isinstance(assessment, RiskAssessment)

    def test_signature_shape_preserved(self):
        assessment = RiskAssessment(**_assessment_payload())
        assert assessment.score == 0.75
        assert assessment.level == RiskLevel.HIGH
        assert assessment.confidence == 0.8
        assert assessment.correlation_id == _CORRELATION_ID

    def test_factors_and_evidence_default_to_empty(self):
        minimal = RiskAssessment(
            correlation_id=_CORRELATION_ID,
            score=0.5,
            level=RiskLevel.MEDIUM,
            confidence=0.5,
            timestamp=_FIXED_TS,
        )
        assert minimal.factors == []
        assert minimal.evidence == []

    def test_metadata_defaults_to_empty(self):
        minimal = RiskAssessment(
            correlation_id=_CORRELATION_ID,
            score=0.5,
            level=RiskLevel.MEDIUM,
            confidence=0.5,
            timestamp=_FIXED_TS,
        )
        assert minimal.metadata == {}


# ---------------------------------------------------------------------------
# 2. RiskAssessment identity
# ---------------------------------------------------------------------------


class TestRiskAssessmentIdentity:
    """Requirements 2, 24: stable, independent, valid UUID identity."""

    def test_id_generated_when_omitted(self):
        payload = {
            key: value
            for key, value in _assessment_payload().items()
            if key != "risk_assessment_id"
        }
        assessment = RiskAssessment(**payload)
        assert isinstance(assessment.risk_assessment_id, uuid.UUID)
        assert assessment.risk_assessment_id.version == 4

    def test_supplied_id_preserved(self):
        assessment_id = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
        assessment = RiskAssessment(
            **_assessment_payload(risk_assessment_id=assessment_id)
        )
        assert assessment.risk_assessment_id == assessment_id

    def test_id_never_derived_from_correlation_id(self):
        assessment = RiskAssessment(**_assessment_payload())
        assert assessment.risk_assessment_id != _CORRELATION_ID

    def test_invalid_uuid_rejected(self):
        with pytest.raises(ValidationError):
            RiskAssessment(
                **_assessment_payload(risk_assessment_id="not-a-uuid")
            )

    def test_invalid_correlation_uuid_rejected(self):
        with pytest.raises(ValidationError):
            RiskAssessment(
                **_assessment_payload(correlation_id="not-a-uuid")
            )

    def test_missing_correlation_id_rejected(self):
        payload = {
            key: value
            for key, value in _assessment_payload().items()
            if key != "correlation_id"
        }
        with pytest.raises(ValidationError):
            RiskAssessment(**payload)


# ---------------------------------------------------------------------------
# 3. Correlation reference
# ---------------------------------------------------------------------------


class TestCorrelationReference:
    """Requirement 3: correlation is referenced, never duplicated."""

    def test_correlation_id_preserved_exactly(self):
        assessment = RiskAssessment(**_assessment_payload())
        assert assessment.correlation_id == _CORRELATION_ID

    def test_no_correlation_object_embedded(self):
        assert not hasattr(RiskAssessment, "correlation")
        assert "correlation" not in RiskAssessment.model_fields

    def test_no_members_embedded(self):
        assert "members" not in RiskAssessment.model_fields

    def test_no_detection_ids_embedded(self):
        assert "detection_ids" not in RiskAssessment.model_fields

    def test_no_correlation_evidence_duplicated(self):
        fields = set(RiskAssessment.model_fields.keys())
        assert "correlation_evidence" not in fields

    def test_assessment_fields_are_exactly_the_contract(self):
        assert set(RiskAssessment.model_fields.keys()) == {
            "risk_assessment_id",
            "correlation_id",
            "score",
            "level",
            "confidence",
            "factors",
            "evidence",
            "metadata",
            "timestamp",
            "provenance",
        }


# ---------------------------------------------------------------------------
# 4 & 5. Score bounds
# ---------------------------------------------------------------------------


class TestScoreBounds:
    """Requirements 4-7: score bounded to [0.0, 1.0] inclusive."""

    def test_score_lower_bound_inclusive(self):
        assessment = RiskAssessment(**_assessment_payload(score=0.0))
        assert assessment.score == 0.0

    def test_score_upper_bound_inclusive(self):
        assessment = RiskAssessment(**_assessment_payload(score=1.0))
        assert assessment.score == 1.0

    def test_score_in_bounds_accepted(self):
        assessment = RiskAssessment(**_assessment_payload(score=0.5))
        assert assessment.score == 0.5

    def test_score_below_zero_rejected(self):
        with pytest.raises(ValidationError):
            RiskAssessment(**_assessment_payload(score=-0.01))

    def test_score_above_one_rejected(self):
        with pytest.raises(ValidationError):
            RiskAssessment(**_assessment_payload(score=1.01))

    def test_score_required(self):
        payload = {
            key: value
            for key, value in _assessment_payload().items()
            if key != "score"
        }
        with pytest.raises(ValidationError):
            RiskAssessment(**payload)


# ---------------------------------------------------------------------------
# 6. Risk level
# ---------------------------------------------------------------------------


class TestRiskLevel:
    """Requirements 8, 9: only the controlled members are valid."""

    def test_all_valid_members_accepted(self):
        for level in RiskLevel:
            assessment = RiskAssessment(**_assessment_payload(level=level))
            assert assessment.level == level

    def test_invalid_level_rejected(self):
        with pytest.raises(ValidationError):
            RiskAssessment(**_assessment_payload(level="extreme"))

    def test_level_required(self):
        payload = {
            key: value
            for key, value in _assessment_payload().items()
            if key != "level"
        }
        with pytest.raises(ValidationError):
            RiskAssessment(**payload)

    def test_ladder_matches_detection_severity_vocabulary(self):
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.CRITICAL.value == "critical"

    def test_no_verdict_brands_in_level(self):
        members = set(RiskLevel.__members__.keys())
        assert "MALICIOUS" not in members
        assert "BENIGN" not in members
        assert "CONFIRMED" not in members


# ---------------------------------------------------------------------------
# 7 & 8. Confidence bounds
# ---------------------------------------------------------------------------


class TestConfidenceBounds:
    """Requirements 10-12: confidence bounded to [0.0, 1.0] inclusive."""

    def test_confidence_lower_bound_inclusive(self):
        assessment = RiskAssessment(**_assessment_payload(confidence=0.0))
        assert assessment.confidence == 0.0

    def test_confidence_upper_bound_inclusive(self):
        assessment = RiskAssessment(**_assessment_payload(confidence=1.0))
        assert assessment.confidence == 1.0

    def test_confidence_in_bounds_accepted(self):
        assessment = RiskAssessment(**_assessment_payload(confidence=0.42))
        assert assessment.confidence == 0.42

    def test_confidence_below_zero_rejected(self):
        with pytest.raises(ValidationError):
            RiskAssessment(**_assessment_payload(confidence=-0.01))

    def test_confidence_above_one_rejected(self):
        with pytest.raises(ValidationError):
            RiskAssessment(**_assessment_payload(confidence=1.01))

    def test_confidence_required(self):
        payload = {
            key: value
            for key, value in _assessment_payload().items()
            if key != "confidence"
        }
        with pytest.raises(ValidationError):
            RiskAssessment(**payload)


# ---------------------------------------------------------------------------
# 9. Risk vs confidence independence
# ---------------------------------------------------------------------------


class TestRiskVsConfidence:
    """Risk and confidence are separate concepts; no formula links them."""

    def test_fields_are_distinct(self):
        fields = set(RiskAssessment.model_fields.keys())
        assert "score" in fields and "level" in fields and "confidence" in fields

    def test_confidence_is_not_score(self):
        assessment = RiskAssessment(**{**_assessment_payload(), "score": 0.1, "confidence": 0.9})
        assert assessment.score == 0.1
        assert assessment.confidence == 0.9
        assert assessment.score != assessment.confidence

    def test_no_derived_confidence_property(self):
        assert not hasattr(RiskAssessment, "computed_confidence")

    def test_module_sources_have_no_formula(self):
        source = inspect.getsource(risk_module)
        assert "score * " not in source
        assert "score *" not in source
        assert "confidence * " not in source
        assert "* confidence" not in source


# ---------------------------------------------------------------------------
# 10. Timestamp validation
# ---------------------------------------------------------------------------


class TestTimestampValidation:
    """Requirement 13: timezone-aware timestamps only."""

    def test_timestamp_required(self):
        payload = {
            key: value
            for key, value in _assessment_payload().items()
            if key != "timestamp"
        }
        with pytest.raises(ValidationError):
            RiskAssessment(**payload)

    def test_naive_timestamp_rejected(self):
        naive = datetime(2025, 8, 1, 12, 0, 0)
        with pytest.raises(ValidationError):
            RiskAssessment(**_assessment_payload(timestamp=naive))

    def test_tz_aware_timestamp_accepted(self):
        assessment = RiskAssessment(**_assessment_payload())
        assert assessment.timestamp == _FIXED_TS


# ---------------------------------------------------------------------------
# 11. Provenance validation
# ---------------------------------------------------------------------------


class TestProvenance:
    """Requirement 14: RISK_ASSESSED is the only valid marker."""

    def test_provenance_defaults_to_risk_assessed(self):
        assessment = RiskAssessment(**_assessment_payload())
        assert assessment.provenance == Provenance.RISK_ASSESSED

    def test_provenance_risk_assessed_accepted(self):
        assessment = RiskAssessment(
            **_assessment_payload(provenance=Provenance.RISK_ASSESSED)
        )
        assert assessment.provenance == Provenance.RISK_ASSESSED

    def test_provenance_correlated_rejected(self):
        with pytest.raises(ValidationError):
            RiskAssessment(
                **_assessment_payload(provenance=Provenance.CORRELATED)
            )

    def test_provenance_detected_rejected(self):
        with pytest.raises(ValidationError):
            RiskAssessment(
                **_assessment_payload(provenance=Provenance.DETECTED)
            )

    def test_provenance_observed_rejected(self):
        with pytest.raises(ValidationError):
            RiskAssessment(
                **_assessment_payload(provenance=Provenance.OBSERVED)
            )

    def test_provenance_enriched_rejected(self):
        with pytest.raises(ValidationError):
            RiskAssessment(
                **_assessment_payload(provenance=Provenance.ENRICHED)
            )

    def test_provenance_reconstructed_rejected(self):
        with pytest.raises(ValidationError):
            RiskAssessment(
                **_assessment_payload(provenance=Provenance.RECONSTRUCTED)
            )

    def test_risk_assessed_string_value(self):
        assert Provenance.RISK_ASSESSED.value == "risk_assessed"

    def test_risk_assessed_is_global_member(self):
        assert Provenance.RISK_ASSESSED in Provenance

    def test_risk_assessed_serialises_as_string(self):
        assessment = RiskAssessment(**_assessment_payload())
        assert json.loads(assessment.model_dump_json())["provenance"] == "risk_assessed"


# ---------------------------------------------------------------------------
# 12. Evidence validation
# ---------------------------------------------------------------------------


class TestEvidenceValidation:
    """Requirement 15: evidence is structured and validated."""

    def test_evidence_structured_record(self):
        evidence = _evidence()
        assert evidence.observation_type == "correlation_confidence"
        assert isinstance(evidence.metadata, dict)

    def test_evidence_defaults_metadata_empty(self):
        evidence = RiskEvidence(observation_type="detection_severity")
        assert evidence.metadata == {}

    def test_evidence_observation_label_required(self):
        with pytest.raises(ValidationError):
            RiskEvidence(observation_type="   ")

    def test_evidence_observation_label_stripped(self):
        evidence = RiskEvidence(observation_type="  detection_severity  ")
        assert evidence.observation_type == "detection_severity"

    def test_evidence_optional_references_accepted(self):
        evidence = RiskEvidence(
            observation_type="detection_severity",
            detection_id=_DETECTION_1,
            event_id=_EVENT_1,
        )
        assert evidence.detection_id == _DETECTION_1
        assert evidence.event_id == _EVENT_1

    def test_evidence_invalid_detection_uuid_rejected(self):
        with pytest.raises(ValidationError):
            RiskEvidence(
                observation_type="detection_severity",
                detection_id="not-a-uuid",
            )

    def test_evidence_invalid_event_uuid_rejected(self):
        with pytest.raises(ValidationError):
            RiskEvidence(
                observation_type="detection_severity",
                event_id="not-a-uuid",
            )

    def test_evidence_metadata_non_json_rejected(self):
        with pytest.raises(ValidationError):
            _evidence(metadata={"blob": object()})

    def test_assessment_evidence_list_validated(self):
        with pytest.raises(ValidationError):
            RiskAssessment(
                **_assessment_payload(
                    evidence=[
                        {"observation_type": "correlation_confidence", "metadata": {"blob": object()}}
                    ]
                )
            )

    def test_evidence_does_not_carry_freeform_text_field(self):
        assert "explanation" not in RiskEvidence.model_fields


# ---------------------------------------------------------------------------
# 13. Factors
# ---------------------------------------------------------------------------


class TestFactorValidation:
    """Risk factors are structured contributors, never computed here."""

    def test_factor_constructs(self):
        factor = _factor()
        assert factor.factor_type == "severity_impact"
        assert factor.contribution == 0.6

    def test_factor_contribution_defaults_none(self):
        factor = RiskFactor(factor_type="severity_impact")
        assert factor.contribution is None

    def test_factor_contribution_bounds(self):
        RiskFactor(factor_type="x", contribution=0.0)
        RiskFactor(factor_type="x", contribution=1.0)
        with pytest.raises(ValidationError):
            RiskFactor(factor_type="x", contribution=-0.01)
        with pytest.raises(ValidationError):
            RiskFactor(factor_type="x", contribution=1.01)

    def test_factor_label_required(self):
        with pytest.raises(ValidationError):
            RiskFactor(factor_type="   ")

    def test_factor_metadata_validated(self):
        with pytest.raises(ValidationError):
            RiskFactor(factor_type="x", metadata={"blob": object()})

    def test_factor_evidence_validated(self):
        with pytest.raises(ValidationError):
            RiskFactor(
                factor_type="x",
                evidence=[{"observation_type": "o", "metadata": {"blob": object()}}],
            )

    def test_no_weights_field(self):
        assert "weight" not in RiskFactor.model_fields


# ---------------------------------------------------------------------------
# 14. Metadata validation
# ---------------------------------------------------------------------------


class TestMetadataValidation:
    """Requirement 16: metadata JSON-compatible and independent."""

    def test_metadata_structured(self):
        assessment = RiskAssessment(**_assessment_payload())
        assert isinstance(assessment.metadata, dict)

    def test_metadata_non_json_rejected(self):
        with pytest.raises(ValidationError):
            RiskAssessment(**_assessment_payload(metadata={"blob": object()}))

    def test_metadata_nested_independent_from_input(self):
        payload = _assessment_payload(
            metadata={"nested": {"list": [1, 2]}}
        )
        source = payload["metadata"]
        assessment = RiskAssessment(**payload)
        source["nested"]["list"].append(99)
        assert assessment.metadata == {"nested": {"list": [1, 2]}}

    def test_assessment_metadata_json_serializable(self):
        assessment = RiskAssessment(**_assessment_payload())
        json.dumps(assessment.metadata)


# ---------------------------------------------------------------------------
# 15. Secret safety
# ---------------------------------------------------------------------------


class TestSecretSafety:
    """Requirement 17: no credentials in evidence/metadata/factors."""

    def test_metadata_rejects_api_key(self):
        with pytest.raises(ValidationError):
            RiskAssessment(**_assessment_payload(metadata={"api_key": "AKIA"}))

    def test_metadata_rejects_authorization_value(self):
        with pytest.raises(ValidationError):
            RiskAssessment(
                **_assessment_payload(metadata={"headers": {"authorization": "Basic abc"}})
            )

    def test_metadata_rejects_bearer_value(self):
        with pytest.raises(ValidationError):
            RiskAssessment(**_assessment_payload(metadata={"token": "Bearer xxx"}))

    def test_metadata_rejects_secret_key(self):
        with pytest.raises(ValidationError):
            RiskAssessment(**_assessment_payload(metadata={"client_secret": "pw"}))

    def test_evidence_metadata_rejects_api_key(self):
        with pytest.raises(ValidationError):
            _evidence(metadata={"api_key": "sk-1234"})

    def test_factor_metadata_rejects_secret(self):
        with pytest.raises(ValidationError):
            RiskFactor(factor_type="x", metadata={"secret": "pw"})

    def test_factor_evidence_metadata_rejects_api_key(self):
        with pytest.raises(ValidationError):
            RiskFactor(
                factor_type="x",
                evidence=[{"observation_type": "o", "metadata": {"api_key": "k"}}],
            )

    def test_no_secret_keys_anywhere_in_contract_fields(self):
        all_fields = (
            set(RiskAssessment.model_fields.keys())
            | set(RiskFactor.model_fields.keys())
            | set(RiskEvidence.model_fields.keys())
        )
        for name in ("password", "api_key", "token", "authorization"):
            assert name not in all_fields


# ---------------------------------------------------------------------------
# 16. JSON compatibility
# ---------------------------------------------------------------------------


class TestJsonCompatibility:
    """Requirement 18: the whole contract round-trips as strict JSON."""

    def test_model_dump_uses_json_types(self):
        assessment = RiskAssessment(**_assessment_payload())
        dumped = assessment.model_dump(mode="json")
        json.dumps(dumped)  # must not raise

    def test_cyclic_metadata_rejected(self):
        cyclic: dict = {"self": None}
        cyclic["self"] = cyclic
        with pytest.raises(ValidationError):
            RiskAssessment(**_assessment_payload(metadata=cyclic))


# ---------------------------------------------------------------------------
# 17. Oversized payload handling
# ---------------------------------------------------------------------------


class TestOversizedPayloads:
    """Large structured payloads are accepted; pathological ones are not."""

    def test_large_structured_evidence_accepted(self):
        large = RiskAssessment(
            **_assessment_payload(
                evidence=[
                    _evidence(observation_type=f"obs_{i}") for i in range(2000)
                ]
            )
        )
        assert len(large.evidence) == 2000

    def test_large_metadata_dict_accepted(self):
        big = {f"k{i}": i for i in range(5000)}
        assessment = RiskAssessment(**_assessment_payload(metadata=big))
        assert len(assessment.metadata) == 5000

    def test_deeply_nested_but_json_metadata_accepted(self):
        nested: dict = {"a": {"a": {"a": {"a": {"a": 1}}}}}
        assessment = RiskAssessment(**_assessment_payload(metadata=nested))
        assert assessment.metadata == nested


# ---------------------------------------------------------------------------
# 18. Input immutability
# ---------------------------------------------------------------------------


class TestInputImmutability:
    """Requirement 20: constructors never mutate source CorrelationResults."""

    def _correlation_result(self) -> CorrelationResult:
        return CorrelationResult(
            correlation_id=_CORRELATION_ID,
            members=[
                CorrelationMember(
                    detection_id=_DETECTION_1,
                    event_id=_EVENT_1,
                    timestamp=_FIXED_TS,
                )
            ],
            timestamp=_FIXED_TS,
            evidence={"basis": "explicit-membership"},
            metadata={"source": "unit-test"},
        )

    def test_assessment_construction_does_not_mutate_correlation(self):
        correlation = self._correlation_result()
        snapshot = copy.deepcopy(correlation)
        RiskAssessment(
            correlation_id=correlation.correlation_id,
            score=0.75,
            level=RiskLevel.HIGH,
            confidence=0.8,
            timestamp=_FIXED_TS,
        )
        assert correlation == snapshot

    def test_construction_does_not_mutate_payload(self):
        payload = _assessment_payload()
        snapshot = copy.deepcopy(payload)
        RiskAssessment(**payload)
        assert payload == snapshot

    def test_deep_copied_assessment_is_independent(self):
        assessment = RiskAssessment(
            **_assessment_payload(metadata={"nested": {"a": [1]}})
        )
        clone = assessment.model_copy(deep=True)
        clone.metadata["nested"]["a"].append(2)
        assert assessment.metadata == {"nested": {"a": [1]}}


# ---------------------------------------------------------------------------
# 19. Deterministic serialization
# ---------------------------------------------------------------------------


class TestDeterministicSerialization:
    """Requirement 21: same input -> identical serialized output."""

    def test_same_input_same_output(self):
        assessment_id = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
        a = RiskAssessment(
            **_assessment_payload(risk_assessment_id=assessment_id)
        )
        b = RiskAssessment(
            **_assessment_payload(risk_assessment_id=assessment_id)
        )
        assert a.model_dump_json() == b.model_dump_json()

    def test_json_round_trip_preserves_contract(self):
        original = RiskAssessment(**_assessment_payload())
        restored = RiskAssessment.model_validate_json(original.model_dump_json())
        assert restored.model_dump() == original.model_dump()


# ---------------------------------------------------------------------------
# 20. Equality behavior
# ---------------------------------------------------------------------------


class TestEquality:
    """Requirement 22: value equality, structural and JSON-based."""

    def test_equal_assessments_equal(self):
        a = RiskAssessment(**_assessment_payload())
        b = RiskAssessment(**_assessment_payload(risk_assessment_id=a.risk_assessment_id))
        assert a == b

    def test_different_score_not_equal(self):
        a = RiskAssessment(**_assessment_payload(score=0.2))
        b = RiskAssessment(**_assessment_payload(score=0.8))
        assert a != b

    def test_different_correlation_not_equal(self):
        other = uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")
        a = RiskAssessment(**_assessment_payload())
        b = RiskAssessment(**_assessment_payload(correlation_id=other))
        assert a != b


# ---------------------------------------------------------------------------
# 21. Contract boundary: no future-layer concepts
# ---------------------------------------------------------------------------


class TestContractBoundary:
    """Requirements 23-25: no scoring/incident/MITRE/response concepts."""

    FORBIDDEN = {
        "incident",
        "incident_id",
        "incident_severity",
        "incident_priority",
        "priority",
        "mitre",
        "tactic",
        "technique",
        "attack_stage",
        "attribution",
        "threat_actor",
        "campaign_id",
        "verdict",
        "malicious",
        "benign",
        "response_action",
        "remediation",
        "playbook",
        "soar",
        "llm",
        "embedding",
        "vector",
        "graph",
        "confidence_score",
    }

    def test_no_future_layer_fields(self):
        fields = set(RiskAssessment.model_fields.keys())
        for name in self.FORBIDDEN:
            assert name not in fields, f"unexpected future-layer field: {name}"

    def test_assessment_fields_are_exactly_the_contract_fields(self):
        assert set(RiskAssessment.model_fields.keys()) == {
            "risk_assessment_id",
            "correlation_id",
            "score",
            "level",
            "confidence",
            "factors",
            "evidence",
            "metadata",
            "timestamp",
            "provenance",
        }

    def test_no_incident_type_defined(self):
        assert not hasattr(risk_module, "Incident")
        assert not hasattr(risk_module, "IncidentSeverity")
        assert not hasattr(risk_module, "ResponseAction")

    def test_no_repository_service_or_api_types(self):
        assert not hasattr(risk_module, "RiskRepository")
        assert not hasattr(risk_module, "RiskQueryService")
        assert not hasattr(risk_module, "RiskApiRouter")

    def test_no_engine_or_model_classes(self):
        assert not hasattr(risk_module, "RiskScoringEngine")
        assert not hasattr(risk_module, "RiskWeights")
        assert not hasattr(risk_module, "CorrelationRiskModel")


# ---------------------------------------------------------------------------
# 22. No scoring engine leakage
# ---------------------------------------------------------------------------


class TestNoScoringEngine:
    """11A tests the CONTRACT, not the algorithm.  No formula/weights."""

    def test_no_score_method(self):
        assert not hasattr(RiskAssessment, "score")
        assert not hasattr(RiskAssessment, "calculate")

    def test_no_formula_helpers_defined(self):
        for helper in ("calculate_risk", "compute_score", "aggregate", "derive_level"):
            assert not hasattr(risk_module, helper)

    def test_no_threshold_constants(self):
        for constant in (
            "SCORE_THRESHOLD",
            "WEIGHTS",
            "RISK_WEIGHTS",
            "SEVERITY_WEIGHT",
            "CONFIDENCE_WEIGHT",
            "CRITICAL_THRESHOLD",
            "DEFAULT_RISK_LEVEL",
        ):
            assert not hasattr(risk_module, constant), constant


# ---------------------------------------------------------------------------
# 23. Dependency isolation
# ---------------------------------------------------------------------------


class TestDependencyIsolation:
    """A clean import of the risk contract pulls in no heavy frameworks."""

    def test_module_imports_no_storage_api_or_bus(self):
        source = inspect.getsource(risk_module)
        for forbidden in ("sqlalchemy", "fastapi", "kafka", "redis", "amqp", "opensearch", "qdrant"):
            assert forbidden not in source, (
                f"risk contract must not import {forbidden}"
            )

    def test_module_imports_only_pydantic_and_provenance(self):
        source = inspect.getsource(risk_module)
        assert "from app.schemas.security_event import Provenance" in source
        assert "from pydantic" in source
        assert "import models" not in source
        assert "from app.repositories" not in source
        assert "from app.services" not in source
        assert "from app.agents" not in source
        assert "from app.api" not in source

    def test_schema_is_constructible_without_database(self):
        assessment = RiskAssessment(**_assessment_payload())
        assert isinstance(assessment.score, float)


# ---------------------------------------------------------------------------
# 24. Provenance regression: earlier boundaries are unchanged
# ---------------------------------------------------------------------------


class TestProvenanceRegression:
    """Adding RISK_ASSESSED must not weaken DETECTED/CORRELATED boundaries."""

    def test_correlation_still_requires_correlated(self):
        with pytest.raises(ValidationError):
            CorrelationResult(
                correlation_id=_CORRELATION_ID,
                members=[
                    CorrelationMember(
                        detection_id=_DETECTION_1,
                        event_id=_EVENT_1,
                        timestamp=_FIXED_TS,
                    )
                ],
                timestamp=_FIXED_TS,
                provenance=Provenance.RISK_ASSESSED,
            )

    def test_detection_still_defaults_detected(self):
        from app.schemas.detection import DetectionResult, DetectionSeverity, RuleType

        rule_payload = {
            "event_id": _EVENT_1,
            "rule_id": "sigma-credential-access-001",
            "rule_type": RuleType.SIGMA,
            "matched": True,
            "severity": DetectionSeverity.HIGH,
            "confidence": 0.9,
            "timestamp": _FIXED_TS,
        }
        assert DetectionResult(**rule_payload).provenance == Provenance.DETECTED

    def test_existing_provenance_members_preserved(self):
        assert Provenance.OBSERVED.value == "observed"
        assert Provenance.ENRICHED.value == "enriched"
        assert Provenance.RECONSTRUCTED.value == "reconstructed"
        assert Provenance.DETECTED.value == "detected"
        assert Provenance.CORRELATED.value == "correlated"


# ---------------------------------------------------------------------------
# 25. Package re-export
# ---------------------------------------------------------------------------


class TestPackageExports:
    def test_risk_schemas_exported_from_package(self):
        from app.schemas import (
            RiskAssessment as PkgRiskAssessment,
            RiskEvidence as PkgRiskEvidence,
            RiskFactor as PkgRiskFactor,
            RiskLevel as PkgRiskLevel,
        )

        assert PkgRiskAssessment is RiskAssessment
        assert PkgRiskEvidence is RiskEvidence
        assert PkgRiskFactor is RiskFactor
        assert PkgRiskLevel is RiskLevel