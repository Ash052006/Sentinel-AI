"""Tests for the Investigation Domain Contract (Step 12A).

Covers InvestigationResult / InvestigationFinding / InvestigationEvidence /
InvestigationObservation, the additive ``AI_GENERATED`` provenance marker,
provenance honesty (AI inference is never observed telemetry), source-backed
evidence with provenance-coherent references, evidence-vs-finding-vs-
observation separation, independent confidence bounds, secret-safe JSON
metadata, determinism, immutability/aliasing, unknown-field behavior, and
contract-boundary enforcement (no agent, LLM, Ollama, context builder,
persistence, API, incident, MITRE, or response concepts).

These are pure unit tests of the **contract** — no database connection, no
repository, no API, and no network calls are made.  They never test
investigation *reasoning*; 12A tests the contract, not the algorithm.
"""

import copy
import inspect
import json
import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

import app.schemas.investigation as investigation_module
from app.schemas.correlation import CorrelationMember, CorrelationResult
from app.schemas.investigation import (
    InvestigationEvidence,
    InvestigationFinding,
    InvestigationObservation,
    InvestigationResult,
)
from app.schemas.risk import RiskAssessment, RiskLevel
from app.schemas.security_event import Provenance


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FIXED_TS = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
_CORRELATION_ID = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
_RISK_ASSESSMENT_ID = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
_DETECTION_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
_EVENT_ID = uuid.UUID("44444444-4444-4444-4444-444444444444")


def _evidence(**overrides) -> InvestigationEvidence:
    base = {
        "evidence_type": "detection_match",
        "provenance": Provenance.DETECTED,
        "detection_id": _DETECTION_ID,
        "metadata": {"rule_id": "sigma-001"},
    }
    base.update(overrides)
    return InvestigationEvidence(**base)


def _observation(**overrides) -> InvestigationObservation:
    base = {
        "observation_type": "context_summary",
        "observation_text": "single host activity",
        "provenance": Provenance.OBSERVED,
    }
    base.update(overrides)
    return InvestigationObservation(**base)


def _finding(**overrides) -> InvestigationFinding:
    base = {
        "finding_type": "activity_pattern",
        "title": "Repeated beaconing",
        "confidence": 0.8,
        "evidence_ids": [],
    }
    base.update(overrides)
    return InvestigationFinding(**base)


def _result_payload(**overrides) -> dict:
    """Return a minimal valid InvestigationResult payload dict (kwargs win)."""
    evidence = _evidence()
    base = {
        "correlation_id": _CORRELATION_ID,
        "risk_assessment_id": _RISK_ASSESSMENT_ID,
        "confidence": 0.8,
        "findings": [_finding(evidence_ids=[evidence.evidence_id])],
        "evidence": [evidence],
        "observations": [_observation()],
        "metadata": {"region": "eu"},
        "timestamp": _FIXED_TS,
    }
    base.update(overrides)
    return base


def _minimal_result(**overrides) -> InvestigationResult:
    """A result with no findings/evidence/observations (contract minimum)."""
    base = {"correlation_id": _CORRELATION_ID, "timestamp": _FIXED_TS}
    base.update(overrides)
    return InvestigationResult(**base)


# ---------------------------------------------------------------------------
# 1. InvestigationResult construction
# ---------------------------------------------------------------------------


class TestValidInvestigationResult:
    """A valid InvestigationResult is accepted, minimal and complete."""

    def test_complete_result_constructs(self):
        result = InvestigationResult(**_result_payload())
        assert isinstance(result, InvestigationResult)

    def test_minimal_result_constructs(self):
        result = _minimal_result()
        assert result.findings == []
        assert result.evidence == []
        assert result.observations == []
        assert result.confidence is None
        assert result.risk_assessment_id is None
        assert result.metadata == {}
        assert result.provenance == Provenance.AI_GENERATED

    def test_shape_preserved(self):
        result = InvestigationResult(**_result_payload(confidence=0.75))
        assert result.correlation_id == _CORRELATION_ID
        assert result.risk_assessment_id == _RISK_ASSESSMENT_ID
        assert result.confidence == 0.75
        assert result.metadata == {"region": "eu"}
        assert result.timestamp == _FIXED_TS

    def test_multiple_findings_evidence_observations_accepted(self):
        ev1 = _evidence()
        ev2 = _evidence(
            evidence_type="risk_factor",
            provenance=Provenance.RISK_ASSESSED,
            risk_assessment_id=_RISK_ASSESSMENT_ID,
        )
        result = InvestigationResult(
            **_result_payload(
                findings=[
                    _finding(evidence_ids=[ev1.evidence_id, ev2.evidence_id]),
                    _finding(finding_type="escalation", title="Escalate", confidence=0.6),
                ],
                evidence=[ev1, ev2],
                observations=[
                    _observation(),
                    _observation(
                        observation_type="ai_reasoning",
                        observation_text="pattern consistent with beaconing",
                        provenance=Provenance.AI_GENERATED,
                    ),
                ],
            )
        )
        assert len(result.findings) == 2
        assert len(result.evidence) == 2
        assert len(result.observations) == 2


# ---------------------------------------------------------------------------
# 2. InvestigationResult identity
# ---------------------------------------------------------------------------

class TestInvestigationIdentity:
    """Stable, independent, valid UUID identity."""

    def test_id_generated_when_omitted(self):
        result = _minimal_result()
        assert isinstance(result.investigation_id, uuid.UUID)
        assert result.investigation_id.version == 4

    def test_supplied_id_preserved(self):
        investigation_id = uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")
        result = _minimal_result(investigation_id=investigation_id)
        assert result.investigation_id == investigation_id

    def test_id_never_derived_from_correlation_id(self):
        result = _minimal_result()
        assert result.investigation_id != _CORRELATION_ID

    def test_ids_are_unique_across_results(self):
        result = _minimal_result()
        other = _minimal_result(investigation_id=uuid.uuid4())
        assert result.investigation_id != other.investigation_id

    def test_invalid_investigation_uuid_rejected(self):
        with pytest.raises(ValidationError):
            _minimal_result(investigation_id="not-a-uuid")

    def test_invalid_correlation_uuid_rejected(self):
        with pytest.raises(ValidationError):
            _minimal_result(correlation_id="not-a-uuid")

    def test_missing_correlation_id_rejected(self):
        with pytest.raises(ValidationError):
            InvestigationResult(timestamp=_FIXED_TS)


# ---------------------------------------------------------------------------
# 3. Correlation / risk reference semantics
# ---------------------------------------------------------------------------

class TestCorrelationReference:
    """The correlation is referenced; nothing is embedded or duplicated."""

    def test_correlation_id_preserved_exactly(self):
        result = InvestigationResult(**_result_payload())
        assert result.correlation_id == _CORRELATION_ID

    def test_risk_assessment_id_optional(self):
        assert _minimal_result().risk_assessment_id is None
        with_ref = _minimal_result(risk_assessment_id=_RISK_ASSESSMENT_ID)
        assert with_ref.risk_assessment_id == _RISK_ASSESSMENT_ID

    def test_no_correlation_object_embedded(self):
        assert "correlation" not in InvestigationResult.model_fields
        assert "members" not in InvestigationResult.model_fields

    def test_no_detection_or_event_lists_embedded(self):
        fields = set(InvestigationResult.model_fields.keys())
        assert "detection_ids" not in fields
        assert "event_ids" not in fields

    def test_multiple_historical_investigations_representable(self):
        a = _minimal_result()
        b = _minimal_result(
            investigation_id=uuid.uuid4(),
            timestamp=datetime(2026, 5, 2, 12, 0, 0, tzinfo=timezone.utc),
        )
        assert a.correlation_id == b.correlation_id
        assert a.investigation_id != b.investigation_id


# ---------------------------------------------------------------------------
# 4. InvestigationResult confidence
# ---------------------------------------------------------------------------

class TestResultConfidence:
    """Result confidence is bounded to [0.0, 1.0] and independent of risk."""

    def test_confidence_optional(self):
        assert _minimal_result().confidence is None

    def test_confidence_bounds_accepted(self):
        assert _minimal_result(confidence=0.0).confidence == 0.0
        assert _minimal_result(confidence=1.0).confidence == 1.0
        assert _minimal_result(confidence=0.5).confidence == 0.5

    def test_confidence_below_zero_rejected(self):
        with pytest.raises(ValidationError):
            _minimal_result(confidence=-0.01)

    def test_confidence_above_one_rejected(self):
        with pytest.raises(ValidationError):
            _minimal_result(confidence=1.01)

    def test_confidence_is_not_a_risk_score(self):
        result = _minimal_result(confidence=0.9)
        assert result.confidence == 0.9
        assert "score" not in InvestigationResult.model_fields

    def test_module_sources_have_no_formula(self):
        source = inspect.getsource(investigation_module)
        assert "score * " not in source
        assert "confidence * " not in source
        assert "* confidence" not in source
        assert "risk_score" not in source


# ---------------------------------------------------------------------------
# 5. InvestigationResult provenance
# ---------------------------------------------------------------------------

class TestResultProvenance:
    """AI_GENERATED is the only valid result provenance."""

    def test_defaults_to_ai_generated(self):
        assert _minimal_result().provenance == Provenance.AI_GENERATED

    def test_ai_generated_accepted(self):
        result = _minimal_result(provenance=Provenance.AI_GENERATED)
        assert result.provenance == Provenance.AI_GENERATED

    def test_observed_rejected(self):
        with pytest.raises(ValidationError):
            _minimal_result(provenance=Provenance.OBSERVED)

    def test_enriched_rejected(self):
        with pytest.raises(ValidationError):
            _minimal_result(provenance=Provenance.ENRICHED)

    def test_reconstructed_rejected(self):
        with pytest.raises(ValidationError):
            _minimal_result(provenance=Provenance.RECONSTRUCTED)

    def test_detected_rejected(self):
        with pytest.raises(ValidationError):
            _minimal_result(provenance=Provenance.DETECTED)

    def test_correlated_rejected(self):
        with pytest.raises(ValidationError):
            _minimal_result(provenance=Provenance.CORRELATED)

    def test_risk_assessed_rejected(self):
        with pytest.raises(ValidationError):
            _minimal_result(provenance=Provenance.RISK_ASSESSED)

    def test_unknown_string_rejected(self):
        with pytest.raises(ValidationError):
            _minimal_result(provenance="investigated")

    def test_ai_generated_serialises_as_string(self):
        result = _minimal_result()
        assert json.loads(result.model_dump_json())["provenance"] == "ai_generated"


# ---------------------------------------------------------------------------
# 6. InvestigationFinding validation
# ---------------------------------------------------------------------------

class TestFindingValidation:
    """Findings are structured conclusions, never free-form evidence."""

    def test_finding_constructs(self):
        finding = _finding()
        assert finding.finding_type == "activity_pattern"
        assert finding.title == "Repeated beaconing"
        assert finding.confidence == 0.8

    def test_summary_optional_and_defaults_none(self):
        assert _finding().summary is None
        assert _finding(summary="consistent with C2").summary == "consistent with C2"

    def test_finding_type_required(self):
        with pytest.raises(ValidationError):
            InvestigationFinding(title="x", confidence=0.5)

    def test_title_required(self):
        with pytest.raises(ValidationError):
            InvestigationFinding(finding_type="x", confidence=0.5)

    def test_confidence_required(self):
        with pytest.raises(ValidationError):
            InvestigationFinding(finding_type="x", title="x")

    def test_finding_type_blank_rejected(self):
        with pytest.raises(ValidationError):
            InvestigationFinding(finding_type="   ", title="x", confidence=0.5)

    def test_title_blank_rejected(self):
        with pytest.raises(ValidationError):
            InvestigationFinding(finding_type="x", title="   ", confidence=0.5)

    def test_summary_blank_rejected(self):
        with pytest.raises(ValidationError):
            _finding(summary="   ")

    def test_labels_stripped(self):
        finding = _finding(finding_type="  escalation  ", title="  Escalate  ")
        assert finding.finding_type == "escalation"
        assert finding.title == "Escalate"

    def test_evidence_ids_default_empty(self):
        assert _finding().evidence_ids == []

    def test_finding_references_evidence_never_embeds_it(self):
        assert "evidence" not in InvestigationFinding.model_fields
        assert "evidence_ids" in InvestigationFinding.model_fields


# ---------------------------------------------------------------------------
# 7. InvestigationFinding confidence
# ---------------------------------------------------------------------------

class TestFindingConfidence:
    """Finding confidence is bounded to [0.0, 1.0] inclusive."""

    def test_lower_bound_inclusive(self):
        assert _finding(confidence=0.0).confidence == 0.0

    def test_upper_bound_inclusive(self):
        assert _finding(confidence=1.0).confidence == 1.0

    def test_mid_value_accepted(self):
        assert _finding(confidence=0.5).confidence == 0.5

    def test_below_zero_rejected(self):
        with pytest.raises(ValidationError):
            _finding(confidence=-0.01)

    def test_above_one_rejected(self):
        with pytest.raises(ValidationError):
            _finding(confidence=1.01)


# ---------------------------------------------------------------------------
# 8. InvestigationFinding provenance (hallucination guard)
# ---------------------------------------------------------------------------

class TestFindingProvenance:
    """A finding is always AI_GENERATED; never observed telemetry."""

    def test_defaults_to_ai_generated(self):
        assert _finding().provenance == Provenance.AI_GENERATED

    def test_ai_generated_accepted(self):
        finding = _finding(provenance=Provenance.AI_GENERATED)
        assert finding.provenance == Provenance.AI_GENERATED

    def test_observed_rejected(self):
        with pytest.raises(ValidationError):
            _finding(provenance=Provenance.OBSERVED)

    def test_enriched_rejected(self):
        with pytest.raises(ValidationError):
            _finding(provenance=Provenance.ENRICHED)

    def test_reconstructed_rejected(self):
        with pytest.raises(ValidationError):
            _finding(provenance=Provenance.RECONSTRUCTED)

    def test_detected_rejected(self):
        with pytest.raises(ValidationError):
            _finding(provenance=Provenance.DETECTED)

    def test_correlated_rejected(self):
        with pytest.raises(ValidationError):
            _finding(provenance=Provenance.CORRELATED)

    def test_risk_assessed_rejected(self):
        with pytest.raises(ValidationError):
            _finding(provenance=Provenance.RISK_ASSESSED)

    def test_serialises_as_ai_generated_not_observed(self):
        assert _finding().model_dump_json().find('"observed"') == -1
        assert '"ai_generated"' in _finding().model_dump_json()


# ---------------------------------------------------------------------------
# 9. InvestigationEvidence validation
# ---------------------------------------------------------------------------

class TestEvidenceValidation:
    """Evidence is a source-backed machine-readable record."""

    def test_evidence_constructs(self):
        evidence = _evidence()
        assert evidence.evidence_type == "detection_match"
        assert evidence.detection_id == _DETECTION_ID
        assert evidence.provenance == Provenance.DETECTED

    def test_evidence_id_generated(self):
        evidence = _evidence()
        assert isinstance(evidence.evidence_id, uuid.UUID)
        assert evidence.evidence_id.version == 4

    def test_evidence_type_required(self):
        with pytest.raises(ValidationError):
            InvestigationEvidence(
                provenance=Provenance.DETECTED, detection_id=_DETECTION_ID
            )

    def test_evidence_type_blank_rejected(self):
        with pytest.raises(ValidationError):
            _evidence(evidence_type="   ")

    def test_evidence_type_stripped(self):
        assert _evidence(evidence_type="  event_field  ").evidence_type == "event_field"

    def test_provenance_required(self):
        with pytest.raises(ValidationError):
            InvestigationEvidence(evidence_type="x", detection_id=_DETECTION_ID)

    def test_metadata_defaults_empty(self):
        evidence = InvestigationEvidence(
            evidence_type="detection_match",
            provenance=Provenance.DETECTED,
            detection_id=_DETECTION_ID,
        )
        assert evidence.metadata == {}

    def test_no_freeform_text_field(self):
        for name in ("description", "explanation", "text", "statement"):
            assert name not in InvestigationEvidence.model_fields

    def test_no_embedded_record_fields(self):
        fields = set(InvestigationEvidence.model_fields.keys())
        for name in ("detection", "event", "correlation", "risk_assessment", "payload"):
            assert name not in fields


# ---------------------------------------------------------------------------
# 10. Evidence provenance — reference coherence
# ---------------------------------------------------------------------------

_SOURCE_REFERENCE = {
    Provenance.OBSERVED: ("event_id", _EVENT_ID),
    Provenance.ENRICHED: ("event_id", _EVENT_ID),
    Provenance.RECONSTRUCTED: ("event_id", _EVENT_ID),
    Provenance.DETECTED: ("detection_id", _DETECTION_ID),
    Provenance.CORRELATED: ("correlation_id", _CORRELATION_ID),
    Provenance.RISK_ASSESSED: ("risk_assessment_id", _RISK_ASSESSMENT_ID),
}


class TestEvidenceReferenceCoherence:
    """Analytical provenance cannot attach without its matching reference."""

    @pytest.mark.parametrize(
        "provenance", sorted(_SOURCE_REFERENCE, key=lambda p: p.value)
    )
    def test_matching_reference_required(self, provenance):
        field_name, ref = _SOURCE_REFERENCE[provenance]
        evidence = _evidence(provenance=provenance, **{field_name: ref})
        assert evidence.provenance == provenance
        with pytest.raises(ValidationError):
            _evidence(provenance=provenance, **{field_name: None})

    def test_observed_requires_event_id(self):
        with pytest.raises(ValidationError):
            _evidence(provenance=Provenance.OBSERVED, event_id=None)

    def test_enriched_requires_event_id(self):
        with pytest.raises(ValidationError):
            _evidence(provenance=Provenance.ENRICHED)

    def test_reconstructed_requires_event_id(self):
        with pytest.raises(ValidationError):
            _evidence(provenance=Provenance.RECONSTRUCTED)

    def test_detected_requires_detection_id(self):
        with pytest.raises(ValidationError):
            _evidence(provenance=Provenance.DETECTED, detection_id=None)

    def test_correlated_requires_correlation_id(self):
        with pytest.raises(ValidationError):
            _evidence(provenance=Provenance.CORRELATED, correlation_id=None)

    def test_risk_assessed_requires_risk_assessment_id(self):
        with pytest.raises(ValidationError):
            _evidence(provenance=Provenance.RISK_ASSESSED, risk_assessment_id=None)

    def test_detected_only_event_reference_rejected(self):
        with pytest.raises(ValidationError):
            _evidence(
                provenance=Provenance.DETECTED, detection_id=None, event_id=_EVENT_ID
            )

    def test_extra_references_beyond_the_required_are_allowed(self):
        evidence = _evidence(
            provenance=Provenance.DETECTED,
            detection_id=_DETECTION_ID,
            event_id=_EVENT_ID,
        )
        assert evidence.event_id == _EVENT_ID

    def test_invalid_uuid_references_rejected(self):
        with pytest.raises(ValidationError):
            _evidence(provenance=Provenance.DETECTED, detection_id="not-a-uuid")
        with pytest.raises(ValidationError):
            _evidence(provenance=Provenance.OBSERVED, event_id="not-a-uuid")
        with pytest.raises(ValidationError):
            _evidence(provenance=Provenance.CORRELATED, correlation_id="not-a-uuid")
        with pytest.raises(ValidationError):
            _evidence(
                provenance=Provenance.RISK_ASSESSED, risk_assessment_id="not-a-uuid"
            )


# ---------------------------------------------------------------------------
# 11. Evidence provenance — AI_GENERATED forbidden
# ---------------------------------------------------------------------------

class TestEvidenceForbidsAiGenerated:
    """Evidence is source-backed; AI-generated content can never be evidence."""

    def test_ai_generated_rejected_even_with_reference(self):
        with pytest.raises(ValidationError):
            _evidence(
                evidence_type="ai_claim",
                provenance=Provenance.AI_GENERATED,
                event_id=_EVENT_ID,
            )

    def test_ai_generated_rejected_on_all_evidence_forms(self):
        for provenance, (field_name, ref) in _SOURCE_REFERENCE.items():
            with pytest.raises(ValidationError):
                _evidence(provenance=Provenance.AI_GENERATED, **{field_name: ref})


# ---------------------------------------------------------------------------
# 12. Provenance test matrix (explicit)
# ---------------------------------------------------------------------------

class TestProvenanceMatrix:
    """Explicit matrix: valid usage / invalid usage / serialization / distinction."""

    @pytest.mark.parametrize(
        "provenance", sorted(_SOURCE_REFERENCE, key=lambda p: p.value)
    )
    def test_valid_evidence_usage(self, provenance):
        field_name, ref = _SOURCE_REFERENCE[provenance]
        evidence = _evidence(provenance=provenance, **{field_name: ref})
        assert evidence.provenance == provenance

    @pytest.mark.parametrize(
        "provenance", sorted(_SOURCE_REFERENCE, key=lambda p: p.value)
    )
    def test_invalid_evidence_usage_missing_reference(self, provenance):
        field_name, _ = _SOURCE_REFERENCE[provenance]
        with pytest.raises(ValidationError):
            _evidence(provenance=provenance, **{field_name: None})

    @pytest.mark.parametrize(
        "provenance", sorted(_SOURCE_REFERENCE, key=lambda p: p.value)
    )
    def test_serialisation_uses_provenance_value(self, provenance):
        field_name, ref = _SOURCE_REFERENCE[provenance]
        evidence = _evidence(provenance=provenance, **{field_name: ref})
        assert evidence.model_dump(mode="json")["provenance"] == provenance.value

    @pytest.mark.parametrize(
        "provenance",
        [
            Provenance.OBSERVED,
            Provenance.ENRICHED,
            Provenance.RECONSTRUCTED,
            Provenance.DETECTED,
            Provenance.CORRELATED,
            Provenance.RISK_ASSESSED,
        ],
    )
    def test_finding_never_serialises_as_other_provenance(self, provenance):
        serialized = _finding().model_dump(mode="json")["provenance"]
        assert serialized == "ai_generated"
        assert serialized != provenance.value

    def test_ai_generated_evidence_invalid_usage(self):
        with pytest.raises(ValidationError):
            _evidence(provenance=Provenance.AI_GENERATED, event_id=_EVENT_ID)

    def test_ai_generated_observation_valid_usage(self):
        observation = _observation(provenance=Provenance.AI_GENERATED)
        assert observation.provenance == Provenance.AI_GENERATED

    def test_ai_generated_serialisation(self):
        assert Provenance.AI_GENERATED.value == "ai_generated"
        serialized = _minimal_result().model_dump(mode="json")["provenance"]
        assert serialized == "ai_generated"

    def test_semantic_observed_vs_ai_generated_distinct(self):
        observed = _observation(provenance=Provenance.OBSERVED)
        generated = _observation(
            observation_type="ai_reasoning",
            observation_text="hypothesis",
            provenance=Provenance.AI_GENERATED,
        )
        assert observed.model_dump(mode="json")["provenance"] == "observed"
        assert generated.model_dump(mode="json")["provenance"] == "ai_generated"
        assert observed.provenance is not generated.provenance

    def test_unknown_provenance_value_rejected_everywhere(self):
        with pytest.raises(ValidationError):
            _evidence(provenance="made_up", detection_id=_DETECTION_ID)
        with pytest.raises(ValidationError):
            _observation(provenance="made_up")
        with pytest.raises(ValidationError):
            _finding(provenance="made_up")
        with pytest.raises(ValidationError):
            _minimal_result(provenance="made_up")


# ---------------------------------------------------------------------------
# 13. InvestigationObservation validation
# ---------------------------------------------------------------------------

class TestObservationValidation:
    """Observations are declared contextual statements."""

    def test_observation_constructs(self):
        observation = _observation()
        assert observation.observation_type == "context_summary"
        assert observation.observation_text == "single host activity"

    def test_observation_type_required(self):
        with pytest.raises(ValidationError):
            InvestigationObservation(
                observation_text="x", provenance=Provenance.OBSERVED
            )

    def test_observation_text_required(self):
        with pytest.raises(ValidationError):
            InvestigationObservation(
                observation_type="x", provenance=Provenance.OBSERVED
            )

    def test_provenance_required(self):
        with pytest.raises(ValidationError):
            InvestigationObservation(observation_type="x", observation_text="y")

    def test_observation_type_blank_rejected(self):
        with pytest.raises(ValidationError):
            _observation(observation_type="  ")

    def test_observation_text_blank_rejected(self):
        with pytest.raises(ValidationError):
            _observation(observation_text="   ")

    def test_observation_text_stripped(self):
        observation = _observation(observation_text="  host talks out  ")
        assert observation.observation_text == "host talks out"

    def test_metadata_defaults_empty(self):
        assert _observation().metadata == {}


# ---------------------------------------------------------------------------
# 14. Observation provenance — generated vs observed
# ---------------------------------------------------------------------------

class TestObservationProvenance:
    """An AI inference must declare AI_GENERATED; never observed."""

    def test_observed_provenance_accepted(self):
        assert _observation().provenance == Provenance.OBSERVED

    def test_ai_generated_provenance_accepted(self):
        observation = _observation(provenance=Provenance.AI_GENERATED)
        assert observation.provenance == Provenance.AI_GENERATED

    def test_invalid_provenance_string_rejected(self):
        with pytest.raises(ValidationError):
            _observation(provenance="observed_via_ai")

    def test_source_backed_declaration_is_distinct_from_generated(self):
        observed = _observation(provenance=Provenance.OBSERVED)
        generated = _observation(
            observation_type="ai_reasoning",
            observation_text="the timeline is consistent with staging",
            provenance=Provenance.AI_GENERATED,
        )
        assert observed.provenance == Provenance.OBSERVED
        assert generated.provenance == Provenance.AI_GENERATED
        assert observed.model_dump(mode="json")["provenance"] != generated.model_dump(mode="json")["provenance"]

    def test_ai_generated_serialises_as_ai_generated(self):
        observation = _observation(provenance=Provenance.AI_GENERATED)
        assert observation.model_dump(mode="json")["provenance"] == "ai_generated"


# ---------------------------------------------------------------------------
# 15. Timestamp validation
# ---------------------------------------------------------------------------

class TestTimestampValidation:
    """Timezone-aware timestamps only; deterministic serialization."""

    def test_timestamp_required(self):
        with pytest.raises(ValidationError):
            InvestigationResult(correlation_id=_CORRELATION_ID)

    def test_naive_timestamp_rejected(self):
        naive = datetime(2026, 5, 1, 12, 0, 0)
        with pytest.raises(ValidationError):
            _minimal_result(timestamp=naive)

    def test_tz_aware_timestamp_accepted(self):
        result = _minimal_result()
        assert result.timestamp == _FIXED_TS

    def test_utc_offset_preserved(self):
        shifted = datetime(2026, 5, 1, 8, 0, 0, tzinfo=timezone.utc)
        result = _minimal_result(timestamp=shifted)
        assert result.timestamp == shifted

    def test_deterministic_timestamp_serialization(self):
        result = _minimal_result()
        serialized = json.loads(result.model_dump_json())
        assert serialized["timestamp"] == "2026-05-01T12:00:00Z"

    def test_timestamp_is_bookkeeping_not_evidence(self):
        assert "timestamp" in InvestigationResult.model_fields
        assert not hasattr(InvestigationResult, "first_seen_at")
        assert not hasattr(InvestigationResult, "last_seen_at")


# ---------------------------------------------------------------------------
# 16. Metadata validation
# ---------------------------------------------------------------------------

class TestMetadataValidation:
    """Metadata is JSON-compatible, deeply validated, and independent."""

    def test_empty_metadata_allowed(self):
        assert _minimal_result(metadata={}).metadata == {}
        assert _finding(metadata={}).metadata == {}
        assert _evidence(metadata={}).metadata == {}
        assert _observation(metadata={}).metadata == {}

    def test_nested_metadata_accepted(self):
        result = _minimal_result(
            metadata={"nested": {"list": [1, 2, {"a": "b"}]}, "flag": True}
        )
        assert result.metadata == {"nested": {"list": [1, 2, {"a": "b"}]}, "flag": True}

    def test_non_json_metadata_rejected_on_result(self):
        with pytest.raises(ValidationError):
            _minimal_result(metadata={"blob": object()})

    def test_non_json_metadata_rejected_on_finding(self):
        with pytest.raises(ValidationError):
            _finding(metadata={"blob": object()})

    def test_non_json_metadata_rejected_on_evidence(self):
        with pytest.raises(ValidationError):
            _evidence(metadata={"blob": object()})

    def test_non_json_metadata_rejected_on_observation(self):
        with pytest.raises(ValidationError):
            _observation(metadata={"blob": object()})

    def test_cyclic_metadata_rejected(self):
        cyclic: dict = {"self": None}
        cyclic["self"] = cyclic
        with pytest.raises(ValidationError):
            _minimal_result(metadata=cyclic)
        with pytest.raises(ValidationError):
            _finding(metadata=cyclic)
        with pytest.raises(ValidationError):
            _evidence(metadata=cyclic)
        with pytest.raises(ValidationError):
            _observation(metadata=cyclic)

    def test_result_metadata_json_serializable(self):
        result = _minimal_result(metadata={"nested": [1, {"k": "v"}]})
        json.dumps(result.metadata)


# ---------------------------------------------------------------------------
# 17. Secret safety
# ---------------------------------------------------------------------------

class TestSecretSafety:
    """Credential-shaped content is rejected by the existing policy."""

    def test_result_metadata_rejects_api_key(self):
        with pytest.raises(ValidationError):
            _minimal_result(metadata={"api_key": "AKIAIOSFODNN7EXAMPLE"})

    def test_result_metadata_rejects_bearer_token(self):
        with pytest.raises(ValidationError):
            _minimal_result(metadata={"token": "Bearer xxx"})

    def test_result_metadata_rejects_authorization_header(self):
        with pytest.raises(ValidationError):
            _minimal_result(metadata={"headers": {"Authorization": "Basic abc"}})

    def test_result_metadata_rejects_client_secret(self):
        with pytest.raises(ValidationError):
            _minimal_result(metadata={"client_secret": "pw"})

    def test_result_metadata_rejects_jwt_under_matching_key(self):
        with pytest.raises(ValidationError):
            _minimal_result(
                metadata={"jwt_secret": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.abc"}
            )

    def test_result_metadata_rejects_database_credential_shapes(self):
        with pytest.raises(ValidationError):
            _minimal_result(
                metadata={"db": {"client_secret": "postgresql://user:pass@host:5432/db"}}
            )

    def test_evidence_metadata_rejects_api_key(self):
        with pytest.raises(ValidationError):
            _evidence(metadata={"api_key": "sk-1234"})

    def test_finding_metadata_rejects_bearer(self):
        with pytest.raises(ValidationError):
            _finding(metadata={"token": "Bearer xyz"})

    def test_observation_metadata_rejects_authorization(self):
        with pytest.raises(ValidationError):
            _observation(metadata={"authorization": "Bearer xyz"})

    def test_secret_shaped_label_on_finding_rejected_by_result(self):
        with pytest.raises(ValidationError):
            InvestigationResult(
                **_result_payload(
                    findings=[_finding(title="rotating api_key secrets")]
                )
            )

    def test_secret_shaped_observation_text_rejected_by_result(self):
        with pytest.raises(ValidationError):
            InvestigationResult(
                **_result_payload(
                    observations=[
                        _observation(
                            observation_type="context_summary",
                            observation_text="captured Authorization header value",
                            provenance=Provenance.OBSERVED,
                        )
                    ]
                )
            )

    def test_secret_shaped_metadata_in_evidence_rejected_by_result(self):
        with pytest.raises(ValidationError):
            InvestigationResult(
                **_result_payload(
                    evidence=[_evidence(metadata={"rule": "x", "api_key": "k"})]
                )
            )

    def test_no_secret_keys_anywhere_in_contract_fields(self):
        all_fields = (
            set(InvestigationResult.model_fields.keys())
            | set(InvestigationFinding.model_fields.keys())
            | set(InvestigationEvidence.model_fields.keys())
            | set(InvestigationObservation.model_fields.keys())
        )
        for name in ("password", "api_key", "token", "authorization", "secret", "cookie"):
            assert name not in all_fields


# ---------------------------------------------------------------------------
# 18. JSON safety and round-trip
# ---------------------------------------------------------------------------

class TestJsonCompatibility:
    """The whole contract round-trips as strict JSON."""

    def test_model_dump_uses_json_types(self):
        result = InvestigationResult(**_result_payload())
        dumped = result.model_dump(mode="json")
        json.dumps(dumped)

    def test_json_round_trip_preserves_contract(self):
        original = InvestigationResult(**_result_payload())
        restored = InvestigationResult.model_validate_json(original.model_dump_json())
        assert restored.model_dump() == original.model_dump()

    def test_serialised_finding_provenance_is_ai_generated(self):
        payload = _result_payload()
        serialized = json.dumps(
            InvestigationResult(**payload).model_dump(mode="json")
        )
        assert '"provenance": "ai_generated"' in serialized
        finding_serialized = json.dumps(payload["findings"][0].model_dump(mode="json"))
        assert '"observed"' not in finding_serialized
        assert '"ai_generated"' in finding_serialized


# ---------------------------------------------------------------------------
# 19. Evidence reference resolution
# ---------------------------------------------------------------------------

class TestEvidenceReferenceResolution:
    """Finding evidence references must resolve to the result's evidence."""

    def test_references_resolve(self):
        result = InvestigationResult(**_result_payload())
        assert result.findings[0].evidence_ids == [
            result.evidence[0].evidence_id
        ]

    def test_multi_reference_finding_resolves(self):
        ev1 = _evidence()
        ev2 = _evidence(provenance=Provenance.OBSERVED, event_id=_EVENT_ID)
        result = InvestigationResult(
            **_result_payload(
                findings=[_finding(evidence_ids=[ev1.evidence_id, ev2.evidence_id])],
                evidence=[ev1, ev2],
            )
        )
        assert len(result.findings[0].evidence_ids) == 2

    def test_unresolved_reference_rejected(self):
        ghost = uuid.uuid4()
        with pytest.raises(ValidationError):
            InvestigationResult(
                **_result_payload(findings=[_finding(evidence_ids=[ghost])])
            )

    def test_partially_unresolved_reference_rejected(self):
        ev = _evidence()
        ghost = uuid.uuid4()
        with pytest.raises(ValidationError):
            InvestigationResult(
                **_result_payload(
                    findings=[_finding(evidence_ids=[ev.evidence_id, ghost])],
                    evidence=[ev],
                )
            )

    def test_duplicate_reference_preserved(self):
        ev = _evidence()
        result = InvestigationResult(
            **_result_payload(
                findings=[_finding(evidence_ids=[ev.evidence_id, ev.evidence_id])],
                evidence=[ev],
            )
        )
        assert result.findings[0].evidence_ids == [ev.evidence_id, ev.evidence_id]

    def test_empty_references_resolve(self):
        result = _minimal_result(findings=[_finding()])
        assert result.findings[0].evidence_ids == []


# ---------------------------------------------------------------------------
# 20. Ordering is preserved (never sorted or deduplicated)
# ---------------------------------------------------------------------------

class TestOrderingPreserved:
    """Structured lists preserve input order; no silent dedup/sort."""

    def test_finding_order_preserved(self):
        result = InvestigationResult(
            **_result_payload(
                findings=[
                    _finding(finding_type="aaa", title="A", confidence=0.3),
                    _finding(finding_type="bbb", title="B", confidence=0.5),
                    _finding(finding_type="ccc", title="C", confidence=0.7),
                ]
            )
        )
        assert [f.finding_type for f in result.findings] == ["aaa", "bbb", "ccc"]

    def test_evidence_order_preserved(self):
        ev1 = _evidence(provenance=Provenance.OBSERVED, event_id=_EVENT_ID)
        ev2 = _evidence(provenance=Provenance.CORRELATED, correlation_id=_CORRELATION_ID)
        result = InvestigationResult(
            **_result_payload(evidence=[ev1, ev2], findings=[])
        )
        assert result.evidence[0].evidence_id == ev1.evidence_id
        assert result.evidence[1].evidence_id == ev2.evidence_id

    def test_observation_order_preserved(self):
        result = InvestigationResult(
            **_result_payload(
                observations=[
                    _observation(observation_type="first", observation_text="a"),
                    _observation(observation_type="second", observation_text="b"),
                ]
            )
        )
        assert [o.observation_type for o in result.observations] == ["first", "second"]

    def test_duplicate_observations_preserved(self):
        result = InvestigationResult(
            **_result_payload(
                observations=[
                    _observation(),
                    _observation(),
                ]
            )
        )
        assert len(result.observations) == 2


# # ---------------------------------------------------------------------------
# 21. Deterministic serialization
# ---------------------------------------------------------------------------

class TestDeterministicSerialization:
    """Same input -> identical serialized output (no nondeterministic IDs)."""

    def test_same_input_same_output(self):
        investigation_id = uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")
        a = _minimal_result(investigation_id=investigation_id)
        b = _minimal_result(investigation_id=investigation_id)
        assert a.model_dump_json() == b.model_dump_json()

    def test_serialization_does_not_reorder(self):
        finding_ids = [uuid.uuid4() for _ in range(3)]
        findings = [
            _finding(finding_type=f"t{i}", title=f"T{i}", confidence=0.5)
            for i in range(3)
        ]
        result = InvestigationResult(
            **_result_payload(findings=findings, evidence=[])
        )
        serialized = json.loads(result.model_dump_json())
        assert [f["finding_type"] for f in serialized["findings"]] == ["t0", "t1", "t2"]


# ---------------------------------------------------------------------------
# 22. Equality behavior
# ---------------------------------------------------------------------------

class TestEquality:
    """Value equality, structural and JSON-based."""

    def test_equal_results_equal(self):
        investigation_id = uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")
        a = _minimal_result(investigation_id=investigation_id)
        b = _minimal_result(investigation_id=investigation_id)
        assert a == b

    def test_different_correlation_not_equal(self):
        a = _minimal_result()
        b = _minimal_result(correlation_id=uuid.uuid4())
        assert a != b

    def test_different_confidence_not_equal(self):
        a = _minimal_result(confidence=0.2)
        b = _minimal_result(confidence=0.8)
        assert a != b

    def test_mixed_payload_not_equal_to_empty(self):
        result = InvestigationResult(**_result_payload())
        assert result != _minimal_result()


# ---------------------------------------------------------------------------
# 23. Input immutability / aliasing
# ---------------------------------------------------------------------------

class TestInputImmutability:
    """Constructors and validators never alias mutable input."""

    def test_construction_does_not_mutate_payload(self):
        payload = _result_payload()
        snapshot = copy.deepcopy(payload)
        InvestigationResult(**payload)
        assert payload == snapshot

    def test_result_metadata_independent_from_input(self):
        payload = _result_payload(metadata={"nested": {"list": [1, 2]}})
        source = payload["metadata"]
        result = InvestigationResult(**payload)
        source["nested"]["list"].append(99)
        assert result.metadata == {"nested": {"list": [1, 2]}}

    def test_finding_metadata_independent_from_input(self):
        source = {"nested": {"a": [1]}}
        finding = _finding(metadata=source)
        source["nested"]["a"].append(2)
        assert finding.metadata == {"nested": {"a": [1]}}

    def test_evidence_metadata_independent_from_input(self):
        source = {"nested": {"a": [1]}}
        evidence = _evidence(metadata=source)
        source["nested"]["a"].append(2)
        assert evidence.metadata == {"nested": {"a": [1]}}

    def test_observation_metadata_independent_from_input(self):
        source = {"nested": {"a": [1]}}
        observation = _observation(metadata=source)
        source["nested"]["a"].append(2)
        assert observation.metadata == {"nested": {"a": [1]}}

    def test_deep_copied_result_is_independent(self):
        result = InvestigationResult(**_result_payload(metadata={"nested": {"a": [1]}}))
        clone = result.model_copy(deep=True)
        clone.metadata["nested"]["a"].append(2)
        assert result.metadata == {"nested": {"a": [1]}}

    def test_evidence_ids_list_is_independent(self):
        references = [uuid.uuid4()]
        finding = _finding(evidence_ids=references)
        references.append(uuid.uuid4())
        assert finding.evidence_ids == [references[0]]


# ---------------------------------------------------------------------------
# 24. Unknown-field behavior (existing Pydantic configuration)
# ---------------------------------------------------------------------------

class TestUnknownFields:
    """Extra fields follow the existing SentinelAI policy (ignored)."""

    def test_unknown_fields_are_ignored(self):
        result = _minimal_result(surprise_field=1, another={"x": 1})
        assert "surprise_field" not in type(result).model_fields
        assert getattr(result, "surprise_field", None) is None
        assert isinstance(result, InvestigationResult)

    def test_unknown_fields_ignored_on_components(self):
        finding = _finding(unexpected=True)
        assert "unexpected" not in type(finding).model_fields
        evidence = _evidence(unexpected=True)
        assert "unexpected" not in type(evidence).model_fields


# ---------------------------------------------------------------------------
# 25. Oversized payload handling
# ---------------------------------------------------------------------------

class TestOversizedPayloads:
    """Large structured payloads are accepted; pathological ones are not."""

    def test_many_findings_accepted(self):
        findings = [_finding(finding_type=f"t{i}", title=f"T{i}", confidence=0.5) for i in range(500)]
        result = _minimal_result(findings=findings)
        assert len(result.findings) == 500

    def test_large_evidence_list_accepted(self):
        evidence = [_evidence() for _ in range(500)]
        result = _minimal_result(evidence=evidence)
        assert len(result.evidence) == 500

    def test_large_metadata_dict_accepted(self):
        big = {f"k{i}": i for i in range(5000)}
        result = _minimal_result(metadata=big)
        assert len(result.metadata) == 5000

    def test_deeply_nested_but_json_metadata_accepted(self):
        nested: dict = {"a": {"a": {"a": {"a": {"a": 1}}}}}
        result = _minimal_result(metadata=nested)
        assert result.metadata == nested


# ---------------------------------------------------------------------------
# 26. Contract boundary: no future-layer concepts
# ---------------------------------------------------------------------------

class TestContractBoundary:
    """No AI/incident/MITRE/response/persistence/API concepts in the contract."""

    FORBIDDEN = {
        "incident",
        "incident_id",
        "incident_severity",
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
        "embedding",
        "vector",
        "vector_store",
        "llm",
        "prompt",
        "prompt_template",
        "model_name",
        "tokens",
        "context_builder",
        "investigation_context",
    }

    def test_no_future_layer_fields(self):
        fields = (
            set(InvestigationResult.model_fields.keys())
            | set(InvestigationFinding.model_fields.keys())
            | set(InvestigationEvidence.model_fields.keys())
            | set(InvestigationObservation.model_fields.keys())
        )
        for name in self.FORBIDDEN:
            assert name not in fields, f"unexpected future-layer field: {name}"

    def test_result_fields_are_exactly_the_contract_fields(self):
        assert set(InvestigationResult.model_fields.keys()) == {
            "investigation_id",
            "correlation_id",
            "risk_assessment_id",
            "confidence",
            "findings",
            "evidence",
            "observations",
            "metadata",
            "timestamp",
            "provenance",
        }

    def test_finding_fields_are_exactly_the_contract_fields(self):
        assert set(InvestigationFinding.model_fields.keys()) == {
            "finding_type",
            "title",
            "summary",
            "confidence",
            "evidence_ids",
            "metadata",
            "provenance",
        }

    def test_evidence_fields_are_exactly_the_contract_fields(self):
        assert set(InvestigationEvidence.model_fields.keys()) == {
            "evidence_id",
            "evidence_type",
            "provenance",
            "detection_id",
            "event_id",
            "correlation_id",
            "risk_assessment_id",
            "metadata",
        }

    def test_observation_fields_are_exactly_the_contract_fields(self):
        assert set(InvestigationObservation.model_fields.keys()) == {
            "observation_type",
            "observation_text",
            "provenance",
            "metadata",
        }

    def test_no_agent_or_context_types(self):
        assert not hasattr(investigation_module, "InvestigationAgent")
        assert not hasattr(investigation_module, "InvestigationContext")
        assert not hasattr(investigation_module, "InvestigationContextBuilder")
        assert not hasattr(investigation_module, "InvestigationRunner")

    def test_no_repository_service_or_api_types(self):
        assert not hasattr(investigation_module, "InvestigationRepository")
        assert not hasattr(investigation_module, "InvestigationQueryService")
        assert not hasattr(investigation_module, "InvestigationApiRouter")
        assert not hasattr(investigation_module, "InvestigationPersistenceService")

    def test_no_incident_or_mitre_types(self):
        assert not hasattr(investigation_module, "Incident")
        assert not hasattr(investigation_module, "MitreAttack")
        assert not hasattr(investigation_module, "ResponseAction")


# ---------------------------------------------------------------------------
# 27. No AI logic
# ---------------------------------------------------------------------------

class TestNoAiLogic:
    """12A is a pure contract: no LLM/Ollama/embedding/vector concepts."""

    def test_module_source_has_no_ai_framework_tokens(self):
        source = inspect.getsource(investigation_module)
        import_lines = "\n".join(
            line
            for line in source.splitlines()
            if line.lstrip().startswith(("import ", "from "))
        ).lower()
        for token in (
            "ollama",
            "openai",
            "anthropic",
            "langchain",
            "langgraph",
            "qdrant",
            "llm",
            "embedding",
            "prompt",
        ):
            assert token not in import_lines, f"unexpected AI import token: {token}"
        for name in (
            "InvestigationAgent",
            "InvestigationRunner",
            "ModelClient",
            "LlmClient",
            "EmbeddingModel",
        ):
            assert not hasattr(investigation_module, name)

    def test_no_reasoning_helpers_defined(self):
        for helper in (
            "analyze",
            "investigate",
            "reason",
            "generate_findings",
            "build_context",
            "run_investigation",
            "ask_model",
        ):
            assert not hasattr(investigation_module, helper)


# ---------------------------------------------------------------------------
# 28. No persistence / API
# ---------------------------------------------------------------------------

class TestNoPersistenceOrApi:
    """The module defines schemas only; imports stay pure."""

    def test_module_imports_only_pydantic_and_provenance(self):
        source = inspect.getsource(investigation_module)
        assert "from app.schemas.security_event import Provenance" in source
        assert "from pydantic" in source
        assert "import models" not in source
        assert "from app.repositories" not in source
        assert "from app.services" not in source
        assert "from app.agents" not in source
        assert "from app.api" not in source
        assert "fastapi" not in source

    def test_schema_is_constructible_without_database(self):
        result = InvestigationResult(**_result_payload())
        assert isinstance(result, InvestigationResult)
        assert result.metadata == {"region": "eu"}


# ---------------------------------------------------------------------------
# 29. Dependency isolation
# ---------------------------------------------------------------------------

class TestDependencyIsolation:
    """A clean import of the investigation contract pulls in no frameworks."""

    def test_module_imports_no_storage_api_or_bus(self):
        source = inspect.getsource(investigation_module)
        for forbidden in (
            "sqlalchemy",
            "fastapi",
            "kafka",
            "rabbitmq",
            "redis",
            "amqp",
            "opensearch",
            "qdrant",
            "neo4j",
            "httpx",
            "requests",
            "socket",
            "subprocess",
            "http.client",
        ):
            assert forbidden not in source, (
                f"investigation contract must not import {forbidden}"
            )

    def test_allowed_imports_only(self):
        source = inspect.getsource(investigation_module)
        assert "import json" in source
        assert "import uuid" in source
        assert "from datetime import datetime" in source


# ---------------------------------------------------------------------------
# 30. Provenance regression: earlier boundaries are unchanged
# ---------------------------------------------------------------------------

class TestProvenanceRegression:
    """AI_GENERATED is additive; detection/correlation/risk are unchanged."""

    def test_existing_members_preserved(self):
        assert Provenance.OBSERVED.value == "observed"
        assert Provenance.ENRICHED.value == "enriched"
        assert Provenance.RECONSTRUCTED.value == "reconstructed"
        assert Provenance.DETECTED.value == "detected"
        assert Provenance.CORRELATED.value == "correlated"
        assert Provenance.RISK_ASSESSED.value == "risk_assessed"

    def test_ai_generated_is_global_member(self):
        assert Provenance.AI_GENERATED in Provenance
        assert Provenance.AI_GENERATED.value == "ai_generated"

    def test_risk_assessment_still_pinned(self):
        with pytest.raises(ValidationError):
            RiskAssessment(
                correlation_id=_CORRELATION_ID,
                score=0.5,
                level=RiskLevel.MEDIUM,
                confidence=0.5,
                timestamp=_FIXED_TS,
                provenance=Provenance.AI_GENERATED,
            )

    def test_correlation_still_requires_correlated(self):
        with pytest.raises(ValidationError):
            CorrelationResult(
                correlation_id=_CORRELATION_ID,
                members=[
                    CorrelationMember(
                        detection_id=_DETECTION_ID,
                        event_id=_EVENT_ID,
                        timestamp=_FIXED_TS,
                    )
                ],
                timestamp=_FIXED_TS,
                provenance=Provenance.AI_GENERATED,
            )

    def test_finding_is_ai_generated_not_a_weakened_risk_boundary(self):
        assert _finding().provenance == Provenance.AI_GENERATED
        assert Provenance.AI_GENERATED is not Provenance.RISK_ASSESSED


# ---------------------------------------------------------------------------
# 31. Package re-export
# ---------------------------------------------------------------------------

class TestPackageExports:
    def test_investigation_schemas_exported_from_package(self):
        from app.schemas import (
            InvestigationEvidence as PkgEvidence,
            InvestigationFinding as PkgFinding,
            InvestigationObservation as PkgObservation,
            InvestigationResult as PkgResult,
        )

        assert PkgResult is InvestigationResult
        assert PkgFinding is InvestigationFinding
        assert PkgEvidence is InvestigationEvidence
        assert PkgObservation is InvestigationObservation