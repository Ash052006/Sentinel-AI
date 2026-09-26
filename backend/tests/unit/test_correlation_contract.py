"""Tests for the Correlation Domain Contract (Step 10A).

Covers the CorrelationResult / CorrelationMember / CorrelationStatus
contract, the ``CORRELATED`` provenance marker, the pure adapter
``to_correlation_members``, traceability, one-event-to-many-detection
representation, confidence bounds, temporal boundaries, JSON
compatibility, secret-safety, immutability, serialization round-trips,
and contract-boundary enforcement (no risk / incident / MITRE / response /
algorithm-specific concepts).

These are pure unit tests of the **contract** — no database connection,
no repository, no API, and no network calls are made.  They never test
correlation *logic* (no "same IP must correlate", no "within five
minutes" rules): 10A tests the contract, not the algorithm.
"""

import copy
import inspect
import json
import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

import app.schemas.correlation as correlation_module
from app.schemas.correlation import (
    CorrelationMember,
    CorrelationResult,
    CorrelationStatus,
    to_correlation_members,
)
from app.schemas.detection import DetectionSeverity, RuleType
from app.schemas.detection_correlation import DetectionCorrelationInput
from app.schemas.security_event import Provenance


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FIXED_TS = datetime(2025, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
_LATER_TS = datetime(2025, 8, 1, 12, 30, 0, tzinfo=timezone.utc)
_EVEN_LATER_TS = datetime(2025, 8, 1, 13, 0, 0, tzinfo=timezone.utc)

_DETECTION_1 = uuid.UUID("11111111-1111-1111-1111-111111111111")
_DETECTION_2 = uuid.UUID("22222222-2222-2222-2222-222222222222")
_DETECTION_3 = uuid.UUID("33333333-3333-3333-3333-333333333333")
_EVENT_1 = uuid.UUID("44444444-4444-4444-4444-444444444444")
_EVENT_2 = uuid.UUID("55555555-5555-5555-5555-555555555555")
_EVENT_3 = uuid.UUID("66666666-6666-6666-6666-666666666666")


def _correlation_input(
    *,
    detection_id: uuid.UUID = _DETECTION_1,
    event_id: uuid.UUID = _EVENT_1,
    timestamp: datetime = _FIXED_TS,
    provenance: Provenance = Provenance.DETECTED,
) -> DetectionCorrelationInput:
    """Return a minimal valid Step 9I DetectionCorrelationInput."""
    return DetectionCorrelationInput(
        detection_id=detection_id,
        event_id=event_id,
        timestamp=timestamp,
        rule_id="sigma-credential-access-001",
        rule_type=RuleType.SIGMA,
        rule_version="1.2.3",
        severity=DetectionSeverity.HIGH,
        confidence=0.9,
        evidence={
            "matched_conditions": ["condition_1"],
            "detection_context": {"engine": "sigma"},
        },
        metadata={"rule_version": "1.2.3", "extra": {"engine": "sigma"}},
        provenance=provenance,
    )


def _member(
    *,
    detection_id: uuid.UUID = _DETECTION_1,
    event_id: uuid.UUID = _EVENT_1,
    timestamp: datetime = _FIXED_TS,
) -> CorrelationMember:
    """Return a minimal valid CorrelationMember."""
    return CorrelationMember(
        detection_id=detection_id,
        event_id=event_id,
        timestamp=timestamp,
    )


def _result_payload(**overrides) -> dict:
    """Return a minimal valid CorrelationResult payload dict (kwargs win)."""
    base: dict = {
        "correlation_id": uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        "members": [_member()],
        "timestamp": _FIXED_TS,
        "evidence": {"basis": "explicit-membership"},
        "metadata": {"source": "unit-test"},
    }
    base.update(overrides)
    return base
# ---------------------------------------------------------------------------
# 1. A valid CorrelationResult constructs correctly
# ---------------------------------------------------------------------------


class TestValidCorrelationResult:
    """Requirement 1: a valid CorrelationResult is accepted (23-26 too)."""

    def test_valid_result_constructs(self):
        result = CorrelationResult(**_result_payload())
        assert isinstance(result, CorrelationResult)

    def test_default_status_is_candidate(self):
        result = CorrelationResult(**_result_payload())
        assert result.status == CorrelationStatus.CANDIDATE

    def test_explicit_status_preserved(self):
        result = CorrelationResult(
            **_result_payload(status=CorrelationStatus.ACTIVE)
        )
        assert result.status == CorrelationStatus.ACTIVE

    def test_confidence_defaults_to_none(self):
        result = CorrelationResult(**_result_payload())
        assert result.confidence is None

    def test_confidence_preserved_when_given(self):
        result = CorrelationResult(**_result_payload(confidence=0.75))
        assert result.confidence == 0.75

    def test_multiple_detections_supported(self):
        result = CorrelationResult(
            **_result_payload(
                members=[
                    _member(detection_id=_DETECTION_1, event_id=_EVENT_1),
                    _member(detection_id=_DETECTION_2, event_id=_EVENT_1),
                    _member(detection_id=_DETECTION_3, event_id=_EVENT_1),
                ]
            )
        )
        assert result.detection_ids == (
            _DETECTION_1,
            _DETECTION_2,
            _DETECTION_3,
        )

    def test_multiple_events_supported(self):
        result = CorrelationResult(
            **_result_payload(
                members=[
                    _member(detection_id=_DETECTION_1, event_id=_EVENT_1),
                    _member(detection_id=_DETECTION_2, event_id=_EVENT_2),
                    _member(detection_id=_DETECTION_3, event_id=_EVENT_3),
                ]
            )
        )
        assert result.event_ids == (_EVENT_1, _EVENT_2, _EVENT_3)

    def test_one_event_multiple_detections_supported(self):
        """One event -> many detections is explicitly representable."""
        result = CorrelationResult(
            **_result_payload(
                members=[
                    _member(detection_id=_DETECTION_1, event_id=_EVENT_1),
                    _member(detection_id=_DETECTION_2, event_id=_EVENT_1),
                ]
            )
        )
        assert result.event_ids == (_EVENT_1, _EVENT_1)
        assert result.detection_ids == (_DETECTION_1, _DETECTION_2)

    def test_multiple_correlations_representable(self):
        first = CorrelationResult(**_result_payload())
        second = CorrelationResult(
            **_result_payload(
                members=[_member(detection_id=_DETECTION_2, event_id=_EVENT_2)]
            )
        )
        assert isinstance(first, CorrelationResult)
        assert isinstance(second, CorrelationResult)
        assert first.detection_ids != second.detection_ids

    def test_empty_members_rejected(self):
        """A valid completed correlation references at least one detection."""
        with pytest.raises(ValidationError):
            CorrelationResult(**_result_payload(members=[]))


# ---------------------------------------------------------------------------
# 2. Correlation identity
# ---------------------------------------------------------------------------


class TestCorrelationIdentity:
    """Requirement 2/27: correlation_id is stable and independent."""

    def test_correlation_id_generated_when_omitted(self):
        payload = {
            key: value
            for key, value in _result_payload().items()
            if key != "correlation_id"
        }
        result = CorrelationResult(**payload)
        assert isinstance(result.correlation_id, uuid.UUID)
        assert result.correlation_id.version == 4

    def test_supplied_correlation_id_preserved(self):
        correlation_id = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
        result = CorrelationResult(**_result_payload(correlation_id=correlation_id))
        assert result.correlation_id == correlation_id

    def test_correlation_id_never_derived_from_detection_ids(self):
        result = CorrelationResult(**_result_payload())
        assert result.correlation_id not in result.detection_ids

    def test_correlation_id_never_derived_from_event_ids(self):
        result = CorrelationResult(**_result_payload())
        assert result.correlation_id not in result.event_ids

    def test_invalid_correlation_id_rejected(self):
        with pytest.raises(ValidationError):
            CorrelationResult(**_result_payload(correlation_id="not-a-uuid"))
# ---------------------------------------------------------------------------
# 3. Detection membership
# ---------------------------------------------------------------------------


class TestDetectionMembership:
    """Requirements 3, 10, 11, 22: exact, preserved, non-empty references."""

    def test_detection_ids_exposed_in_order(self):
        payload = _result_payload(
            members=[
                _member(detection_id=_DETECTION_2, event_id=_EVENT_1),
                _member(detection_id=_DETECTION_1, event_id=_EVENT_2),
            ]
        )
        result = CorrelationResult(**payload)
        assert result.detection_ids == (_DETECTION_2, _DETECTION_1)

    def test_detection_ids_preserved_exactly(self):
        result = CorrelationResult(**_result_payload())
        assert result.detection_ids == (_DETECTION_1,)
        assert result.members[0].detection_id == _DETECTION_1

    def test_duplicate_detection_ids_preserved(self):
        """Duplicates are documented and preserved, never silently dropped."""
        payload = _result_payload(
            members=[
                _member(detection_id=_DETECTION_1, event_id=_EVENT_1),
                _member(detection_id=_DETECTION_1, event_id=_EVENT_2),
            ]
        )
        result = CorrelationResult(**payload)
        assert result.detection_ids == (_DETECTION_1, _DETECTION_1)

    def test_invalid_detection_uuid_rejected(self):
        with pytest.raises(ValidationError):
            CorrelationMember(
                detection_id="not-a-uuid",
                event_id=_EVENT_1,
                timestamp=_FIXED_TS,
            )

    def test_missing_detection_id_rejected(self):
        payload = {
            "event_id": _EVENT_1,
            "timestamp": _FIXED_TS,
        }
        with pytest.raises(ValidationError):
            CorrelationMember(**payload)

    def test_member_fields_are_exactly_the_reference_fields(self):
        """A member is a reference — it never duplicates the detection."""
        assert set(CorrelationMember.model_fields.keys()) == {
            "detection_id",
            "event_id",
            "timestamp",
        }

    def test_members_never_duplicate_the_detection_record(self):
        assert not hasattr(CorrelationMember, "evidence")
        assert not hasattr(CorrelationMember, "rule_id")
        assert not hasattr(CorrelationMember, "severity")
        assert not hasattr(CorrelationMember, "confidence")
        assert not hasattr(CorrelationMember, "metadata")
# ---------------------------------------------------------------------------
# 4. Event references
# ---------------------------------------------------------------------------


class TestEventReferences:
    """Requirements 4, 12, 24-25: exact event identity is preserved."""

    def test_event_ids_exposed_in_order(self):
        payload = _result_payload(
            members=[
                _member(detection_id=_DETECTION_1, event_id=_EVENT_2),
                _member(detection_id=_DETECTION_2, event_id=_EVENT_1),
            ]
        )
        result = CorrelationResult(**payload)
        assert result.event_ids == (_EVENT_2, _EVENT_1)

    def test_event_ids_are_references_not_replacements(self):
        """event_ids stay source-event UUIDs; no new identity is invented."""
        result = CorrelationResult(**_result_payload())
        assert result.event_ids == (_EVENT_1,)
        for event_id in result.event_ids:
            assert event_id in (_EVENT_1, _EVENT_2, _EVENT_3)

    def test_invalid_event_uuid_rejected(self):
        with pytest.raises(ValidationError):
            CorrelationMember(
                detection_id=_DETECTION_1,
                event_id="not-a-uuid",
                timestamp=_FIXED_TS,
            )

    def test_missing_event_id_rejected(self):
        payload = {"detection_id": _DETECTION_1, "timestamp": _FIXED_TS}
        with pytest.raises(ValidationError):
            CorrelationMember(**payload)

    def test_one_event_many_detections_keeps_event_identity(self):
        payload = _result_payload(
            members=[
                _member(detection_id=_DETECTION_1, event_id=_EVENT_1),
                _member(detection_id=_DETECTION_2, event_id=_EVENT_1),
            ]
        )
        result = CorrelationResult(**payload)
        assert result.event_ids == (_EVENT_1, _EVENT_1)
        assert all(event_id == _EVENT_1 for event_id in result.event_ids)


# ---------------------------------------------------------------------------
# 5. Temporal information
# ---------------------------------------------------------------------------


class TestTemporalBounds:
    """Requirements 5, 6: tz-aware timestamps; descriptive boundaries."""

    def test_member_timestamp_required(self):
        payload = {
            "detection_id": _DETECTION_1,
            "event_id": _EVENT_1,
        }
        with pytest.raises(ValidationError):
            CorrelationMember(**payload)

    def test_naive_member_timestamp_rejected(self):
        naive = datetime(2025, 8, 1, 12, 0, 0)
        with pytest.raises(ValidationError):
            CorrelationMember(
                detection_id=_DETECTION_1,
                event_id=_EVENT_1,
                timestamp=naive,
            )

    def test_result_timestamp_required(self):
        payload = _result_payload()
        payload.pop("timestamp")
        with pytest.raises(ValidationError):
            CorrelationResult(**payload)

    def test_naive_result_timestamp_rejected(self):
        naive = datetime(2025, 8, 1, 12, 0, 0)
        with pytest.raises(ValidationError):
            CorrelationResult(**_result_payload(timestamp=naive))

    def test_member_timestamps_preserved(self):
        payload = _result_payload(
            members=[
                _member(detection_id=_DETECTION_1, timestamp=_FIXED_TS),
                _member(detection_id=_DETECTION_2, timestamp=_LATER_TS),
            ]
        )
        result = CorrelationResult(**payload)
        assert result.members[0].timestamp == _FIXED_TS
        assert result.members[1].timestamp == _LATER_TS

    def test_first_seen_and_last_seen_are_descriptive_boundaries(self):
        payload = _result_payload(
            members=[
                _member(detection_id=_DETECTION_1, timestamp=_FIXED_TS),
                _member(detection_id=_DETECTION_2, timestamp=_EVEN_LATER_TS),
                _member(detection_id=_DETECTION_3, timestamp=_LATER_TS),
            ]
        )
        result = CorrelationResult(**payload)
        assert result.first_seen_at == _FIXED_TS
        assert result.last_seen_at == _EVEN_LATER_TS

    def test_temporal_boundaries_are_not_stored_fields(self):
        """Boundaries are computed views — not time-window configuration."""
        fields = set(CorrelationResult.model_fields.keys())
        assert "first_seen_at" not in fields
        assert "last_seen_at" not in fields
        assert "time_window" not in fields
        assert "max_gap_seconds" not in fields


# ---------------------------------------------------------------------------
# 6. Confidence
# ---------------------------------------------------------------------------


class TestConfidence:
    """Requirements 7, 8, 9: correlation confidence is bounded [0.0, 1.0]."""

    def test_confidence_lower_bound_inclusive(self):
        result = CorrelationResult(**_result_payload(confidence=0.0))
        assert result.confidence == 0.0

    def test_confidence_upper_bound_inclusive(self):
        result = CorrelationResult(**_result_payload(confidence=1.0))
        assert result.confidence == 1.0

    def test_confidence_in_bounds_accepted(self):
        result = CorrelationResult(**_result_payload(confidence=0.42))
        assert result.confidence == 0.42

    def test_confidence_below_zero_rejected(self):
        with pytest.raises(ValidationError):
            CorrelationResult(**_result_payload(confidence=-0.01))

    def test_confidence_above_one_rejected(self):
        with pytest.raises(ValidationError):
            CorrelationResult(**_result_payload(confidence=1.01))

    def test_confidence_optional(self):
        assert CorrelationResult(**_result_payload()).confidence is None

    def test_member_detections_carry_no_correlation_confidence(self):
        """Correlation confidence is separate from detection confidence:
        members only reference detections by identity."""
        assert "confidence" not in CorrelationMember.model_fields
# ---------------------------------------------------------------------------
# 7. Evidence and metadata
# ---------------------------------------------------------------------------


class TestEvidenceAndMetadata:
    """Requirements 13-15, 21: structured, JSON-compatible, independent."""

    def test_evidence_remains_structured(self):
        evidence = {"matched": True, "reasons": ["explicit-membership"]}
        result = CorrelationResult(**_result_payload(evidence=evidence))
        assert result.evidence == evidence
        assert isinstance(result.evidence, dict)

    def test_metadata_remains_structured(self):
        metadata = {"label": "unit-test", "tags": ["contract"]}
        result = CorrelationResult(**_result_payload(metadata=metadata))
        assert result.metadata == metadata
        assert isinstance(result.metadata, dict)

    def test_evidence_is_json_serializable(self):
        result = CorrelationResult(**_result_payload())
        json.dumps(result.evidence)

    def test_metadata_is_json_serializable(self):
        result = CorrelationResult(**_result_payload())
        json.dumps(result.metadata)

    def test_non_json_evidence_rejected(self):
        with pytest.raises(ValidationError):
            CorrelationResult(
                **_result_payload(evidence={"blob": object()})
            )

    def test_non_json_metadata_rejected(self):
        with pytest.raises(ValidationError):
            CorrelationResult(
                **_result_payload(metadata={"blob": object()})
            )

    def test_nested_evidence_independent_from_input(self):
        payload = _result_payload(
            evidence={"nested": {"list": [1, 2]}, "basis": "x"}
        )
        source_evidence = payload["evidence"]
        result = CorrelationResult(**payload)
        source_evidence["nested"]["list"].append(99)
        assert result.evidence == {
            "nested": {"list": [1, 2]},
            "basis": "x",
        }

    def test_nested_metadata_independent_from_input(self):
        payload = _result_payload(
            metadata={"nested": {"deep": {"k": "v"}}}
        )
        source_metadata = payload["metadata"]
        result = CorrelationResult(**payload)
        source_metadata["nested"]["deep"]["k"] = "mutated"
        assert result.metadata == {"nested": {"deep": {"k": "v"}}}


# ---------------------------------------------------------------------------
# 8. Secret safety
# ---------------------------------------------------------------------------


class TestSecretSafety:
    """Requirement 16: no credentials/keys in evidence or metadata."""

    def test_evidence_rejects_api_key_key(self):
        with pytest.raises(ValidationError):
            CorrelationResult(
                **_result_payload(evidence={"api_key": "sk-1234"})
            )

    def test_evidence_rejects_authorization_value(self):
        with pytest.raises(ValidationError):
            CorrelationResult(
                **_result_payload(
                    evidence={"headers": {"authorization": "Basic abc"}}
                )
            )

    def test_evidence_rejects_bearer_value(self):
        with pytest.raises(ValidationError):
            CorrelationResult(
                **_result_payload(evidence={"token": "Bearer xxx"})
            )

    def test_evidence_rejects_secret_key(self):
        with pytest.raises(ValidationError):
            CorrelationResult(
                **_result_payload(evidence={"client_secret": "pw"})
            )

    def test_metadata_rejects_api_key(self):
        with pytest.raises(ValidationError):
            CorrelationResult(
                **_result_payload(metadata={"api_key": "AKIA1234"})
            )

    def test_metadata_rejects_jwt_bearer_string(self):
        with pytest.raises(ValidationError):
            CorrelationResult(
                **_result_payload(
                    metadata={"jwt": "bearer eyJhbGciOiJIUzI1NiJ9"}
                )
            )

    def test_members_never_carry_secret_bearing_payloads(self):
        """References only — no evidence/metadata travel on a member."""
        member = _member()
        assert not hasattr(member, "evidence")
        assert not hasattr(member, "metadata")
# ---------------------------------------------------------------------------
# 9. Provenance
# ---------------------------------------------------------------------------


class TestProvenance:
    """Requirement 17: CORRELATED provenance is the only valid marker."""

    def test_provenance_defaults_to_correlated(self):
        result = CorrelationResult(**_result_payload())
        assert result.provenance == Provenance.CORRELATED

    def test_provenance_correlated_accepted(self):
        result = CorrelationResult(
            **_result_payload(provenance=Provenance.CORRELATED)
        )
        assert result.provenance == Provenance.CORRELATED

    def test_provenance_detected_rejected(self):
        with pytest.raises(ValidationError):
            CorrelationResult(
                **_result_payload(provenance=Provenance.DETECTED)
            )

    def test_provenance_observed_rejected(self):
        with pytest.raises(ValidationError):
            CorrelationResult(
                **_result_payload(provenance=Provenance.OBSERVED)
            )

    def test_provenance_enriched_rejected(self):
        with pytest.raises(ValidationError):
            CorrelationResult(
                **_result_payload(provenance=Provenance.ENRICHED)
            )

    def test_provenance_reconstructed_rejected(self):
        with pytest.raises(ValidationError):
            CorrelationResult(
                **_result_payload(provenance=Provenance.RECONSTRUCTED)
            )

    def test_correlated_value_string(self):
        assert Provenance.CORRELATED.value == "correlated"

    def test_correlated_is_a_global_provenance_member(self):
        assert Provenance.CORRELATED in Provenance

    def test_detection_to_correlation_input_still_enforces_detected(self):
        """Regression: 9I keeps requiring DETECTED — the new CORRELATED
        value must not leak into (or weaken) the detection boundary."""
        with pytest.raises(ValidationError):
            _correlation_input(provenance=Provenance.CORRELATED)

    def test_detection_contract_defaults_remain_detected(self):
        from app.schemas.detection import DetectionResult

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


# ---------------------------------------------------------------------------
# 10. Status
# ---------------------------------------------------------------------------


class TestStatus:
    """Requirements 18, 19: only the neutral lifecycle values are valid."""

    def test_all_status_values_accepted(self):
        for status in CorrelationStatus:
            result = CorrelationResult(**_result_payload(status=status))
            assert result.status == status

    def test_invalid_status_rejected(self):
        with pytest.raises(ValidationError):
            CorrelationResult(**_result_payload(status="confirmed"))

    def test_verdict_status_rejected(self):
        for verdict in ("malicious", "benign", "true_positive", "false_positive"):
            with pytest.raises(ValidationError):
                CorrelationResult(**_result_payload(status=verdict))

    def test_no_verdict_status_members_exist(self):
        members = set(CorrelationStatus.__members__.keys())
        assert "MALICIOUS" not in members
        assert "BENIGN" not in members
        assert "TRUE_POSITIVE" not in members
        assert "FALSE_POSITIVE" not in members

    def test_status_value_strings_are_neutral(self):
        assert CorrelationStatus.CANDIDATE.value == "candidate"
        assert CorrelationStatus.ACTIVE.value == "active"
        assert CorrelationStatus.CLOSED.value == "closed"
# ---------------------------------------------------------------------------
# 11. Immutability
# ---------------------------------------------------------------------------


class TestImmutability:
    """Requirement 20: contracts never mutate their source inputs."""

    def test_adapter_does_not_mutate_input_records(self):
        inputs = [
            _correlation_input(detection_id=_DETECTION_1, event_id=_EVENT_1),
            _correlation_input(detection_id=_DETECTION_2, event_id=_EVENT_2),
        ]
        snapshots = copy.deepcopy(inputs)
        to_correlation_members(inputs)
        assert inputs == snapshots

    def test_result_construction_does_not_mutate_payload(self):
        payload = _result_payload()
        snapshot = copy.deepcopy(payload)
        CorrelationResult(**payload)
        assert payload == snapshot

    def test_members_share_no_mutable_state_with_inputs(self):
        source = _correlation_input()
        member = to_correlation_members([source])[0]
        assert member.detection_id == source.detection_id
        assert member.event_id == source.event_id
        assert member.timestamp == source.timestamp
        assert not hasattr(member, "evidence")
        assert not hasattr(member, "metadata")

    def test_deep_copied_result_is_independent(self):
        result = CorrelationResult(
            **_result_payload(evidence={"nested": {"a": [1]}})
        )
        clone = result.model_copy(deep=True)
        clone.evidence["nested"]["a"].append(2)
        assert result.evidence == {"nested": {"a": [1]}}


# ---------------------------------------------------------------------------
# 12. Serialization
# ---------------------------------------------------------------------------


class TestSerialization:
    """Requirement 33: full JSON round-trip preserves the contract."""

    def test_model_dump_json_round_trip(self):
        original = CorrelationResult(
            **_result_payload(
                members=[
                    _member(detection_id=_DETECTION_1, event_id=_EVENT_1),
                    _member(detection_id=_DETECTION_2, event_id=_EVENT_2),
                ],
                confidence=0.6,
            )
        )
        dumped = original.model_dump_json()
        restored = CorrelationResult.model_validate_json(dumped)
        assert restored.model_dump() == original.model_dump()

    def test_json_contains_members_with_exact_references(self):
        result = CorrelationResult(**_result_payload())
        parsed = json.loads(result.model_dump_json())
        assert parsed["correlation_id"] == str(result.correlation_id)
        assert str(_DETECTION_1) in {
            m["detection_id"] for m in parsed["members"]
        }
        assert str(_EVENT_1) in {m["event_id"] for m in parsed["members"]}

    def test_provenance_serialises_as_string(self):
        result = CorrelationResult(**_result_payload())
        assert json.loads(result.model_dump_json())["provenance"] == "correlated"

    def test_derived_views_are_not_part_of_the_stored_json(self):
        result = CorrelationResult(**_result_payload())
        payload = json.loads(result.model_dump_json())
        assert "detection_ids" not in payload
        assert "event_ids" not in payload

    def test_no_batch_or_analysis_envelope_in_step_10a(self):
        """The CorrelationAnalysis / CorrelationFailure envelopes belong to
        the future Correlation Agent step — 10A must not invent them."""
        with pytest.raises(ImportError):
            from app.schemas.correlation import CorrelationAnalysis  # noqa: F401

        with pytest.raises(ImportError):
            from app.schemas.correlation import CorrelationFailure  # noqa: F401
# ---------------------------------------------------------------------------
# 13. Adapter purity
# ---------------------------------------------------------------------------


class TestAdapterPurity:
    """Requirement 35: the adapter is pure, deterministic, non-mutating."""

    def test_adapter_is_a_plain_function(self):
        assert callable(to_correlation_members)

    def test_empty_input_yields_empty_members(self):
        assert to_correlation_members([]) == []

    def test_membership_order_preserved(self):
        inputs = [
            _correlation_input(detection_id=_DETECTION_2, event_id=_EVENT_2),
            _correlation_input(detection_id=_DETECTION_1, event_id=_EVENT_1),
        ]
        members = to_correlation_members(inputs)
        assert [m.detection_id for m in members] == [_DETECTION_2, _DETECTION_1]
        assert [m.event_id for m in members] == [_EVENT_2, _EVENT_1]

    def test_duplicates_preserved_by_adapter(self):
        inputs = [
            _correlation_input(detection_id=_DETECTION_1, event_id=_EVENT_1),
            _correlation_input(detection_id=_DETECTION_1, event_id=_EVENT_2),
        ]
        members = to_correlation_members(inputs)
        assert [m.detection_id for m in members] == [_DETECTION_1, _DETECTION_1]

    def test_same_input_yields_same_output(self):
        inputs = [_correlation_input()]
        assert to_correlation_members(inputs) == to_correlation_members(inputs)

    def test_adapter_rejects_non_input_records(self):
        with pytest.raises(TypeError):
            to_correlation_members([{"detection_id": str(_DETECTION_1)}])

    def test_adapter_rejects_correlation_results_as_input(self):
        """The adapter consumes 9I detection transport, never results."""
        result = CorrelationResult(**_result_payload())
        with pytest.raises(TypeError):
            to_correlation_members([result])

    def test_adapter_source_has_no_grouping_or_comparison_logic(self):
        source = inspect.getsource(to_correlation_members)
        assert "==" not in source
        assert "sorted(" not in source
        assert "def group" not in source
        assert "group_by" not in source
        assert ".group(" not in source
        assert "correlate(" not in source

    def test_adapter_does_not_touch_database_or_api(self):
        source = inspect.getsource(to_correlation_members)
        assert "Session" not in source
        assert "create_engine" not in source
        assert "requests." not in source
# ---------------------------------------------------------------------------
# 14. Contract boundary: no future-layer concepts
# ---------------------------------------------------------------------------


class TestContractBoundary:
    """Requirements 28-32: the domain contract stays free of future layers."""

    FORBIDDEN = {
        "risk",
        "risk_score",
        "threat_score",
        "incident",
        "incident_id",
        "priority",
        "mitre",
        "attack_stage",
        "campaign_id",
        "response_action",
        "remediation",
        "playbook",
        "correlation_score",
        "llm",
        "graph",
        "sequence",
        "attack_chain",
        "embedding",
        "vector",
        "alert_id",
        "verdict",
    }

    def test_no_future_layer_fields_on_result(self):
        fields = set(CorrelationResult.model_fields.keys())
        for name in self.FORBIDDEN:
            assert name not in fields, f"unexpected future-layer field: {name}"

    def test_no_future_layer_fields_on_member(self):
        fields = set(CorrelationMember.model_fields.keys())
        for name in self.FORBIDDEN:
            assert name not in fields, f"unexpected future-layer field: {name}"

    def test_result_fields_are_exactly_the_contract_fields(self):
        assert set(CorrelationResult.model_fields.keys()) == {
            "correlation_id",
            "members",
            "status",
            "confidence",
            "evidence",
            "metadata",
            "timestamp",
            "provenance",
        }

    def test_no_correlation_methods_exist(self):
        assert not hasattr(CorrelationResult, "correlate")
        assert not hasattr(CorrelationResult, "group")
        assert not hasattr(CorrelationResult, "score")

    def test_no_algorithm_specific_fields_exist(self):
        fields = set(CorrelationResult.model_fields.keys())
        for name in (
            "same_ip",
            "same_user",
            "same_process",
            "same_host",
            "relationship_type",
            "time_window",
            "max_gap_seconds",
            "attack_chain",
            "graph",
        ):
            assert name not in fields, f"unexpected algorithm field: {name}"

    def test_no_relationship_enum_defined(self):
        assert not hasattr(correlation_module, "CorrelationRelationshipType")

    def test_no_risk_model_defined(self):
        assert not hasattr(correlation_module, "CorrelationRiskScore")
        assert not hasattr(correlation_module, "RiskLevel")

    def test_module_imports_no_storage_api_or_bus(self):
        source = inspect.getsource(correlation_module)
        for forbidden in ("sqlalchemy", "fastapi", "kafka", "redis", "amqp"):
            assert forbidden not in source, (
                f"correlation contract must not import {forbidden}"
            )


# ---------------------------------------------------------------------------
# 15. No correlation algorithm leakage
# ---------------------------------------------------------------------------


class TestNoAlgorithmLeakage:
    """10A tests the CONTRACT, not the algorithm.  No test may encode a
    correlation rule; these tests lock the absence of such logic."""

    def test_adapter_source_never_compares_member_attributes(self):
        source = inspect.getsource(to_correlation_members)
        assert "event_id ==" not in source
        assert "detection_id ==" not in source
        assert "other." not in source

    def test_adapter_source_has_no_time_window_or_distance_logic(self):
        source = inspect.getsource(to_correlation_members)
        assert "timedelta" not in source
        assert "within" not in source
        assert "minutes" not in source

    def test_adapter_source_has_no_scoring(self):
        source = inspect.getsource(to_correlation_members)
        assert "score" not in source
        assert "weight" not in source

    def test_no_module_level_algorithm_configuration(self):
        for constant in (
            "TIME_WINDOW_SECONDS",
            "MAX_GAP",
            "SIMILARITY_THRESHOLD",
            "DEFAULT_CORRELATION_WINDOW",
        ):
            assert not hasattr(correlation_module, constant)

    def test_contract_has_no_ip_matching_helpers(self):
        for helper in ("same_ip", "match_ip", "shared_ip"):
            assert not hasattr(correlation_module, helper)

    def test_contract_has_no_entity_matching_helpers(self):
        for helper in ("same_user", "match_user", "shared_process"):
            assert not hasattr(correlation_module, helper)

    def test_contract_source_contains_no_grouping_loop(self):
        """The module may iterate to clone/validate, never to group."""
        source = inspect.getsource(correlation_module)
        assert "group_by" not in source
        assert "collections.defaultdict" not in source