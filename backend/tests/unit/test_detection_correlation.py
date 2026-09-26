"""Tests for the Detection-to-Correlation Contract (Step 9I).

Covers the DetectionCorrelationInput / DetectionCorrelationBatch contract,
the pure adapters (``to_correlation_input`` / ``to_correlation_batch``),
traceability, provenance preservation, structured evidence/metadata
transport, immutability, validation, secret-safety, failure rejection,
batch semantics, serialization round-trips, and contract-boundary
enforcement (no risk / verdict / incident / correlation concepts).

These are pure unit tests of the **contract** — no database connection,
no repository, no API, and no network calls are made.
"""

import copy
import json
import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.schemas.detection import (
    DetectionEvidence,
    DetectionMetadata,
    DetectionResult,
    DetectionSeverity,
    RuleType,
)
from app.schemas.detection_agent import DetectionAnalysis, DetectionFailure
from app.schemas.detection_correlation import (
    DetectionCorrelationBatch,
    DetectionCorrelationBatchMetadata,
    DetectionCorrelationInput,
    to_correlation_batch,
    to_correlation_input,
)
from app.schemas.detection_query import DetectionResultRecord
from app.schemas.security_event import Provenance


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FIXED_TS = datetime(2025, 8, 1, 12, 0, 0, tzinfo=timezone.utc)

_DETECTION_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
_EVENT_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")


def _minimal_evidence(**overrides) -> DetectionEvidence:
    """Return a minimal valid Step 9A DetectionEvidence instance."""
    base: dict = {
        "matched_conditions": ["condition_1"],
        "matched_fields": {"CommandLine": "powershell -enc AABC"},
        "rule_references": {"attack": "T1059.001"},
        "detection_context": {"engine": "sigma", "rule_hash": "abc123"},
    }
    base.update(overrides)
    return DetectionEvidence(**base)


def _minimal_metadata(**overrides) -> DetectionMetadata:
    """Return a minimal valid Step 9A DetectionMetadata instance."""
    base: dict = {
        "rule_version": "1.2.3",
        "engine_version": "0.1.0",
        "execution_time_ms": 12.5,
        "total_rules_evaluated": 7,
        "extra": {"run_id": "abc"},
    }
    base.update(overrides)
    return DetectionMetadata(**base)


def _result(**overrides) -> DetectionResult:
    """Return a minimal valid matched Step 9A DetectionResult."""
    base: dict = {
        "detection_id": _DETECTION_ID,
        "event_id": _EVENT_ID,
        "rule_id": "sigma-credential-access-001",
        "rule_type": RuleType.SIGMA,
        "matched": True,
        "severity": DetectionSeverity.HIGH,
        "confidence": 0.9,
        "timestamp": _FIXED_TS,
        "evidence": _minimal_evidence(),
        "metadata": _minimal_metadata(),
        "provenance": Provenance.DETECTED,
    }
    base.update(overrides)
    return DetectionResult(**base)


def _record(**overrides) -> DetectionResultRecord:
    """Return a minimal Step 9G DetectionResultRecord read model.

    Mirrors what the Step 9G query layer returns for a persisted
    ``detection_results`` row (structured JSONB dicts, always matched,
    always DETECTED).
    """
    base: dict = {
        "id": uuid.UUID("33333333-3333-3333-3333-333333333333"),
        "event_id": _EVENT_ID,
        "detection_id": _DETECTION_ID,
        "rule_id": "sigma-credential-access-001",
        "rule_type": RuleType.SIGMA,
        "rule_version": "1.2.3",
        "severity": DetectionSeverity.HIGH,
        "matched": True,
        "confidence": 0.9,
        "evidence": {
            "matched_conditions": ["condition_1"],
            "matched_fields": {"CommandLine": "powershell -enc AABC"},
            "rule_references": {"attack": "T1059.001"},
            "detection_context": {"engine": "sigma", "rule_hash": "abc123"},
        },
        "result_metadata": {
            "rule_version": "1.2.3",
            "engine_version": "0.1.0",
            "execution_time_ms": 12.5,
            "total_rules_evaluated": 7,
            "extra": {"run_id": "abc"},
        },
        "detected_at": _FIXED_TS,
        "provenance": Provenance.DETECTED,
        "created_at": _FIXED_TS,
        "updated_at": _FIXED_TS,
    }
    base.update(overrides)
    return DetectionResultRecord(**base)


def _input_payload(**overrides) -> dict:
    """Return a minimal valid DetectionCorrelationInput payload dict."""
    base: dict = {
        "detection_id": _DETECTION_ID,
        "event_id": _EVENT_ID,
        "timestamp": _FIXED_TS,
        "rule_id": "sigma-credential-access-001",
        "rule_type": RuleType.SIGMA,
        "rule_version": "1.2.3",
        "severity": DetectionSeverity.HIGH,
        "confidence": 0.9,
        "evidence": {
            "matched_conditions": ["condition_1"],
            "detection_context": {"engine": "sigma"},
        },
        "metadata": {"rule_version": "1.2.3", "extra": {"engine": "sigma"}},
        "provenance": Provenance.DETECTED,
    }
    base.update(overrides)
    return base
# ---------------------------------------------------------------------------
# 1. Conversion from a Step 9A DetectionResult
# ---------------------------------------------------------------------------


class TestFromDetectionResult:
    """A valid matched DetectionResult converts successfully (1)."""

    def test_valid_result_converts(self):
        adapted = to_correlation_input(_result())
        assert isinstance(adapted, DetectionCorrelationInput)

    def test_detection_id_preserved(self):
        result = _result(detection_id=_DETECTION_ID)
        assert to_correlation_input(result).detection_id == _DETECTION_ID

    def test_event_id_preserved(self):
        result = _result(event_id=_EVENT_ID)
        assert to_correlation_input(result).event_id == _EVENT_ID

    def test_detection_id_never_regenerated(self):
        result = _result(detection_id=_DETECTION_ID)
        assert to_correlation_input(result).detection_id == result.detection_id

    def test_event_id_is_not_a_correlation_or_incident_id(self):
        """Traceability: the contract keeps event_id, no new identity."""
        fields = set(DetectionCorrelationInput.model_fields.keys())
        assert "event_id" in fields
        assert "correlation_id" not in fields
        assert "incident_id" not in fields
        assert "alert_id" not in fields

    def test_rule_id_preserved(self):
        result = _result(rule_id="yara-apt-backdoor-v2")
        assert to_correlation_input(result).rule_id == "yara-apt-backdoor-v2"

    def test_timestamp_preserved(self):
        adapted = to_correlation_input(_result(timestamp=_FIXED_TS))
        assert adapted.timestamp == _FIXED_TS

    def test_rule_type_preserved(self):
        result = _result(rule_type=RuleType.YARA)
        assert to_correlation_input(result).rule_type == RuleType.YARA

    def test_rule_version_preserved_from_metadata(self):
        result = _result(metadata=_minimal_metadata(rule_version="2.0.0"))
        assert to_correlation_input(result).rule_version == "2.0.0"

    def test_rule_version_none_when_metadata_lacks_version(self):
        result = _result(metadata=_minimal_metadata(rule_version=None))
        assert to_correlation_input(result).rule_version is None

    def test_severity_preserved(self):
        result = _result(severity=DetectionSeverity.CRITICAL)
        assert to_correlation_input(result).severity == DetectionSeverity.CRITICAL

    def test_confidence_preserved(self):
        result = _result(confidence=0.42)
        assert to_correlation_input(result).confidence == 0.42

    def test_provenance_preserved(self):
        assert to_correlation_input(_result()).provenance == Provenance.DETECTED

    def test_evidence_remains_structured(self):
        evidence = _minimal_evidence()
        adapted = to_correlation_input(_result(evidence=evidence))
        assert adapted.evidence == evidence.model_dump()
        assert isinstance(adapted.evidence, dict)
        assert isinstance(adapted.evidence["matched_conditions"], list)
        assert isinstance(adapted.evidence["matched_fields"], dict)

    def test_metadata_remains_structured(self):
        metadata = _minimal_metadata()
        adapted = to_correlation_input(_result(metadata=metadata))
        assert adapted.metadata == metadata.model_dump()
        assert isinstance(adapted.metadata, dict)
        assert isinstance(adapted.metadata["extra"], dict)


# ---------------------------------------------------------------------------
# 2. Conversion from the Step 9G read model
# ---------------------------------------------------------------------------


class TestFromReadModelRecord:
    """The adapter accepts an already-retrieved DetectionResultRecord."""

    def test_valid_record_converts(self):
        adapted = to_correlation_input(_record())
        assert isinstance(adapted, DetectionCorrelationInput)

    def test_detection_id_preserved(self):
        assert to_correlation_input(_record()).detection_id == _DETECTION_ID

    def test_event_id_preserved(self):
        assert to_correlation_input(_record()).event_id == _EVENT_ID

    def test_rule_id_preserved(self):
        record = _record(rule_id="yara-apt-backdoor-v2")
        assert to_correlation_input(record).rule_id == "yara-apt-backdoor-v2"

    def test_rule_type_preserved(self):
        record = _record(rule_type=RuleType.YARA)
        assert to_correlation_input(record).rule_type == RuleType.YARA

    def test_rule_version_preserved(self):
        record = _record(rule_version="3.1.4")
        assert to_correlation_input(record).rule_version == "3.1.4"

    def test_timestamp_maps_from_detected_at(self):
        recorded_at = datetime(2025, 9, 1, 8, 30, 0, tzinfo=timezone.utc)
        adapted = to_correlation_input(_record(detected_at=recorded_at))
        assert adapted.timestamp == recorded_at

    def test_severity_preserved(self):
        record = _record(severity=DetectionSeverity.LOW)
        assert to_correlation_input(record).severity == DetectionSeverity.LOW

    def test_confidence_preserved(self):
        record = _record(confidence=0.75)
        assert to_correlation_input(record).confidence == 0.75

    def test_provenance_preserved(self):
        assert to_correlation_input(_record()).provenance == Provenance.DETECTED

    def test_evidence_transported_as_stored_dict(self):
        record = _record()
        adapted = to_correlation_input(record)
        assert adapted.evidence == record.evidence

    def test_metadata_transported_as_stored_dict(self):
        record = _record()
        adapted = to_correlation_input(record)
        assert adapted.metadata == record.result_metadata
        assert adapted.metadata["rule_version"] == "1.2.3"
# ---------------------------------------------------------------------------
# 3. Immutability: the contract must not mutate its inputs
# ---------------------------------------------------------------------------


class TestNoMutation:
    """The adapters never mutate results, evidence, or metadata (14-16)."""

    def test_input_detection_result_not_mutated(self):
        result = _result()
        snapshot = copy.deepcopy(result)
        to_correlation_input(result)
        assert result == snapshot

    def test_input_record_not_mutated(self):
        record = _record()
        snapshot = copy.deepcopy(record)
        to_correlation_input(record)
        assert record == snapshot

    def test_evidence_not_mutated(self):
        evidence = _minimal_evidence()
        snapshot = copy.deepcopy(evidence)
        to_correlation_input(_result(evidence=evidence))
        assert evidence == snapshot

    def test_metadata_not_mutated(self):
        metadata = _minimal_metadata()
        snapshot = copy.deepcopy(metadata)
        to_correlation_input(_result(metadata=metadata))
        assert metadata == snapshot

    def test_record_evidence_not_mutated(self):
        record = _record()
        evidence_snapshot = copy.deepcopy(record.evidence)
        to_correlation_input(record)
        assert record.evidence == evidence_snapshot

    def test_record_metadata_not_mutated(self):
        record = _record()
        metadata_snapshot = copy.deepcopy(record.result_metadata)
        to_correlation_input(record)
        assert record.result_metadata == metadata_snapshot

    def test_converted_contract_is_independent_of_source_evidence(self):
        """Mutating the source after conversion must not leak into the contract."""
        record = _record()
        adapted = to_correlation_input(record)
        record.evidence["matched_conditions"].append("mutated_after")
        record.result_metadata["extra"]["mutated"] = True
        assert "mutated_after" not in adapted.evidence["matched_conditions"]
        assert "mutated" not in adapted.metadata["extra"]

    def test_adapted_result_evidence_is_independent(self):
        result = _result()
        adapted = to_correlation_input(result)
        adapted.evidence["matched_conditions"].append("mutated_after")
        assert "mutated_after" not in result.evidence.matched_conditions
# ---------------------------------------------------------------------------
# 4. Validation
# ---------------------------------------------------------------------------


class TestValidation:
    """Validation mirrors the existing detection contract (17-19)."""

    def test_invalid_confidence_below_zero_rejected(self):
        with pytest.raises(ValidationError):
            DetectionCorrelationInput(**_input_payload(confidence=-0.01))

    def test_invalid_confidence_above_one_rejected(self):
        with pytest.raises(ValidationError):
            DetectionCorrelationInput(**_input_payload(confidence=1.01))

    def test_confidence_bounds_are_inclusive(self):
        low = DetectionCorrelationInput(**_input_payload(confidence=0.0))
        high = DetectionCorrelationInput(**_input_payload(confidence=1.0))
        assert low.confidence == 0.0
        assert high.confidence == 1.0

    def test_naive_timestamp_rejected(self):
        naive = datetime(2025, 8, 1, 12, 0, 0)
        with pytest.raises(ValidationError):
            DetectionCorrelationInput(**_input_payload(timestamp=naive))

    def test_timezone_aware_timestamp_accepted(self):
        tz_aware = datetime(2025, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
        adapted = DetectionCorrelationInput(**_input_payload(timestamp=tz_aware))
        assert adapted.timestamp == tz_aware

    def test_invalid_event_uuid_rejected(self):
        with pytest.raises(ValidationError):
            DetectionCorrelationInput(**_input_payload(event_id="not-a-uuid"))

    def test_invalid_detection_uuid_rejected(self):
        with pytest.raises(ValidationError):
            DetectionCorrelationInput(**_input_payload(detection_id="not-a-uuid"))

    def test_blank_rule_id_rejected(self):
        # 9A DetectionResult uses min_length=1 (no strip); the contract
        # mirrors that exact rule — an empty string is rejected.
        with pytest.raises(ValidationError):
            DetectionCorrelationInput(**_input_payload(rule_id=""))

    def test_non_detected_provenance_rejected(self):
        """A detection must never be relabelled observed/enriched/reconstructed."""
        with pytest.raises(ValidationError):
            DetectionCorrelationInput(
                **_input_payload(provenance=Provenance.OBSERVED)
            )
        with pytest.raises(ValidationError):
            DetectionCorrelationInput(
                **_input_payload(provenance=Provenance.ENRICHED)
            )
        with pytest.raises(ValidationError):
            DetectionCorrelationInput(
                **_input_payload(provenance=Provenance.RECONSTRUCTED)
            )

    def test_provenance_defaults_to_detected(self):
        payload = _input_payload()
        payload.pop("provenance")
        assert DetectionCorrelationInput(**payload).provenance == Provenance.DETECTED

    def test_missing_required_fields_rejected(self):
        with pytest.raises(ValidationError):
            DetectionCorrelationInput(**{})


# ---------------------------------------------------------------------------
# 5. Secret-safety
# ---------------------------------------------------------------------------


class TestSecretSafety:
    """Secret-bearing evidence/metadata are rejected (20-21)."""

    @pytest.mark.parametrize(
        "pattern", ["api_key", "authorization", "bearer", "secret"]
    )
    def test_secret_bearing_evidence_rejected(self, pattern):
        payload = _input_payload(
            evidence={"detection_context": {pattern: "credential-value"}}
        )
        with pytest.raises(ValidationError):
            DetectionCorrelationInput(**payload)

    @pytest.mark.parametrize(
        "pattern", ["api_key", "authorization", "bearer", "secret"]
    )
    def test_secret_bearing_metadata_rejected(self, pattern):
        payload = _input_payload(metadata={"extra": {pattern: "credential-value"}})
        with pytest.raises(ValidationError):
            DetectionCorrelationInput(**payload)

    def test_credential_phrase_in_evidence_rejected(self):
        """Secrets buried in a nested value are still caught."""
        payload = _input_payload(
            evidence={"matched_fields": {"CommandLine": "Authorization: Bearer abc"}}
        )
        with pytest.raises(ValidationError):
            DetectionCorrelationInput(**payload)

    def test_adapter_rejects_record_with_secret_evidence(self):
        """Defence-in-depth: records with secret evidence fail at the boundary."""
        record = _record(evidence={"detection_context": {"secret": "hunter2"}})
        with pytest.raises(ValidationError):
            to_correlation_input(record)

    def test_adapter_rejects_record_with_secret_metadata(self):
        record = _record(result_metadata={"extra": {"authorization": "Bearer x"}})
        with pytest.raises(ValidationError):
            to_correlation_input(record)

    def test_contract_models_expose_no_secret_fields(self):
        for model in (
            DetectionCorrelationInput,
            DetectionCorrelationBatch,
            DetectionCorrelationBatchMetadata,
        ):
            fields = set(model.model_fields.keys())
            assert "api_key" not in fields
            assert "authorization" not in fields
            assert "token" not in fields
            assert "secret" not in fields
            assert "headers" not in fields
            assert "raw_response" not in fields
# ---------------------------------------------------------------------------
# 6. Failures are NOT detections
# ---------------------------------------------------------------------------


class TestFailureRejection:
    """DetectionFailure and non-matches can never silently become input (22)."""

    def test_detection_failure_is_rejected(self):
        # Note: message must not trip the 9E secret pattern validator.
        failure = DetectionFailure(
            engine="sigma",
            rule_id="sigma-bad",
            error_type="malformed_rule",
            message="failed to parse rule content",
        )
        with pytest.raises(TypeError):
            to_correlation_input(failure)

    def test_detection_analysis_is_rejected(self):
        analysis = DetectionAnalysis(
            event_id=_EVENT_ID,
            results=[_result()],
            timestamp=_FIXED_TS,
        )
        with pytest.raises(TypeError):
            to_correlation_input(analysis)

    def test_failure_record_is_rejected(self):
        from app.schemas.detection_query import DetectionFailureRecord

        failure = DetectionFailureRecord(
            id=uuid.uuid4(),
            event_id=_EVENT_ID,
            engine="sigma",
            rule_id="sigma-bad",
            error_type="malformed_rule",
            error_message="boom",
            failed_at=_FIXED_TS,
            created_at=_FIXED_TS,
            updated_at=_FIXED_TS,
        )
        with pytest.raises(TypeError):
            to_correlation_input(failure)

    def test_non_match_detection_result_rejected(self):
        result = _result(matched=False)
        with pytest.raises(ValueError, match="matched=False"):
            to_correlation_input(result)

    def test_non_match_record_rejected(self):
        record = _record(matched=False)
        with pytest.raises(ValueError, match="matched=False"):
            to_correlation_input(record)

    def test_unrelated_object_rejected(self):
        with pytest.raises(TypeError):
            to_correlation_input("definitely-a-detection")

    def test_failure_in_batch_rejected(self):
        failure = DetectionFailure(
            engine="yara",
            rule_id="<event>",
            error_type="internal_error",
            message="engine failure",
        )
        with pytest.raises(TypeError):
            to_correlation_batch([_result(), failure])


# ---------------------------------------------------------------------------
# 7. Batch contract
# ---------------------------------------------------------------------------


class TestBatch:
    """Batch is a pure transport envelope (23-26)."""

    def test_empty_batch_works(self):
        batch = to_correlation_batch([])
        assert batch.detections == []
        assert batch.metadata.record_count == 0

    def test_multiple_detections_convert(self):
        results = [_result(detection_id=uuid.uuid4()) for _ in range(3)]
        batch = to_correlation_batch(results)
        assert batch.metadata.record_count == 3
        assert [i.detection_id for i in batch.detections] == [
            r.detection_id for r in results
        ]

    def test_mixed_result_and_record_sources(self):
        batch = to_correlation_batch([_result(), _record()])
        assert batch.metadata.record_count == 2

    def test_batch_preserves_input_order(self):
        """Order is transport order; the adapter never reorders."""
        ids = [uuid.uuid4(), uuid.uuid4(), uuid.uuid4()]
        results = [
            _result(detection_id=ids[1]),
            _result(detection_id=ids[0]),
            _result(detection_id=ids[2]),
        ]
        batch = to_correlation_batch(results)
        assert [i.detection_id for i in batch.detections] == [
            ids[1],
            ids[0],
            ids[2],
        ]

    def test_batch_is_deterministic(self):
        results = [_result(detection_id=uuid.uuid4()) for _ in range(3)]
        first = to_correlation_batch(results)
        second = to_correlation_batch(results)
        assert first == second

    def test_timestamp_order_is_not_attack_sequence(self):
        """The batch never reorders by timestamp — no attack-chain implication."""
        later = _result(timestamp=datetime(2025, 9, 1, tzinfo=timezone.utc))
        earlier = _result(timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc))
        batch = to_correlation_batch([later, earlier])
        assert [i.detection_id for i in batch.detections] == [
            later.detection_id,
            earlier.detection_id,
        ]

    def test_duplicate_detection_ids_preserved(self):
        """The contract transports duplicates; it never silently drops them."""
        same_id = uuid.uuid4()
        batch = to_correlation_batch(
            [_result(detection_id=same_id), _result(detection_id=same_id)]
        )
        assert batch.metadata.record_count == 2
        assert [i.detection_id for i in batch.detections] == [same_id, same_id]

    def test_record_count_mismatch_rejected(self):
        batch_payload = {
            "detections": [to_correlation_input(_result())],
            "metadata": {"record_count": 2},
        }
        with pytest.raises(ValidationError, match="record_count"):
            DetectionCorrelationBatch(**batch_payload)

    def test_batch_from_detection_result_page_items(self):
        """A deterministically ordered read page maps into an ordered batch."""
        page_items = [_record() for _ in range(2)]
        batch = to_correlation_batch(page_items)
        assert batch.metadata.record_count == 2
# ---------------------------------------------------------------------------
# 8. Serialization round-trips
# ---------------------------------------------------------------------------


class TestRoundTrip:
    """model -> JSON -> model preserves every meaningful field."""

    @pytest.mark.parametrize("source_factory", [_result, _record])
    def test_json_round_trip_preserves_all_fields(self, source_factory):
        adapted = to_correlation_input(source_factory())
        json_str = adapted.model_dump_json()
        restored = DetectionCorrelationInput.model_validate_json(json_str)
        assert restored == adapted

    @pytest.mark.parametrize("source_factory", [_result, _record])
    def test_json_round_trip_preserves_identities(self, source_factory):
        adapted = to_correlation_input(source_factory())
        restored = DetectionCorrelationInput.model_validate_json(
            adapted.model_dump_json()
        )
        assert restored.detection_id == adapted.detection_id
        assert restored.event_id == adapted.event_id
        assert restored.rule_id == adapted.rule_id
        assert restored.rule_type == adapted.rule_type
        assert restored.rule_version == adapted.rule_version
        assert restored.timestamp == adapted.timestamp

    @pytest.mark.parametrize("source_factory", [_result, _record])
    def test_json_round_trip_preserves_evidence_metadata_provenance(
        self, source_factory
    ):
        adapted = to_correlation_input(source_factory())
        restored = DetectionCorrelationInput.model_validate_json(
            adapted.model_dump_json()
        )
        assert restored.evidence == adapted.evidence
        assert restored.metadata == adapted.metadata
        assert restored.severity == adapted.severity
        assert restored.confidence == adapted.confidence
        assert restored.provenance == Provenance.DETECTED

    def test_batch_json_round_trip(self):
        batch = to_correlation_batch([_result(), _record()])
        restored = DetectionCorrelationBatch.model_validate_json(
            batch.model_dump_json()
        )
        assert restored == batch
        assert restored.metadata.record_count == 2

    def test_serialization_is_json_not_pickle(self):
        """The contract serializes to JSON — never pickle or objects."""
        adapted = to_correlation_input(_result())
        json_str = adapted.model_dump_json()
        parsed = json.loads(json_str)
        assert parsed["detection_id"] == str(_DETECTION_ID)
        assert parsed["event_id"] == str(_EVENT_ID)
        assert parsed["rule_id"] == "sigma-credential-access-001"
        assert parsed["rule_type"] == "sigma"
        assert parsed["severity"] == "high"
        assert parsed["provenance"] == "detected"
        assert isinstance(parsed["evidence"], dict)
        assert isinstance(parsed["metadata"], dict)
        # It must also re-validate cleanly (JSON -> model).
        DetectionCorrelationInput.model_validate(json.loads(json_str))


# ---------------------------------------------------------------------------
# 9. Contract boundary: nothing from future layers
# ---------------------------------------------------------------------------


class TestContractBoundary:
    """The contract contains no future-layer concepts."""

    FORBIDDEN = (
        "risk",
        "risk_score",
        "threat_score",
        "verdict",
        "incident",
        "incident_id",
        "correlation_id",
        "correlation_score",
        "attack_stage",
        "campaign_id",
        "mitre",
        "response_action",
        "priority",
        "alert_id",
        "group",
        "attack_chain",
        "sequence",
        "graph",
    )

    def test_input_has_no_future_layer_fields(self):
        fields = set(DetectionCorrelationInput.model_fields.keys())
        for name in self.FORBIDDEN:
            assert name not in fields, f"unexpected future-layer field: {name}"

    def test_batch_has_no_future_layer_fields(self):
        fields = set(DetectionCorrelationBatch.model_fields.keys())
        assert "correlation_id" not in fields
        assert "incident_id" not in fields
        assert "groups" not in fields
        assert "score" not in fields
        assert "sequence" not in fields

    def test_batch_metadata_has_no_future_layer_fields(self):
        fields = set(DetectionCorrelationBatchMetadata.model_fields.keys())
        assert set(fields) == {"record_count"}

    def test_input_fields_are_exactly_the_contract_fields(self):
        """The contract's field set is explicit and stable."""
        assert set(DetectionCorrelationInput.model_fields.keys()) == {
            "detection_id",
            "event_id",
            "timestamp",
            "rule_id",
            "rule_type",
            "rule_version",
            "severity",
            "confidence",
            "evidence",
            "metadata",
            "provenance",
        }

    def test_no_correlation_methods_exist(self):
        """The contract transports; it does not compute relationships."""
        assert not hasattr(DetectionCorrelationInput, "correlate")
        assert not hasattr(DetectionCorrelationBatch, "group")
        assert not hasattr(DetectionCorrelationBatch, "score")


# ---------------------------------------------------------------------------
# 10. Adapter purity
# ---------------------------------------------------------------------------


class TestAdapterPurity:
    """Adapters are deterministic, pure, and side-effect free."""

    def test_adapters_are_plain_functions(self):
        assert callable(to_correlation_input)
        assert callable(to_correlation_batch)

    def test_same_input_yields_same_output(self):
        result = _result()
        assert to_correlation_input(result) == to_correlation_input(result)

    def test_adapter_does_not_touch_database(self):
        """Pure function — no session, engine, or repository imports."""
        import inspect

        source = inspect.getsource(to_correlation_input)
        assert "Session" not in source and "create_engine" not in source