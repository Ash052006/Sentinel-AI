"""Tests for the Correlation Agent and baseline strategy (Step 10B).

Covers the deterministic same-event correlation strategy, the
CorrelationAgent orchestration boundary, determinism, input immutability,
ordering, event relationships, duplicate semantics, evidence, confidence,
secret-safety, failure isolation, strategy injection, and the absence of
future concepts (risk / incident / MITRE / response / AI).

Pure unit tests — no database, no network, no LLM.  The agent and
strategy operate entirely in memory on Step 9I / Step 10A contracts.
"""

import copy
import inspect
import json
import logging
import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

import app.agents.correlation as agent_module
from app.agents.correlation import CorrelationAgent
from app.schemas.correlation import (
    CorrelationMember,
    CorrelationResult,
    CorrelationStatus,
    to_correlation_members,
)
from app.schemas.detection import DetectionSeverity, RuleType
from app.schemas.detection_correlation import (
    DetectionCorrelationBatch,
    DetectionCorrelationBatchMetadata,
    DetectionCorrelationInput,
)
from app.schemas.security_event import Provenance
from app.services.correlation.exceptions import (
    CorrelationError,
    CorrelationInputError,
    CorrelationStrategyError,
)
from app.services.correlation.strategy import (
    SIGNAL_SHARED_EVENT,
    SIGNAL_STANDALONE,
    CorrelationGroup,
    CorrelationStrategy,
    DeterministicCorrelationStrategy,
)

_FIXED_TS = datetime(2025, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
_LATER_TS = datetime(2025, 8, 1, 12, 30, 0, tzinfo=timezone.utc)
_EVEN_LATER_TS = datetime(2025, 8, 1, 13, 0, 0, tzinfo=timezone.utc)

_DETECTION_1 = uuid.UUID("11111111-1111-1111-1111-111111111111")
_DETECTION_2 = uuid.UUID("22222222-2222-2222-2222-222222222222")
_DETECTION_3 = uuid.UUID("33333333-3333-3333-3333-333333333333")
_DETECTION_4 = uuid.UUID("44444444-4444-4444-4444-444444440004")
_EVENT_1 = uuid.UUID("55555555-5555-5555-5555-555555555551")
_EVENT_2 = uuid.UUID("66666666-6666-6666-6666-666666666662")
_EVENT_3 = uuid.UUID("77777777-7777-7777-7777-777777777773")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _input(
    *,
    detection_id: uuid.UUID = _DETECTION_1,
    event_id: uuid.UUID = _EVENT_1,
    timestamp: datetime = _FIXED_TS,
    rule_id: str = "sigma-credential-access-001",
    rule_type: RuleType = RuleType.SIGMA,
    rule_version: str | None = "1.2.3",
    severity: DetectionSeverity = DetectionSeverity.HIGH,
    confidence: float = 0.9,
    evidence: dict | None = None,
    metadata: dict | None = None,
) -> DetectionCorrelationInput:
    """Return a minimal valid Step 9I DetectionCorrelationInput."""
    return DetectionCorrelationInput(
        detection_id=detection_id,
        event_id=event_id,
        timestamp=timestamp,
        rule_id=rule_id,
        rule_type=rule_type,
        rule_version=rule_version,
        severity=severity,
        confidence=confidence,
        evidence=(
            evidence
            if evidence is not None
            else {"matched_conditions": ["condition_1"]}
        ),
        metadata=(
            metadata
            if metadata is not None
            else {"rule_version": "1.2.3"}
        ),
        provenance=Provenance.DETECTED,
    )


def _batch(
    *inputs: DetectionCorrelationInput,
) -> DetectionCorrelationBatch:
    """Wrap ordered inputs in a valid Step 9I batch envelope."""
    records = list(inputs)
    return DetectionCorrelationBatch(
        detections=records,
        metadata=DetectionCorrelationBatchMetadata(
            record_count=len(records),
        ),
    )


def _signature(result: CorrelationResult) -> dict:
    """Deterministic projection of a result (identity excluded)."""
    return {
        "detection_ids": tuple(
            member.detection_id for member in result.members
        ),
        "event_ids": tuple(member.event_id for member in result.members),
        "status": result.status.value,
        "confidence": result.confidence,
        "evidence": result.evidence,
        "metadata": result.metadata,
        "timestamp": result.timestamp,
        "provenance": result.provenance.value,
    }


# ---------------------------------------------------------------------------
# 1. Basic correlation
# ---------------------------------------------------------------------------


class TestBasicCorrelation:
    """Requirements 1-7: empty, single, same-event, mixed batches."""

    def test_empty_batch_produces_no_results(self):
        results = CorrelationAgent().analyze(_batch(), clock=_FIXED_TS)
        assert results == []

    def test_single_detection_forms_standalone_correlation(self):
        results = CorrelationAgent().analyze(
            _batch(_input()), clock=_FIXED_TS
        )
        assert len(results) == 1
        assert results[0].detection_ids == (_DETECTION_1,)
        assert results[0].evidence == {
            "reason": SIGNAL_STANDALONE,
            "event_id": str(_EVENT_1),
            "member_count": 1,
        }

    def test_two_detections_from_same_event(self):
        results = CorrelationAgent().analyze(
            _batch(
                _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_2, event_id=_EVENT_1),
            ),
            clock=_FIXED_TS,
        )
        assert len(results) == 1
        assert results[0].detection_ids == (_DETECTION_1, _DETECTION_2)
        assert results[0].evidence == {
            "reason": SIGNAL_SHARED_EVENT,
            "event_id": str(_EVENT_1),
            "member_count": 2,
        }

    def test_many_detections_from_same_event(self):
        results = CorrelationAgent().analyze(
            _batch(
                _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_2, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_3, event_id=_EVENT_1),
            ),
            clock=_FIXED_TS,
        )
        assert len(results) == 1
        assert results[0].detection_ids == (
            _DETECTION_1, _DETECTION_2, _DETECTION_3,
        )
        assert results[0].event_ids == (
            _EVENT_1, _EVENT_1, _EVENT_1,
        )

    def test_multiple_independent_events(self):
        results = CorrelationAgent().analyze(
            _batch(
                _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_2, event_id=_EVENT_2),
            ),
            clock=_FIXED_TS,
        )
        assert len(results) == 2
        assert results[0].detection_ids == (_DETECTION_1,)
        assert results[1].detection_ids == (_DETECTION_2,)

    def test_multiple_independent_correlations(self):
        results = CorrelationAgent().analyze(
            _batch(
                _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_2, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_3, event_id=_EVENT_2),
                _input(detection_id=_DETECTION_4, event_id=_EVENT_2),
            ),
            clock=_FIXED_TS,
        )
        assert len(results) == 2
        assert results[0].detection_ids == (_DETECTION_1, _DETECTION_2)
        assert results[1].detection_ids == (_DETECTION_3, _DETECTION_4)

    def test_mixed_correlated_and_uncorrelated_detections(self):
        results = CorrelationAgent().analyze(
            _batch(
                _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_2, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_3, event_id=_EVENT_2),
            ),
            clock=_FIXED_TS,
        )
        assert len(results) == 2
        assert results[0].evidence["reason"] == SIGNAL_SHARED_EVENT
        assert results[0].detection_ids == (_DETECTION_1, _DETECTION_2)
        assert results[1].evidence["reason"] == SIGNAL_STANDALONE
        assert results[1].detection_ids == (_DETECTION_3,)


# ---------------------------------------------------------------------------
# 2. Identity
# ---------------------------------------------------------------------------


class TestIdentityAndDeterminism:
    """Requirements 8-10: correlation identity + deterministic repeat."""

    def test_correlation_ids_are_distinct_from_detection_ids(self):
        results = CorrelationAgent().analyze(
            _batch(_input(detection_id=_DETECTION_1, event_id=_EVENT_1)),
            clock=_FIXED_TS,
        )
        correlation_id = results[0].correlation_id
        assert isinstance(correlation_id, uuid.UUID)
        assert correlation_id not in results[0].detection_ids
        assert correlation_id != _DETECTION_1
        assert correlation_id != _EVENT_1

    def test_each_result_has_a_unique_correlation_id(self):
        results = CorrelationAgent().analyze(
            _batch(
                _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_2, event_id=_EVENT_2),
            ),
            clock=_FIXED_TS,
        )
        ids = [result.correlation_id for result in results]
        assert len(set(ids)) == len(ids)

    def test_identity_follows_step10a_generated_identity_semantics(self):
        # Step 10A defines correlation_id as a generated identity
        # (uuid4 default factory); it is never derived from the
        # detection/event identities.
        result = CorrelationAgent().analyze(
            _batch(_input()), clock=_FIXED_TS
        )[0]
        assert result.correlation_id != result.members[0].detection_id
        assert result.correlation_id != result.members[0].event_id

    def test_repeated_analysis_is_fully_deterministic_with_clock(self):
        batch = _batch(
            _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
            _input(detection_id=_DETECTION_2, event_id=_EVENT_1),
            _input(detection_id=_DETECTION_3, event_id=_EVENT_2),
        )
        agent = CorrelationAgent()
        first = agent.analyze(batch, clock=_FIXED_TS)
        second = agent.analyze(batch, clock=_FIXED_TS)
        assert [_signature(r) for r in first] == [
            _signature(r) for r in second
        ]

    def test_identity_fields_differ_across_invocations(self):
        # correlation_id is generated identity per Step 10A — the
        # deterministic projection above excludes it; the ids themselves
        # are per-execution identities.
        batch = _batch(_input())
        first = CorrelationAgent().analyze(batch, clock=_FIXED_TS)[0]
        second = CorrelationAgent().analyze(batch, clock=_FIXED_TS)[0]
        assert first.correlation_id != second.correlation_id

    def test_content_is_deterministic_even_without_a_clock(self):
        batch = _batch(
            _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
            _input(detection_id=_DETECTION_2, event_id=_EVENT_1),
        )
        agent = CorrelationAgent()
        first, second = agent.analyze(batch), agent.analyze(batch)
        for a, b in zip(first, second):
            assert a.detection_ids == b.detection_ids
            assert a.event_ids == b.event_ids
            assert a.evidence == b.evidence
            assert a.metadata == b.metadata
            assert a.status == b.status
            assert a.confidence == b.confidence
            assert a.provenance == b.provenance


# ---------------------------------------------------------------------------
# 3. Input integrity
# ---------------------------------------------------------------------------


class TestInputIntegrity:
    """Requirements 11-15: nothing is mutated, nothing aliases inputs."""

    def test_input_batch_is_not_mutated(self):
        batch = _batch(
            _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
            _input(detection_id=_DETECTION_2, event_id=_EVENT_1),
        )
        before = batch.model_dump()
        CorrelationAgent().analyze(batch, clock=_FIXED_TS)
        assert batch.model_dump() == before

    def test_detection_objects_are_not_mutated(self):
        detection = _input()
        before = detection.model_dump()
        CorrelationAgent().analyze(_batch(detection), clock=_FIXED_TS)
        assert detection.model_dump() == before

    def test_input_evidence_and_metadata_are_not_mutated(self):
        evidence = {"matched_conditions": ["a"], "nested": {"k": "v"}}
        metadata = {"rule_version": "1.2.3", "nested": [1, 2]}
        detection = _input(evidence=evidence, metadata=metadata)
        before_evidence = copy.deepcopy(evidence)
        before_metadata = copy.deepcopy(metadata)
        CorrelationAgent().analyze(_batch(detection), clock=_FIXED_TS)
        assert evidence == before_evidence
        assert metadata == before_metadata

    def test_results_do_not_alias_input_structures(self):
        evidence = {"matched_conditions": ["a"]}
        detection = _input(evidence=evidence)
        result = CorrelationAgent().analyze(
            _batch(detection), clock=_FIXED_TS
        )[0]
        assert result.evidence is not evidence
        # mutating the input evidence cannot affect the existing result
        evidence["matched_conditions"].append("mutated")
        assert result.evidence == {
            "reason": SIGNAL_STANDALONE,
            "event_id": str(_EVENT_1),
            "member_count": 1,
        }
        # mutating the result evidence cannot affect the input.  The input
        # still only reflects the deliberate external mutation above; the
        # result-side mutation never wrote back into it.
        result.evidence["reason"] = "mutated"
        assert detection.evidence["matched_conditions"] == ["a", "mutated"]

    def test_members_are_references_not_detection_copies(self):
        result = CorrelationAgent().analyze(
            _batch(_input(detection_id=_DETECTION_1, event_id=_EVENT_1)),
            clock=_FIXED_TS,
        )[0]
        member = result.members[0]
        assert isinstance(member, CorrelationMember)
        assert member.detection_id == _DETECTION_1
        assert member.event_id == _EVENT_1
        assert member.timestamp == _FIXED_TS


# ---------------------------------------------------------------------------
# 4. Ordering
# ---------------------------------------------------------------------------


class TestOrdering:
    """Requirements 16-18: stable output, stable members, batch order."""

    def test_output_follows_first_seen_input_order(self):
        results = CorrelationAgent().analyze(
            _batch(
                _input(detection_id=_DETECTION_1, event_id=_EVENT_2),
                _input(detection_id=_DETECTION_2, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_3, event_id=_EVENT_2),
            ),
            clock=_FIXED_TS,
        )
        assert [r.event_ids[0] for r in results] == [_EVENT_2, _EVENT_1]
        assert results[0].detection_ids == (_DETECTION_1, _DETECTION_3)
        assert results[1].detection_ids == (_DETECTION_2,)

    def test_member_order_follows_batch_order(self):
        results = CorrelationAgent().analyze(
            _batch(
                _input(detection_id=_DETECTION_2, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_3, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
            ),
            clock=_FIXED_TS,
        )
        assert results[0].detection_ids == (
            _DETECTION_2, _DETECTION_3, _DETECTION_1,
        )

    def test_batch_order_is_stable_across_repeated_analysis(self):
        batch = _batch(
            _input(detection_id=_DETECTION_1, event_id=_EVENT_2),
            _input(detection_id=_DETECTION_2, event_id=_EVENT_1),
        )
        agent = CorrelationAgent()
        first = agent.analyze(batch, clock=_FIXED_TS)
        second = agent.analyze(batch, clock=_FIXED_TS)
        assert [r.detection_ids for r in first] == [
            r.detection_ids for r in second
        ]


# ---------------------------------------------------------------------------
# 5. Event relationships
# ---------------------------------------------------------------------------


class TestEventRelationships:
    """Requirements 19-22: same/different event behaviour."""

    def test_same_event_id_is_grouped(self):
        results = CorrelationAgent().analyze(
            _batch(
                _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_2, event_id=_EVENT_1),
            ),
            clock=_FIXED_TS,
        )
        assert len(results) == 1
        assert results[0].event_ids == (_EVENT_1, _EVENT_1)

    def test_different_event_ids_are_never_grouped(self):
        results = CorrelationAgent().analyze(
            _batch(
                _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_2, event_id=_EVENT_2),
                _input(detection_id=_DETECTION_3, event_id=_EVENT_1),
            ),
            clock=_FIXED_TS,
        )
        assert len(results) == 2
        assert results[0].detection_ids == (_DETECTION_1, _DETECTION_3)
        assert results[1].detection_ids == (_DETECTION_2,)

    def test_interleaved_events_keep_each_event_together(self):
        results = CorrelationAgent().analyze(
            _batch(
                _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_2, event_id=_EVENT_2),
                _input(detection_id=_DETECTION_3, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_4, event_id=_EVENT_2),
            ),
            clock=_FIXED_TS,
        )
        assert results[0].detection_ids == (_DETECTION_1, _DETECTION_3)
        assert results[1].detection_ids == (_DETECTION_2, _DETECTION_4)

    def test_many_events_with_many_detections(self):
        results = CorrelationAgent().analyze(
            _batch(
                _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_2, event_id=_EVENT_2),
                _input(detection_id=_DETECTION_3, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_4, event_id=_EVENT_3),
            ),
            clock=_FIXED_TS,
        )
        assert len(results) == 3
        assert results[0].detection_ids == (_DETECTION_1, _DETECTION_3)
        assert results[1].detection_ids == (_DETECTION_2,)
        assert results[2].detection_ids == (_DETECTION_4,)


# ---------------------------------------------------------------------------
# 6. Duplicates
# ---------------------------------------------------------------------------


class TestDuplicates:
    """Requirement 23: Step 9I/10A duplicate semantics are preserved."""

    def test_identical_detection_records_are_preserved(self):
        results = CorrelationAgent().analyze(
            _batch(
                _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
            ),
            clock=_FIXED_TS,
        )
        assert len(results) == 1
        assert results[0].detection_ids == (_DETECTION_1, _DETECTION_1)
        assert results[0].evidence["member_count"] == 2

    def test_same_detection_across_events_splits_into_groups(self):
        results = CorrelationAgent().analyze(
            _batch(
                _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_1, event_id=_EVENT_2),
            ),
            clock=_FIXED_TS,
        )
        assert len(results) == 2
        assert results[0].detection_ids == (_DETECTION_1,)
        assert results[1].detection_ids == (_DETECTION_1,)

    def test_no_artificial_unique_detection_ids_are_created(self):
        result = CorrelationAgent().analyze(
            _batch(
                _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
            ),
            clock=_FIXED_TS,
        )[0]
        assert len(set(result.detection_ids)) == 1
        assert all(det == _DETECTION_1 for det in result.detection_ids)


# ---------------------------------------------------------------------------
# 7. Evidence
# ---------------------------------------------------------------------------


class TestEvidence:
    """Requirements 24-27: explaining, JSON-safe, no raw payloads."""

    def test_evidence_exists_for_every_correlation(self):
        results = CorrelationAgent().analyze(
            _batch(
                _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_2, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_3, event_id=_EVENT_2),
            ),
            clock=_FIXED_TS,
        )
        for result in results:
            assert isinstance(result.evidence, dict)
            assert result.evidence.get("reason") in (
                SIGNAL_SHARED_EVENT,
                SIGNAL_STANDALONE,
            )

    def test_evidence_explains_the_deterministic_reason(self):
        result = CorrelationAgent().analyze(
            _batch(
                _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_2, event_id=_EVENT_1),
            ),
            clock=_FIXED_TS,
        )[0]
        assert result.evidence == {
            "reason": SIGNAL_SHARED_EVENT,
            "event_id": str(_EVENT_1),
            "member_count": 2,
        }

    def test_evidence_is_json_compatible(self):
        results = CorrelationAgent().analyze(
            _batch(_input()), clock=_FIXED_TS
        )
        for result in results:
            round_tripped = json.loads(json.dumps(result.evidence))
            assert round_tripped == result.evidence

    def test_evidence_contains_no_raw_security_payload(self):
        batch = _batch(
            _input(
                detection_id=_DETECTION_1,
                event_id=_EVENT_1,
                evidence={
                    "source": "raw",
                    "command_line": "attacker cmd",
                },
                metadata={"raw": {"process": "powershell -enc blob"}},
            ),
            _input(detection_id=_DETECTION_2, event_id=_EVENT_1),
        )
        result = CorrelationAgent().analyze(batch, clock=_FIXED_TS)[0]
        serialized = json.dumps(result.evidence)
        assert "command_line" not in serialized
        assert "attacker" not in serialized
        assert "powershell" not in serialized
        assert set(result.evidence.keys()) == {
            "reason", "event_id", "member_count",
        }

    def test_evidence_counts_match_members_and_metadata_is_empty(self):
        batch = _batch(
            _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
            _input(detection_id=_DETECTION_2, event_id=_EVENT_1),
            _input(detection_id=_DETECTION_3, event_id=_EVENT_2),
        )
        results = CorrelationAgent().analyze(batch, clock=_FIXED_TS)
        for result in results:
            assert result.evidence["member_count"] == len(result.members)
            assert result.evidence["event_id"] == str(result.event_ids[0])
            assert result.metadata == {}


# ---------------------------------------------------------------------------
# 8. Confidence
# ---------------------------------------------------------------------------


class TestConfidence:
    """Requirements 28-30: no confidence surrogates from detections."""

    def test_correlation_confidence_is_absent_by_default(self):
        results = CorrelationAgent().analyze(
            _batch(_input(confidence=0.42)), clock=_FIXED_TS
        )
        assert all(result.confidence is None for result in results)

    def test_detection_confidence_is_never_reused(self):
        batch = _batch(
            _input(detection_id=_DETECTION_1, confidence=1.0),
            _input(detection_id=_DETECTION_2, confidence=0.0),
            _input(detection_id=_DETECTION_3, confidence=0.55),
        )
        results = CorrelationAgent().analyze(batch, clock=_FIXED_TS)
        assert all(result.confidence is None for result in results)

    def test_boundary_detection_confidences_do_not_leak(self):
        # 0.0 and 1.0 are valid detection confidences; neither is reused.
        batch = _batch(
            _input(detection_id=_DETECTION_1, confidence=0.0),
            _input(detection_id=_DETECTION_2, confidence=1.0),
        )
        result = CorrelationAgent().analyze(batch, clock=_FIXED_TS)[0]
        assert result.confidence is None


# ---------------------------------------------------------------------------
# 9. Status and provenance (Step 10A defaults)
# ---------------------------------------------------------------------------


class TestStatusAndProvenance:
    """Requirements 33-35: Step 10A lifecycle and provenance semantics."""

    def test_status_is_candidate_by_default(self):
        result = CorrelationAgent().analyze(
            _batch(_input()), clock=_FIXED_TS
        )[0]
        assert result.status == CorrelationStatus.CANDIDATE
        assert result.status.value == "candidate"

    def test_produced_status_never_deviates_from_candidate(self):
        results = CorrelationAgent().analyze(
            _batch(
                _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_2, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_3, event_id=_EVENT_2),
            ),
            clock=_FIXED_TS,
        )
        assert all(
            result.status == CorrelationStatus.CANDIDATE
            for result in results
        )

    def test_invalid_status_is_rejected_by_the_contract(self):
        with pytest.raises(ValidationError):
            CorrelationResult(
                members=to_correlation_members([_input()]),
                timestamp=_FIXED_TS,
                status="forged",
            )

    def test_provenance_is_correlated_on_every_result(self):
        results = CorrelationAgent().analyze(
            _batch(
                _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_2, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_3, event_id=_EVENT_2),
            ),
            clock=_FIXED_TS,
        )
        for result in results:
            assert result.provenance == Provenance.CORRELATED
        assert Provenance.CORRELATED in Provenance


# ---------------------------------------------------------------------------
# 10. Secret safety
# ---------------------------------------------------------------------------


class TestSecretSafety:
    """Requirements 31-33: no secrets in evidence, exceptions, or logs."""

    def test_credential_shaped_input_is_rejected_at_the_9i_boundary(self):
        with pytest.raises(ValidationError):
            _input(evidence={"api_key": "super-secret-value"})
        with pytest.raises(ValidationError):
            _input(metadata={"authorization": "Bearer abc.def.ghi"})

    def test_agent_exception_messages_never_echo_secrets(self):
        with pytest.raises(CorrelationInputError) as exc_info:
            CorrelationAgent().analyze("api_key=super-secret-value")
        message = str(exc_info.value).lower()
        for pattern in (
            "api_key",
            "super-secret",
            "authorization",
            "bearer",
            "password",
        ):
            assert pattern not in message

    def test_failing_strategy_logs_no_secrets(self, caplog):
        class ExplodingStrategy:
            name = "exploding"

            def correlate(self, inputs):
                raise RuntimeError(
                    "leak api_key=super-secret-credential-value"
                )

        agent = CorrelationAgent(strategy=ExplodingStrategy())
        with caplog.at_level(
            logging.WARNING, logger="app.agents.correlation"
        ):
            with pytest.raises(CorrelationStrategyError):
                agent.analyze(_batch(_input()), clock=_FIXED_TS)
        records = "\n".join(record.getMessage() for record in caplog.records)
        assert "super-secret-credential-value" not in records
        assert "leak" not in records

    def test_successful_agent_logs_no_payload_content(self, caplog):
        batch = _batch(
            _input(
                detection_id=_DETECTION_1,
                event_id=_EVENT_1,
                evidence={"matched_conditions": ["condition_1"]},
            ),
            _input(detection_id=_DETECTION_2, event_id=_EVENT_1),
        )
        with caplog.at_level(
            logging.INFO, logger="app.agents.correlation"
        ):
            CorrelationAgent().analyze(batch, clock=_FIXED_TS)
        messages = "\n".join(r.getMessage() for r in caplog.records)
        assert "condition_1" not in messages
        assert "input-1" not in messages.lower()
        assert "strategy=deterministic_same_event" in messages
        assert "inputs=2" in messages
        assert "correlations=1" in messages


# ---------------------------------------------------------------------------
# 10. Failure isolation
# ---------------------------------------------------------------------------


class TestFailureIsolation:
    """Requirements 34-36: controlled failure, no fake/partial results."""

    def test_non_batch_input_raises_controlled_error(self):
        with pytest.raises(CorrelationInputError):
            CorrelationAgent().analyze(["not", "a", "batch"])

    def test_none_batch_raises_controlled_error(self):
        with pytest.raises(CorrelationInputError):
            CorrelationAgent().analyze(None)

    def test_unexpected_strategy_failure_wraps_with_original_cause(self):
        class ExplodingStrategy:
            name = "exploding"

            def correlate(self, inputs):
                raise RuntimeError("boom")

        agent = CorrelationAgent(strategy=ExplodingStrategy())
        with pytest.raises(CorrelationStrategyError) as exc_info:
            agent.analyze(_batch(_input()), clock=_FIXED_TS)
        assert isinstance(exc_info.value.__cause__, RuntimeError)

    def test_controlled_input_error_propagates_unwrapped(self):
        class BadStrategy:
            name = "bad"

            def correlate(self, inputs):
                raise CorrelationInputError("bad record inside inputs")

        agent = CorrelationAgent(strategy=BadStrategy())
        with pytest.raises(CorrelationInputError):
            agent.analyze(_batch(_input()), clock=_FIXED_TS)

    def test_strategy_failure_never_returns_partial_results(self):
        class ExplodingStrategy:
            name = "exploding"

            def correlate(self, inputs):
                raise RuntimeError("boom")

        agent = CorrelationAgent(strategy=ExplodingStrategy())
        with pytest.raises(CorrelationStrategyError):
            agent.analyze(
                _batch(
                    _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
                    _input(detection_id=_DETECTION_2, event_id=_EVENT_2),
                ),
                clock=_FIXED_TS,
            )

    def test_malformed_group_output_is_a_controlled_failure(self):
        class GarbageStrategy:
            name = "garbage"

            def correlate(self, inputs):
                return [42]

        agent = CorrelationAgent(strategy=GarbageStrategy())
        with pytest.raises(CorrelationStrategyError):
            agent.analyze(_batch(_input()), clock=_FIXED_TS)

    def test_empty_group_output_is_a_controlled_failure(self):
        class EmptyGroupStrategy:
            name = "empty"

            def correlate(self, inputs):
                return [
                    CorrelationGroup(
                        members=(),
                        signal=SIGNAL_STANDALONE,
                        event_id=_EVENT_1,
                    )
                ]

        agent = CorrelationAgent(strategy=EmptyGroupStrategy())
        with pytest.raises(CorrelationStrategyError):
            agent.analyze(_batch(_input()), clock=_FIXED_TS)

    def test_mixed_valid_and_invalid_output_is_a_controlled_failure(self):
        class MixedStrategy:
            name = "mixed"

            def correlate(self, inputs):
                return [
                    CorrelationGroup(
                        members=(inputs[0],),
                        signal=SIGNAL_STANDALONE,
                        event_id=inputs[0].event_id,
                    ),
                    "not a group",
                ]

        agent = CorrelationAgent(strategy=MixedStrategy())
        with pytest.raises(CorrelationStrategyError):
            agent.analyze(_batch(_input()), clock=_FIXED_TS)

    def test_exception_hierarchy(self):
        assert issubclass(CorrelationInputError, CorrelationError)
        assert issubclass(CorrelationStrategyError, CorrelationError)


# ---------------------------------------------------------------------------
# 11. Strategy independence
# ---------------------------------------------------------------------------


class TestStrategyIndependence:
    """Requirements 37-40: strategy is testable and injectable."""

    def test_strategy_name_is_exposed(self):
        assert (
            DeterministicCorrelationStrategy().name
            == "deterministic_same_event"
        )

    def test_strategy_is_independently_testable(self):
        strategy = DeterministicCorrelationStrategy()
        groups = strategy.correlate(
            [
                _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_2, event_id=_EVENT_2),
                _input(detection_id=_DETECTION_3, event_id=_EVENT_1),
            ]
        )
        assert [group.event_id for group in groups] == [
            _EVENT_1, _EVENT_2,
        ]
        assert groups[0].signal == SIGNAL_SHARED_EVENT
        assert groups[1].signal == SIGNAL_STANDALONE
        assert [m.detection_id for m in groups[0].members] == [
            _DETECTION_1, _DETECTION_3,
        ]

    def test_agent_delegates_to_configured_strategy(self):
        class RecordingStrategy:
            name = "recording"

            def __init__(self):
                self.called_with = None

            def correlate(self, inputs):
                self.called_with = inputs
                return [
                    CorrelationGroup(
                        members=(inputs[0],),
                        signal=SIGNAL_STANDALONE,
                        event_id=inputs[0].event_id,
                    )
                ]

        strategy = RecordingStrategy()
        agent = CorrelationAgent(strategy=strategy)
        batch = _batch(
            _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
            _input(detection_id=_DETECTION_2, event_id=_EVENT_1),
        )
        results = agent.analyze(batch, clock=_FIXED_TS)
        assert strategy.called_with is batch.detections
        assert len(results) == 1
        assert results[0].detection_ids == (_DETECTION_1,)
        assert results[0].evidence["reason"] == SIGNAL_STANDALONE

    def test_default_agent_uses_the_baseline_strategy(self):
        batch = _batch(
            _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
            _input(detection_id=_DETECTION_2, event_id=_EVENT_1),
        )
        assert len(CorrelationAgent().analyze(batch, clock=_FIXED_TS)) == 1

    def test_agent_source_contains_no_grouping_rules(self):
        source = inspect.getsource(agent_module)
        assert "event_id ==" not in source
        assert "members_by_group" not in source
        assert SIGNAL_SHARED_EVENT not in source
        assert SIGNAL_STANDALONE not in source


# ---------------------------------------------------------------------------
# 12. Strategy input validation (independent layer)
# ---------------------------------------------------------------------------


class TestStrategyInputValidation:
    """The strategy layer validates its own inputs."""

    def test_strategy_rejects_non_input_records(self):
        with pytest.raises(CorrelationInputError):
            DeterministicCorrelationStrategy().correlate(
                ["not a detection"]
            )

    def test_strategy_rejects_non_input_at_any_position(self):
        strategy = DeterministicCorrelationStrategy()
        items = [
            _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
            "not a detection",
        ]
        with pytest.raises(CorrelationInputError) as exc_info:
            strategy.correlate(items)
        assert "position 1" in str(exc_info.value)

    def test_strategy_empty_sequence_returns_no_groups(self):
        assert DeterministicCorrelationStrategy().correlate([]) == []

    def test_strategy_groups_are_immutable(self):
        group = DeterministicCorrelationStrategy().correlate([_input()])[0]
        with pytest.raises(AttributeError):
            group.signal = "mutated"  # type: ignore[misc]
        with pytest.raises(AttributeError):
            group.members = ()  # type: ignore[misc]


# ---------------------------------------------------------------------------
# 13. No future concepts
# ---------------------------------------------------------------------------


class TestNoFutureConcepts:
    """Requirements 41-48: no risk/incident/MITRE/response/AI/storage."""

    def test_no_risk_score_in_outputs(self):
        results = CorrelationAgent().analyze(
            _batch(_input()), clock=_FIXED_TS
        )
        for result in results:
            for name in (
                "risk", "risk_score", "risk_level", "threat_score",
                "priority", "alert_level",
            ):
                assert name not in result.evidence
                assert name not in result.metadata
                assert not hasattr(result, name)

    def test_no_incident_fields_in_outputs(self):
        result = CorrelationAgent().analyze(
            _batch(_input()), clock=_FIXED_TS
        )[0]
        for name in (
            "incident_id", "incident_severity", "incident_status",
            "incident_priority",
        ):
            assert not hasattr(result, name)

    def test_no_mitre_fields_in_outputs(self):
        result = CorrelationAgent().analyze(
            _batch(_input()), clock=_FIXED_TS
        )[0]
        for name in ("tactic", "technique", "procedure", "attack_stage"):
            assert not hasattr(result, name)

    def test_no_severity_aggregation_into_correlation(self):
        batch = _batch(
            _input(
                detection_id=_DETECTION_1,
                severity=DetectionSeverity.CRITICAL,
            ),
            _input(
                detection_id=_DETECTION_2,
                severity=DetectionSeverity.LOW,
            ),
        )
        result = CorrelationAgent().analyze(batch, clock=_FIXED_TS)[0]
        assert "severity" not in result.evidence
        assert "severity" not in result.metadata
        # members carry references only — no severity/confidence payload
        member = result.members[0]
        assert set(CorrelationMember.model_fields) == {
            "detection_id", "event_id", "timestamp",
        }

    def test_no_response_or_attribution_fields(self):
        result = CorrelationAgent().analyze(
            _batch(_input()), clock=_FIXED_TS
        )[0]
        for name in (
            "response", "remediation", "blocking", "playbook",
            "attacker", "campaign", "threat_actor",
        ):
            assert name not in result.evidence
            assert name not in result.metadata
            assert not hasattr(result, name)

    def test_no_time_window_configuration(self):
        strategy_source = inspect.getsource(
            DeterministicCorrelationStrategy
        )
        agent_source = inspect.getsource(agent_module)
        combined = strategy_source + agent_source
        for constant in ("TIME_WINDOW", "MAX_GAP", "timedelta", "within"):
            assert constant not in combined

    def test_no_llm_network_or_storage_dependency(self):
        import app.services.correlation.exceptions as exceptions_module
        import app.services.correlation.strategy as strategy_module

        combined = (
            inspect.getsource(agent_module)
            + "\n"
            + inspect.getsource(strategy_module)
            + "\n"
            + inspect.getsource(exceptions_module)
        ).lower()
        for forbidden in (
            "llm", "ollama", "embedding", "vector", "langgraph",
            "requests.", "http.client", "socket.", "neo4j", "qdrant",
            "kafka", "rabbitmq", "sqlalchemy", "postgresql", "redis",
            "fastapi",
        ):
            assert forbidden not in combined, forbidden

    def test_strategy_is_stateless_across_invocations(self):
        strategy = DeterministicCorrelationStrategy()
        first = strategy.correlate(
            [_input(detection_id=_DETECTION_1, event_id=_EVENT_1)]
        )
        second = strategy.correlate(
            [
                _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_2, event_id=_EVENT_2),
            ]
        )
        # the first call's state must not influence the second call
        assert len(first) == 1
        assert len(second) == 2
        assert second[0].signal == SIGNAL_STANDALONE


# ---------------------------------------------------------------------------
# 14. Edge cases and property tests
# ---------------------------------------------------------------------------


class TestEdgeCasesAndProperties:
    """Timezone, UUID, large batches, unicode, optionals, boundaries."""

    def test_member_timestamps_preserved_and_timezone_aware(self):
        results = CorrelationAgent().analyze(
            _batch(
                _input(
                    detection_id=_DETECTION_1,
                    event_id=_EVENT_1,
                    timestamp=_FIXED_TS,
                ),
                _input(
                    detection_id=_DETECTION_2,
                    event_id=_EVENT_2,
                    timestamp=_LATER_TS,
                ),
            ),
            clock=_EVEN_LATER_TS,
        )
        assert results[0].members[0].timestamp == _FIXED_TS
        assert results[1].members[0].timestamp == _LATER_TS
        assert all(
            member.timestamp.tzinfo is not None
            for result in results
            for member in result.members
        )

    def test_temporal_boundaries_are_descriptive_not_evidence(self):
        batch = _batch(
            _input(
                detection_id=_DETECTION_1,
                timestamp=_FIXED_TS,
                event_id=_EVENT_1,
            ),
            _input(
                detection_id=_DETECTION_2,
                timestamp=_EVEN_LATER_TS,
                event_id=_EVENT_1,
            ),
        )
        result = CorrelationAgent().analyze(
            batch, clock=_EVEN_LATER_TS
        )[0]
        assert result.first_seen_at == _FIXED_TS
        assert result.last_seen_at == _EVEN_LATER_TS

    def test_temporal_proximity_alone_never_correlates(self):
        # Same instant, three different events: NOT one giant correlation.
        results = CorrelationAgent().analyze(
            _batch(
                _input(
                    detection_id=_DETECTION_1,
                    event_id=_EVENT_1,
                    timestamp=_FIXED_TS,
                ),
                _input(
                    detection_id=_DETECTION_2,
                    event_id=_EVENT_2,
                    timestamp=_FIXED_TS,
                ),
                _input(
                    detection_id=_DETECTION_3,
                    event_id=_EVENT_3,
                    timestamp=_FIXED_TS,
                ),
            ),
            clock=_FIXED_TS,
        )
        assert len(results) == 3
        for result in results:
            assert result.evidence["reason"] == SIGNAL_STANDALONE
            assert len(result.members) == 1

    def test_naive_timestamps_are_rejected_by_the_contract(self):
        with pytest.raises(ValidationError):
            _input(timestamp=datetime(2025, 8, 1, 12, 0, 0))

    def test_uuid_edge_cases(self):
        all_zero = uuid.UUID(int=0)
        max_uuid = uuid.UUID(int=(2**128) - 1)
        batch = _batch(
            _input(detection_id=all_zero, event_id=all_zero),
            _input(detection_id=all_zero, event_id=max_uuid),
            _input(detection_id=max_uuid, event_id=all_zero),
        )
        results = CorrelationAgent().analyze(batch, clock=_FIXED_TS)
        assert len(results) == 2
        assert results[0].detection_ids == (all_zero, max_uuid)
        assert results[0].event_ids == (all_zero, all_zero)
        assert results[1].detection_ids == (all_zero,)
        assert results[1].event_ids == (max_uuid,)

    def test_very_large_batch_is_linear_and_complete(self):
        batch_size = 2000
        inputs = [
            _input(
                detection_id=uuid.uuid4(),
                event_id=(
                    _EVENT_1 if index % 2 == 0 else uuid.uuid4()
                ),
            )
            for index in range(batch_size)
        ]
        results = CorrelationAgent().analyze(
            _batch(*inputs), clock=_FIXED_TS
        )
        shared = sum(
            1
            for result in results
            if result.evidence["reason"] == SIGNAL_SHARED_EVENT
        )
        assert shared == 1
        assert len(results) == 1 + batch_size // 2
        total = sum(len(result.members) for result in results)
        assert total == batch_size

    def test_repeated_event_ids_keep_batch_order_not_chronology(self):
        batch = _batch(
            _input(
                detection_id=_DETECTION_1,
                timestamp=_LATER_TS,
                event_id=_EVENT_1,
            ),
            _input(
                detection_id=_DETECTION_2,
                timestamp=_FIXED_TS,
                event_id=_EVENT_1,
            ),
        )
        result = CorrelationAgent().analyze(batch, clock=_FIXED_TS)[0]
        assert result.detection_ids == (_DETECTION_1, _DETECTION_2)

    def test_repeated_rule_ids_do_not_cause_grouping(self):
        batch = _batch(
            _input(
                detection_id=_DETECTION_1,
                event_id=_EVENT_1,
                rule_id="shared-rule",
            ),
            _input(
                detection_id=_DETECTION_2,
                event_id=_EVENT_2,
                rule_id="shared-rule",
            ),
        )
        results = CorrelationAgent().analyze(batch, clock=_FIXED_TS)
        assert len(results) == 2
        assert results[0].evidence["reason"] == SIGNAL_STANDALONE
        assert results[1].evidence["reason"] == SIGNAL_STANDALONE

    def test_similar_evidence_text_never_causes_grouping(self):
        # Two detections share rule, severity, confidence and an identical
        # evidence payload, but originate from different events.  Evidence
        # and metadata are never parsed for grouping signals.
        batch = _batch(
            _input(
                detection_id=_DETECTION_1,
                event_id=_EVENT_1,
                rule_id="shared-rule",
                evidence={
                    "matched_conditions": ["process.execution"],
                    "command_line": "cmd.exe /c whoami",
                },
                metadata={"rule_version": "1.0.0"},
            ),
            _input(
                detection_id=_DETECTION_2,
                event_id=_EVENT_2,
                rule_id="shared-rule",
                evidence={
                    "matched_conditions": ["process.execution"],
                    "command_line": "cmd.exe /c whoami",
                },
                metadata={"rule_version": "1.0.0"},
            ),
        )
        results = CorrelationAgent().analyze(batch, clock=_FIXED_TS)
        assert len(results) == 2
        for result in results:
            assert result.evidence["reason"] == SIGNAL_STANDALONE
            assert len(result.members) == 1

    def test_batch_membership_alone_never_causes_grouping(self):
        # Three unrelated detections transported in one envelope: the batch
        # itself is not a grouping signal.
        results = CorrelationAgent().analyze(
            _batch(
                _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_2, event_id=_EVENT_2),
                _input(detection_id=_DETECTION_3, event_id=_EVENT_3),
            ),
            clock=_FIXED_TS,
        )
        assert len(results) == 3
        for result in results:
            assert result.evidence["reason"] == SIGNAL_STANDALONE

    def test_missing_optional_fields_and_empty_payloads(self):
        detection = _input(rule_version=None, evidence={}, metadata={})
        result = CorrelationAgent().analyze(
            _batch(detection), clock=_FIXED_TS
        )[0]
        assert result.members[0].detection_id == _DETECTION_1
        assert result.evidence["member_count"] == 1
        assert detection.rule_version is None
        assert detection.evidence == {}
        assert detection.metadata == {}

    def test_unicode_and_long_strings(self):
        unicode_rule = "συμβάν-日本語-🚀-" * 20
        evidence = {"note": "日本語テキスト", "extra": "x" * 120}
        detection = _input(rule_id=unicode_rule, evidence=evidence)
        result = CorrelationAgent().analyze(
            _batch(detection), clock=_FIXED_TS
        )[0]
        assert result.evidence["member_count"] == 1
        assert result.members[0].detection_id == _DETECTION_1
        assert detection.rule_id == unicode_rule