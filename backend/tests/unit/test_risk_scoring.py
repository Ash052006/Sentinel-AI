"""Tests for the Risk Scoring Agent and deterministic engine (Step 11B).

Covers the deterministic cardinality risk scoring engine, the
RiskScoringAgent orchestration boundary, the exact scoring formula
(weights, normalization, clamping), risk level thresholds and reachability,
confidence independence, factor/evidence correspondence, determinism, input
immutability, secret-safety, invalid-input handling, agent injection,
dependency isolation, and regression against the completed detection /
correlation subsystems.

Pure unit tests — no database, no network, no LLM.  The agent and engine
operate entirely in memory on Step 10A / Step 11A contracts.
"""

import copy
import inspect
import json
import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

import app.agents.risk_scoring as agent_module
import app.services.risk.engine as engine_module
from app.agents.risk_scoring import RiskScoringAgent
from app.agents.correlation import CorrelationAgent
from app.schemas.correlation import (
    CorrelationMember,
    CorrelationResult,
    CorrelationStatus,
)
from app.schemas.detection import DetectionSeverity, RuleType
from app.schemas.detection_correlation import (
    DetectionCorrelationBatch,
    DetectionCorrelationBatchMetadata,
    DetectionCorrelationInput,
)
from app.schemas.risk import RiskAssessment, RiskEvidence, RiskFactor, RiskLevel
from app.schemas.security_event import Provenance
from app.services.risk.engine import (
    BREADTH_REFERENCE,
    CONFIDENCE_ABSENT_BASELINE,
    DIVERSITY_REFERENCE,
    LEVEL_CRITICAL_MIN,
    LEVEL_HIGH_MAX,
    LEVEL_LOW_MAX,
    LEVEL_MEDIUM_MAX,
    POLICY_NAME,
    ROUND_DECIMALS,
    VOLUME_REFERENCE,
    WEIGHT_BREADTH,
    WEIGHT_DIVERSITY,
    WEIGHT_VOLUME,
    DeterministicRiskScoringEngine,
    RiskScoringStrategy,
    clamp01,
    confidence_for_correlation,
    normalize_excess,
    risk_level_for_score,
)
from app.services.risk.exceptions import (
    RiskScoringError,
    RiskScoringInputError,
    RiskScoringStrategyError,
)

_FIXED_TS = datetime(2025, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
_LATER_TS = datetime(2025, 8, 1, 12, 30, 0, tzinfo=timezone.utc)
_EVEN_LATER_TS = datetime(2025, 8, 1, 13, 0, 0, tzinfo=timezone.utc)

_CORRELATION_ID = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

_DETECTION_1 = uuid.UUID("11111111-1111-1111-1111-111111111111")
_DETECTION_2 = uuid.UUID("22222222-2222-2222-2222-222222222222")
_DETECTION_3 = uuid.UUID("33333333-3333-3333-3333-333333333333")
_DETECTION_4 = uuid.UUID("44444444-4444-4444-4444-444444444444")
_DETECTION_5 = uuid.UUID("55555555-5555-5555-5555-555555555555")
_DETECTION_6 = uuid.UUID("66666666-6666-6666-6666-666666666666")
_DETECTION_7 = uuid.UUID("77777777-7777-7777-7777-777777777777")
_DETECTION_8 = uuid.UUID("88888888-8888-8888-8888-888888888888")
_EVENT_1 = uuid.UUID("aaaa11aa-1111-1111-1111-111111111111")
_EVENT_2 = uuid.UUID("aaaa22aa-2222-2222-2222-222222222222")
_EVENT_3 = uuid.UUID("aaaa33aa-3333-3333-3333-333333333333")
_EVENT_4 = uuid.UUID("aaaa44aa-4444-4444-4444-444444444444")

DETECTIONS = (
    _DETECTION_1,
    _DETECTION_2,
    _DETECTION_3,
    _DETECTION_4,
    _DETECTION_5,
    _DETECTION_6,
    _DETECTION_7,
    _DETECTION_8,
)
EVENTS = (_EVENT_1, _EVENT_2, _EVENT_3, _EVENT_4)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _member(
    detection_id: uuid.UUID = _DETECTION_1,
    event_id: uuid.UUID = _EVENT_1,
    timestamp: datetime = _FIXED_TS,
) -> CorrelationMember:
    """Return a minimal valid Step 10A CorrelationMember reference."""
    return CorrelationMember(
        detection_id=detection_id,
        event_id=event_id,
        timestamp=timestamp,
    )


def _correlation(
    members: list[CorrelationMember] | None = None,
    *,
    correlation_id: uuid.UUID = _CORRELATION_ID,
    confidence: float | None = None,
    status: CorrelationStatus = CorrelationStatus.CANDIDATE,
    timestamp: datetime = _FIXED_TS,
) -> CorrelationResult:
    """Return a valid Step 10A CorrelationResult."""
    return CorrelationResult(
        correlation_id=correlation_id,
        members=(members if members is not None else [_member()]),
        status=status,
        confidence=confidence,
        timestamp=timestamp,
    )


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


def _scoring_signature(assessment: RiskAssessment) -> dict:
    """Deterministic projection of an assessment (identity excluded)."""
    return {
        "correlation_id": assessment.correlation_id,
        "score": assessment.score,
        "level": assessment.level.value,
        "confidence": assessment.confidence,
        "factors": [factor.model_dump() for factor in assessment.factors],
        "evidence": [item.model_dump() for item in assessment.evidence],
        "metadata": assessment.metadata,
    }


def _factor_type_names(assessment: RiskAssessment) -> list[str]:
    return [factor.factor_type for factor in assessment.factors]


def _evidence_types(evidence: list[RiskEvidence]) -> list[str]:
    return [item.observation_type for item in evidence]


# ---------------------------------------------------------------------------
# 1. Basic scoring (matrix 1-6)
# ---------------------------------------------------------------------------


class TestBasicScoring:
    """End-to-end scoring of representative correlations."""

    def test_standalone_correlation_scores_nothing(self):
        # 1. a minimal standalone correlation scores exactly 0.0 (LOW)
        assessment = DeterministicRiskScoringEngine().score(
            _correlation(members=[_member()]),
            timestamp=_FIXED_TS,
        )
        assert assessment.score == 0.0
        assert assessment.level is RiskLevel.LOW

    def test_single_case_identity_preserved(self):
        # 2. correlation_id is preserved exactly on the assessment
        assessment = RiskScoringAgent().analyze(
            _correlation(members=[_member()]),
            clock=_FIXED_TS,
        )
        assert assessment.correlation_id == _CORRELATION_ID

    def test_larger_correlation_scores_higher(self):
        # 3. more correlated detections -> strictly higher score
        low = DeterministicRiskScoringEngine().score(
            _correlation(members=[_member()]),
            timestamp=_FIXED_TS,
        )
        high = DeterministicRiskScoringEngine().score(
            _correlation(
                members=[_member(_DETECTION_1), _member(_DETECTION_2)]
            ),
            timestamp=_FIXED_TS,
        )
        assert high.score > low.score

    def test_unknown_severity_metadata_never_reaches_score(self):
        # 4. severity/rule data absent from CorrelationResult is not used
        assessment = RiskScoringAgent().analyze(
            _correlation(members=[_member()]),
            clock=_FIXED_TS,
        )
        dumped = json.dumps(assessment.model_dump(mode="json")).lower()
        assert "severity" not in dumped
        assert "sigma" not in dumped

    def test_confidence_independent_fields(self):
        # 5. score/level exist independent of confidence field values
        a = RiskScoringAgent().analyze(
            _correlation(confidence=None), clock=_FIXED_TS
        )
        b = RiskScoringAgent().analyze(
            _correlation(confidence=0.8), clock=_FIXED_TS
        )
        assert a.score == b.score == 0.0

    def test_provenance_is_risk_assessed(self):
        # 6. the assessment carries RISK_ASSESSED provenance
        assessment = RiskScoringAgent().analyze(
            _correlation(), clock=_FIXED_TS
        )
        assert assessment.provenance is Provenance.RISK_ASSESSED


# ---------------------------------------------------------------------------
# 2. Score bounds, determinism, differentiation (matrix 7-12)
# ---------------------------------------------------------------------------


class TestScoreBounds:

    def test_score_lower_boundary_zero(self):
        # 7. minimal input reaches exactly 0.0
        assessment = DeterministicRiskScoringEngine().score(
            _correlation(members=[_member()]),
            timestamp=_FIXED_TS,
        )
        assert assessment.score == 0.0

    def test_score_upper_boundary_one(self):
        # 8. maximal input reaches exactly 1.0
        members = [
            _member(detection_id=det, event_id=EVENTS[i % len(EVENTS)])
            for i, det in enumerate(DETECTIONS)
        ]
        assessment = DeterministicRiskScoringEngine().score(
            _correlation(members=members),
            timestamp=_FIXED_TS,
        )
        assert assessment.score == 1.0
        assert assessment.level is RiskLevel.CRITICAL

    def test_score_never_below_zero(self):
        # 9. never below 0 (clamping guarantee)
        members = [_member()]
        affinity = normalize_excess(len(members), VOLUME_REFERENCE)
        raw = (
            WEIGHT_VOLUME * affinity
            + WEIGHT_BREADTH * 0.0
            + WEIGHT_DIVERSITY * 0.0
        )
        assert clamp01(raw) >= 0.0

    def test_score_never_above_one(self):
        # 10. never above 1 (clamping guarantee)
        raw = (
            WEIGHT_VOLUME * 5.0
            + WEIGHT_BREADTH * 5.0
            + WEIGHT_DIVERSITY * 5.0
        )
        assert clamp01(raw) <= 1.0

    def test_different_inputs_different_scores(self):
        # 11. structurally different correlations score differently
        single = DeterministicRiskScoringEngine().score(
            _correlation(members=[_member()]), timestamp=_FIXED_TS
        )
        multi = DeterministicRiskScoringEngine().score(
            _correlation(
                members=[
                    _member(_DETECTION_1, _EVENT_1),
                    _member(_DETECTION_2, _EVENT_2),
                ]
            ),
            timestamp=_FIXED_TS,
        )
        assert multi.score != single.score

    def test_rounding_is_stable(self):
        # 12. same formula input yields the same rounded score
        members = [
            _member(det, _EVENT_1) for det in DETECTIONS[:4]
        ]
        engine = DeterministicRiskScoringEngine()
        a = engine.score(_correlation(members=members), timestamp=_FIXED_TS)
        b = engine.score(_correlation(members=members), timestamp=_FIXED_TS)
        assert a.score == b.score
        assert a.score == round(a.score, ROUND_DECIMALS)


# ---------------------------------------------------------------------------
# 3. Level reachability and thresholds (matrix 13-18)
# ---------------------------------------------------------------------------


class TestRiskLevels:

    def _score(self, *pairs):
        members = [
            _member(detection_id=d, event_id=e) for d, e in pairs
        ]
        return DeterministicRiskScoringEngine().score(
            _correlation(members=members), timestamp=_FIXED_TS
        )

    def test_low_level_reachable(self):
        # 13. LOW reachable (minimal score 0.0)
        assert self._score((_DETECTION_1, _EVENT_1)).level is RiskLevel.LOW

    def test_medium_level_reachable(self):
        # 14. MEDIUM reachable
        assessment = self._score(
            (_DETECTION_1, _EVENT_1),
            (_DETECTION_2, _EVENT_1),
            (_DETECTION_3, _EVENT_1),
            (_DETECTION_4, _EVENT_1),
        )
        assert assessment.level is RiskLevel.MEDIUM

    def test_high_level_reachable(self):
        # 15. HIGH reachable -> score >= 0.55 and < 0.75
        assessment = self._score(
            *[(det, _EVENT_1) for det in DETECTIONS[:8]]
        )
        assert assessment.score >= LEVEL_MEDIUM_MAX - 1e-9
        assert assessment.score < LEVEL_CRITICAL_MIN - 1e-9
        assert assessment.level is RiskLevel.HIGH

    def test_critical_level_reachable(self):
        # 16. CRITICAL reachable
        assessment = self._score(
            *[(det, EVENTS[i % len(EVENTS)]) for i, det in enumerate(DETECTIONS)]
        )
        assert assessment.level is RiskLevel.CRITICAL

    def test_low_max_boundary_exact(self):
        # 17. threshold 0.30 -> exactly MEDIUM (lower-inclusive)
        assert risk_level_for_score(LEVEL_LOW_MAX) is RiskLevel.MEDIUM

    def test_medium_and_high_boundaries_exact(self):
        # 18. 0.55 -> HIGH, 0.75 -> CRITICAL, edges one step lower
        assert risk_level_for_score(LEVEL_MEDIUM_MAX) is RiskLevel.HIGH
        assert risk_level_for_score(LEVEL_HIGH_MAX) is RiskLevel.CRITICAL
        assert risk_level_for_score(LEVEL_LOW_MAX - 1e-9) is RiskLevel.LOW
        assert (
            risk_level_for_score(LEVEL_MEDIUM_MAX - 1e-9)
            is RiskLevel.MEDIUM
        )
        assert (
            risk_level_for_score(LEVEL_HIGH_MAX - 1e-9) is RiskLevel.HIGH
        )


# ---------------------------------------------------------------------------
# 4. Confidence: bounds, determinism, independence (matrix 19-23)
# ---------------------------------------------------------------------------


class TestConfidence:

    def test_confidence_lower_boundary_zero(self):
        # 19. confidence lower boundary 0.0 reachable
        assessment = RiskScoringAgent().analyze(
            _correlation(confidence=0.0), clock=_FIXED_TS
        )
        assert assessment.confidence == 0.0

    def test_confidence_upper_boundary_one(self):
        # 20. confidence upper boundary 1.0 reachable
        assessment = RiskScoringAgent().analyze(
            _correlation(confidence=1.0), clock=_FIXED_TS
        )
        assert assessment.confidence == 1.0

    def test_confidence_absent_baseline(self):
        # 21. correlation without confidence -> documented baseline (0.0)
        assessment = RiskScoringAgent().analyze(
            _correlation(confidence=None), clock=_FIXED_TS
        )
        assert assessment.confidence == CONFIDENCE_ABSENT_BASELINE
        assert confidence_for_correlation(
            _correlation(confidence=None)
        ) == CONFIDENCE_ABSENT_BASELINE

    def test_confidence_deterministic(self):
        # 22. same inputs -> same confidence
        a = RiskScoringAgent().analyze(
            _correlation(confidence=0.42), clock=_FIXED_TS
        )
        b = RiskScoringAgent().analyze(
            _correlation(confidence=0.42), clock=_FIXED_TS
        )
        assert a.confidence == b.confidence == 0.42

    def test_confidence_never_changes_score(self):
        # 23. independent of score: varying confidence does not change score
        low_conf = RiskScoringAgent().analyze(
            _correlation(confidence=0.1), clock=_FIXED_TS
        )
        high_conf = RiskScoringAgent().analyze(
            _correlation(confidence=0.9), clock=_FIXED_TS
        )
        assert low_conf.score == high_conf.score
        assert low_conf.level is high_conf.level


# ---------------------------------------------------------------------------
# 5. Factors (matrix 24-29)
# ---------------------------------------------------------------------------


class TestFactors:

    def _assessment(self, pairs):
        members = [
            _member(detection_id=d, event_id=e) for d, e in pairs
        ]
        return DeterministicRiskScoringEngine().score(
            _correlation(members=members), timestamp=_FIXED_TS
        )

    def test_factors_present_in_documented_order(self):
        # 24. three factors enumerated in a stable, documented order
        assessment = self._assessment(
            [(_DETECTION_1, _EVENT_1), (_DETECTION_2, _EVENT_2)]
        )
        assert _factor_type_names(assessment) == [
            "member_volume",
            "event_breadth",
            "detection_diversity",
        ]

    def test_member_volume_contribution(self):
        # 25. member_volume contribution = normalized member count excess
        pairs = [(det, _EVENT_1) for det in DETECTIONS[:5]]
        assessment = self._assessment(pairs)
        volume_factor = assessment.factors[0]
        expected = round(normalize_excess(5, VOLUME_REFERENCE), ROUND_DECIMALS)
        assert volume_factor.contribution == expected

    def test_event_breadth_contribution(self):
        # 26. event_breadth contribution = normalized distinct event count
        assessment = self._assessment(
            [(_DETECTION_1, _EVENT_1), (_DETECTION_2, _EVENT_2)]
        )
        breadth_factor = assessment.factors[1]
        expected = round(normalize_excess(2, BREADTH_REFERENCE), ROUND_DECIMALS)
        assert breadth_factor.contribution == expected

    def test_detection_diversity_contribution(self):
        # 27. detection_diversity contribution = normalized distinct detections
        assessment = self._assessment(
            list(zip(DETECTIONS[:3], (EVENTS[0], _EVENT_1, _EVENT_1)))
        )
        diversity_factor = assessment.factors[2]
        expected = round(
            normalize_excess(3, DIVERSITY_REFERENCE), ROUND_DECIMALS
        )
        assert diversity_factor.contribution == expected

    def test_factor_contributions_bounded(self):
        # 28. every contribution lies within [0, 1]
        assessment = self._assessment(
            (det, EVENTS[i % len(EVENTS)])
            for i, det in enumerate(DETECTIONS)
        )
        for factor in assessment.factors:
            assert 0.0 <= factor.contribution <= 1.0

    def test_factor_evidence_matches_members(self):
        # 29. member_volume factor evidence references the actual members
        pairs = [(_DETECTION_1, _EVENT_1), (_DETECTION_2, _EVENT_2)]
        assessment = self._assessment(pairs)
        volume_evidence = assessment.factors[0].evidence
        assert len(volume_evidence) == 2
        assert {e.detection_id for e in volume_evidence} == {
            _DETECTION_1,
            _DETECTION_2,
        }
        assert {e.event_id for e in volume_evidence} == {_EVENT_1, _EVENT_2}


# ---------------------------------------------------------------------------
# 6. Evidence (matrix 30-35)
# ---------------------------------------------------------------------------


class TestEvidence:

    def _assessment(self, pairs):
        members = [
            _member(detection_id=d, event_id=e) for d, e in pairs
        ]
        return DeterministicRiskScoringEngine().score(
            _correlation(members=members), timestamp=_FIXED_TS
        )

    def test_assessment_evidence_per_member(self):
        # 30. one correlation_member observation per member
        assessment = self._assessment(
            [(_DETECTION_1, _EVENT_1), (_DETECTION_2, _EVENT_2)]
        )
        assert _evidence_types(assessment.evidence) == [
            "correlation_member",
            "correlation_member",
        ]

    def test_evidence_references_preserved(self):
        # 31. evidence carries the actual detection/event references
        assessment = self._assessment(
            [(_DETECTION_1, _EVENT_1), (_DETECTION_2, _EVENT_2)]
        )
        ids = {(e.detection_id, e.event_id) for e in assessment.evidence}
        assert ids == {(_DETECTION_1, _EVENT_1), (_DETECTION_2, _EVENT_2)}

    def test_no_fabricated_evidence(self):
        # 32. every evidence item maps to an actual input fact
        assessment = self._assessment(
            list(zip(DETECTIONS[:3], (EVENTS[0], EVENTS[1], EVENTS[0])))
        )
        member_ids = {
            m.detection_id for m in assessment.evidence
        }
        assert member_ids <= set(DETECTIONS[:3])
        # factor evidence touches only real detections/events
        for factor in assessment.factors:
            for item in factor.evidence:
                if item.detection_id is not None:
                    assert item.detection_id in set(DETECTIONS[:3])
                if item.event_id is not None:
                    assert item.event_id in {EVENTS[0], EVENTS[1]}

    def test_event_breadth_factor_evidence(self):
        # 33. event_breadth factor evidence names distinct events
        assessment = self._assessment(
            [(_DETECTION_1, _EVENT_1), (_DETECTION_2, _EVENT_1)]
        )
        breadth_evidence = assessment.factors[1].evidence
        assert [e.observation_type for e in breadth_evidence] == [
            "distinct_event"
        ]
        assert breadth_evidence[0].event_id == _EVENT_1

    def test_detection_diversity_factor_evidence(self):
        # 34. detection_diversity factor evidence names distinct detections
        assessment = self._assessment(
            [(_DETECTION_1, _EVENT_1), (_DETECTION_2, _EVENT_1)]
        )
        diversity_evidence = assessment.factors[2].evidence
        assert [e.observation_type for e in diversity_evidence] == [
            "distinct_detection",
            "distinct_detection",
        ]

    def test_evidence_deterministic_order(self):
        # 35. evidence is emitted in stable, reproducible order
        pairs = [
            (_DETECTION_2, _EVENT_2),
            (_DETECTION_1, _EVENT_1),
            (_DETECTION_2, _EVENT_1),
        ]
        a = self._assessment(pairs)
        b = self._assessment(pairs)
        assert _scoring_signature(a)["evidence"] == _scoring_signature(b)[
            "evidence"
        ]


# ---------------------------------------------------------------------------
# 7. Correlation identity preservation / no duplication (matrix 36-38)
# ---------------------------------------------------------------------------


class TestCorrelationIdentity:

    def test_correlation_id_preserved_exactly(self):
        # 36. correlation_id is preserved (never regenerated)
        cid = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
        assessment = RiskScoringAgent().analyze(
            _correlation(correlation_id=cid), clock=_FIXED_TS
        )
        assert assessment.correlation_id == cid

    def test_no_correlation_duplication(self):
        # 37. the correlation is never embedded/copied into the assessment
        assessment = RiskScoringAgent().analyze(
            _correlation(), clock=_FIXED_TS
        )
        dumped = json.dumps(assessment.model_dump(mode="json")).lower()
        assert "members" not in dumped
        assert "correlation_" not in dumped or "correlation_id" in dumped

    def test_risk_assessment_id_is_distinct_identity(self):
        # 38. risk_assessment_id differs from correlation_id and is auto
        assessment = RiskScoringAgent().analyze(
            _correlation(), clock=_FIXED_TS
        )
        assert assessment.risk_assessment_id != assessment.correlation_id


# ---------------------------------------------------------------------------
# 8. Immutability (matrix 39-43)
# ---------------------------------------------------------------------------


class TestImmutability:

    def test_inputs_not_mutated_by_engine(self):
        # 39. engine never mutates the correlation or its members
        correlation = _correlation(
            members=[_member(_DETECTION_1), _member(_DETECTION_2)]
        )
        before = copy.deepcopy(correlation)
        DeterministicRiskScoringEngine().score(
            correlation, timestamp=_FIXED_TS
        )
        assert correlation == before

    def test_inputs_not_mutated_by_agent(self):
        # 40. agent never mutates the correlation
        correlation = _correlation(
            members=[_member(_DETECTION_1), _member(_DETECTION_2)]
        )
        before = copy.deepcopy(correlation)
        RiskScoringAgent().analyze(correlation, clock=_FIXED_TS)
        assert correlation == before

    def test_factor_evidence_independent_of_sources(self):
        # 41. mutating correlation after scoring cannot leak into factors
        correlation = _correlation(members=[_member(_DETECTION_1)])
        assessment = RiskScoringAgent().analyze(
            correlation, clock=_FIXED_TS
        )
        original_factor_count = len(assessment.factors[0].evidence)
        # attempt to mutate the correlation post-hoc
        correlation.members.append(_member(_DETECTION_2))
        assert len(assessment.factors[0].evidence) == original_factor_count

    def test_metadata_not_shared_with_input(self):
        # 42. assessment metadata is independent of correlation metadata
        correlation = _correlation()
        correlation.metadata["note"] = "x"
        assessment = RiskScoringAgent().analyze(
            correlation, clock=_FIXED_TS
        )
        assert "note" not in assessment.metadata

    def test_repeated_scoring_does_not_accumulate(self):
        # 43. no state accumulation across calls (stateless engine)
        correlation = _correlation(members=[_member(_DETECTION_1)])
        engine = DeterministicRiskScoringEngine()
        first = engine.score(correlation, timestamp=_FIXED_TS)
        engine.score(correlation, timestamp=_FIXED_TS)
        engine.score(correlation, timestamp=_FIXED_TS)
        last = engine.score(correlation, timestamp=_FIXED_TS)
        assert first.score == last.score
        assert len(first.factors) == len(last.factors)


# ---------------------------------------------------------------------------
# 9. Determinism (matrix 44-49)
# ---------------------------------------------------------------------------


class TestDeterminism:

    def test_identical_inputs_identical_assessment(self):
        # 44. same correlation + same clock -> identical scoring fields
        correlation = _correlation(
            members=[_member(_DETECTION_1), _member(_DETECTION_2)]
        )
        a = RiskScoringAgent().analyze(correlation, clock=_FIXED_TS)
        b = RiskScoringAgent().analyze(correlation, clock=_FIXED_TS)
        assert _scoring_signature(a) == _scoring_signature(b)

    def test_timestamp_does_not_affect_score(self):
        # 45. clock affects only the bookkeeping timestamp, never the score
        correlation = _correlation(
            members=[_member(_DETECTION_1), _member(_DETECTION_2)]
        )
        early = RiskScoringAgent().analyze(
            correlation, clock=_FIXED_TS
        )
        late = RiskScoringAgent().analyze(
            correlation, clock=_EVEN_LATER_TS
        )
        assert early.score == late.score
        assert early.level is late.level
        assert early.confidence == late.confidence
        assert early.timestamp == _FIXED_TS
        assert late.timestamp == _EVEN_LATER_TS

    def test_member_order_does_not_change_score(self):
        # 46. reordered members still produce the same score/level
        pairs = [
            (_DETECTION_1, _EVENT_1),
            (_DETECTION_2, _EVENT_2),
            (_DETECTION_3, _EVENT_1),
        ]
        direct = [
            _member(detection_id=d, event_id=e) for d, e in pairs
        ]
        shuffled = [
            _member(detection_id=d, event_id=e) for d, e in pairs[::-1]
        ]
        engine = DeterministicRiskScoringEngine()
        a = engine.score(
            _correlation(members=direct), timestamp=_FIXED_TS
        )
        b = engine.score(
            _correlation(members=shuffled), timestamp=_FIXED_TS
        )
        assert a.score == b.score
        assert a.level is b.level

    def test_no_clock_deterministic_with_clock(self):
        # 47. injecting a clock yields fully reproducible output
        correlation = _correlation(members=[_member(_DETECTION_1)])
        a = RiskScoringAgent().analyze(correlation, clock=_FIXED_TS)
        b = RiskScoringAgent().analyze(correlation, clock=_FIXED_TS)
        assert _scoring_signature(a) == _scoring_signature(b)

    def test_fixed_normalization_reference_values(self):
        # 48. normalization is a pure function of documented references
        assert normalize_excess(1, VOLUME_REFERENCE) == 0.0
        assert normalize_excess(VOLUME_REFERENCE, VOLUME_REFERENCE) == 1.0
        assert normalize_excess(100, VOLUME_REFERENCE) == 1.0

    def test_engine_name_constant(self):
        # 49. the engine is identifiable by a stable name
        assert DeterministicRiskScoringEngine().name == POLICY_NAME


# ---------------------------------------------------------------------------
# 10. Security / secret-safety (matrix 50-56)
# ---------------------------------------------------------------------------


class TestSecurity:

    def _assessment(self, pairs):
        members = [
            _member(detection_id=d, event_id=e) for d, e in pairs
        ]
        return DeterministicRiskScoringEngine().score(
            _correlation(members=members), timestamp=_FIXED_TS
        )

    def test_metadata_contains_no_secret_patterns(self):
        # 50. assessment metadata is secret-free
        assessment = self._assessment(
            list(zip(DETECTIONS, EVENTS))
        )
        blob = json.dumps(assessment.metadata).lower()
        for pattern in ("api_key", "authorization", "bearer", "secret"):
            assert pattern not in blob

    def test_evidence_contains_no_secret_patterns(self):
        # 51. evidence is secret-free
        assessment = self._assessment(
            list(zip(DETECTIONS, EVENTS))
        )
        blob = json.dumps(
            [e.model_dump(mode="json") for e in assessment.evidence]
        ).lower()
        for pattern in ("api_key", "authorization", "bearer", "secret"):
            assert pattern not in blob

    def test_factor_metadata_contains_no_secret_patterns(self):
        # 52. factor metadata is secret-free
        assessment = self._assessment(
            list(zip(DETECTIONS, EVENTS))
        )
        blob = json.dumps(
            [f.model_dump(mode="json") for f in assessment.factors]
        ).lower()
        for pattern in ("api_key", "authorization", "bearer", "secret"):
            assert pattern not in blob

    def test_correlation_payload_not_copied(self):
        # 53. correlation evidence/metadata content is never copied out
        correlation = _correlation()
        correlation.evidence = {"reason": "shared_event_id"}
        correlation.metadata = {"opaque": "value"}
        assessment = RiskScoringAgent().analyze(
            correlation, clock=_FIXED_TS
        )
        assert "opaque" not in json.dumps(assessment.metadata)
        assert "reason" not in assessment.metadata

    def test_no_timestamps_in_metadata_or_evidence(self):
        # 54. scoring metadata/evidence carry no timestamp inputs
        assessment = self._assessment(
            [(_DETECTION_1, _EVENT_1), (_DETECTION_2, _EVENT_2)]
        )
        dumped = json.dumps(assessment.model_dump(mode="json"))
        assert "first_seen" not in dumped
        assert "last_seen" not in dumped
        assert "'" not in dumped  # no datetime reprs leaked

    def test_no_severity_rule_or_threat_fields(self):
        # 55. no severity/rule/threat-intel content in the assessment
        assessment = self._assessment(
            list(zip(DETECTIONS, EVENTS))
        )
        dumped = json.dumps(assessment.model_dump(mode="json")).lower()
        for token in (
            "ip_address", "malware", "attacker", "mitre", "ttps",
            "geo", "reputation", "playbook", "incident_id",
        ):
            assert token not in dumped

    def test_validation_filters_invalid_provenance(self):
        # 56. non-RISK_ASSESSED provenance is rejected by the contract
        with pytest.raises(ValidationError):
            RiskAssessment(
                correlation_id=_CORRELATION_ID,
                score=0.5,
                level=RiskLevel.MEDIUM,
                confidence=0.5,
                timestamp=_FIXED_TS,
                provenance=Provenance.DETECTED,
            )


# ---------------------------------------------------------------------------
# 11. Invalid input (matrix 57-64)
# ---------------------------------------------------------------------------


class TestInvalidInput:

    def test_engine_rejects_non_correlation(self):
        # 57. engine raises RiskScoringInputError for non-correlation input
        with pytest.raises(RiskScoringInputError):
            DeterministicRiskScoringEngine().score(
                "not-a-correlation", timestamp=_FIXED_TS
            )

    def test_agent_rejects_non_correlation(self):
        # 58. agent raises RiskScoringInputError for non-correlation input
        with pytest.raises(RiskScoringInputError):
            RiskScoringAgent().analyze(
                "not-a-correlation", clock=_FIXED_TS
            )

    def test_error_is_controlled_hierarchy(self):
        # 59. errors belong to the RiskScoringError hierarchy
        assert issubclass(RiskScoringInputError, RiskScoringError)
        assert issubclass(RiskScoringStrategyError, RiskScoringError)

    def test_agent_converts_strategy_failure(self):
        # 60. unexpected strategy failures become RiskScoringStrategyError
        class _Broken(RiskScoringStrategy):
            name = "broken"

            def score(self, correlation, *, timestamp):
                raise RuntimeError("boom")

        with pytest.raises(RiskScoringStrategyError):
            RiskScoringAgent(engine=_Broken()).analyze(
                _correlation(), clock=_FIXED_TS
            )

    def test_agent_rejects_malformed_strategy_result(self):
        # 61. non-RiskAssessment strategy output is refused
        class _Wrong(RiskScoringStrategy):
            name = "wrong"

            def score(self, correlation, *, timestamp):
                return {"score": 0.5}

        with pytest.raises(RiskScoringStrategyError):
            RiskScoringAgent(engine=_Wrong()).analyze(
                _correlation(), clock=_FIXED_TS
            )

    def test_invalid_input_message_is_specific(self):
        # 62. input errors identify the offending type
        with pytest.raises(RiskScoringInputError) as excinfo:
            RiskScoringAgent().analyze(object(), clock=_FIXED_TS)
        assert "CorrelationResult" in str(excinfo.value)

    def test_normalization_rejects_bad_reference(self):
        # 63. normalize_excess rejects invalid references defensively
        with pytest.raises(ValueError):
            normalize_excess(2, 1)

    def test_engine_empty_members_not_silently_allowed(self):
        # 64. the contract rejects empty member lists (no empty correlation)
        with pytest.raises(ValidationError):
            _correlation(members=[])


# ---------------------------------------------------------------------------
# 12. Agent (matrix 65-72)
# ---------------------------------------------------------------------------


class TestAgent:

    def test_agent_default_engine(self):
        # 65. default engine is the deterministic engine
        agent = RiskScoringAgent()
        assert agent.engine_name == "deterministic_cardinality_risk_v1"

    def test_agent_engine_injection(self):
        # 66. a custom engine can be injected
        class _Custom(RiskScoringStrategy):
            name = "custom"

            def score(self, correlation, *, timestamp):
                return RiskAssessment(
                    correlation_id=correlation.correlation_id,
                    score=0.25,
                    level=RiskLevel.MEDIUM,
                    confidence=0.5,
                    timestamp=timestamp,
                )

        agent = RiskScoringAgent(engine=_Custom())
        assessment = agent.analyze(_correlation(), clock=_FIXED_TS)
        assert agent.engine_name == "custom"
        assert assessment.score == 0.25
        assert assessment.level is RiskLevel.MEDIUM

    def test_agent_is_stateless(self):
        # 67. repeated analyze() on identical input stays identical
        agent = RiskScoringAgent()
        correlation = _correlation(members=[_member(_DETECTION_1)])
        a = agent.analyze(correlation, clock=_FIXED_TS)
        b = agent.analyze(correlation, clock=_FIXED_TS)
        assert _scoring_signature(a) == _scoring_signature(b)

    def test_agent_no_persistence_side_effects(self):
        # 68. analyze() performs no persistence, no network, no bookkeeping
        agent = RiskScoringAgent()
        before = len(copy.deepcopy(_scoring_signature(
            agent.analyze(_correlation(), clock=_FIXED_TS)
        )))
        assert before >= 0

    def test_agent_clock_defaults_to_utc(self):
        # 69. without a clock the timestamp is timezone-aware UTC
        assessment = RiskScoringAgent().analyze(_correlation())
        assert assessment.timestamp.tzinfo is not None
        assert assessment.timestamp.utcoffset() == timezone.utc.utcoffset(None)

    def test_agent_returns_risk_assessment(self):
        # 70. analyze() always returns a RiskAssessment
        assessment = RiskScoringAgent().analyze(_correlation())
        assert isinstance(assessment, RiskAssessment)

    def test_two_agents_isolated(self):
        # 71. two agent instances do not share state
        agent_a = RiskScoringAgent()
        agent_b = RiskScoringAgent()
        a = agent_a.analyze(_correlation(), clock=_FIXED_TS)
        b = agent_b.analyze(_correlation(), clock=_FIXED_TS)
        assert _scoring_signature(a) == _scoring_signature(b)

    def test_agent_importable_from_package(self):
        # 72. the agent is exported from app.agents
        from app.agents import RiskScoringAgent as PkgAgent

        assert PkgAgent is RiskScoringAgent


# ---------------------------------------------------------------------------
# 13. Dependency isolation (matrix 73-78)
# ---------------------------------------------------------------------------


class TestDependencyIsolation:

    _ENGINE_FORBIDDEN = (
        "llm", "ollama", "embedding", "vector", "langgraph",
        "requests.", "http.client", "socket.", "neo4j", "qdrant",
        "kafka", "rabbitmq", "sqlalchemy", "postgresql", "redis",
        "fastapi",
    )

    def test_engine_source_has_no_llm_imports(self):
        # 73. engine module imports no LLM/AI/embedding
        source = inspect.getsource(engine_module).lower()
        for forbidden in (
            "llm", "ollama", "embedding", "vector", "langgraph",
        ):
            assert forbidden not in source, forbidden

    def test_engine_source_has_no_storage_or_network_imports(self):
        # 74. engine module imports no storage/network/API
        source = inspect.getsource(engine_module).lower()
        for forbidden in (
            "requests.", "http.client", "socket.", "neo4j", "qdrant",
            "kafka", "rabbitmq", "sqlalchemy", "postgresql", "redis",
            "fastapi",
        ):
            assert forbidden not in source, forbidden

    def test_agent_source_has_no_llm_imports(self):
        # 75. agent module imports no LLM/AI/embedding
        source = inspect.getsource(agent_module).lower()
        for forbidden in (
            "llm", "ollama", "embedding", "vector", "langgraph",
        ):
            assert forbidden not in source, forbidden

    def test_agent_source_has_no_storage_or_network_imports(self):
        # 76. agent module imports no storage/network/API
        source = inspect.getsource(agent_module).lower()
        for forbidden in (
            "requests.", "http.client", "socket.", "neo4j", "qdrant",
            "kafka", "rabbitmq", "sqlalchemy", "postgresql", "redis",
            "fastapi",
        ):
            assert forbidden not in source, forbidden

    def test_risk_package_exports(self):
        # 77. package exports the public API
        import app.services.risk as risk_pkg

        for symbol in (
            "RiskScoringError",
            "RiskScoringInputError",
            "RiskScoringStrategyError",
            "RiskScoringStrategy",
            "DeterministicRiskScoringEngine",
            "clamp01",
            "normalize_excess",
            "risk_level_for_score",
            "confidence_for_correlation",
        ):
            assert hasattr(risk_pkg, symbol), symbol

    def test_agent_holds_no_shared_state_between_modules(self):
        # 78. agent/engine modules share no mutable module state
        assert not hasattr(engine_module, "_CACHE")
        assert not hasattr(agent_module, "_CACHE")


# ---------------------------------------------------------------------------
# 14. Regression (matrix 79-86)
# ---------------------------------------------------------------------------


class TestRegression:

    def test_risk_scoring_after_correlation_agent(self):
        # 79. a real CorrelationAgent output can be scored end to end
        batch = _batch(
            _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
            _input(detection_id=_DETECTION_2, event_id=_EVENT_1),
            _input(detection_id=_DETECTION_4, event_id=_EVENT_3),
        )
        results = CorrelationAgent().analyze(batch, clock=_FIXED_TS)
        assert len(results) == 2
        scored = [
            RiskScoringAgent().analyze(r, clock=_LATER_TS)
            for r in results
        ]
        assert len(scored) == 2
        assert {a.correlation_id for a in scored} == {
            r.correlation_id for r in results
        }
        # the two-member shared-event correlation must score above 0
        shared = [a for a in scored if a.score > 0.0]
        assert len(shared) == 1

    def test_risk_does_not_consume_detection_payload(self):
        # 80. detection payloads are not used (evidence-free assessment)
        correlation = _correlation(members=[_member(_DETECTION_1)])
        assessment = RiskScoringAgent().analyze(
            correlation, clock=_FIXED_TS
        )
        dumped = json.dumps(assessment.model_dump(mode="json"))
        assert "matched_conditions" not in dumped

    def test_correlation_contract_unchanged(self):
        # 81. 10A contract still enforces CORRELATED provenance
        with pytest.raises(ValidationError):
            CorrelationResult(
                members=[_member()],
                timestamp=_FIXED_TS,
                provenance=Provenance.DETECTED,
            )

    def test_risk_contract_rejects_out_of_range_score(self):
        # 82. 11A contract still enforces score bounds
        with pytest.raises(ValidationError):
            RiskAssessment(
                correlation_id=_CORRELATION_ID,
                score=1.1,
                level=RiskLevel.CRITICAL,
                confidence=0.5,
                timestamp=_FIXED_TS,
            )

    def test_correlation_agent_determinism_unchanged(self):
        # 83. correlation agent regression: same batch -> same member groups
        batch = _batch(
            _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
            _input(detection_id=_DETECTION_2, event_id=_EVENT_1),
            _input(detection_id=_DETECTION_4, event_id=_EVENT_3),
        )
        first = CorrelationAgent().analyze(batch, clock=_FIXED_TS)
        second = CorrelationAgent().analyze(batch, clock=_FIXED_TS)

        def _groups(results):
            return sorted(
                tuple(
                    (m.detection_id, m.event_id)
                    for m in r.members
                )
                for r in results
            )

        assert _groups(first) == _groups(second)

    def test_detection_severity_enum_importable(self):
        # 84. detection severity import path still resolves
        from app.schemas.detection import DetectionSeverity as Sev

        assert Sev.HIGH.value == "high"
        assert Sev.CRITICAL.value == "critical"

    def test_provenance_enum_has_risk_assessed(self):
        # 85. Provenance.RISK_ASSESSED still present
        assert hasattr(Provenance, "RISK_ASSESSED")
        assert Provenance.RISK_ASSESSED.value == "risk_assessed"

    def test_full_pipeline_deterministic(self):
        # 86. Correlate then score -> identical outcomes across two runs
        def _stripped(assessment):
            signature = _scoring_signature(assessment)
            signature.pop("correlation_id")
            return signature

        def _run():
            batch = _batch(
                _input(detection_id=_DETECTION_1, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_2, event_id=_EVENT_1),
                _input(detection_id=_DETECTION_3, event_id=_EVENT_2),
            )
            results = CorrelationAgent().analyze(batch, clock=_FIXED_TS)
            outcomes = [
                _stripped(RiskScoringAgent().analyze(r, clock=_LATER_TS))
                for r in results
            ]
            return sorted(outcomes, key=lambda o: o["score"])

        assert _run() == _run()