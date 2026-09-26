"""Step 15 — Threat Attribution Engine tests.

Covers the 20 required categories:

1. Engine construction (strategy injection, invalid strategy rejection).
2. Input validation (wrong input type, naive/absent clock, bounds).
3. No-attribution / insufficient / unattributed behavior.
4. Single-candidate attribution.
5. Multiple candidates + deterministic ordering.
6. Conflicting candidates preserved.
7. Duplicate evidence preserved.
8. Same-evidence-both-sides (support + conflict on one target).
9. Confidence (min/max/normal/invalid; no NaN/Inf; no risk conversion).
10. Risk independence.
11. Investigation-confidence independence.
12. RAG independence.
13. Provenance retention and pinning.
14. Explainability (decision paths, evidence traceability).
15. Determinism (clock + UUID factory injection).
16. Immutability (inputs never mutated).
17. Secret safety, fail-closed.
18. Error handling (sanitized, chained, distinct taxonomy).
19. Dependency isolation (AST scan).
20. Performance / bounds behavior.
"""

from __future__ import annotations

import ast
import itertools
import json
import pathlib
import uuid
from datetime import datetime, timezone

import pytest

from app.schemas.security_event import Provenance
from app.schemas.threat_attribution import (
    AttributionAssessment,
    AttributionHypothesis,
    AttributionStatus,
    AttributionTargetType,
    MAX_ATTRIBUTION_EVIDENCE_ITEMS,
    MAX_ATTRIBUTION_HYPOTHESES,
)
from app.schemas.risk import RiskLevel
from app.services.threat_attribution import (
    POLICY_NAME,
    ThreatAttributionEngine,
    ThreatAttributionInput,
    AttributionClaim,
    AttributionContext,
    AttributionError,
    AttributionOutputValidationError,
    AttributionRelation,
    AttributionSafetyError,
    AttributionStrategy,
    AttributionStrategyError,
    InvalidAttributionInputError,
    UnsupportedAttributionSignalError,
)
from app.services.threat_attribution.policy import (
    CONFIDENCE_DECIMALS,
    assess_status,
    attribution_confidence,
)

CID = uuid.UUID("10000000-0000-0000-0000-000000000000")
EID = uuid.UUID("20000000-0000-0000-0000-000000000000")
NOW = datetime(2026, 9, 21, 12, 0, 0, tzinfo=timezone.utc)


def make_claim(
    identifier: str = "APT29",
    target_type: str = "threat_group",
    relationship: AttributionRelation = AttributionRelation.SUPPORTS,
    provenance: Provenance = Provenance.OBSERVED,
    evidence_type: str = "beacon_tls",
    event_id: uuid.UUID | None = EID,
    detection_id: uuid.UUID | None = None,
    correlation_id: uuid.UUID | None = None,
    risk_assessment_id: uuid.UUID | None = None,
    investigation_id: uuid.UUID | None = None,
    metadata: dict | None = None,
    claim_id: uuid.UUID | None = None,
) -> AttributionClaim:
    kwargs = {
        "target_type": target_type,
        "target_identifier": identifier,
        "relationship": relationship,
        "provenance": provenance,
        "evidence_type": evidence_type,
        "event_id": event_id,
        "detection_id": detection_id,
        "correlation_id": correlation_id,
        "risk_assessment_id": risk_assessment_id,
        "investigation_id": investigation_id,
        "metadata": metadata or {},
    }
    if claim_id is not None:
        kwargs["claim_id"] = claim_id
    return AttributionClaim(**kwargs)


def make_input(
    claims: list[AttributionClaim] | None = None,
    context: AttributionContext | None = None,
    correlation_id: uuid.UUID = CID,
) -> ThreatAttributionInput:
    return ThreatAttributionInput(
        correlation_id=correlation_id,
        claims=claims or [],
        context=context,
    )


def make_context(
    risk_level: RiskLevel | None = None,
    investigation_confidence: float | None = None,
    rag_documents_retrieved: int | None = None,
) -> AttributionContext:
    return AttributionContext(
        risk_level=risk_level,
        investigation_confidence=investigation_confidence,
        rag_documents_retrieved=rag_documents_retrieved,
    )


def seq_factory():
    """Deterministic UUID factory: 1, 2, 3, ... for reproducible tests."""
    counter = itertools.count(1)

    def _next() -> uuid.UUID:
        return uuid.UUID(int=next(counter))

    return _next


def run_engine(
    input_data: ThreatAttributionInput,
    *,
    clock: datetime = NOW,
    factory=None,
    engine: ThreatAttributionEngine | None = None,
) -> AttributionAssessment:
    eng = engine or ThreatAttributionEngine()
    ids = factory if factory is not None else seq_factory()
    return eng.assess(input_data, clock=clock, uuid_factory=ids)


# ---------------------------------------------------------------------------
# 1. Engine construction
# ---------------------------------------------------------------------------


class TestEngineConstruction:
    def test_default_strategy_is_deterministic(self):
        engine = ThreatAttributionEngine()
        assert engine.strategy is not None
        assert engine.strategy.name == POLICY_NAME

    def test_injected_strategy_used_and_accessible(self):
        capture = {}
        class MirrorStrategy(AttributionStrategy):
            name = "mirror"

            def assess(self, input_data, *, timestamp, uuid_factory):
                capture["timestamp"] = timestamp
                capture["uuid_factory"] = uuid_factory
                return ThreatAttributionEngine().strategy.assess(
                    input_data, timestamp=timestamp, uuid_factory=uuid_factory
                )

        custom = MirrorStrategy()
        engine = ThreatAttributionEngine(strategy=custom)
        assert engine.strategy is custom
        inp = make_input([make_claim()])
        run_engine(inp, engine=engine)
        assert capture["timestamp"] == NOW
        assert capture["uuid_factory"] is not None

    def test_invalid_strategy_rejected(self):
        with pytest.raises(TypeError):
            ThreatAttributionEngine(strategy=object())

    def test_strategy_contract_enforced(self):
        class NoAssess:
            name = "broken"

        with pytest.raises(TypeError):
            ThreatAttributionEngine(strategy=NoAssess())


# ---------------------------------------------------------------------------
# 2. Input validation
# ---------------------------------------------------------------------------


class TestInputValidation:
    def test_non_contract_input_rejected(self):
        engine = ThreatAttributionEngine()
        for bad in ("boom", None, [], {"correlation_id": "x"}, 42):
            with pytest.raises(InvalidAttributionInputError):
                engine.assess(bad)

    def test_naive_clock_rejected(self):
        with pytest.raises(InvalidAttributionInputError):
            run_engine(make_input(), clock=datetime(2026, 9, 21, 12, 0, 0))

    def test_non_datetime_clock_rejected(self):
        with pytest.raises(InvalidAttributionInputError):
            run_engine(make_input(), clock="2026-09-21T12:00:00Z")

    def test_claim_cap_boundary_accepted(self):
        claims = [make_claim(identifier=f"t{i}", target_type="threat_group")
                  for i in range(10)] * 25
        assert len(claims) == 250
        inp = make_input(claims)
        result = run_engine(inp)
        assert len(result.evidence) == 250

    def test_claim_cap_exceeded_rejected_at_contract(self):
        claims = [make_claim() for _ in range(251)]
        with pytest.raises(ValueError):
            make_input(claims)

    def test_supported_target_hypothesis_bound_exceeded_rejected(self):
        claims = [
            make_claim(identifier=f"target-{i}", target_type="threat_group")
            for i in range(MAX_ATTRIBUTION_HYPOTHESES + 1)
        ]
        with pytest.raises(InvalidAttributionInputError):
            run_engine(make_input(claims))

    def test_supported_target_hypothesis_bound_boundary_accepted(self):
        claims = [
            make_claim(identifier=f"target-{i}", target_type="threat_group")
            for i in range(MAX_ATTRIBUTION_HYPOTHESES)
        ]
        result = run_engine(make_input(claims))
        assert len(result.hypotheses) == MAX_ATTRIBUTION_HYPOTHESES

    def test_metadata_margin_oversize_after_claim_id_rejected(self):
        padding = "x" * 4050
        claim = make_claim(metadata={"note": padding})
        inp = make_input([claim])
        with pytest.raises(InvalidAttributionInputError):
            run_engine(inp)


# ---------------------------------------------------------------------------
# 3. No-attribution / insufficient / unattributed
# ---------------------------------------------------------------------------


class TestNoAttribution:
    def test_empty_input_is_insufficient_evidence(self):
        result = run_engine(make_input())
        assert result.status is AttributionStatus.INSUFFICIENT_EVIDENCE
        assert result.hypotheses == []
        assert result.evidence == []

    def test_empty_input_with_rich_context_still_insufficient(self):
        result = run_engine(
            make_input(context=make_context(
                risk_level=RiskLevel.CRITICAL,
                investigation_confidence=1.0,
                rag_documents_retrieved=100,
            ))
        )
        assert result.status is AttributionStatus.INSUFFICIENT_EVIDENCE
        assert result.hypotheses == []

    def test_conflicts_only_is_unattributed(self):
        result = run_engine(
            make_input([make_claim(relationship=AttributionRelation.CONFLICTS)])
        )
        assert result.status is AttributionStatus.UNATTRIBUTED
        assert result.hypotheses == []
        assert len(result.evidence) == 1

    def test_no_claim_reaches_decision_metadata(self):
        result = run_engine(make_input())
        assert result.metadata["decision"] == "no_attribution_claims"
        assert result.metadata["claim_count"] == 0


# ---------------------------------------------------------------------------
# 4. Single candidate
# ---------------------------------------------------------------------------


class TestSingleCandidate:
    def test_one_supporting_signal_is_partially_supported(self):
        result = run_engine(make_input([make_claim()]))
        assert result.status is AttributionStatus.PARTIALLY_SUPPORTED
        assert len(result.hypotheses) == 1
        h = result.hypotheses[0]
        assert h.target_identifier == "APT29"
        assert h.target_type is AttributionTargetType.THREAT_GROUP
        assert h.confidence == pytest.approx(1 / 3)

    def test_two_supporting_signals_are_attributed(self):
        result = run_engine(make_input([make_claim(), make_claim()]))
        assert result.status is AttributionStatus.ATTRIBUTED
        h = result.hypotheses[0]
        assert len(h.supporting_evidence_ids) == 2
        assert h.confidence == pytest.approx(2 / 3)

    def test_three_supporting_signals_saturate(self):
        result = run_engine(make_input([make_claim() for _ in range(3)]))
        assert result.hypotheses[0].confidence == pytest.approx(1.0)

    def test_single_target_conflicts_with_unknown_provenance_ok(self):
        result = run_engine(
            make_input(
                [
                    make_claim(provenance=Provenance.CORRELATED, correlation_id=EID),
                    make_claim(provenance=Provenance.CORRELATED, correlation_id=EID),
                ]
            )
        )
        assert result.status is AttributionStatus.ATTRIBUTED


# ---------------------------------------------------------------------------
# 5. Multiple candidates
# ---------------------------------------------------------------------------


class TestMultipleCandidates:
    def test_two_supported_targets_conflict_and_both_preserved(self):
        result = run_engine(
            make_input(
                [
                    make_claim(identifier="APT29", target_type="threat_group"),
                    make_claim(identifier="APT29", target_type="threat_group"),
                    make_claim(identifier="Lazarus", target_type="threat_group"),
                ]
            )
        )
        assert result.status is AttributionStatus.CONFLICTING
        ids = [h.target_identifier for h in result.hypotheses]
        assert ids == ["APT29", "Lazarus"]
        by_id = {h.target_identifier: h for h in result.hypotheses}
        assert len(by_id["APT29"].supporting_evidence_ids) == 2
        assert len(by_id["Lazarus"].supporting_evidence_ids) == 1

    def test_different_target_types_order_deterministic(self):
        result = run_engine(
            make_input(
                [
                    make_claim(identifier="Zebra", target_type="malware_family"),
                    make_claim(identifier="Alpha", target_type="threat_actor"),
                    make_claim(identifier="Mid", target_type="campaign"),
                ]
            )
        )
        order = [(h.target_type.value, h.target_identifier) for h in result.hypotheses]
        assert order == sorted(order)

    def test_multi_target_decision_metadata(self):
        result = run_engine(
            make_input(
                [
                    make_claim(identifier="A", target_type="threat_group"),
                    make_claim(identifier="B", target_type="threat_group"),
                ]
            )
        )
        assert result.metadata["decision"] == "multiple_supported_targets"
        assert result.metadata["supported_target_count"] == 2


# ---------------------------------------------------------------------------
# 6. Conflicting candidates preserved
# ---------------------------------------------------------------------------


class TestConflictingCandidates:
    def test_conflict_on_target_does_not_hide_evidence(self):
        result = run_engine(
            make_input(
                [
                    make_claim(),
                    make_claim(relationship=AttributionRelation.CONFLICTS),
                ]
            )
        )
        assert result.status is AttributionStatus.CONFLICTING
        h = result.hypotheses[0]
        assert len(h.supporting_evidence_ids) == 1
        assert len(h.conflicting_evidence_ids) == 1
        assert h.confidence == pytest.approx(0.166667)

    def test_one_conflicted_target_plus_clean_target_conflicts(self):
        result = run_engine(
            make_input(
                [
                    make_claim(identifier="A", target_type="threat_group"),
                    make_claim(identifier="A", target_type="threat_group", relationship=AttributionRelation.CONFLICTS),
                    make_claim(identifier="B", target_type="threat_group"),
                ]
            )
        )
        assert result.status is AttributionStatus.CONFLICTING
        by_id = {h.target_identifier: h for h in result.hypotheses}
        assert len(by_id["A"].conflicting_evidence_ids) == 1
        assert by_id["B"].conflicting_evidence_ids == []


# ---------------------------------------------------------------------------
# 7. Duplicate evidence preserved
# ---------------------------------------------------------------------------


class TestDuplicateEvidencePreserved:
    def test_identical_claims_are_separate_evidence_items(self):
        c1 = make_claim()
        c2 = make_claim()
        result = run_engine(make_input([c1, c2]))
        assert len(result.evidence) == 2
        ids = {e.evidence_id for e in result.evidence}
        assert len(ids) == 2
        h = result.hypotheses[0]
        assert len(h.supporting_evidence_ids) == 2

    def test_evidence_ids_trace_to_claims(self):
        c1 = make_claim()
        c2 = make_claim()
        result = run_engine(make_input([c1, c2]))
        trace = {e.metadata["claim_id"]: e.evidence_id for e in result.evidence}
        assert trace[str(c1.claim_id)] == result.evidence[0].evidence_id
        assert trace[str(c2.claim_id)] == result.evidence[1].evidence_id


# ---------------------------------------------------------------------------
# 8. Same evidence both sides
# ---------------------------------------------------------------------------


class TestSameEvidenceBothSides:
    def test_same_source_reference_both_sides_preserved(self):
        result = run_engine(
            make_input(
                [
                    make_claim(
                        provenance=Provenance.OBSERVED, event_id=EID,
                        relationship=AttributionRelation.SUPPORTS,
                    ),
                    make_claim(
                        provenance=Provenance.OBSERVED, event_id=EID,
                        relationship=AttributionRelation.CONFLICTS,
                    ),
                ]
            )
        )
        assert result.status is AttributionStatus.CONFLICTING
        h = result.hypotheses[0]
        assert len(h.supporting_evidence_ids) == 1
        assert len(h.conflicting_evidence_ids) == 1

    def test_same_evidence_id_never_on_both_sides_of_one_hypothesis(self):
        result = run_engine(
            make_input(
                [
                    make_claim(relationship=AttributionRelation.SUPPORTS),
                    make_claim(relationship=AttributionRelation.CONFLICTS),
                ]
            )
        )
        h = result.hypotheses[0]
        assert not set(h.supporting_evidence_ids) & set(h.conflicting_evidence_ids)


# ---------------------------------------------------------------------------
# 9. Confidence
# ---------------------------------------------------------------------------


class TestConfidence:
    def test_helper_bounds(self):
        assert attribution_confidence(1, 0) == pytest.approx(0.333333)
        assert attribution_confidence(2, 0) == pytest.approx(0.666667)
        assert attribution_confidence(3, 0) == pytest.approx(1.0)

    def test_helper_conflict_reduces(self):
        assert attribution_confidence(2, 1) == pytest.approx(0.444444)
        assert attribution_confidence(1, 9) == pytest.approx(0.033333)

    def test_helper_saturation_at_three(self):
        assert attribution_confidence(4, 0) == pytest.approx(1.0)
        assert attribution_confidence(100, 0) == pytest.approx(1.0)

    def test_helper_invalid_args(self):
        with pytest.raises(ValueError):
            attribution_confidence(0, 0)
        with pytest.raises(ValueError):
            attribution_confidence(1, -1)

    def test_never_nan_or_inf(self):
        for s in range(1, 60):
            for c in range(0, 8):
                value = attribution_confidence(s, c)
                assert 0.0 <= value <= 1.0

    def test_confidence_is_not_risk_conversion(self):
        assert attribution_confidence(1, 0) not in {
            RiskLevel.LOW.value,
            RiskLevel.MEDIUM.value,
            RiskLevel.HIGH.value,
            RiskLevel.CRITICAL.value,
        }

    def test_status_never_derived_from_confidence(self):
        status = assess_status(
            claim_count=1,
            supported_targets=(("threat_group:APT29", 1, 0),),
        )
        assert status is AttributionStatus.PARTIALLY_SUPPORTED
        conflicting = assess_status(
            claim_count=2,
            supported_targets=(("threat_group:APT29", 1, 1),),
        )
        assert conflicting is AttributionStatus.CONFLICTING


# ---------------------------------------------------------------------------
# 10. Risk independence
# ---------------------------------------------------------------------------


class TestRiskIndependence:
    def test_risk_level_never_alters_output(self):
        claims = [make_claim(claim_id=uuid.UUID(int=5)),
                  make_claim(claim_id=uuid.UUID(int=6))]
        base = run_engine(make_input(claims))
        for level in (
            RiskLevel.LOW,
            RiskLevel.MEDIUM,
            RiskLevel.HIGH,
            RiskLevel.CRITICAL,
        ):
            varied = run_engine(
                make_input(claims, context=make_context(risk_level=level))
            )
            assert varied.model_dump_json() == base.model_dump_json()

    def test_critical_risk_does_not_raise_status(self):
        result = run_engine(
            make_input(
                [make_claim()],
                context=make_context(risk_level=RiskLevel.CRITICAL),
            )
        )
        assert result.status is AttributionStatus.PARTIALLY_SUPPORTED

    def test_low_risk_does_not_downgrade_status(self):
        result = run_engine(
            make_input(
                [make_claim() for _ in range(2)],
                context=make_context(risk_level=RiskLevel.LOW),
            )
        )
        assert result.status is AttributionStatus.ATTRIBUTED


# ---------------------------------------------------------------------------
# 11. Investigation-confidence independence
# ---------------------------------------------------------------------------


class TestInvestigationConfidenceIndependence:
    def test_investigation_confidence_never_alters_output(self):
        claims = [make_claim(claim_id=uuid.UUID(int=7)),
                  make_claim(claim_id=uuid.UUID(int=8))]
        base = run_engine(make_input(claims))
        for value in (0.0, 0.5, 1.0, None):
            varied = run_engine(
                make_input(
                    claims,
                    context=make_context(investigation_confidence=value),
                )
            )
            assert varied.model_dump_json() == base.model_dump_json()

    def test_confidence_near_zero_still_attributes_on_evidence(self):
        result = run_engine(
            make_input(
                [make_claim() for _ in range(2)],
                context=make_context(investigation_confidence=0.0),
            )
        )
        assert result.status is AttributionStatus.ATTRIBUTED


# ---------------------------------------------------------------------------
# 12. RAG independence
# ---------------------------------------------------------------------------


class TestRagIndependence:
    def test_rag_count_never_alters_output(self):
        claims = [make_claim(claim_id=uuid.UUID(int=9)),
                  make_claim(claim_id=uuid.UUID(int=10))]
        base = run_engine(make_input(claims))
        for count in (0, 1, 500, None):
            varied = run_engine(
                make_input(
                    claims,
                    context=make_context(rag_documents_retrieved=count),
                )
            )
            assert varied.model_dump_json() == base.model_dump_json()

    def test_rag_retrieval_never_attributes_alone(self):
        result = run_engine(
            make_input(
                [],
                context=make_context(
                    risk_level=RiskLevel.HIGH,
                    investigation_confidence=0.9,
                    rag_documents_retrieved=200,
                ),
            )
        )
        assert result.status is AttributionStatus.INSUFFICIENT_EVIDENCE
        assert result.hypotheses == []

    def test_no_rag_text_field_is_consumable(self):
        fields = AttributionContext.model_fields.keys()
        assert "rag_documents_retrieved" in fields
        assert not any("rag" in field and "documents" not in field for field in fields)
        assert not any("snippet" in field or "text" in field for field in fields)


# ---------------------------------------------------------------------------
# 13. Provenance retention and pinning
# ---------------------------------------------------------------------------


class TestProvenance:
    PROVENANCE_MAP = {
        Provenance.OBSERVED: ("event_id", EID),
        Provenance.ENRICHED: ("event_id", EID),
        Provenance.RECONSTRUCTED: ("event_id", EID),
        Provenance.DETECTED: ("detection_id", EID),
        Provenance.CORRELATED: ("correlation_id", EID),
        Provenance.RISK_ASSESSED: ("risk_assessment_id", EID),
        Provenance.AI_GENERATED: ("investigation_id", EID),
    }

    def test_every_source_provenance_retained_and_referenced(self):
        for provenance, (field, value) in self.PROVENANCE_MAP.items():
            claim = make_claim(provenance=provenance, **{field: value})
            result = run_engine(make_input([claim]))
            assert len(result.evidence) == 1
            ev = result.evidence[0]
            assert ev.provenance is provenance
            assert getattr(ev, field) == value

    def test_evidence_map_matches_source(self):
        result = run_engine(
            make_input(
                [
                    make_claim(provenance=Provenance.DETECTED, detection_id=EID),
                    make_claim(
                        provenance=Provenance.RISK_ASSESSED,
                        risk_assessment_id=EID,
                    ),
                ]
            )
        )
        assert result.evidence[0].detection_id == EID
        assert result.evidence[1].risk_assessment_id == EID

    def test_assessment_and_hypotheses_pinned(self):
        result = run_engine(make_input([make_claim() for _ in range(2)]))
        assert result.provenance is Provenance.ATTRIBUTION_ASSESSED
        assert all(
            h.provenance is Provenance.ATTRIBUTION_ASSESSED
            for h in result.hypotheses
        )

    def test_claim_cannot_cite_attribution_assessed(self):
        with pytest.raises(ValueError):
            make_claim(provenance=Provenance.ATTRIBUTION_ASSESSED, event_id=EID)

    def test_claim_requires_matching_reference(self):
        with pytest.raises(ValueError):
            AttributionClaim(
                target_type="threat_group",
                target_identifier="APT29",
                evidence_type="beacon",
                provenance=Provenance.CORRELATED,
                event_id=EID,
            )


# ---------------------------------------------------------------------------
# 14. Explainability
# ---------------------------------------------------------------------------


class TestExplainability:
    def test_every_hypothesis_has_supporting_evidence(self):
        result = run_engine(
            make_input(
                [
                    make_claim(identifier="A", target_type="threat_group"),
                    make_claim(identifier="B", target_type="threat_group"),
                ]
            )
        )
        present = {e.evidence_id for e in result.evidence}
        for h in result.hypotheses:
            assert h.supporting_evidence_ids
            assert set(h.supporting_evidence_ids) <= present

    def test_policy_label_recorded(self):
        result = run_engine(make_input([make_claim()]))
        assert result.metadata["policy"] == POLICY_NAME

    def test_decision_paths_all_categories(self):
        cases = [
            (make_input([]), "no_attribution_claims"),
            (make_input([make_claim(relationship=AttributionRelation.CONFLICTS)]), "no_supported_target"),
            (
                make_input(
                    [make_claim(), make_claim(relationship=AttributionRelation.CONFLICTS)]
                ),
                "single_supported_target_conflicted",
            ),
            (
                make_input(
                    [make_claim(identifier="A", target_type="threat_group"),
                     make_claim(identifier="B", target_type="threat_group")]
                ),
                "multiple_supported_targets",
            ),
            (
                make_input([make_claim() for _ in range(2)]),
                "single_supported_target_attributed",
            ),
            (make_input([make_claim()]), "single_supported_target_partial"),
        ]
        for inp, expected in cases:
            assert run_engine(inp).metadata["decision"] == expected

    def test_claim_id_traceability_in_metadata(self):
        claim = make_claim()
        result = run_engine(make_input([claim]))
        assert result.evidence[0].metadata["claim_id"] == str(claim.claim_id)


# ---------------------------------------------------------------------------
# 15. Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_fixed_clock_and_ids_identical_output(self):
        inp = make_input([make_claim() for _ in range(2)])
        one = run_engine(inp)
        two = run_engine(inp)
        assert one.model_dump_json() == two.model_dump_json()

    def test_claim_order_does_not_change_snapshot(self):
        forward = [make_claim(identifier="Z", target_type="threat_group"),
                   make_claim(identifier="A", target_type="threat_group")]
        reverse = list(reversed(forward))
        a = run_engine(make_input(forward))
        b = run_engine(make_input(reverse))
        hypotheses_a = [(h.target_identifier, h.confidence) for h in a.hypotheses]
        hypotheses_b = [(h.target_identifier, h.confidence) for h in b.hypotheses]
        assert hypotheses_a == hypotheses_b

    def test_injected_uuid_factory_used(self):
        used = []

        def factory():
            used.append(1)
            return uuid.uuid4()

        inp = make_input([make_claim() for _ in range(2)])
        run_engine(inp, factory=factory)
        assert len(used) == 4  # 2 evidence + 1 hypothesis + 1 assessment

    def test_injected_clock_recorded(self):
        stamp = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        result = run_engine(make_input([make_claim()]), clock=stamp)
        assert result.timestamp == stamp


# ---------------------------------------------------------------------------
# 16. Immutability
# ---------------------------------------------------------------------------


class TestImmutability:
    def test_input_unchanged_after_assessment(self):
        claims = [
            make_claim(identifier="A", target_type="threat_group"),
            make_claim(identifier="A", target_type="threat_group", metadata={"k": [1, 2]}),
        ]
        inp = make_input(claims, context=make_context(risk_level=RiskLevel.HIGH))
        before = inp.model_dump_json()
        run_engine(inp)
        assert inp.model_dump_json() == before

    def test_claim_metadata_not_annotated_in_place(self):
        claim = make_claim(metadata={"note": "hello"})
        inp = make_input([claim])
        run_engine(inp)
        assert "claim_id" not in claim.metadata


# ---------------------------------------------------------------------------
# 17. Secret safety, fail-closed
# ---------------------------------------------------------------------------


class TestSecretSafety:
    def test_sensitive_key_in_metadata_rejected(self):
        claim = make_claim(metadata={"secret_value": "hunter2"})
        with pytest.raises(AttributionSafetyError):
            run_engine(make_input([claim]))

    def test_aws_key_identifier_rejected(self):
        claim = make_claim(metadata={"note": "AKIAIOSFODNN7EXAMPLE"})
        with pytest.raises(AttributionSafetyError):
            run_engine(make_input([claim]))

    def test_openai_style_token_rejected(self):
        claim = make_claim(metadata={"note": "sk-" + "a" * 30})
        with pytest.raises(AttributionSafetyError):
            run_engine(make_input([claim]))

    def test_token_pattern_rejected(self):
        claim = make_claim(metadata={"note": "ghp_" + "a" * 36})
        with pytest.raises(AttributionSafetyError):
            run_engine(make_input([claim]))

    def test_secret_value_never_leaks_into_message(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        claim = make_claim(metadata={"note": secret})
        with pytest.raises(AttributionSafetyError) as exc:
            run_engine(make_input([claim]))
        assert secret not in str(exc.value)

    def test_hash_like_metadata_not_flagged_as_secret(self):
        claim = make_claim(metadata={"sha256": "a" * 64})
        result = run_engine(make_input([claim]))
        assert result.status is AttributionStatus.PARTIALLY_SUPPORTED

    def test_fail_closed_no_partial_result(self):
        claim = make_claim(metadata={"secret_value": "hunter2"})
        with pytest.raises(AttributionSafetyError):
            run_engine(make_input([claim]))


# ---------------------------------------------------------------------------
# 18. Error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    def test_sanitized_engine_error_rejects_wrong_shape(self):
        engine = ThreatAttributionEngine()
        with pytest.raises(InvalidAttributionInputError) as exc:
            engine.assess({"correlation_id": "x"})
        assert "ThreatAttributionInput" in str(exc.value)

    def test_strategy_failure_wrapped_and_chained(self):
        class BrokenStrategy(AttributionStrategy):
            name = "broken"

            def assess(self, input_data, *, timestamp, uuid_factory):
                raise RuntimeError("internal boom")

        engine = ThreatAttributionEngine(strategy=BrokenStrategy())
        with pytest.raises(AttributionStrategyError) as exc:
            engine.assess(make_input([make_claim()]))
        assert isinstance(exc.value.__cause__, RuntimeError)

    def test_strategy_exception_sanitized(self):
        class BrokenStrategy(AttributionStrategy):
            name = "broken"

            def assess(self, input_data, *, timestamp, uuid_factory):
                raise ValueError("raw sensitive payload AKIAIOSFODNN7EXAMPLE")

        engine = ThreatAttributionEngine(strategy=BrokenStrategy())
        with pytest.raises(AttributionStrategyError) as exc:
            engine.assess(make_input([make_claim()]))
        assert "AKIAIOSFODNN7EXAMPLE" not in str(exc.value)

    def test_non_assessment_output_rejected(self):
        class GadgetStrategy(AttributionStrategy):
            name = "gadget"

            def assess(self, input_data, *, timestamp, uuid_factory):
                return object()

        engine = ThreatAttributionEngine(strategy=GadgetStrategy())
        with pytest.raises(AttributionOutputValidationError):
            engine.assess(make_input([make_claim()]))

    def test_contract_invalid_output_rejected(self):
        class TamperStrategy(AttributionStrategy):
            name = "tamper"

            def assess(self, input_data, *, timestamp, uuid_factory):
                bad = AttributionAssessment.model_construct(
                    attribution_assessment_id=uuid.uuid4(),
                    correlation_id=CID,
                    status=AttributionStatus.ATTRIBUTED,
                    hypotheses=[
                        AttributionHypothesis.model_construct(
                            hypothesis_id=uuid.uuid4(),
                            target_type="threat_group",
                            target_identifier="APT29",
                            confidence=0.9,
                            supporting_evidence_ids=[uuid.uuid4()],
                            conflicting_evidence_ids=[],
                            metadata={},
                            provenance="attribution_assessed",
                        )
                    ],
                    evidence=[],
                    metadata={},
                    timestamp=NOW,
                    provenance="attribution_assessed",
                )
                return bad

        engine = ThreatAttributionEngine(strategy=TamperStrategy())
        with pytest.raises(AttributionOutputValidationError):
            engine.assess(make_input([make_claim()]))

    def test_unsupported_unknown_signal_rejected(self):
        claim = make_claim(target_type="unknown")
        with pytest.raises(UnsupportedAttributionSignalError):
            run_engine(make_input([claim]))

    def test_unsupported_signal_dominates_other_signals(self):
        claims = [
            make_claim(target_type="unknown"),
            make_claim(identifier="APT29", target_type="threat_group"),
        ]
        with pytest.raises(UnsupportedAttributionSignalError):
            run_engine(make_input(claims))

    def test_safety_exception_dual_inheritance(self):
        with pytest.raises(AttributionError):
            raise AttributionSafetyError("refusal")
        assert issubclass(AttributionSafetyError, ValueError)


# ---------------------------------------------------------------------------
# 19. Dependency isolation (AST scan)
# ---------------------------------------------------------------------------


class TestDependencyIsolation:
    SERVICE_DIR = pathlib.Path(
        "app/services/threat_attribution"
    )
    FORBIDDEN_ROOTS = [
        "fastapi",
        "sqlalchemy",
        "qdrant",
        "neo4j",
        "kafka",
        "rabbitmq",
        "httpx",
        "requests",
        "subprocess",
        "openai",
        "anthropic",
        "langchain",
        "google",
        "redis",
        "celery",
        "aiohttp",
    ]
    FORBIDDEN_CALLS = ["eval", "exec", "compile"]

    FORBIDDEN_APP_IMPORTS = [
        "app.agents",
        "app.services.risk",
        "app.services.knowledge",
        "app.services.rag",
        "app.services.threat_intel",
        "app.api",
        "app.rag",
    ]

    def _modules(self):
        return sorted(self.SERVICE_DIR.glob("*.py"))

    def test_no_forbidden_external_imports(self):
        for module in self._modules():
            tree = ast.parse(module.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        root = alias.name.split(".")[0]
                        assert root not in self.FORBIDDEN_ROOTS, (
                            f"{module.name} imports forbidden dependency {root}"
                        )
                elif isinstance(node, ast.ImportFrom) and node.module:
                    root = node.module.split(".")[0]
                    assert root not in self.FORBIDDEN_ROOTS, (
                        f"{module.name} imports forbidden dependency {root}"
                    )

    def test_no_dynamic_execution(self):
        for module in self._modules():
            tree = ast.parse(module.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func = node.func
                    name = (
                        func.id
                        if isinstance(func, ast.Name)
                        else func.attr
                        if isinstance(func, ast.Attribute)
                        else None
                    )
                    assert name not in self.FORBIDDEN_CALLS, (
                        f"{module.name} uses forbidden {name}()"
                    )

    def test_no_upstream_pipeline_modules_imported(self):
        for module in self._modules():
            tree = ast.parse(module.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    for root in self.FORBIDDEN_APP_IMPORTS:
                        assert not node.module.startswith(root), (
                            f"{module.name} imports {root}, violating "
                            "dependency isolation and risk/RAG/investigation "
                            "independence"
                        )

    def test_no_llm_rag_or_persistence_tokens(self):
        for module in self._modules():
            tree = ast.parse(module.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    assert "gemini" not in node.module.lower()
                    assert "rag" not in node.module.lower()
                    assert "vector" not in node.module.lower()
                    assert "persist" not in node.module.lower()


# ---------------------------------------------------------------------------
# 20. Performance / bounds behavior
# ---------------------------------------------------------------------------


class TestBoundsAndPerformance:
    def test_full_claim_cap_single_target(self):
        claims = [make_claim() for _ in range(MAX_ATTRIBUTION_EVIDENCE_ITEMS)]
        result = run_engine(make_input(claims))
        assert len(result.evidence) == MAX_ATTRIBUTION_EVIDENCE_ITEMS
        assert len(result.hypotheses) == 1
        assert result.hypotheses[0].confidence == pytest.approx(1.0)

    def test_evidence_cap_not_exceeded(self):
        assert len(run_engine(make_input()).evidence) <= MAX_ATTRIBUTION_EVIDENCE_ITEMS

    def test_hypotheses_cap_not_exceeded(self):
        result = run_engine(
            make_input([make_claim() for _ in range(20)])
        )
        assert len(result.hypotheses) <= MAX_ATTRIBUTION_HYPOTHESES

    def test_large_input_completes(self):
        claims = [
            make_claim(identifier=f"target-{i % 10}", target_type="threat_group")
            for i in range(250)
        ]
        result = run_engine(make_input(claims))
        assert len(result.evidence) == 250
        assert len(result.hypotheses) == 10
        assert result.status is AttributionStatus.CONFLICTING

    def test_confidence_precision_bounded(self):
        for s in range(1, 8):
            for c in range(0, 4):
                value = attribution_confidence(s, c)
                decimals = max(
                    0, len(str(value).split(".")[1]) if "." in str(value) else 0
                )
                assert decimals <= CONFIDENCE_DECIMALS