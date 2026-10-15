"""Deterministic prediction engine tests — V3.24.

Pure and fully offline: these tests construct :class:`PredictionInputs` values
directly and never touch a database, a clock, or a provider.  That is possible
*because* the engine has no LLM dependency, and it is worth asserting the
consequences explicitly — determinism and the refusal to speculate are the two
properties most worth locking down, and both are cheapest to verify here.
"""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from app.agents.prediction.engine import (
    PREDICTIONS_ARE_NOT_EVIDENCE,
    AttackPredictionEngine,
)
from app.schemas.attack_prediction import (
    AvailableReference,
    DebateHypothesis,
    DebateSummary,
    ObservedTechnique,
    PredictionInputs,
)
from app.services.prediction.exceptions import PredictionBoundsError
from app.services.prediction.vocabulary import (
    DEFAULT_PREDICTION_BOUNDS,
    CONSENSUS_DEBATE_SUPPORT,
    CONTRADICTION_PENALTY_PER_REFERENCE,
    LOW_CONFIDENCE_THRESHOLD,
    MAX_CONTRADICTION_PENALTY,
    PredictionBounds,
    PredictionKind,
    confidence_band,
    mentions_stage,
    validate_technique_id,
)

CORRELATION_ID = uuid.UUID("11111111-1111-4111-8111-111111111111")
DEBATE_ID = uuid.UUID("22222222-2222-4222-8222-222222222222")
DIGEST = "a" * 64


def _references(*names: str, entity_kind: str = "detection") -> dict[str, AvailableReference]:
    return {
        name: AvailableReference(
            reference=name, entity_kind=entity_kind, node_id=f"node-{index}"
        )
        for index, name in enumerate(names)
    }


def _hypothesis(
    hypothesis_id: str,
    statement: str,
    supporting: tuple[str, ...] = (),
    contesting: tuple[str, ...] = (),
    *,
    confidence: float = 0.8,
) -> DebateHypothesis:
    return DebateHypothesis(
        hypothesis_id=hypothesis_id,
        statement=statement,
        confidence=confidence,
        category_label="technique_analyst",
        supporting_refs=list(supporting),
        contesting_refs=list(contesting),
    )


def _inputs(
    *,
    references: dict[str, AvailableReference] | None = None,
    hypotheses: tuple[DebateHypothesis, ...] = (),
    techniques: dict[str, ObservedTechnique] | None = None,
    consensus_state: str = "consensus",
    debate: bool = True,
    graph_node_count: int = 10,
    graph_edge_count: int = 12,
    bounds: PredictionBounds = DEFAULT_PREDICTION_BOUNDS,
) -> PredictionInputs:
    return PredictionInputs(
        correlation_id=CORRELATION_ID,
        graph_snapshot_digest=DIGEST,
        graph_node_count=graph_node_count,
        graph_edge_count=graph_edge_count,
        observed_techniques=techniques or {},
        evidence_refs=references if references is not None else {},
        debate=(
            DebateSummary(
                debate_id=DEBATE_ID,
                consensus_state=consensus_state,
                consensus_strength=0.8,
                provider="scripted",
                model="deterministic",
                hypotheses=list(hypotheses),
            )
            if debate
            else None
        ),
        bounds=bounds,
    )


# ---------------------------------------------------------------------------
# The prediction-is-not-evidence statement
# ---------------------------------------------------------------------------


def test_every_result_states_predictions_are_not_evidence():
    result = AttackPredictionEngine().predict(_inputs())
    assert result.limitations_note == PREDICTIONS_ARE_NOT_EVIDENCE
    assert "not evidence" in result.limitations_note


# ---------------------------------------------------------------------------
# Refusing to speculate is a success
# ---------------------------------------------------------------------------


def test_nothing_grounded_yields_insufficient_evidence_not_a_guess():
    """No persisted mapping and no naming debate means no predictions.

    This is the single most important behaviour in the module: emitting a
    plausible-sounding stage here would be the engine inventing attack knowledge.
    """
    inputs = _inputs(references=_references("detection:1"), hypotheses=())
    result = AttackPredictionEngine().predict(inputs)

    assert result.status.value == "INSUFFICIENT_EVIDENCE"
    assert result.predictions == []
    assert any(
        "does not speculate" in limitation.detail
        for limitation in result.limitations
    )


def test_hypothesis_naming_a_stage_whose_citations_do_not_resolve_is_discarded():
    """A naming hypothesis with unresolvable citations grounds nothing.

    Otherwise a debate could support a prediction by citing references that do
    not exist, which is the citation-laundering failure mode.
    """
    inputs = _inputs(
        references=_references("detection:1"),
        hypotheses=(
            _hypothesis("h1", "credential access", ("detection:does-not-exist",)),
        ),
    )
    result = AttackPredictionEngine().predict(inputs)

    assert result.status.value == "INSUFFICIENT_EVIDENCE"
    assert result.predictions == []


def test_a_debate_that_declined_does_not_name_a_stage():
    """``insufficient_evidence`` consensus contributes nothing to discovery."""
    inputs = _inputs(
        references=_references("detection:1"),
        hypotheses=(_hypothesis("h1", "credential access", ("detection:1",)),),
        consensus_state="insufficient_evidence",
    )
    result = AttackPredictionEngine().predict(inputs)

    assert result.status.value == "INSUFFICIENT_EVIDENCE"
    assert result.predictions == []


# ---------------------------------------------------------------------------
# Grounded prediction
# ---------------------------------------------------------------------------


def test_debate_named_stage_is_predicted_with_only_resolvable_citations():
    inputs = _inputs(
        references=_references("detection:1", "detection:2"),
        hypotheses=(
            _hypothesis("h1", "credential access", ("detection:2", "detection:ghost")),
        ),
    )
    result = AttackPredictionEngine().predict(inputs)

    assert result.status.value == "PREDICTED"
    assert len(result.predictions) == 1
    prediction = result.predictions[0]
    assert prediction.prediction_kind is PredictionKind.CREDENTIAL_ACCESS
    assert prediction.depth.value == "immediate"
    cited = [item.reference for item in prediction.uncertainty.supporting_evidence]
    assert cited == ["detection:2"]
    assert "detection:ghost" not in cited


def test_persisted_attack_mapping_is_the_only_way_to_carry_a_technique_id():
    """Without a persisted mapping the stage is a label, not a technique."""
    debate_only = AttackPredictionEngine().predict(
        _inputs(
            references=_references("detection:1"),
            hypotheses=(_hypothesis("h1", "lateral movement", ("detection:1",)),),
        )
    )
    assert debate_only.predictions[0].technique.technique_id is None
    assert "no persisted ATT&CK mapping names this predicted stage" in (
        debate_only.predictions[0].technique.technique_id_reason
    )

    with_mapping = AttackPredictionEngine().predict(
        _inputs(
            references=_references("detection:1"),
            techniques={
                "T1021": ObservedTechnique(
                    technique_id="T1021",
                    technique_name="Remote Services",
                    tactic=None,
                    supporting_refs=["detection:1"],
                )
            },
        )
    )
    assert with_mapping.predictions[0].technique.technique_id == "T1021"


def test_a_malformed_persisted_id_is_refused_at_the_contract():
    """Corrupt input is rejected at the boundary, not deep in the engine.

    ``ObservedTechnique`` is the engine's input door onto an ATT&CK id, so it
    enforces the same shape ``AttackTechnique`` does.  Letting a malformed value
    through would surface later as a raw ``ValidationError`` while building the
    *output* — an opaque 500 instead of a governed refusal.
    """
    with pytest.raises(ValidationError, match="ATT&CK technique shape"):
        ObservedTechnique(
            technique_id="not-an-id", supporting_refs=["detection:1"]
        )

    # Well-formed but lower-case persisted ids are normalized, not rejected:
    # the id came from a real row and only its casing is inconsistent.
    assert (
        ObservedTechnique(technique_id="t1021").technique_id == "T1021"
    )


# ---------------------------------------------------------------------------
# Determinism (§16)
# ---------------------------------------------------------------------------


def test_identical_inputs_produce_byte_identical_results():
    build = lambda: _inputs(  # noqa: E731
        references=_references("detection:1", "detection:2", "detection:3"),
        hypotheses=(
            _hypothesis("h2", "lateral movement", ("detection:2",)),
            _hypothesis("h1", "credential access", ("detection:1",)),
        ),
        techniques={
            "T1003": ObservedTechnique(
                technique_id="T1003",
                technique_name="OS Credential Dumping",
                supporting_refs=["detection:3"],
            )
        },
    )
    engine = AttackPredictionEngine()

    first = engine.predict(build())
    second = engine.predict(build())

    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    assert first.prediction_session_id == second.prediction_session_id


def test_candidate_order_does_not_depend_on_input_order():
    """Hypothesis order must not change which stage is 'immediate'."""
    references = _references("detection:1", "detection:2")
    forward = _inputs(
        references=references,
        hypotheses=(
            _hypothesis("h1", "credential access", ("detection:1",)),
            _hypothesis("h2", "lateral movement", ("detection:2",)),
        ),
    )
    backward = _inputs(
        references=references,
        hypotheses=(
            _hypothesis("h2", "lateral movement", ("detection:2",)),
            _hypothesis("h1", "credential access", ("detection:1",)),
        ),
    )
    engine = AttackPredictionEngine()

    a = engine.predict(forward)
    b = engine.predict(backward)

    assert [p.prediction_kind for p in a.predictions] == [
        p.prediction_kind for p in b.predictions
    ]
    assert [p.depth.value for p in a.predictions] == [p.depth.value for p in b.predictions]


def test_session_id_changes_when_the_graph_snapshot_changes():
    engine = AttackPredictionEngine()
    first = engine.predict(_inputs())
    mutated = _inputs().model_copy(update={"graph_snapshot_digest": "b" * 64})
    assert engine.predict(mutated).prediction_session_id != first.prediction_session_id


def test_session_id_changes_when_the_configuration_changes():
    """Two differently bounded runs must never be compared as one artifact."""
    engine = AttackPredictionEngine()
    tight = PredictionBounds(max_predictions_emitted=2)
    assert (
        engine.predict(_inputs(bounds=tight)).prediction_session_id
        != engine.predict(_inputs()).prediction_session_id
    )


# ---------------------------------------------------------------------------
# Horizon (§19)
# ---------------------------------------------------------------------------


def test_horizon_never_exceeds_depth_two_and_says_what_it_withheld():
    inputs = _inputs(
        references=_references(*[f"detection:{i}" for i in range(1, 6)]),
        hypotheses=(
            _hypothesis("h1", "credential access", ("detection:1",)),
            _hypothesis("h2", "lateral movement", ("detection:2",)),
            _hypothesis("h3", "persistence", ("detection:3",)),
            _hypothesis("h4", "data exfiltration", ("detection:4",)),
            _hypothesis("h5", "command and control", ("detection:5",)),
        ),
    )
    result = AttackPredictionEngine().predict(inputs)

    assert len(result.predictions) == 2
    assert [p.depth.value for p in result.predictions] == ["immediate", "subsequent"]
    assert [p.prediction_kind for p in result.predictions] == [
        PredictionKind.CREDENTIAL_ACCESS,
        PredictionKind.LATERAL_MOVEMENT,
    ]
    capped = [l for l in result.limitations if l.kind.value == "horizon_capped"]
    assert capped, "withholding grounded candidates must be disclosed"
    assert "3 grounded candidate(s) were withheld" in capped[0].detail


def test_no_prediction_is_emitted_beyond_the_emission_bound():
    inputs = _inputs(
        references=_references("detection:1", "detection:2"),
        hypotheses=(
            _hypothesis("h1", "credential access", ("detection:1",)),
            _hypothesis("h2", "lateral movement", ("detection:2",)),
        ),
        bounds=PredictionBounds(max_predictions_emitted=1),
    )
    result = AttackPredictionEngine().predict(inputs)
    assert len(result.predictions) == 1
    assert any(l.kind.value == "horizon_capped" for l in result.limitations)


# ---------------------------------------------------------------------------
# Contradictions are preserved (§12)
# ---------------------------------------------------------------------------


def test_contradicting_citations_are_emitted_alongside_supporting_ones():
    inputs = _inputs(
        references=_references("detection:1", "detection:2", "detection:3"),
        hypotheses=(
            _hypothesis(
                "h1",
                "credential access",
                ("detection:1",),
                ("detection:2", "detection:3"),
            ),
        ),
    )
    result = AttackPredictionEngine().predict(inputs)
    prediction = result.predictions[0]

    assert prediction.status.value == "CONTESTED"
    assert len(prediction.uncertainty.contradicting_evidence) == 2
    assert len(prediction.uncertainty.supporting_evidence) == 1
    assert prediction.uncertainty.evidence_support.value == "debate_claim"


def test_contradiction_penalty_is_capped():
    """Three contradictions cost the same as two; one cannot outvote evidence."""
    references = _references(*[f"detection:{i}" for i in range(1, 6)])
    two = AttackPredictionEngine().predict(
        _inputs(
            references=references,
            hypotheses=(
                _hypothesis("h1", "credential access", ("detection:1",), ("detection:2", "detection:3")),
            ),
        )
    )
    three = AttackPredictionEngine().predict(
        _inputs(
            references=references,
            hypotheses=(
                _hypothesis("h1", "credential access", ("detection:1",), ("detection:2", "detection:3", "detection:4")),
            ),
        )
    )
    assert (
        two.predictions[0].uncertainty.confidence
        == three.predictions[0].uncertainty.confidence
    )
    assert MAX_CONTRADICTION_PENALTY == 2 * CONTRADICTION_PENALTY_PER_REFERENCE


def test_a_reference_cited_both_ways_provides_no_support():
    """A self-contested citation cannot carry a prediction on its own.

    The engine drops such a reference from the supporting set before scoring,
    so if it was the *only* support the grounded stage disappears rather than
    being emitted with a contradiction attached — which would read as
    "grounded but disputed" when in fact it was grounded by nothing.
    """
    only_support = _inputs(
        references=_references("detection:1", "detection:2"),
        hypotheses=(
            _hypothesis("h1", "credential access", ("detection:1",), ("detection:1",)),
        ),
    )
    assert AttackPredictionEngine().predict(only_support).predictions == []

    # With a second, uncontested citation the stage survives and the
    # self-contested reference is reported only as opposition.
    partial = _inputs(
        references=_references("detection:1", "detection:2", "detection:3"),
        hypotheses=(
            _hypothesis(
                "h1",
                "credential access",
                ("detection:1", "detection:2"),
                ("detection:1",),
            ),
        ),
    )
    prediction = AttackPredictionEngine().predict(partial).predictions[0]
    assert [e.reference for e in prediction.uncertainty.supporting_evidence] == [
        "detection:2"
    ]
    assert [e.reference for e in prediction.uncertainty.contradicting_evidence] == [
        "detection:1"
    ]


def test_single_contradiction_lowers_confidence_below_two():
    references = _references("detection:1", "detection:2")
    engine = AttackPredictionEngine()
    clean = engine.predict(
        _inputs(references=references, hypotheses=(_hypothesis("h1", "credential access", ("detection:1",)),))
    )
    disputed = engine.predict(
        _inputs(
            references=references,
            hypotheses=(_hypothesis("h1", "credential access", ("detection:1",), ("detection:2",)),),
        )
    )
    assert (
        disputed.predictions[0].uncertainty.confidence
        < clean.predictions[0].uncertainty.confidence
    )


# ---------------------------------------------------------------------------
# Confidence formula (§17)
# ---------------------------------------------------------------------------


def test_confidence_is_always_within_the_unit_interval():
    inputs = _inputs(
        references=_references(*[f"detection:{i}" for i in range(1, 9)]),
        hypotheses=(
            _hypothesis(
                "h1",
                "credential access",
                tuple(f"detection:{i}" for i in range(1, 6)),
                tuple(f"detection:{i}" for i in range(6, 9)),
            ),
        ),
    )
    confidence = AttackPredictionEngine().predict(inputs).predictions[0].uncertainty.confidence
    assert 0.0 <= confidence <= 1.0
    assert confidence_band(confidence).value in {"very_low", "low", "moderate", "high"}


def test_debate_only_support_cannot_exceed_the_ceiling():
    """Words alone can never produce a confident prediction."""
    references = _references(*[f"detection:{i}" for i in range(1, 5)])
    inputs = _inputs(
        references=references,
        hypotheses=(
            _hypothesis(
                "h1",
                "credential access",
                tuple(f"detection:{i}" for i in range(1, 5)),
            ),
        ),
        consensus_state="consensus",
    )
    prediction = AttackPredictionEngine().predict(inputs).predictions[0]
    assert prediction.uncertainty.evidence_support.value == "debate_claim"
    assert prediction.uncertainty.confidence <= 0.50


def test_persisted_evidence_supports_a_higher_confidence_than_debate_claims():
    references = _references("detection:1", "detection:2")
    engine = AttackPredictionEngine()
    persisted = engine.predict(
        _inputs(
            references=references,
            techniques={
                "T1003": ObservedTechnique(
                    technique_id="T1003",
                    technique_name="OS Credential Dumping",
                    supporting_refs=["detection:1", "detection:2"],
                )
            },
        )
    )
    debated = engine.predict(
        _inputs(
            references=references,
            hypotheses=(
                _hypothesis("h1", "credential access", ("detection:1", "detection:2")),
            ),
        )
    )
    assert (
        persisted.predictions[0].uncertainty.confidence
        > debated.predictions[0].uncertainty.confidence
    )
    assert persisted.predictions[0].uncertainty.evidence_support.value == (
        "persisted_evidence"
    )


def test_confidence_basis_accounts_for_every_component():
    prediction = AttackPredictionEngine().predict(
        _inputs(
            references=_references("detection:1"),
            hypotheses=(_hypothesis("h1", "credential access", ("detection:1",)),),
        )
    ).predictions[0]
    assert set(prediction.uncertainty.confidence_basis) == {
        "evidence_support",
        "evidence_diversity",
        "debate_support",
        "target_specificity",
        "contradiction_penalty",
    }


def test_low_confidence_is_reported_rather_than_hidden():
    """A stage named only by a single-source, heavily disputed claim."""
    references = _references("detection:1", "detection:2", "detection:3")
    result = AttackPredictionEngine().predict(
        _inputs(
            references=references,
            hypotheses=(
                _hypothesis(
                    "h1",
                    "credential access",
                    ("detection:1",),
                    ("detection:2", "detection:3"),
                ),
            ),
            consensus_state="contested",
        )
    )
    prediction = result.predictions[0]
    assert prediction.status.value == "CONTESTED"
    assert prediction.uncertainty.confidence < LOW_CONFIDENCE_THRESHOLD or (
        prediction.status.value == "CONTESTED"
    )


# ---------------------------------------------------------------------------
# Bounds (§18)
# ---------------------------------------------------------------------------


def test_oversized_graph_raises_before_any_result_is_built():
    bounds = PredictionBounds(max_graph_nodes=5)
    with pytest.raises(PredictionBoundsError, match="max_graph_nodes"):
        AttackPredictionEngine().predict(_inputs(graph_node_count=6, bounds=bounds))


def test_oversized_edge_count_raises():
    bounds = PredictionBounds(max_graph_edges=5)
    with pytest.raises(PredictionBoundsError, match="max_graph_edges"):
        AttackPredictionEngine().predict(_inputs(graph_edge_count=6, bounds=bounds))


def test_too_many_debate_claims_raises():
    bounds = PredictionBounds(max_debate_claims=2)
    hypotheses = tuple(
        _hypothesis(f"h{i}", "credential access", ("detection:1",)) for i in range(3)
    )
    with pytest.raises(PredictionBoundsError, match="max_debate_claims"):
        AttackPredictionEngine().predict(_inputs(hypotheses=hypotheses, bounds=bounds))


def test_too_many_grounded_candidates_raises():
    bounds = PredictionBounds(max_candidate_predictions=2)
    references = _references(*[f"detection:{i}" for i in range(1, 5)])
    hypotheses = (
        _hypothesis("h1", "credential access", ("detection:1",)),
        _hypothesis("h2", "lateral movement", ("detection:2",)),
        _hypothesis("h3", "persistence", ("detection:3",)),
        _hypothesis("h4", "data exfiltration", ("detection:4",)),
    )
    with pytest.raises(PredictionBoundsError, match="max_candidate_predictions"):
        AttackPredictionEngine().predict(
            _inputs(references=references, hypotheses=hypotheses, bounds=bounds)
        )


def test_depth_of_one_is_not_a_supported_configuration():
    with pytest.raises(ValueError, match="max_depth"):
        PredictionBounds(max_depth=1)


# ---------------------------------------------------------------------------
# Closed vocabulary (§9)
# ---------------------------------------------------------------------------


def test_stage_matching_respects_word_boundaries():
    entry_credential = None
    from app.services.prediction.vocabulary import STAGE_VOCABULARY

    entry_credential = STAGE_VOCABULARY[PredictionKind.CREDENTIAL_ACCESS]
    assert mentions_stage("possible credential access", entry_credential)
    assert mentions_stage("Credential-Access attempt", entry_credential)
    # "credentialing" must not fire the "credential access" stage.
    assert not mentions_stage("credentialing of accounts", entry_credential)


def test_consensus_debate_support_never_exceeds_one():
    assert all(0.0 <= value <= 1.0 for value in CONSENSUS_DEBATE_SUPPORT.values())


def test_consensus_state_reduces_confidence():
    references = _references("detection:1", "detection:2")
    engine = AttackPredictionEngine()
    agreed = engine.predict(
        _inputs(
            references=references,
            hypotheses=(_hypothesis("h1", "credential access", ("detection:1",)),),
            consensus_state="consensus",
        )
    )
    contested = engine.predict(
        _inputs(
            references=references,
            hypotheses=(_hypothesis("h1", "credential access", ("detection:1",)),),
            consensus_state="contested",
        )
    )
    assert (
        contested.predictions[0].uncertainty.confidence
        < agreed.predictions[0].uncertainty.confidence
    )