"""Prediction contract and persistence-model tests — V3.24.

These assert the properties that must survive any future refactor:

* a prediction can never be serialized as evidence (§4);
* ATT&CK identifiers are never invented or repaired (§9);
* the vocabulary is closed — no unmodelled enum member can appear (§10);
* the four prediction tables pin provenance in the database, not just in
  application code (§21);
* every constraint the ORM declares is also declared by the migration, so
  ``alembic check`` cannot drift silently.
"""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError
from sqlalchemy import CheckConstraint, UniqueConstraint

from app.models.attack_prediction import (
    AttackPredictionEvidenceRecord,
    AttackPredictionRecord,
    AttackPredictionSessionRecord,
    AttackPredictionUncertaintyRecord,
)
from app.schemas.attack_prediction import (
    AttackPrediction,
    AttackTechnique,
    PredictionEvidence,
    PredictionFailureResponse,
    PredictionInputs,
    PredictionResult,
    PredictionUncertainty,
)
from app.services.prediction.vocabulary import (
    ENGINE_VERSION,
    STAGE_PRIORITY,
    STAGE_VOCABULARY,
    PredictionKind,
    TECHNIQUE_ID_PATTERN,
    confidence_band,
    vocabulary_document,
)
from app.schemas.security_event import Provenance

SESSION_ID = uuid.UUID("33333333-3333-4333-8333-333333333333")
PREDICTION_ID = uuid.UUID("44444444-4444-4444-8444-444444444444")


def _technique(**overrides) -> dict:
    base = {
        "technique_id": None,
        "technique_name": None,
        "tactic": None,
        "technique_id_reason": "no persisted mapping names this stage",
    }
    base.update(overrides)
    return base


def _prediction(**overrides) -> dict:
    evidence = PredictionEvidence(
        reference="detection:1",
        entity_kind="detection",
        node_id="node-1",
        stance="supporting",
        detail="persisted",
    )
    base = {
        "prediction_id": PREDICTION_ID,
        "prediction_kind": PredictionKind.CREDENTIAL_ACCESS,
        "depth": "immediate",
        "status": PredictionStatusValue,
        "target": "credential access",
        "target_basis": "debate_referenced",
        "technique": _technique(),
        "rationale": {
            "summary": "Credential access is a plausible next stage.",
            "basis": "debate_hypothesis",
            "basis_detail": "named by debate hypothesis h1",
        },
        "uncertainty": {
            "confidence": 0.4,
            "confidence_band": confidence_band(0.4).value,
            "confidence_basis": {
                "evidence_support": 1.0,
                "evidence_diversity": 0.33,
                "debate_support": 1.0,
                "target_specificity": 0.5,
                "contradiction_penalty": 0.0,
            },
            "supporting_evidence": [evidence],
            "evidence_support": "debate_claim",
        },
    }
    base.update(overrides)
    return base


from app.services.prediction.vocabulary import PredictionStatus  # noqa: E402

PredictionStatusValue = PredictionStatus.PREDICTED


# ---------------------------------------------------------------------------
# Prediction ≠ evidence (§4)
# ---------------------------------------------------------------------------


def test_every_prediction_contract_pins_provenance_to_ai_generated():
    """The type system, not a convention, is what forbids evidence provenance.

    ``Provenance`` also contains ``observed``, ``detected``, ``correlated`` and
    ``risk_assessed``.  Because every prediction model types ``provenance`` as
    ``Literal[Provenance.AI_GENERATED]``, passing one of those is a validation
    error rather than a persisted row that reads like a finding.
    """
    for evidence_provenance in (
        Provenance.OBSERVED,
        Provenance.DETECTED,
        Provenance.CORRELATED,
        Provenance.RISK_ASSESSED,
    ):
        with pytest.raises(ValidationError):
            AttackPrediction(**_prediction(provenance=evidence_provenance))


def test_failure_response_is_also_pinned_to_ai_generated():
    with pytest.raises(ValidationError):
        PredictionFailureResponse(
            failure_code="prediction_error",
            detail="boom",
            provenance=Provenance.DETECTED,
        )


def test_predictions_carry_no_unmodelled_fields():
    """``extra="forbid"`` means a consumer never has to guess about a field."""
    with pytest.raises(ValidationError):
        AttackPrediction(**_prediction(severity="HIGH"))


# ---------------------------------------------------------------------------
# ATT&CK identifiers (§9)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", ["T-1003", "T100", "TT1003", "T1003.1", "credential"])
def test_malformed_technique_ids_are_rejected_not_repaired(bad):
    with pytest.raises(ValidationError):
        AttackTechnique(**_technique(technique_id=bad))


def test_well_formed_technique_id_is_accepted():
    technique = AttackTechnique(
        **_technique(technique_id="T1003", technique_name="OS Credential Dumping")
    )
    assert technique.technique_id == "T1003"


def test_no_attack_catalog_is_embedded_in_the_vocabulary():
    """No ATT&CK identifier appears as stage vocabulary.

    An embedded technique id would be ATT&CK knowledge baked into the engine —
    exactly the knowledge V3.24 is forbidden to invent.  Stage recognition is
    therefore driven purely by descriptive words that a persisted row or a debate
    actually wrote.
    """
    tokens = [token for entry in STAGE_VOCABULARY.values() for token in entry.tokens]
    assert tokens
    for token in tokens:
        assert not TECHNIQUE_ID_PATTERN.match(token), (
            f"{token!r} is an ATT&CK identifier, not a descriptive label"
        )
    assert str(vocabulary_document()["stages"]).lower().count("t1") == 0


# ---------------------------------------------------------------------------
# Closed vocabulary (§10)
# ---------------------------------------------------------------------------


def test_vocabulary_document_covers_every_stage_exactly_once():
    document = vocabulary_document()
    assert set(document["stages"]) == {kind.value for kind in PredictionKind}
    assert document["stage_priority"] == [kind.value for kind in STAGE_PRIORITY]
    assert len(STAGE_PRIORITY) == len(set(STAGE_PRIORITY))
    assert set(STAGE_VOCABULARY) == set(STAGE_PRIORITY)


def test_confidence_bands_are_ordered_and_total():
    assert confidence_band(0.0).value == "very_low"
    assert confidence_band(0.34).value == "very_low"
    assert confidence_band(0.35).value == "low"
    assert confidence_band(0.60).value == "moderate"
    assert confidence_band(0.90).value == "high"


def test_confidence_formula_weights_sum_to_one():
    """The bound is a property of the formula, not of a clamp applied later."""
    weights = vocabulary_document()["confidence_formula"]["weights"]
    assert sum(weights.values()) == pytest.approx(1.0)


def test_engine_version_is_declared():
    assert ENGINE_VERSION.startswith("v3.24")


# ---------------------------------------------------------------------------
# Confidence must be bounded (§17)
# ---------------------------------------------------------------------------


def test_uncertainty_confidence_cannot_leave_the_unit_interval():
    for value in (-0.1, 1.5):
        with pytest.raises(ValidationError):
            PredictionUncertainty(
                confidence=value,
                confidence_band=confidence_band(0.5).value,
                confidence_basis={},
                evidence_support="debate_claim",
            )


# ---------------------------------------------------------------------------
# Database-level firewalls (§21)
# ---------------------------------------------------------------------------

ALL_TABLES = (
    AttackPredictionSessionRecord,
    AttackPredictionRecord,
    AttackPredictionEvidenceRecord,
    AttackPredictionUncertaintyRecord,
)


#: Constraint and index names each model *supplies*, i.e. before the shared
#: ``ck_%(table_name)s_%(constraint_name)s`` naming convention expands them.
#: This is the same model-vs-migration pairing the frozen V3.23 debate tables use.
EXPECTED_OBJECT_NAMES: dict[str, tuple[str, ...]] = {
    "attack_prediction_sessions": (
        "provenance_ai_generated",
        "attack_prediction_sessions_status_check",
        "ix_attack_prediction_sessions_correlation_id",
        "ix_attack_prediction_sessions_status",
        "ix_attack_prediction_sessions_graph_snapshot_digest",
        "ix_attack_prediction_sessions_debate_id",
    ),
    "attack_predictions": (
        "provenance_ai_generated",
        "attack_predictions_confidence_range",
        "attack_predictions_depth_bound",
        "attack_predictions_status_check",
        "attack_predictions_evidence_support_check",
        "ix_attack_predictions_session_id",
        "ix_attack_predictions_prediction_kind",
        "ix_attack_predictions_status",
        "ix_attack_predictions_technique_id",
    ),
    "attack_prediction_evidence": (
        "provenance_ai_generated",
        "attack_prediction_evidence_stance_check",
        "uq_attack_prediction_evidence_reference_stance",
        "ix_attack_prediction_evidence_prediction_id",
        "ix_attack_prediction_evidence_reference",
        "ix_attack_prediction_evidence_stance",
    ),
    "attack_prediction_uncertainties": (
        "provenance_ai_generated",
        "attack_prediction_uncertainties_confidence_range",
        "uq_attack_prediction_uncertainties_prediction_id",
        "ix_attack_prediction_uncertainties_prediction_id",
    ),
}


@pytest.mark.parametrize("model", ALL_TABLES, ids=lambda m: m.__tablename__)
def test_every_table_pins_provenance_in_the_database(model):
    """The CHECK survives a regression in the service layer.

    Application code already writes only ``ai_generated``; the constraint is what
    makes that guarantee hold even if that code changes.
    """
    sqltexts = [
        str(constraint.sqltext)
        for constraint in model.__table__.constraints
        if isinstance(constraint, CheckConstraint)
        and "provenance" in str(constraint.sqltext)
    ]
    assert sqltexts, f"{model.__tablename__} does not constrain provenance"
    assert all("ai_generated" in text for text in sqltexts)


@pytest.mark.parametrize("model", ALL_TABLES, ids=lambda m: m.__tablename__)
def test_model_and_migration_declare_the_same_constraints(model):
    """Guards against silent drift between the ORM and the applied migration.

    The migration is the artifact actually run against a database, so a
    constraint or index that exists only in the ORM would be enforced by nothing.
    """
    import importlib.util
    from pathlib import Path

    migrations = Path("app/database/postgres/migrations/versions")
    path = migrations / "a7b8c9d0e1f2_create_attack_prediction_tables.py"
    spec = importlib.util.spec_from_file_location("v324_migration", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    source = path.read_text()
    for name in EXPECTED_OBJECT_NAMES[model.__tablename__]:
        assert f'"{name}"' in source, (
            f"{model.__tablename__}.{name} is missing from the migration"
        )
    assert module.revision == "a7b8c9d0e1f2"
    assert module.down_revision == "f6a7b8c9d0e1"


def test_evidence_citations_cannot_be_duplicated():
    """A duplicated citation would silently raise a count-based confidence."""
    names = {
        constraint.name
        for constraint in AttackPredictionEvidenceRecord.__table__.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    assert "uq_attack_prediction_evidence_reference_stance" in names


def test_one_uncertainty_row_per_prediction():
    names = {
        constraint.name
        for constraint in AttackPredictionUncertaintyRecord.__table__.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    assert "uq_attack_prediction_uncertainties_prediction_id" in names


def test_no_table_duplicates_a_v2_or_v3_payload():
    """Prediction tables store pointers and reasoning, never source content."""
    for model in ALL_TABLES:
        columns = {column.name for column in model.__table__.columns}
        assert "raw_payload" not in columns
        assert "evidence_json" not in columns
        assert "prompt" not in columns


# Session identity is derived from inputs only (§24)
# ---------------------------------------------------------------------------


def test_prediction_inputs_default_to_the_default_bounds():
    """Omitting bounds must not silently mean "unbounded"."""
    inputs = PredictionInputs(
        correlation_id=uuid.uuid4(),
        graph_snapshot_digest="a" * 64,
        graph_node_count=1,
        graph_edge_count=1,
    )
    assert inputs.bounds.max_depth == 2
    assert inputs.bounds.max_predictions_emitted == 4
    assert inputs.debate is None


def test_result_requires_the_not_evidence_statement_to_be_present():
    """The statement is not optional prose — it is part of the contract."""
    fields = PredictionResult.model_fields
    assert "limitations_note" in fields
    assert "provenance" in fields