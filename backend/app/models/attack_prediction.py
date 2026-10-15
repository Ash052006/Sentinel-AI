"""Relational persistence for attack predictions — V3.24.

Four tables record the analytical output of a prediction run.  They store
**references and reasoning text only**: no V2 record, no V3.22 graph row, and no
V3.23 debate row is duplicated or modified here.  A prediction is downstream
analytical state, not evidence.

Idempotency is a database guarantee, not an application convention.
``attack_prediction_sessions.id`` is a deterministic ``uuid5`` over
``(correlation_id, graph_snapshot_digest, debate_id,
prediction_configuration_digest)`` and is the primary key, so re-running the same
prediction over the same inputs collides on the key instead of inserting a
duplicate.  Current time is deliberately not part of that identity.

``attack_predictions.id`` is likewise a deterministic ``uuid5`` over the evidence
that justifies the prediction, so a changed justification produces a *new* row
rather than mutating a recorded conclusion.

The firewall that matters most is enforced here in the database rather than in
application code: every table carries ``provenance`` CHECK-pinned to
``ai_generated``.  A bug that tried to persist a prediction as ``observed``,
``detected``, ``correlated`` or ``risk_assessed`` would fail the constraint, so
"a prediction is never evidence" survives a regression in the service layer.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import (
    JSON,
    CheckConstraint,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.postgres.base import Base, UUIDTimestampMixin

_ID_LENGTH = 64
_DIGEST_LENGTH = 64
_TYPE_LENGTH = 64
_PROVENANCE_LENGTH = 32
_TEXT_LENGTH = 1024

#: Provenance every prediction row is pinned to.
_PREDICTION_PROVENANCE = "ai_generated"


class AttackPredictionSessionRecord(UUIDTimestampMixin, Base):
    """One prediction session, keyed by its deterministic identity."""

    __tablename__ = "attack_prediction_sessions"

    __table_args__ = (
        Index("ix_attack_prediction_sessions_correlation_id", "correlation_id"),
        Index("ix_attack_prediction_sessions_status", "status"),
        Index(
            "ix_attack_prediction_sessions_graph_snapshot_digest",
            "graph_snapshot_digest",
        ),
        Index("ix_attack_prediction_sessions_debate_id", "debate_id"),
        CheckConstraint(
            f"provenance = '{_PREDICTION_PROVENANCE}'",
            name="provenance_ai_generated",
        ),
        CheckConstraint(
            "status IN ('predicted','low_confidence','insufficient_evidence','contested')",
            name="attack_prediction_sessions_status_check",
        ),
    )

    #: The persisted V2 correlation this session predicts for.  Deliberately no
    #: foreign key: a prediction must outlive the state that produced it, and
    #: analytical state is never gated on the evidence lifecycle.
    correlation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        comment="V2 correlation under prediction; a soft reference by design.",
    )

    #: Digest of the exact V3.22 graph snapshot consumed.  Part of the session
    #: identity: new evidence means a new prediction, not a mutated one.
    graph_snapshot_digest: Mapped[str] = mapped_column(
        String(_DIGEST_LENGTH),
        nullable=False,
        comment="SHA-256 of the canonical bounded V3.22 graph that was read.",
    )

    #: Digest of the prediction configuration (bounds + engine version).  Part of
    #: the identity so two differently configured runs never collide.
    prediction_configuration_digest: Mapped[str] = mapped_column(
        String(_DIGEST_LENGTH),
        nullable=False,
        comment="SHA-256 of the bounds and engine version used for this run.",
    )

    #: The V3.23 debate consumed, when one existed.  Nullable because a
    #: prediction is explicitly allowed without a debate; its absence is recorded
    #: as a limitation rather than treated as a failure.
    debate_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        comment="V3.23 debate consumed; NULL when no debate was available.",
    )

    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="insufficient_evidence",
        comment=(
            "Session outcome. 'insufficient_evidence' is a successful outcome, not "
            "an error: declining to speculate is the correct result when no "
            "evidence names a plausible next stage."
        ),
    )

    engine_version: Mapped[str] = mapped_column(
        String(_TYPE_LENGTH), nullable=False, comment="Prediction engine version."
    )

    graph_node_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, comment="Bounded graph nodes consumed."
    )
    graph_edge_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, comment="Bounded graph edges consumed."
    )
    observed_technique_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Persisted ATT&CK techniques found; 0 means none may be asserted.",
    )
    max_depth: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=2,
        comment="Prediction horizon used; architecturally capped at 2.",
    )

    provenance: Mapped[str] = mapped_column(
        String(_PROVENANCE_LENGTH),
        nullable=False,
        default=_PREDICTION_PROVENANCE,
        comment="Always ai_generated: a prediction is analysis, never evidence.",
    )

    session_payload: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        comment=(
            "Canonical JSON document of the completed prediction session. The "
            "normalized child tables (predictions, evidence, uncertainties) are the "
            "queryable and auditable projection of the same write; this column is "
            "the lossless read model so a GET returns exactly what the POST "
            "produced. Contains no prompt text, no API key, and no raw provider "
            "payload, because the engine has no provider."
        ),
    )

    predictions: Mapped[list["AttackPredictionRecord"]] = relationship(
        "AttackPredictionRecord",
        back_populates="session",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class AttackPredictionRecord(UUIDTimestampMixin, Base):
    """One predicted future progression.

    Note what is absent: there is no severity, no outcome, and no status column
    that could be read as a finding.  ``prediction_status`` is a *prediction*
    status (``predicted`` / ``low_confidence`` / ``insufficient_evidence`` /
    ``contested``), which is why it is named to match that vocabulary exactly.
    """

    __tablename__ = "attack_predictions"

    __table_args__ = (
        Index("ix_attack_predictions_session_id", "session_id"),
        Index("ix_attack_predictions_prediction_kind", "prediction_kind"),
        Index("ix_attack_predictions_status", "prediction_status"),
        Index("ix_attack_predictions_technique_id", "technique_id"),
        CheckConstraint(
            f"provenance = '{_PREDICTION_PROVENANCE}'",
            name="provenance_ai_generated",
        ),
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="attack_predictions_confidence_range",
        ),
        CheckConstraint(
            "depth >= 1 AND depth <= 2",
            name="attack_predictions_depth_bound",
        ),
        CheckConstraint(
            "prediction_status IN "
            "('predicted','low_confidence','insufficient_evidence','contested')",
            name="attack_predictions_status_check",
        ),
        CheckConstraint(
            "evidence_support IN ('persisted_evidence','debate_claim','mixed')",
            name="attack_predictions_evidence_support_check",
        ),
    )

    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("attack_prediction_sessions.id", ondelete="CASCADE"),
        nullable=False,
        comment="Owning prediction session.",
    )

    prediction_kind: Mapped[str] = mapped_column(
        String(_TYPE_LENGTH), nullable=False, comment="Closed prediction category."
    )
    depth: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        comment="1 = plausible next stage; 2 = one subsequent stage. Never deeper.",
    )
    prediction_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="Prediction outcome vocabulary; never an evidence state.",
    )

    target: Mapped[str] = mapped_column(
        String(128), nullable=False, comment="Bounded predicted-stage label."
    )
    target_basis: Mapped[str] = mapped_column(
        String(_TYPE_LENGTH),
        nullable=False,
        comment="How the target was identified (persisted / debate / analytical).",
    )
    basis: Mapped[str] = mapped_column(
        String(_TYPE_LENGTH),
        nullable=False,
        comment="Why the candidate was permitted to exist.",
    )

    #: Persisted ATT&CK technique id, or NULL.  NULL is the normal case: no
    #: ATT&CK catalog is embedded, so an id exists only when a persisted detection
    #: supplied one.
    technique_id: Mapped[str | None] = mapped_column(
        String(10),
        nullable=True,
        comment="Persisted ATT&CK technique id; NULL when no mapping supports one.",
    )
    technique_name: Mapped[str | None] = mapped_column(
        String(128), nullable=True, comment="Persisted ATT&CK technique name."
    )
    tactic: Mapped[str | None] = mapped_column(
        String(64), nullable=True, comment="Persisted ATT&CK tactic name."
    )
    technique_id_reason: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
        comment="Why the technique id is present or absent.",
    )

    confidence: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        comment=(
            "Confidence that the proposed future progression is plausible. Not a "
            "risk score, not debate confidence, not agent confidence."
        ),
    )
    confidence_band: Mapped[str] = mapped_column(
        String(16), nullable=False, comment="Discrete band over the confidence value."
    )
    evidence_support: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="Whether support is persisted evidence, a debate claim, or both.",
    )

    rationale_summary: Mapped[str] = mapped_column(
        String(_TEXT_LENGTH), nullable=False, comment="Secret-safe one-line rationale."
    )
    basis_detail: Mapped[str] = mapped_column(
        String(512), nullable=False, comment="Why the recorded basis applies."
    )

    provenance: Mapped[str] = mapped_column(
        String(_PROVENANCE_LENGTH),
        nullable=False,
        default=_PREDICTION_PROVENANCE,
        comment="Always ai_generated: a prediction is analysis, never evidence.",
    )

    prediction_payload: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        comment="Canonical JSON of this prediction as returned by the API.",
    )

    session: Mapped[AttackPredictionSessionRecord] = relationship(
        AttackPredictionSessionRecord, back_populates="predictions"
    )
    evidence: Mapped[list["AttackPredictionEvidenceRecord"]] = relationship(
        "AttackPredictionEvidenceRecord",
        back_populates="prediction",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    uncertainty: Mapped["AttackPredictionUncertaintyRecord | None"] = relationship(
        "AttackPredictionUncertaintyRecord",
        back_populates="prediction",
        cascade="all, delete-orphan",
        lazy="selectin",
        uselist=False,
    )


class AttackPredictionEvidenceRecord(UUIDTimestampMixin, Base):
    """One supporting or contradicting citation for a prediction.

    Stores a **pointer** to a persisted source in the same
    ``{reference, entity_kind, node_id}`` shape V3.23 debates use, plus the
    prediction's own stance.  No source content is copied, so a prediction can
    never be mistaken for holding evidence, and no secret-shaped payload can be
    duplicated into an analytical table.
    """

    __tablename__ = "attack_prediction_evidence"

    __table_args__ = (
        Index("ix_attack_prediction_evidence_prediction_id", "prediction_id"),
        Index("ix_attack_prediction_evidence_reference", "reference"),
        Index("ix_attack_prediction_evidence_stance", "stance"),
        # A citation is identified by what it points at, its owner and its
        # stance.  Enforced in the database so no code path can inflate a
        # prediction's evidence count by re-inserting the same citation — which
        # would silently raise its confidence, since support is a count.
        UniqueConstraint(
            "prediction_id",
            "reference",
            "stance",
            name="uq_attack_prediction_evidence_reference_stance",
        ),
        CheckConstraint(
            f"provenance = '{_PREDICTION_PROVENANCE}'",
            name="provenance_ai_generated",
        ),
        CheckConstraint(
            "stance IN ('supporting','contradicting')",
            name="attack_prediction_evidence_stance_check",
        ),
    )

    prediction_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("attack_predictions.id", ondelete="CASCADE"),
        nullable=False,
        comment="Owning prediction.",
    )
    reference: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        comment="Persisted V2 source reference; a pointer, never source content.",
    )
    entity_kind: Mapped[str] = mapped_column(
        String(64), nullable=False, comment="V3.22 node type of the cited source."
    )
    node_id: Mapped[str] = mapped_column(
        String(128), nullable=False, comment="Deterministic V3.22 graph node id."
    )
    stance: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        comment="supporting or contradicting; contradictions are never suppressed.",
    )
    detail: Mapped[str] = mapped_column(
        String(512), nullable=False, comment="Secret-safe reason this citation matters."
    )
    provenance: Mapped[str] = mapped_column(
        String(_PROVENANCE_LENGTH),
        nullable=False,
        default=_PREDICTION_PROVENANCE,
        comment="Always ai_generated, matching the parent prediction.",
    )

    prediction: Mapped[AttackPredictionRecord] = relationship(
        AttackPredictionRecord, back_populates="evidence"
    )


class AttackPredictionUncertaintyRecord(UUIDTimestampMixin, Base):
    """Explicit uncertainty for one prediction.

    Persisted separately because uncertainty is a first-class analytical output,
    not a comment on a prediction: the confidence breakdown, the contradicting
    evidence count, the recorded gaps and the limitations are all queryable
    without parsing JSON.  This is what makes §12 auditable after the fact.
    """

    __tablename__ = "attack_prediction_uncertainties"

    __table_args__ = (
        Index("ix_attack_prediction_uncertainties_prediction_id", "prediction_id"),
        # One uncertainty per prediction, at the database level.  ``uselist=False``
        # on the relationship only describes the ORM's read shape; without this
        # constraint a second row could exist, leaving the persisted
        # contradicting count ambiguous about which record is authoritative.
        UniqueConstraint(
            "prediction_id",
            name="uq_attack_prediction_uncertainties_prediction_id",
        ),
        CheckConstraint(
            f"provenance = '{_PREDICTION_PROVENANCE}'",
            name="provenance_ai_generated",
        ),
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="attack_prediction_uncertainties_confidence_range",
        ),
    )

    prediction_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("attack_predictions.id", ondelete="CASCADE"),
        nullable=False,
        comment="Owning prediction; one uncertainty row per prediction.",
    )
    confidence: Mapped[float] = mapped_column(
        Float, nullable=False, comment="Bounded prediction confidence."
    )
    confidence_band: Mapped[str] = mapped_column(
        String(16), nullable=False, comment="Discrete confidence band."
    )
    confidence_basis: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        comment="Deterministic component breakdown of the confidence formula.",
    )
    supporting_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, comment="Supporting citation count."
    )
    contradicting_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment=(
            "Contradicting citation count. Recorded explicitly so a prediction "
            "cannot quietly lose its opposition."
        ),
    )
    evidence_gaps: Mapped[list] = mapped_column(
        JSON, nullable=False, default=list, comment="Recorded evidence gaps."
    )
    unresolved_questions: Mapped[list] = mapped_column(
        JSON, nullable=False, default=list, comment="Recorded unresolved questions."
    )
    limitations: Mapped[list] = mapped_column(
        JSON,
        nullable=False,
        default=list,
        comment="Typed limitation records.",
    )
    provenance: Mapped[str] = mapped_column(
        String(_PROVENANCE_LENGTH),
        nullable=False,
        default=_PREDICTION_PROVENANCE,
        comment="Always ai_generated, matching the parent prediction.",
    )

    prediction: Mapped[AttackPredictionRecord] = relationship(
        AttackPredictionRecord, back_populates="uncertainty"
    )


def prediction_row_payloads(result: Any) -> dict[str, list[dict[str, Any]]]:
    """Normalize a :class:`PredictionResult` into per-table row payloads.

    Shared by the persistence service and its tests so the projection has exactly
    one definition.
    """
    predictions: list[dict[str, Any]] = []
    evidence_rows: list[dict[str, Any]] = []
    uncertainty_rows: list[dict[str, Any]] = []

    for prediction in result.predictions:
        predictions.append(
            {
                "prediction_id": prediction.prediction_id,
                "prediction_kind": prediction.prediction_kind.value,
                "depth": prediction.depth.depth,
                "prediction_status": prediction.status.value.lower(),
                "target": prediction.target,
                "target_basis": prediction.target_basis.value,
                "basis": prediction.rationale.basis.value,
                "technique_id": prediction.technique.technique_id,
                "technique_name": prediction.technique.technique_name,
                "tactic": prediction.technique.tactic,
                "technique_id_reason": prediction.technique.technique_id_reason,
                "confidence": prediction.uncertainty.confidence,
                "confidence_band": prediction.uncertainty.confidence_band.value,
                "evidence_support": prediction.uncertainty.evidence_support.value,
                "rationale_summary": prediction.rationale.summary,
                "basis_detail": prediction.rationale.basis_detail,
                "prediction_payload": prediction.model_dump(mode="json"),
            }
        )
        for item in [
            *prediction.uncertainty.supporting_evidence,
            *prediction.uncertainty.contradicting_evidence,
        ]:
            evidence_rows.append(
                {
                    "prediction_id": prediction.prediction_id,
                    "reference": item.reference,
                    "entity_kind": item.entity_kind,
                    "node_id": item.node_id,
                    "stance": item.stance.value,
                    "detail": item.detail,
                }
            )
        uncertainty_rows.append(
            {
                "prediction_id": prediction.prediction_id,
                "confidence": prediction.uncertainty.confidence,
                "confidence_band": prediction.uncertainty.confidence_band.value,
                "confidence_basis": {
                    key.value: value
                    for key, value in prediction.uncertainty.confidence_basis.items()
                },
                "supporting_count": len(prediction.uncertainty.supporting_evidence),
                "contradicting_count": len(prediction.uncertainty.contradicting_evidence),
                "evidence_gaps": list(prediction.uncertainty.evidence_gaps),
                "unresolved_questions": list(
                    prediction.uncertainty.unresolved_questions
                ),
                "limitations": [
                    item.model_dump(mode="json") for item in prediction.uncertainty.limitations
                ],
            }
        )

    return {
        "predictions": predictions,
        "evidence": evidence_rows,
        "uncertainties": uncertainty_rows,
    }


__all__ = [
    "AttackPredictionEvidenceRecord",
    "AttackPredictionRecord",
    "AttackPredictionSessionRecord",
    "AttackPredictionUncertaintyRecord",
    "prediction_row_payloads",
]