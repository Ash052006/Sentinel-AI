"""Relational persistence for proposed playbooks — V3.25.

Four tables record a *proposal*: the session, its ordered steps, the actions
within them, and the evidence each action cites.  They store references and
reasoning text only.  No V2 record, V3.22 graph row, V3.23 debate row or V3.24
prediction row is duplicated or modified here, so a playbook cannot become a
shadow copy of the evidence it was derived from.

Two properties are enforced by the database rather than by convention, because
both are load-bearing safety guarantees that a service-layer bug must not be able
to undo.

**A proposal can never be recorded as work performed.**  Every table pins
``provenance`` to ``ai_generated``, and — the stronger control —
``playbook_actions`` pins ``lifecycle`` to the two states generation may produce.
There is no column anywhere in this schema for an execution outcome, a result, or
an approval timestamp, so "this playbook was approved and executed" cannot be
represented, let alone inferred.  Downstream approval and execution live in the
existing ``approval_requests`` and ``soar_executions`` tables, which is where they
belong.

**Idempotency is a database guarantee.**  ``playbook_sessions.id`` is a
deterministic ``uuid5`` over ``(correlation_id, graph_snapshot_digest, debate_id,
prediction_session_id, playbook_configuration_digest)``, so re-generating over
unchanged inputs collides on the primary key instead of inserting a second
proposal.  Current time is deliberately excluded from that identity: a proposal is
a function of its inputs, not of when it was made.

``playbook_actions.id`` is a deterministic ``uuid5`` over what the action *is*,
and ``playbook_action_evidence`` carries a uniqueness constraint over
``(action_id, reference, stance)``.  Together they mean a proposal cannot
accumulate duplicate citations to inflate its own evidence count — which matters
here because evidence support is a direct term in the confidence formula.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
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

_TYPE_LENGTH = 64
_PROVENANCE_LENGTH = 32
_DIGEST_LENGTH = 64
_LINE_LENGTH = 512
_TEXT_LENGTH = 1024

#: Provenance every playbook row is pinned to.
_PLAYBOOK_PROVENANCE = "ai_generated"

#: The only lifecycles generation may persist.  Mirrors
#: :data:`app.services.playbook.vocabulary.GENERATED_LIFECYCLES`.
_GENERATED_LIFECYCLE_VALUES = ("proposed", "approval_required")

#: Status vocabulary, checked rather than free text.
_STATUS_VALUES = ("proposed", "insufficient_evidence", "contested")


class PlaybookSessionRecord(UUIDTimestampMixin, Base):
    """One generated playbook, keyed by its deterministic identity."""

    __tablename__ = "playbook_sessions"

    __table_args__ = (
        Index("ix_playbook_sessions_correlation_id", "correlation_id"),
        Index("ix_playbook_sessions_status", "status"),
        Index("ix_playbook_sessions_lifecycle", "lifecycle"),
        Index(
            "ix_playbook_sessions_graph_snapshot_digest",
            "graph_snapshot_digest",
        ),
        Index("ix_playbook_sessions_prediction_session_id", "prediction_session_id"),
        CheckConstraint(
            f"provenance = '{_PLAYBOOK_PROVENANCE}'",
            name="provenance_ai_generated",
        ),
        CheckConstraint(
            f"lifecycle IN {_GENERATED_LIFECYCLE_VALUES}",
            name="playbook_sessions_lifecycle_check",
        ),
        CheckConstraint(
            f"status IN {_STATUS_VALUES}",
            name="playbook_sessions_status_check",
        ),
    )

    #: The V2 correlation this proposal addresses.  Deliberately no foreign key: a
    #: proposal must outlive the state that produced it.
    correlation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        comment="V2 correlation addressed; a soft reference by design.",
    )

    graph_snapshot_digest: Mapped[str] = mapped_column(
        String(_DIGEST_LENGTH),
        nullable=False,
        comment="SHA-256 of the canonical bounded V3.22 graph that was read.",
    )

    playbook_configuration_digest: Mapped[str] = mapped_column(
        String(_DIGEST_LENGTH),
        nullable=False,
        comment="SHA-256 of the bounds and engine version used for this run.",
    )

    debate_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        comment="V3.23 debate consumed; NULL when none was available.",
    )

    prediction_session_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        comment="V3.24 prediction session consumed; NULL when none was available.",
    )

    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="proposed",
        comment=(
            "Session outcome. 'insufficient_evidence' is a successful outcome, not "
            "an error: declining to propose is correct when no persisted evidence "
            "resolves to an addressable target."
        ),
    )

    lifecycle: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="proposed",
        comment=(
            "Only 'proposed' and 'approval_required' are permitted. Approved, "
            "executing, executed and verified are structurally unrepresentable "
            "here; those states belong to the approval and response subsystems."
        ),
    )

    engine_version: Mapped[str] = mapped_column(
        String(_TYPE_LENGTH), nullable=False, comment="Playbook engine version."
    )

    action_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, comment="Actions proposed in this run."
    )
    step_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, comment="Ordered steps in this run."
    )
    approval_required_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Actions the frozen table classifies as approval_required.",
    )
    not_executable_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment=(
            "Actions with no execution path today. Recorded explicitly so a "
            "proposal is never mistaken for an executable plan."
        ),
    )
    confidence: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
        comment=(
            "Mean confidence of the proposed actions: how well supported the "
            "proposal is. Not execution probability, not risk, not prediction "
            "confidence."
        ),
    )
    graph_node_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, comment="Bounded graph nodes consumed."
    )
    graph_edge_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, comment="Bounded graph edges consumed."
    )
    target_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Indicator values that passed structural target validation.",
    )

    provenance: Mapped[str] = mapped_column(
        String(_PROVENANCE_LENGTH),
        nullable=False,
        default=_PLAYBOOK_PROVENANCE,
        comment="Always ai_generated: a proposal is neither evidence nor a finding.",
    )

    playbook_payload: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        comment=(
            "Canonical JSON document of the completed run. The normalized child "
            "tables are the queryable projection of the same write; this column is "
            "the lossless read model, so a GET returns exactly what the POST "
            "produced. Contains no prompt text, no API key, no provider payload and "
            "no source record content."
        ),
    )

    steps: Mapped[list["PlaybookStepRecord"]] = relationship(
        "PlaybookStepRecord",
        back_populates="session",
        cascade="all, delete-orphan",
        lazy="selectin",
        order_by="PlaybookStepRecord.step_number",
    )


class PlaybookStepRecord(UUIDTimestampMixin, Base):
    """One ordered phase of a proposed playbook."""

    __tablename__ = "playbook_steps"

    __table_args__ = (
        Index("ix_playbook_steps_session_id", "session_id"),
        Index("ix_playbook_steps_step_number", "step_number"),
        UniqueConstraint(
            "session_id",
            "step_number",
            name="uq_playbook_steps_session_step_number",
        ),
        CheckConstraint(
            f"provenance = '{_PLAYBOOK_PROVENANCE}'",
            name="provenance_ai_generated",
        ),
        CheckConstraint(
            "step_number >= 1 AND step_number <= 64",
            name="playbook_steps_step_number_bound",
        ),
    )

    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("playbook_sessions.id", ondelete="CASCADE"),
        nullable=False,
        comment="Owning playbook session.",
    )
    step_number: Mapped[int] = mapped_column(
        Integer, nullable=False, comment="1-based position in the proposed sequence."
    )
    name: Mapped[str] = mapped_column(
        String(128), nullable=False, comment="Bounded step name from the closed set."
    )
    purpose: Mapped[str] = mapped_column(
        String(_LINE_LENGTH), nullable=False, comment="Why this phase comes first."
    )
    depends_on_steps: Mapped[list] = mapped_column(
        JSON,
        nullable=False,
        default=list,
        comment="Preceding step numbers, derived from the action dependency edges.",
    )

    provenance: Mapped[str] = mapped_column(
        String(_PROVENANCE_LENGTH),
        nullable=False,
        default=_PLAYBOOK_PROVENANCE,
        comment="Always ai_generated, matching the parent session.",
    )

    session: Mapped[PlaybookSessionRecord] = relationship(
        PlaybookSessionRecord, back_populates="steps"
    )
    actions: Mapped[list["PlaybookActionRecord"]] = relationship(
        "PlaybookActionRecord",
        back_populates="step",
        cascade="all, delete-orphan",
        lazy="selectin",
        order_by="PlaybookActionRecord.position",
    )


class PlaybookActionRecord(UUIDTimestampMixin, Base):
    """One proposed response action.

    Note the columns that are *not* here.  There is no ``status``, no ``result``,
    no ``outcome``, no ``executed_at``, and no approval reference.  Every column
    describes a proposal and its justification, which is why this table cannot be
    read — by anyone, in any query — as a record that a response occurred.
    """

    __tablename__ = "playbook_actions"

    __table_args__ = (
        Index("ix_playbook_actions_session_id", "session_id"),
        Index("ix_playbook_actions_step_id", "step_id"),
        Index("ix_playbook_actions_action", "action"),
        Index("ix_playbook_actions_capability", "capability"),
        Index("ix_playbook_actions_target_reference", "target_reference"),
        UniqueConstraint(
            "session_id",
            "action_id",
            name="uq_playbook_actions_session_action_id",
        ),
        CheckConstraint(
            f"provenance = '{_PLAYBOOK_PROVENANCE}'",
            name="provenance_ai_generated",
        ),
        CheckConstraint(
            "capability IN ('available','unavailable')",
            name="playbook_actions_capability_check",
        ),
        CheckConstraint(
            "execution_backend IN ('mock_sandbox','none')",
            name="playbook_actions_execution_backend_check",
        ),
        CheckConstraint(
            "approval_requirement IN "
            "('no_approval','approval_required','not_executable')",
            name="playbook_actions_approval_requirement_check",
        ),
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="playbook_actions_confidence_range",
        ),
        CheckConstraint(
            "grounding_basis IN ('established_evidence','prediction_supported','both')",
            name="playbook_actions_grounding_basis_check",
        ),
    )

    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("playbook_sessions.id", ondelete="CASCADE"),
        nullable=False,
        comment="Owning playbook session.",
    )
    step_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("playbook_steps.id", ondelete="CASCADE"),
        nullable=False,
        comment="Owning step within the sequence.",
    )
    action_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        comment=(
            "Deterministic uuid5 over the action, its target reference and its "
            "occurrence, so re-generation over unchanged inputs collides instead of "
            "inserting a duplicate proposal."
        ),
    )
    position: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Position within the owning step; the topological order is stored here.",
    )

    action: Mapped[str] = mapped_column(
        String(_TYPE_LENGTH),
        nullable=False,
        comment="Closed action vocabulary value from the frozen action table.",
    )
    category: Mapped[str] = mapped_column(
        String(_TYPE_LENGTH), nullable=False, comment="Closed category vocabulary."
    )
    target_type: Mapped[str] = mapped_column(
        String(_TYPE_LENGTH),
        nullable=False,
        comment="Closed target vocabulary; structurally validated before persistence.",
    )
    target_reference: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        comment=(
            "Typed pointer to the persisted source that resolved this target. The "
            "target value itself is recorded in action_payload; this column is the "
            "pointer that makes the pointer auditable."
        ),
    )
    target_basis: Mapped[str] = mapped_column(
        String(_LINE_LENGTH),
        nullable=False,
        comment="Why this value was accepted as an addressable target.",
    )

    capability: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        comment=(
            "'available' only when a provider exists today; otherwise 'unavailable', "
            "so the proposal never implies a capability SentinelAI lacks."
        ),
    )
    execution_backend: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        comment="'mock_sandbox' for the six dispatchable actions; otherwise 'none'.",
    )
    approval_requirement: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment=(
            "Recommended human authorization for this action. This column records a "
            "recommendation only; granting approval is not modelled here."
        ),
    )
    #: The existing response-layer action this maps onto, when one exists.
    response_action: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        comment=(
            "Matching ResponseActionType in the existing response layer; NULL when "
            "no execution path exists."
        ),
    )

    rollback_supported: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment=(
            "Whether a compensating action exists in the closed vocabulary. "
            "Compensation is proposed separately and is never automatic."
        ),
    )
    rollback_action: Mapped[str | None] = mapped_column(
        String(_TYPE_LENGTH),
        nullable=True,
        comment="The compensating action, or NULL when nothing safely reverses this one.",
    )

    risk_level: Mapped[str] = mapped_column(
        String(16), nullable=False, comment="bounded low/medium/high."
    )
    priority: Mapped[str] = mapped_column(
        String(16), nullable=False, comment="Closed priority vocabulary."
    )
    expected_outcome: Mapped[str] = mapped_column(
        String(_LINE_LENGTH), nullable=False, comment="What the proposal aims to achieve."
    )
    verification_required: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="Whether an analyst should confirm the effect afterwards.",
    )

    confidence: Mapped[float] = mapped_column(
        Float, nullable=False, comment="How well supported this proposal is, in [0, 1]."
    )
    confidence_band: Mapped[str] = mapped_column(
        String(16), nullable=False, comment="Discrete band over the confidence value."
    )
    confidence_basis: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        comment=(
            "Deterministic component breakdown, retained so the reported "
            "confidence can be recomputed by hand from the record."
        ),
    )
    grounding_basis: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment=(
            "established_evidence, prediction_supported, or both. A prediction may "
            "justify preparation; it may never, alone, justify a disruptive action."
        ),
    )

    provenance: Mapped[str] = mapped_column(
        String(_PROVENANCE_LENGTH),
        nullable=False,
        default=_PLAYBOOK_PROVENANCE,
        comment="Always ai_generated: a proposed action is never a finding.",
    )

    action_payload: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        comment="Canonical JSON of this action as returned by the API.",
    )

    step: Mapped[PlaybookStepRecord] = relationship(
        PlaybookStepRecord, back_populates="actions"
    )
    evidence: Mapped[list["PlaybookActionEvidenceRecord"]] = relationship(
        "PlaybookActionEvidenceRecord",
        back_populates="action",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class PlaybookActionEvidenceRecord(UUIDTimestampMixin, Base):
    """One evidence pointer justifying a proposed action.

    Stores a typed ``<evidence_source>:<id>`` pointer to a persisted source.  No
    source content is copied: a rationale or an action row must never become a
    second copy of the record it cites, both because it would duplicate
    secret-shaped payloads and because a copied record starts to look like
    evidence the system itself produced.
    """

    __tablename__ = "playbook_action_evidence"

    __table_args__ = (
        Index("ix_playbook_action_evidence_action_id", "action_id"),
        Index("ix_playbook_action_evidence_reference", "reference"),
        Index("ix_playbook_action_evidence_stance", "stance"),
        Index("ix_playbook_action_evidence_source", "source"),
        # A citation is identified by what it points at, its owner and its stance.
        # Enforced in the database so no code path can inflate an action's evidence
        # count by re-inserting the same citation — which would silently raise its
        # confidence, since evidence support is a direct term in the formula.
        UniqueConstraint(
            "action_id",
            "reference",
            "stance",
            name="uq_playbook_action_evidence_reference_stance",
        ),
        CheckConstraint(
            f"provenance = '{_PLAYBOOK_PROVENANCE}'",
            name="provenance_ai_generated",
        ),
        CheckConstraint(
            "stance IN ('supporting','contradicting')",
            name="playbook_action_evidence_stance_check",
        ),
        # The source is constrained to the evidence vocabulary only.  'debate_claim'
        # and 'prediction' are included because those are legitimately *cited*, but
        # they are the two that cannot alone justify a disruptive action — an
        # invariant enforced on the action contract, not here.
        CheckConstraint(
            "source IN ('event','detection','correlation','risk_assessment',"
            "'investigation','threat_intelligence','incident_memory','attack_path',"
            "'debate_claim','prediction')",
            name="playbook_action_evidence_source_check",
        ),
    )

    action_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("playbook_actions.id", ondelete="CASCADE"),
        nullable=False,
        comment="Owning proposed action.",
    )
    source: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="Closed evidence-source vocabulary value.",
    )
    reference: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        comment="Typed '<evidence_source>:<id>' pointer; never source content.",
    )
    stance: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        comment=(
            "supporting or contradicting. Contradictions are recorded rather than "
            "suppressed, so disagreement survives into the stored proposal."
        ),
    )
    detail: Mapped[str] = mapped_column(
        String(_LINE_LENGTH),
        nullable=False,
        comment=(
            "Secret-safe, engine-authored reason this pointer matters. Never a "
            "restatement of the cited record."
        ),
    )
    provenance: Mapped[str] = mapped_column(
        String(_PROVENANCE_LENGTH),
        nullable=False,
        default=_PLAYBOOK_PROVENANCE,
        comment="Always ai_generated, matching the parent action.",
    )

    action: Mapped[PlaybookActionRecord] = relationship(
        PlaybookActionRecord, back_populates="evidence"
    )


def playbook_row_payloads(result: Any) -> dict[str, list[dict[str, Any]]]:
    """Normalize a :class:`PlaybookResult` into per-table row payloads.

    Shared by the persistence service and its tests so the projection has exactly
    one definition.
    """
    steps: list[dict[str, Any]] = []
    actions: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []

    for step in result.playbook.steps:
        steps.append(
            {
                "step_number": step.step_number,
                "name": step.name,
                "purpose": step.purpose,
                "depends_on_steps": list(step.depends_on_steps),
            }
        )
        for position, action in enumerate(step.actions):
            actions.append(
                {
                    "step_number": step.step_number,
                    "position": position,
                    "action_id": action.action_id,
                    "action": action.action.value,
                    "category": action.category.value,
                    "target_type": action.target_type.value,
                    "target_reference": action.target_reference,
                    "target_basis": action.target_basis,
                    "capability": action.capability.value,
                    "execution_backend": action.execution_backend.value,
                    "approval_requirement": action.approval.requirement.value,
                    "response_action": action.response_action,
                    "rollback_supported": action.rollback.rollback_supported,
                    "rollback_action": (
                        action.rollback.rollback_action.value
                        if action.rollback.rollback_action
                        else None
                    ),
                    "risk_level": action.risk_level,
                    "priority": action.priority.value,
                    "expected_outcome": action.expected_outcome,
                    "verification_required": action.verification_required,
                    "confidence": action.confidence,
                    "confidence_band": action.confidence_band.value,
                    "confidence_basis": {
                        key.value: value
                        for key, value in action.confidence_basis.items()
                    },
                    "grounding_basis": action.rationale.grounding.value,
                    "action_payload": action.model_dump(mode="json"),
                }
            )
            for item in action.evidence:
                evidence.append(
                    {
                        "action_id": action.action_id,
                        "source": item.source.value,
                        "reference": item.reference,
                        "stance": item.stance,
                        "detail": item.detail,
                    }
                )

    return {"steps": steps, "actions": actions, "evidence": evidence}


__all__ = [
    "PlaybookActionEvidenceRecord",
    "PlaybookActionRecord",
    "PlaybookSessionRecord",
    "PlaybookStepRecord",
    "playbook_row_payloads",
]