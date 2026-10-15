"""Relational persistence for multi-agent debates — V3.23.

Five tables record the analytical output of a debate.  They store **references
and reasoning text only** — no V2 record is duplicated here, and the knowledge
graph is never written.  A debate row is downstream analytical state.

Idempotency is a database guarantee, not an application convention:
``debate_sessions.id`` is a deterministic ``uuid5`` over
``(correlation_id, graph_snapshot_digest, configuration_digest)`` and is the
primary key, so re-running the same debate over the same immutable graph
snapshot collides on the key instead of inserting a duplicate.

``debate_arguments`` covers both arguments and counterarguments because they are
the same shape (author, target, statement, evidence) distinguished by ``kind``;
splitting them would duplicate columns and constraints for no gain.

Provenance: every table carries ``provenance`` CHECK-pinned to
``ai_generated``.  A debate conclusion is AI-generated reasoning; it must never
serialize as ``observed``, ``detected``, ``correlated``, or ``risk_assessed``,
which belong to the V2 entities that genuinely produced them.  Reusing the
existing ``Provenance.AI_GENERATED`` value also means no V2 table needs to be
altered to accommodate V3.23.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
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
_TYPE_LENGTH = 48
_PROVENANCE_LENGTH = 32
_TEXT_LENGTH = 1024

#: Provenance every debate row is pinned to.  The CHECK constraint is what makes
#: a future bug that writes ``observed`` onto a debate impossible to persist.
_DEBATE_PROVENANCE = "ai_generated"


class DebateSessionRecord(UUIDTimestampMixin, Base):
    """One debate session, keyed by its deterministic identity."""

    __tablename__ = "debate_sessions"

    __table_args__ = (
        Index("ix_debate_sessions_correlation_id", "correlation_id"),
        Index("ix_debate_sessions_status", "status"),
        Index("ix_debate_sessions_graph_snapshot_digest", "graph_snapshot_digest"),
        CheckConstraint(
            f"provenance = '{_DEBATE_PROVENANCE}'",
            name="provenance_ai_generated",
        ),
        CheckConstraint(
            "status IN ('pending','running','completed','failed')",
            name="debate_sessions_status_check",
        ),
    )

    #: The persisted V2 correlation this debate reasons about.  Deliberately no
    #: foreign key: correlation lifecycle and analytical discussion are
    #: independent, and a debate must outlive the row it discusses (the same
    #: reasoning V2 applies to incident reports and memories).
    correlation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        comment="V2 correlation under debate; a soft reference by design.",
    )
    graph_snapshot_digest: Mapped[str] = mapped_column(
        String(_DIGEST_LENGTH),
        nullable=False,
        comment=(
            "SHA-256 of the canonical bounded V3.22 graph.  Part of the "
            "deterministic session identity: a changed graph means a new "
            "debate, not a mutated one."
        ),
    )
    configuration_digest: Mapped[str] = mapped_column(
        String(_DIGEST_LENGTH),
        nullable=False,
        comment="SHA-256 of the bounds and agent roster used for this debate.",
    )
    status: Mapped[str] = mapped_column(
        String(24),
        nullable=False,
        default="pending",
        comment="Lifecycle status; 'failed' records a governed failure, never a fake consensus.",
    )
    provider: Mapped[str] = mapped_column(
        String(_TYPE_LENGTH), nullable=False, comment="Non-secret provider identifier."
    )
    model: Mapped[str | None] = mapped_column(
        String(_TYPE_LENGTH), nullable=True, comment="Non-secret model identifier."
    )
    engine_version: Mapped[str] = mapped_column(
        String(_TYPE_LENGTH), nullable=False, comment="Debate engine version."
    )
    provenance: Mapped[str] = mapped_column(
        String(_PROVENANCE_LENGTH),
        nullable=False,
        default=_DEBATE_PROVENANCE,
        comment="Always ai_generated: debate output is reasoning, not evidence.",
    )
    session_payload: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        comment=(
            "Canonical JSON document of the completed debate. The normalized "
            "child tables (rounds, assessments, arguments, consensus) are the "
            "queryable and auditable projection of the same write; this column "
            "is the lossless read model so a GET returns exactly what the POST "
            "produced, including engine-derived facts and evidence scope, which "
            "are pure functions of the graph snapshot this session pins."
        ),
    )
    graph_node_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    graph_edge_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    evidence_reference_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    agent_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    failure_code: Mapped[str | None] = mapped_column(
        String(_TYPE_LENGTH),
        nullable=True,
        comment="Stable failure code when status='failed'; never free-form text.",
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    rounds: Mapped[list["DebateRoundRecord"]] = relationship(
        "DebateRoundRecord",
        back_populates="session",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="DebateRoundRecord.round_number",
    )
    assessments: Mapped[list["DebateAgentAssessmentRecord"]] = relationship(
        "DebateAgentAssessmentRecord",
        back_populates="session",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    arguments: Mapped[list["DebateArgumentRecord"]] = relationship(
        "DebateArgumentRecord",
        back_populates="session",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    consensus: Mapped["DebateConsensusRecord | None"] = relationship(
        "DebateConsensusRecord",
        back_populates="session",
        cascade="all, delete-orphan",
        passive_deletes=True,
        uselist=False,
    )

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return (
            f"<DebateSessionRecord {self.id} correlation={self.correlation_id} "
            f"status={self.status}>"
        )


class DebateRoundRecord(UUIDTimestampMixin, Base):
    """One bounded round of a debate."""

    __tablename__ = "debate_rounds"

    __table_args__ = (
        UniqueConstraint(
            "debate_id", "round_number", name="uq_debate_rounds_debate_round"
        ),
        Index("ix_debate_rounds_debate_id", "debate_id"),
        CheckConstraint(
            f"provenance = '{_DEBATE_PROVENANCE}'",
            name="provenance_ai_generated",
        ),
    )

    debate_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "debate_sessions.id",
            ondelete="CASCADE",
            name="fk_debate_rounds_debate_id_debate_sessions",
        ),
        nullable=False,
    )
    round_number: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="0 = shared evidence context; 1-4 = the bounded debate rounds.",
    )
    round_kind: Mapped[str] = mapped_column(String(_TYPE_LENGTH), nullable=False)
    summary: Mapped[str] = mapped_column(
        String(_TEXT_LENGTH), nullable=False, comment="Round summary; bounded."
    )
    agent_ids: Mapped[list] = mapped_column(
        JSON, nullable=False, default=list, comment="Agent ids participating."
    )
    argument_ids: Mapped[list] = mapped_column(
        JSON, nullable=False, default=list, comment="Argument ids raised."
    )
    counterargument_ids: Mapped[list] = mapped_column(
        JSON, nullable=False, default=list, comment="Counterargument ids raised."
    )
    provenance: Mapped[str] = mapped_column(
        String(_PROVENANCE_LENGTH), nullable=False, default=_DEBATE_PROVENANCE
    )

    session: Mapped[DebateSessionRecord] = relationship(
        "DebateSessionRecord", back_populates="rounds"
    )


class DebateAgentAssessmentRecord(UUIDTimestampMixin, Base):
    """One agent's independent assessment within a debate."""

    __tablename__ = "debate_agent_assessments"

    __table_args__ = (
        UniqueConstraint(
            "debate_id", "agent_id", name="uq_debate_agent_assessments_debate_agent"
        ),
        Index("ix_debate_agent_assessments_debate_id", "debate_id"),
        CheckConstraint(
            f"provenance = '{_DEBATE_PROVENANCE}'",
            name="provenance_ai_generated",
        ),
    )

    debate_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "debate_sessions.id",
            ondelete="CASCADE",
            name="fk_debate_agent_assessments_debate_id_debate_sessions",
        ),
        nullable=False,
    )
    agent_id: Mapped[str] = mapped_column(
        String(_ID_LENGTH), nullable=False, comment="Stable 'agent:<role>' identity."
    )
    role: Mapped[str] = mapped_column(String(_TYPE_LENGTH), nullable=False)
    objective: Mapped[str] = mapped_column(
        String(_TEXT_LENGTH), nullable=False, comment="The agent's stated objective."
    )
    confidence: Mapped[float] = mapped_column(
        Float, nullable=False, comment="The agent's own calibrated confidence."
    )
    observations: Mapped[list] = mapped_column(
        JSON,
        nullable=False,
        default=list,
        comment=(
            "Evidenced observations as {claim_id, statement, evidence_references, "
            "confidence}.  Never facts: facts are engine-derived and stored on "
            "the session-level fact list."
        ),
    )
    hypotheses: Mapped[list] = mapped_column(
        JSON,
        nullable=False,
        default=list,
        comment="Interpretations as {claim_id, statement, evidence_references, confidence}.",
    )
    evidence_references: Mapped[list] = mapped_column(
        JSON,
        nullable=False,
        default=list,
        comment=(
            "Evidence references as {reference, entity_kind, node_id} pointers "
            "into persisted V2 evidence. Pointers only; never copied V2 records."
        ),
    )
    limitations: Mapped[list] = mapped_column(
        JSON,
        nullable=False,
        default=list,
        comment="What the agent could not establish from the supplied evidence.",
    )
    provenance: Mapped[str] = mapped_column(
        String(_PROVENANCE_LENGTH), nullable=False, default=_DEBATE_PROVENANCE
    )

    session: Mapped[DebateSessionRecord] = relationship(
        "DebateSessionRecord", back_populates="assessments"
    )


class DebateArgumentRecord(UUIDTimestampMixin, Base):
    """One argument or counterargument raised during a debate.

    Both share a shape — author, target, statement, evidence — and are
    distinguished by ``kind``, so a single table with a single set of
    constraints keeps referential integrity simple.
    """

    __tablename__ = "debate_arguments"

    __table_args__ = (
        UniqueConstraint(
            "debate_id", "argument_id", name="uq_debate_arguments_debate_argument"
        ),
        Index("ix_debate_arguments_debate_id", "debate_id"),
        Index("ix_debate_arguments_target_hypothesis_id", "target_hypothesis_id"),
        Index("ix_debate_arguments_target_argument_id", "target_argument_id"),
        CheckConstraint(
            f"provenance = '{_DEBATE_PROVENANCE}'",
            name="provenance_ai_generated",
        ),
        CheckConstraint(
            "kind IN ('argument','counterargument')",
            name="debate_arguments_kind_check",
        ),
        CheckConstraint(
            "json_array_length(evidence_references) > 0",
            name="debate_arguments_evidence_present_check",
        ),
    )

    debate_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "debate_sessions.id",
            ondelete="CASCADE",
            name="fk_debate_arguments_debate_id_debate_sessions",
        ),
        nullable=False,
    )
    argument_id: Mapped[str] = mapped_column(
        String(_ID_LENGTH),
        nullable=False,
        comment="Deterministic uuid5 of (round, author, target, statement).",
    )
    kind: Mapped[str] = mapped_column(String(24), nullable=False)
    author_agent_id: Mapped[str] = mapped_column(String(_ID_LENGTH), nullable=False)
    author_role: Mapped[str] = mapped_column(String(_TYPE_LENGTH), nullable=False)
    target_agent_id: Mapped[str | None] = mapped_column(
        String(_ID_LENGTH), nullable=True
    )
    target_role: Mapped[str | None] = mapped_column(String(_TYPE_LENGTH), nullable=True)
    target_hypothesis_id: Mapped[str | None] = mapped_column(
        String(_ID_LENGTH),
        nullable=True,
        comment="Hypothesis this argument takes a position on; null for counterarguments.",
    )
    target_argument_id: Mapped[str | None] = mapped_column(
        String(_ID_LENGTH),
        nullable=True,
        comment="Argument this counterargument challenges; null for arguments.",
    )
    stance: Mapped[str | None] = mapped_column(
        String(16), nullable=True, comment="'supports' or 'opposes'; null for counterarguments."
    )
    weakness: Mapped[str | None] = mapped_column(
        String(48),
        nullable=True,
        comment="Closed weakness vocabulary; null for arguments.",
    )
    statement: Mapped[str] = mapped_column(
        String(_TEXT_LENGTH), nullable=False, comment="Bounded analytical statement."
    )
    evidence_references: Mapped[list] = mapped_column(
        JSON,
        nullable=False,
        default=list,
        comment=(
            "Sorted evidence references as {reference, entity_kind, node_id}. "
            "Pointers into persisted V2 evidence only: no V2 record content is "
            "copied. A CHECK constraint requires at least one."
        ),
    )
    provenance: Mapped[str] = mapped_column(
        String(_PROVENANCE_LENGTH), nullable=False, default=_DEBATE_PROVENANCE
    )

    session: Mapped[DebateSessionRecord] = relationship(
        "DebateSessionRecord", back_populates="arguments"
    )


class DebateConsensusRecord(UUIDTimestampMixin, Base):
    """The deterministic reconciliation outcome for one debate."""

    __tablename__ = "debate_consensus"

    __table_args__ = (
        UniqueConstraint("debate_id", name="uq_debate_consensus_debate_id"),
        Index("ix_debate_consensus_debate_id", "debate_id"),
        Index("ix_debate_consensus_state", "state"),
        CheckConstraint(
            f"provenance = '{_DEBATE_PROVENANCE}'",
            name="provenance_ai_generated",
        ),
        CheckConstraint(
            "state IN ('consensus','partial_consensus','contested',"
            "'insufficient_evidence')",
            name="debate_consensus_state_check",
        ),
        CheckConstraint(
            "consensus_strength >= 0.0 AND consensus_strength <= 1.0",
            name="debate_consensus_strength_range_check",
        ),
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="debate_consensus_confidence_range_check",
        ),
    )

    debate_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "debate_sessions.id",
            ondelete="CASCADE",
            name="fk_debate_consensus_debate_id_debate_sessions",
        ),
        nullable=False,
    )
    state: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="Closed consensus vocabulary; never free-form.",
    )
    leading_hypothesis: Mapped[str | None] = mapped_column(
        String(_TEXT_LENGTH),
        nullable=True,
        comment="Engine-selected leading hypothesis; null when none was raised.",
    )
    leading_hypothesis_id: Mapped[str | None] = mapped_column(
        String(_ID_LENGTH), nullable=True
    )
    consensus_strength: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
        comment="Share of the agent roster supporting the leading hypothesis.",
    )
    confidence: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
        comment=(
            "Deterministically computed from agreement, evidence support, "
            "completeness, and contradiction.  Never a blind average."
        ),
    )
    supporting_argument_ids: Mapped[list] = mapped_column(
        JSON, nullable=False, default=list
    )
    opposing_argument_ids: Mapped[list] = mapped_column(
        JSON, nullable=False, default=list
    )
    dissent: Mapped[list] = mapped_column(
        JSON,
        nullable=False,
        default=list,
        comment="Recorded losing positions; a debate never discards them.",
    )
    unresolved_questions: Mapped[list] = mapped_column(
        JSON, nullable=False, default=list
    )
    evidence_gaps: Mapped[list] = mapped_column(
        JSON,
        nullable=False,
        default=list,
        comment="Entity kinds the graph could not supply for this debate.",
    )
    evidence_references: Mapped[list] = mapped_column(
        JSON, nullable=False, default=list
    )
    provenance: Mapped[str] = mapped_column(
        String(_PROVENANCE_LENGTH), nullable=False, default=_DEBATE_PROVENANCE
    )

    session: Mapped[DebateSessionRecord] = relationship(
        "DebateSessionRecord", back_populates="consensus"
    )


__all__ = [
    "DebateAgentAssessmentRecord",
    "DebateArgumentRecord",
    "DebateConsensusRecord",
    "DebateRoundRecord",
    "DebateSessionRecord",
]