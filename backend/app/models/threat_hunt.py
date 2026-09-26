"""Threat Hunt persistence model — V2.19.

``threat_hunts`` is the DRAFT/RUNNING/COMPLETED/FAILED/CANCELLED lifecycle
row.  The hunt never touches live security state; this table (and its
evidence/finding/timeline children) is the only write surface of the
Threat Hunting subsystem.

Hunt lifecycle is invariant-preserving:

* A hunt is created as ``draft`` and executed at most once.
* ``running`` is transient and set only during a synchronous run.
* A finished hunt is ``completed`` or ``failed`` (never re-run, never
  re-opened).
* Only a non-terminal hunt can be cancelled from the boundary.

Filters are persisted verbatim (JSONB) so a completed hunt remains fully
explainable and re-auditable after the fact.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.postgres.base import Base
from app.schemas.threat_hunting import (
    EVIDENCE_PROVENANCE_VALUES,
    HUNT_MAX_NAME_LENGTH,
    HuntEvidenceType,
    HuntType,
    ThreatHuntStatus,
)

_UUID36 = String(36)

_STATUS_VALUES = tuple(member.value for member in ThreatHuntStatus)
_HUNT_TYPE_VALUES = tuple(member.value for member in HuntType)
_EVIDENCE_TYPE_VALUES = tuple(member.value for member in HuntEvidenceType)
_PROVENANCE_VALUES = EVIDENCE_PROVENANCE_VALUES


def nullable_uuid36() -> Mapped[str | None]:
    """Portable 36-char UUID text column (works on PG + SQLite tests)."""
    return mapped_column(_UUID36, nullable=True)


class ThreatHuntRow(Base):
    """One persisted threat hunt with its closed lifecycle."""

    __tablename__ = "threat_hunts"
    __table_args__ = (
        CheckConstraint(
            f"hunt_type IN ({','.join(repr(v) for v in _HUNT_TYPE_VALUES)})",
            name="hunt_type_allowed",
        ),
        CheckConstraint(
            f"status IN ({','.join(repr(v) for v in _STATUS_VALUES)})",
            name="status_allowed",
        ),
        CheckConstraint("end_time > start_time", name="bounded_window"),
    )

    hunt_id: Mapped[str] = mapped_column(
        _UUID36,
        primary_key=True,
        default=lambda: str(_uuid.uuid4()),
        comment="Unique identity of the hunt.",
    )
    name: Mapped[str] = mapped_column(
        String(HUNT_MAX_NAME_LENGTH),
        nullable=False,
        comment="Analyst-assigned hunt name.",
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="",
        comment="Analyst description (free-form, not executed).",
    )
    hunt_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="Closed hunt template identifier.",
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=ThreatHuntStatus.DRAFT.value,
        comment="Closed lifecycle status.",
    )
    start_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="Start of the bounded hunting window.",
    )
    end_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="End of the bounded hunting window (exclusive).",
    )
    created_by: Mapped[_uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        comment="Trusted identity that created the hunt.",
    )
    created_by_role: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="Role label of the creating actor.",
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When the run began.",
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When the run completed or failed.",
    )
    filters: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
        comment="Persisted structured filters (JSONB array of objects).",
    )
    result_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Total evidence items collected by the run.",
    )
    finding_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Total findings produced by the run.",
    )
    timeline_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Total timeline items produced by the run.",
    )
    error_code: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        comment="Sanitized structured error code when the run failed.",
    )
    error_message: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
        comment="Sanitized human-readable error message when the run failed.",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class ThreatHuntEvidenceRow(Base):
    """One evidence item: a reference into an existing persisted record.

    ``evidence_id`` is the deterministic artifact id within the hunt;
    ``reference_id`` is the identity of the existing record that was
    **observed**, never a copy.  Provenance and severities are inherited
    verbatim from the source envelope — a hunt never invents either.
    """

    __tablename__ = "threat_hunt_evidence"
    __table_args__ = (
        CheckConstraint(
            f"evidence_type IN ({','.join(repr(v) for v in _EVIDENCE_TYPE_VALUES)})",
            name="evidence_type_allowed",
        ),
        CheckConstraint(
            f"provenance IN ({','.join(repr(v) for v in _PROVENANCE_VALUES)})",
            name="provenance_allowed",
        ),
        Index("ix_threat_hunt_evidence_hunt_observed", "hunt_id", "observed_at"),
        Index("ix_threat_hunt_evidence_hunt_provenance", "hunt_id", "provenance"),
    )

    hunt_id: Mapped[str] = mapped_column(
        _UUID36,
        ForeignKey("threat_hunts.hunt_id", ondelete="CASCADE"),
        primary_key=True,
        comment="Owning hunt.",
    )
    evidence_id: Mapped[str] = mapped_column(
        _UUID36,
        primary_key=True,
        comment="Deterministic artifact id within the hunt.",
    )
    evidence_key: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="Closed evidence key (surface/provenance edge).",
    )
    evidence_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="Closed evidence kind.",
    )
    reference_id: Mapped[str] = mapped_column(
        _UUID36,
        nullable=False,
        comment="Identity of the referenced existing record.",
    )
    event_id: Mapped[str | None] = nullable_uuid36()
    correlation_id: Mapped[str | None] = nullable_uuid36()
    provenance: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="Inherited envelope provenance.",
    )
    severity: Mapped[str | None] = mapped_column(
        String(16),
        nullable=True,
        comment="Inherited severity/level when the source carries one.",
    )
    subject: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="Deterministic grouping subject carried from the source record (e.g. actor IP, indicator value).",
    )
    observed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="The source record's own event timestamp.",
    )
    title: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
        comment="Short deterministic descriptor.",
    )
    summary: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
        comment="Deterministic, secret-free one-line summary.",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


class ThreatHuntFindingRow(Base):
    """One deterministic, evidence-derived finding.

    Findings are grouped counts and inherited severities listed in
    ``context``; ``provenance``/``severity`` are taken from the referenced
    evidence, never generated.
    """

    __tablename__ = "threat_hunt_findings"
    __table_args__ = (
        CheckConstraint(
            f"provenance IN ({','.join(repr(v) for v in _PROVENANCE_VALUES)})",
            name="provenance_allowed",
        ),
    )

    hunt_id: Mapped[str] = mapped_column(
        _UUID36,
        ForeignKey("threat_hunts.hunt_id", ondelete="CASCADE"),
        primary_key=True,
        comment="Owning hunt.",
    )
    finding_id: Mapped[str] = mapped_column(
        _UUID36,
        primary_key=True,
        comment="Deterministic artifact id within the hunt.",
    )
    title: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
        comment="Short deterministic finding title.",
    )
    description: Mapped[str] = mapped_column(
        String(1000),
        nullable=False,
        comment="Deterministic, evidence-derived description.",
    )
    severity: Mapped[str | None] = mapped_column(
        String(16),
        nullable=True,
        comment="Inherited severity/level when defensible from evidence.",
    )
    provenance: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="Provenance of the underlying evidence.",
    )
    observed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Earliest evidence timestamp in the finding.",
    )
    evidence_ids: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
        comment="Bounded list of hunt-scoped evidence ids (JSONB).",
    )
    context: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
        comment="Deterministic grouping context (JSONB; e.g. rule_id, counts).",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


class ThreatHuntTimelineItemRow(Base):
    """One item of the deterministic hunt timeline.

    ``evidence_id`` references the hunt-scoped evidence item and
    ``reference_id`` its underlying record; ordering is by ``observed_at``
    ascending with entries lacking an instant ordered last (stable tiebreak
    by ``timeline_item_id``).
    """

    __tablename__ = "threat_hunt_timeline_items"
    __table_args__ = (
        CheckConstraint(
            f"evidence_type IN ({','.join(repr(v) for v in _EVIDENCE_TYPE_VALUES)})",
            name="evidence_type_allowed",
        ),
        CheckConstraint(
            f"provenance IN ({','.join(repr(v) for v in _PROVENANCE_VALUES)})",
            name="provenance_allowed",
        ),
        Index("ix_threat_hunt_timeline_hunt_observed", "hunt_id", "observed_at"),
    )

    hunt_id: Mapped[str] = mapped_column(
        _UUID36,
        ForeignKey("threat_hunts.hunt_id", ondelete="CASCADE"),
        primary_key=True,
        comment="Owning hunt.",
    )
    timeline_item_id: Mapped[str] = mapped_column(
        _UUID36,
        primary_key=True,
        comment="Deterministic artifact id within the hunt.",
    )
    evidence_id: Mapped[str] = mapped_column(
        _UUID36,
        nullable=False,
        comment="The hunt-scoped evidence item this entry references.",
    )
    reference_id: Mapped[str] = mapped_column(
        _UUID36,
        nullable=False,
        comment="Underlying existing record identity.",
    )
    observed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Chronological key: the evidence's own timestamp.",
    )
    evidence_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="Evidence kind of the referenced item.",
    )
    evidence_summary: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
        comment="Deterministic summary copied from the referenced evidence.",
    )
    provenance: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="Provenance of the referenced evidence.",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


__all__ = [
    "ThreatHuntRow",
    "ThreatHuntEvidenceRow",
    "ThreatHuntFindingRow",
    "ThreatHuntTimelineItemRow",
]