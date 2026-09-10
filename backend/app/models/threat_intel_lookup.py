"""Threat Intelligence Lookup persistence model (Step 8C-A).

This is the **persistence contract** for a single provider lookup executed
against one indicator on behalf of one security event (Step 8B's
:class:`~app.schemas.threat_intelligence_agent.ProviderAssociation` and
:class:`~app.schemas.threat_intelligence_agent.ProviderFailure`).

It is a **normalized** design: a lookup is a single, atomic provider
execution attempt that resolves to exactly one outcome — either a
successful result/evidence or a failure.  Both outcomes are represented
on the same row through mutually-exclusive optional columns:

* *result / evidence* columns (``found``, ``confidence``, ``evidence``,
  ``result_metadata``, ``result_timestamp``) are populated on success and
  null on failure;
* *failure* columns (``status = error``, ``error_type``,
  ``error_message``, ``retryable``) are populated on failure and null/absent
  on success.

This preserves the required ``event → indicator → provider → result``
traceability without a redundant 1:1 result table.

Event relationship
------------------
``event_id`` is the UUID of the originating security event.  SentinelAI
does **not yet** persist a dedicated ``events`` table, so this is stored as
an indexed UUID column (an implicit logical foreign key) rather than a hard
SQL foreign key.  When an ``events`` model is introduced in a later step,
this column becomes a real foreign key without changing its meaning.  We
deliberately do **not** create an unrelated duplicate event model here.

Provenance
----------
Threat-intelligence evidence is *enrichment*.  The ``provenance`` column of
a lookup (representing the evidence provenance) is constrained by a
database CHECK constraint to the :class:`Provenance.ENRICHED` value so that
TI evidence can **never** be persisted as ``observed``/``reconstructed``
merely because it relates to an observed event.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum as SqlEnum,
    ForeignKey,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.postgres.base import Base, UUIDTimestampMixin
from app.schemas.security_event import Provenance


class LookupStatus(str, Enum):
    """Outcome of a provider lookup execution.

    ``success``  — the provider returned a result (evidence columns set).
    ``error``    — the provider failed (failure columns set).

    ``retryable`` is tracked separately, as a boolean, so that status
    and repeatability remain independent concerns.
    """

    SUCCESS = "success"
    ERROR = "error"

class ThreatIntelLookup(UUIDTimestampMixin, Base):
    """A single provider lookup performed for one indicator on one event.

    Attributes:
        event_id: UUID of the originating security event (indexed; becomes
            a real foreign key once an ``events`` model exists).
        indicator_id: Foreign key to an :class:`ThreatIntelIndicator`.
        provider: Name of the provider that executed the lookup.
        status: One of :class:`LookupStatus` (success | error).
        performed_at: When the lookup was performed (UTC, timezone-aware).
        retryable: Whether a failure is likely transient and retryable.
        error_type: Machine-readable failure category (failure only).
        error_message: Human-readable, secret-safe message (failure only).
        found: Whether the provider had information (success only).
        confidence: Optional confidence in [0.0, 1.0] (success only).
        result_timestamp: When the provider produced its result.
        evidence: Structured provider evidence (JSONB, success only).  This
            is the provider's *structured* payload, never a raw HTTP dump.
        result_metadata: Optional safe provider metadata (JSONB).
        provenance: Evidence provenance, constrained to ENRICHED.
        indicator: The indicator this lookup concerns.
    """

    __tablename__ = "threat_intel_lookups"
    __table_args__ = (
        CheckConstraint(
            "provenance = 'enriched'",
            name="provenance_enriched",
        ),
    )

    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
    )

    indicator_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("threat_intel_indicators.id"),
        nullable=False,
        index=True,
    )

    provider: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )

    status: Mapped[LookupStatus] = mapped_column(
        SqlEnum(
            LookupStatus,
            name="lookup_status",
            values_callable=lambda enum: [member.value for member in enum],
            native_enum=False,
        ),
        nullable=False,
    )

    performed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # -- Failure representation (status = error) -----------------------------

    retryable: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True,
    )

    error_type: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Secret-safe human-readable error message.",
    )

    # -- Result / evidence representation (status = success) -----------------

    found: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True,
    )

    confidence: Mapped[float | None] = mapped_column(
        nullable=True,
        comment="Optional confidence in [0.0, 1.0].",
    )

    result_timestamp: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    evidence: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        comment=(
            "Structured provider-specific evidence (JSONB).  This holds "
            "the provider's structured payload — never a raw HTTP response "
            "or a dump-everything blob."
        ),
    )

    result_metadata: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="Optional safe, non-secret provider metadata (JSONB).",
    )

    # -- Provenance -----------------------------------------------------------

    provenance: Mapped[str] = mapped_column(
        String(32),
        default=Provenance.ENRICHED.value,
        nullable=False,
        comment=(
            "Evidence provenance.  Threat-intelligence evidence is "
            "enrichment and is constrained to ENRICHED by CHECK constraint; "
            "it can never be stored as observed/reconstructed."
        ),
    )

    # -- Relationships -------------------------------------------------------

    indicator: Mapped["ThreatIntelIndicator"] = relationship(  # noqa: F821
        back_populates="lookups",
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<ThreatIntelLookup id={self.id} provider={self.provider!r} "
            f"status={self.status.value} event_id={self.event_id}>"
        )
