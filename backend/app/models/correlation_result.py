"""Correlation persistence model (Step 10C-A).

This is the **persistence contract** for a single Step 10A
:class:`~app.schemas.correlation.CorrelationResult` produced by the Step
10B :class:`~app.agents.correlation.CorrelationAgent`.

Design intent
-------------
* ``correlation_id`` (the Step 10A ``CorrelationResult.correlation_id``)
  is unique and is the **idempotency identity**: re-persisting the same
  correlation is a no-op, while a later re-correlation that produces a
  fresh UUID is a new, legitimate historical row.
* Correlation **references** detections — it never duplicates a
  ``DetectionResult`` record.  Each member of the correlation is stored as
  a lightweight reference row (``detection_id``, ``event_id``,
  ``timestamp``, ``member_order``) in
  :class:`~app.models.correlation_member.CorrelationMember`; the
  detection subsystem remains the source of truth.
* Step 10A ``first_seen_at`` / ``last_seen_at`` are **computed views** and
  are deliberately not stored; they are derived from member timestamps.
* Provenance is constrained by a database CHECK constraint to the
  ``Provenance.CORRELATED`` value so correlation output can **never** be
  persisted as ``observed``/``enriched``/``reconstructed``/``detected``.
* ``status`` and ``confidence`` are neutral Step 10A bookkeeping: the
  status is a lifecycle marker (never a verdict), and confidence — when
  present — is bounded to ``[0.0, 1.0]`` by a CHECK constraint and is not
  a risk score.
* Security: ``evidence`` and ``result_metadata`` are structured, bounded
  JSONB payloads.  Credential-shaped keys are redacted by the Step 10C-B
  persistence service before write; no raw rule source, event payload, or
  secret is ever stored here.

This model defines the layout only.  The repository/service that persists
``CorrelationResult`` objects (Step 10C-B) is **not** implemented here.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Enum as SqlEnum,
    Float,
    String,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.postgres.base import Base, UUIDTimestampMixin
from app.schemas.correlation import CorrelationStatus
from app.schemas.security_event import Provenance


def _correlation_status_values(enum_class) -> list[str]:
    """Return the raw string values of :class:`CorrelationStatus`."""
    return [member.value for member in enum_class]


class CorrelationResult(UUIDTimestampMixin, Base):
    """A single persisted correlation result.

    Attributes:
        correlation_id: Step 10A ``CorrelationResult.correlation_id``.
            Unique — the idempotency identity of a persisted correlation.
        status: Neutral lifecycle state (``candidate``/``active``/``closed``).
        confidence: Optional correlation-level confidence in ``[0.0, 1.0]``
            (CHECK-constrained; ``NULL`` when undefined).
        evidence: Structured, non-secret correlation evidence (JSONB).
        result_metadata: Safe, non-secret correlation metadata (JSONB).
        timestamp: When the correlation was established (UTC, tz-aware).
        provenance: Correlation provenance, constrained to ``correlated``.
    """

    __tablename__ = "correlation_results"
    __table_args__ = (
        CheckConstraint(
            "confidence IS NULL OR "
            "(confidence >= 0.0 AND confidence <= 1.0)",
            name="correlation_confidence_range",
        ),
        CheckConstraint(
            "provenance = 'correlated'",
            name="provenance_correlated",
        ),
    )

    correlation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        unique=True,
        index=True,
        comment=(
            "Step 10A CorrelationResult.correlation_id.  Unique identity "
            "of a persisted correlation — the idempotency key for "
            "re-persists."
        ),
    )

    status: Mapped[CorrelationStatus] = mapped_column(
        SqlEnum(
            CorrelationStatus,
            name="correlation_status",
            values_callable=_correlation_status_values,
            native_enum=False,
        ),
        nullable=False,
        comment=(
            "Neutral lifecycle state of the correlation "
            "(candidate / active / closed).  Bookkeeping only; never a "
            "verdict."
        ),
    )

    confidence: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
        comment=(
            "Optional correlation-level confidence in [0.0, 1.0] "
            "(CHECK-constrained).  NULL when the engine produced no "
            "numeric confidence; never an aggregate of detection "
            "confidence and never a risk score."
        ),
    )

    evidence: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        comment=(
            "Structured correlation evidence (JSONB).  Holds the engine's "
            "structured non-secret evidence — never a raw rule, event, or "
            "detection payload blob."
        ),
    )

    result_metadata: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        comment="Optional safe, non-secret correlation metadata (JSONB).",
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment=(
            "When the correlation was established (10A result timestamp, "
            "UTC, tz-aware).  Descriptive bookkeeping, not evidence."
        ),
    )

    provenance: Mapped[str] = mapped_column(
        String(32),
        default=Provenance.CORRELATED.value,
        nullable=False,
        comment=(
            "Correlation provenance.  Correlations are derived analytical "
            "conclusions and are constrained to CORRELATED by CHECK "
            "constraint; they can never be stored as "
            "observed/enriched/reconstructed/detected."
        ),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<CorrelationResult id={self.id} "
            f"correlation_id={self.correlation_id} "
            f"status={self.status.value}>"
        )