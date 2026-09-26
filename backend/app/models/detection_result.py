"""Detection persistence model (Step 9F-A).

This is the **persistence contract** for a single detection match produced
by a Step 9E evaluation (one ``DetectionResult`` from a
:class:`~app.schemas.detection_agent.DetectionAnalysis`).

Design intent
-------------
* The Step 9E agent only emits *matched* results into an analysis, so every
  persisted row is a match.  The ``matched`` column is constrained to
  ``true`` by a database CHECK constraint, and a non-matching evaluation is
  represented by **no row** (the absence of a row over the evaluation window
  *is* the no-match record).
* ``detection_id`` (the Step 9A ``DetectionResult.detection_id``) is unique
  and is the **idempotency identity**: re-persisting the same analysis is a
  no-op, while a re-evaluation that produces a fresh UUID is a new,
  legitimate historical row.
* ``event_id`` is the UUID of the originating security event.  SentinelAI
  does **not** yet persist a dedicated ``events`` table, so this is stored as
  an indexed UUID column (an implicit logical foreign key) exactly as
  ``threat_intel_lookups.event_id`` is.
* Provenance is constrained by a database CHECK constraint to the
  ``Provenance.DETECTED`` value so detection evidence can **never** be
  persisted as ``observed``/``enriched``/``reconstructed``.
* Security: ``evidence`` and ``result_metadata`` are structured, bounded
  JSONB payloads.  Credential-shaped keys are redacted by the Step 9F-B
  persistence service before write; no raw rule source, event payload, or
  secret is ever stored here.

This model defines the layout only.  The repository/service that persists a
``DetectionAnalysis`` (Step 9F-B) is **not** implemented here.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum as SqlEnum,
    Float,
    String,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.postgres.base import Base, UUIDTimestampMixin
from app.schemas.detection import DetectionSeverity, RuleType
from app.schemas.security_event import Provenance


def _rule_type_values(enum_class) -> list[str]:
    """Return the raw string values of :class:`RuleType` (``sigma``/``yara``)."""
    return [member.value for member in enum_class]


def _severity_values(enum_class) -> list[str]:
    """Return the raw string values of :class:`DetectionSeverity`."""
    return [member.value for member in enum_class]


class DetectionResult(UUIDTimestampMixin, Base):
    """A single persisted detection match.

    Attributes:
        event_id: UUID of the originating security event (indexed; becomes
            a real foreign key once an ``events`` model exists).
        detection_id: Step 9A ``DetectionResult.detection_id``.  Unique —
            the idempotency identity of a persisted result.
        rule_id: Identity of the evaluated rule (traceable to a
            ``DetectionRule`` definition in the registry).
        rule_type: Engine type that produced the result (``sigma``/``yara``).
        rule_version: Version of the evaluated rule; ``"unknown"`` when the
            result metadata carries no version.
        severity: Rule-author severity of the finding.
        matched: Always ``true`` (CHECK-constrained); non-matches are not
            persisted.
        confidence: Engine confidence in ``[0.0, 1.0]`` (CHECK-constrained).
        evidence: Structured match evidence (JSONB) — never raw rule or
            event payloads, never secrets.
        result_metadata: Safe, non-secret evaluation metadata (JSONB).
        detected_at: When the evaluation was performed (UTC, tz-aware).
        provenance: Evidence provenance, constrained to ``detected``.
    """

    __tablename__ = "detection_results"
    __table_args__ = (
        CheckConstraint(
            "matched = true",
            name="detection_matched_required",
        ),
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="detection_confidence_range",
        ),
        CheckConstraint(
            "provenance = 'detected'",
            name="provenance_detected",
        ),
    )

    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
    )

    detection_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        unique=True,
        index=True,
        comment=(
            "Step 9A DetectionResult.detection_id.  Unique identity of a "
            "persisted detection match — the idempotency key for re-persists."
        ),
    )

    rule_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )

    rule_type: Mapped[RuleType] = mapped_column(
        SqlEnum(
            RuleType,
            name="rule_type",
            values_callable=_rule_type_values,
            native_enum=False,
        ),
        nullable=False,
    )

    rule_version: Mapped[str] = mapped_column(
        String(64),
        default="unknown",
        nullable=False,
        comment=(
            "Version of the evaluated rule.  Falls back to 'unknown' when "
            "the result metadata carries no rule version."
        ),
    )

    severity: Mapped[DetectionSeverity] = mapped_column(
        SqlEnum(
            DetectionSeverity,
            name="detection_severity",
            values_callable=_severity_values,
            native_enum=False,
        ),
        nullable=False,
        index=True,
    )

    matched: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        comment=(
            "Always true.  The agent only emits matched results, and the "
            "CHECK constraint is the database-level enforcement; "
            "non-matches are represented by the absence of a row."
        ),
    )

    confidence: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        comment="Engine confidence in [0.0, 1.0] (CHECK-constrained).",
    )

    evidence: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        comment=(
            "Structured match evidence (JSONB).  Holds the engine's "
            "structured non-secret evidence — never a raw rule or event "
            "payload blob."
        ),
    )

    result_metadata: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        comment="Optional safe, non-secret evaluation metadata (JSONB).",
    )

    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    provenance: Mapped[str] = mapped_column(
        String(32),
        default=Provenance.DETECTED.value,
        nullable=False,
        comment=(
            "Evidence provenance.  Detection evidence is a derived analytical "
            "conclusion and is constrained to DETECTED by CHECK constraint; "
            "it can never be stored as observed/enriched/reconstructed."
        ),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<DetectionResult id={self.id} rule_id={self.rule_id!r} "
            f"severity={self.severity.value} event_id={self.event_id}>"
        )