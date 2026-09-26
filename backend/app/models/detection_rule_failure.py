"""Detection rule failure persistence model (Step 9F-A).

This is the **persistence contract** for a single rule-level or engine-level
detection failure (one :class:`~app.schemas.detection_agent.DetectionFailure`
from a Step 9E :class:`~app.schemas.detection_agent.DetectionAnalysis`),
normalised into a row with an ``engine`` discriminator.

Design intent
-------------
* ``event_id`` is the UUID of the originating security event, stored as an
  indexed UUID column (an implicit logical foreign key) — exactly as
  ``threat_intel_lookups.event_id`` and ``detection_results.event_id``.
* ``rule_id`` is the failed rule's ID, or the ``"<engine>"`` sentinel for
  engine-level failures (the Step 9E agent convention).
* ``provenance`` is CHECK-constrained to ``Provenance.DETECTED`` — a rule
  failure is an analytical outcome of the detection phase and can never be
  persisted as observed/enriched/reconstructed.
* ``error_message`` is secret-safe: the Step 9F-B persistence service
  sanitizes and bounds it before write.

This model defines the layout only.  The repository/service that persists a
``DetectionAnalysis`` (Step 9F-B) is **not** implemented here.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import CheckConstraint, DateTime, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.postgres.base import Base, UUIDTimestampMixin
from app.schemas.security_event import Provenance


class DetectionRuleFailure(UUIDTimestampMixin, Base):
    """A single persisted detection rule/engine failure.

    Attributes:
        event_id: UUID of the originating security event (indexed; becomes
            a real foreign key once an ``events`` model exists).
        engine: Engine that produced the failure (``"sigma"``/``"yara"``).
        rule_id: Failed rule ID, or ``"<engine>"`` for engine-level failures.
        error_type: Machine-readable failure category (e.g.
            ``"malformed_rule"``, ``"unsupported_feature"``,
            ``"invalid_target"``, ``"engine_error"``).
        error_message: Secret-safe, bounded human-readable failure text.
        failed_at: When the failure occurred (UTC, tz-aware).
        provenance: Evidence provenance, constrained to ``detected``.
    """

    __tablename__ = "detection_rule_failures"
    __table_args__ = (
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

    engine: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    rule_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )

    error_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    error_message: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Secret-safe human-readable error message.",
    )

    failed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    provenance: Mapped[str] = mapped_column(
        String(32),
        default=Provenance.DETECTED.value,
        nullable=False,
        comment=(
            "Evidence provenance.  Detection failures are analytical "
            "outcomes of the detection phase and are constrained to DETECTED "
            "by CHECK constraint."
        ),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<DetectionRuleFailure id={self.id} engine={self.engine!r} "
            f"rule_id={self.rule_id!r} event_id={self.event_id}>"
        )