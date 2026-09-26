"""Correlation membership persistence model (Step 10C-A).

The persistence contract for one member of a persisted Step 10A
:class:`~app.schemas.correlation.CorrelationResult`.

Design intent
-------------
* A member is a **reference**, never a copy of the detection record:
  ``detection_id`` / ``event_id`` / ``timestamp`` are Step 10A
  ``CorrelationMember`` values preserved exactly, and SentinelAI does
  **not** store duplicated ``DetectionResult`` rows here.
* ``member_order`` preserves the Step 10A ``CorrelationResult.members``
  order exactly; the unique constraint ``(correlation_id, member_order)``
  guards against duplicate/out-of-order members within one correlation.
* ``correlation_id`` is a real foreign key back to
  :class:`~app.models.correlation_result.CorrelationResult`
  (``correlation_results.correlation_id``); deleting a correlation
  cascades to its member rows.

This model defines the layout only.  Members are persisted by the Step
10C-B repository/service together with their parent correlation.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKeyConstraint, Integer, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.postgres.base import Base, UUIDTimestampMixin


class CorrelationMember(UUIDTimestampMixin, Base):
    """One detection reference belonging to a persisted correlation.

    Attributes:
        correlation_id: Step 10A ``CorrelationResult.correlation_id`` —
            foreign key to ``correlation_results``.
        detection_id: Exact identity of the referenced detection.
        event_id: Exact identity of the referenced source security event.
        timestamp: The member detection's own evaluation timestamp.
        member_order: 0-based position of the member within the
            correlation, preserving Step 10A member order.
    """

    __tablename__ = "correlation_members"
    __table_args__ = (
        UniqueConstraint(
            "correlation_id",
            "member_order",
            name="uq_correlation_members_correlation_order",
        ),
        ForeignKeyConstraint(
            ["correlation_id"],
            ["correlation_results.correlation_id"],
            name="fk_correlation_members_correlation_id_correlation_results",
            ondelete="CASCADE",
        ),
    )

    correlation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        comment=(
            "Step 10A CorrelationResult.correlation_id.  Identifies the "
            "parent correlation; deleted with it (ON DELETE CASCADE)."
        ),
    )

    detection_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment=(
            "Exact identity of the referenced detection.  A reference, not "
            "a copy of the DetectionResult record."
        ),
    )

    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment=(
            "Exact identity of the source security event for the member "
            "detection.  Preserved; never replaced with a correlation/"
            "incident/alert identifier."
        ),
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment=(
            "The member detection's own evaluation timestamp (Step 10A "
            "member timestamp).  A descriptive temporal boundary, not "
            "correlation evidence."
        ),
    )

    member_order: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment=(
            "0-based position of the member within the correlation.  "
            "Preserves the Step 10A members order exactly."
        ),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<CorrelationMember id={self.id} "
            f"detection_id={self.detection_id} "
            f"event_id={self.event_id} order={self.member_order}>"
        )