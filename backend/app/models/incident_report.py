"""Incident Report persistence model — V2.20.

``incident_reports`` is the single write surface of the AI Incident Report
Generator — every generation produces exactly one new row:

* ``generated`` rows carry the full:class:`~app.schemas.incident_report.IncidentReport`
  payload (JSONB) verbatim plus denormalized summary columns (title, model,
  generated_at);
* ``failed`` rows carry only a sanitized ``error_code`` / ``error_message``
  and never a payload, so a failed generation is auditable but never
  presents partial content as a report.

Contract rules honoured here:

* ``report_id`` is unique (the row PK); ``correlation_id`` is an **indexed
  plain UUID reference with no foreign key** — a report must outlive the
  correlation lifecycle it cites (mirrors the incident-memory / approval
  convention).
* A new report is generated on every request; there is no update path for
  an existing report row.
* ``status`` is CHECK-pinned to ``generated`` | ``failed``; a generated row
  always has a payload and a failed row always has an error.
* The table is append-only from the service's perspective; nothing here ever
  executes policy, approvals or SOAR.

This model defines the layout only; the repository/service that drives it is
implemented in ``app/repositories/incident_report.py`` and
``app/services/reporting/service.py``.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database.postgres.base import Base
from app.schemas.incident_report import (
    MAX_REPORT_ERROR_CODE_LENGTH,
    MAX_REPORT_ERROR_MESSAGE_LENGTH,
    MAX_REPORT_TITLE_LENGTH,
)

_UUID36 = String(36)


class IncidentReportRow(Base):
    """One persisted incident report attempt (generated or failed)."""

    __tablename__ = "incident_reports"
    __table_args__ = (
        CheckConstraint(
            "status IN ('generated', 'failed')",
            name="status_allowed",
        ),
        CheckConstraint(
            "(status = 'generated') = (payload IS NOT NULL)",
            name="generated_has_payload",
        ),
        CheckConstraint(
            "(status = 'failed') = (error_code IS NOT NULL)",
            name="failed_has_error",
        ),
    )

    report_id: Mapped[str] = mapped_column(
        _UUID36,
        primary_key=True,
        default=lambda: str(_uuid.uuid4()),
        comment="Unique identity of the report row.",
    )
    correlation_id: Mapped[str] = mapped_column(
        _UUID36,
        nullable=False,
        index=True,
        comment=(
            "The correlation the report anchors to.  Deliberately a plain "
            "UUID with NO foreign key: a report must outlive the correlation "
            "lifecycle it cites (mirrors the incident-memory convention)."
        ),
    )
    status: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="generated",
        comment="generated / failed (CHECK-pinned).",
    )
    payload: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        comment=(
            "The full assembled IncidentReport payload (JSONB).  Present "
            "only for generated rows; failed rows never carry partial "
            "content."
        ),
    )
    title: Mapped[str | None] = mapped_column(
        String(MAX_REPORT_TITLE_LENGTH),
        nullable=True,
        comment="Generated title (generated rows only).",
    )
    model: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        comment="Model identifier used (generated rows only).",
    )
    generated_by: Mapped[_uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        comment="Trusted identity that generated the report.",
    )
    generated_by_role: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="Role label of the generating actor.",
    )
    generated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Completion instant (generated rows only).",
    )
    error_code: Mapped[str | None] = mapped_column(
        String(MAX_REPORT_ERROR_CODE_LENGTH),
        nullable=True,
        comment="Sanitized structured error code (failed rows only).",
    )
    error_message: Mapped[str | None] = mapped_column(
        String(MAX_REPORT_ERROR_MESSAGE_LENGTH),
        nullable=True,
        comment="Sanitized human-readable failure reason (failed rows only).",
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

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<IncidentReportRow report_id={self.report_id} "
            f"correlation_id={self.correlation_id} status={self.status}>"
        )


__all__ = ["IncidentReportRow"]