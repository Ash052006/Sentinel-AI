"""Incident Report persistence repository (V2.20).

Data-access layer for :class:`~app.models.incident_report.IncidentReportRow`.

Contract rules honoured here:

* The repository does **not** commit.  Transaction boundaries are owned by
  the reporting service so one generation (or failure row) commits atomically
  with its audit trail.
* Reads are deterministic: every list orders by ``created_at`` descending
  with ``report_id`` ascending as the two-key tie-break so page boundaries
  never drift; an optional ``correlation_id`` filter echoes the list call.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.incident_report import IncidentReportRow


class IncidentReportRepository:
    """Data-access layer for incident report rows."""

    def __init__(self, db: Session) -> None:
        self.db = db

    # ------------------------------------------------------------------
    # Generic
    # ------------------------------------------------------------------

    def add(self, entity: IncidentReportRow) -> None:
        """Stage *entity* for insertion.  The caller owns the transaction."""
        self.db.add(entity)

    # ------------------------------------------------------------------
    # Identity reads
    # ------------------------------------------------------------------

    def get_by_report_id(self, report_id: uuid.UUID) -> IncidentReportRow | None:
        """Return the persisted report for *report_id*, if any."""
        return self.db.scalar(
            select(IncidentReportRow).where(
                IncidentReportRow.report_id == str(report_id)
            )
        )

    # ------------------------------------------------------------------
    # List reads
    # ------------------------------------------------------------------

    def count_reports(
        self,
        *,
        correlation_id: uuid.UUID | None = None,
    ) -> int:
        """Return the number of reports, optionally *correlation_id*-filtered."""
        stmt = select(func.count()).select_from(IncidentReportRow)
        if correlation_id is not None:
            stmt = stmt.where(
                IncidentReportRow.correlation_id == str(correlation_id)
            )
        return int(self.db.scalar(stmt) or 0)

    def list_reports(
        self,
        *,
        limit: int,
        offset: int,
        correlation_id: uuid.UUID | None = None,
    ) -> list[IncidentReportRow]:
        """Return one deterministic page of reports, newest first."""
        stmt = (
            select(IncidentReportRow)
            .order_by(
                IncidentReportRow.created_at.desc(),
                IncidentReportRow.report_id.asc(),
            )
            .limit(limit)
            .offset(offset)
        )
        if correlation_id is not None:
            stmt = stmt.where(
                IncidentReportRow.correlation_id == str(correlation_id)
            )
        return list(self.db.scalars(stmt))


__all__ = ["IncidentReportRepository"]