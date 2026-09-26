"""Incident Report service facade (V2.20) — persistence, audit, read models.

``IncidentReportService`` is the single governed entry point for the report
surface.  It owns:

* **generation** — audit ``generated_requested``, run the read-only generator,
  persist exactly one new report row, audit ``generated_succeeded``;
* **failed-row persistence** — every terminal failure (except a missing
  correlation) persists a ``failed`` row carrying a sanitized
  ``error_code`` / ``error_message`` and audits ``generated_failed``, so a
  refusal is auditable without ever presenting partial content as a report;
* **reads** — deterministic detail and list read models.

Errors are raised as the closed :mod:`app.services.reporting.errors`
hierarchy; the transport maps them to HTTP semantics.  The service never
executes policy/approvals/SOAR and never mutates security state.

Audit ordering note: ``log_action`` commits immediately, so the report row is
committed first and then audited; a failed audit-log write can never roll
back a successfully persisted row.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy.orm import Session

from app.models.incident_report import IncidentReportRow
from app.models.user import User
from app.repositories.incident_report import IncidentReportRepository
from app.schemas.incident_report import (
    DEFAULT_REPORT_PAGE_SIZE,
    MAX_REPORT_ERROR_CODE_LENGTH,
    MAX_REPORT_PAGE_SIZE,
    IncidentReport,
    IncidentReportPage,
    IncidentReportRecord,
    IncidentReportSummary,
    ReportStatus,
)
from app.services.audit_service import log_action

from .errors import (
    IncidentReportError,
    ReportCorrelationNotFoundError,
    ReportNotFoundError,
    ReportUnexpectedError,
    sanitize,
)
from .generator import IncidentReportGenerator

logger = logging.getLogger(__name__)


def _as_utc(value: datetime | None) -> datetime | None:
    """Normalize a possibly-naive DB instant to tz-aware UTC (both backends)."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _role_of(actor: User) -> str:
    return actor.role.name if actor.role is not None else "unknown"


def _summary_from_row(row: IncidentReportRow) -> IncidentReportSummary:
    return IncidentReportSummary(
        report_id=uuid.UUID(row.report_id),
        correlation_id=uuid.UUID(row.correlation_id),
        status=ReportStatus(row.status),
        title=row.title,
        model=row.model,
        generated_by=row.generated_by,
        generated_by_role=row.generated_by_role,
        generated_at=_as_utc(row.generated_at),
        error_code=row.error_code,
        error_message=row.error_message,
        created_at=_as_utc(row.created_at),
        updated_at=_as_utc(row.updated_at),
    )


def _record_from_row(row: IncidentReportRow) -> IncidentReportRecord:
    payload: IncidentReport | None = None
    if row.status == ReportStatus.GENERATED.value and row.payload is not None:
        try:
            payload = IncidentReport.model_validate(row.payload)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Stored report payload failed validation: %s", type(exc).__name__)
            raise ReportUnexpectedError(
                "the persisted report payload could not be read back"
            ) from exc
    return IncidentReportRecord(
        **_summary_from_row(row).model_dump(),
        payload=payload,
    )


class IncidentReportService:
    """Generate, retrieve and list incident reports (governed surface)."""

    def __init__(
        self,
        *,
        generator_factory: Callable[[], IncidentReportGenerator] | None = None,
        repository_factory: Callable[
            [Session], IncidentReportRepository
        ] = IncidentReportRepository,
    ) -> None:
        self._generator_factory = generator_factory or (
            lambda: IncidentReportGenerator()
        )
        self._repository_factory = repository_factory

    # ------------------------------------------------------------------
    # Generation
    # ------------------------------------------------------------------

    def generate(
        self,
        db: Session,
        *,
        actor: User,
        correlation_id: uuid.UUID,
    ) -> IncidentReportRecord:
        """Generate and persist one new report row for *correlation_id*.

        Raises:
            ReportCorrelationNotFoundError: the correlation does not exist
                (no failed row is persisted).
            IncidentReportError subclasses: the attempt failed and a
                ``failed`` row was persisted (sanitized error carried).
        """
        role = _role_of(actor)
        log_action(
            db,
            "incident_report.generated_requested",
            user_id=actor.id,
            resource="incident_reports",
            details=(
                f"Report generation requested for correlation "
                f"{correlation_id} by {role}"
            ),
            ip_address=None,
        )

        marker = _ReportRowMarker(db, self._repository_factory(db))

        try:
            generator = self._generator_factory()
            report = generator.generate(
                db, actor=actor, correlation_id=correlation_id
            )
        except ReportCorrelationNotFoundError:
            log_action(
                db,
                "incident_report.generated_failed",
                user_id=actor.id,
                resource="incident_reports",
                details=(
                    f"Report generation failed (CORRELATION_NOT_FOUND) for "
                    f"correlation {correlation_id} — no report row persisted"
                ),
                ip_address=None,
            )
            raise
        except IncidentReportError as exc:
            marker.persist_failed(
                correlation_id=correlation_id,
                actor=actor,
                role=role,
                code=exc.code,
                message=sanitize(str(exc)),
            )
            log_action(
                db,
                "incident_report.generated_failed",
                user_id=actor.id,
                resource="incident_reports",
                details=(
                    f"Report generation failed for correlation "
                    f"{correlation_id} ({exc.code}): {sanitize(str(exc))}"
                ),
                ip_address=None,
            )
            raise
        except Exception as exc:  # unexpected internal defect — fail closed
            logger.warning(
                "Report generation internal failure (correlation=%s): %s",
                correlation_id,
                type(exc).__name__,
            )
            marker.persist_failed(
                correlation_id=correlation_id,
                actor=actor,
                role=role,
                code=ReportUnexpectedError.code,
                message=sanitize(str(exc)),
            )
            log_action(
                db,
                "incident_report.generated_failed",
                user_id=actor.id,
                resource="incident_reports",
                details=(
                    f"Report generation failed for correlation "
                    f"{correlation_id} (REPORT_INTERNAL)"
                ),
                ip_address=None,
            )
            raise ReportUnexpectedError(
                "incident report generation failed internally"
            ) from exc

        marker.persist_generated(
            correlation_id=correlation_id,
            actor=actor,
            role=role,
            report=report,
        )
        log_action(
            db,
            "incident_report.generated_succeeded",
            user_id=actor.id,
            resource="incident_reports",
            details=(
                f"Report {report.report_id} generated for correlation "
                f"{correlation_id} by {role} using {report.model}"
            ),
            ip_address=None,
        )
        return _record_from_row(
            marker.last_row(
                "the generated report row could not be read back"
            )
        )

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def get(
        self,
        db: Session,
        *,
        report_id: uuid.UUID,
    ) -> IncidentReportRecord:
        """Return the persisted report for *report_id*."""
        row = self._repository_factory(db).get_by_report_id(report_id)
        if row is None:
            raise ReportNotFoundError(f"Report {report_id} not found")
        return _record_from_row(row)

    def list(
        self,
        db: Session,
        *,
        page: int = 1,
        page_size: int = DEFAULT_REPORT_PAGE_SIZE,
        correlation_id: uuid.UUID | None = None,
    ) -> IncidentReportPage:
        """Return one deterministic page of report summaries, newest first."""
        normalized_page = max(1, page)
        normalized_size = min(max(1, page_size), MAX_REPORT_PAGE_SIZE)
        repo = self._repository_factory(db)
        total = repo.count_reports(correlation_id=correlation_id)
        rows = repo.list_reports(
            limit=normalized_size,
            offset=(normalized_page - 1) * normalized_size,
            correlation_id=correlation_id,
        )
        return IncidentReportPage(
            items=[_summary_from_row(row) for row in rows],
            total=total,
            page=normalized_page,
            page_size=normalized_size,
            correlation_id=correlation_id,
        )


class _ReportRowMarker:
    """Stages + commits report rows; small helper so the service stays thin.

    Guards against re-introducing partial content as a report: a failed row
    is committed only with a sanitized error and never a payload.
    """

    def __init__(self, db: Session, repo: IncidentReportRepository) -> None:
        self.db = db
        self.repo = repo
        self._last_row: IncidentReportRow | None = None

    def persist_failed(
        self,
        *,
        correlation_id: uuid.UUID,
        actor: User,
        role: str,
        code: str,
        message: str,
    ) -> None:
        row = IncidentReportRow(
            report_id=str(uuid.uuid4()),
            correlation_id=str(correlation_id),
            status=ReportStatus.FAILED.value,
            generated_by=actor.id,
            generated_by_role=role,
            error_code=code[:MAX_REPORT_ERROR_CODE_LENGTH],
            error_message=message,
        )
        self.repo.add(row)
        self.db.commit()
        self.db.refresh(row)
        self._last_row = row

    def persist_generated(
        self,
        *,
        correlation_id: uuid.UUID,
        actor: User,
        role: str,
        report: IncidentReport,
    ) -> None:
        row = IncidentReportRow(
            report_id=str(report.report_id),
            correlation_id=str(correlation_id),
            status=ReportStatus.GENERATED.value,
            payload=report.model_dump(mode="json"),
            title=report.ai.title,
            model=report.model,
            generated_by=actor.id,
            generated_by_role=role,
            generated_at=report.generated_at,
        )
        self.repo.add(row)
        self.db.commit()
        self.db.refresh(row)
        self._last_row = row

    def last_row(self, missing_message: str) -> IncidentReportRow:
        """Return the row this marker last persisted; fail closed if lost."""
        if self._last_row is None:
            raise ReportUnexpectedError(missing_message)
        return self._last_row


__all__ = ["IncidentReportService"]