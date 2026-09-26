"""Threat Hunting orchestration facade — V2.19.

``ThreatHuntService`` is the single governed entry point for the analyst
surface.  It owns the hunt lifecycle (create → run once → completed/failed,
or cancel a draft), executes the bounded engine inside a DB transaction,
persists the engine's artifacts, and returns read models.  Every transition
is audited.

Errors are raised as closed :mod:`.errors` types that the transport maps to
HTTP semantics; the only data written by a hunt are the hunt row, its
evidence/findings/timeline, and its audit trail.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.user import User
from app.repositories import threat_hunting as repo
from app.schemas.threat_hunting import (
    HUNT_DEFAULT_PAGE_SIZE,
    HUNT_MAX_PAGE_SIZE,
    HuntFilter,
    HuntType,
    ThreatHuntCreate,
    ThreatHuntDetail,
    ThreatHuntEvidencePage,
    ThreatHuntEvidenceRecord,
    ThreatHuntFindingPage,
    ThreatHuntFindingRecord,
    ThreatHuntPage,
    ThreatHuntStatus,
    ThreatHuntSummary,
    ThreatHuntTimelinePage,
    ThreatHuntTimelineItemRecord,
)
from app.services.audit_service import log_action

from .engine import ThreatHuntEngine
from .errors import (
    HuntAlreadyCancelledError,
    HuntAlreadyCompletedError,
    HuntAlreadyFailedError,
    HuntAlreadyRunningError,
    HuntExecutionError,
    HuntLimitError,
    HuntNotFoundError,
    HuntStateError,
    HuntUnexpectedError,
    HuntValidationError,
    sanitize,
)
from .grammar import compile_predicates


def _str_uuid(value: uuid.UUID) -> str:
    return str(value)


def _summary_from_row(row) -> ThreatHuntSummary:
    return ThreatHuntSummary(
        hunt_id=uuid.UUID(row.hunt_id),
        name=row.name,
        hunt_type=HuntType(row.hunt_type),
        status=ThreatHuntStatus(row.status),
        start_time=row.start_time,
        end_time=row.end_time,
        created_by=row.created_by,
        created_by_role=row.created_by_role,
        created_at=row.created_at,
        started_at=row.started_at,
        completed_at=row.completed_at,
        result_count=row.result_count,
        finding_count=row.finding_count,
        timeline_count=row.timeline_count,
        error_code=row.error_code,
        error_message=row.error_message,
    )


def _detail_from_row(row) -> ThreatHuntDetail:
    summary = _summary_from_row(row)
    raw_filters = list(row.filters or [])
    filters = [HuntFilter(**item) for item in raw_filters]
    return ThreatHuntDetail(
        **summary.model_dump(),
        description=row.description,
        filters=filters,
    )


class ThreatHuntService:
    """Create, run, inspect and cancel threat hunts (analyst-driven)."""

    @staticmethod
    def create(
        db: Session,
        actor: User,
        payload: ThreatHuntCreate,
    ) -> ThreatHuntDetail:
        role = actor.role.name if actor.role is not None else "unknown"
        hunt_id = uuid.uuid4()
        filters = [item.model_dump(mode="json") for item in payload.filters]
        row = repo.create_hunt(
            db,
            hunt_id=hunt_id,
            name=payload.name,
            description=payload.description,
            hunt_type=payload.hunt_type.value,
            start_time=payload.start_time,
            end_time=payload.end_time,
            created_by=actor.id,
            created_by_role=role,
            filters=filters,
        )
        db.commit()
        log_action(
            db,
            "threat_hunt.created",
            user_id=actor.id,
            resource="threat_hunts",
            details=f"Hunt '{payload.name}' ({payload.hunt_type.value}) created by {role}",
            ip_address=None,
        )
        return _detail_from_row(row)

    @staticmethod
    def list(
        db: Session,
        *,
        actor: User,  # noqa: ARG002
        page: int = 1,
        page_size: int = HUNT_DEFAULT_PAGE_SIZE,
        status_filter: ThreatHuntStatus | None = None,
        hunt_type_filter: HuntType | None = None,
    ) -> ThreatHuntPage:
        rows, total = repo.list_hunts(
            db,
            status=status_filter.value if status_filter else None,
            hunt_type=hunt_type_filter.value if hunt_type_filter else None,
            page=page,
            page_size=page_size,
        )
        return ThreatHuntPage(
            items=[_summary_from_row(r) for r in rows],
            total=total,
            page=max(1, page),
            page_size=min(max(1, page_size), HUNT_MAX_PAGE_SIZE),
            status_filter=status_filter,
            hunt_type_filter=hunt_type_filter,
        )

    @staticmethod
    def get(db: Session, *, actor: User, hunt_id: uuid.UUID) -> ThreatHuntDetail:  # noqa: ARG002
        row = repo.get_hunt(db, hunt_id)
        if row is None:
            raise HuntNotFoundError(f"Hunt {hunt_id} not found")
        return _detail_from_row(row)

    @staticmethod
    def run(db: Session, *, actor: User, hunt_id: uuid.UUID) -> ThreatHuntDetail:
        row = repo.get_hunt(db, hunt_id)
        if row is None:
            raise HuntNotFoundError(f"Hunt {hunt_id} not found")

        if not repo.cas_transition(db, hunt_id, ThreatHuntStatus.DRAFT, ThreatHuntStatus.RUNNING):
            current = ThreatHuntStatus(row.status)
            if current == ThreatHuntStatus.RUNNING:
                raise HuntAlreadyRunningError(f"Hunt {hunt_id} is already running")
            if current == ThreatHuntStatus.COMPLETED:
                raise HuntAlreadyCompletedError(f"Hunt {hunt_id} is already completed")
            if current == ThreatHuntStatus.FAILED:
                raise HuntAlreadyFailedError(f"Hunt {hunt_id} has already failed")
            if current == ThreatHuntStatus.CANCELLED:
                raise HuntAlreadyCancelledError(f"Hunt {hunt_id} is cancelled")
            raise HuntStateError(f"Hunt {hunt_id} is not runnable")

        started_at = datetime.now(timezone.utc)
        repo.stamp_run_started(db, hunt_id, started_at)
        db.flush()
        log_action(
            db,
            "threat_hunt.executed",
            user_id=actor.id,
            resource="threat_hunts",
            details=f"Run started for hunt '{row.name}'",
            ip_address=None,
        )

        filters = [HuntFilter(**item) for item in (row.filters or [])]
        try:
            predicates, _surfaces = compile_predicates(HuntType(row.hunt_type), filters)
        except Exception as exc:  # pragma: no cover - only stored validated filters
            raise HuntValidationError(sanitize(str(exc))) from exc

        engine = ThreatHuntEngine(db)
        try:
            result = engine.run(
                hunt_id=hunt_id,
                hunt_type=HuntType(row.hunt_type),
                start_time=row.start_time,
                end_time=row.end_time,
                predicates=predicates,
            )
        except HuntLimitError as exc:
            _fail(db, hunt_id, actor.id, "LIMITS_EXCEEDED", sanitize(str(exc)))
            raise HuntLimitError(sanitize(str(exc))) from exc
        except Exception as exc:  # including HuntExecutionError
            _fail(db, hunt_id, actor.id, "EXECUTION_FAILED", sanitize(str(exc)))
            raise HuntExecutionError(sanitize(str(exc))) from exc

        try:
            _persist_result(db, hunt_id, result)
        except Exception as exc:
            db.rollback()
            _fail(db, hunt_id, actor.id, "PERSISTENCE_FAILED", sanitize(str(exc)))
            raise HuntUnexpectedError("hunt artifacts could not be persisted") from exc

        db.commit()
        log_action(
            db,
            "threat_hunt.completed",
            user_id=actor.id,
            resource="threat_hunts",
            details=(
                f"Run completed: {result_count_label(result)}"
            ),
            ip_address=None,
        )
        updated = repo.get_hunt(db, hunt_id)
        return _detail_from_row(updated)  # type: ignore[arg-type]

    @staticmethod
    def cancel(db: Session, *, actor: User, hunt_id: uuid.UUID) -> ThreatHuntDetail:
        row = repo.get_hunt(db, hunt_id)
        if row is None:
            raise HuntNotFoundError(f"Hunt {hunt_id} not found")
        if not repo.cas_transition(
            db, hunt_id, ThreatHuntStatus.DRAFT, ThreatHuntStatus.CANCELLED
        ):
            current = ThreatHuntStatus(row.status)
            if current == ThreatHuntStatus.CANCELLED:
                raise HuntAlreadyCancelledError(f"Hunt {hunt_id} is already cancelled")
            raise HuntStateError(
                f"Hunt {hunt_id} is {current.value} and cannot be cancelled"
            )
        db.commit()
        log_action(
            db,
            "threat_hunt.cancelled",
            user_id=actor.id,
            resource="threat_hunts",
            details=f"Hunt '{row.name}' cancelled",
            ip_address=None,
        )
        updated = repo.get_hunt(db, hunt_id)
        return _detail_from_row(updated)  # type: ignore[arg-type]

    # ------------------------------------------------------------------
    # read pages
    # ------------------------------------------------------------------

    @staticmethod
    def list_evidence(
        db: Session,
        *,
        actor: User,  # noqa: ARG002
        hunt_id: uuid.UUID,
        page: int = 1,
        page_size: int = HUNT_DEFAULT_PAGE_SIZE,
    ) -> ThreatHuntEvidencePage:
        _require_exists(db, hunt_id)
        rows, total = repo.list_evidence(db, hunt_id, page=page, page_size=page_size)
        return ThreatHuntEvidencePage(
            items=[_evidence_record(r) for r in rows],
            total=total,
            page=max(1, page),
            page_size=page_size,
        )

    @staticmethod
    def list_findings(
        db: Session,
        *,
        actor: User,  # noqa: ARG002
        hunt_id: uuid.UUID,
        page: int = 1,
        page_size: int = HUNT_DEFAULT_PAGE_SIZE,
    ) -> ThreatHuntFindingPage:
        _require_exists(db, hunt_id)
        rows, total = repo.list_findings(db, hunt_id, page=page, page_size=page_size)
        return ThreatHuntFindingPage(
            items=[_finding_record(r) for r in rows],
            total=total,
            page=max(1, page),
            page_size=page_size,
        )

    @staticmethod
    def list_timeline(
        db: Session,
        *,
        actor: User,  # noqa: ARG002
        hunt_id: uuid.UUID,
        page: int = 1,
        page_size: int = HUNT_DEFAULT_PAGE_SIZE,
    ) -> ThreatHuntTimelinePage:
        _require_exists(db, hunt_id)
        rows, total = repo.list_timeline(db, hunt_id, page=page, page_size=page_size)
        return ThreatHuntTimelinePage(
            items=[_timeline_record(r) for r in rows],
            total=total,
            page=max(1, page),
            page_size=page_size,
        )


def result_count_label(result) -> str:
    return (
        f"{len(result.evidence)} evidence item(s), "
        f"{len(result.findings)} finding(s), "
        f"{len(result.timeline)} timeline item(s)"
    )


def _require_exists(db: Session, hunt_id: uuid.UUID) -> None:
    row = repo.get_hunt(db, hunt_id)
    if row is None:
        raise HuntNotFoundError(f"Hunt {hunt_id} not found")


def _fail(
    db: Session,
    hunt_id: uuid.UUID,
    user_id: uuid.UUID,
    code: str,
    message: str,
) -> None:
    repo.stamp_run_finished(
        db,
        hunt_id,
        target=ThreatHuntStatus.FAILED,
        completed_at=datetime.now(timezone.utc),
        result_count=0,
        finding_count=0,
        timeline_count=0,
        error_code=code,
        error_message=message,
    )
    log_action(
        db,
        f"threat_hunt.failed",
        user_id=user_id,
        resource="threat_hunts",
        details=f"Hunt {hunt_id} failed ({code}): {message}",
        ip_address=None,
    )
    db.commit()


def _persist_result(db: Session, hunt_id: uuid.UUID, result) -> None:
    evidence_rows = []
    for item in result.evidence:
        evidence_rows.append(
            {
                "hunt_id": str(hunt_id),
                "evidence_id": str(engine_id_from_key(hunt_id, item.key)),
                "evidence_key": item.key,
                "evidence_type": item.evidence_type,
                "reference_id": str(item.reference_id),
                "event_id": _str_uuid(item.event_id) if item.event_id else None,
                "correlation_id": _str_uuid(item.correlation_id) if item.correlation_id else None,
                "provenance": item.provenance,
                "severity": item.severity,
                "subject": item.subject,
                "observed_at": item.observed_at,
                "title": item.title,
                "summary": item.summary,
                "created_at": datetime.now(timezone.utc),
            }
        )
    finding_rows = []
    for item in result.findings:
        finding_rows.append(
            {
                "hunt_id": str(hunt_id),
                "finding_id": str(item.finding_id),
                "title": item.title,
                "description": item.description,
                "severity": item.severity,
                "provenance": item.provenance,
                "observed_at": item.observed_at,
                "evidence_ids": [str(uid) for uid in item.evidence_ids],
                "context": item.context,
                "created_at": datetime.now(timezone.utc),
            }
        )
    timeline_rows = []
    for item in result.timeline:
        timeline_rows.append(
            {
                "hunt_id": str(hunt_id),
                "timeline_item_id": str(item.timeline_item_id),
                "evidence_id": str(item.evidence_id),
                "reference_id": str(item.reference_id),
                "observed_at": item.observed_at,
                "evidence_type": item.evidence_type,
                "evidence_summary": item.evidence_summary,
                "provenance": item.provenance,
                "created_at": datetime.now(timezone.utc),
            }
        )
    repo.persist_artifacts(
        db,
        hunt_id=hunt_id,
        evidence=evidence_rows,
        findings=finding_rows,
        timeline_items=timeline_rows,
    )
    ended = datetime.now(timezone.utc)
    repo.stamp_run_finished(
        db,
        hunt_id,
        target=ThreatHuntStatus.COMPLETED,
        completed_at=ended,
        result_count=len(evidence_rows),
        finding_count=len(finding_rows),
        timeline_count=len(timeline_rows),
    )
    db.flush()


def engine_id_from_key(hunt_id: uuid.UUID, key: str) -> uuid.UUID:
    from .grammar import udid

    return udid(hunt_id, f"evidence:{key}")


def _evidence_record(row) -> ThreatHuntEvidenceRecord:
    return ThreatHuntEvidenceRecord(
        evidence_id=uuid.UUID(row.evidence_id),
        evidence_type=row.evidence_type,
        reference_id=uuid.UUID(row.reference_id),
        event_id=uuid.UUID(row.event_id) if row.event_id else None,
        correlation_id=uuid.UUID(row.correlation_id) if row.correlation_id else None,
        provenance=row.provenance,
        severity=row.severity,
        observed_at=row.observed_at,
        title=row.title,
        summary=row.summary,
    )


def _finding_record(row) -> ThreatHuntFindingRecord:
    return ThreatHuntFindingRecord(
        finding_id=uuid.UUID(row.finding_id),
        title=row.title,
        description=row.description,
        severity=row.severity,
        provenance=row.provenance,
        observed_at=row.observed_at,
        evidence_ids=[uuid.UUID(uid) for uid in (row.evidence_ids or [])],
        context=row.context or {},
    )


def _timeline_record(row) -> ThreatHuntTimelineItemRecord:
    return ThreatHuntTimelineItemRecord(
        timeline_item_id=uuid.UUID(row.timeline_item_id),
        evidence_id=uuid.UUID(row.evidence_id),
        observed_at=row.observed_at,
        evidence_type=row.evidence_type,
        evidence_summary=row.evidence_summary,
        provenance=row.provenance,
    )


__all__ = ["ThreatHuntService"]