"""Detection query service (Step 9G) — read-only retrieval over 9F persistence.

Provides validated, read-only access to persisted detection data without any
write surface: it composes :class:`DetectionRepository` reads and converts
rows into :mod:`app.schemas.detection_query` read models.  It is the layer a
future (Step 9I-era) read API will call — no endpoints are added here.

Design principles:

* **Read-only** — ``DetectionQueryService`` never calls ``add``/``delete``,
  ``flush``, ``commit``, or ``rollback``.  Callers own the session and its
  transaction; queries never mutate it.  (A failed read leaves the session
  untouched — the owner decides whether to roll back.)
* **Validated input** — detection/event UUIDs, rule IDs (non-empty, bounded),
  and page semantics are validated up front; invalid input raises
  :class:`DetectionQueryValidationError` before any database work.
* **Sanitized failures** — database errors surface as
  :class:`DetectionQueryError` with safe, consumer-facing messages.  Raw
  driver/SQL text is logged, never propagated.
* **Deterministic pages** — every list orders by ``detected_at``/``failed_at``
  descending with a stable secondary key, so page boundaries never drift.
* **No N+1** — :meth:`get_analysis_with_children` loads all child rows for an
  event with two bulk queries and composes them.

Pipeline::

    DetectionPersistenceService (9F-B writes, then commit)
        -> detection_results / detection_rule_failures
            -> DetectionQueryService (this module, read-only)
                -> DetectionResultRecord / FailureRecord / Analysis views
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy.orm import Session

from app.models.detection_result import DetectionResult as DetectionResultRow
from app.models.detection_rule_failure import (
    DetectionRuleFailure as DetectionRuleFailureRow,
)
from app.repositories.detection import DetectionRepository
from app.schemas.detection_query import (
    DetectionAnalysisRecord,
    DetectionAnalysisSummary,
    DetectionFailurePage,
    DetectionFailureRecord,
    DetectionResultPage,
    DetectionResultRecord,
)
from app.schemas.security_event import Provenance

logger = logging.getLogger(__name__)

#: Default page size for paginated reads (bounded offset pagination).
DEFAULT_PAGE_SIZE = 50

#: Hard cap on a single page; guards against unbounded result materialization.
MAX_PAGE_SIZE = 200

#: Default limit for the "recent results" feed.
DEFAULT_RECENT_LIMIT = 50

#: Hard cap on the "recent results" feed.
MAX_RECENT_LIMIT = 200

#: Max length of a rule ID accepted by rule-scoped queries (matches the model).
_MAX_RULE_ID_LENGTH = 255


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class DetectionQueryError(Exception):
    """Raised when a detection query cannot be satisfied.

    Instances never contain credentials, raw event payloads, raw rule
    content, raw database/SQL error text, or tracebacks — only safe
    contextual identifiers such as the event UUID.  The underlying exception
    is preserved as ``__cause__`` for server-side logging.
    """

    def __init__(self, event_id: uuid.UUID | None = None, reason: str = "") -> None:
        message = "Detection query failed"
        if event_id is not None:
            message += f" for event {event_id}"
        if reason:
            message += f": {reason}"
        super().__init__(message)
        self.event_id = event_id


class DetectionQueryValidationError(DetectionQueryError):
    """Raised when query input cannot be validated safely.

    Raised *before* any database work: malformed UUIDs, empty or oversized
    rule IDs, and out-of-bounds page/limit arguments all land here.
    """


# ---------------------------------------------------------------------------
# Validation + safe value helpers
# ---------------------------------------------------------------------------


def _as_utc(value: datetime | None) -> datetime | None:
    """Normalize a possibly-naive database instant to a tz-aware UTC value.

    SQLite stores ``DateTime(timezone=True)`` columns as naive UTC instants;
    PostgreSQL returns tz-aware values.  Normalizing at the read boundary
    gives consumers identical records on both backends.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _coerce_uuid(value: object, *, field: str) -> uuid.UUID:
    """Return *value* as a UUID, rejecting anything that is not one."""
    try:
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise DetectionQueryValidationError(
            reason=f"{field} must be a valid UUID"
        ) from exc


def _validate_rule_id(rule_id: object) -> str:
    """Return a trimmed, non-empty rule ID bounded to the model column size."""
    if not isinstance(rule_id, str):
        raise DetectionQueryValidationError(
            reason="rule_id must be a non-empty string"
        )
    rule_id = rule_id.strip()
    if not rule_id:
        raise DetectionQueryValidationError(reason="rule_id must not be empty")
    if len(rule_id) > _MAX_RULE_ID_LENGTH:
        raise DetectionQueryValidationError(
            reason=f"rule_id must not exceed {_MAX_RULE_ID_LENGTH} characters"
        )
    return rule_id


def _validate_page(page: object, page_size: object) -> tuple[int, int]:
    """Validate 1-based pagination arguments; return corrected integers."""
    try:
        page_int = int(page)
        page_size_int = int(page_size)
    except (TypeError, ValueError) as exc:
        raise DetectionQueryValidationError(
            reason="page and page_size must be integers"
        ) from exc
    if page_int < 1:
        raise DetectionQueryValidationError(reason="page must be >= 1")
    if page_size_int < 1:
        raise DetectionQueryValidationError(reason="page_size must be >= 1")
    if page_size_int > MAX_PAGE_SIZE:
        raise DetectionQueryValidationError(
            reason=f"page_size must not exceed {MAX_PAGE_SIZE}"
        )
    return page_int, page_size_int


def _validate_recent_limit(limit: object) -> int:
    """Validate the recent-results feed limit; return its integer value."""
    try:
        limit_int = int(limit)
    except (TypeError, ValueError) as exc:
        raise DetectionQueryValidationError(reason="limit must be an integer") from exc
    if limit_int < 1:
        raise DetectionQueryValidationError(reason="limit must be >= 1")
    if limit_int > MAX_RECENT_LIMIT:
        raise DetectionQueryValidationError(
            reason=f"limit must not exceed {MAX_RECENT_LIMIT}"
        )
    return limit_int


# ---------------------------------------------------------------------------
# Row -> read-model conversion (read boundary normalization)
# ---------------------------------------------------------------------------


def _to_result_record(row: DetectionResultRow) -> DetectionResultRecord:
    """Convert a persisted ``detection_results`` row into its read record."""
    return DetectionResultRecord(
        id=row.id,
        event_id=row.event_id,
        detection_id=row.detection_id,
        rule_id=row.rule_id,
        rule_type=row.rule_type,
        rule_version=row.rule_version,
        severity=row.severity,
        matched=row.matched,
        confidence=row.confidence,
        evidence=dict(row.evidence or {}),
        result_metadata=dict(row.result_metadata or {}),
        detected_at=_as_utc(row.detected_at),
        provenance=Provenance(row.provenance),
        created_at=_as_utc(row.created_at),
        updated_at=_as_utc(row.updated_at),
    )


def _to_failure_record(row: DetectionRuleFailureRow) -> DetectionFailureRecord:
    """Convert a persisted failure row into its read record."""
    return DetectionFailureRecord(
        id=row.id,
        event_id=row.event_id,
        engine=row.engine,
        rule_id=row.rule_id,
        error_type=row.error_type,
        error_message=row.error_message,
        failed_at=_as_utc(row.failed_at),
        provenance=Provenance(row.provenance),
        created_at=_as_utc(row.created_at),
        updated_at=_as_utc(row.updated_at),
    )
# ---------------------------------------------------------------------------
# Query service
# ---------------------------------------------------------------------------


class DetectionQueryService:
    """Read-only retrieval over the Step 9F persistence layer.

    Every method follows the persistence-service convention of receiving the
    caller-owned ``db`` session as the first argument::

        service = DetectionQueryService()
        record = service.get_result(db, detection_id)

    Read-only guarantee: this service never calls ``add``/``delete``,
    ``flush``, ``commit``, or ``rollback`` on the session.  It composes
    repository reads and converts rows to read models; callers own the
    transaction, and a session that hit a real database failure here should
    be rolled back by its owner.

    Args:
        repository_factory: Optional repository factory; defaults to
            :class:`DetectionRepository`.  Injected for testability.
    """

    def __init__(
        self,
        repository_factory: Callable[[Session], DetectionRepository] = DetectionRepository,
    ) -> None:
        self._repository_factory = repository_factory

    def _repo(self, db: Session) -> DetectionRepository:
        return self._repository_factory(db)

    @staticmethod
    def _db_error(
        exc: Exception,
        *,
        event_id: uuid.UUID | None = None,
        reason: str,
    ) -> DetectionQueryError:
        """Build a sanitized query error from a low-level failure.

        The raw exception is logged for operators; only the safe *reason*
        string reaches the consumer.
        """
        logger.warning(
            "Detection query failed (reason=%s, event=%s): %s",
            reason,
            event_id,
            exc,
        )
        return DetectionQueryError(event_id=event_id, reason=reason)

    # ------------------------------------------------------------------
    # Single result
    # ------------------------------------------------------------------

    def get_result(
        self,
        db: Session,
        detection_id: uuid.UUID | str,
    ) -> DetectionResultRecord | None:
        """Return the persisted match with *detection_id*, or ``None``."""
        detection_id = _coerce_uuid(detection_id, field="detection_id")
        try:
            row = self._repo(db).get_result_by_detection_id(detection_id)
        except DetectionQueryError:
            raise
        except Exception as exc:
            raise self._db_error(
                exc, reason="failed to load detection result"
            ) from exc
        return _to_result_record(row) if row is not None else None

    # ------------------------------------------------------------------
    # Results: event-scoped, rule-scoped, recent feed
    # ------------------------------------------------------------------

    def list_results_for_event(
        self,
        db: Session,
        event_id: uuid.UUID | str,
        *,
        page: int = 1,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> DetectionResultPage:
        """Return one bounded page of an event's persisted matches.

        Deterministic ordering: ``detected_at`` descending, ``detection_id``
        ascending as the tie-break.  ``total`` is the event's full match
        count (unaffected by pagination).
        """
        event_id = _coerce_uuid(event_id, field="event_id")
        page, page_size = _validate_page(page, page_size)
        repo = self._repo(db)
        try:
            total = repo.count_results_for_event(event_id)
            rows = repo.get_results_for_event(
                event_id, limit=page_size, offset=(page - 1) * page_size
            )
        except DetectionQueryError:
            raise
        except Exception as exc:
            raise self._db_error(
                exc, event_id=event_id, reason="failed to list detection results"
            ) from exc
        return DetectionResultPage(
            items=[_to_result_record(row) for row in rows],
            total=total,
            page=page,
            page_size=page_size,
        )

    def list_results_for_rule(
        self,
        db: Session,
        rule_id: str,
        *,
        page: int = 1,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> DetectionResultPage:
        """Return one bounded page of a rule's persisted matches.

        Deterministic ordering: ``detected_at`` descending, ``detection_id``
        ascending as the tie-break.  ``total`` is the rule's full match
        count (unaffected by pagination).
        """
        rule_id = _validate_rule_id(rule_id)
        page, page_size = _validate_page(page, page_size)
        repo = self._repo(db)
        try:
            total = repo.count_results_for_rule(rule_id)
            rows = repo.get_results_for_rule(
                rule_id, limit=page_size, offset=(page - 1) * page_size
            )
        except DetectionQueryError:
            raise
        except Exception as exc:
            raise self._db_error(
                exc, reason="failed to list detection results"
            ) from exc
        return DetectionResultPage(
            items=[_to_result_record(row) for row in rows],
            total=total,
            page=page,
            page_size=page_size,
        )
    def list_recent_results(
        self,
        db: Session,
        *,
        limit: int = DEFAULT_RECENT_LIMIT,
    ) -> list[DetectionResultRecord]:
        """Return up to *limit* newest persisted matches across all events.

        A bounded feed (not paginated), mirroring the threat-intel
        ``get_recent_lookups`` convention.  Ordering is deterministic:
        ``detected_at`` descending, ``detection_id`` ascending.
        """
        limit = _validate_recent_limit(limit)
        try:
            rows = self._repo(db).list_recent_results(limit=limit)
        except DetectionQueryError:
            raise
        except Exception as exc:
            raise self._db_error(
                exc, reason="failed to list recent detection results"
            ) from exc
        return [_to_result_record(row) for row in rows]

    # ------------------------------------------------------------------
    # Failures (event-scoped = "the event's analysis failures")
    # ------------------------------------------------------------------

    def list_failures_for_analysis(
        self,
        db: Session,
        event_id: uuid.UUID | str,
        *,
        page: int = 1,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> DetectionFailurePage:
        """Return one bounded page of the event's persisted failures.

        An "analysis" is event-scoped in the persistence contract; this
        returns every rule/engine failure recorded for *event_id*.
        Deterministic ordering: ``failed_at`` descending, row id ascending.
        """
        event_id = _coerce_uuid(event_id, field="event_id")
        page, page_size = _validate_page(page, page_size)
        repo = self._repo(db)
        try:
            total = repo.count_failures_for_event(event_id)
            rows = repo.get_failures_for_event(
                event_id, limit=page_size, offset=(page - 1) * page_size
            )
        except DetectionQueryError:
            raise
        except Exception as exc:
            raise self._db_error(
                exc, event_id=event_id, reason="failed to list detection failures"
            ) from exc
        return DetectionFailurePage(
            items=[_to_failure_record(row) for row in rows],
            total=total,
            page=page,
            page_size=page_size,
        )

    # ------------------------------------------------------------------
    # Event analysis views
    # ------------------------------------------------------------------

    def get_analysis(
        self,
        db: Session,
        event_id: uuid.UUID | str,
    ) -> DetectionAnalysisSummary | None:
        """Return the aggregate summary of the event's analysis, or ``None``.

        Two aggregate queries (count + time windows per table); child rows
        are not loaded.  Returns ``None`` when the event has neither results
        nor failures recorded.
        """
        event_id = _coerce_uuid(event_id, field="event_id")
        repo = self._repo(db)
        try:
            results = repo.get_results_overview(event_id)
            failures = repo.get_failures_overview(event_id)
        except DetectionQueryError:
            raise
        except Exception as exc:
            raise self._db_error(
                exc, event_id=event_id, reason="failed to load detection analysis"
            ) from exc
        if results.count == 0 and failures.count == 0:
            return None
        return DetectionAnalysisSummary(
            event_id=event_id,
            result_count=results.count,
            failure_count=failures.count,
            first_detected_at=_as_utc(results.first_detected_at),
            last_detected_at=_as_utc(results.last_detected_at),
            first_failed_at=_as_utc(failures.first_failed_at),
            last_failed_at=_as_utc(failures.last_failed_at),
        )

    def get_analysis_with_children(
        self,
        db: Session,
        event_id: uuid.UUID | str,
    ) -> DetectionAnalysisRecord | None:
        """Return the full event analysis including all child records.

        Children are eager-loaded with two bulk queries (all results, all
        failures) and composed — never one query per child, so there is no
        N+1.  Returns ``None`` when the event has neither results nor
        failures recorded.
        """
        event_id = _coerce_uuid(event_id, field="event_id")
        repo = self._repo(db)
        try:
            results = repo.get_results_overview(event_id)
            failures = repo.get_failures_overview(event_id)
            result_rows = repo.get_results_for_event(event_id)
            failure_rows = repo.get_failures_for_event(event_id)
        except DetectionQueryError:
            raise
        except Exception as exc:
            raise self._db_error(
                exc, event_id=event_id, reason="failed to load detection analysis"
            ) from exc
        if results.count == 0 and failures.count == 0:
            return None
        return DetectionAnalysisRecord(
            event_id=event_id,
            result_count=results.count,
            failure_count=failures.count,
            first_detected_at=_as_utc(results.first_detected_at),
            last_detected_at=_as_utc(results.last_detected_at),
            first_failed_at=_as_utc(failures.first_failed_at),
            last_failed_at=_as_utc(failures.last_failed_at),
            results=[_to_result_record(row) for row in result_rows],
            failures=[_to_failure_record(row) for row in failure_rows],
        )