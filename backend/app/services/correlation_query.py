"""Correlation query service (Step 10D) — read-only retrieval over 10C persistence.

Provides validated, read-only access to persisted correlation data without any
write surface: it composes :class:`CorrelationRepository` reads and converts
rows into :mod:`app.schemas.correlation_query` read models.  It is the layer a
future correlation read API will call — no endpoints are added here.

Design principles:

* **Read-only** — ``CorrelationQueryService`` never calls ``add``/``delete``,
  ``flush``, ``commit``, or ``rollback``.  Callers own the session and its
  transaction; queries never mutate it.  (A failed read leaves the session
  untouched — the owner decides whether to roll back.)
* **Validated input** — correlation/detection/event UUIDs and page semantics
  are validated up front; invalid input raises
  :class:`CorrelationQueryValidationError` before any database work.
* **Sanitized failures** — database errors surface as
  :class:`CorrelationQueryError` with safe, consumer-facing messages.  Raw
  driver/SQL text is logged, never propagated.
* **Deterministic pages** — every list orders by ``timestamp`` descending
  with a stable secondary key (``correlation_id`` ascending), so page
  boundaries never drift.
* **No N+1** — pages and details embed their members from one bulk member
  query, never one query per correlation.

Pipeline::

    CorrelationPersistenceService (10C writes, then commit)
        -> correlation_results / correlation_members
            -> CorrelationQueryService (this module, read-only)
                -> CorrelationResultRecord / CorrelationPage
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy.orm import Session

from app.models.correlation_member import CorrelationMember as CorrelationMemberRow
from app.models.correlation_result import CorrelationResult as CorrelationResultRow
from app.repositories.correlation import CorrelationRepository
from app.schemas.correlation_query import (
    CorrelationMemberRecord,
    CorrelationPage,
    CorrelationResultRecord,
)
from app.schemas.security_event import Provenance

logger = logging.getLogger(__name__)

#: Default page size for paginated reads (bounded offset pagination).
DEFAULT_PAGE_SIZE = 50

#: Hard cap on a single page; guards against unbounded result materialization.
MAX_PAGE_SIZE = 200

#: Default limit for the "recent correlations" feed.
DEFAULT_RECENT_LIMIT = 50

#: Hard cap on the "recent correlations" feed.
MAX_RECENT_LIMIT = 200


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class CorrelationQueryError(Exception):
    """Raised when a correlation query cannot be satisfied.

    Instances never contain credentials, raw evidence, raw event payloads,
    raw database/SQL error text, or tracebacks — only safe contextual
    identifiers such as the correlation UUID.  The underlying exception is
    preserved as ``__cause__`` for server-side logging.
    """

    def __init__(
        self,
        correlation_id: uuid.UUID | None = None,
        reason: str = "",
    ) -> None:
        message = "Correlation query failed"
        if correlation_id is not None:
            message += f" for correlation {correlation_id}"
        if reason:
            message += f": {reason}"
        super().__init__(message)
        self.correlation_id = correlation_id


class CorrelationQueryValidationError(CorrelationQueryError):
    """Raised when query input cannot be validated safely.

    Raised *before* any database work: malformed UUIDs and out-of-bounds
    page/limit arguments all land here.
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
        raise CorrelationQueryValidationError(
            reason=f"{field} must be a valid UUID"
        ) from exc


def _validate_page(page: object, page_size: object) -> tuple[int, int]:
    """Validate 1-based pagination arguments; return corrected integers."""
    try:
        page_int = int(page)
        page_size_int = int(page_size)
    except (TypeError, ValueError) as exc:
        raise CorrelationQueryValidationError(
            reason="page and page_size must be integers"
        ) from exc
    if page_int < 1:
        raise CorrelationQueryValidationError(reason="page must be >= 1")
    if page_size_int < 1:
        raise CorrelationQueryValidationError(reason="page_size must be >= 1")
    if page_size_int > MAX_PAGE_SIZE:
        raise CorrelationQueryValidationError(
            reason=f"page_size must not exceed {MAX_PAGE_SIZE}"
        )
    return page_int, page_size_int


def _validate_recent_limit(limit: object) -> int:
    """Validate the recent-correlations feed limit; return its integer value."""
    try:
        limit_int = int(limit)
    except (TypeError, ValueError) as exc:
        raise CorrelationQueryValidationError(reason="limit must be an integer") from exc
    if limit_int < 1:
        raise CorrelationQueryValidationError(reason="limit must be >= 1")
    if limit_int > MAX_RECENT_LIMIT:
        raise CorrelationQueryValidationError(
            reason=f"limit must not exceed {MAX_RECENT_LIMIT}"
        )
    return limit_int


# ---------------------------------------------------------------------------
# Row -> read-model conversion (read boundary normalization)
# ---------------------------------------------------------------------------


def _to_member_record(row: CorrelationMemberRow) -> CorrelationMemberRecord:
    """Convert a persisted ``correlation_members`` row into its read record."""
    return CorrelationMemberRecord(
        id=row.id,
        correlation_id=row.correlation_id,
        detection_id=row.detection_id,
        event_id=row.event_id,
        timestamp=_as_utc(row.timestamp),
        member_order=row.member_order,
        created_at=_as_utc(row.created_at),
        updated_at=_as_utc(row.updated_at),
    )


def _to_result_record(
    row: CorrelationResultRow,
    members: list[CorrelationMemberRow],
) -> CorrelationResultRecord:
    """Convert a persisted ``correlation_results`` row (plus its members)
    into its full read record."""
    return CorrelationResultRecord(
        id=row.id,
        correlation_id=row.correlation_id,
        status=row.status,
        confidence=row.confidence,
        evidence=dict(row.evidence or {}),
        result_metadata=dict(row.result_metadata or {}),
        timestamp=_as_utc(row.timestamp),
        provenance=Provenance(row.provenance),
        members=[_to_member_record(member) for member in members],
        created_at=_as_utc(row.created_at),
        updated_at=_as_utc(row.updated_at),
    )


# ---------------------------------------------------------------------------
# Query service
# ---------------------------------------------------------------------------


class CorrelationQueryService:
    """Read-only retrieval over the Step 10C persistence layer.

    Every method follows the persistence-service convention of receiving the
    caller-owned ``db`` session as the first argument::

        service = CorrelationQueryService()
        record  = service.get_correlation(db, correlation_id)

    Read-only guarantee: this service never calls ``add``/``delete``,
    ``flush``, ``commit``, or ``rollback`` on the session.  It composes
    repository reads and converts rows to read models; callers own the
    transaction, and a session that hit a real database failure here should
    be rolled back by its owner.

    Args:
        repository_factory: Optional repository factory; defaults to
            :class:`CorrelationRepository`.  Injected for testability.
    """

    def __init__(
        self,
        repository_factory: Callable[[Session], CorrelationRepository] = CorrelationRepository,
    ) -> None:
        self._repository_factory = repository_factory

    def _repo(self, db: Session) -> CorrelationRepository:
        return self._repository_factory(db)

    @staticmethod
    def _db_error(
        exc: Exception,
        *,
        correlation_id: uuid.UUID | None = None,
        reason: str,
    ) -> CorrelationQueryError:
        """Build a sanitized query error from a low-level failure.

        The raw exception is logged for operators; only the safe *reason*
        string reaches the consumer.
        """
        logger.warning(
            "Correlation query failed (reason=%s, correlation=%s): %s",
            reason,
            correlation_id,
            exc,
        )
        return CorrelationQueryError(correlation_id=correlation_id, reason=reason)

    # ------------------------------------------------------------------
    # Correlation detail
    # ------------------------------------------------------------------

    def get_correlation(
        self,
        db: Session,
        correlation_id: uuid.UUID | str,
    ) -> CorrelationResultRecord | None:
        """Return the persisted correlation with *correlation_id*, or ``None``.

        Unknown IDs produce a controlled not-found result (``None``), never
        an error.  Members are embedded in persisted ``member_order``.
        """
        correlation_id = _coerce_uuid(correlation_id, field="correlation_id")
        repo = self._repo(db)
        try:
            row = repo.get_by_correlation_id(correlation_id)
            members = (
                repo.get_members_for_correlation(correlation_id)
                if row is not None
                else []
            )
        except CorrelationQueryError:
            raise
        except Exception as exc:
            raise self._db_error(
                exc,
                correlation_id=correlation_id,
                reason="failed to load correlation",
            ) from exc
        if row is None:
            return None
        return _to_result_record(row, members)

    # ------------------------------------------------------------------
    # Correlations: detection-scoped, event-scoped, recent feed
    # ------------------------------------------------------------------

    def list_correlations_for_detection(
        self,
        db: Session,
        detection_id: uuid.UUID | str,
        *,
        page: int = 1,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> CorrelationPage:
        """Return one bounded page of correlations referencing *detection_id*.

        Each correlation appears at most once regardless of how many of its
        members reference the detection (membership follows persisted rows).
        Deterministic ordering: ``timestamp`` descending, ``correlation_id``
        ascending.  ``total`` is the distinct correlation count for the
        detection (unaffected by pagination).
        """
        detection_id = _coerce_uuid(detection_id, field="detection_id")
        page, page_size = _validate_page(page, page_size)
        repo = self._repo(db)
        try:
            total = repo.count_correlations_for_detection(detection_id)
            rows = repo.list_correlations_for_detection(
                detection_id, limit=page_size, offset=(page - 1) * page_size
            )
        except CorrelationQueryError:
            raise
        except Exception as exc:
            raise self._db_error(
                exc, reason="failed to list correlations for detection"
            ) from exc
        return self._page_from_rows(rows, total, page, page_size, repo)

    def list_correlations_for_event(
        self,
        db: Session,
        event_id: uuid.UUID | str,
        *,
        page: int = 1,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> CorrelationPage:
        """Return one bounded page of correlations referencing *event_id*.

        Each correlation appears at most once.  Deterministic ordering:
        ``timestamp`` descending, ``correlation_id`` ascending.  ``total`` is
        the distinct correlation count for the event (unaffected by
        pagination).
        """
        event_id = _coerce_uuid(event_id, field="event_id")
        page, page_size = _validate_page(page, page_size)
        repo = self._repo(db)
        try:
            total = repo.count_correlations_for_event(event_id)
            rows = repo.list_correlations_for_event(
                event_id, limit=page_size, offset=(page - 1) * page_size
            )
        except CorrelationQueryError:
            raise
        except Exception as exc:
            raise self._db_error(
                exc, reason="failed to list correlations for event"
            ) from exc
        return self._page_from_rows(rows, total, page, page_size, repo)

    def list_recent_correlations(
        self,
        db: Session,
        *,
        limit: int = DEFAULT_RECENT_LIMIT,
    ) -> list[CorrelationResultRecord]:
        """Return up to *limit* newest persisted correlations across all rows.

        A bounded feed (not paginated), mirroring the detection recent-results
        convention.  Ordering is deterministic: ``timestamp`` descending,
        ``correlation_id`` ascending.
        """
        limit = _validate_recent_limit(limit)
        repo = self._repo(db)
        try:
            rows = repo.list_recent_correlations(limit=limit)
        except CorrelationQueryError:
            raise
        except Exception as exc:
            raise self._db_error(
                exc, reason="failed to list recent correlations"
            ) from exc
        return self._records_with_members(rows, repo)

    # ------------------------------------------------------------------
    # Counting
    # ------------------------------------------------------------------

    def count_correlations(self, db: Session) -> int:
        """Return the total number of persisted correlations.

        Computed with a database-side ``COUNT`` — never a full-table Python
        materialization.
        """
        try:
            return self._repo(db).count_correlations()
        except CorrelationQueryError:
            raise
        except Exception as exc:
            raise self._db_error(exc, reason="failed to count correlations") from exc

    def count_correlations_for_detection(
        self,
        db: Session,
        detection_id: uuid.UUID | str,
    ) -> int:
        """Return the number of distinct correlations referencing
        *detection_id* (database-side COUNT)."""
        detection_id = _coerce_uuid(detection_id, field="detection_id")
        try:
            return self._repo(db).count_correlations_for_detection(detection_id)
        except CorrelationQueryError:
            raise
        except Exception as exc:
            raise self._db_error(
                exc, reason="failed to count correlations for detection"
            ) from exc

    def count_correlations_for_event(
        self,
        db: Session,
        event_id: uuid.UUID | str,
    ) -> int:
        """Return the number of distinct correlations referencing *event_id*
        (database-side COUNT)."""
        event_id = _coerce_uuid(event_id, field="event_id")
        try:
            return self._repo(db).count_correlations_for_event(event_id)
        except CorrelationQueryError:
            raise
        except Exception as exc:
            raise self._db_error(
                exc, reason="failed to count correlations for event"
            ) from exc

    # -- composition helpers ----------------------------------------------

    def _page_from_rows(
        self,
        rows: list[CorrelationResultRow],
        total: int,
        page: int,
        page_size: int,
        repo: CorrelationRepository,
    ) -> CorrelationPage:
        """Wrap *rows* (members embedded, one bulk query) in a page envelope."""
        return CorrelationPage(
            items=self._records_with_members(rows, repo),
            total=total,
            page=page,
            page_size=page_size,
        )

    def _records_with_members(
        self,
        rows: list[CorrelationResultRow],
        repo: CorrelationRepository,
    ) -> list[CorrelationResultRecord]:
        """Convert *rows* embedding their members from a single bulk query."""
        if not rows:
            return []
        by_correlation: dict[uuid.UUID, list[CorrelationMemberRow]] = {}
        for member in repo.get_members_for_correlations(
            [row.correlation_id for row in rows]
        ):
            by_correlation.setdefault(member.correlation_id, []).append(member)
        return [
            _to_result_record(row, by_correlation.get(row.correlation_id, []))
            for row in rows
        ]