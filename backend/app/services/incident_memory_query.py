"""Incident memory query service (Step 18) — read-only retrieval over Step 17 persistence.

Provides validated, read-only access to persisted incident memories without
any write surface: it composes :class:`IncidentMemoryRepository` reads and
converts rows into :mod:`app.schemas.incident_memory_query` read models.  It
is the layer a future incident memory recall API will call — no endpoints
are added here.

Design principles:

* **Read-only** — ``IncidentMemoryQueryService`` never calls
  ``add``/``delete``, ``flush``, ``commit``, or ``rollback``.  Callers own
  the session and its transaction; queries never mutate it.  (A failed read
  leaves the session untouched — the owner decides whether to roll back.)
* **Validated input** — memory/correlation UUIDs and page semantics are
  validated up front; invalid input raises
  :class:`IncidentMemoryQueryValidationError` before any database work.
* **Sanitized failures** — database errors surface as
  :class:`IncidentMemoryQueryError` with safe, consumer-facing messages.
  Raw driver/SQL text and payloads are logged, never propagated.
* **Deterministic pages** — every list orders by row ``created_at``
  descending with a stable secondary key (``memory_id`` ascending), so
  page boundaries never drift.
* **Persisted view, types re-validated** — records mirror the Step 17
  columns; ``memory_type`` / ``provenance`` are re-validated through their
  Step 16 enums at the read edge, while the already-redacted structured
  JSONB payloads are surfaced verbatim (never re-scanned).

Pipeline::

    IncidentMemoryPersistenceService (17 writes, then commit)
        -> incident_memories
            -> IncidentMemoryQueryService (this module, read-only)
                -> IncidentMemoryRecord / IncidentMemoryPage
"""

from __future__ import annotations

import copy
import logging
import uuid
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy.orm import Session

from app.models.incident_memory import IncidentMemoryRow
from app.repositories.incident_memory import IncidentMemoryRepository
from app.schemas.incident_memory import MemoryType
from app.schemas.incident_memory_query import (
    IncidentMemoryPage,
    IncidentMemoryRecord,
)
from app.schemas.security_event import Provenance

logger = logging.getLogger(__name__)

#: Default page size for paginated reads (bounded offset pagination).
DEFAULT_PAGE_SIZE = 50

#: Hard cap on a single page; guards against unbounded result materialization.
MAX_PAGE_SIZE = 200

#: Default limit for the "recent incident memories" feed.
DEFAULT_RECENT_LIMIT = 50

#: Hard cap on the "recent incident memories" feed.
MAX_RECENT_LIMIT = 200


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class IncidentMemoryQueryError(Exception):
    """Raised when an incident memory query cannot be satisfied.

    Instances never contain credentials, raw evidence, raw memory payloads,
    raw database/SQL error text, or tracebacks — only safe contextual
    identifiers such as the ``memory_id``.  The underlying exception is
    preserved as ``__cause__`` for server-side logging.
    """

    def __init__(
        self,
        memory_id: uuid.UUID | None = None,
        reason: str = "",
    ) -> None:
        message = "Incident memory query failed"
        if memory_id is not None:
            message += f" for memory {memory_id}"
        if reason:
            message += f": {reason}"
        super().__init__(message)
        self.memory_id = memory_id


class IncidentMemoryQueryValidationError(IncidentMemoryQueryError):
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
        raise IncidentMemoryQueryValidationError(
            reason=f"{field} must be a valid UUID"
        ) from exc


def _validate_page(page: object, page_size: object) -> tuple[int, int]:
    """Validate 1-based pagination arguments; return corrected integers."""
    try:
        page_int = int(page)
        page_size_int = int(page_size)
    except (TypeError, ValueError) as exc:
        raise IncidentMemoryQueryValidationError(
            reason="page and page_size must be integers"
        ) from exc
    if page_int < 1:
        raise IncidentMemoryQueryValidationError(reason="page must be >= 1")
    if page_size_int < 1:
        raise IncidentMemoryQueryValidationError(reason="page_size must be >= 1")
    if page_size_int > MAX_PAGE_SIZE:
        raise IncidentMemoryQueryValidationError(
            reason=f"page_size must not exceed {MAX_PAGE_SIZE}"
        )
    return page_int, page_size_int


def _validate_recent_limit(limit: object) -> int:
    """Validate the recent-memories feed limit; return its integer value."""
    try:
        limit_int = int(limit)
    except (TypeError, ValueError) as exc:
        raise IncidentMemoryQueryValidationError(
            reason="limit must be an integer"
        ) from exc
    if limit_int < 1:
        raise IncidentMemoryQueryValidationError(reason="limit must be >= 1")
    if limit_int > MAX_RECENT_LIMIT:
        raise IncidentMemoryQueryValidationError(
            reason=f"limit must not exceed {MAX_RECENT_LIMIT}"
        )
    return limit_int


# ---------------------------------------------------------------------------
# Row -> read-model conversion (read boundary normalization)
# ---------------------------------------------------------------------------


def _to_memory_record(row: IncidentMemoryRow) -> IncidentMemoryRecord:
    """Convert a persisted ``incident_memories`` row into its read record.

    ``memory_type`` and ``provenance`` are re-validated through the Step 16
    enums at the read edge; the already-redacted structured JSONB payloads
    are carried across verbatim (deep-copied), never re-scanned — the Step
    17 write path already rejected/redacted secret-shaped content.
    """
    return IncidentMemoryRecord(
        id=row.id,
        memory_id=row.memory_id,
        memory_type=MemoryType(row.memory_type),
        title=row.title,
        summary=row.summary,
        correlation_id=row.correlation_id,
        sources=copy.deepcopy(row.sources or []),
        indicators=copy.deepcopy(row.indicators or []),
        entities=copy.deepcopy(row.entities or []),
        techniques=copy.deepcopy(row.techniques or []),
        findings=copy.deepcopy(row.findings or []),
        actions=copy.deepcopy(row.actions or []),
        outcomes=copy.deepcopy(row.outcomes or {}),
        memory_metadata=copy.deepcopy(row.memory_metadata or {}),
        confidence=row.confidence,
        provenance=Provenance(row.provenance),
        created_at=_as_utc(row.created_at),
        updated_at=_as_utc(row.updated_at),
    )


# ---------------------------------------------------------------------------
# Query service
# ---------------------------------------------------------------------------


class IncidentMemoryQueryService:
    """Read-only retrieval over the Step 17 persistence layer.

    Every method follows the persistence-service convention of receiving the
    caller-owned ``db`` session as the first argument::

        service = IncidentMemoryQueryService()
        record  = service.get_memory(db, memory_id)

    Read-only guarantee: this service never calls ``add``/``delete``,
    ``flush``, ``commit``, or ``rollback`` on the session.  It composes
    repository reads and converts rows to read models; callers own the
    transaction, and a session that hit a real database failure here should
    be rolled back by its owner.

    Args:
        repository_factory: Optional repository factory; defaults to
            :class:`IncidentMemoryRepository`.  Injected for testability.
    """

    def __init__(
        self,
        repository_factory: Callable[
            [Session], IncidentMemoryRepository
        ] = IncidentMemoryRepository,
    ) -> None:
        self._repository_factory = repository_factory

    def _repo(self, db: Session) -> IncidentMemoryRepository:
        return self._repository_factory(db)

    @staticmethod
    def _db_error(
        exc: Exception,
        *,
        memory_id: uuid.UUID | None = None,
        reason: str,
    ) -> IncidentMemoryQueryError:
        """Build a sanitized query error from a low-level failure.

        The raw exception is logged for operators; only the safe *reason*
        string reaches the consumer.
        """
        logger.warning(
            "Incident memory query failed (reason=%s, memory=%s): %s",
            reason,
            memory_id,
            exc,
        )
        return IncidentMemoryQueryError(memory_id=memory_id, reason=reason)

    # ------------------------------------------------------------------
    # Incident memory detail
    # ------------------------------------------------------------------

    def get_memory(
        self,
        db: Session,
        memory_id: uuid.UUID | str,
    ) -> IncidentMemoryRecord | None:
        """Return the persisted memory with *memory_id*, or ``None``.

        Unknown IDs produce a controlled not-found result (``None``), never
        an error.
        """
        memory_id = _coerce_uuid(memory_id, field="memory_id")
        repo = self._repo(db)
        try:
            row = repo.get_by_memory_id(memory_id)
            if row is None:
                return None
            return _to_memory_record(row)
        except IncidentMemoryQueryError:
            raise
        except Exception as exc:
            raise self._db_error(
                exc,
                memory_id=memory_id,
                reason="failed to load incident memory",
            ) from exc

    # ------------------------------------------------------------------
    # Incident memories: all-memories browse, correlation-scoped, recent
    # ------------------------------------------------------------------

    def list_memories(
        self,
        db: Session,
        *,
        page: int = 1,
        page_size: int = DEFAULT_PAGE_SIZE,
        memory_type: MemoryType | None = None,
    ) -> IncidentMemoryPage:
        """Return one bounded page of all persisted incident memories.

        Deterministic ordering: ``created_at`` descending, ``memory_id``
        ascending.  ``total`` is the total number of persisted memories
        (unaffected by pagination).  When *memory_type* is given the page is
        restricted to that Step 16 memory type via a database-side equality
        filter — the service stays the authoritative filtering layer, the
        API never filters in Python.
        """
        if memory_type is not None and not isinstance(memory_type, MemoryType):
            raise IncidentMemoryQueryValidationError(
                reason="memory_type must be a valid MemoryType"
            )
        page, page_size = _validate_page(page, page_size)
        repo = self._repo(db)
        try:
            total = repo.count_memories(memory_type=memory_type)
            rows = repo.list_memories(
                limit=page_size,
                offset=(page - 1) * page_size,
                memory_type=memory_type,
            )
        except IncidentMemoryQueryError:
            raise
        except Exception as exc:
            raise self._db_error(
                exc, reason="failed to list incident memories"
            ) from exc
        return IncidentMemoryPage(
            items=[_to_memory_record(row) for row in rows],
            total=total,
            page=page,
            page_size=page_size,
        )

    def list_memories_for_correlation(
        self,
        db: Session,
        correlation_id: uuid.UUID | str,
        *,
        page: int = 1,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> IncidentMemoryPage:
        """Return one bounded page of memories citing *correlation_id*.

        Deliberately matches the plain nullable ``correlation_id`` column
        (no FK — memory outlives the correlation lifecycle) so memories
        remain retrievable after a correlation is closed/removed.
        Deterministic ordering: ``created_at`` descending, ``memory_id``
        ascending.  ``total`` is the citing-memory count (unaffected by
        pagination).
        """
        correlation_id = _coerce_uuid(correlation_id, field="correlation_id")
        page, page_size = _validate_page(page, page_size)
        repo = self._repo(db)
        try:
            total = repo.count_memories_for_correlation(correlation_id)
            rows = repo.list_memories_for_correlation(
                correlation_id, limit=page_size, offset=(page - 1) * page_size
            )
        except IncidentMemoryQueryError:
            raise
        except Exception as exc:
            raise self._db_error(
                exc, reason="failed to list incident memories for correlation"
            ) from exc
        return IncidentMemoryPage(
            items=[_to_memory_record(row) for row in rows],
            total=total,
            page=page,
            page_size=page_size,
        )

    def list_recent_memories(
        self,
        db: Session,
        *,
        limit: int = DEFAULT_RECENT_LIMIT,
    ) -> list[IncidentMemoryRecord]:
        """Return up to *limit* newest persisted incident memories across all rows.

        A bounded feed (not paginated), mirroring the correlation
        recent-results convention.  Ordering is deterministic:
        ``created_at`` descending, ``memory_id`` ascending.
        """
        limit = _validate_recent_limit(limit)
        repo = self._repo(db)
        try:
            rows = repo.list_recent_memories(limit=limit)
        except IncidentMemoryQueryError:
            raise
        except Exception as exc:
            raise self._db_error(
                exc, reason="failed to list recent incident memories"
            ) from exc
        return [_to_memory_record(row) for row in rows]

    # ------------------------------------------------------------------
    # Counting
    # ------------------------------------------------------------------

    def count_memories(
        self,
        db: Session,
        memory_type: MemoryType | None = None,
    ) -> int:
        """Return the total number of persisted incident memories.

        Computed with a database-side ``COUNT`` — never a full-table Python
        materialization.  When *memory_type* is given, only memories of that
        Step 16 memory type are counted (matching the general list filter).
        """
        if memory_type is not None and not isinstance(memory_type, MemoryType):
            raise IncidentMemoryQueryValidationError(
                reason="memory_type must be a valid MemoryType"
            )
        try:
            return self._repo(db).count_memories(memory_type=memory_type)
        except IncidentMemoryQueryError:
            raise
        except Exception as exc:
            raise self._db_error(exc, reason="failed to count incident memories") from exc

    def count_memories_for_correlation(
        self,
        db: Session,
        correlation_id: uuid.UUID | str,
    ) -> int:
        """Return the number of persisted memories citing *correlation_id*
        (database-side COUNT)."""
        correlation_id = _coerce_uuid(correlation_id, field="correlation_id")
        try:
            return self._repo(db).count_memories_for_correlation(correlation_id)
        except IncidentMemoryQueryError:
            raise
        except Exception as exc:
            raise self._db_error(
                exc, reason="failed to count incident memories for correlation"
            ) from exc