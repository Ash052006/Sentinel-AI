"""Incident memory persistence repository (Step 17).

Data-access layer for Step 16 :class:`~app.schemas.incident_memory.
IncidentMemory` envelopes through the Step 17 persistence model
(:class:`~app.models.incident_memory.IncidentMemoryRow`).

Design decisions
----------------
* **Idempotency identity is ``memory_id``.**  A persisted incident memory
  is keyed by its unique ``memory_id``; re-persisting the same
  ``memory_id`` is a no-op.  The Step 16 ``IncidentMemory.memory_id`` is
  therefore the persistence idempotency key — the same role the Step 10C-A
  ``correlation_id`` plays for :class:`~app.models.correlation_result.
  CorrelationResult`.
* **No foreign key to ``correlation_id``.**  Incident memory is historical
  *recall memory*: it must **outlive** the Step 10A/11 correlation/risk
  lifecycle it cites.  A ``correlation_id`` foreign key with
  ``ON DELETE CASCADE`` would silently destroy memory when a correlation
  is retired, corrupting the recall history.  ``correlation_id`` is a
  plain, nullable UUID — no FK — and linkage is asserted by the Step 16
  extraction, never by the persistence schema.  This is a deliberate,
  documented departure from the Step 10C-A correlation-member schema.
* **Secret-safe at the boundary.**  Structured JSON columns (``sources``,
  ``indicators``, ``entities``, ``techniques``, ``findings``, ``actions``,
  ``outcomes``, ``memory_metadata``) are **redacted** — never silently
  dropped or rewritten — before the row is staged: credential-shaped keys
  are replaced with the ``<redacted>`` marker, and any structured content
  whose serialized JSON exceeds a bounded size is **rejected** (never
  truncated) so the envelope always round-trips exactly.  Error messages
  never contain payloads, secrets, or raw database/SQL error text — only
  safe contextual identifiers (``memory_id``).
* **Provenance pinned to ``recalled``.**  A database CHECK constraint
  (``provenance = 'recalled'``) guarantees a recalled memory can never
  masquerade as observed/enriched/detected evidence — the Provenance
  value is that of the Step 16 *envelope* (RECALLED), while per-source
  provenance inside ``sources`` is preserved verbatim (OBSERVED/ENRICHED/
  …), never rewritten.
* **Bounded.**  ``title`` ≤ 200 and ``summary`` ≤ 2000 characters by
  database CHECK; ``confidence`` ∈ [0.0, 1.0] when present; the four
  JSONB structured columns are each bounded to the Step 11 evidence cap at
  persistence time (defence-in-depth on top of the Step 16 validator).
"""

from __future__ import annotations

import uuid

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.models.incident_memory import IncidentMemoryRow
from app.schemas.incident_memory import MemoryType


def _memory_type_filter(memory_type: MemoryType | None) -> tuple:
    """Return a ``WHERE`` predicate tuple for an optional memory-type filter.

    An equality filter on the Step 16 ``memory_type`` column (stored as its
    enum value) evaluated database-side.  When no filter is requested the
    returned tuple is empty, so ``.where(*)`` with it leaves the query
    unfiltered.
    """
    if memory_type is None:
        return ()
    return (IncidentMemoryRow.memory_type == memory_type.value,)


class IncidentMemoryValidationError(Exception):
    """Raised when an item cannot be mapped to an incident memory row.

    Created with only a safe contextual ``memory_id`` (when known); never
    with a payload, a secret, or a raw database error.  Depending on when
    it fires it aborts either a whole ``persist_memories`` transaction (a
    validation error surfaced through the service) or a single staged row
    (a repository-level mapping error surfaced by the caller).
    """

    def __init__(self, memory_id: uuid.UUID | None = None, reason: str = "") -> None:
        message = "Invalid incident memory"
        if memory_id is not None:
            message += f" for memory {memory_id}"
        if reason:
            message += f": {reason}"
        super().__message if False else Exception.__init__(self, message)
        self.memory_id = memory_id


class IncidentMemoryRepository:
    """Entity-level persistence operations for Step 16 incident memories.

    The repository never commits or rolls back — transaction ownership
    belongs to the Step 17 persistence service
    (:class:`~app.services.incident_memory_persistence
    .IncidentMemoryPersistenceService`).  Every write is staged; a single
    caller-owned ``commit()`` publishes the whole unit atomically.
    """

    def __init__(self, db: Session) -> None:
        self.db = db

    def add(self, entity: IncidentMemoryRow) -> None:
        """Stage *entity* for insertion.  The caller owns the commit."""
        self.db.add(entity)

    def get_by_memory_id(self, memory_id: uuid.UUID) -> IncidentMemoryRow | None:
        """Return the persisted row for *memory_id*, if any.

        The repository read used by the Step 17 persistence service to keep
        ``persist_memories`` idempotent: an existing ``memory_id`` means the
        memory was already persisted and a re-persist is a no-op.
        """
        return self.db.scalar(
            select(IncidentMemoryRow).where(
                IncidentMemoryRow.memory_id == memory_id
            )
        )

    def count_memories(
        self,
        memory_type: MemoryType | None = None,
    ) -> int:
        """Return the number of persisted incident memories (for summary / tests).

        When *memory_type* is given, only memories of that Step 16 type are
        counted (a database-side equality filter, never a Python walk).
        """
        where = _memory_type_filter(memory_type)
        return self.db.scalar(
            select(func.count(IncidentMemoryRow.memory_id)).where(*where)
        ) or 0

    # ------------------------------------------------------------------
    # Read-only query surface (Step 18)
    #
    # The Step 18 query methods are strictly read-only: they never add,
    # flush, commit, or roll back — the caller (the Step 18 query service)
    # owns the session and its transaction.  Ordering is deterministic:
    # ``created_at`` descending with a ``memory_id`` ascending secondary
    # key so page boundaries never drift, and every query is bounded by an
    # explicit ``limit``.
    # ------------------------------------------------------------------

    def list_memories(
        self,
        *,
        limit: int,
        offset: int = 0,
        memory_type: MemoryType | None = None,
    ) -> list[IncidentMemoryRow]:
        """Return one bounded page of persisted memories, newest first.

        Deterministic ordering: ``created_at`` descending, ``memory_id``
        ascending.  *limit* is required so list reads are always bounded.
        When *memory_type* is given, only memories of that Step 16 type are
        returned (a database-side equality filter).
        """
        return list(
            self.db.scalars(
                select(IncidentMemoryRow)
                .where(*_memory_type_filter(memory_type))
                .order_by(
                    desc(IncidentMemoryRow.created_at),
                    IncidentMemoryRow.memory_id,
                )
                .limit(limit)
                .offset(offset)
            )
        )

    def list_memories_for_correlation(
        self,
        correlation_id: uuid.UUID,
        *,
        limit: int,
        offset: int = 0,
    ) -> list[IncidentMemoryRow]:
        """Return one bounded page of memories citing *correlation_id*.

        Matches the plain nullable ``correlation_id`` column (no FK — the
        Step 17 deliberate decision that historical memory outlives the
        correlation lifecycle).  Deterministic ordering: ``created_at``
        descending, ``memory_id`` ascending.
        """
        return list(
            self.db.scalars(
                select(IncidentMemoryRow)
                .where(IncidentMemoryRow.correlation_id == correlation_id)
                .order_by(
                    desc(IncidentMemoryRow.created_at),
                    IncidentMemoryRow.memory_id,
                )
                .limit(limit)
                .offset(offset)
            )
        )

    def list_recent_memories(self, *, limit: int) -> list[IncidentMemoryRow]:
        """Return the *limit* newest persisted memories across all rows.

        A bounded feed (not paginated), deterministic by ``created_at``
        descending, ``memory_id`` ascending.
        """
        return list(
            self.db.scalars(
                select(IncidentMemoryRow)
                .order_by(
                    desc(IncidentMemoryRow.created_at),
                    IncidentMemoryRow.memory_id,
                )
                .limit(limit)
            )
        )

    def count_memories_for_correlation(self, correlation_id: uuid.UUID) -> int:
        """Return the number of persisted memories citing *correlation_id*.

        Computed with a database-side ``COUNT`` — never a full-table Python
        materialization.
        """
        return self.db.scalar(
            select(func.count(IncidentMemoryRow.memory_id)).where(
                IncidentMemoryRow.correlation_id == correlation_id
            )
        ) or 0


class IncidentMemoryRepositoryError(Exception):
    """Base for Step 17 repository errors that the service translates.

    Never carries a payload, a secret, or raw database error text — only
    safe contextual identifiers.
    """

    def __init__(self, memory_id: uuid.UUID | None = None, reason: str = "") -> None:
        message = "Incident memory repository error"
        if memory_id is not None:
            message += f" for memory {memory_id}"
        if reason:
            message += f": {reason}"
        super().__init__(message)
        self.memory_id = memory_id


class IncidentMemoryRepositoryValidationError(IncidentMemoryRepositoryError):
    """Raised when an item cannot be mapped to a row safely.

    Used for pre-commit validation failures (e.g. structured content
    exceeding a bound) that must abort the whole transaction.
    """
