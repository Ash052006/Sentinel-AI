"""Incident memory → Investigation Context retrieval integration — Step 20.

The bridge between the Step 18 read-only
:class:`~app.services.incident_memory_query.IncidentMemoryQueryService` and
the Step 12B investigation context.  It retrieves persisted incident
memories as **historical background references** for an investigation —
deterministically, bounded, and read-only — and hands the Step 18 read
models to the context builder, which converts them into explicit
:class:`~app.schemas.investigation_context.IncidentMemoryReferenceContext`
records.

Data flow (the builder itself never touches the database)::

    Investigation Context usage
        -> retrieve_historical_incident_memories(db, ...)
            -> IncidentMemoryQueryService   (Step 18, read-only)
                -> IncidentMemoryRepository
                    -> PostgreSQL

Design principles:

* **Retrieval boundary** — this module accesses the query service only.
  It never constructs ``IncidentMemoryRow`` objects, never queries
  SQLAlchemy directly, and never imports the persistence model or
  repository.
* **Not semantic retrieval** — no embeddings, vector search, keyword
  relevance, or LLM resorting.  Retrieval uses only structured Step 18
  constraints already supported by the query service: a bounded
  correlation-scoped page (``correlation_id``) or the bounded recent feed.
  No relevance score is invented.
* **Bounded** — ``max_references`` is validated against the documented
  ``MAX_INCIDENT_MEMORY_REFERENCES`` cap; invalid values are rejected,
  never silently truncated, and the bound always stays below the Step 18
  ``MAX_PAGE_SIZE`` / ``MAX_RECENT_LIMIT`` caps.
* **Deterministic** — results come back in the Step 18 ordering
  (``created_at`` descending, ``memory_id`` ascending) and are never
  re-ordered here.  Ties are resolved by memory_id exactly as the query
  service defines.
* **Fail closed, sanitized** — a query failure propagates the query
  service's sanitized :class:`IncidentMemoryQueryError`.  Nothing is
  fabricated: the caller never receives fabricated or partial memory.
  Error instances carry no credentials, raw SQL, or payload content.
* **Immutable** — retrieved records are returned as-is (the query service
  already deep-copies structured payloads); this module never mutates
  them.
"""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.schemas.incident_memory_query import IncidentMemoryRecord
from app.schemas.investigation_context import MAX_INCIDENT_MEMORY_REFERENCES
from app.services.incident_memory_query import (
    IncidentMemoryQueryError,
    IncidentMemoryQueryService,
)

#: Default number of historical incident-memory references retrieved for an
#: investigation context.  Equal to the documented context cap.
DEFAULT_INCIDENT_MEMORY_REFERENCES = MAX_INCIDENT_MEMORY_REFERENCES


class IncidentMemoryContextRetrievalError(Exception):
    """Raised when retrieval parameters are invalid or retrieval fails.

    Messages are sanitized and never contain memory payloads, credentials,
    SQL text, or tracebacks.
    """

    __slots__ = ()


def _validate_max_references(max_references: object) -> int:
    """Validate the retrieval bound; return its integer form.

    Rejects (rather than truncates) any value above the documented cap so
    an investigation context is never silently starved of historical
    context — a requested bound is a policy decision, not a hint.
    """
    if isinstance(max_references, bool) or not isinstance(max_references, int):
        raise IncidentMemoryContextRetrievalError(
            "max_references must be an integer"
        )
    if max_references < 1:
        raise IncidentMemoryContextRetrievalError(
            "max_references must be >= 1"
        )
    if max_references > MAX_INCIDENT_MEMORY_REFERENCES:
        raise IncidentMemoryContextRetrievalError(
            f"max_references must not exceed MAX_INCIDENT_MEMORY_REFERENCES="
            f"{MAX_INCIDENT_MEMORY_REFERENCES} (got {max_references})"
        )
    return max_references


def retrieve_historical_incident_memories(
    db: Session,
    *,
    correlation_id: uuid.UUID | str | None = None,
    max_references: int = DEFAULT_INCIDENT_MEMORY_REFERENCES,
    query_service: IncidentMemoryQueryService | None = None,
) -> list[IncidentMemoryRecord]:
    """Retrieve bounded historical incident memories for an investigation.

    Retrieval criteria are the structured Step 18 constraints the existing
    investigation context justifies:

    * ``correlation_id`` — when supplied, the memories citing that
      correlation (newest first), so an investigation of a correlation
      recalls the incident memory previously stored for it.
    * otherwise — the bounded recent feed (newest memories across the
      system), giving the investigation recent historical incidents as
      background reference.

    Every returned record is a read-only ``IncidentMemoryRecord`` in the
    query service's deterministic order.  Failures propagate the sanitized
    :class:`IncidentMemoryQueryError` (fail closed); no memory is
    fabricated and this function never raises a partial list.

    Args:
        db: The caller-owned SQLAlchemy session (never accessed directly —
            it is passed to the Step 18 query service).
        correlation_id: Optional correlation UUID to scope the retrieval.
        max_references: Optional bound in ``[1, MAX_INCIDENT_MEMORY_REFERENCES]``;
            invalid values are rejected before any database work.
        query_service: Optional ``IncidentMemoryQueryService`` instance
            (dependency injection); a fresh service is built when omitted.

    Raises:
        IncidentMemoryContextRetrievalError: for invalid retrieval
            parameters (never for database failures).
        IncidentMemoryQueryError: sanitized, when the query service reports
            a failure (propagated unchanged, fail closed).
    """
    validated = _validate_max_references(max_references)
    service = query_service or IncidentMemoryQueryService()
    if correlation_id is not None:
        page = service.list_memories_for_correlation(
            db,
            correlation_id,
            page=1,
            page_size=validated,
        )
        return list(page.items)
    return list(service.list_recent_memories(db, limit=validated))