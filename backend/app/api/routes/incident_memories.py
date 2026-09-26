"""Incident Memory API (Step 19) — read-only transport for the Incident Memory Query Layer.

Exposes the Step 18 :class:`~app.services.incident_memory_query.
IncidentMemoryQueryService` as a thin, authenticated, read-only FastAPI
surface over the Step 17 persistence contract.

Architecture::

    HTTP request
        -> JWT authentication (existing get_current_user dependency)
        -> RBAC authorization (existing require_role: admin/analyst/ciso)
        -> IncidentMemoryQueryService (Step 18, read-only)
        -> 18 response schema (IncidentMemoryRecord / IncidentMemoryPage)
        -> HTTP response

Design principles:

* **Thin transport only** — every route validates its HTTP input, calls one
  ``IncidentMemoryQueryService`` method, and returns a Step 18 read model.
  No route queries the repository or the database directly, constructs its
  own SQL, filters in Python, paginates manually, or mutates persisted
  state.  The optional ``memory_type`` filter is delegated to the query
  service (validated database-side), never applied in the route.
* **Read-only** — only ``GET`` endpoints are defined.  Incident memories are
  created exclusively by the Step 16 incident-memory extraction and the
  Step 17 ``IncidentMemoryPersistenceService``; there is no
  creation/update/delete API (and no Step 19 change to that).
* **Reuses existing security** — the existing JWT ``HTTPBearer`` dependency
  and the existing ``require_role`` RBAC factory are reused verbatim; no
  second authentication system, no query-string/body/custom-header auth.
* **Consistent HTTP semantics** — exact lookups that miss return 404;
  collection queries return 200 with an empty ``items`` list; malformed UUIDs
  are rejected with 422 by FastAPI path typing; invalid ``memory_type``
  values are rejected with 422 by FastAPI query validation; service
  validation failures map to 422 and sanitized database failures to 503.
* **Route ordering** — the collection root, the static ``/recent`` and the
  segmented ``/correlation/{correlation_id}`` routes are registered before
  the parameterized ``/{memory_id}`` route so a literal ``/recent`` path
  segment never resolves as a UUID.
* **Provenance and secret-safety are preserved verbatim** — the persisted
  Step 17 row already redacted/rejected secret-shaped content and pinned
  ``provenance``; the API returns the validated read model unchanged,
  neither re-transforming values nor re-scanning payloads.

Logging follows the existing API conventions: successful reads are not
logged (no read-audit convention exists in the project), authorization
denials are audited by ``require_role``, and query failures are logged
sanitized by the service and the centralized exception handler.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from typing import TypeVar

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_db, require_role
from app.models.user import User
from app.schemas.incident_memory import MemoryType
from app.schemas.incident_memory_query import IncidentMemoryPage, IncidentMemoryRecord
from app.services.incident_memory_query import (
    DEFAULT_PAGE_SIZE,
    DEFAULT_RECENT_LIMIT,
    MAX_PAGE_SIZE,
    MAX_RECENT_LIMIT,
    IncidentMemoryQueryError,
    IncidentMemoryQueryService,
    IncidentMemoryQueryValidationError,
)

logger = logging.getLogger(__name__)

router = APIRouter()

#: Roles allowed to read incident memories (the existing SOC role model —
#: ``require_role("admin", "analyst", "ciso")``; same convention as the
#: Detection, Correlation, and Risk Assessment APIs).
_SOC_ROLES = ("admin", "analyst", "ciso")

#: Stateless, read-only query service shared by every incident memory route.
_service = IncidentMemoryQueryService()

T = TypeVar("T")


def _call_query(fn: Callable[[], T]) -> T:
    """Execute one IncidentMemoryQueryService call, translating its errors to HTTP.

    Keeps the route an HTTP-only shim: service-level validation failures
    become 422 (the HTTP contract), sanitized database/query failures
    become a 503 with a generic message (matching the ``get_db`` / health
    unavailability convention), and anything else propagates to the
    centralized exception handler.
    """
    try:
        return fn()
    except IncidentMemoryQueryValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    except IncidentMemoryQueryError as exc:
        logger.warning("Incident memory query failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Incident memory data is unavailable",
        ) from exc


# ---------------------------------------------------------------------------
# GET /api/incident-memories — persisted incident memories (read-only)
# ---------------------------------------------------------------------------
#
# The collection root, the static ``/recent``, and the segmented
# ``/correlation/{correlation_id}`` routes are registered before the
# parameterized ``/{memory_id}`` route so that ``/recent`` never resolves
# as a UUID path segment.


@router.get(
    "",
    response_model=IncidentMemoryPage,
    summary="List incident memories",
    description=(
        "Return one bounded page of all persisted incident memories, newest "
        "first.  May be narrowed with the optional memory_type filter "
        "(validated against the Step 16 MemoryType enumeration; an unknown "
        "value is rejected with 422).  Empty result sets return 200 with an "
        "empty items list."
    ),
)
def list_incident_memories(
    memory_type: MemoryType | None = Query(
        None,
        description="Return only memories of this Step 16 type.",
    ),
    page: int = Query(1, ge=1, description="1-based page number."),
    page_size: int = Query(
        DEFAULT_PAGE_SIZE,
        ge=1,
        le=MAX_PAGE_SIZE,
        description="Maximum items per page (1..200).",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*_SOC_ROLES)),
) -> IncidentMemoryPage:
    return _call_query(
        lambda: _service.list_memories(
            db, page=page, page_size=page_size, memory_type=memory_type
        )
    )


@router.get(
    "/recent",
    response_model=list[IncidentMemoryRecord],
    summary="List recent incident memories",
    description=(
        "Return the newest persisted incident memories across all rows "
        "(bounded feed, default 50, max 200), in deterministic timestamp "
        "descending order."
    ),
)
def list_recent_incident_memories(
    limit: int = Query(
        DEFAULT_RECENT_LIMIT,
        ge=1,
        le=MAX_RECENT_LIMIT,
        description="Maximum number of memories to return (1..200).",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*_SOC_ROLES)),
) -> list[IncidentMemoryRecord]:
    return _call_query(lambda: _service.list_recent_memories(db, limit=limit))


@router.get(
    "/correlation/{correlation_id}",
    response_model=IncidentMemoryPage,
    summary="List incident memories for a correlation",
    description=(
        "Return one bounded page of the persisted incident memories that "
        "cite a correlation.  The correlation link is historical recall "
        "memory (plain, nullable column — no foreign key), so memories remain "
        "retrievable after a correlation is closed/removed.  Empty result "
        "sets return 200 with an empty items list."
    ),
)
def list_correlation_incident_memories(
    correlation_id: uuid.UUID,
    page: int = Query(1, ge=1, description="1-based page number."),
    page_size: int = Query(
        DEFAULT_PAGE_SIZE,
        ge=1,
        le=MAX_PAGE_SIZE,
        description="Maximum items per page (1..200).",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*_SOC_ROLES)),
) -> IncidentMemoryPage:
    return _call_query(
        lambda: _service.list_memories_for_correlation(
            db, correlation_id, page=page, page_size=page_size
        )
    )


@router.get(
    "/{memory_id}",
    response_model=IncidentMemoryRecord,
    summary="Get one incident memory",
    description=(
        "Return the persisted incident memory identified by memory_id.  A "
        "missing memory returns 404."
    ),
)
def get_incident_memory(
    memory_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*_SOC_ROLES)),
) -> IncidentMemoryRecord:
    record = _call_query(lambda: _service.get_memory(db, memory_id))
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident memory not found",
        )
    return record