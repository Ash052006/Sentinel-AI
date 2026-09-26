"""Correlation API (Step 10E) — read-only transport for the Correlation Query Layer.

Exposes the Step 10D :class:`~app.services.correlation_query.CorrelationQueryService`
as a thin, authenticated, read-only FastAPI surface over the Step 10C
persistence contract.

Architecture::

    HTTP request
        -> JWT authentication (existing get_current_user dependency)
        -> RBAC authorization (existing require_role: admin/analyst/ciso)
        -> CorrelationQueryService (Step 10D, read-only)
        -> 10D read-model response schema (CorrelationResultRecord / CorrelationPage)
        -> HTTP response

Design principles:

* **Thin transport only** — every route validates its HTTP input, calls one
  ``CorrelationQueryService`` method, and returns a Step 10D read model.  No
  route queries the repository or the database directly, constructs its own
  SQL, paginates manually, or mutates persisted state.
* **Read-only** — only ``GET`` endpoints are defined.  Correlations are
  created exclusively by the CorrelationAgent + CorrelationPersistenceService
  (Steps 10B/10C); there is no creation/update/delete API.
* **Reuses existing security** — the existing JWT ``HTTPBearer`` dependency
  and the existing ``require_role`` RBAC factory are reused verbatim; no
  second authentication system, no query-string/body/custom-header auth.
* **Consistent HTTP semantics** — exact lookups that miss return 404;
  collection queries return 200 with an empty ``items`` list; malformed UUIDs
  are rejected with 422 by FastAPI path typing; service validation failures
  map to 422 and sanitized database failures to 503.
* **Route ordering** — the static ``/recent`` route is registered before the
  parameterized ``/{correlation_id}`` route so ``/recent`` never resolves as a
  UUID path segment.

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
from app.schemas.correlation_query import CorrelationPage, CorrelationResultRecord
from app.services.correlation_query import (
    DEFAULT_PAGE_SIZE,
    DEFAULT_RECENT_LIMIT,
    MAX_PAGE_SIZE,
    MAX_RECENT_LIMIT,
    CorrelationQueryError,
    CorrelationQueryService,
    CorrelationQueryValidationError,
)

logger = logging.getLogger(__name__)

router = APIRouter()

#: Roles allowed to read correlation telemetry (the existing SOC role model —
#: ``require_role("admin", "analyst", "ciso")``; same convention as the
#: Detection API).
_SOC_ROLES = ("admin", "analyst", "ciso")

#: Stateless, read-only query service shared by every correlation route.
_service = CorrelationQueryService()

T = TypeVar("T")


def _call_query(fn: Callable[[], T]) -> T:
    """Execute one CorrelationQueryService call, translating its errors to HTTP.

    Keeps the route an HTTP-only shim: service-level validation failures
    become 422 (the HTTP contract), sanitized database/query failures
    become a 503 with a generic message (matching the ``get_db`` / health
    unavailability convention), and anything else propagates to the
    centralized exception handler.
    """
    try:
        return fn()
    except CorrelationQueryValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    except CorrelationQueryError as exc:
        logger.warning("Correlation query failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Correlation data is unavailable",
        ) from exc


# ---------------------------------------------------------------------------
# GET /api/correlations — persisted correlations (read-only)
# ---------------------------------------------------------------------------
#
# Static/segmented paths are registered before the parameterized
# ``/{correlation_id}`` route so that ``/recent`` never resolves as a UUID
# path segment.


@router.get(
    "/recent",
    response_model=list[CorrelationResultRecord],
    summary="List recent correlations",
    description=(
        "Return the newest persisted correlations across all events "
        "(bounded feed, default 50, max 200), in deterministic "
        "timestamp descending order."
    ),
)
def list_recent_correlations(
    limit: int = Query(
        DEFAULT_RECENT_LIMIT,
        ge=1,
        le=MAX_RECENT_LIMIT,
        description="Maximum number of correlations to return (1..200).",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*_SOC_ROLES)),
) -> list[CorrelationResultRecord]:
    return _call_query(lambda: _service.list_recent_correlations(db, limit=limit))


@router.get(
    "/detection/{detection_id}",
    response_model=CorrelationPage,
    summary="List correlations for a detection",
    description=(
        "Return one bounded page of the persisted correlations that "
        "reference a detection.  Each correlation appears at most once, "
        "regardless of how many of its members reference the detection.  "
        "Empty result sets return 200 with an empty items list."
    ),
)
def list_detection_correlations(
    detection_id: uuid.UUID,
    page: int = Query(1, ge=1, description="1-based page number."),
    page_size: int = Query(
        DEFAULT_PAGE_SIZE,
        ge=1,
        le=MAX_PAGE_SIZE,
        description="Maximum items per page (1..200).",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*_SOC_ROLES)),
) -> CorrelationPage:
    return _call_query(
        lambda: _service.list_correlations_for_detection(
            db, detection_id, page=page, page_size=page_size
        )
    )


@router.get(
    "/event/{event_id}",
    response_model=CorrelationPage,
    summary="List correlations for an event",
    description=(
        "Return one bounded page of the persisted correlations that "
        "reference an event.  Each correlation appears at most once, "
        "regardless of how many of its members reference the event.  "
        "Empty result sets return 200 with an empty items list."
    ),
)
def list_event_correlations(
    event_id: uuid.UUID,
    page: int = Query(1, ge=1, description="1-based page number."),
    page_size: int = Query(
        DEFAULT_PAGE_SIZE,
        ge=1,
        le=MAX_PAGE_SIZE,
        description="Maximum items per page (1..200).",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*_SOC_ROLES)),
) -> CorrelationPage:
    return _call_query(
        lambda: _service.list_correlations_for_event(
            db, event_id, page=page, page_size=page_size
        )
    )


@router.get(
    "/{correlation_id}",
    response_model=CorrelationResultRecord,
    summary="Get one correlation",
    description=(
        "Return the persisted correlation identified by correlation_id, "
        "including every member reference.  A missing correlation returns "
        "404."
    ),
)
def get_correlation(
    correlation_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*_SOC_ROLES)),
) -> CorrelationResultRecord:
    record = _call_query(lambda: _service.get_correlation(db, correlation_id))
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Correlation not found",
        )
    return record