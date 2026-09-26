"""Detection API (Step 9H) — read-only transport for the Detection Query Layer.

Exposes the Step 9G :class:`~app.services.detection_query.DetectionQueryService`
as a thin, authenticated, read-only FastAPI surface over the Step 9F
persistence contract.

Architecture::

    HTTP request
        -> JWT authentication (existing get_current_user dependency)
        -> RBAC authorization (existing require_role: admin/analyst/ciso)
        -> DetectionQueryService (Step 9G, read-only)
        -> 9G read-model response schema
        -> HTTP response

Design principles:

* **Thin transport only** — every route validates its HTTP input, calls one
  ``DetectionQueryService`` method, and returns a Step 9G read model.  No
  route performs detection logic, constructs its own SQL, paginates manually,
  or mutates persisted state.
* **Read-only** — only ``GET`` endpoints are defined.  Detection creation
  remains owned by the DetectionAgent + DetectionPersistenceService.
* **Reuses existing security** — the existing JWT ``HTTPBearer`` dependency
  and the existing ``require_role`` RBAC factory are reused verbatim; no
  second authentication system, no query-string/body/custom-header auth.
* **Consistent HTTP semantics** — exact lookups that miss return 404;
  collection queries return 200 with an empty ``items`` list; malformed
  UUIDs are rejected with 422 by FastAPI path typing; service validation
  failures map to 422 and sanitized database failures to 503.
* **Event-scoped analyses** — the Step 9G contract treats an "analysis" as
  the set of ``detection_results`` / ``detection_rule_failures`` rows
  recorded for one ``event_id`` (no separate analysis table exists), so the
  analysis route paths use the event UUID as the analysis identity.

Logging follows the existing API conventions: successful reads are not
logged (no read-audit convention exists), authorization denials are audited
by ``require_role``, and query failures are logged sanitized by the service
and the centralized exception handler.
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
from app.schemas.detection_query import (
    DetectionAnalysisRecord,
    DetectionFailurePage,
    DetectionResultPage,
    DetectionResultRecord,
)
from app.services.detection_query import (
    DEFAULT_PAGE_SIZE,
    DEFAULT_RECENT_LIMIT,
    MAX_PAGE_SIZE,
    MAX_RECENT_LIMIT,
    DetectionQueryError,
    DetectionQueryService,
    DetectionQueryValidationError,
)

logger = logging.getLogger(__name__)

router = APIRouter()
analyses_router = APIRouter()

#: Roles allowed to read detection telemetry (the existing SOC role model —
#: ``require_role("admin", "analyst", "ciso")`` guards the security-test
#: endpoint; detection data follows the same security-team convention).
_SOC_ROLES = ("admin", "analyst", "ciso")

#: Stateless, read-only query service shared by every detection route.
_service = DetectionQueryService()

T = TypeVar("T")


def _call_query(fn: Callable[[], T]) -> T:
    """Execute one DetectionQueryService call, translating its errors to HTTP.

    Keeps the route an HTTP-only shim: service-level validation failures
    become 422 (the HTTP contract), sanitized database/query failures
    become a 503 with a generic message (matching the ``get_db`` / health
    unavailability convention), and anything else propagates to the
    centralized exception handler.
    """
    try:
        return fn()
    except DetectionQueryValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    except DetectionQueryError as exc:
        logger.warning("Detection query failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Detection data is unavailable",
        ) from exc


# ---------------------------------------------------------------------------
# GET /api/detections — persisted detection results (read-only)
# ---------------------------------------------------------------------------
#
# Static/segmented paths are registered before the parameterized
# ``/{detection_id}`` route so that ``/recent`` never resolves as a UUID
# path segment.


@router.get(
    "/recent",
    response_model=list[DetectionResultRecord],
    summary="List recent detection results",
    description=(
        "Return the newest persisted detection matches across all events "
        "(bounded feed, default 50, max 200), in deterministic "
        "detected_at descending order."
    ),
)
def list_recent_detections(
    limit: int = Query(
        DEFAULT_RECENT_LIMIT,
        ge=1,
        le=MAX_RECENT_LIMIT,
        description="Maximum number of results to return (1..200).",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*_SOC_ROLES)),
) -> list[DetectionResultRecord]:
    return _call_query(lambda: _service.list_recent_results(db, limit=limit))


@router.get(
    "/event/{event_id}",
    response_model=DetectionResultPage,
    summary="List detections for an event",
    description=(
        "Return one bounded page of the persisted detection matches for an "
        "event.  Empty result sets return 200 with an empty items list."
    ),
)
def list_event_detections(
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
) -> DetectionResultPage:
    return _call_query(
        lambda: _service.list_results_for_event(
            db, event_id, page=page, page_size=page_size
        )
    )


@router.get(
    "/rule/{rule_id}",
    response_model=DetectionResultPage,
    summary="List detections for a rule",
    description=(
        "Return one bounded page of the persisted detection matches for a "
        "rule ID.  Rule IDs are application-defined identifiers; they are "
        "matched exactly and never normalized.  Empty result sets return "
        "200 with an empty items list."
    ),
)
def list_rule_detections(
    rule_id: str,
    page: int = Query(1, ge=1, description="1-based page number."),
    page_size: int = Query(
        DEFAULT_PAGE_SIZE,
        ge=1,
        le=MAX_PAGE_SIZE,
        description="Maximum items per page (1..200).",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*_SOC_ROLES)),
) -> DetectionResultPage:
    return _call_query(
        lambda: _service.list_results_for_rule(
            db, rule_id, page=page, page_size=page_size
        )
    )


@router.get(
    "/{detection_id}",
    response_model=DetectionResultRecord,
    summary="Get one detection result",
    description=(
        "Return the persisted detection match identified by detection_id. "
        "A missing detection returns 404."
    ),
)
def get_detection(
    detection_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*_SOC_ROLES)),
) -> DetectionResultRecord:
    record = _call_query(lambda: _service.get_result(db, detection_id))
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection not found",
        )
    return record


# ---------------------------------------------------------------------------
# GET /api/detection-analyses — event-scoped analysis views (read-only)
# ---------------------------------------------------------------------------
#
# An "analysis" is event-scoped in the Step 9G contract: the analysis
# identity is the originating event's UUID (there is no separate analysis
# table or analysis id).  The path parameters therefore carry event UUIDs.


@analyses_router.get(
    "/{event_id}",
    response_model=DetectionAnalysisRecord,
    summary="Get a detection analysis",
    description=(
        "Return the full event-scoped analysis — aggregate counts, time "
        "windows, and every persisted result and failure child record — "
        "identified by the originating event's UUID.  A missing analysis "
        "(no results and no failures recorded) returns 404."
    ),
)
def get_analysis(
    event_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*_SOC_ROLES)),
) -> DetectionAnalysisRecord:
    record = _call_query(
        lambda: _service.get_analysis_with_children(db, event_id)
    )
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection analysis not found",
        )
    return record


@analyses_router.get(
    "/{event_id}/failures",
    response_model=DetectionFailurePage,
    summary="List a detection analysis' rule/engine failures",
    description=(
        "Return one bounded page of the persisted detection rule/engine "
        "failures recorded for the event.  Failures remain failures — no "
        "severity, risk, or alert semantics are assigned.  Empty failure "
        "sets return 200 with an empty items list."
    ),
)
def list_analysis_failures(
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
) -> DetectionFailurePage:
    return _call_query(
        lambda: _service.list_failures_for_analysis(
            db, event_id, page=page, page_size=page_size
        )
    )