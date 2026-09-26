"""Risk Assessment API (Step 11E) — read-only transport for the Risk Query Layer.

Exposes the Step 11D :class:`~app.services.risk_query.RiskQueryService`
as a thin, authenticated, read-only FastAPI surface over the Step 11C
persistence contract.

Architecture::

    HTTP request
        -> JWT authentication (existing get_current_user dependency)
        -> RBAC authorization (existing require_role: admin/analyst/ciso)
        -> RiskQueryService (Step 11D, read-only)
        -> 11D read-model response schema (RiskAssessmentRecord / RiskAssessmentPage)
        -> HTTP response

Design principles:

* **Thin transport only** — every route validates its HTTP input, calls one
  ``RiskQueryService`` method, and returns a Step 11D read model.  No route
  queries the repository or the database directly, constructs its own SQL,
  paginates manually, or mutates persisted state.
* **Read-only** — only ``GET`` endpoints are defined.  Risk assessments are
  created exclusively by the RiskScoringAgent + RiskPersistenceService
  (Steps 11B/11C); there is no creation/update/delete API.
* **Reuses existing security** — the existing JWT ``HTTPBearer`` dependency
  and the existing ``require_role`` RBAC factory are reused verbatim; no
  second authentication system, no query-string/body/custom-header auth.
* **Consistent HTTP semantics** — exact lookups that miss return 404;
  collection queries return 200 with an empty ``items`` list; malformed UUIDs
  are rejected with 422 by FastAPI path typing; service validation failures
  map to 422 and sanitized database failures to 503.
* **Route ordering** — the static ``/recent`` and ``/correlation/{correlation_id}``
  routes are registered before the parameterized ``/{risk_assessment_id}``
  route so a literal ``/recent`` path segment never resolves as a UUID.

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
from app.schemas.risk_query import RiskAssessmentPage, RiskAssessmentRecord
from app.services.risk_query import (
    DEFAULT_PAGE_SIZE,
    DEFAULT_RECENT_LIMIT,
    MAX_PAGE_SIZE,
    MAX_RECENT_LIMIT,
    RiskQueryError,
    RiskQueryService,
    RiskQueryValidationError,
)

logger = logging.getLogger(__name__)

router = APIRouter()

#: Roles allowed to read risk assessments (the existing SOC role model —
#: ``require_role("admin", "analyst", "ciso")``; same convention as the
#: Detection and Correlation APIs).
_SOC_ROLES = ("admin", "analyst", "ciso")

#: Stateless, read-only query service shared by every risk route.
_service = RiskQueryService()

T = TypeVar("T")


def _call_query(fn: Callable[[], T]) -> T:
    """Execute one RiskQueryService call, translating its errors to HTTP.

    Keeps the route an HTTP-only shim: service-level validation failures
    become 422 (the HTTP contract), sanitized database/query failures
    become a 503 with a generic message (matching the ``get_db`` / health
    unavailability convention), and anything else propagates to the
    centralized exception handler.
    """
    try:
        return fn()
    except RiskQueryValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    except RiskQueryError as exc:
        logger.warning("Risk query failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Risk data is unavailable",
        ) from exc


# ---------------------------------------------------------------------------
# GET /api/risk-assessments — persisted risk assessments (read-only)
# ---------------------------------------------------------------------------
#
# Static/segmented paths are registered before the parameterized
# ``/{risk_assessment_id}`` route so that ``/recent`` never resolves as a
# UUID path segment.


@router.get(
    "/recent",
    response_model=list[RiskAssessmentRecord],
    summary="List recent risk assessments",
    description=(
        "Return the newest persisted risk assessments across all rows "
        "(bounded feed, default 50, max 200), in deterministic "
        "timestamp descending order."
    ),
)
def list_recent_risk_assessments(
    limit: int = Query(
        DEFAULT_RECENT_LIMIT,
        ge=1,
        le=MAX_RECENT_LIMIT,
        description="Maximum number of assessments to return (1..200).",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*_SOC_ROLES)),
) -> list[RiskAssessmentRecord]:
    return _call_query(lambda: _service.list_recent_assessments(db, limit=limit))


@router.get(
    "/correlation/{correlation_id}",
    response_model=RiskAssessmentPage,
    summary="List risk assessments for a correlation",
    description=(
        "Return one bounded page of the persisted risk assessments that "
        "evaluate a correlation.  A correlation may legitimately carry "
        "several historical assessments, so every matching assessment is "
        "returned (never collapsed to one).  Empty result sets return 200 "
        "with an empty items list."
    ),
)
def list_correlation_risk_assessments(
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
) -> RiskAssessmentPage:
    return _call_query(
        lambda: _service.list_assessments_for_correlation(
            db, correlation_id, page=page, page_size=page_size
        )
    )


@router.get(
    "/{risk_assessment_id}",
    response_model=RiskAssessmentRecord,
    summary="Get one risk assessment",
    description=(
        "Return the persisted risk assessment identified by "
        "risk_assessment_id.  A missing assessment returns 404."
    ),
)
def get_risk_assessment(
    risk_assessment_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*_SOC_ROLES)),
) -> RiskAssessmentRecord:
    record = _call_query(lambda: _service.get_assessment(db, risk_assessment_id))
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Risk assessment not found",
        )
    return record