"""Threat Hunting API (V2.19) — governed analyst surface.

Exposes the :class:`~app.services.threat_hunting.service.ThreatHuntService`
as an authenticated FastAPI surface: create a draft hunt, run it once
(completed/failed), cancel a draft, and read its evidence / findings /
timeline.

Boundaries honoured here:

* **Thin transport only.**  Every route validates its HTTP input, calls one
  ``ThreatHuntService`` method, and returns a read model.  No route
  constructs SQL or reaches for a repository.
* **Roles, not bodies.**  The actor's role and id come from the
  authenticated user; ``admin``/``analyst``/``ciso`` may read and run
  hunts.  A request body never carries a role or an authorization claim.
* **Hunts never escalate.**  There is no route here to mutate security
  records, block an actor, issue a response action, or invoke SOAR.  A
  hunt only ever returns evidence derived from already-persisted history.
* **Consistent HTTP semantics** — malformed payloads / bad grammar map to
  422; unknown hunts to 404; lifecycle conflicts (running a completed hunt,
  cancelling a completed hunt, exceeding a bound) to 409; sanitized
  infrastructure failures to 503; unexpected internal defects to 500.
* **Route ordering** — static routes are declared before parameterized ones
  so a literal segment never resolves as an id.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from typing import Any, TypeVar

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.api.dependencies import bearer_scheme, get_current_user, get_db
from app.models.user import User
from app.schemas.threat_hunting import (
    HuntType,
    ThreatHuntCreate,
    ThreatHuntDetail,
    ThreatHuntEvidencePage,
    ThreatHuntFindingPage,
    ThreatHuntPage,
    ThreatHuntStatus,
    ThreatHuntTimelinePage,
)
from app.services.audit_service import log_action
from app.services.threat_hunting import ThreatHuntService
from app.services.threat_hunting.errors import (
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
)

logger = logging.getLogger(__name__)

router = APIRouter()

_READ_ROLES = ("admin", "analyst", "ciso")
_MUTATION_ROLES = ("admin", "analyst", "ciso")

_DEFAULT_PAGE_SIZE = 50
_MAX_PAGE_SIZE = 200

_service = ThreatHuntService

T = TypeVar("T")


def _require_roles(
    *allowed_roles: str,
) -> Callable:
    """Authorized-role dependency for the threat-hunting surface."""

    def dependency(
        request: Request,
        credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
        db: Session = Depends(get_db),
    ) -> User:
        denied_by = None
        user_id = None
        try:
            user = get_current_user(credentials, db)
            user_id = user.id
            if user.role is None or user.role.name not in allowed_roles:
                denied_by = "insufficient role"
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions",
                )
            return user
        except HTTPException as exc:
            log_action(
                db,
                "threat_hunt.unauthorized_attempt",
                user_id=user_id,
                resource="threat_hunts",
                details=denied_by or "invalid or missing credentials",
                ip_address=request.client.host if request.client else None,
            )
            raise

    dependency.__name__ = f"require_roles({','.join(allowed_roles)})"
    return dependency


_require_read = _require_roles(*_READ_ROLES)
_require_mutate = _require_roles(*_MUTATION_ROLES)


def _call_service(fn: Callable[[], T]) -> T:
    """Execute one ThreatHuntService call, translating its errors to HTTP."""
    try:
        return fn()
    except HuntValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    except HuntNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except (
        HuntStateError,
        HuntAlreadyCompletedError,
        HuntAlreadyRunningError,
        HuntAlreadyFailedError,
        HuntAlreadyCancelledError,
        HuntLimitError,
    ) as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except HuntUnexpectedError as exc:
        logger.warning("Threat hunt internal failure: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Threat hunt failed internally",
        ) from exc
    except HuntExecutionError as exc:
        logger.warning("Threat hunt execution failure: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        logger.warning("Threat hunt transport failure: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Threat hunt data is unavailable",
        ) from exc


# ---------------------------------------------------------------------------
# GET /api/threat-hunts — list hunts
# ---------------------------------------------------------------------------


@router.get(
    "",
    response_model=ThreatHuntPage,
    summary="List threat hunts",
    description=(
        "Return persisted threat hunts (newest first), optionally filtered "
        "by status and/or hunt type."
    ),
)
def list_hunts(  # noqa: A001 - route name mirrors the resource
    page: int = Query(default=1, ge=1, description="One-based page."),
    page_size: int = Query(
        default=_DEFAULT_PAGE_SIZE,
        ge=1,
        le=_MAX_PAGE_SIZE,
        description="Rows per page.",
    ),
    status: ThreatHuntStatus | None = Query(
        default=None,
        description="Optional hunt status filter.",
    ),
    hunt_type: HuntType | None = Query(
        default=None,
        description="Optional hunt type filter.",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_read),  # noqa: ARG001
) -> ThreatHuntPage:
    return _call_service(
        lambda: _service.list(
            db,
            actor=current_user,
            page=page,
            page_size=page_size,
            status_filter=status,
            hunt_type_filter=hunt_type,
        )
    )


# ---------------------------------------------------------------------------
# POST /api/threat-hunts — create a draft hunt
# ---------------------------------------------------------------------------


@router.post(
    "",
    response_model=ThreatHuntDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Create a threat hunt",
    description=(
        "Create a validated draft hunt for the given bounded window and "
        "structured filters.  The hunt is not executed until run."
    ),
)
def create_hunt(
    payload: ThreatHuntCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_mutate),  # noqa: ARG001
) -> ThreatHuntDetail:
    return _call_service(lambda: _service.create(db, current_user, payload))


# ---------------------------------------------------------------------------
# GET /api/threat-hunts/{hunt_id} — one hunt
# ---------------------------------------------------------------------------


@router.get(
    "/{hunt_id}",
    response_model=ThreatHuntDetail,
    summary="Fetch one threat hunt",
    description="Return one hunt including its persisted structured filters.",
)
def get_hunt(
    hunt_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_read),  # noqa: ARG001
) -> ThreatHuntDetail:
    return _call_service(lambda: _service.get(db, actor=current_user, hunt_id=hunt_id))


# ---------------------------------------------------------------------------
# POST /api/threat-hunts/{hunt_id}/run — execute once
# ---------------------------------------------------------------------------


@router.post(
    "/{hunt_id}/run",
    response_model=ThreatHuntDetail,
    status_code=status.HTTP_200_OK,
    summary="Run a threat hunt",
    description=(
        "Execute a draft hunt exactly once and persist its evidence, "
        "findings and timeline.  Requiring a draft and executing at most "
        "once; a run that exceeds a bound fails the hunt (409)."
    ),
)
def run_hunt(
    hunt_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_mutate),  # noqa: ARG001
) -> ThreatHuntDetail:
    return _call_service(lambda: _service.run(db, actor=current_user, hunt_id=hunt_id))


# ---------------------------------------------------------------------------
# POST /api/threat-hunts/{hunt_id}/cancel — cancel a draft
# ---------------------------------------------------------------------------


@router.post(
    "/{hunt_id}/cancel",
    response_model=ThreatHuntDetail,
    status_code=status.HTTP_200_OK,
    summary="Cancel a threat hunt",
    description="Cancel a draft hunt.  Terminal/completed hunts cannot be cancelled.",
)
def cancel_hunt(
    hunt_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_mutate),  # noqa: ARG001
) -> ThreatHuntDetail:
    return _call_service(lambda: _service.cancel(db, actor=current_user, hunt_id=hunt_id))


# ---------------------------------------------------------------------------
# GET /api/threat-hunts/{hunt_id}/evidence — evidence page
# ---------------------------------------------------------------------------


@router.get(
    "/{hunt_id}/evidence",
    response_model=ThreatHuntEvidencePage,
    summary="List a hunt's evidence",
    description="Return the persisted evidence items of one hunt (bounded page).",
)
def list_evidence(
    hunt_id: uuid.UUID,
    page: int = Query(default=1, ge=1, description="One-based page."),
    page_size: int = Query(
        default=_DEFAULT_PAGE_SIZE,
        ge=1,
        le=_MAX_PAGE_SIZE,
        description="Rows per page.",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_read),  # noqa: ARG001
) -> ThreatHuntEvidencePage:
    return _call_service(
        lambda: _service.list_evidence(
            db,
            actor=current_user,
            hunt_id=hunt_id,
            page=page,
            page_size=page_size,
        )
    )


# ---------------------------------------------------------------------------
# GET /api/threat-hunts/{hunt_id}/findings — findings page
# ---------------------------------------------------------------------------


@router.get(
    "/{hunt_id}/findings",
    response_model=ThreatHuntFindingPage,
    summary="List a hunt's findings",
    description="Return the deterministic findings of one hunt (bounded page).",
)
def list_findings(
    hunt_id: uuid.UUID,
    page: int = Query(default=1, ge=1, description="One-based page."),
    page_size: int = Query(
        default=_DEFAULT_PAGE_SIZE,
        ge=1,
        le=_MAX_PAGE_SIZE,
        description="Rows per page.",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_read),  # noqa: ARG001
) -> ThreatHuntFindingPage:
    return _call_service(
        lambda: _service.list_findings(
            db,
            actor=current_user,
            hunt_id=hunt_id,
            page=page,
            page_size=page_size,
        )
    )


# ---------------------------------------------------------------------------
# GET /api/threat-hunts/{hunt_id}/timeline — timeline page
# ---------------------------------------------------------------------------


@router.get(
    "/{hunt_id}/timeline",
    response_model=ThreatHuntTimelinePage,
    summary="List a hunt's timeline",
    description="Return the chronological timeline of one hunt (bounded page).",
)
def list_timeline(
    hunt_id: uuid.UUID,
    page: int = Query(default=1, ge=1, description="One-based page."),
    page_size: int = Query(
        default=_DEFAULT_PAGE_SIZE,
        ge=1,
        le=_MAX_PAGE_SIZE,
        description="Rows per page.",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_read),  # noqa: ARG001
) -> ThreatHuntTimelinePage:
    return _call_service(
        lambda: _service.list_timeline(
            db,
            actor=current_user,
            hunt_id=hunt_id,
            page=page,
            page_size=page_size,
        )
    )


__all__ = ["router"]