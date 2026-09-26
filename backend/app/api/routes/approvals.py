"""Approval Workflow API (V2.16) — thin human-in-the-loop transport.

Exposes the :class:`~app.services.approval.ApprovalService` as an
authenticated FastAPI surface: create a pending approval for a
``REQUIRES_APPROVAL`` policy decision, list/read approvals, and resolve
them (approve / reject / cancel) with a required accountability comment.

Architecture::

    HTTP request
        -> JWT authentication (existing get_current_user dependency)
        -> RBAC authorization (SOC roles: admin / analyst / ciso) with an
           audited approval-specific 401/403 dependency
        -> ApprovalService (V2.16, transactional)
        -> ApprovalRecord / ApprovalPage read model
        -> HTTP response

Design principles:

* **Thin transport only** — every route validates its HTTP input, calls one
  ``ApprovalService`` method, and returns a read model.  No route queries
  the repository or database directly.
* **Reuses existing security** — the existing JWT ``HTTPBearer`` scheme and
  identity resolution are reused verbatim.  This module adds a small
  authorized-role dependency that also audits denied attempts
  (``approval.unauthorized_attempt``) so governance actions are
  attributable; there is still no second authentication system.
* **Roles, not bodies.**  The actor's identity and role are read from the
  authenticated user (the trusted store).  The request body carries the
  decision, target, optional note, and resolution comment only — never a
  role, an action, or an authorization claim.
* **Consistent HTTP semantics** — malformed input / non-REQUIRES_APPROVAL
  decisions map to 422; unknown approval ids to 404; lifecycle conflicts
  (already resolved, expired decisions) to 409; idempotent re-create /
  re-approve return 200 with the existing record; sanitized infrastructure
  failures to 503.
* **Route ordering** — the static ``/recent`` route is registered before
  the parameterized ``/{approval_id}`` route so a literal ``/recent``
  segment never resolves as a UUID.
* **No response-service import.**  This module deliberately imports only
  the approval service package and never the Step 25 response service, so
  the response/execution surface stays out of the HTTP layer.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from typing import TypeVar

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.api.dependencies import bearer_scheme, get_current_user, get_db
from app.models.user import User
from app.schemas.approval import (
    ApprovalDecisionInput,
    ApprovalPage,
    ApprovalRecord,
    ApprovalRequestCreate,
    ApprovalStatus,
)
from app.services.approval import (
    APPROVAL_SOC_ROLES,
    ApprovalConflictError,
    ApprovalNotFoundError,
    ApprovalService,
    ApprovalServiceError,
    ApprovalValidationError,
    DEFAULT_PAGE_SIZE,
    DEFAULT_RECENT_LIMIT,
    MAX_PAGE_SIZE,
    MAX_RECENT_LIMIT,
)
from app.services.audit_service import log_action

logger = logging.getLogger(__name__)

router = APIRouter()

#: Stateless service shared by every approval route (sessions are passed
#: per call, matching the risk-query convention).
_service = ApprovalService()

T = TypeVar("T")


def _require_soc_role(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Authorized-role dependency for the approval surface.

    Reuses the existing identity lookup verbatim (it returns 401 on an
    invalid token and 403 on an inactive account), audits every denied
    attempt as ``approval.unauthorized_attempt`` (without echoing the
    credential), and then requires one of the SOC roles.  No second
    authentication system — this is the same HTTPBearer scheme the rest of
    the API uses.
    """
    denied_by = None
    user_id = None
    try:
        user = get_current_user(credentials, db)
        user_id = user.id
        if user.role is None or user.role.name not in APPROVAL_SOC_ROLES:
            denied_by = "insufficient role"
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return user
    except HTTPException as exc:
        log_action(
            db,
            "approval.unauthorized_attempt",
            user_id=user_id,
            resource="approval",
            details=denied_by or "invalid or missing credentials",
            ip_address=request.client.host if request.client else None,
        )
        raise


def _call_service(fn: Callable[[], T]) -> T:
    """Execute one ApprovalService call, translating its errors to HTTP."""
    try:
        return fn()
    except ApprovalValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    except ApprovalNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except ApprovalConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except ApprovalServiceError as exc:
        logger.warning("Approval service failure: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Approval data is unavailable",
        ) from exc


def _structured_status(
    actor: User,
    ip_address: str | None,
) -> "tuple[uuid.UUID, str, str | None]":
    """Return (actor id, actor role, caller ip) for a service call."""
    role = actor.role.name if actor.role is not None else "unknown"
    return actor.id, role, ip_address


# ---------------------------------------------------------------------------
# POST /api/approvals — route a REQUIRES_APPROVAL decision to a human
# ---------------------------------------------------------------------------


@router.post(
    "",
    response_model=ApprovalRecord,
    status_code=status.HTTP_201_CREATED,
    summary="Create an approval request",
    description=(
        "Route a REQUIRES_APPROVAL policy decision to an authorized human. "
        "The action is inherited from the decision; creating the same "
        "decision again is idempotent while pending/approved and a 409 once "
        "it has resolved."
    ),
)
def create_approval_request(
    payload: ApprovalRequestCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_soc_role),
) -> ApprovalRecord:
    actor_id, actor_role, ip = _structured_status(current_user, request.client.host if request.client else None)
    return _call_service(
        lambda: _service.create_request(
            db,
            payload,
            actor_user_id=actor_id,
            actor_role=actor_role,
            ip_address=ip,
        )
    )


# ---------------------------------------------------------------------------
# GET /api/approvals — collections (static /recent registered first)
# ---------------------------------------------------------------------------


@router.get(
    "/recent",
    response_model=list[ApprovalRecord],
    summary="List recent approval requests",
    description=(
        "Return the newest approval requests (bounded feed, default 50, "
        "max 200), deterministic timestamp-descending order, optionally "
        "filtered by status."
    ),
)
def list_recent_approvals(
    limit: int = Query(
        DEFAULT_RECENT_LIMIT,
        ge=1,
        le=MAX_RECENT_LIMIT,
        description="Maximum number of approvals to return (1..200).",
    ),
    approval_status: ApprovalStatus | None = Query(
        default=None,
        alias="status",
        description="Optional status filter (pending/approved/rejected/expired/cancelled).",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_soc_role),
) -> list[ApprovalRecord]:
    return _call_service(
        lambda: _service.list_recent_requests(
            db,
            limit=limit,
            status=approval_status,
        )
    )


@router.get(
    "",
    response_model=ApprovalPage,
    summary="List approval requests (paged)",
    description=(
        "Return one bounded page of approval requests, newest first, with a "
        "database-side total.  Optionally filtered by status.  Empty result "
        "sets return 200 with an empty items list."
    ),
)
def list_approvals(
    page: int = Query(1, ge=1, description="1-based page number."),
    page_size: int = Query(
        DEFAULT_PAGE_SIZE,
        ge=1,
        le=MAX_PAGE_SIZE,
        description="Maximum items per page (1..200).",
    ),
    approval_status: ApprovalStatus | None = Query(
        default=None,
        alias="status",
        description="Optional status filter (pending/approved/rejected/expired/cancelled).",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_soc_role),
) -> ApprovalPage:
    return _call_service(
        lambda: _service.list_requests(
            db,
            page=page,
            page_size=page_size,
            status=approval_status,
        )
    )


@router.get(
    "/{approval_id}",
    response_model=ApprovalRecord,
    summary="Get one approval request",
    description=(
        "Return the approval request identified by its deterministic "
        "approval_id.  A missing request returns 404."
    ),
)
def get_approval(
    approval_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_soc_role),
) -> ApprovalRecord:
    record = _call_service(lambda: _service.get_request(db, approval_id))
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Approval request not found",
        )
    return record


# ---------------------------------------------------------------------------
# POST /api/approvals/{approval_id}/... — human resolutions
# ---------------------------------------------------------------------------


@router.post(
    "/{approval_id}/approve",
    response_model=ApprovalRecord,
    summary="Approve an approval request",
    description=(
        "Grant a pending approval (required accountability comment).  "
        "Approval authorizes — and only authorizes — the Step 25 Response "
        "layer to simulate the action; a separate response_status records "
        "what actually happened.  Approving an already-approved request is "
        "idempotent; resolving a non-pending request is a 409."
    ),
)
def approve_approval(
    approval_id: uuid.UUID,
    decision: ApprovalDecisionInput,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_soc_role),
) -> ApprovalRecord:
    actor_id, actor_role, ip = _structured_status(current_user, request.client.host if request.client else None)
    return _call_service(
        lambda: _service.approve(
            db,
            approval_id,
            decision,
            actor_user_id=actor_id,
            actor_role=actor_role,
            ip_address=ip,
        )
    )


@router.post(
    "/{approval_id}/reject",
    response_model=ApprovalRecord,
    summary="Reject an approval request",
    description=(
        "Refuse a pending approval (required accountability comment).  "
        "Terminal — a rejected request never executes anything."
    ),
)
def reject_approval(
    approval_id: uuid.UUID,
    decision: ApprovalDecisionInput,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_soc_role),
) -> ApprovalRecord:
    actor_id, actor_role, ip = _structured_status(current_user, request.client.host if request.client else None)
    return _call_service(
        lambda: _service.reject(
            db,
            approval_id,
            decision,
            actor_user_id=actor_id,
            actor_role=actor_role,
            ip_address=ip,
        )
    )


@router.post(
    "/{approval_id}/cancel",
    response_model=ApprovalRecord,
    summary="Cancel an approval request",
    description=(
        "Withdraw a pending approval before resolution (required "
        "accountability comment).  Terminal."
    ),
)
def cancel_approval(
    approval_id: uuid.UUID,
    decision: ApprovalDecisionInput,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_soc_role),
) -> ApprovalRecord:
    actor_id, actor_role, ip = _structured_status(current_user, request.client.host if request.client else None)
    return _call_service(
        lambda: _service.cancel(
            db,
            approval_id,
            decision,
            actor_user_id=actor_id,
            actor_role=actor_role,
            ip_address=ip,
        )
    )