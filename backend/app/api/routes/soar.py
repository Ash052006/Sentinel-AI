"""SOAR API (V2.18) — thin governed-orchestration transport.

Exposes the :class:`~app.services.soar.service.SoarService` as an
authenticated FastAPI surface: list/read the code-registered playbooks,
list/read executions, execute a playbook under an authorizing policy
decision (sandbox/mock providers only), run a validated dry-run, and cancel
a pending/in-flight execution.

Boundaries honoured here (documented in ``docs/development/soar_v218.md``):

* **Thin transport only.**  Every route validates its HTTP input, calls one
  ``SoarService`` method, and returns a read model.  No route constructs SQL
  or reaches for a repository.
* **Roles, not bodies.**  The actor's role and id are read from the
  authenticated user: ``admin``/``analyst``/``ciso`` may read; only
  ``admin`` may execute, dry-run or cancel.  Request bodies carry the
  decision, a controlled target reference and a playbook id — never a role,
  never a provider id, never a step, never an authorization claim.
* **Playbooks are code-registered.**  There is no route to create, mutate,
  import or delete a playbook; the fixed seed set is synced automatically.
* **V2.18 providers are sandbox/mock.**  Nothing here performs a real-world
  security action or connects to a real external system; dry-runs execute
  nothing and persist nothing.
* **Consistent HTTP semantics** — malformed payloads / unknown playbook map
  to 422; unknown executions/playbooks to 404; lifecycle conflicts
  (cancelling a terminal execution) to 409; sanitized infrastructure
  failures to 503; unexpected internal defects to 500.
* **Route ordering** — static routes are declared before parameterized ones
  so a literal segment never resolves as an id.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from typing import Any, TypeVar

from fastapi import APIRouter, Depends, HTTPException, Request, Query, status
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.api.dependencies import bearer_scheme, get_current_user, get_db
from app.models.user import User
from app.schemas.soar import (
    SoarDryRunResult,
    SoarExecutionPage,
    SoarExecutionRecord,
    SoarExecutionRequest,
    SoarExecutionStatus,
    SoarPlaybookPage,
    SoarPlaybookRecord,
)
from app.services.audit_service import log_action
from app.services.soar import SoarService
from app.services.soar.errors import (
    SoarConflictError,
    SoarInternalError,
    SoarNotFoundError,
    SoarServiceError,
    SoarValidationError,
)

logger = logging.getLogger(__name__)

router = APIRouter()

#: Role surface:
#: * read      -> admin / analyst / ciso
#: * lifecycle -> admin (execute, dry-run, cancel)
_READ_ROLES = ("admin", "analyst", "ciso")
_MUTATION_ROLES = ("admin",)

#: Pagination bounds (mirrors the page contracts in the schemas).
_DEFAULT_PAGE_SIZE = 50
_MAX_PAGE_SIZE = 200

_service = SoarService

T = TypeVar("T")


def _require_roles(
    *allowed_roles: str,
) -> Callable:
    """Authorized-role dependency for the SOAR surface."""

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
                "soar.unauthorized_attempt",
                user_id=user_id,
                resource="soar",
                details=denied_by or "invalid or missing credentials",
                ip_address=request.client.host if request.client else None,
            )
            raise

    dependency.__name__ = f"require_roles({','.join(allowed_roles)})"
    return dependency


_require_read = _require_roles(*_READ_ROLES)
_require_mutate = _require_roles(*_MUTATION_ROLES)


def _call_service(fn: Callable[[], T]) -> T:
    """Execute one SoarService call, translating its errors to HTTP."""
    try:
        return fn()
    except SoarValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    except SoarNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except SoarConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except SoarInternalError as exc:
        logger.warning("SOAR internal failure: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="SOAR orchestration failed internally",
        ) from exc
    except SoarServiceError as exc:
        logger.warning("SOAR service failure: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        logger.warning("SOAR transport failure: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SOAR data is unavailable",
        ) from exc


def _svc(db: Session, actor: User) -> tuple[SoarService, str]:
    role = actor.role.name if actor.role is not None else "unknown"
    return SoarService(), role


# ---------------------------------------------------------------------------
# GET /api/soar/playbooks — code-registered playbook list
# ---------------------------------------------------------------------------


@router.get(
    "/playbooks",
    response_model=SoarPlaybookPage,
    summary="List the code-registered SOAR playbooks",
    description=(
        "Return the fixed, code-owned playbook set (latest active version "
        "of each).  There is no client-side playbook authoring; this surface "
        "is read-only."
    ),
)
def list_playbooks(
    page: int = Query(default=1, ge=1, description="One-based page."),
    page_size: int = Query(
        default=_DEFAULT_PAGE_SIZE,
        ge=1,
        le=_MAX_PAGE_SIZE,
        description="Rows per page.",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_read),  # noqa: ARG001
) -> SoarPlaybookPage:
    return _call_service(
        lambda: _svc(db, current_user)[0].list_playbooks(
            db, page=page, page_size=page_size
        )
    )


# ---------------------------------------------------------------------------
# GET /api/soar/playbooks/{playbook_id} — one registered playbook
# ---------------------------------------------------------------------------


@router.get(
    "/playbooks/{playbook_id}",
    response_model=SoarPlaybookRecord,
    summary="Fetch one registered SOAR playbook",
    description=(
        "Return one code-registered playbook's latest active definition "
        "including its declarative steps."
    ),
)
def get_playbook(
    playbook_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_read),  # noqa: ARG001
) -> SoarPlaybookRecord:
    return _call_service(lambda: _svc(db, current_user)[0].get_playbook(db, playbook_id))


# ---------------------------------------------------------------------------
# GET /api/soar/executions — execution history
# ---------------------------------------------------------------------------


@router.get(
    "/executions",
    response_model=SoarExecutionPage,
    summary="List SOAR executions",
    description=(
        "Return persisted governed executions (newest first), optionally "
        "filtered by status.  Each item includes its step result trace."
    ),
)
def list_executions(
    page: int = Query(default=1, ge=1, description="One-based page."),
    page_size: int = Query(
        default=_DEFAULT_PAGE_SIZE,
        ge=1,
        le=_MAX_PAGE_SIZE,
        description="Rows per page.",
    ),
    status_filter: SoarExecutionStatus | None = Query(
        default=None,
        alias="status",
        description="Optional execution status filter.",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_read),  # noqa: ARG001
) -> SoarExecutionPage:
    return _call_service(
        lambda: _svc(db, current_user)[0].list_executions(
            db,
            page=page,
            page_size=page_size,
            status=status_filter,
        )
    )


# ---------------------------------------------------------------------------
# POST /api/soar/dry-run — validated projection, no side effects
# ---------------------------------------------------------------------------


@router.post(
    "/dry-run",
    status_code=status.HTTP_200_OK,
    response_model=SoarDryRunResult,
    summary="Dry-run a playbook (validate-only, no side effects)",
    description=(
        "Validate a governed submission against the policy gate and project "
        "each step's outcome with the registered providers in simulation "
        "mode.  Executes nothing, persists nothing; the response is a "
        "report with simulated=True."
    ),
)
def dry_run(
    payload: SoarExecutionRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_mutate),
) -> SoarDryRunResult:
    svc, role = _svc(db, current_user)
    return _call_service(
        lambda: svc.dry_run(
            db,
            payload,
            actor_user_id=current_user.id,
            actor_role=role,
            ip_address=request.client.host if request.client else None,
        )
    )


# ---------------------------------------------------------------------------
# POST /api/soar/executions — execute a playbook under a governed decision
# ---------------------------------------------------------------------------


@router.post(
    "/executions",
    status_code=status.HTTP_200_OK,
    response_model=SoarExecutionRecord,
    summary="Execute a registered playbook under an authorizing decision",
    description=(
        "Run a code-registered playbook against the sandbox/mock providers. "
        "The decision is re-verified by an independent policy gate before "
        "any provider is invoked: a DENIED decision is rejected, a "
        "REQUIRES_APPROVAL decision needs a verifiable human approval grant, "
        "and an identical governed submission is never re-executed."
    ),
)
def execute(
    payload: SoarExecutionRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_mutate),
) -> SoarExecutionRecord:
    svc, role = _svc(db, current_user)
    return _call_service(
        lambda: svc.execute(
            db,
            payload,
            actor_user_id=current_user.id,
            actor_role=role,
            ip_address=request.client.host if request.client else None,
        )
    )


# ---------------------------------------------------------------------------
# GET /api/soar/executions/{execution_id} — one execution
# ---------------------------------------------------------------------------


@router.get(
    "/executions/{execution_id}",
    response_model=SoarExecutionRecord,
    summary="Fetch one SOAR execution with its step trace",
    description=(
        "Return the persisted execution identified by its deterministic "
        "execution_id, including every step result."
    ),
)
def get_execution(
    execution_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_read),  # noqa: ARG001
) -> SoarExecutionRecord:
    return _call_service(lambda: _svc(db, current_user)[0].get_execution(db, execution_id))


# ---------------------------------------------------------------------------
# POST /api/soar/executions/{execution_id}/cancel — cancel an in-flight run
# ---------------------------------------------------------------------------


@router.post(
    "/executions/{execution_id}/cancel",
    status_code=status.HTTP_200_OK,
    response_model=SoarExecutionRecord,
    summary="Cancel a pending or in-flight SOAR execution",
    description=(
        "Transition a pending or running execution to cancelled (idempotent "
        "for an already-cancelled run).  Attempting to cancel a terminal "
        "execution is a 409 conflict."
    ),
)
def cancel_execution(
    execution_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_mutate),
) -> SoarExecutionRecord:
    svc, role = _svc(db, current_user)
    return _call_service(
        lambda: svc.cancel(
            db,
            execution_id,
            actor_user_id=current_user.id,
            actor_role=role,
            ip_address=request.client.host if request.client else None,
        )
    )


__all__ = [
    "cancel_execution",
    "dry_run",
    "execute",
    "get_execution",
    "get_playbook",
    "list_executions",
    "list_playbooks",
    "router",
]