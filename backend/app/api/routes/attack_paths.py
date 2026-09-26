"""Attack Path Visualization API (V2.21) — read-only graph surface.

Exposes the :class:`~app.services.attack_path.service.AttackPathService`
as an authenticated FastAPI surface: fetch the evidence-grounded attack
path graph for one correlation.

Boundaries honoured here (mirrors the V2.20 incident-reports surface):

* **Thin transport only.**  The route validates its HTTP input, calls one
  ``AttackPathService`` method and returns a read model.  No route
  constructs SQL or reaches for a repository.
* **Read-only.**  There is no mutation endpoint: no SOAR execution, no
  response action, no actor blocking.  The path is a projection of what is
  already persisted.
* **Roles, not bodies.**  ``admin``/``analyst``/``ciso`` may read; the
  actor's role comes from the authenticated user, never from a body.
* **Consistent HTTP semantics** — malformed ids map to 422; unknown
  correlations to 404; unexpected source failures to 503; internal defects
  to 500.  Unauthorized attempts are audited (read success is not, to
  avoid audit noise).
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from typing import TypeVar

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.api.dependencies import bearer_scheme, get_current_user, get_db
from app.models.user import User
from app.schemas.attack_path import AttackPathResponse
from app.services.attack_path.errors import (
    AttackPathCorrelationNotFoundError,
    AttackPathError,
    AttackPathSourceError,
)
from app.services.attack_path.service import AttackPathService
from app.services.audit_service import log_action

logger = logging.getLogger(__name__)

router = APIRouter()

_READ_ROLES = ("admin", "analyst", "ciso")

T = TypeVar("T")


def _require_roles(
    *allowed_roles: str,
) -> Callable:
    """Authorized-role dependency for the attack-path surface."""

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
                "attack_path.unauthorized_attempt",
                user_id=user_id,
                resource="attack_paths",
                details=denied_by or "invalid or missing credentials",
                ip_address=request.client.host if request.client else None,
            )
            raise

    dependency.__name__ = f"require_roles({','.join(allowed_roles)})"
    return dependency


_require_read = _require_roles(*_READ_ROLES)


def _call_service(fn: Callable[[], T]) -> T:
    """Execute one AttackPathService call, translating its errors to HTTP."""
    try:
        return fn()
    except AttackPathCorrelationNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except AttackPathSourceError as exc:
        logger.warning("Attack path source failure: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except AttackPathError as exc:
        logger.warning("Attack path projection error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Attack path projection is not valid",
        ) from exc
    except Exception as exc:
        logger.warning("Attack path transport failure: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Attack path data is unavailable",
        ) from exc


# Facade kept behind a module-level singleton so importing the app never
# constructs heavy query services eagerly; reads construct it lazily.
_service: AttackPathService | None = None


def _get_service() -> AttackPathService:
    global _service
    if _service is None:
        _service = AttackPathService()
    return _service


# ---------------------------------------------------------------------------
# GET /api/attack-paths/{correlation_id} — one correlation's graph
# ---------------------------------------------------------------------------


@router.get(
    "/{correlation_id}",
    response_model=AttackPathResponse,
    summary="Fetch the attack path graph for a correlation",
    description=(
        "Return the evidence-grounded, read-only attack-path projection for "
        "one correlation: every node and edge is backed by a persisted "
        "record, deterministically ordered, with per-surface availability "
        "and explicit truncation metadata.  The projection never infers "
        "missing attack steps and performs no writes."
    ),
)
def get_attack_path(
    correlation_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_read),  # noqa: ARG001
) -> AttackPathResponse:
    return _call_service(
        lambda: _get_service().build_graph(db, correlation_id=correlation_id)
    )


__all__ = ["router"]