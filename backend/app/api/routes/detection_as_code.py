"""Detection-as-Code API (V2.17) — thin governed-lifecycle transport.

Exposes the :class:`~app.services.detection_as_code.lifecycle.LifecycleService`
as an authenticated FastAPI surface: list governed rules, read one rule's
full lifecycle, and drive validate / release / deploy / rollback /
enable-disable transitions.

Architecture::

    HTTP request
        -> JWT authentication (existing get_current_user dependency)
        -> RBAC authorization (ciso = read-only, analyst = read + validate,
           admin = full lifecycle) via an audited 401/403 dependency
        -> LifecycleService (V2.17, transactional + audited)
        -> DetectionAsCodeRuleDetail / rule page / validation read models
        -> HTTP response

Design principles:

* **Thin transport only** — every route validates its HTTP input, calls one
  ``LifecycleService`` method, and returns a read model.  No route queries
  the repository or constructs its own SQL.
* **Roles, not bodies.**  The actor's role and id are read from the
  authenticated user.  The RBAC surface is: ``ciso`` = read-only,
  ``analyst`` = read + validate, ``admin`` = full lifecycle (release,
  deploy, rollback, enable/disable).  Request bodies carry ``rule_id`` /
  version / bump metadata only — never a role, an authorization claim, or a
  content hash.
* **Server-side trust.**  ``validate`` always recomputes the source hash
  server-side; clients can never supply a digest or a fixture path.
* **Consistent HTTP semantics** — malformed payloads / missing bump
  metadata map to 422; unknown rule ids to 404; lifecycle-state conflicts
  (unreleased deploy, re-validate after content change without a bump, ...)
  to 409; sanitized infrastructure failures to 503.  Idempotent transitions
  (re-validate identical content, redeploy the active version) return 200
  with the existing record.
* **Route ordering** — all static/mutation routes are declared before the
  parameterized ``/{rule_id}`` route so a literal segment never resolves as
  a rule id.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import TypeVar

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.api.dependencies import bearer_scheme, get_current_user, get_db
from app.models.user import User
from app.schemas.detection_as_code import (
    DeployRequest,
    DetectionAsCodeRuleDetail,
    DetectionAsCodeRulePage,
    ReleaseRequest,
    RollbackRequest,
    SetEnabledRequest,
    ValidateRuleRequest,
)
from app.services.audit_service import log_action
from app.services.detection_as_code.exceptions import (
    DetectionAsCodeError,
    DetectionRuleNotFoundError,
    VersionConflictError,
)
from app.services.detection_as_code.lifecycle import LifecycleService

logger = logging.getLogger(__name__)

router = APIRouter()

#: Role surface (matches the DAC RBAC contract).
#: * read       -> admin / analyst / ciso
#: * validate   -> admin / analyst
#: * lifecycle  -> admin (release, deploy, rollback, enable/disable)
_READ_ROLES = ("admin", "analyst", "ciso")
_VALIDATE_ROLES = ("admin", "analyst")
_LIFECYCLE_ROLES = ("admin",)

#: Pagination bounds (mirrors the page contract in the schemas).
_DEFAULT_PAGE_SIZE = 50
_MAX_PAGE_SIZE = 200

_service = LifecycleService

T = TypeVar("T")


def _require_roles(
    *allowed_roles: str,
) -> Callable:
    """Authorized-role dependency for the detection-as-code surface."""

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
                "detection_as_code.unauthorized_attempt",
                user_id=user_id,
                resource="detection_as_code",
                details=denied_by or "invalid or missing credentials",
                ip_address=request.client.host if request.client else None,
            )
            raise

    dependency.__name__ = f"require_roles({','.join(allowed_roles)})"
    return dependency


_require_read = _require_roles(*_READ_ROLES)
_require_validate = _require_roles(*_VALIDATE_ROLES)
_require_lifecycle = _require_roles(*_LIFECYCLE_ROLES)


def _call_service(fn: Callable[[], T]) -> T:
    """Execute one LifecycleService call, translating its errors to HTTP."""
    try:
        return fn()
    except VersionConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except DetectionRuleNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except DetectionAsCodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        logger.warning("Detection-as-Code service failure: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Detection-as-Code data is unavailable",
        ) from exc


def _lifecycle(db: Session, actor: User) -> LifecycleService:
    role = actor.role.name if actor.role is not None else "unknown"
    return _service(
        db,
        actor_role=role,
        actor_user_id=actor.id,
    )


# ---------------------------------------------------------------------------
# GET /api/detection-as-code — governed rule list
# ---------------------------------------------------------------------------


@router.get(
    "",
    response_model=DetectionAsCodeRulePage,
    summary="List governed detection rules (latest versions)",
    description=(
        "Return the latest governed version of every rule in the controlled "
        "manifest, ordered deterministically.  Only rules that have been "
        "validated exist here; a governed-but-unvalidated rule is absent "
        "until it is validated."
    ),
)
def list_detection_rules(
    page: int = Query(default=1, ge=1, description="One-based page."),
    page_size: int = Query(
        default=_DEFAULT_PAGE_SIZE,
        ge=1,
        le=_MAX_PAGE_SIZE,
        description="Rows per page.",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_read),  # noqa: ARG001
) -> DetectionAsCodeRulePage:
    return _call_service(lambda: _lifecycle(db, current_user).list_rules(page, page_size))


# ---------------------------------------------------------------------------
# GET /api/detection-as-code/{rule_id} — one rule's full lifecycle
# ---------------------------------------------------------------------------


@router.get(
    "/{rule_id}",
    response_model=DetectionAsCodeRuleDetail,
    summary="Fetch one governed rule with its full lifecycle",
    description=(
        "Return the latest version record plus its recomputable validation "
        "detail, release/deploy history and versioning/rollback history."
    ),
)
def get_detection_rule(
    rule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_read),  # noqa: ARG001
) -> DetectionAsCodeRuleDetail:
    return _call_service(
        lambda: _lifecycle(db, current_user).get_rule_detail(rule_id)
    )


# ---------------------------------------------------------------------------
# POST /api/detection-as-code/validate
# ---------------------------------------------------------------------------


@router.post(
    "/validate",
    status_code=status.HTTP_200_OK,
    summary="Validate a governed rule server-side",
    description=(
        "Run the full fail-closed validation pipeline (source integrity, "
        "hash, secrets, type, severity, metadata, real-engine compile + "
        "fixtures) for one rule.  Re-validating identical content is "
        "idempotent.  A content change since the governed version requires "
        "an explicit version + bump_class + change_reason."
    ),
)
def validate_rule(
    payload: ValidateRuleRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_validate),
) -> dict:
    service = _lifecycle(db, current_user)
    record = _call_service(
        lambda: service.validate_rule(
            payload.rule_id,
            version=payload.version,
            bump_class=payload.bump_class,
            change_reason=payload.change_reason,
        )
    )
    log_action(
        db,
        "detection_as_code.api.validate",
        user_id=current_user.id,
        resource=f"rule:{payload.rule_id}",
        details=f"rule_id={payload.rule_id} version={record.version}",
        ip_address=request.client.host if request.client else None,
    )
    return {"rule_id": record.rule_id, "version": record.version}


# ---------------------------------------------------------------------------
# POST /api/detection-as-code/release
# ---------------------------------------------------------------------------


@router.post(
    "/release",
    status_code=status.HTTP_200_OK,
    summary="Release a validated version",
    description="Promote an already-validated immutable version to RELEASED.",
)
def release_rule(
    payload: ReleaseRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_lifecycle),
) -> dict:
    service = _lifecycle(db, current_user)
    record = _call_service(
        lambda: service.release(payload.rule_id, payload.version)
    )
    log_action(
        db,
        "detection_as_code.api.release",
        user_id=current_user.id,
        resource=f"rule:{payload.rule_id}",
        details=f"rule_id={payload.rule_id} version={payload.version}",
        ip_address=request.client.host if request.client else None,
    )
    return {"rule_id": record.rule_id, "version": record.version}


# ---------------------------------------------------------------------------
# POST /api/detection-as-code/deploy
# ---------------------------------------------------------------------------


@router.post(
    "/deploy",
    status_code=status.HTTP_200_OK,
    summary="Deploy a released version into the governed registry",
    description=(
        "Mark the released version as the active deployment for its rule. "
        "Deploying a new version demotes the previous active version; "
        "redeploying the active version is idempotent."
    ),
)
def deploy_rule(
    payload: DeployRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_lifecycle),
) -> dict:
    service = _lifecycle(db, current_user)
    record = _call_service(
        lambda: service.deploy(payload.rule_id, payload.version)
    )
    log_action(
        db,
        "detection_as_code.api.deploy",
        user_id=current_user.id,
        resource=f"rule:{payload.rule_id}",
        details=f"rule_id={payload.rule_id} version={payload.version}",
        ip_address=request.client.host if request.client else None,
    )
    return {"rule_id": record.rule_id, "version": record.version}


# ---------------------------------------------------------------------------
# POST /api/detection-as-code/rollback
# ---------------------------------------------------------------------------


@router.post(
    "/rollback",
    status_code=status.HTTP_200_OK,
    summary="Roll a rule back to a released version",
    description=(
        "Activate an existing released + validated version, demoting the "
        "currently deployed version.  Rolling back to the already-active "
        "version is idempotent; the target must be a released version."
    ),
)
def rollback_rule(
    payload: RollbackRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_lifecycle),
) -> dict:
    service = _lifecycle(db, current_user)
    record = _call_service(
        lambda: service.rollback(payload.rule_id, payload.version)
    )
    log_action(
        db,
        "detection_as_code.api.rollback",
        user_id=current_user.id,
        resource=f"rule:{payload.rule_id}",
        details=f"rule_id={payload.rule_id} version={payload.version}",
        ip_address=request.client.host if request.client else None,
    )
    return {"rule_id": record.rule_id, "version": record.version}


# ---------------------------------------------------------------------------
# POST /api/detection-as-code/enabled
# ---------------------------------------------------------------------------


@router.post(
    "/enabled",
    status_code=status.HTTP_200_OK,
    summary="Enable or disable a governed rule version",
    description=(
        "Toggle the enabled flag on a governed version.  A disabled rule "
        "stays registered in the deployed registry but is not evaluated."
    ),
)
def set_enabled(
    payload: SetEnabledRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_lifecycle),
) -> dict:
    service = _lifecycle(db, current_user)
    record = _call_service(
        lambda: service.set_enabled(
            payload.rule_id, payload.version, payload.enabled
        )
    )
    log_action(
        db,
        "detection_as_code.api.enabled"
        if payload.enabled
        else "detection_as_code.api.disabled",
        user_id=current_user.id,
        resource=f"rule:{payload.rule_id}",
        details=f"rule_id={payload.rule_id} version={payload.version}",
        ip_address=request.client.host if request.client else None,
    )
    return {"rule_id": record.rule_id, "version": record.version}