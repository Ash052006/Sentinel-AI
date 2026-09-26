"""Incident Report API (V2.20) — governed report surface.

Exposes the :class:`~app.services.reporting.service.IncidentReportService`
as an authenticated FastAPI surface: generate a new evidence-grounded AI
incident report for one correlation, and read generated report rows.

Boundaries honoured here:

* **Thin transport only.**  Every route validates its HTTP input, calls one
  ``IncidentReportService`` method, and returns a read model.  No route
  constructs SQL or reaches for a repository.
* **Roles, not bodies.**  The actor's role and id come from the
  authenticated user; ``admin``/``analyst``/``ciso`` may generate and read
  reports.  A request body never carries a role or an authorization claim.
* **Reports never escalate.**  There is no route here to mutate security
  records, block an actor, issue a response action, or invoke SOAR.  The
  generator is strictly read-only over already-persisted history.
* **Consistent HTTP semantics** — malformed payloads map to 422; unknown
  correlations / reports to 404; report bounds and citation/credential
  rejections to 409 / 422; sanitized source or provider failures to 503;
  unexpected internal defects to 500.
* **Route ordering** — static routes are declared before parameterized ones
  so a literal segment never resolves as an id.
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
from app.schemas.incident_report import (
    DEFAULT_REPORT_PAGE_SIZE,
    MAX_REPORT_PAGE_SIZE,
    IncidentReportGenerateRequest,
    IncidentReportPage,
    IncidentReportRecord,
)
from app.services.audit_service import log_action
from app.services.reporting.errors import (
    IncidentReportError,
    ReportBoundError,
    ReportContextError,
    ReportCorrelationNotFoundError,
    ReportEvidenceError,
    ReportNotFoundError,
    ReportProviderError,
    ReportSecretSafetyError,
    ReportUnexpectedError,
    ReportValidationError,
)
from app.services.reporting.service import IncidentReportService

logger = logging.getLogger(__name__)

router = APIRouter()

_READ_ROLES = ("admin", "analyst", "ciso")
_MUTATION_ROLES = ("admin", "analyst", "ciso")

T = TypeVar("T")


def _require_roles(
    *allowed_roles: str,
) -> Callable:
    """Authorized-role dependency for the incident-report surface."""

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
                "incident_report.unauthorized_attempt",
                user_id=user_id,
                resource="incident_reports",
                details=denied_by or "invalid or missing credentials",
                ip_address=request.client.host if request.client else None,
            )
            raise

    dependency.__name__ = f"require_roles({','.join(allowed_roles)})"
    return dependency


_require_read = _require_roles(*_READ_ROLES)
_require_mutate = _require_roles(*_MUTATION_ROLES)


def _call_service(fn: Callable[[], T]) -> T:
    """Execute one IncidentReportService call, translating its errors to HTTP."""
    try:
        return fn()
    except ReportBoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except ReportNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except ReportCorrelationNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except ReportValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    except (ReportEvidenceError, ReportSecretSafetyError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    except (ReportContextError, ReportProviderError) as exc:
        logger.warning("Incident report source/provider failure: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except ReportUnexpectedError as exc:
        logger.warning("Incident report internal failure: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Incident report failed internally",
        ) from exc
    except IncidentReportError as exc:
        logger.warning("Incident report error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Incident report is not valid",
        ) from exc
    except Exception as exc:
        logger.warning("Incident report transport failure: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Incident report data is unavailable",
        ) from exc


# Lazily constructed so importing the app never requires a configured Gemini
# API key (reads never construct the generator).  Tests swap in a service
# whose generator uses a fake LLM.
_service: IncidentReportService | None = None


def _get_service() -> IncidentReportService:
    global _service
    if _service is None:
        _service = IncidentReportService()
    return _service


# ---------------------------------------------------------------------------
# GET /api/incident-reports — list reports
# ---------------------------------------------------------------------------


@router.get(
    "",
    response_model=IncidentReportPage,
    summary="List incident reports",
    description=(
        "Return persisted incident reports (newest first), optionally "
        "filtered by the correlation they anchor to."
    ),
)
def list_reports(
    page: int = Query(default=1, ge=1, description="One-based page."),
    page_size: int = Query(
        default=DEFAULT_REPORT_PAGE_SIZE,
        ge=1,
        le=MAX_REPORT_PAGE_SIZE,
        description="Rows per page.",
    ),
    correlation_id: uuid.UUID | None = Query(
        default=None,
        description="Optional correlation filter.",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_read),  # noqa: ARG001
) -> IncidentReportPage:
    return _call_service(
        lambda: _get_service().list(
            db,
            page=page,
            page_size=page_size,
            correlation_id=correlation_id,
        )
    )


# ---------------------------------------------------------------------------
# POST /api/incident-reports/generate — generate one report
# ---------------------------------------------------------------------------


@router.post(
    "/generate",
    response_model=IncidentReportRecord,
    status_code=status.HTTP_201_CREATED,
    summary="Generate an incident report",
    description=(
        "Generate and persist exactly one new evidence-grounded AI incident "
        "report for the given correlation.  The generator is strictly "
        "read-only over already-persisted records; a new report row is "
        "created on every call."
    ),
)
def generate_report(
    payload: IncidentReportGenerateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_mutate),  # noqa: ARG001
) -> IncidentReportRecord:
    return _call_service(
        lambda: _get_service().generate(
            db,
            actor=current_user,
            correlation_id=payload.correlation_id,
        )
    )


# ---------------------------------------------------------------------------
# GET /api/incident-reports/{report_id} — one report
# ---------------------------------------------------------------------------


@router.get(
    "/{report_id}",
    response_model=IncidentReportRecord,
    summary="Fetch one incident report",
    description=(
        "Return one report including its full assembled payload (None for "
        "failed rows)."
    ),
)
def get_report(
    report_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_read),  # noqa: ARG001
) -> IncidentReportRecord:
    return _call_service(
        lambda: _get_service().get(db, report_id=report_id)
    )


__all__ = ["router"]