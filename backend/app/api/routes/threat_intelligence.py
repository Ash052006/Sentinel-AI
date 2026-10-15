"""Threat Intelligence API (Step 8A) — read-only transport for Step 8A data.

Exposes the Step 8A persisted threat-intelligence records
(:class:`~app.models.threat_intel_indicator.ThreatIntelIndicator` and
:class:`~app.models.threat_intel_lookup.ThreatIntelLookup`) as an
authenticated, RBAC-guarded, read-only FastAPI surface over the Step 8A
query layer.

Architecture::

    HTTP request
        -> JWT authentication (existing get_current_user dependency)
        -> RBAC authorization (existing require_role: admin/analyst/ciso)
        -> ThreatIntelQueryService (read-only)
        -> 8A read-model response schema
        -> HTTP response

Design principles:

* **Thin transport only** — every route validates its HTTP input, calls one
  :class:`~app.services.threat_intelligence_query.ThreatIntelQueryService`
  method, and returns a Step-8A read model.  No route performs indicator
  logic, constructs its own SQL, paginates manually, or mutates state.
* **Read-only** — only ``GET`` endpoints are defined.  Indicators and
  lookups are created solely by the Threat Intelligence Agent and
  :class:`~app.services.threat_intelligence_persistence.ThreatIntelligencePersistenceService`;
  there is no create/update/delete path here, by design.
* **Reuses existing security** — the existing JWT ``HTTPBearer`` dependency
  and the existing ``require_role`` RBAC factory are reused verbatim; no
  second authentication system, no query-string/body/custom-header auth.
* **Bounded and deterministic** — pagination is capped by the service, and
  ordering includes an ``id`` tie-break so pages cannot duplicate or drop
  rows.
* **No fabricated verdicts** — the response contains no malicious/benign
  verdict, severity, or risk field, because Step 8A persists none.  Provider
  outcomes are reported as the stored ``status``/``found`` values they are.
* **No secrets** — no provider credential, API key, raw provider response
  body, or raw provider exception ever appears in a response; the service
  re-sanitizes stored evidence and error text on read.

Logging follows the existing API conventions: successful reads are not
logged (no read-audit convention exists), authorization denials are audited
by ``require_role``, and query failures are logged sanitized by the
centralized exception handler.
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
from app.schemas.threat_intelligence_query import (
    ThreatIntelIndicatorDetail,
    ThreatIntelIndicatorEvents,
    ThreatIntelIndicatorPage,
)
from app.services.threat_intelligence_query import (
    DEFAULT_PAGE_SIZE,
    MAX_EVENTS_PER_INDICATOR,
    MAX_LOOKUPS_PER_INDICATOR,
    MAX_PAGE_SIZE,
    ThreatIntelIndicatorNotFoundError,
    ThreatIntelQueryError,
    ThreatIntelQueryService,
    ThreatIntelQueryValidationError,
)

logger = logging.getLogger(__name__)

router = APIRouter()

T = TypeVar("T")

#: Read access mirrors the other SOC read surfaces: analysts and CISOs can
#: read threat intelligence; ``viewer`` is intentionally excluded exactly as
#: it is for detections, correlations, risks, and incident reports.
_READ_ROLES = ("admin", "analyst", "ciso")

_require_read = require_role(*_READ_ROLES)


def _call_service(fn: Callable[[], T]) -> T:
    """Execute one query-service call, translating its errors to HTTP."""
    try:
        return fn()
    except ThreatIntelIndicatorNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Indicator not found",
        ) from exc
    except ThreatIntelQueryValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    except ThreatIntelQueryError as exc:
        logger.warning("Threat intelligence query failure: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Threat intelligence data is temporarily unavailable",
        ) from exc


def _get_service(db: Session) -> ThreatIntelQueryService:
    return ThreatIntelQueryService(db)


# ---------------------------------------------------------------------------
# GET /api/threat-intelligence/indicators — list indicators
# ---------------------------------------------------------------------------


@router.get(
    "/indicators",
    response_model=ThreatIntelIndicatorPage,
    summary="List threat-intelligence indicators",
    description=(
        "Return a bounded, deterministically ordered page of persisted "
        "threat-intelligence indicators (most recently observed first), "
        "optionally filtered by indicator type and/or a value substring.  "
        "Each record carries a rollup of its persisted provider lookups; no "
        "verdict, severity, or risk is returned because none is persisted."
    ),
)
def list_indicators(
    page: int = Query(default=1, ge=1, description="One-based page."),
    page_size: int = Query(
        default=DEFAULT_PAGE_SIZE,
        ge=1,
        le=MAX_PAGE_SIZE,
        description="Rows per page.",
    ),
    indicator_type: str | None = Query(
        default=None,
        description=(
            "Optional exact filter on indicator type: ip, domain, url, or hash."
        ),
    ),
    q: str | None = Query(
        default=None,
        description=(
            "Optional case-insensitive substring filter on the indicator value "
            "or canonical key (e.g. '8.8.8.8')."
        ),
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_read),  # noqa: ARG001
) -> ThreatIntelIndicatorPage:
    return _call_service(
        lambda: _get_service(db).list_indicators(
            page=page,
            page_size=page_size,
            indicator_type=indicator_type,
            value_filter=q,
        )
    )


# ---------------------------------------------------------------------------
# GET /api/threat-intelligence/indicators/{indicator_id} — indicator detail
# ---------------------------------------------------------------------------


@router.get(
    "/indicators/{indicator_id}",
    response_model=ThreatIntelIndicatorDetail,
    summary="Get one threat-intelligence indicator with its lookups",
    description=(
        "Return one persisted indicator together with its bounded provider "
        "lookup history (VirusTotal / AbuseIPDB / AlienVault OTX), the distinct "
        "security-event ids it was extracted from, and per-lookup provider "
        "status.  Provider outcomes are reported exactly as persisted; a "
        "failed lookup is shown as a failure, never as a malicious verdict."
    ),
)
def get_indicator(
    indicator_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_read),  # noqa: ARG001
) -> ThreatIntelIndicatorDetail:
    return _call_service(
        lambda: _get_service(db).get_indicator(
            indicator_id,
            lookup_limit=MAX_LOOKUPS_PER_INDICATOR,
            event_limit=MAX_EVENTS_PER_INDICATOR,
        )
    )


# ---------------------------------------------------------------------------
# GET /api/threat-intelligence/indicators/{id}/events — event correlation
# ---------------------------------------------------------------------------


@router.get(
    "/indicators/{indicator_id}/events",
    response_model=ThreatIntelIndicatorEvents,
    summary="List the events an indicator was observed in",
    description=(
        "Return the distinct security-event ids a persisted indicator was "
        "extracted from, read from the ``event_id`` recorded on its lookups.  "
        "This is a correlation view over an existing column; it invents no "
        "relationship.  SentinelAI persists no security-event table, so the "
        "ids are correlation keys and are not dereferenced further."
    ),
)
def list_indicator_events(
    indicator_id: uuid.UUID,
    limit: int = Query(
        default=MAX_EVENTS_PER_INDICATOR,
        ge=1,
        le=MAX_EVENTS_PER_INDICATOR,
        description="Maximum distinct event ids to return.",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_read),  # noqa: ARG001
) -> ThreatIntelIndicatorEvents:
    return _call_service(
        lambda: _get_service(db).list_indicator_events(indicator_id, limit=limit)
    )
