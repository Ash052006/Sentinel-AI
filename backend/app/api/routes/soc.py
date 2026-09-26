"""Natural Language SOC API (Step 23) — one read-only natural-language endpoint.

Exposes the :class:`~app.services.soc.engine.SOCQueryService` as a thin,
authenticated FastAPI surface.  The pipeline is::

    POST /api/soc/query
        -> JWT authentication (existing get_current_user dependency)
        -> RBAC authorization (existing require_role: admin/analyst/ciso)
        -> SOCQueryService.parse (LLM → candidate intent, fail-closed)
        -> deterministic allowlist-intent validation
        -> read-only query executor (existing query services)
        -> structured SOCQueryResponse

Design principles:

* **Thin transport only** — the route validates its body, calls one engine
  method, and returns the response contract.  All SOC logic lives in
  ``app.services.soc``.
* **One endpoint, read-only** — the ONLY Natural Language SOC endpoint.
  It is read-only with respect to SentinelAI security data; there is no
  SOC write/action surface, and the engine only composes existing read
  query services.
* **Reuses existing security** — JWT ``HTTPBearer`` + ``require_role``
  (admin/analyst/ciso), the same convention as the Detection, Correlation,
  Risk, and Incident Memory APIs.  Authorization denials are audited by
  ``require_role``.
* **Sanitized HTTP semantics** — 401 unauthenticated / 403 unauthorized /
  422 invalid request or invalid parsed intent / 503 parser-provider or
  data unavailable / 500 sanitized unexpected error.  Raw Gemini responses,
  raw user queries, and database internals are never returned.  Exact
  lookups that miss return a structured ``found=false`` result (200), not a
  404 — the natural-language query itself succeeded.
* **Logging** — user queries are never logged (they may contain sensitive
  security information); only result counts and sanitized failure classes
  are logged, matching the existing no-read-audit convention.

The ``_soc`` module global is replaced in tests (the standard
``monkeypatch.setattr(soc_routes, "_soc", fake)`` pattern).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_db, require_role
from app.models.user import User
from app.schemas.soc_query import SOCQueryRequest, SOCQueryResponse
from app.services.soc.errors import (
    SOCConfigurationError,
    SOCError,
    SOCExecutionError,
    SOCInputValidationError,
    SOCIntentValidationError,
    SOCParserError,
    SOCProviderError,
    SOCSafetyError,
)

logger = logging.getLogger(__name__)

router = APIRouter()

#: Roles allowed to use Natural Language SOC (the existing SOC role model —
#: ``require_role("admin", "analyst", "ciso")``; same convention as the
#: Detection, Correlation, Risk, and Incident Memory APIs).
_SOC_ROLES = ("admin", "analyst", "ciso")

#: Engine instance; replaced in tests via ``monkeypatch.setattr``.
_soc = None


def _get_engine():
    global _soc
    if _soc is None:
        from app.services.soc.engine import SOCQueryService

        _soc = SOCQueryService()
    return _soc


# ---------------------------------------------------------------------------
# Error bridge
# ---------------------------------------------------------------------------


def _map_soc_error(exc: Exception) -> HTTPException:
    """Translate engine errors to the SentinelAI HTTP error contract.

    Sanitized by construction: no raw provider output, no raw user query,
    no secrets, no database internals.
    """

    if isinstance(exc, (SOCInputValidationError, SOCSafetyError)):
        # 422 — invalid request / rejected unsafe parsed intent.
        return HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        )
    if isinstance(exc, SOCIntentValidationError):
        # 422 — unsupported resource/operation, invalid filter, malformed
        # identifier, or illegal pagination in the parsed intent.
        return HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        )
    if isinstance(exc, SOCParserError) and not isinstance(exc, SOCProviderError):
        # 422 — the LLM produced malformed/out-of-contract output; nothing
        # is repaired or executed.
        return HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Unable to interpret the query",
        )
    if isinstance(exc, (SOCProviderError, SOCConfigurationError)):
        # 503 — parser provider unavailable / not configured.
        return HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Natural language understanding is currently unavailable",
        )
    if isinstance(exc, SOCExecutionError):
        # 503 — an existing read query service failed.
        return HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SOC data is unavailable",
        )
    # Unexpected SOC failure — log sanitized, never leak internals.
    logger.warning("Unexpected Natural Language SOC failure: %s", type(exc).__name__)
    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Internal server error",
    )


# ---------------------------------------------------------------------------
# POST /api/soc/query
# ---------------------------------------------------------------------------


@router.post(
    "/query",
    response_model=SOCQueryResponse,
    summary="Ask a read-only Natural Language SOC question",
    description=(
        "Translate a bounded natural-language security-data question into "
        "a validated, allowlisted, read-only SOC query intent and execute "
        "it against the existing read query services.  The response "
        "contains the validated intent, deterministic execution metadata, "
        "the serialized read-model results, count/pagination, deterministic "
        "semantic labels, and a deterministic note.  This endpoint never "
        "executes arbitrary SQL, code, or actions, and never writes to "
        "SentinelAI data."
    ),
)
def natural_language_query(
    payload: SOCQueryRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*_SOC_ROLES)),
) -> SOCQueryResponse:
    # The user query is never logged (it may contain sensitive security
    # information); only the parse outcome and result count are logged.
    logger.info(
        "soc.query start (user=%s, query_bytes=%d)",
        current_user.id,
        len(payload.query),
    )
    engine = _get_engine()
    try:
        response = engine.query(db, payload.query)
    except SOCError as exc:
        raise _map_soc_error(exc) from exc
    logger.info(
        "soc.query done (user=%s, count=%d)",
        current_user.id,
        response.count,
    )
    return response