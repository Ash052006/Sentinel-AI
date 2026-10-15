"""Investigation / Explainability API.

Exposes :class:`~app.services.explainability.ExplainabilityService` as an
authenticated, read-only FastAPI surface: an evidence-grounded explanation of
*why* SentinelAI reached a conclusion about one correlation.

Architecture::

    HTTP request
        -> JWT authentication (existing get_current_user dependency)
        -> RBAC authorization (existing require_role: admin/analyst/ciso)
        -> ExplainabilityService (read-only over persisted records)
        -> configured reasoning provider (Gemini/Groq) via InvestigationAgent
        -> ExplainabilityResult (deterministic dimensions + AI narrative)

Design principles:

* **Thin transport only** — each route validates its HTTP input, calls one
  ``ExplainabilityService`` method, and returns the response contract.  No
  route queries the repository or the database directly and no route mutates
  persisted state.
* **Grounded explanation** — GET returns only the deterministic, source-backed
  dimensions (fast, cacheable).  POST additionally asks the configured AI
  provider for a narrative; the AI may only reference existing evidence and
  failures degrade to ``ai_unavailable`` (never a 5xx and never a fabricated
  narrative).
* **Reuses existing security** — the existing JWT ``HTTPBearer`` dependency and
  ``require_role`` RBAC factory are reused verbatim.
* **Consistent HTTP semantics** — malformed ids map to 422; unknown
  correlations to 404; bound violations to 409; sanitized source failures to
  503.
* **No side effects beyond the configured provider request** — the AI cannot
  execute tools, issue a response, or write anything.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from typing import TypeVar

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.agents.investigation.provider import build_investigation_agent
from app.api.dependencies import get_db, require_role
from app.models.user import User
from app.schemas.explainability import ExplainabilityResult, ExplanationRequest
from app.services.explainability import (
    ExplainabilityBoundError,
    ExplainabilityContextError,
    ExplainabilityError,
    ExplainabilityNotFoundError,
    ExplainabilityService,
    ExplainabilitySources,
    ExplainabilityValidationError,
)

logger = logging.getLogger(__name__)

router = APIRouter()

#: Roles allowed to read explanations (the existing SOC role model).
_SOC_ROLES = ("admin", "analyst", "ciso")

T = TypeVar("T")

# Lazily constructed so importing the app never builds a provider client
# (which would require an API key).  Tests swap in a service with fake sources.
_service: ExplainabilityService | None = None


def _get_service() -> ExplainabilityService:
    global _service
    if _service is None:
        _service = ExplainabilityService(
            ExplainabilitySources(agent_factory=build_investigation_agent)
        )
    return _service


def _call_service(fn: Callable[[], T]) -> T:
    """Execute one ExplainabilityService call, translating errors to HTTP."""
    try:
        return fn()
    except ExplainabilityNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except ExplainabilityValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    except ExplainabilityBoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except ExplainabilityContextError as exc:
        logger.warning("Explainability context failure: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Explanation source data is unavailable",
        ) from exc
    except ExplainabilityError as exc:
        logger.warning("Explainability failure: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="The explanation request is not valid",
        ) from exc
    except Exception as exc:
        logger.warning("Explainability transport failure: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Explanation data is unavailable",
        ) from exc


@router.get(
    "/{correlation_id}/explanation",
    response_model=ExplainabilityResult,
    summary="Explain a correlation (deterministic)",
    description=(
        "Return the deterministic, source-backed explanation of the given "
        "correlation: how its detections, risk assessment, policy, response "
        "and audit context are grounded in persisted records.  No AI provider "
        "is contacted.  A missing correlation returns 404."
    ),
)
def explain_correlation_deterministic(
    correlation_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*_SOC_ROLES)),
) -> ExplainabilityResult:
    return _call_service(
        lambda: _get_service().explain_correlation(
            db, correlation_id, use_ai=False
        )
    )


@router.post(
    "/{correlation_id}/explanation",
    response_model=ExplainabilityResult,
    summary="Explain a correlation (with AI narrative)",
    description=(
        "Return the deterministic explanation plus an optional AI narrative "
        "produced by the configured reasoning provider.  Every AI finding may "
        "only reference existing evidence; ungrounded findings are flagged and "
        "provider failures degrade to status 'ai_unavailable' with the "
        "deterministic dimensions intact.  A missing correlation returns 404."
    ),
)
def explain_correlation_with_ai(
    correlation_id: uuid.UUID,
    payload: ExplanationRequest | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*_SOC_ROLES)),
) -> ExplainabilityResult:
    use_ai = payload.use_ai if payload is not None else True
    return _call_service(
        lambda: _get_service().explain_correlation(
            db, correlation_id, use_ai=use_ai
        )
    )


__all__ = ["router"]
