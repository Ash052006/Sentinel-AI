"""Multi-Agent Debate API — V3.23.

Exposes the bounded debate engine as a thin, authenticated, RBAC-protected
FastAPI surface::

    HTTP request
        -> JWT authentication (existing get_current_user dependency)
        -> RBAC authorization (existing require_role: admin/analyst/ciso)
        -> bounded V3.22 graph (existing KnowledgeGraphQueries)
        -> DebateEngine (5 agents, rounds 0-4, deterministic reconciliation)
        -> DebateService (idempotent persistence)
        -> DebateSessionResponse

Design principles:

* **No evidence creation** — a debate can only cite what the immutable V3.22
  graph already contains.  The engine never writes the graph and never
  invents a reference; an unresolvable citation rejects the entire agent
  output.  This endpoint is analytical, not evidentiary.
* **Bounded** — five agents, a fixed five-round lifecycle, and hard caps on
  claims, arguments, counterarguments, and unresolved questions.  A caller
  cannot request a larger debate.
* **Idempotent** — the session id is a deterministic uuid5 over
  ``(correlation_id, graph_snapshot_digest, configuration_digest)``, and the
  primary key enforces it.  Repeating a POST over an unchanged graph returns the
  stored debate instead of starting a second one.  Changed evidence produces a
  new debate rather than overwriting an old conclusion.
* **No silent fallback** — if the model provider is unavailable, times out, or
  returns output that fails structural validation, the request fails with a
  governed error.  The engine never fabricates a consensus to fill the gap,
  because a fabricated consensus is indistinguishable from a real one to every
  downstream consumer.  The provider is selected server-side from
  ``LLM_PROVIDER`` (Gemini or Groq), one provider serves the whole debate, and
  a failing provider is never quietly replaced by the other.
* **Thin transport** — routes validate input, delegate, and shape a response.
  No route builds SQL, filters in Python, or reaches into the graph internals.

Route ordering note: the collection route ``GET ""`` is registered before
``/{debate_id}`` so the literal path can never be parsed as an identifier.
"""

from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Path, Request, status
from sqlalchemy.orm import Session

from app.agents.debate.engine import DebateEngine
from app.agents.debate.exceptions import (
    DebateBoundsError,
    DebateError,
    DebateEvidenceError,
    DebateModelValidationError,
    DebatePartialFailureError,
    DebateProviderError,
)
from app.agents.debate.runtime import build_debate_runtime
from app.api.dependencies import get_db, require_role
from app.models.user import User
from app.schemas.debate import DebateFailureResponse, DebateSession
from app.services.audit_service import log_action
from app.services.debate.persistence import DebateService
from app.services.knowledge_graph.queries import (
    GraphNodeNotFound,
    KnowledgeGraphQueries,
)
from app.services.knowledge_graph.vocabulary import DEFAULT_BOUNDS

logger = logging.getLogger(__name__)

router = APIRouter(
    # No prefix here: app/api/router.py supplies "/debates" and app.main mounts
    # that under "/api", giving /api/debates/...
    tags=["debates"],
)

#: SOC read access, identical to the existing V2 read conventions and the V3.22
#: knowledge-graph read roles.
DEBATE_READ_ROLES = ("admin", "analyst", "ciso")

#: Failure-to-status mapping.  Every entry is a governed failure: the client is
#: told what failed and why, and no consensus is ever invented to fill the gap.
_PROVIDER_STATUS = {
    "debate_provider_unavailable": status.HTTP_503_SERVICE_UNAVAILABLE,
    "debate_provider_timeout": status.HTTP_504_GATEWAY_TIMEOUT,
    "debate_provider_error": status.HTTP_502_BAD_GATEWAY,
    "debate_model_validation_error": status.HTTP_502_BAD_GATEWAY,
}


def _engine() -> DebateEngine:
    """Build the engine with the configured reasoning provider.

    Provider selection is server-side deployment configuration
    (``Settings.llm_provider``), resolved by ``build_debate_runtime``.  A
    client cannot ask for a specific provider or model here: the endpoint takes
    only a correlation id, so the debate API is not a model-routing control
    surface.

    Deliberately no fallback runtime and no cross-provider retry: an
    unavailable provider must surface as a governed failure, because a
    deterministic stand-in debate — or a debate silently completed by a
    different model than the one recorded in its metadata — would be
    indistinguishable from a real one.
    """
    return DebateEngine(runtime=build_debate_runtime())


def _failure_body(
    *, correlation_id: uuid.UUID, failure_code: str, detail: str
) -> dict:
    """Shape a governed failure body.

    Uses :class:`DebateFailureResponse` so the failure payload is validated by
    the same contract as a success payload, and so a client can never receive a
    consensus-looking response for a failed debate.
    """
    return DebateFailureResponse(
        correlation_id=correlation_id,
        status="failed",
        failure_code=failure_code,
        detail=detail,
    ).model_dump(mode="json")


def _log(
    db: Session,
    *,
    action: str,
    user: User,
    resource: str,
    details: str,
    request: Request | None = None,
) -> None:
    """Record one debate lifecycle event.

    Details carry only non-secret identifiers — never the prompt text, the
    provider endpoint, an API key, or a raw provider response.  An idempotent
    replay is deliberately *not* logged as a new completion: repeating a POST
    over an unchanged graph performs no new reasoning, so recording it as one
    would overstate how much analysis actually happened.
    """
    log_action(
        db,
        action,
        user_id=user.id,
        resource=resource,
        details=details,
        ip_address=request.client.host if request and request.client else None,
    )


def _graph_or_404(db: Session, correlation_id: uuid.UUID):
    """Fetch the bounded graph, mapping absence to 404.

    Raises 404 for both "no such correlation" and "correlation is not in the
    graph" without disclosing which, matching the V3.22 convention.
    """
    queries = KnowledgeGraphQueries(DEFAULT_BOUNDS)
    try:
        return queries.get_correlation_graph(db, correlation_id)
    except GraphNodeNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.post(
    "/{correlation_id}",
    response_model=DebateSession,
    status_code=status.HTTP_200_OK,
    summary="Run or return the deterministic debate for one correlation",
    responses={
        404: {"description": "No persisted graph for this correlation."},
        422: {"description": "Malformed correlation identifier."},
        502: {"description": "Model output failed structural validation."},
        503: {"description": "Model provider unavailable."},
        504: {"description": "Model provider timed out."},
    },
)
def run_debate(
    correlation_id: uuid.UUID = Path(
        ...,
        description="Correlation UUID (correlation_results.correlation_id).",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*DEBATE_READ_ROLES)),
) -> DebateSession:
    """Run the five-agent debate over a correlation's bounded graph.

    Returns 200 with the completed debate.  The response is the same whether
    this call performed the debate or returned an identical existing one; a
    client cannot tell, and does not need to, because the stored conclusion is
    byte-identical either way.
    """
    graph = _graph_or_404(db, correlation_id)
    queries = KnowledgeGraphQueries(DEFAULT_BOUNDS)
    try:
        session = _engine().run(
            graph,
            correlation_id=correlation_id,
            unavailable_entity_types=queries.unavailable_entity_types(),
        )
    except DebatePartialFailureError as exc:
        # At least one agent failed. Reporting a consensus over the surviving
        # subset would misrepresent a partial roster as a full debate. The
        # status is derived from the preserved underlying cause, so a provider
        # outage is reported as 503/504 rather than flattened to a generic 502.
        code = exc.failure_code
        logger.warning(
            "debate partial failure: correlation=%s code=%s failed_agents=%s",
            correlation_id,
            code,
            exc.failed_agents,
        )
        _log(
            db,
            action="debate.failed",
            user=current_user,
            resource="debates",
            details=(
                f"Partial failure for correlation {correlation_id}: {code} "
                f"({len(exc.failed_agents)} agent(s) failed)"
            ),
        )
        raise HTTPException(
            status_code=_PROVIDER_STATUS.get(
                code, status.HTTP_502_BAD_GATEWAY
            ),
            detail=_failure_body(
                correlation_id=correlation_id,
                failure_code=code,
                detail=str(exc),
            ),
        ) from exc
    except (DebateModelValidationError, DebateProviderError) as exc:
        logger.warning(
            "debate failure: correlation=%s code=%s",
            correlation_id,
            exc.failure_code,
        )
        _log(
            db,
            action="debate.failed",
            user=current_user,
            resource="debates",
            details=(
                f"Failure for correlation {correlation_id}: {exc.failure_code}"
            ),
        )
        raise HTTPException(
            status_code=_PROVIDER_STATUS.get(
                exc.failure_code, status.HTTP_502_BAD_GATEWAY
            ),
            detail=_failure_body(
                correlation_id=correlation_id,
                failure_code=exc.failure_code,
                detail=str(exc),
            ),
        ) from exc
    except DebateEvidenceError as exc:
        logger.warning(
            "debate evidence rejection: correlation=%s",
            correlation_id,
        )
        _log(
            db,
            action="debate.rejected",
            user=current_user,
            resource="debates",
            details=(
                f"Evidence validation rejected agent output for correlation "
                f"{correlation_id}: {exc.failure_code}"
            ),
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=_failure_body(
                correlation_id=correlation_id,
                failure_code=exc.failure_code,
                detail=str(exc),
            ),
        ) from exc
    except DebateBoundsError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=_failure_body(
                correlation_id=correlation_id,
                failure_code=exc.failure_code,
                detail=str(exc),
            ),
        ) from exc
    except DebateError as exc:  # pragma: no cover - defensive catch-all
        logger.error("unexpected debate failure: correlation=%s", correlation_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=_failure_body(
                correlation_id=correlation_id,
                failure_code="debate_error",
                detail=str(exc),
            ),
        ) from exc

    stored, created = DebateService(db).persist_session(session)
    if created:
        # Only a genuinely new conclusion is audited as a completion; an
        # idempotent replay performed no new reasoning.
        _log(
            db,
            action="debate.completed",
            user=current_user,
            resource="debates",
            details=(
                f"Debate {stored.debate_id} for correlation "
                f"{stored.correlation_id}: {stored.consensus.state.value} "
                f"(confidence {stored.consensus.confidence:.2f}, "
                f"{stored.metadata.agent_count} agents, "
                f"{len(stored.rounds)} rounds)"
            ),
        )
    logger.info(
        "debate %s correlation=%s consensus=%s confidence=%.2f",
        stored.debate_id,
        stored.correlation_id,
        stored.consensus.state.value,
        stored.consensus.confidence,
    )
    return stored


@router.get(
    "/{debate_id}",
    response_model=DebateSession,
    summary="One stored debate",
    responses={
        404: {"description": "No such debate."},
        422: {"description": "Malformed debate identifier."},
    },
)
def get_debate(
    debate_id: uuid.UUID = Path(
        ...,
        description="Debate UUID (deterministic uuid5).",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*DEBATE_READ_ROLES)),
) -> DebateSession:
    """Return a stored debate exactly as it was recorded.

    A debate conclusion is a record of what was known when the debate ran, so
    this is a strict read of the stored session — never a re-run and never a
    recomputation against the current graph.
    """
    session = DebateService(db).get_session(debate_id)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"debate {debate_id} was not found",
        )
    return session


__all__ = ["DEBATE_READ_ROLES", "router"]