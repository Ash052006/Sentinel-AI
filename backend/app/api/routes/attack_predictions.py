"""Attack Prediction Engine API (V3.24) — authenticated prediction surface.

Routes (mounted under ``/api``):

* ``POST /api/attack-predictions/{correlation_id}`` — run (or return) the
  deterministic prediction for one correlation.
* ``GET  /api/attack-predictions/{prediction_id}`` — read one stored prediction.

Three deliberate constraints:

**The client cannot define a prediction.**  The POST body is empty: it takes a
correlation id and nothing else.  A client cannot submit a technique, a
confidence, evidence or a predicted stage and have the server believe it.  Every
such value is derived server-side from persisted evidence, the V3.22 graph and
the V3.23 debate.  A request body carrying a technique would be a client
attempting to fabricate an analytical conclusion, and the role check — not a
field filter — is what keeps it out.

**A failure never becomes a prediction.**  Context, bounds and validation
failures surface as governed status codes carrying a
:class:`PredictionFailureResponse`.  The engine never falls back to a fabricated
plausible answer to keep a client happy.

**Replay is not re-reasoning.**  Re-POSTing over unchanged inputs performs no
new analysis, so it is not logged as a new completion; audit records should
reflect how much reasoning actually happened, not how many times a client
retried.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable

from fastapi import APIRouter, Depends, HTTPException, Path, Request, status
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.agents.prediction.engine import AttackPredictionEngine
from app.api.dependencies import bearer_scheme, get_current_user, get_db
from app.models.user import User
from app.schemas.attack_prediction import PredictionFailureResponse, PredictionResult
from app.services.audit_service import log_action
from app.services.prediction.context import assemble_prediction_inputs
from app.services.prediction.exceptions import (
    PredictionBoundsError,
    PredictionContextError,
    PredictionError,
    PredictionPersistenceError,
    failure_code,
)
from app.services.prediction.persistence import AttackPredictionService
from app.services.prediction.vocabulary import DEFAULT_PREDICTION_BOUNDS, PredictionBounds

logger = logging.getLogger(__name__)

# No prefix here: app/api/router.py supplies "/attack-predictions" and app.main
# mounts that under "/api", giving /api/attack-predictions/...
router = APIRouter(tags=["attack-predictions"])

#: SOC read access, identical to the V3.22 graph and V3.23 debate read roles.
ATTACK_PREDICTION_READ_ROLES = ("admin", "analyst", "ciso")

#: Failure-to-status mapping.  Every entry is governed: the client learns
#: exactly which failure occurred, and no prediction is invented to cover it.
_PREDICTION_STATUS: dict[str, int] = {
    "prediction_bounds_error": status.HTTP_422_UNPROCESSABLE_CONTENT,
    "prediction_context_error": status.HTTP_404_NOT_FOUND,
    "prediction_evidence_error": status.HTTP_422_UNPROCESSABLE_CONTENT,
    "prediction_validation_error": status.HTTP_500_INTERNAL_SERVER_ERROR,
    "prediction_configuration_error": status.HTTP_503_SERVICE_UNAVAILABLE,
    "prediction_persistence_error": status.HTTP_503_SERVICE_UNAVAILABLE,
    "prediction_not_found": status.HTTP_404_NOT_FOUND,
    "prediction_error": status.HTTP_500_INTERNAL_SERVER_ERROR,
}


def _require_roles(*allowed_roles: str) -> Callable:
    """Role dependency that audits every denied attempt.

    Wrapping the credential check itself (rather than trusting FastAPI to reject
    the request first) is what makes the audit entry trustworthy: an anonymous
    caller, an expired token and a valid-but-insufficient role all produce one
    ``attack_prediction.unauthorized_attempt`` row, with the user id recorded
    only when a user was actually resolved.
    """

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
                "attack_prediction.unauthorized_attempt",
                user_id=user_id,
                resource="attack_predictions",
                details=denied_by or "invalid or missing credentials",
                ip_address=request.client.host if request.client else None,
            )
            raise

    dependency.__name__ = f"require_roles({','.join(allowed_roles)})"
    return dependency


_require_read = _require_roles(*ATTACK_PREDICTION_READ_ROLES)


def _engine() -> AttackPredictionEngine:
    """Build the deterministic engine.

    V3.24 performs no model call, so there is no provider to select, no fallback
    to configure and no cloud dependency: identical inputs always yield
    identical predictions.  The ``provider``/``model`` recorded on a result
    describe the *consumed* V3.23 debate, never a call this engine made.
    """
    return AttackPredictionEngine()


def _bounds() -> PredictionBounds:
    return DEFAULT_PREDICTION_BOUNDS


def _failure_body(
    *,
    correlation_id: uuid.UUID | None,
    prediction_session_id: uuid.UUID | None,
    code: str,
    detail: str,
) -> dict:
    """Shape a governed failure body.

    Validated through :class:`PredictionFailureResponse` so a failure is checked
    by the same contract family as a success: a client can never receive a
    prediction-shaped response for a run that failed.
    """
    return PredictionFailureResponse(
        correlation_id=correlation_id,
        prediction_session_id=prediction_session_id,
        status="failed",
        failure_code=code,
        detail=detail,
    ).model_dump(mode="json")


def _raise_prediction_failure(exc: PredictionError, correlation_id: uuid.UUID) -> None:
    """Translate one engine failure into its governed HTTP response.

    ``str(exc)`` is safe to return: prediction failure messages are authored in
    this module and describe missing or malformed *persisted* data, so they carry
    no secret, credential or provider payload.  That is a deliberate boundary —
    provider errors are never routed through here.
    """
    code = failure_code(exc)
    logger.warning("Prediction failure: correlation=%s code=%s", correlation_id, code)
    raise HTTPException(
        status_code=_PREDICTION_STATUS.get(code, status.HTTP_500_INTERNAL_SERVER_ERROR),
        detail=_failure_body(
            correlation_id=correlation_id,
            prediction_session_id=None,
            code=code,
            detail=str(exc),
        ),
    ) from exc


# ---------------------------------------------------------------------------
# POST /api/attack-predictions/{correlation_id}
# ---------------------------------------------------------------------------


@router.post(
    "/{correlation_id}",
    response_model=PredictionResult,
    status_code=status.HTTP_200_OK,
    summary="Run or return the deterministic attack prediction for one correlation",
    description=(
        "Produce an evidence-grounded prediction of plausible next attack "
        "progression for one correlation.  Every prediction must be supported "
        "by at least one resolvable persisted graph reference; the engine "
        "persists no new evidence, creates no graph rows, and returns "
        "INSUFFICIENT_EVIDENCE rather than speculate when nothing is grounded."
    ),
    responses={
        401: {"description": "Missing or invalid credentials."},
        403: {"description": "Authenticated but not permitted to predict."},
        404: {"description": "No persisted graph exists for this correlation."},
        422: {"description": "Malformed correlation id, or a bound was exceeded."},
        500: {"description": "Prediction failed validation."},
        503: {"description": "Prediction inputs or persistence were unavailable."},
    },
)
def run_prediction(
    request: Request,
    correlation_id: uuid.UUID = Path(
        ...,
        description="Correlation UUID (correlation_results.correlation_id).",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_read),
) -> PredictionResult:
    """Predict plausible next attack progression for a correlation.

    Returns 200 both when this call performed the analysis and when it returned
    an identical existing prediction.  A client cannot tell the difference and
    does not need to: the stored conclusion is identical either way, because the
    session identity is derived from immutable inputs.
    """
    bounds = _bounds()
    try:
        inputs = assemble_prediction_inputs(db, correlation_id, bounds=bounds)
    except PredictionContextError as exc:
        log_action(
            db,
            "attack_prediction.failed",
            user_id=current_user.id,
            resource=f"correlation:{correlation_id}",
            details=f"code={failure_code(exc)} reason=no_persisted_graph",
            ip_address=request.client.host if request.client else None,
        )
        _raise_prediction_failure(exc, correlation_id)
        raise  # unreachable; _raise_prediction_failure always raises

    try:
        result = _engine().predict(inputs)
    except PredictionError as exc:
        log_action(
            db,
            "attack_prediction.failed",
            user_id=current_user.id,
            resource=f"correlation:{correlation_id}",
            details=f"code={failure_code(exc)}",
            ip_address=request.client.host if request.client else None,
        )
        _raise_prediction_failure(exc, correlation_id)
        raise  # unreachable; keeps type checkers from using a possibly-unbound name

    # Persistence runs before any success audit is written. The audit trail has
    # to describe what the database actually holds: logging "created" first
    # would leave a permanent record of a session that a failed write never
    # produced, and would log a "created" event on an idempotent replay that
    # created nothing.
    service = AttackPredictionService(db)
    try:
        stored, created = service.persist_result(result)
    except PredictionPersistenceError as exc:
        log_action(
            db,
            "attack_prediction.failed",
            user_id=current_user.id,
            resource=f"correlation:{correlation_id}",
            details=f"code={failure_code(exc)}",
            ip_address=request.client.host if request.client else None,
        )
        _raise_prediction_failure(exc, correlation_id)
        raise  # unreachable

    if created:
        log_action(
            db,
            "attack_prediction.created",
            user_id=current_user.id,
            resource=f"correlation:{correlation_id}",
            details=(
                f"session={stored.prediction_session_id} "
                f"predictions={len(stored.predictions)} "
                f"status={stored.status.value} "
                f"graph_snapshot={stored.metadata.graph_snapshot_digest[:12]}"
            ),
            ip_address=request.client.host if request.client else None,
        )
        log_action(
            db,
            "attack_prediction.completed",
            user_id=current_user.id,
            resource=f"correlation:{correlation_id}",
            details=(
                f"session={stored.prediction_session_id} "
                f"evidence={service.count_evidence(stored.prediction_session_id)} "
                f"debate={stored.metadata.debate_id or 'none'} "
                f"techniques_observed={stored.metadata.observed_technique_count}"
            ),
            ip_address=request.client.host if request.client else None,
        )
    else:
        # Deliberately not a second completion record: identical inputs over an
        # immutable digest recompute to the identical answer without performing
        # any new reasoning, so counting it would overstate the analysis.
        logger.info(
            "prediction replay (no new reasoning): correlation=%s session=%s",
            correlation_id,
            stored.prediction_session_id,
        )

    return stored


# ---------------------------------------------------------------------------
# GET /api/attack-predictions/{prediction_id}
# ---------------------------------------------------------------------------


@router.get(
    "/{prediction_id}",
    response_model=PredictionResult,
    summary="Read one stored attack prediction",
    description=(
        "Return a stored prediction together with the session context that "
        "qualifies it: supporting and contradicting evidence, evidence gaps, "
        "unresolved questions and limitations.  A prediction is never returned "
        "without its evidence."
    ),
    responses={
        401: {"description": "Missing or invalid credentials."},
        403: {"description": "Authenticated but not permitted to read."},
        404: {"description": "No stored prediction with this identifier."},
        422: {"description": "Malformed prediction identifier."},
    },
)
def get_prediction(
    prediction_id: uuid.UUID = Path(
        ...,
        description="Prediction identifier (attack_predictions.id).",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_read),  # noqa: ARG001
) -> PredictionResult:
    """Return the stored session document that owns ``prediction_id``.

    The whole session is returned rather than a bare prediction row because a
    prediction is not meaningful in isolation: its confidence, gaps and
    limitations are session-scoped context, and returning the row alone would
    invite a client to read it as a finding.
    """
    result = AttackPredictionService(db).get_prediction(prediction_id)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_failure_body(
                correlation_id=None,
                prediction_session_id=None,
                code="prediction_not_found",
                detail=f"no stored prediction with id {prediction_id}",
            ),
        )
    return result


__all__ = [
    "ATTACK_PREDICTION_READ_ROLES",
    "get_prediction",
    "router",
    "run_prediction",
]