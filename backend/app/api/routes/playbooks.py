"""AI Playbook Generation API (V3.25) — authenticated proposal surface.

Routes (mounted under ``/api``):

* ``POST /api/playbooks/{correlation_id}`` — generate (or return) the
  deterministic proposal for one correlation.
* ``GET  /api/playbooks/correlation/{correlation_id}`` — list the proposals
  recorded for a correlation.
* ``GET  /api/playbooks/{playbook_id}`` — read one stored proposal.
* ``POST /api/playbooks/{playbook_id}/validate`` — re-check a stored proposal
  against the current contracts and capability table.

Four deliberate constraints:

**The client cannot define a playbook.**  The POST body is empty: it takes a
correlation id and nothing else.  A client cannot submit an action, a target, a
priority, a confidence or an approval state.  Every such value is derived
server-side from persisted evidence, the V3.22 graph, the V3.23 debate and the
V3.24 prediction.  A request body carrying an action would be a client asking
the generator to comply with an action *it* chose, which inverts the entire
purpose of an evidence-grounded proposal.

**Generating is not approving, and proposing is not executing.**  The only
lifecycles this surface can return or persist are ``proposed`` and
``approval_required``.  There is no route here that approves a playbook, and no
route here that executes one.  Approval lives in the existing HITL approval
service and execution in the existing response layer; both consume a playbook,
neither is reachable from this API.

**A failure never becomes a playbook.**  Context, bounds, safety and persistence
failures surface as governed status codes carrying a
:class:`PlaybookFailureResponse`.  The engine never degrades to a thin
plausible-looking plan to keep a client happy — it either proposes something it
can justify, or reports ``INSUFFICIENT_EVIDENCE``.

**Replay is not re-reasoning.**  Re-POSTing over unchanged inputs performs no
new analysis, so it is not logged as a new creation.  Audit records should
reflect how much reasoning happened, not how many times a client retried.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable

from fastapi import APIRouter, Depends, HTTPException, Path, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.agents.playbook.engine import PlaybookEngine
from app.api.dependencies import get_current_user, get_db
from app.models.user import User
from app.schemas.playbook import (
    PlaybookFailureResponse,
    PlaybookListResult,
    PlaybookResult,
)
from app.services.audit_service import log_action
from app.services.playbook.context import PlaybookContextAssembler
from app.services.playbook.exceptions import (
    PlaybookError,
    PlaybookNotFoundError,
    PlaybookPersistenceError,
    failure_code,
)
from app.services.playbook.persistence import PlaybookService
from app.services.playbook.vocabulary import DEFAULT_PLAYBOOK_BOUNDS, PlaybookBounds

logger = logging.getLogger(__name__)

# No prefix here: app/api/router.py supplies "/playbooks" and app.main mounts
# that under "/api", giving /api/playbooks/...
router = APIRouter(tags=["playbooks"])

#: Generation is strictly a proposal-writing operation, so the read roles are
#: reused rather than a new role being invented: an analyst who may read a
#: prediction may request the plan derived from it.  Execution roles are
#: deliberately not required here, because nothing on this surface executes.
PLAYBOOK_READ_ROLES = ("admin", "analyst", "ciso")

#: Failure-to-status mapping.  Every entry is governed: the client learns
#: exactly which failure occurred, and no playbook is invented to cover it.
_PLAYBOOK_STATUS: dict[str, int] = {
    "playbook_bounds_error": status.HTTP_422_UNPROCESSABLE_CONTENT,
    "playbook_context_error": status.HTTP_404_NOT_FOUND,
    "playbook_evidence_error": status.HTTP_422_UNPROCESSABLE_CONTENT,
    "playbook_safety_error": status.HTTP_422_UNPROCESSABLE_CONTENT,
    "playbook_dependency_error": status.HTTP_422_UNPROCESSABLE_CONTENT,
    "playbook_validation_error": status.HTTP_500_INTERNAL_SERVER_ERROR,
    "playbook_configuration_error": status.HTTP_503_SERVICE_UNAVAILABLE,
    "playbook_persistence_error": status.HTTP_503_SERVICE_UNAVAILABLE,
    "playbook_not_found": status.HTTP_404_NOT_FOUND,
    "playbook_model_output_error": status.HTTP_422_UNPROCESSABLE_CONTENT,
    "playbook_model_candidate_error": status.HTTP_422_UNPROCESSABLE_CONTENT,
    "playbook_generation_provider_error": status.HTTP_503_SERVICE_UNAVAILABLE,
    "playbook_error": status.HTTP_500_INTERNAL_SERVER_ERROR,
}


#: Bearer scheme that returns ``None`` instead of rejecting a missing header, so
#: the auditing role dependency below is reached and can record the attempt.  The
#: shared auto-raising scheme would reject the request first and the denial would
#: leave no trace.
_auditable_scheme = HTTPBearer(auto_error=False)


def _require_roles(*allowed_roles: str) -> Callable:
    """Role dependency that audits every denied attempt.

    Wrapping the credential check itself (rather than trusting FastAPI to reject
    the request first) is what makes the audit entry trustworthy: an anonymous
    caller, an expired token and a valid-but-insufficient role all produce one
    ``playbook.unauthorized_attempt`` row, with the user id recorded only when a
    user was actually resolved.

    ``_auditable_scheme`` exists for that reason.  The shared ``bearer_scheme``
    is ``HTTPBearer(auto_error=True)``, so a request with no ``Authorization``
    header is rejected while FastAPI is still *resolving dependencies* -- before
    this function's body ever runs, and therefore before anything can be
    audited.  A non-raising scheme hands ``None`` through instead, so the
    anonymous case reaches the same ``except`` branch as the other two.  The
    shared scheme is left alone rather than relaxed globally for every route.
    """

    def dependency(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = Depends(_auditable_scheme),
        db: Session = Depends(get_db),
    ) -> User:
        denied_by = None
        user_id = None
        try:
            if credentials is None or not isinstance(credentials.credentials, str):
                denied_by = "missing credentials"
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                )
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
                "playbook.unauthorized_attempt",
                user_id=user_id,
                resource="playbooks",
                details=denied_by or "invalid or missing credentials",
                ip_address=request.client.host if request.client else None,
            )
            raise

    dependency.__name__ = f"require_roles({','.join(allowed_roles)})"
    return dependency


_require_read = _require_roles(*PLAYBOOK_READ_ROLES)


def _engine() -> PlaybookEngine:
    """Build the deterministic engine.

    V3.25's default path performs no model call, so there is no provider to
    select and no cloud dependency: identical inputs always yield an identical
    proposal.  The optional model-candidate path is off unless explicitly
    configured, because it is advisory — a candidate it returns must survive the
    same validation as a deterministic one, and a provider outage must never be
    able to fail a generation that the engine could have completed on its own.
    """
    return PlaybookEngine(
        bounds=_bounds(),
        allow_model_candidates=False,
    )


def _bounds() -> PlaybookBounds:
    return DEFAULT_PLAYBOOK_BOUNDS


def _failure_body(
    *,
    correlation_id: uuid.UUID | None,
    playbook_id: uuid.UUID | None,
    code: str,
    detail: str,
) -> dict:
    """Shape a governed failure body.

    Validated through :class:`PlaybookFailureResponse` so a failure is checked
    by the same contract family as a success: a client can never receive a
    playbook-shaped response for a run that failed.
    """
    return PlaybookFailureResponse(
        correlation_id=correlation_id,
        playbook_id=playbook_id,
        status="failed",
        failure_code=code,
        detail=detail,
    ).model_dump(mode="json")


#: Failure codes whose message text originates outside this process.
#:
#: Every other playbook failure message is authored inside
#: ``app/services/playbook`` and describes persisted data, so returning it
#: verbatim is both safe and the most useful thing a client can be told.  A
#: provider failure is different in kind: its text comes from a third-party
#: client's own error reporting, where credentials, ``Authorization`` headers
#: and connection strings routinely appear.  Those messages are therefore never
#: echoed -- neither to the client nor to the log -- and only the governed code
#: and a fixed explanation are released.
_REDACTED_DETAIL: dict[str, str] = {
    "playbook_generation_provider_error": (
        "the generation provider is unavailable or rejected the request; the "
        "provider's own error text is withheld because it is not authored by "
        "this service"
    ),
}


def _raise_playbook_failure(
    exc: PlaybookError,
    correlation_id: uuid.UUID | None,
    playbook_id: uuid.UUID | None = None,
) -> None:
    """Translate one engine failure into its governed HTTP response.

    ``str(exc)`` is returned verbatim for every failure whose message is authored
    in this package, because such messages describe missing or malformed
    *persisted* data and carry no secret, credential or provider payload.

    Provider failures are the exception and are handled defensively rather than
    on trust.  Their text originates in a third-party client, so it is replaced
    with a fixed explanation: redacting here rather than relying on every future
    caller to sanitize first means a provider that changes its error format
    cannot start leaking credentials through this surface.
    """
    code = failure_code(exc)
    safe_detail = _REDACTED_DETAIL.get(code)
    if safe_detail is not None:
        detail = safe_detail
    else:
        detail = str(exc)
    logger.warning(
        "Playbook failure: correlation=%s playbook=%s code=%s",
        correlation_id,
        playbook_id,
        code,
    )
    raise HTTPException(
        status_code=_PLAYBOOK_STATUS.get(code, status.HTTP_500_INTERNAL_SERVER_ERROR),
        detail=_failure_body(
            correlation_id=correlation_id,
            playbook_id=playbook_id,
            code=code,
            detail=detail,
        ),
    ) from exc


# ---------------------------------------------------------------------------
# POST /api/playbooks/{correlation_id}
# ---------------------------------------------------------------------------


@router.post(
    "/{correlation_id}",
    response_model=PlaybookResult,
    status_code=status.HTTP_200_OK,
    summary="Generate or return the proposed playbook for one correlation",
    description=(
        "Produce an evidence-grounded *proposal* of response actions for one "
        "correlation.  Every proposed action must cite at least one resolvable "
        "persisted reference; a disruptive action additionally requires "
        "established evidence rather than a prediction alone.  Actions SentinelAI "
        "cannot perform today are reported as NOT_EXECUTABLE rather than omitted. "
        "The result is always proposed or approval_required: this endpoint never "
        "approves and never executes."
    ),
    responses={
        401: {"description": "Missing or invalid credentials."},
        403: {"description": "Authenticated but not permitted to generate."},
        404: {"description": "No persisted graph exists for this correlation."},
        422: {"description": "Malformed correlation id, or a bound was exceeded."},
        500: {"description": "The generated proposal failed validation."},
        503: {"description": "Inputs or persistence were unavailable."},
    },
)
def generate_playbook(
    request: Request,
    correlation_id: uuid.UUID = Path(
        ...,
        description="Correlation UUID (correlation_results.correlation_id).",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_read),
) -> PlaybookResult:
    """Propose a response playbook for a correlation.

    Returns 200 both when this call performed the generation and when it
    returned an identical existing proposal.  A client cannot tell the
    difference and does not need to: the stored conclusion is identical either
    way, because the session identity is derived from immutable inputs.
    """
    bounds = _bounds()
    try:
        inputs = PlaybookContextAssembler(db, bounds=bounds).assemble(correlation_id)
    except PlaybookError as exc:
        log_action(
            db,
            "playbook.failed",
            user_id=current_user.id,
            resource=f"correlation:{correlation_id}",
            details=f"code={failure_code(exc)} reason=context_unavailable",
            ip_address=request.client.host if request.client else None,
        )
        _raise_playbook_failure(exc, correlation_id)
        raise  # unreachable; _raise_playbook_failure always raises

    try:
        result = _engine().generate(inputs)
    except PlaybookError as exc:
        log_action(
            db,
            "playbook.failed",
            user_id=current_user.id,
            resource=f"correlation:{correlation_id}",
            details=f"code={failure_code(exc)}",
            ip_address=request.client.host if request.client else None,
        )
        _raise_playbook_failure(exc, correlation_id)
        raise  # unreachable; keeps type checkers from using a possibly-unbound name

    # Persistence runs before any success audit is written.  The audit trail has
    # to describe what the database actually holds: logging "created" first would
    # leave a permanent record of a proposal a failed write never produced, and
    # would log a "created" event on an idempotent replay that created nothing.
    service = PlaybookService(db)
    try:
        stored, created = service.persist_result(result)
    except PlaybookPersistenceError as exc:
        log_action(
            db,
            "playbook.failed",
            user_id=current_user.id,
            resource=f"correlation:{correlation_id}",
            details=f"code={failure_code(exc)}",
            ip_address=request.client.host if request.client else None,
        )
        _raise_playbook_failure(exc, correlation_id)
        raise  # unreachable

    if created:
        log_action(
            db,
            "playbook.created",
            user_id=current_user.id,
            resource=f"correlation:{correlation_id}",
            details=(
                f"playbook={stored.playbook_id} "
                f"actions={len(stored.playbook.actions)} "
                f"status={stored.status.value} "
                f"lifecycle={stored.lifecycle.value} "
                f"graph_snapshot={stored.metadata.graph_snapshot_digest[:12]}"
            ),
            ip_address=request.client.host if request.client else None,
        )
        log_action(
            db,
            "playbook.completed",
            user_id=current_user.id,
            resource=f"correlation:{correlation_id}",
            details=(
                f"playbook={stored.playbook_id} "
                f"steps={len(stored.playbook.steps)} "
                f"evidence={service.count_evidence(stored.playbook_id)} "
                f"approval_required={service.count_actions(stored.playbook_id)} "
                f"limitations={len(stored.limitations)} "
                "executed=none"
            ),
            ip_address=request.client.host if request.client else None,
        )
    else:
        # Deliberately not a second completion record: identical inputs over an
        # immutable digest recompute to the identical answer without performing
        # any new reasoning, so counting it would overstate the analysis.  There
        # is also deliberately no "executed" event anywhere on this surface.
        logger.info(
            "playbook replay (no new reasoning): correlation=%s playbook=%s",
            correlation_id,
            stored.playbook_id,
        )

    return stored


# ---------------------------------------------------------------------------
# GET /api/playbooks/correlation/{correlation_id}
# ---------------------------------------------------------------------------
#
# Declared BEFORE "/{playbook_id}" so the literal path segment wins.  FastAPI
# matches in declaration order, and "{playbook_id}" is typed as a UUID, so a
# later declaration would make "/correlation/<uuid>" unmatchable rather than
# merely shadowed — an ordering bug that would surface as a confusing 422 on a
# perfectly valid request.


@router.get(
    "/correlation/{correlation_id}",
    response_model=PlaybookListResult,
    summary="List the proposals recorded for one correlation",
    description=(
        "Return every stored proposal for a correlation, newest first, with the "
        "counts a reader needs to judge scope: how many actions were proposed, "
        "how many need approval, and how many SentinelAI cannot execute today."
    ),
    responses={
        401: {"description": "Missing or invalid credentials."},
        403: {"description": "Authenticated but not permitted to read."},
        422: {"description": "Malformed correlation identifier."},
    },
)
def list_playbooks_for_correlation(
    correlation_id: uuid.UUID = Path(
        ...,
        description="Correlation UUID (correlation_results.correlation_id).",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_read),  # noqa: ARG001
) -> PlaybookListResult:
    """List stored proposals for ``correlation_id``.

    An unknown correlation yields an empty list rather than 404: "no proposal has
    been generated yet" is a legitimate state, not a missing resource.
    """
    return PlaybookService(db).get_by_correlation(correlation_id)


# ---------------------------------------------------------------------------
# POST /api/playbooks/{playbook_id}/validate
# ---------------------------------------------------------------------------


@router.post(
    "/{playbook_id}/validate",
    summary="Re-validate a stored proposal against the current contracts",
    description=(
        "Re-check a stored proposal: its lifecycle, its evidence grounding, its "
        "dependency graph, its rollback truthfulness and its capability claims "
        "against the current frozen action table.  Read-only: validation never "
        "writes, never approves and never executes.  Use it to confirm that a "
        "stored proposal is still consistent after a vocabulary change."
    ),
    responses={
        401: {"description": "Missing or invalid credentials."},
        403: {"description": "Authenticated but not permitted to read."},
        404: {"description": "No stored proposal with this identifier."},
        422: {"description": "The stored proposal no longer satisfies a contract."},
        503: {"description": "Inputs or persistence were unavailable."},
    },
)
def validate_playbook(
    request: Request,
    playbook_id: uuid.UUID = Path(
        ...,
        description="Proposal identifier (playbook_sessions.id).",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_read),
) -> dict:
    """Validate one stored proposal without mutating it.

    Returns 200 with ``valid: true`` when the stored document still satisfies
    every contract.  A document that no longer validates — because the vocabulary
    moved under it, say — returns 422 with the governed failure code, and the
    stored proposal is left exactly as it was.
    """
    service = PlaybookService(db)
    stored = service.get_session(playbook_id)
    if stored is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_failure_body(
                correlation_id=None,
                playbook_id=playbook_id,
                code=PlaybookNotFoundError.failure_code,
                detail=f"no stored playbook with id {playbook_id}",
            ),
        )

    try:
        # Re-validating through the model is the check: the same validators that
        # reject lifecycle escalation, arbitrary capability claims, prediction-
        # only destructive grounding and cyclic dependencies would all fire here.
        PlaybookResult.model_validate(stored.model_dump(mode="json"))
    except PlaybookError as exc:  # pragma: no cover - defensive
        log_action(
            db,
            "playbook.rejected",
            user_id=current_user.id,
            resource=f"playbook:{playbook_id}",
            details=f"code={failure_code(exc)}",
            ip_address=request.client.host if request.client else None,
        )
        _raise_playbook_failure(exc, stored.correlation_id, playbook_id)
        raise
    except Exception as exc:
        log_action(
            db,
            "playbook.rejected",
            user_id=current_user.id,
            resource=f"playbook:{playbook_id}",
            details="code=playbook_validation_error",
            ip_address=request.client.host if request.client else None,
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=_failure_body(
                correlation_id=stored.correlation_id,
                playbook_id=playbook_id,
                code="playbook_validation_error",
                detail="the stored proposal no longer satisfies the current contracts",
            ),
        ) from exc

    return {
        "playbook_id": playbook_id,
        "correlation_id": stored.correlation_id,
        "valid": True,
        "status": stored.status.value,
        "lifecycle": stored.lifecycle.value,
        "action_count": len(stored.playbook.actions),
        "executed": False,
        "note": (
            "Validation is read-only. This proposal remains unapproved and "
            "unexecuted."
        ),
    }


# ---------------------------------------------------------------------------
# GET /api/playbooks/{playbook_id}
# ---------------------------------------------------------------------------


@router.get(
    "/{playbook_id}",
    response_model=PlaybookResult,
    summary="Read one stored playbook proposal",
    description=(
        "Return a stored proposal together with everything that qualifies it: "
        "per-action evidence, capabilities, approval requirements, rollback "
        "metadata, the confidence breakdown, and the recorded gaps, dissent and "
        "limitations.  A proposal is never returned without its uncertainty."
    ),
    responses={
        401: {"description": "Missing or invalid credentials."},
        403: {"description": "Authenticated but not permitted to read."},
        404: {"description": "No stored proposal with this identifier."},
        422: {"description": "Malformed proposal identifier."},
    },
)
def get_playbook(
    playbook_id: uuid.UUID = Path(
        ...,
        description="Proposal identifier (playbook_sessions.id).",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_read),  # noqa: ARG001
) -> PlaybookResult:
    """Return the stored proposal with the given identifier."""
    stored = PlaybookService(db).get_session(playbook_id)
    if stored is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_failure_body(
                correlation_id=None,
                playbook_id=playbook_id,
                code=PlaybookNotFoundError.failure_code,
                detail=f"no stored playbook with id {playbook_id}",
            ),
        )
    return stored


__all__ = ["PLAYBOOK_READ_ROLES", "router"]