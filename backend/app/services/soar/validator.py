"""SOAR validation helpers (V2.18).

Pure, side-effect-free structural rules shared by the playbook registry,
the engine and the service layer.

The **only** target-validation authority is the Step 25 Response
validator (``app.services.response.validator.validate_target``) — SOAR
never re-implements target rules and never interprets a target.  The
per-action availability rules enforced here:

* a step whose operation equals the authorizing decision's action inherits
  the decision's canonical target (the primary step is always this case);
* a step whose operation differs MUST carry an explicitly bound target —
  bound at registration, structurally validated per *its* operation, never
  supplied at execution time.
"""

from __future__ import annotations

import re
import uuid

from app.schemas.policy_decision import PolicyDecision, PolicyDecisionStatus
from app.schemas.soar import SoarPlaybookDefinition, SoarStep
from app.services.response.errors import ResponseValidationError
from app.services.response.validator import validate_target as _validate_target
from app.services.soar.errors import SoarValidationError

#: Safe shape for a registered playbook id (letters, digits, underscore,
#: hyphen, dot — no whitespace, no path separators, no glob chars).
_PLAYBOOK_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")

#: Safe shape for a registered provider id.
_PROVIDER_ID_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def validate_playbook_id(playbook_id: str) -> str:
    """Structurally validate a registered playbook identifier."""
    if not isinstance(playbook_id, str) or not _PLAYBOOK_ID_RE.match(playbook_id):
        raise SoarValidationError(
            "playbook_id must be a safe lower-case alphanumeric identifier"
        )
    return playbook_id.lower()


def validate_provider_id(provider_id: str) -> str:
    """Structurally validate a registered provider identifier."""
    if not isinstance(provider_id, str) or not _PROVIDER_ID_RE.match(provider_id):
        raise SoarValidationError(
            "provider_id must be a safe lower-case provider identifier"
        )
    return provider_id.lower()


def coerce_decision(decision: object) -> PolicyDecision | None:
    """Coerce the policy decision into a validated :class:`PolicyDecision`,
    or None when it is malformed (the caller must fail closed)."""
    if isinstance(decision, PolicyDecision):
        return decision
    if isinstance(decision, dict):
        try:
            return PolicyDecision.model_validate(decision)
        except Exception:  # noqa: BLE001 - sanitized; fail closed
            return None
    return None


def canonical_target(
    *,
    action: ResponseActionType,
    target: str,
) -> str:
    """Return the canonical form of *target* for *action*.

    The **only** target-validation authority is the Step 25 Response
    validator (``app.services.response.validator.validate_target``) — SOAR
    never re-implements target rules and never interprets a target.  The
    decision supplies the action; the request supplies the controlled
    target identifier, exactly as :class:`~app.schemas.response.ResponseRequest`
    does.

    Raises:
        SoarValidationError: when *target* fails structural validation for
            *action* (fail closed — no DNS, filesystem or network).
    """
    try:
        return _validate_target(action, target)
    except ResponseValidationError as exc:
        raise SoarValidationError(
            "the SOAR target failed structural validation for its action"
        ) from exc


def step_effective_target(
    *,
    step: SoarStep,
    decision_action: str,
    decision_target: str,
) -> str:
    """The canonical target a step applies.

    A step performing the authorizing action inherits the decision's
    canonical target.  Any other step must carry an explicitly bound
    target, structurally validated per its own operation — the caller can
    never supply one at execution time.
    """
    if str(step.operation.value) == str(decision_action):
        return decision_target
    if not step.target:
        raise SoarValidationError(
            f"step #{step.step_number} ({step.operation.value}) requires an "
            "explicitly bound target because it does not perform the "
            "authorizing action"
        )
    try:
        return _validate_target(step.operation, step.target)
    except ResponseValidationError as exc:
        raise SoarValidationError(
            f"step #{step.step_number} target failed structural validation "
            f"for {step.operation.value}"
        ) from exc


def validate_playbook_definition(definition: SoarPlaybookDefinition) -> SoarPlaybookDefinition:
    """Validate a playbook definition's closed structural invariants
    (schema version, sequential steps, primary-anchor, bounded size,
    safe ids per step)."""
    playbook_id = validate_playbook_id(definition.playbook_id)
    for step in definition.steps:
        validate_provider_id(step.provider_id)
    return definition.model_copy(update={"playbook_id": playbook_id})


def execution_status_allowed(req_decision_status: PolicyDecisionStatus) -> bool:
    """True when the decision status can ever reach a provider (ALLOWED or
    REQUIRES_APPROVAL-with-grant).  DENIED/unknown fail closed."""
    return req_decision_status in (
        PolicyDecisionStatus.ALLOWED,
        PolicyDecisionStatus.REQUIRES_APPROVAL,
    )


def is_uuid(value: object) -> bool:
    try:
        return isinstance(uuid.UUID(str(value)), uuid.UUID)
    except (TypeError, ValueError, AttributeError):
        return False


__all__ = [
    "canonical_target",
    "coerce_decision",
    "execution_status_allowed",
    "is_uuid",
    "step_effective_target",
    "validate_playbook_definition",
    "validate_playbook_id",
    "validate_provider_id",
]