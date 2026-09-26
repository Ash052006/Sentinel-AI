"""Response request validation: targets, identity, idempotency (Step 25).

Two responsibilities live here, both deterministic and side-effect-free:

1. **Per-action target validation.** Each :class:`ResponseActionType`
   accepts only its controlled identifier shape.  Validation is purely
   structural (regex / pure parsing) — there is **never** a DNS lookup,
   filesystem access, network call, or external-system contact, and a
   malformed target is rejected.  Nothing here infers, resolves, or
   in-paints a target.
2. **Identity & idempotency keys.** ``response_id`` and the idempotency
   key are derived deterministically from ``policy_decision_id +
   action_type + target`` content (never from randomness), so an
   identical submission always lands on the same identity and can be
   suppressed without duplicating execution.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import uuid
from collections.abc import Callable
from typing import Any

from app.schemas.policy_decision import PolicyDecision, ResponseActionType
from app.schemas.response import (
    RESPONSE_ID_NAMESPACE,
    RESPONSE_IDEMPOTENCY_NAMESPACE,
    ResponseRequest,
)
from app.services.response.errors import ResponseValidationError

#: Canonical, compact JSON serializer for identity derivation (same
#: separators as Step 24 decision ids).
_JSON_KWARGS: dict[str, Any] = {
    "sort_keys": True,
    "separators": (",", ":"),
    "default": str,
}

# ---------------------------------------------------------------------------
# Per-action target contracts (STRUCTURAL ONLY — no I/O of any kind)
# ---------------------------------------------------------------------------

#: Single hostname label (isolate_endpoint target).
_ENDPOINT_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

#: Fully-qualified domain name without scheme/port/path/userinfo.
_DOMAIN_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)

#: Account identifier (bare username or user@domain).
_ACCOUNT_RE = re.compile(r"^[a-z0-9._@-]{3,128}$")

#: Session identifier.
_SESSION_RE = re.compile(r"^[a-z0-9._-]{1,128}$")

#: Logical file path (POSIX-style, relative, single segment chain).
_FILE_RE = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")


def _canonical_ip(target: str) -> str:
    """Validate a bare IP (IPv4 or IPv6) via pure parsing — no DNS, no
    resolution, no network.  Returns the canonical textual form."""
    try:
        parsed = ipaddress.ip_address(target)
    except ValueError as exc:
        raise ResponseValidationError(
            "the block_ip target must be a valid IPv4 or IPv6 address"
        ) from exc
    return str(parsed)


def _canonical_domain(target: str) -> str:
    if len(target) > 253 or not _DOMAIN_RE.match(target):
        raise ResponseValidationError(
            "the block_domain target must be a valid domain name"
        )
    return target.lower()


def _canonical_quarantine_file(target: str) -> str:
    if not _FILE_RE.match(target):
        raise ResponseValidationError(
            "the quarantine_file target must be a safe logical file path"
        )
    if ".." in target or target.startswith(("/", "~", "\\")):
        raise ResponseValidationError(
            "the quarantine_file target must be a relative logical path"
        )
    if len(target) >= 2 and target[1] == ":":
        raise ResponseValidationError(
            "the quarantine_file target must not be an absolute drive path"
        )
    return target


def _canonical_account(target: str) -> str:
    if not _ACCOUNT_RE.match(target):
        raise ResponseValidationError(
            "the disable_account target must be a valid account identifier"
        )
    return target.lower()


def _canonical_session(target: str) -> str:
    if not _SESSION_RE.match(target):
        raise ResponseValidationError(
            "the terminate_session target must be a valid session identifier"
        )
    return target.lower()


def _canonical_endpoint(target: str) -> str:
    if not _ENDPOINT_RE.match(target):
        raise ResponseValidationError(
            "the isolate_endpoint target must be a valid endpoint identifier"
        )
    return target.lower()


#: Fixed, code-constant action → validator mapping.  Deterministic; never
#: user-controlled; never derived from strings.
def _validators() -> dict[ResponseActionType, Callable[[str], str]]:
    return {
        ResponseActionType.BLOCK_IP: _canonical_ip,
        ResponseActionType.BLOCK_DOMAIN: _canonical_domain,
        ResponseActionType.QUARANTINE_FILE: _canonical_quarantine_file,
        ResponseActionType.DISABLE_ACCOUNT: _canonical_account,
        ResponseActionType.TERMINATE_SESSION: _canonical_session,
        ResponseActionType.ISOLATE_ENDPOINT: _canonical_endpoint,
    }


_TARGET_VALIDATORS: dict[ResponseActionType, Callable[[str], str]] = _validators()


def validate_target(action: ResponseActionType, target: str) -> str:
    """Structurally validate *target* for *action* and return its
    canonical form.

    Raises:
        ResponseValidationError: unsupported action or malformed target
            (sanitized).
    """
    validator = _TARGET_VALIDATORS.get(action)
    if validator is None:
        raise ResponseValidationError(
            "the requested action does not support a target"
        )
    if not isinstance(target, str):
        raise ResponseValidationError("the response target must be a string")
    stripped = target.strip()
    if not stripped:
        raise ResponseValidationError("the response target must not be blank")
    return validator(stripped)


# ---------------------------------------------------------------------------
# Identity & idempotency
# ---------------------------------------------------------------------------


def idempotency_content(
    *,
    policy_decision_id: uuid.UUID,
    action: ResponseActionType,
    target: str,
) -> dict[str, str]:
    """The canonical, sorted content the idempotency key and response id
    are derived from.  Exactly the three policy/execution identity
    components the Step 25 doctrine pins."""
    return {
        "policy_decision_id": str(policy_decision_id),
        "action_type": action.value,
        "target": target,
    }


def derive_idempotency_key(
    *,
    policy_decision_id: uuid.UUID,
    action: ResponseActionType,
    target: str,
) -> str:
    """Deterministic SHA-256 idempotency key (hex).  Same inputs always
    yield the same key; different inputs yield different keys."""
    canonical = json.dumps(
        idempotency_content(
            policy_decision_id=policy_decision_id,
            action=action,
            target=target,
        ),
        **_JSON_KWARGS,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def derive_response_id(
    *,
    policy_decision_id: uuid.UUID,
    action: ResponseActionType,
    target: str,
) -> uuid.UUID:
    """Deterministic UUIDv5 response id derived from the idempotency
    content.  Never random; never depends on wall-clock or ordering."""
    key = derive_idempotency_key(
        policy_decision_id=policy_decision_id,
        action=action,
        target=target,
    )
    return uuid.uuid5(RESPONSE_ID_NAMESPACE, key)


def check_request_identity(
    request: ResponseRequest,
    *,
    policy_decision_id: uuid.UUID,
    action: ResponseActionType,
    target: str,
) -> bool:
    """True when *request* carries the canonical identity for its
    (decision, action, target) content — callers must use
    :func:`derive_response_id`."""
    expected = derive_response_id(
        policy_decision_id=policy_decision_id,
        action=action,
        target=target,
    )
    return request.response_id == expected


def coerce_decision(decision: Any) -> PolicyDecision | None:
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


__all__ = [
    "check_request_identity",
    "coerce_decision",
    "derive_idempotency_key",
    "derive_response_id",
    "idempotency_content",
    "validate_target",
]