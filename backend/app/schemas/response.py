"""Response & Mitigation Domain Contract — Step 25.

Defines the foundational **domain contract** for the Version 1 Response
& Mitigation layer: the structured request to execute a *previously
permitted* response action, the execution-status vocabulary, and the
auditable result record the Response layer produces.

The pipeline already knows:

* Detection — *what matched?*
* Correlation — *what is related?*
* Risk Assessment — *how dangerous?*
* Investigation / Attribution — *what happened and who may be
  responsible?*
* Policy Decision — *may this proposed response action proceed?*
* **Response & Mitigation (this module)** — *how is that permitted
  action safely executed, and what happened?*

Design principles:

* **Execution is a consequence of policy, never a substitute for it.**
  This contract carries the ``policy_decision_id`` reference that
  authorized the action; the Response layer's executor independently
  re-checks that the decision is ``ALLOWED`` and matches the request
  (action / correlation / ids) before any provider is invoked.  A
  ``DENIED`` or ``REQUIRES_APPROVAL`` decision (or a malformed one)
  must never reach a provider.
* **Closed action vocabulary.** :class:`ResponseActionType` is imported
  *from the Step 24 Policy Decision contract* — a single shared type, so
  the response layer and the policy layer can never drift apart.  There
  is no "custom" action, no free-form command, no function name, no SQL
  and no shell string anywhere in this contract.
* **Structured requests only.** :class:`ResponseRequest` names a
  validated target identifier and carries bounded, secret-free
  bookkeeping.  It never accepts natural language, code, URLs-as-action-
  payloads, or arbitrary payloads.
* **Structured results.** :class:`ResponseResult` records the outcome
  (``executed`` / ``failed`` / ``skipped`` / ``rejected``), which
  provider ran, timing, a sanitized message, and an ``error_code``.
* **Provenance-aware.** A response result carries the additive
  ``Provenance.RESPONSE_EXECUTED`` value.  It is never labelled
  observed / detected / correlated / risk_assessed / ai_generated /
  policy_decided or any other prior value.
* **Secret-safe & deterministic.** Targets and metadata are strict
  JSON-compatible, secret-scanning, deep-copying payloads (mirroring the
  Step 10A / 11A / 24 contract boundary).  ``response_id`` and the
  idempotency key are derived deterministically from request + decision
  content, never from randomness.
* **Contract only.** This module validates and describes; it contains no
  provider, no execution logic, no I/O, no filesystem/network/OS access,
  no LLM, and no external-system contact.

Relationship to the pipeline::

    PolicyDecision (Step 24)                (ALLOWED only)
        -> ResponseRequest                  (Step 25 — this module)
            -> ResponseLayer executor       (Step 25 service layer)
                -> ResponseProvider         (Step 25 service layer)
                    -> ResponseResult       (Step 25 — this module)
                        -> [Audit]          (future — records the attempt)

``Response != Policy``: this contract never answers *may it proceed*; it
only describes an attempt to execute an already-permitted action.  And
``Response != System Mutation``: nothing here touches a host, firewall,
account, file, or endpoint — those integrations are future SOAR scope.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.policy_decision import (
    PolicyDecision,
    ResponseActionType,
)
from app.schemas.security_event import Provenance


# ---------------------------------------------------------------------------
# Bounds & constants (single source of truth, documented)
# ---------------------------------------------------------------------------

#: Maximum length of a raw target identifier as accepted by the contract.
#: The per-action *structural* validation lives in the service layer (the
#: contract does not know which action a target belongs to).
RESPONSE_MAX_TARGET_LENGTH = 512

#: Maximum length of a provider name.
RESPONSE_MAX_PROVIDER_LENGTH = 64

#: Maximum length of a sanitized error code.
RESPONSE_MAX_ERROR_CODE_LENGTH = 64

#: Maximum length of a sanitized result message.
RESPONSE_MAX_MESSAGE_LENGTH = 500

#: Maximum serialized metadata depth (mirror Step 11A / 24 conventions).
RESPONSE_MAX_METADATA_DEPTH = 4

#: Deterministic identity namespace for the Response layer.
RESPONSE_ID_NAMESPACE = uuid.UUID("7a2c4e6f-9b1d-4a52-8c9e-0f1a2b3c4d5e")

#: Deterministic idempotency namespace (not used for random ids).
RESPONSE_IDEMPOTENCY_NAMESPACE = uuid.UUID("1c3d5f7a-9b2c-4e6f-8a1b-2c3d4e5f6a7b")

#: Credential-shaped strings re-checked at this boundary (mirror Step 11A/24).
_SECRET_PATTERNS = ("api_key", "authorization", "bearer", "secret")

#: The maximum number of entries the in-memory processed-idempotency map
#: may hold before the executor fails closed with a provisioning error.
RESPONSE_MAX_PROCESSED_KEYS = 10_000


# ---------------------------------------------------------------------------
# Secret-safety helpers (mirror the Step 9A / 10A / 11A / 24 patterns)
# ---------------------------------------------------------------------------


def _assert_json_compatible(value: Any, field: str) -> None:
    """Raise ValueError when *value* is not strictly JSON-serializable."""
    try:
        json.dumps(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be JSON-compatible: {exc}") from exc


def _assert_no_secrets(value: Any, field: str) -> None:
    """Raise ValueError when *value* contains common secret patterns."""
    serialized = json.dumps(value).lower()
    for pattern in _SECRET_PATTERNS:
        if pattern in serialized:
            raise ValueError(
                f"{field} must not contain secrets ('{pattern}' detected)"
            )


def _json_clone(value: dict[str, Any]) -> dict[str, Any]:
    """Return an independent, JSON-compatible deep copy of *value*."""
    return json.loads(json.dumps(value))


def _require_non_blank(value: str, field: str) -> str:
    """Reject blank strings in structured labels."""
    stripped = value.strip()
    if not stripped:
        raise ValueError(f"{field} must not be blank")
    return stripped


def _ensure_tz_aware(value: datetime, field: str) -> datetime:
    """Reject naive (timezone-unaware) timestamps."""
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(
            f"{field} must be timezone-aware; naive timestamps are not accepted"
        )
    return value


def _ensure_metadata_bounded(value: dict[str, Any], field: str) -> dict[str, Any]:
    """Reject unboundedly deep metadata (anti-DoS / determinism guard)."""
    def depth(item: Any, current: int) -> int:
        if current > RESPONSE_MAX_METADATA_DEPTH:
            return current
        if isinstance(item, dict):
            return max((depth(v, current + 1) for v in item.values()), default=current)
        if isinstance(item, list):
            return max((depth(v, current + 1) for v in item), default=current)
        return current

    if depth(value, 0) > RESPONSE_MAX_METADATA_DEPTH:
        raise ValueError(
            f"{field} must not exceed {RESPONSE_MAX_METADATA_DEPTH} levels of nesting"
        )
    return _json_clone(value)


def _reject_control_characters(value: str, field: str) -> str:
    """Reject control characters in structured strings (never embedded)."""
    if any(
        ch != "\t"
        and ((o := ord(ch)) < 32 or o == 127 or 128 <= o <= 159)
        for ch in value
    ):
        raise ValueError(f"{field} must not contain control characters")
    return value


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ResponseExecutionStatus(str, Enum):
    """The four possible outcomes of a response execution attempt.

    * ``executed`` — the request passed the policy gate and the provider
      completed its simulated/adapted execution successfully.
    * ``failed``   — the request was permitted but the provider raised an
      error / could not execute (failures are never silently converted
      into successes).
    * ``skipped``  — the request was recognised as an already-processed
      duplicate (idempotency suppression) or deliberately not executed.
    * ``rejected`` — the request was refused before any provider was
      called: policy gate not ALLOWED, request/decision mismatch, or
      malformed input/action/target.
    """

    EXECUTED = "executed"
    FAILED = "failed"
    SKIPPED = "skipped"
    REJECTED = "rejected"


# ---------------------------------------------------------------------------
# Response request
# ---------------------------------------------------------------------------


class ResponseRequest(BaseModel):
    """Structured request to execute an *already-permitted* action once.

    ``action_type`` and ``policy_decision_id`` must agree exactly with the
    authorizing :class:`PolicyDecision` (action, correlation, and ids are
    verified by the executor's policy gate).  ``target`` is a *controlled
    identifier* validated per action by the service layer; the contract
    here bounds it, rejects control characters, and scans for secrets — it
    does not interpret the identifier (no filesystem, DNS, or network).
    """

    model_config = ConfigDict(extra="forbid")

    response_id: uuid.UUID = Field(
        ...,
        description=(
            "Deterministic and unique to this execution attempt.  Derived "
            "from request + decision content (idempotency-aware), never "
            "random."
        ),
    )
    policy_decision_id: uuid.UUID = Field(
        ...,
        description=(
            "Reference to the Step 24 PolicyDecision that authorized this "
            "action.  The executor re-verifies it exists and is ALLOWED."
        ),
    )
    correlation_id: uuid.UUID = Field(
        ...,
        description=(
            "The correlation this response concerns (must match the policy "
            "decision's correlation)."
        ),
    )
    action_type: ResponseActionType = Field(
        ...,
        description=(
            "The proposed response action, using the SAME closed "
            "vocabulary as Step 24 (imported, never redefined)."
        ),
    )
    target: str = Field(
        ...,
        min_length=1,
        max_length=RESPONSE_MAX_TARGET_LENGTH,
        description=(
            "Controlled target identifier (IP, domain, file id, account, "
            "session, endpoint).  Validated structurally per action by the "
            "service layer — the contract never interprets it."
        ),
    )
    approval_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "Optional reference to a V2.16 human-in-the-loop approval "
            "grant (ApprovalRecord.approval_id) that authorizes a "
            "REQUIRES_APPROVAL decision.  CARRIES NO PERMISSION ITSELF: the "
            "executor only honours it through an explicit ApprovalVerifier "
            "wired into the Response service.  Absent by default so existing "
            "ALLOWED-only call sites are unchanged."
        ),
    )
    requested_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description=(
            "Timezone-aware instant the attempt was requested.  "
            "Bookkeeping, not execution timing."
        ),
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Structured, JSON-compatible, secret-free bookkeeping about "
            "this attempt.  Never executed or interpreted."
        ),
    )

    @field_validator("target")
    @classmethod
    def _ensure_target_safe(cls, v: str) -> str:
        _reject_control_characters(v, "target")
        _assert_json_compatible(v, "target")
        _assert_no_secrets(v, "target")
        return _require_non_blank(v, "target")

    @field_validator("requested_at")
    @classmethod
    def _ensure_timezone_aware(cls, v: datetime) -> datetime:
        return _ensure_tz_aware(v, "requested_at")

    @field_validator("metadata")
    @classmethod
    def _ensure_metadata_valid(cls, v: dict[str, Any]) -> dict[str, Any]:
        _assert_json_compatible(v, "metadata")
        _assert_no_secrets(v, "metadata")
        return _ensure_metadata_bounded(v, "metadata")


# ---------------------------------------------------------------------------
# Response result
# ---------------------------------------------------------------------------


class ResponseResult(BaseModel):
    """Auditable outcome of one response execution attempt.

    Every inclusion or rejection produces this record (with
    ``provenance=RESPONSE_EXECUTED``), so the audit trail is uniform:
    what decision authorized the attempt, what action and target were
    used, which provider ran, when it started and finished, whether it
    succeeded, and (where applicable) a sanitized error code.  No
    secrets, tokens, or raw payloads are ever recorded here.
    """

    model_config = ConfigDict(extra="forbid")

    response_id: uuid.UUID = Field(
        ...,
        description=(
            "Deterministic identity of this attempt — matches the "
            "request's response_id it answers."
        ),
    )
    policy_decision_id: uuid.UUID = Field(
        ...,
        description="The authorizing policy decision that was re-verified.",
    )
    correlation_id: uuid.UUID = Field(
        ...,
        description="The correlation the attempt concerned.",
    )
    action_type: ResponseActionType = Field(
        ...,
        description="The action that was attempted (closed vocabulary).",
    )
    execution_status: ResponseExecutionStatus = Field(
        ...,
        description="executed / failed / skipped / rejected.",
    )
    target: str = Field(
        ...,
        max_length=RESPONSE_MAX_TARGET_LENGTH,
        description=(
            "Canonicalised target identifier recorded for audit (never a "
            "raw payload, never a secret)."
        ),
    )
    provider: str | None = Field(
        default=None,
        max_length=RESPONSE_MAX_PROVIDER_LENGTH,
        description=(
            "The provider that ran the attempt, or None when the attempt "
            "never reached a provider (rejected/skipped).  A stable name, "
            "never a callable."
        ),
    )
    started_at: datetime | None = Field(
        default=None,
        description=(
            "Timezone-aware instant execution began (None when no provider "
            "was invoked)."
        ),
    )
    completed_at: datetime | None = Field(
        default=None,
        description=(
            "Timezone-aware instant the attempt finished (expected to equal "
            "started_at for deterministic mock providers)."
        ),
    )
    message: str = Field(
        default="",
        max_length=RESPONSE_MAX_MESSAGE_LENGTH,
        description=(
            "Sanitized, template-built message describing the outcome.  "
            "Never echoes raw target/payload content; never LLM text."
        ),
    )
    error_code: str | None = Field(
        default=None,
        max_length=RESPONSE_MAX_ERROR_CODE_LENGTH,
        description=(
            "Stable sanitized error/rejection code when applicable (e.g. "
            "'POLICY_DENIED', 'DUPLICATE_REQUEST')."
        ),
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Deterministic structured bookkeeping about the attempt "
            "(provider metadata, sanitized)."
        ),
    )
    timestamp: datetime = Field(
        ...,  # set by the service (result production timestamp)
        description=(
            "Timezone-aware instant this result record was produced."
        ),
    )
    provenance: Provenance = Field(
        default=Provenance.RESPONSE_EXECUTED,
        description=(
            "Always RESPONSE_EXECUTED — a response result is never "
            "observed telemetry, never a detection/correlation/risk/"
            "investigation/attribution/recall/learning, and never a policy "
            "decision."
        ),
    )

    @field_validator("target")
    @classmethod
    def _ensure_target_safe(cls, v: str) -> str:
        stripped = v.strip()
        _reject_control_characters(stripped, "target")
        _assert_json_compatible(stripped, "target")
        _assert_no_secrets(stripped, "target")
        return _require_non_blank(stripped, "target")

    @field_validator("provider")
    @classmethod
    def _ensure_provider_not_blank(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return _require_non_blank(v, "provider")

    @field_validator("message")
    @classmethod
    def _ensure_message_safe(cls, v: str) -> str:
        _assert_json_compatible(v, "message")
        _assert_no_secrets(v, "message")
        _reject_control_characters(v, "message")
        return v

    @field_validator("error_code")
    @classmethod
    def _ensure_error_code_not_blank(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return _require_non_blank(v, "error_code")

    @field_validator("started_at", "completed_at", "timestamp")
    @classmethod
    def _ensure_timezone_aware(cls, v: datetime | None) -> datetime | None:
        if v is None:
            return None
        return _ensure_tz_aware(v, "timestamp")

    @field_validator("metadata")
    @classmethod
    def _ensure_metadata_valid(cls, v: dict[str, Any]) -> dict[str, Any]:
        _assert_json_compatible(v, "metadata")
        _assert_no_secrets(v, "metadata")
        return _ensure_metadata_bounded(v, "metadata")

    @field_validator("provenance")
    @classmethod
    def _ensure_response_provenance(cls, v: Provenance) -> Provenance:
        """Pin response results to RESPONSE_EXECUTED (mirror Step 24)."""
        if v is not Provenance.RESPONSE_EXECUTED:
            raise ValueError(
                "response results must carry RESPONSE_EXECUTED provenance; "
                f"got {v.value!r}"
            )
        return v


__all__ = [
    "RESPONSE_ID_NAMESPACE",
    "RESPONSE_IDEMPOTENCY_NAMESPACE",
    "RESPONSE_MAX_ERROR_CODE_LENGTH",
    "RESPONSE_MAX_MESSAGE_LENGTH",
    "RESPONSE_MAX_METADATA_DEPTH",
    "RESPONSE_MAX_PROVIDER_LENGTH",
    "RESPONSE_MAX_TARGET_LENGTH",
    "PolicyDecision",
    "ResponseActionType",
    "ResponseExecutionStatus",
    "ResponseRequest",
    "ResponseResult",
]