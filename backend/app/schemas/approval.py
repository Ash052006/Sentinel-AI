"""Approval Workflow Domain Contract — V2.16.

Defines the foundational **domain contract** for the Version 2 Human-in-
the-Loop approval workflow: the structured request to route a
``REQUIRES_APPROVAL`` policy decision to a human analyst / CISO, the
closed approval-state vocabulary, and the auditable approval record that
the workflow produces.

The pipeline already knows:

* Detection — *what matched?*
* Correlation — *what is related?*
* Risk Assessment — *how dangerous?*
* Investigation / Attribution — *what happened and who may be
  responsible?*
* Policy Decision — *may this proposed response action proceed?*
* Response & Mitigation — *how is a permitted action safely executed?*
* **Approval Workflow (this module)** — *did a human authorize a
  REQUIRES_APPROVAL decision, and what did the Response layer do with
  that authorization?*

Design principles:

* **Human decision, never machine.** An approval is a governance record
  of a human decision over a policy decision.  Everything here is
  structured bookkeeping: no LLM, no Gemini/LangGraph, no model ever
  decides an approval, who may approve, or why.  There is no automatic
  approval, no approval scoring, and no free-form instruction channel.
* **Approval == authorization, not execution.** ``APPROVED`` means a
  human granted the underlying policy decision; it neither creates nor
  executes a response action.  A separately recorded ``response_status``
  reflects what the Response & Mitigation layer subsequently did
  (``executed`` / ``failed`` / ``skipped`` / ``rejected``) — these are
  *different* fields on purpose, so nobody can mistake "approved" for
  "done".
* **Closed state vocabulary.** :class:`ApprovalStatus` has exactly five
  members (``pending`` / ``approved`` / ``rejected`` / ``expired`` /
  ``cancelled``).  Terminal states never transition; ``approved`` is
  idempotent and never re-executes.
* **Closed action vocabulary.** The action is inherited from the Step 24
  :class:`~app.schemas.policy_decision.PolicyDecision` (imported, never
  redefined, never supplied by the client).  ``target`` is a *controlled
  identifier* validated per action by the existing Response validator —
  the contract here bounds it, rejects control characters, and scans for
  secrets.
* **One lifecycle per decision.** A policy decision resolves exactly
  once; ``approval_id`` and ``policy_decision_id`` are both deterministic
  and unique, so an already-resolved decision can never be re-opened or
  double-executed.
* **Provenance-aware.** An approval record carries the additive
  ``Provenance.APPROVAL_REVIEWED`` value and forbids all prior values —
  an approval is a human governance action, never observed telemetry,
  never a detection/correlation/risk/attribution/recall/learning, and
  never a policy decision or a response result.
* **Secret-safe & deterministic.** Comments, notes and targets are strict
  JSON-compatible, secret-scanning, deep-copying payloads (mirroring the
  Step 9A / 10A / 11A / 24 / 25 boundaries).
* **Contract only.** This module validates and describes; it contains no
  decision, no approval logic, no transitions, no persistence, no
  response execution, no I/O, and no LLM.

Relationship to the pipeline::

    PolicyDecision (Step 24)  REQUIRES_APPROVAL
        -> ApprovalRequestCreate        (V2.16 — this module)
            -> ApprovalService           (V2.16 service layer)
                -> ApprovalRecord        (V2.16 — this module)
                    -> [ResponseRequest on APPROVED]  (Step 25 keeps the
                       execution gate; approval authorizes, never executes)

``Approval != Response``: this contract only records that a human granted
or refused a decision.  The actual (simulated) execution happens — when an
approval is granted — through the existing Step 25 Response layer, which
re-checks everything at its own gate.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.policy_decision import (
    PolicyDecision,
    ResponseActionType,
)
from app.schemas.risk import RiskLevel
from app.schemas.security_event import Provenance


# ---------------------------------------------------------------------------
# Bounds & constants (single source of truth, documented)
# ---------------------------------------------------------------------------

#: Maximum length of a controlled target identifier carried from the
#: Response contract (the per-action *structural* validation lives in the
#: Response service layer; this contract mirrors the Step 25 bound).
APPROVAL_MAX_TARGET_LENGTH = 512

#: Maximum length of a request/decision comment or note.
APPROVAL_MAX_COMMENT_LENGTH = 500

#: Maximum length of the inherited policy reason.
APPROVAL_MAX_REASON_LENGTH = 500

#: Maximum length of the inherited ``policy_rule_id``.
APPROVAL_MAX_RULE_ID_LENGTH = 64

#: Maximum length of a role label recorded on a request.
APPROVAL_MAX_ROLE_LENGTH = 32

#: How long a pending approval may wait for a human decision before it
#: expires (lazy-expired; there is no scheduler).  A fixed TTL keeps
#: stale grants from hanging around indefinitely.
APPROVAL_PENDING_TTL = timedelta(hours=24)

#: Deterministic identity namespace for approval records.  Fixed so the
#: same (decision, action, target, requester) tuple always derives the
#: same ``approval_id`` — the workflow never uses randomness for identity.
APPROVAL_NAMESPACE = uuid.UUID("3d4e5f6a-7b8c-4d9e-8f0a-1b2c3d4e5f60")

#: Credential-shaped strings re-checked at this boundary (mirror 11A/24/25).
_SECRET_PATTERNS = ("api_key", "authorization", "bearer", "secret")


# ---------------------------------------------------------------------------
# Secret-safety helpers (mirror the Step 9A / 10A / 11A / 24 / 25 patterns)
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


def _reject_control_characters(value: str, field: str) -> str:
    """Reject control characters in structured strings (tab is allowed)."""
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


class ApprovalStatus(str, Enum):
    """The five possible states of an approval request.

    * ``pending``   — created from a REQUIRES_APPROVAL decision and waiting
      for an authorized human.
    * ``approved``  — an authorized human granted the decision.  Terminal.
      Granting an approval authorizes (and only authorizes) the Step 25
      Response layer to act; a separate ``response_status`` records what
      happened.
    * ``rejected``  — an authorized human refused the decision.  Terminal.
    * ``expired``   — the pending request outlived the fixed TTL.  Terminal;
      an expired request can never be approved.
    * ``cancelled`` — the request was withdrawn before resolution.  Terminal.
    """

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


#: Human decisions over a REQUIRES_APPROVAL decision (authorized roles).
#: ``None`` + not-yet-expired subset is the live (actionable) pending set.
APPROVAL_DECISION_STATUSES = frozenset(
    {ApprovalStatus.APPROVED, ApprovalStatus.REJECTED}
)

#: Statuses that can never transition again.
APPROVAL_TERMINAL_STATUSES = frozenset(
    {ApprovalStatus.APPROVED, ApprovalStatus.REJECTED, ApprovalStatus.EXPIRED, ApprovalStatus.CANCELLED}
)


# ---------------------------------------------------------------------------
# Approval request creation
# ---------------------------------------------------------------------------


class ApprovalRequestCreate(BaseModel):
    """Structured request to route one policy decision to a human.

    The decision is carried in full (the Step 24 contract validates it);
    the **action is inherited from the decision** — the client supplies
    only the controlled ``target`` and an optional note, never an action,
    never its own authorization claim, and never an instruction.
    """

    model_config = ConfigDict(extra="forbid")

    decision: PolicyDecision = Field(
        ...,
        description=(
            "The Step 24 policy decision to route for human authorization.  "
            "Must carry decision=REQUIRES_APPROVAL and requires_approval=True "
            "(enforced by the service layer).  The proposed action is read "
            "from this decision and is never supplied by the client."
        ),
    )
    target: str = Field(
        ...,
        min_length=1,
        max_length=APPROVAL_MAX_TARGET_LENGTH,
        description=(
            "Controlled target identifier (IP, domain, file id, account, "
            "session, endpoint).  Validated structurally per action by the "
            "existing Response validator — the contract never interprets it."
        ),
    )
    request_note: str | None = Field(
        default=None,
        max_length=APPROVAL_MAX_COMMENT_LENGTH,
        description=(
            "Optional, secret-free note attached by the requester for the "
            "human reviewer (max 500 chars)."
        ),
    )

    @field_validator("target")
    @classmethod
    def _ensure_target_safe(cls, v: str) -> str:
        _reject_control_characters(v, "target")
        _assert_json_compatible(v, "target")
        _assert_no_secrets(v, "target")
        return _require_non_blank(v, "target")

    @field_validator("request_note")
    @classmethod
    def _ensure_note_safe(cls, v: str | None) -> str | None:
        if v is None:
            return None
        _reject_control_characters(v, "request_note")
        _assert_json_compatible(v, "request_note")
        _assert_no_secrets(v, "request_note")
        return _require_non_blank(v, "request_note")


# ---------------------------------------------------------------------------
# Approval decision input
# ---------------------------------------------------------------------------


class ApprovalDecisionInput(BaseModel):
    """Structured human response to a pending approval.

    The comment is required (accountability for a governance action —
    who decided and, in their own words, why).  Never an instruction
    channel: it is bookkeeping only and is never executed or interpreted.
    """

    model_config = ConfigDict(extra="forbid")

    comment: str = Field(
        ...,
        min_length=1,
        max_length=APPROVAL_MAX_COMMENT_LENGTH,
        description=(
            "The human reviewer's own, secret-free comment for the audit "
            "trail (1..500 chars).  Bookkeeping only — never interpreted."
        ),
    )

    @field_validator("comment")
    @classmethod
    def _ensure_comment_safe(cls, v: str) -> str:
        _reject_control_characters(v, "comment")
        _assert_json_compatible(v, "comment")
        _assert_no_secrets(v, "comment")
        return _require_non_blank(v, "comment")


# ---------------------------------------------------------------------------
# Approval record (read model)
# ---------------------------------------------------------------------------


class ApprovalRecord(BaseModel):
    """The auditable read model of one approval request.

    Distinguishes, on purpose:

    * ``status`` — the approval lifecycle state (pending / approved /
      rejected / expired / cancelled), decided **by a human**;
    * ``response_status`` — what the Step 25 Response layer did after an
      APPROVED grant (executed / failed / skipped / rejected), decided by
      the Response executor.

    "Approved" therefore never implies "executed", and "executed" never
    implies a human approved when ``response_status`` is absent.
    """

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID = Field(
        ...,
        description="Persistence-row primary key (instrumentation identity, not evidence).",
    )
    approval_id: uuid.UUID = Field(
        ...,
        description=(
            "Deterministic domain identity of this approval (UUIDv5 over "
            "decision/action/target/requester content).  Unique."
        ),
    )
    policy_decision_id: uuid.UUID = Field(
        ...,
        description=(
            "The Step 24 decision being routed.  Unique — one decision has "
            "exactly one approval lifecycle."
        ),
    )
    correlation_id: uuid.UUID = Field(
        ...,
        description="The correlation the underlying decision concerns (reference only).",
    )
    action_type: ResponseActionType = Field(
        ...,
        description="The proposed action, inherited from the decision.",
    )
    target: str = Field(
        ...,
        max_length=APPROVAL_MAX_TARGET_LENGTH,
        description="Canonicalized controlled target identifier.",
    )
    status: ApprovalStatus = Field(
        ...,
        description="pending / approved / rejected / expired / cancelled.",
    )
    reason: str = Field(
        ...,
        min_length=1,
        max_length=APPROVAL_MAX_REASON_LENGTH,
        description="The decision's deterministic policy reason (preserved verbatim).",
    )
    policy_rule_id: str = Field(
        ...,
        min_length=3,
        max_length=APPROVAL_MAX_RULE_ID_LENGTH,
        description="The policy rule that required approval.",
    )
    risk_level: RiskLevel = Field(
        ...,
        description="Risk level carried from the decision.",
    )
    risk_score: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Risk score carried from the decision when available.",
    )
    confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Confidence carried from the decision when available.",
    )
    evidence: list[dict[str, Any]] = Field(
        default_factory=list,
        description=(
            "Sanitized, structured references preserved from the decision "
            "(never fabricated, never rewritten)."
        ),
    )
    request_note: str | None = Field(
        default=None,
        max_length=APPROVAL_MAX_COMMENT_LENGTH,
        description="The requester's note, if any.",
    )
    requested_by: uuid.UUID = Field(
        ...,
        description="Authenticated identity of the requester (the workflow trusts no claims).",
    )
    requested_by_role: str = Field(
        ...,
        max_length=APPROVAL_MAX_ROLE_LENGTH,
        description="The requester's role as read from the trusted identity store.",
    )
    requested_at: datetime = Field(
        ...,
        description="Timezone-aware instant the request was created.",
    )
    expires_at: datetime = Field(
        ...,
        description="Timezone-aware instant the pending request expires (fixed TTL).",
    )
    resolved_at: datetime | None = Field(
        default=None,
        description="Timezone-aware instant a human (or lapse) resolved the request.",
    )
    resolved_by: uuid.UUID | None = Field(
        default=None,
        description="Authenticated identity of the human who resolved the request (None for expiry).",
    )
    resolution_reason: str | None = Field(
        default=None,
        max_length=APPROVAL_MAX_COMMENT_LENGTH,
        description="The human's own comment, or the documentary expiry reason.",
    )
    response_status: str | None = Field(
        default=None,
        max_length=16,
        description=(
            "What the Step 25 Response layer did after an APPROVED grant "
            "(executed / failed / skipped / rejected) — distinct from and "
            "never conflated with the approval status."
        ),
    )
    response_provider: str | None = Field(
        default=None,
        max_length=64,
        description=(
            "Which provider ran when the grant reached the Response layer "
            "(simulated mock in V2.16), or None when nothing ran."
        ),
    )
    response_error_code: str | None = Field(
        default=None,
        max_length=64,
        description="Sanitized response error/rejection code when applicable.",
    )
    provenance: Provenance = Field(
        default=Provenance.APPROVAL_REVIEWED,
        description=(
            "Always APPROVAL_REVIEWED — an approval is a human governance "
            "action and is never any prior provenance value."
        ),
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured, JSON-compatible, secret-free bookkeeping.",
    )
    created_at: datetime = Field(
        ...,
        description="When the row was first persisted (UTC, timezone-aware).",
    )
    updated_at: datetime = Field(
        ...,
        description="When the row was last modified (UTC, timezone-aware).",
    )

    @field_validator("target", "resolution_reason")
    @classmethod
    def _ensure_safe_strings(cls, v: str | None) -> str | None:
        if v is None:
            return None
        _reject_control_characters(v, "field")
        _assert_json_compatible(v, "field")
        _assert_no_secrets(v, "field")
        return _require_non_blank(v, "field")

    @field_validator("reason")
    @classmethod
    def _ensure_preserved_reason(cls, v: str) -> str:
        """Keep the inherited policy reason structurally safe but verbatim.

        ``reason`` is preserved verbatim from the Step 24 decision snapshot
        (already vetted by the decision contract), so it is *not* re-scanned
        for credential-shaped patterns here — a policy reason may legitimately
        discuss authorization, secrets policy, etc.  Rejecting such content at
        this read boundary would make an otherwise valid persisted approval
        impossible to read back.  Control characters and blank values are
        still rejected.
        """
        _reject_control_characters(v, "reason")
        _assert_json_compatible(v, "reason")
        return _require_non_blank(v, "reason")

    @field_validator("resolved_at", "requested_at", "expires_at", "created_at", "updated_at")
    @classmethod
    def _ensure_timezone_aware(cls, v: datetime | None) -> datetime | None:
        if v is None:
            return None
        return _ensure_tz_aware(v, "approval timestamps")

    @field_validator("metadata")
    @classmethod
    def _ensure_metadata_valid(cls, v: dict[str, Any]) -> dict[str, Any]:
        _assert_json_compatible(v, "metadata")
        _assert_no_secrets(v, "metadata")
        return _json_clone(v)

    @field_validator("provenance")
    @classmethod
    def _ensure_approval_provenance(cls, v: Provenance) -> Provenance:
        """Pin approval records to APPROVAL_REVIEWED (mirror Step 11A/24/25)."""
        if v is not Provenance.APPROVAL_REVIEWED:
            raise ValueError(
                "approval records must carry APPROVAL_REVIEWED provenance; "
                f"got {v.value!r}"
            )
        return v


# ---------------------------------------------------------------------------
# Pagination envelope
# ---------------------------------------------------------------------------


class ApprovalPage(BaseModel):
    """One 1-based page of approval records."""

    items: list[ApprovalRecord] = Field(
        ...,
        description="The page's approval records, newest first.",
    )
    total: int = Field(
        ...,
        ge=0,
        description="Total number of approval records matching the query.",
    )
    page: int = Field(
        ...,
        ge=1,
        description="Requested 1-based page number.",
    )
    page_size: int = Field(
        ...,
        ge=1,
        description="Requested maximum number of items per page.",
    )


__all__ = [
    "APPROVAL_DECISION_STATUSES",
    "APPROVAL_MAX_COMMENT_LENGTH",
    "APPROVAL_MAX_REASON_LENGTH",
    "APPROVAL_MAX_ROLE_LENGTH",
    "APPROVAL_MAX_RULE_ID_LENGTH",
    "APPROVAL_MAX_TARGET_LENGTH",
    "APPROVAL_NAMESPACE",
    "APPROVAL_PENDING_TTL",
    "APPROVAL_TERMINAL_STATUSES",
    "ApprovalDecisionInput",
    "ApprovalPage",
    "ApprovalRecord",
    "ApprovalRequestCreate",
    "ApprovalStatus",
]