"""SOAR Domain Contract — V2.18.

Defines the foundational **domain contract** for the SentinelAI SOAR
(Security Orchestration, Automation and Response) layer: the closed
operation vocabulary, the declarative playbook shape, the execution-state
vocabularies, and the persisted read models for *playbooks, playbook
versions, executions and step executions*.

Pipeline position::

    Detection -> Correlation -> Risk -> Investigation -> Attribution
        -> Policy (Step 24) -> Approval (V2.16) -> Response (Step 25)
            -> SOAR (this module) -> Playbook -> Provider (sandbox)

Design principles:

* **SOAR orchestrates; it never decides and never bypasses.** SOAR does
  NOT replace the Policy Decision Engine or the Response & Mitigation
  layer.  It runs a registered, declarative playbook *only* under an
  authorizing policy decision (``ALLOWED`` or a ``REQUIRES_APPROVAL``
  decision backed by a verifiable human grant in the V2.16 approval
  workflow).  A ``DENIED`` decision can never reach a provider.
* **Closed operations.** The operation vocabulary is the *same* Step 24
  :class:`~app.schemas.policy_decision.ResponseActionType` (imported,
  never redefined) — block_ip, block_domain, quarantine_file,
  disable_account, terminate_session, isolate_endpoint.  There is no
  custom action, no free-form command, no function name, no SQL, and no
  shell string anywhere in this contract.
* **Declarative playbooks only.** A playbook is an ordered list of
  validated ``SoarStep`` values — each step names one provider and one
  operation, with bounded parameters, a bounded retry count and a bounded
  timeout.  Playbooks are **server-registered** (seeded into the playbook
  registry); clients can never author, import, or upload code.  A step
  never carries a command, path, URL, module, script or executable.
* **Targets are governed, never smuggled.** The primary target is
  inherited from the authorizing decision's action + canonical target.
  A step *may* declare its own target, but only structurally validated
  per its operation at registration time — never supplied at execution.
* **Deterministic identity & idempotency.** ``execution_id`` and the
  idempotency key are content-derived (policy decision, approval,
  response, playbook, target, action), never random and never wall-clock
  based.
* **Secret-safe & bounded.** Every free-form field rejects control
  characters and credential-shaped content; metadata is strictly
  JSON-compatible and depth-bounded; messages/error codes are sanitized
  templates.
* **Contract only.** This module validates and describes.  It contains no
  provider, no execution logic, no I/O, no LLM, and no external-system
  contact.

Most important boundary (documented in
``docs/development/soar_v218.md``):

    V2.18 SOAR uses sandbox/mock providers.  It does NOT perform
    real-world security actions, connect to real network/system
    adapters, or allow arbitrary code/script/command execution.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas.policy_decision import (
    PolicyDecision,
    PolicyDecisionStatus,
    ResponseActionType,
)


# ---------------------------------------------------------------------------
# Bounds & constants (single source of truth, documented)
# ---------------------------------------------------------------------------

#: Deterministic UUIDv5 namespace for all SOAR identities (fixed, so the
#: same content tuple always derives the same identity — never random).
SOAR_NAMESPACE = uuid.UUID("8b7a6c2e-9d4f-4a73-8c1e-2f3a4b5c6d7e")

#: Maximum length of a registered playbook identifier.
SOAR_MAX_PLAYBOOK_ID_LENGTH = 128

#: Maximum length of a human-readable playbook name.
SOAR_MAX_PLAYBOOK_NAME_LENGTH = 200

#: Maximum length of a playbook description.
SOAR_MAX_DESCRIPTION_LENGTH = 1000

#: Maximum length of the declarative playbook schema version label.
SOAR_MAX_SCHEMA_VERSION_LENGTH = 16

#: Maximum length of a registered provider identifier.
SOAR_MAX_PROVIDER_ID_LENGTH = 64

#: Maximum length of a playbook semantic-version label.
SOAR_MAX_VERSION_LENGTH = 32

#: Maximum length of a sanitized error/rejection code.
SOAR_MAX_ERROR_CODE_LENGTH = 64

#: Maximum length of a sanitized result message.
SOAR_MAX_MESSAGE_LENGTH = 500

#: Maximum length of a raw target identifier (structural validation lives
#: in the Step 25 service layer; the contract only bounds it).
SOAR_MAX_TARGET_LENGTH = 512

#: Maximum serialized metadata depth (mirror Step 25 / 24 conventions).
SOAR_MAX_METADATA_DEPTH = 4

#: Serialized upper bound on SOAR request/record ``metadata`` dictionaries.
SOAR_MAX_METADATA_SERIALIZED_BYTES = 65536

#: Maximum number of serialized bytes in one declarative playbook
#: definition (anti-DoS / determinism guard).
SOAR_MAX_PLAYBOOK_DEFINITION_BYTES = 64 * 1024

#: Maximum number of steps in one playbook.
SOAR_MAX_STEPS = 50

#: Maximum length of a step label.
SOAR_MAX_STEP_LABEL_LENGTH = 120

#: Maximum per-step retry count (bounded, never unlimited).
SOAR_MAX_RETRIES = 3

#: Minimum per-step timeout (seconds) — a step cannot be "timed out"
#: through a zero/immediate timeout.
SOAR_MIN_TIMEOUT_SECONDS = 5

#: Maximum per-step timeout (seconds).
SOAR_MAX_TIMEOUT_SECONDS = 300

#: Initial playbook version for every registered playbook.
SOAR_PLAYBOOK_INITIAL_VERSION = "1.0.0"

#: The maximum number of entries the in-memory processed-idempotency map
#: may hold before the engine fails closed with a provisioning error
#: (mirrors the Step 25 response executor guard).
SOAR_MAX_PROCESSED_KEYS = 10_000

#: The single supported declarative playbook schema version.
SOAR_CURRENT_SCHEMA_VERSION = "1.0.0"

#: Credential-shaped strings re-checked at this boundary (mirror Step 24/25).
_SOAR_SECRET_PATTERNS = ("api_key", "authorization", "bearer", "secret")


# ---------------------------------------------------------------------------
# Secret-safety helpers (mirror the Step 24 / 25 patterns)
# ---------------------------------------------------------------------------


def _assert_json_compatible(value: Any, field: str) -> None:
    try:
        json.dumps(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be JSON-compatible: {exc}") from exc


def _assert_no_secrets(value: Any, field: str) -> None:
    serialized = json.dumps(value).lower()
    for pattern in _SOAR_SECRET_PATTERNS:
        if pattern in serialized:
            raise ValueError(
                f"{field} must not contain secrets ('{pattern}' detected)"
            )


def _json_clone(value: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(value))


def _require_non_blank(value: str, field: str) -> str:
    stripped = value.strip()
    if not stripped:
        raise ValueError(f"{field} must not be blank")
    return stripped


def _ensure_tz_aware(value: datetime, field: str) -> datetime:
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(
            f"{field} must be timezone-aware; naive timestamps are not accepted"
        )
    return value


def _ensure_metadata_bounded(value: dict[str, Any], field: str) -> dict[str, Any]:
    def depth(item: Any, current: int) -> int:
        if current > SOAR_MAX_METADATA_DEPTH:
            return current
        if isinstance(item, dict):
            return max((depth(v, current + 1) for v in item.values()), default=current)
        if isinstance(item, list):
            return max((depth(v, current + 1) for v in item), default=current)
        return current

    if depth(value, 0) > SOAR_MAX_METADATA_DEPTH:
        raise ValueError(
            f"{field} must not exceed {SOAR_MAX_METADATA_DEPTH} levels of nesting"
        )
    if len(json.dumps(value)) > SOAR_MAX_METADATA_SERIALIZED_BYTES:
        raise ValueError(
            f"{field} must not exceed "
            f"{SOAR_MAX_METADATA_SERIALIZED_BYTES} serialized bytes"
        )
    return _json_clone(value)


def _reject_control_characters(value: str, field: str) -> str:
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


class SoarProviderType(str, Enum):
    """The closed set of registered provider adapters.

    Every provider is a **sandbox/mock** adapter in V2.18 — there is no
    real firewall, EDR or identity provider behind it.
    """

    FIREWALL = "firewall"
    EDR = "edr"
    IDENTITY = "identity"


class SoarExecutionStatus(str, Enum):
    """Lifecycle state of one SOAR execution.

    * ``pending``   — awaiting a human approval grant (recorded, nothing
      executed).
    * ``running``   — the playbook is actively executing steps.
    * ``succeeded`` — every step of the playbook succeeded.
    * ``failed``    — a step failed under STOP_ON_FAILURE (or the run was
      refused) and no further step executed.
    * ``partial``   — some steps succeeded before the run stopped.
    * ``cancelled`` — an authorized human cancelled the run.
    * ``rejected``  — the policy gate refused the run before any provider
      was invoked (e.g. DENIED, requies a missing/invalid approval).
    """

    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    PARTIAL = "partial"
    CANCELLED = "cancelled"
    REJECTED = "rejected"


class SoarStepStatus(str, Enum):
    """Lifecycle state of one step inside an execution.

    * ``pending``   — queued, not yet attempted.
    * ``running``   — the provider adapter is being invoked.
    * ``succeeded`` — the sandbox provider completed successfully.
    * ``failed``    — the step failed (final, after any bounded retries).
    * ``skipped``   — not attempted because an earlier step stopped the
      run (STOP_ON_FAILURE) or the run was cancelled.
    * ``timed_out`` — the step exceeded its bounded timeout.
    * ``cancelled`` — skipped because an authorized human cancelled the run.
    """

    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"


class SoarFailurePolicy(str, Enum):
    """How a step failure propagates through the playbook.

    * ``stop_on_failure``   — the run stops at the first failed step
      (remaining steps become ``skipped``).
    * ``continue_on_failure`` — the run continues, but every failed step
      is still recorded as FAILED (a failure is never converted into a
      success; the choice to continue is explicit and audited).
    """

    STOP_ON_FAILURE = "stop_on_failure"
    CONTINUE_ON_FAILURE = "continue_on_failure"


class SoarFailureCategory(str, Enum):
    """Stable category of a step failure.

    Only :data:`SOAR_RETRYABLE_CATEGORIES` may ever be retried.
    Authorization, policy and invalid-input failures are **never** retried.
    """

    TIMEOUT = "timeout"
    TRANSIENT = "transient"
    PROVIDER_ERROR = "provider_error"
    INVALID_INPUT = "invalid_input"
    POLICY = "policy"
    AUTHORIZATION = "authorization"
    INTERNAL = "internal"


#: Failures that a bounded retry may legitimately address.
SOAR_RETRYABLE_CATEGORIES = frozenset(
    {
        SoarFailureCategory.TIMEOUT,
        SoarFailureCategory.TRANSIENT,
        SoarFailureCategory.PROVIDER_ERROR,
    }
)


# ---------------------------------------------------------------------------
# Playbook (declarative definition units)
# ---------------------------------------------------------------------------


class SoarStep(BaseModel):
    """One declarative step of a registered playbook.

    A step is a **declarative directive**: name a provider adapter, name
    one closed operation, bound parameters, bound retries, bound timeout.
    It carries no command, no script, no shell string, no filesystem path,
    no module/import, no URL payload and no executable identity.
    """

    model_config = ConfigDict(extra="forbid")

    step_number: int = Field(
        ...,
        ge=1,
        description="1-based position of the step in the playbook.",
    )
    label: str = Field(
        ...,
        min_length=1,
        max_length=SOAR_MAX_STEP_LABEL_LENGTH,
        description="Human-readable, secret-free step label.",
    )
    provider_id: str = Field(
        ...,
        min_length=1,
        max_length=SOAR_MAX_PROVIDER_ID_LENGTH,
        description=(
            "Registered provider adapter identifier (allowlisted server-"
            "side; never a user-controlled import or URL)."
        ),
    )
    operation: ResponseActionType = Field(
        ...,
        description=(
            "The closed operation this step performs (same vocabulary as "
            "Step 24/25, imported never redefined)."
        ),
    )
    target: str | None = Field(
        default=None,
        min_length=1,
        max_length=SOAR_MAX_TARGET_LENGTH,
        description=(
            "Optional explicitly bound target for this step.  When None, "
            "the step inherits the canonical target of the authorizing "
            "decision.  A provided target is structurally validated per its "
            "operation at registration time — never supplied at execution."
        ),
    )
    params: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Structured, JSON-compatible, secret-free, depth-bounded "
            "bookkeeping passed to the provider adapter.  Never executed "
            "or interpreted as code."
        ),
    )
    retries: int = Field(
        default=0,
        ge=0,
        le=SOAR_MAX_RETRIES,
        description=(
            f"Number of additional attempts permitted on retryable "
            f"failures (0..{SOAR_MAX_RETRIES}).  Authorization, policy and "
            "invalid-input failures are never retried."
        ),
    )
    timeout_seconds: int = Field(
        default=30,
        ge=SOAR_MIN_TIMEOUT_SECONDS,
        le=SOAR_MAX_TIMEOUT_SECONDS,
        description=(
            f"Bounded per-attempt timeout in seconds "
            f"({SOAR_MIN_TIMEOUT_SECONDS}..{SOAR_MAX_TIMEOUT_SECONDS})."
        ),
    )

    @field_validator("label", "target")
    @classmethod
    def _ensure_safe_strings(cls, v: str | None) -> str | None:
        if v is None:
            return None
        _reject_control_characters(v, "field")
        _assert_json_compatible(v, "field")
        _assert_no_secrets(v, "field")
        return _require_non_blank(v, "field")

    @field_validator("provider_id")
    @classmethod
    def _ensure_provider_label_safe(cls, v: str) -> str:
        _reject_control_characters(v, "provider_id")
        _assert_json_compatible(v, "provider_id")
        _assert_no_secrets(v, "provider_id")
        return _require_non_blank(v, "provider_id")

    @field_validator("params")
    @classmethod
    def _ensure_params_valid(cls, v: dict[str, Any]) -> dict[str, Any]:
        _assert_json_compatible(v, "params")
        _assert_no_secrets(v, "params")
        return _ensure_metadata_bounded(v, "params")


class SoarPlaybookDefinition(BaseModel):
    """A full declarative playbook (the server-registered artifact).

    The ``primary_action`` is the authorizing action the playbook
    orchestrates.  Every step may declare its own operation, but the first
    step MUST perform the primary action so the playbook is anchored to the
    approved decision.
    """

    model_config = ConfigDict(extra="forbid")

    playbook_id: str = Field(
        ...,
        min_length=1,
        max_length=SOAR_MAX_PLAYBOOK_ID_LENGTH,
        description="Stable, unique identifier of the registered playbook.",
    )
    name: str = Field(
        ...,
        min_length=1,
        max_length=SOAR_MAX_PLAYBOOK_NAME_LENGTH,
        description="Human-readable playbook name.",
    )
    description: str = Field(
        ...,
        min_length=1,
        max_length=SOAR_MAX_DESCRIPTION_LENGTH,
        description="Human-readable, secret-free description of the workflow.",
    )
    schema_version: str = Field(
        default=SOAR_CURRENT_SCHEMA_VERSION,
        max_length=SOAR_MAX_SCHEMA_VERSION_LENGTH,
        description=(
            "Version of the declarative playbook schema this artifact "
            "conforms to.  Only the current version is accepted."
        ),
    )
    primary_action: ResponseActionType = Field(
        ...,
        description=(
            "The action the playbook orchestrates — must match the action "
            "of the authorizing policy decision and of its first step."
        ),
    )
    failure_policy: SoarFailurePolicy = Field(
        default=SoarFailurePolicy.STOP_ON_FAILURE,
        description=(
            "How a step failure propagates (stop_on_failure default; an "
            "explicit continue is never a silent success)."
        ),
    )
    steps: list[SoarStep] = Field(
        ...,
        min_length=1,
        max_length=SOAR_MAX_STEPS,
        description="Ordered declarative steps of the playbook (1..50).",
    )

    @field_validator("playbook_id")
    @classmethod
    def _ensure_playbook_id_safe(cls, v: str) -> str:
        _reject_control_characters(v, "playbook_id")
        _assert_json_compatible(v, "playbook_id")
        _assert_no_secrets(v, "playbook_id")
        return _require_non_blank(v, "playbook_id")

    @field_validator("name")
    @classmethod
    def _ensure_name_safe(cls, v: str) -> str:
        _reject_control_characters(v, "name")
        _assert_json_compatible(v, "name")
        _assert_no_secrets(v, "name")
        return _require_non_blank(v, "name")

    @field_validator("description")
    @classmethod
    def _ensure_description_safe(cls, v: str) -> str:
        _reject_control_characters(v, "description")
        _assert_json_compatible(v, "description")
        _assert_no_secrets(v, "description")
        return _require_non_blank(v, "description")

    @field_validator("steps")
    @classmethod
    def _ensure_steps_sequential(cls, v: list[SoarStep]) -> list[SoarStep]:
        for idx, step in enumerate(v, start=1):
            if step.step_number != idx:
                raise ValueError(
                    "playbook steps must be sequential 1..n without gaps"
                )
        return v

    @model_validator(mode="after")
    def _ensure_primary_step_anchors_primary_action(self) -> "SoarPlaybookDefinition":
        if self.schema_version != SOAR_CURRENT_SCHEMA_VERSION:
            raise ValueError(
                "unsupported playbook schema version; only "
                f"{SOAR_CURRENT_SCHEMA_VERSION} is accepted"
            )
        if self.steps and self.steps[0].operation is not self.primary_action:
            raise ValueError(
                "the playbook's first step must perform its primary_action"
            )
        if len(json.dumps(self.model_dump(mode="json"))) > SOAR_MAX_PLAYBOOK_DEFINITION_BYTES:
            raise ValueError(
                "playbook definition exceeds the bounded serialized size"
            )
        return self


class SoarPlaybookValidator:
    """Pure, side-effect-free validation helpers for a playbook.

    The contract keeps the *structural* rules; the service layer (which
    owns the provider registry) applies cross-cutting rules such as
    "every step provider is registered" and "the provider supports the
    step's operation".  This class implements the rules that need no I/O.
    """

    @staticmethod
    def ensure_playbook_id(v: str) -> str:
        _reject_control_characters(v, "playbook_id")
        _assert_json_compatible(v, "playbook_id")
        _assert_no_secrets(v, "playbook_id")
        return _require_non_blank(v, "playbook_id")

    @staticmethod
    def ensure_definition_size(v: SoarPlaybookDefinition) -> SoarPlaybookDefinition:
        size = len(json.dumps(v.model_dump(mode="json")))
        if size > SOAR_MAX_PLAYBOOK_DEFINITION_BYTES:
            raise ValueError(
                "playbook definition exceeds the bounded serialized size"
            )
        return v


# ---------------------------------------------------------------------------
# Execution request
# ---------------------------------------------------------------------------


class SoarExecutionRequest(BaseModel):
    """Structured request to run a registered playbook under an
    authorizing policy decision.

    The **decision is carried in full**; ``action_type``, ``correlation_id``
    and ``policy_decision_id`` are inherited from it, and the playbook is
    registered.  The client supplies the controlled ``target`` identifier
    (a reference, exactly as the Step 25 :class:`ResponseRequest` does) —
    never an action, never a provider id, never a playbook step, and never
    an authorization claim.

    A ``REQUIRES_APPROVAL`` decision must carry a verifiable ``approval_id``
    for the run to reach a provider; without it the engine records a
    ``pending`` execution and never calls a provider.
    """

    model_config = ConfigDict(extra="forbid")

    decision: PolicyDecision = Field(
        ...,
        description=(
            "The Step 24 policy decision authorizing the workflow.  Its "
            "action, correlation and ids drive the run; the gate re-verifies "
            "it (ALLOWED or REQUIRES_APPROVAL with a valid human grant) "
            "before any provider is invoked."
        ),
    )
    target: str = Field(
        ...,
        min_length=1,
        max_length=SOAR_MAX_TARGET_LENGTH,
        description=(
            "Controlled target identifier (IP, domain, file id, account, "
            "session, endpoint) that the primary step applies.  Structurally "
            "validated per the decision's action by the Step 25 service "
            "layer — SOAR never interprets it (no DNS, filesystem or "
            "network)."
        ),
    )
    approval_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "Optional reference to a V2.16 human approval grant that "
            "authorizes a REQUIRES_APPROVAL decision.  CARRIES NO "
            "PERMISSION ITSELF: the gate only honours it through an "
            "ApprovalGrantVerifier wired into the SOAR engine."
        ),
    )
    response_id: uuid.UUID = Field(
        ...,
        description=(
            "Deterministic reference to the Step 25 Response result this "
            "orchestration builds upon (traceability: policy_decision_id -> "
            "approval_id -> response_id -> soar execution)."
        ),
    )
    playbook_id: str = Field(
        ...,
        min_length=1,
        max_length=SOAR_MAX_PLAYBOOK_ID_LENGTH,
        description="Registered, allowlisted playbook to run.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Structured, JSON-compatible, secret-free bookkeeping about "
            "this run.  Never executed or interpreted."
        ),
    )

    @field_validator("playbook_id")
    @classmethod
    def _ensure_playbook_id_safe(cls, v: str) -> str:
        return SoarPlaybookValidator.ensure_playbook_id(v)

    @field_validator("target")
    @classmethod
    def _ensure_target_safe(cls, v: str) -> str:
        _reject_control_characters(v, "target")
        _assert_json_compatible(v, "target")
        _assert_no_secrets(v, "target")
        return _require_non_blank(v, "target")

    @field_validator("metadata")
    @classmethod
    def _ensure_metadata_valid(cls, v: dict[str, Any]) -> dict[str, Any]:
        _assert_json_compatible(v, "metadata")
        _assert_no_secrets(v, "metadata")
        return _ensure_metadata_bounded(v, "metadata")


# ---------------------------------------------------------------------------
# Read models
# ---------------------------------------------------------------------------


class SoarPlaybookRecord(BaseModel):
    """Read model of one registered playbook (latest active version)."""

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID = Field(
        ...,
        description="Persistence-row primary key (instrumentation, not evidence).",
    )
    playbook_id: str = Field(
        ...,
        max_length=SOAR_MAX_PLAYBOOK_ID_LENGTH,
        description="Stable registered playbook identifier.",
    )
    name: str = Field(
        ...,
        max_length=SOAR_MAX_PLAYBOOK_NAME_LENGTH,
        description="Human-readable name.",
    )
    description: str = Field(
        ...,
        max_length=SOAR_MAX_DESCRIPTION_LENGTH,
        description="Secret-free description.",
    )
    schema_version: str = Field(
        ...,
        max_length=SOAR_MAX_SCHEMA_VERSION_LENGTH,
        description="Declarative schema version.",
    )
    version: str = Field(
        ...,
        max_length=SOAR_MAX_VERSION_LENGTH,
        description="Current semantic version of the playbook.",
    )
    version_id: uuid.UUID = Field(
        ...,
        description="Deterministic immutable playbook-version identity.",
    )
    primary_action: ResponseActionType = Field(
        ...,
        description="The action the playbook orchestrates.",
    )
    failure_policy: SoarFailurePolicy = Field(
        ...,
        description="How a step failure propagates.",
    )
    enabled: bool = Field(
        ...,
        description="Whether the playbook may be executed.",
    )
    step_count: int = Field(
        ...,
        ge=1,
        le=SOAR_MAX_STEPS,
        description="Number of steps in the playbook.",
    )
    steps: list[SoarStep] = Field(
        ...,
        min_length=1,
        max_length=SOAR_MAX_STEPS,
        description="The declarative steps (mirrored from the version).",
    )
    created_at: datetime = Field(
        ...,
        description="Timezone-aware creation instant.",
    )
    updated_at: datetime = Field(
        ...,
        description="Timezone-aware last-modification instant.",
    )

    @field_validator("created_at", "updated_at")
    @classmethod
    def _ensure_timezone_aware(cls, v: datetime) -> datetime:
        return _ensure_tz_aware(v, "playbook timestamps")


class SoarPlaybookPage(BaseModel):
    """One 1-based page of registered playbooks."""

    items: list[SoarPlaybookRecord] = Field(
        ...,
        description="The page's playbooks.",
    )
    total: int = Field(
        ...,
        ge=0,
        description="Total number of registered playbooks.",
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


class SoarStepExecutionRecord(BaseModel):
    """Auditable outcome of one step within an execution."""

    model_config = ConfigDict(extra="forbid")

    step_execution_id: uuid.UUID = Field(
        ...,
        description="Deterministic step-execution identity.",
    )
    execution_id: uuid.UUID = Field(
        ...,
        description="The parent execution's domain identity.",
    )
    step_number: int = Field(
        ...,
        ge=1,
        description="1-based position within the playbook.",
    )
    label: str = Field(
        ...,
        max_length=SOAR_MAX_STEP_LABEL_LENGTH,
        description="The step's label.",
    )
    provider_id: str = Field(
        ...,
        max_length=SOAR_MAX_PROVIDER_ID_LENGTH,
        description="The registered provider adapter that ran the step.",
    )
    operation: ResponseActionType = Field(
        ...,
        description="The closed operation performed.",
    )
    target: str = Field(
        ...,
        max_length=SOAR_MAX_TARGET_LENGTH,
        description="The canonical target the step applied.",
    )
    status: SoarStepStatus = Field(
        ...,
        description="pending/running/succeeded/failed/skipped/timed_out/cancelled.",
    )
    retries_attempted: int = Field(
        default=0,
        ge=0,
        le=SOAR_MAX_RETRIES,
        description="How many retryable attempts occurred before the final one.",
    )
    error_code: str | None = Field(
        default=None,
        max_length=SOAR_MAX_ERROR_CODE_LENGTH,
        description="Sanitized failure/rejection code when applicable.",
    )
    message: str | None = Field(
        default=None,
        max_length=SOAR_MAX_MESSAGE_LENGTH,
        description="Sanitized, template-built message (never raw payloads).",
    )
    started_at: datetime | None = Field(
        default=None,
        description="Timezone-aware instant the step began (None if never run).",
    )
    completed_at: datetime | None = Field(
        default=None,
        description="Timezone-aware instant the step finished (None if never run).",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured, secret-free bookkeeping.",
    )

    @field_validator("started_at", "completed_at")
    @classmethod
    def _ensure_timezone_aware(cls, v: datetime | None) -> datetime | None:
        if v is None:
            return None
        return _ensure_tz_aware(v, "step timestamps")

    @field_validator("metadata")
    @classmethod
    def _ensure_metadata_valid(cls, v: dict[str, Any]) -> dict[str, Any]:
        _assert_json_compatible(v, "metadata")
        _assert_no_secrets(v, "metadata")
        return _ensure_metadata_bounded(v, "metadata")


class SoarExecutionRecord(BaseModel):
    """Auditable read model of one SOAR execution.

    ``simulated`` distinguishes a live sandbox run (``False``) from a
    validated dry-run projection (``True``) — a simulated record must never
    be presented as a real execution.
    """

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID = Field(
        ...,
        description="Persistence-row primary key (instrumentation only).",
    )
    execution_id: uuid.UUID = Field(
        ...,
        description="Deterministic domain identity of this execution.",
    )
    idempotency_key: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Deterministic content-derived idempotency key (hex).",
    )
    policy_decision_id: uuid.UUID = Field(
        ...,
        description="The authorizing Step 24 policy decision.",
    )
    correlation_id: uuid.UUID = Field(
        ...,
        description="The correlation the workflow concerns.",
    )
    approval_id: uuid.UUID | None = Field(
        default=None,
        description="The human approval grant consulted, when applicable.",
    )
    response_id: uuid.UUID = Field(
        ...,
        description="The Step 25 Response result this run builds upon.",
    )
    playbook_id: str = Field(
        ...,
        max_length=SOAR_MAX_PLAYBOOK_ID_LENGTH,
        description="The registered playbook that ran.",
    )
    playbook_version: str = Field(
        ...,
        max_length=SOAR_MAX_VERSION_LENGTH,
        description="The playbook version that ran.",
    )
    primary_action: ResponseActionType = Field(
        ...,
        description="The authorized action the playbook orchestrated.",
    )
    target: str = Field(
        ...,
        max_length=SOAR_MAX_TARGET_LENGTH,
        description="The canonical target inherited from the decision.",
    )
    status: SoarExecutionStatus = Field(
        ...,
        description="pending/running/succeeded/failed/partial/cancelled/rejected.",
    )
    failure_policy: SoarFailurePolicy = Field(
        ...,
        description="How a step failure propagates.",
    )
    simulated: bool = Field(
        ...,
        description=(
            "True for a validated dry-run projection (never a real run; "
            "no provider side effects).  False for a live sandbox run."
        ),
    )
    error_code: str | None = Field(
        default=None,
        max_length=SOAR_MAX_ERROR_CODE_LENGTH,
        description="Sanitized failure/rejection code when applicable.",
    )
    started_at: datetime | None = Field(
        default=None,
        description="Timezone-aware instant execution began (None when rejected).",
    )
    completed_at: datetime | None = Field(
        default=None,
        description="Timezone-aware instant execution finished.",
    )
    created_by: uuid.UUID = Field(
        ...,
        description="Trusted identity that requested the run.",
    )
    created_by_role: str = Field(
        ...,
        max_length=32,
        description="Role label of the requesting actor.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured, secret-free bookkeeping.",
    )
    steps: list[SoarStepExecutionRecord] = Field(
        default_factory=list,
        description="Ordered step-execution records (empty for a rejected run).",
    )
    created_at: datetime = Field(
        ...,
        description="Timezone-aware creation instant.",
    )
    updated_at: datetime = Field(
        ...,
        description="Timezone-aware last-modification instant.",
    )

    @field_validator("created_at", "updated_at", "started_at", "completed_at")
    @classmethod
    def _ensure_timezone_aware(cls, v: datetime | None) -> datetime | None:
        if v is None:
            return None
        return _ensure_tz_aware(v, "execution timestamps")

    @field_validator("metadata")
    @classmethod
    def _ensure_metadata_valid(cls, v: dict[str, Any]) -> dict[str, Any]:
        _assert_json_compatible(v, "metadata")
        _assert_no_secrets(v, "metadata")
        return _ensure_metadata_bounded(v, "metadata")


class SoarExecutionPage(BaseModel):
    """One 1-based page of SOAR executions."""

    items: list[SoarExecutionRecord] = Field(
        ...,
        description="The page's executions, newest first.",
    )
    total: int = Field(
        ...,
        ge=0,
        description="Total number of executions matching the query.",
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


# ---------------------------------------------------------------------------
# Dry-run (validation + simulation, zero side effects)
# ---------------------------------------------------------------------------


class SoarDryRunStepResult(BaseModel):
    """Projected outcome of one step in a dry-run.

    ``status`` is always ``succeeded`` for a validated step — the
    simulation asserts the step *would* run — and ``simulated`` is always
    True.  A dry-run never mutates provider state, never persists, and
    never produces a real execution.
    """

    model_config = ConfigDict(extra="forbid")

    step_execution_id: uuid.UUID = Field(
        ...,
        description="Deterministic projected step-execution identity.",
    )
    step_number: int = Field(
        ...,
        ge=1,
        description="1-based position within the playbook.",
    )
    label: str = Field(
        ...,
        max_length=SOAR_MAX_STEP_LABEL_LENGTH,
        description="The step's label.",
    )
    provider_id: str = Field(
        ...,
        max_length=SOAR_MAX_PROVIDER_ID_LENGTH,
        description="The provider that would run this step.",
    )
    operation: ResponseActionType = Field(
        ...,
        description="The closed operation that would be performed.",
    )
    target: str = Field(
        ...,
        max_length=SOAR_MAX_TARGET_LENGTH,
        description="The canonical target the step would apply.",
    )
    status: SoarStepStatus = Field(
        ...,
        description="Always succeeded for a validated simulated step.",
    )
    simulated: bool = Field(
        ...,
        description="Always True — this is a projection, never an action.",
    )
    message: str | None = Field(
        default=None,
        max_length=SOAR_MAX_MESSAGE_LENGTH,
        description="Sanitized wording of the projected provider behaviour.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured, secret-free projection bookkeeping.",
    )

    @field_validator("metadata")
    @classmethod
    def _ensure_metadata_valid(cls, v: dict[str, Any]) -> dict[str, Any]:
        _assert_json_compatible(v, "metadata")
        _assert_no_secrets(v, "metadata")
        return _ensure_metadata_bounded(v, "metadata")


class SoarDryRunResult(BaseModel):
    """Validated projection of what an execution *would* do.

    A dry-run confirms the playbook is registered and enabled, every
    provider resolves and supports its operation, every target validates,
    and then simulates the run deterministically.  No provider side
    effects occur and no execution row is persisted.
    """

    model_config = ConfigDict(extra="forbid")

    simulated: bool = Field(
        default=True,
        description="Always True — a dry-run is a projection, never a run.",
    )
    playbook_id: str = Field(
        ...,
        max_length=SOAR_MAX_PLAYBOOK_ID_LENGTH,
        description="The registered playbook that was simulated.",
    )
    playbook_version: str = Field(
        ...,
        max_length=SOAR_MAX_VERSION_LENGTH,
        description="The playbook version that was simulated.",
    )
    policy_decision_id: uuid.UUID = Field(
        ...,
        description="The authorizing decision under which it was simulated.",
    )
    correlation_id: uuid.UUID = Field(
        ...,
        description="The correlation the simulation concerned.",
    )
    response_id: uuid.UUID = Field(
        ...,
        description="The Step 25 response the run would build upon.",
    )
    approval_id: uuid.UUID | None = Field(
        default=None,
        description="The human approval grant the simulation consulted, if any.",
    )
    target: str = Field(
        ...,
        max_length=SOAR_MAX_TARGET_LENGTH,
        description="The canonical target the run would apply.",
    )
    status: SoarExecutionStatus = Field(
        ...,
        description="Projected outcome (succeeded when the simulation passes).",
    )
    error_code: str | None = Field(
        default=None,
        max_length=SOAR_MAX_ERROR_CODE_LENGTH,
        description="Sanitized reason when the validation/simulation failed.",
    )
    steps: list[SoarDryRunStepResult] = Field(
        default_factory=list,
        description="Projected step outcomes, in order.",
    )
    message: str = Field(
        ...,
        max_length=SOAR_MAX_MESSAGE_LENGTH,
        description="Sanitized summary of the projection.",
    )
    created_at: datetime = Field(
        ...,
        description="Timezone-aware instant the projection was produced.",
    )

    @field_validator("created_at")
    @classmethod
    def _ensure_timezone_aware(cls, v: datetime) -> datetime:
        return _ensure_tz_aware(v, "dry-run timestamp")


__all__ = [
    "SOAR_CURRENT_SCHEMA_VERSION",
    "SOAR_MAX_DESCRIPTION_LENGTH",
    "SOAR_MAX_ERROR_CODE_LENGTH",
    "SOAR_MAX_MESSAGE_LENGTH",
    "SOAR_MAX_METADATA_DEPTH",
    "SOAR_MAX_METADATA_SERIALIZED_BYTES",
    "SOAR_MAX_PLAYBOOK_DEFINITION_BYTES",
    "SOAR_MAX_PLAYBOOK_ID_LENGTH",
    "SOAR_MAX_PLAYBOOK_NAME_LENGTH",
    "SOAR_MAX_PROCESSED_KEYS",
    "SOAR_MAX_PROVIDER_ID_LENGTH",
    "SOAR_MAX_RETRIES",
    "SOAR_MAX_SCHEMA_VERSION_LENGTH",
    "SOAR_MAX_STEP_LABEL_LENGTH",
    "SOAR_MAX_STEPS",
    "SOAR_MAX_TARGET_LENGTH",
    "SOAR_MAX_TIMEOUT_SECONDS",
    "SOAR_MAX_VERSION_LENGTH",
    "SOAR_MIN_TIMEOUT_SECONDS",
    "SOAR_NAMESPACE",
    "SOAR_PLAYBOOK_INITIAL_VERSION",
    "SOAR_RETRYABLE_CATEGORIES",
    "PolicyDecisionStatus",
    "ResponseActionType",
    "SoarDryRunResult",
    "SoarDryRunStepResult",
    "SoarExecutionPage",
    "SoarExecutionRecord",
    "SoarExecutionRequest",
    "SoarExecutionStatus",
    "SoarFailureCategory",
    "SoarFailurePolicy",
    "SoarPlaybookDefinition",
    "SoarPlaybookPage",
    "SoarPlaybookRecord",
    "SoarPlaybookValidator",
    "SoarProviderType",
    "SoarStep",
    "SoarStepExecutionRecord",
    "SoarStepStatus",
]