"""Policy Decision Domain Contract — Step 24.

Defines the foundational **domain contract** for the Version 1 Policy
Decision layer: the validated Pydantic representation of a *proposed*
security response action, the structured input the deterministic policy
engine evaluates, the declarative policy rules it applies, and the
auditable decision it produces.

Detection answers *"what matched?"*, correlation answers *"what is
related?"*, risk answers *"how dangerous?"*, investigation/attribution
answers *"what happened and who may be responsible?"*.  Policy Decision
answers a different question: *"may this **proposed** response action
proceed — and if so, under which rule, with what explanation?"*  This
module defines the objects the deterministic Policy Decision Engine will
consume and produce.  It **does not answer the question** — it contains
no evaluation logic, no thresholds, no rules, no action execution, no
network/DB access, and no LLM.

Design principles:

* **Contract only** — no policy engine, no rule table, no evaluation, no
  thresholds, no response execution, no SOAR, no persistence, no API, no
  message bus, no LLM.  The Step 24 service layer evaluates these
  contracts deterministically.
* **Closed action vocabulary** — :class:`ResponseActionType` is a fixed
  six-member enumeration.  There is no "custom" action, no free-form
  command, no function/method name, no SQL, and no shell string anywhere
  in this contract; an unknown action type is rejected at validation.
* **Structured input only** — :class:`PolicyInput` carries only typed,
  bounded evaluation context (identifiers, controlled levels, bounded
  scores, availability flags, references).  It never accepts raw natural
  language, user-supplied policy code, Python expressions, SQL, or
  function names.
* **Declarative rules** — :class:`PolicyRule` is pure data (thresholds,
  booleans, priorities, description).  It stores no executable code and
  no expressions; the engine's gates are fixed, auditable code, never
  rule-supplied logic.
* **Provenance-aware** — a policy decision is a derived conclusion and
  carries the additive ``Provenance.POLICY_DECIDED`` value.  It is never
  labelled observed / enriched / reconstructed / detected / correlated /
  risk_assessed / ai_generated / attribution_assessed / recalled /
  learned.
* **Evidence references, never fabrications** — :class:`PolicyEvidence`
  only *references* legitimate existing identifiers (correlation,
  detection, risk assessment, investigation, attribution, incident
  memory) with the *original* ``source_provenance`` of the referenced
  item preserved verbatim.  The engine never invents identifiers and
  never rewrites provenance; a recalled memory reference stays
  ``recalled`` and is never turned into current evidence, and an
  investigation reference is never silently upgraded to
  ``ai_generated`` policy evidence.
* **Structured & secret-safe** — metadata and evidence are strict
  JSON-compatible payloads that reject credential-shaped content
  (mirroring the Step 10A / 11A contract boundary).
* **Deterministic & non-mutating** — the contract generates no decision,
  no reason, and no identity derivation; it never mutates its inputs and
  clones caller-owned payloads so downstream objects never alias caller
  state.

Relationship to the pipeline::

    RiskAssessment / Investigation / Attribution   (existing outputs)
        -> PolicyInput                              (Step 24 — this module)
            -> PolicyDecisionEngine                 (Step 24 service layer)
                -> PolicyDecision                   (Step 24 — this module)
                    -> [Future Response & Mitigation layer — NOT this step]

``Policy Decision != Response Execution``: this contract describes a
decision record only.  Nothing here executes an action, contacts a host,
blocks traffic, disables an account, or calls an external system.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.risk import RiskLevel
from app.schemas.security_event import Provenance
from app.schemas.threat_attribution import AttributionStatus


# ---------------------------------------------------------------------------
# Bounds & constants (single source of truth, documented)
# ---------------------------------------------------------------------------

#: Maximum number of structured evidence references a policy input or
#: decision may carry.  Bounds the contract; rejects rather than truncates.
POLICY_MAX_EVIDENCE_REFERENCES = 16

#: Maximum length of an evidence ``role`` label.
POLICY_MAX_ROLE_LENGTH = 64

#: Maximum length of a ``policy_rule_id``.
POLICY_MAX_RULE_ID_LENGTH = 64

#: Bounds on client- and engine-supplied ``metadata`` dictionaries so a
#: single decision can never carry an unbounded nested/oversized blob into
#: the stored record (mirror of the SOAR metadata depth bound).
POLICY_MAX_METADATA_DEPTH = 4

POLICY_MAX_METADATA_SERIALIZED_BYTES = 65536

#: Deterministic identity namespace for engine-produced decision ids.
#: Fixed so identical (input, clock, rules) tuples always derive the same
#: ``policy_decision_id``; the engine never uses randomness for identity.
POLICY_DECISION_NAMESPACE = uuid.UUID(
    "6f1e0f4a-2c41-4a4d-9f0b-1d2e3a4b5c6d"
)

#: Credential-shaped strings re-checked at this boundary (mirror Step 11A).
_SECRET_PATTERNS = ("api_key", "authorization", "bearer", "secret")

#: ``policy_rule_id`` shape: uppercase token groups joined by hyphens,
#: e.g. ``POLICY-BLOCK-IP-001``.  Pure data; never parsed as code.
_RULE_ID_PATTERN = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*$")


def risk_rank(level: RiskLevel) -> int:
    """Ordinal rank of a :class:`RiskLevel` for threshold comparisons.

    Deterministic total order: ``low(0) < medium(1) < high(2) <
    critical(3)``.  Used by the rule-conflict validator and the engine's
    risk-floor gate; the contract itself never scores anything.
    """
    return {
        RiskLevel.LOW: 0,
        RiskLevel.MEDIUM: 1,
        RiskLevel.HIGH: 2,
        RiskLevel.CRITICAL: 3,
    }[level]


# ---------------------------------------------------------------------------
# Secret-safety helpers (mirror the Step 9A / 10A / 11A contract patterns)
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


def _ensure_metadata_bounded(value: dict[str, Any], field: str) -> dict[str, Any]:
    """Reject metadata that exceeds the depth or serialized-size bounds."""

    def depth(item: Any, current: int) -> int:
        if current > POLICY_MAX_METADATA_DEPTH:
            return current
        if isinstance(item, dict):
            return max((depth(v, current + 1) for v in item.values()), default=current)
        if isinstance(item, list):
            return max((depth(v, current + 1) for v in item), default=current)
        return current

    if depth(value, 0) > POLICY_MAX_METADATA_DEPTH:
        raise ValueError(
            f"{field} must not exceed {POLICY_MAX_METADATA_DEPTH} levels of nesting"
        )
    if len(json.dumps(value)) > POLICY_MAX_METADATA_SERIALIZED_BYTES:
        raise ValueError(
            f"{field} must not exceed "
            f"{POLICY_MAX_METADATA_SERIALIZED_BYTES} serialized bytes"
        )
    return value


def _ensure_tz_aware(value: datetime, field: str) -> datetime:
    """Reject naive (timezone-unaware) timestamps."""
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(
            f"{field} must be timezone-aware; naive timestamps are not accepted"
        )
    return value


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class PolicyDecisionStatus(str, Enum):
    """The three possible outcomes of a policy evaluation.

    * ``allowed`` — every applicable rule's conditions passed; the action
      is permitted **by policy** (this step still never executes it).
    * ``denied`` — at least one required condition failed; the action is
      not permitted.
    * ``requires_approval`` — conditions passed but the rule (or an
      elevated risk level) demands explicit human authorization before
      any future response layer may act.
    """

    ALLOWED = "allowed"
    DENIED = "denied"
    REQUIRES_APPROVAL = "requires_approval"


class ResponseActionType(str, Enum):
    """Closed vocabulary of proposed response actions the policy can judge.

    Deliberately fixed: no arbitrary action type can be introduced by any
    caller, rule, or model output.  An unsupported value is rejected at
    validation (it never reaches the engine).
    """

    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    QUARANTINE_FILE = "quarantine_file"
    DISABLE_ACCOUNT = "disable_account"
    TERMINATE_SESSION = "terminate_session"
    ISOLATE_ENDPOINT = "isolate_endpoint"


class PolicyEvidenceType(str, Enum):
    """Which existing subsystem a policy evidence reference points at.

    Only legitimate existing identity domains are allowed; policy
    evidence is always a *reference* into them, never an embedded or
    fabricated record.
    """

    CORRELATION = "correlation"
    DETECTION = "detection"
    RISK_ASSESSMENT = "risk_assessment"
    INVESTIGATION = "investigation"
    ATTRIBUTION = "attribution"
    INCIDENT_MEMORY = "incident_memory"


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


class PolicyEvidence(BaseModel):
    """One structured *reference* supporting a policy evaluation.

    An evidence item never invents an identifier: ``reference_id`` must
    be the UUID of an existing correlation / detection / risk assessment
    / investigation / attribution / incident memory the caller actually
    has.  ``source_provenance`` preserves the *original* provenance of
    the referenced item verbatim (e.g. ``recalled`` for a historical
    incident memory, ``risk_assessed`` for a risk assessment); the policy
    layer never rewrites it and never stamps its own provenance onto
    evidence.
    """

    model_config = ConfigDict(extra="forbid")

    evidence_type: PolicyEvidenceType = Field(
        ...,
        description=(
            "Which existing subsystem the reference points at.  Closed "
            "vocabulary — never a free-form label."
        ),
    )
    reference_id: uuid.UUID = Field(
        ...,
        description=(
            "UUID of the existing referenced item (a legitimate existing "
            "identifier — never fabricated by the policy layer)."
        ),
    )
    role: str = Field(
        ...,
        min_length=1,
        max_length=POLICY_MAX_ROLE_LENGTH,
        description=(
            "Structured, machine-readable role of this reference in the "
            "decision, e.g. 'primary_correlation', 'supporting_risk'.  "
            "Not free-form prose."
        ),
    )
    source_provenance: Provenance | None = Field(
        default=None,
        description=(
            "The referenced item's ORIGINAL provenance, preserved "
            "verbatim when known.  None when the caller does not supply "
            "it.  Never rewritten by the policy layer; policy decisions "
            "are never evidence and evidence is never relabelled as "
            "policy decisions."
        ),
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Structured, JSON-compatible, secret-free bookkeeping about "
            "this reference."
        ),
    )

    @field_validator("role")
    @classmethod
    def _ensure_role_not_blank(cls, v: str) -> str:
        return _require_non_blank(v, "role")

    @field_validator("metadata")
    @classmethod
    def _ensure_metadata_valid(cls, v: dict[str, Any]) -> dict[str, Any]:
        _assert_json_compatible(v, "evidence metadata")
        _assert_no_secrets(v, "evidence metadata")
        return _ensure_metadata_bounded(_json_clone(v), "evidence metadata")


# ---------------------------------------------------------------------------
# Policy input
# ---------------------------------------------------------------------------


class PolicyInput(BaseModel):
    """Structured, deterministic evaluation context for the policy engine.

    Carries only what a rule evaluation needs: the correlation under
    consideration, the proposed action, controlled risk level, bounded
    optional scores, optional investigation/attribution context,
    evidence *availability*, optional concrete evidence references,
    bookkeeping metadata, and a timestamp.

    Explicitly **not** accepted here: raw natural language, policy code,
    Python expressions, SQL, function/method names, shell strings, or
    any free-form instruction.  The contract rejects unknown fields
    (``extra='forbid'``) so no hidden channel can reach the engine.
    """

    model_config = ConfigDict(extra="forbid")

    correlation_id: uuid.UUID = Field(
        ...,
        description=(
            "The correlation this decision concerns (a reference — the "
            "correlation subsystem stays authoritative; no correlation "
            "object is embedded)."
        ),
    )
    requested_action: ResponseActionType = Field(
        ...,
        description=(
            "The proposed response action being judged.  Closed "
            "enumeration; unsupported action types are rejected."
        ),
    )
    risk_level: RiskLevel = Field(
        ...,
        description=(
            "Current assessed risk level of the correlated situation "
            "(from the existing Risk Assessment layer)."
        ),
    )
    risk_score: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "Optional normalized risk score in [0.0, 1.0] when "
            "available.  Carried for explanation; never calculated here."
        ),
    )
    confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "Optional investigation/assessment confidence in [0.0, 1.0] "
            "when available.  None means 'unavailable' and fails any "
            "confidence gate (fail-closed) rather than being treated as "
            "a passing value."
        ),
    )
    attribution_status: AttributionStatus | None = Field(
        default=None,
        description=(
            "Optional threat-attribution status when an attribution "
            "assessment has been performed.  None means no attribution "
            "context is available."
        ),
    )
    investigation_available: bool = Field(
        default=False,
        description=(
            "Whether an AI investigation result is available as context "
            "for this evaluation (a structured availability flag — never "
            "the investigation text itself)."
        ),
    )
    evidence_available: bool = Field(
        default=False,
        description=(
            "Whether legitimate supporting evidence exists for this "
            "situation.  The evidence gate denies actions when this is "
            "False under a rule that requires evidence."
        ),
    )
    evidence_references: list[PolicyEvidence] = Field(
        default_factory=list,
        description=(
            "Optional concrete references to existing items supporting "
            "the evaluation.  Bounded; caller-supplied only — the policy "
            "layer never fabricates entries."
        ),
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Structured, JSON-compatible, secret-free context required "
            "by policy bookkeeping.  Never executed or interpreted."
        ),
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description=(
            "Timezone-aware instant this input was captured.  "
            "Descriptive bookkeeping, not evidence."
        ),
    )

    @field_validator("timestamp")
    @classmethod
    def _ensure_timezone_aware(cls, v: datetime) -> datetime:
        return _ensure_tz_aware(v, "timestamp")

    @field_validator("metadata")
    @classmethod
    def _ensure_metadata_valid(cls, v: dict[str, Any]) -> dict[str, Any]:
        _assert_json_compatible(v, "metadata")
        _assert_no_secrets(v, "metadata")
        return _ensure_metadata_bounded(_json_clone(v), "metadata")

    @field_validator("evidence_references")
    @classmethod
    def _ensure_evidence_valid(
        cls, v: list[PolicyEvidence]
    ) -> list[PolicyEvidence]:
        if len(v) > POLICY_MAX_EVIDENCE_REFERENCES:
            raise ValueError(
                "evidence_references must not exceed "
                f"{POLICY_MAX_EVIDENCE_REFERENCES} items"
            )
        _assert_no_secrets(
            [item.model_dump(mode="json") for item in v],
            "evidence_references",
        )
        return list(v)


# ---------------------------------------------------------------------------
# Policy rule
# ---------------------------------------------------------------------------


class PolicyRule(BaseModel):
    """One declarative, executable-code-free policy rule.

    A rule is pure data: identity, scope, thresholds, boolean
    requirements, approval behaviour, priority, and description.  It
    stores no expressions, no code, no callables, and no function names;
    the engine evaluates it through fixed, auditable gates.

    Threshold semantics (each optional threshold is a floor the input
    must meet for the rule to be *applicable*):

    * ``minimum_risk_level`` — input ``risk_level`` must be at or above
      this rank (``low < medium < high < critical``).
    * ``minimum_confidence`` — input ``confidence`` must be present and
      at or above this value; ``None`` confidence fails (fail-closed).
    * ``require_evidence`` — input ``evidence_available`` must be True.
    * ``require_investigation`` — input ``investigation_available`` must
      be True.
    * ``require_attribution`` — input ``attribution_status`` must be
      present and supported (``attributed`` / ``partially_supported``).

    Decision behaviour when all thresholds pass:

    * ``requires_approval=True`` -> ``REQUIRES_APPROVAL``.
    * ``approval_above_risk_level`` set and input risk at/above it ->
      ``REQUIRES_APPROVAL`` (elevated-risk escalation).
    * otherwise -> ``ALLOWED``.
    """

    model_config = ConfigDict(extra="forbid")

    policy_rule_id: str = Field(
        ...,
        min_length=3,
        max_length=POLICY_MAX_RULE_ID_LENGTH,
        pattern=_RULE_ID_PATTERN,
        description=(
            "Stable, human-readable rule identity, e.g. "
            "'POLICY-BLOCK-IP-001'.  Pure data — never executed."
        ),
    )
    action_type: ResponseActionType | None = Field(
        default=None,
        description=(
            "Which proposed action this rule governs; None means the "
            "rule applies to every action (cross-cutting rules are not "
            "used by the default policy but are supported by the "
            "engine)."
        ),
    )
    minimum_risk_level: RiskLevel = Field(
        ...,
        description="Minimum risk level at or above which this rule applies."
    )
    minimum_confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "Minimum confidence in [0.0, 1.0] required for this rule to "
            "apply; None means no confidence requirement."
        ),
    )
    require_evidence: bool = Field(
        default=True,
        description="Whether evidence availability is required (fail-closed default)."
    )
    require_investigation: bool = Field(
        default=False,
        description="Whether an AI investigation result must be available."
    )
    require_attribution: bool = Field(
        default=False,
        description="Whether a supported attribution status must be present."
    )
    requires_approval: bool = Field(
        default=False,
        description=(
            "Whether this rule, when it applies, always demands human "
            "authorization before any future response layer may act."
        ),
    )
    approval_above_risk_level: RiskLevel | None = Field(
        default=None,
        description=(
            "Optional elevated-risk escalation: when set, an otherwise "
            "allowable decision becomes REQUIRES_APPROVAL at or above "
            "this risk level."
        ),
    )
    enabled: bool = Field(
        default=True,
        description="Disabled rules are ignored by the engine (kept for audit)."
    )
    priority: int = Field(
        ...,
        ge=0,
        description=(
            "Deterministic precedence: lower value evaluates first.  "
            "Ties break on policy_rule_id (ascending)."
        ),
    )
    description: str = Field(
        ...,
        min_length=1,
        max_length=500,
        description="Human-readable statement of the rule's exact semantics."
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="JSON-compatible, secret-free rule bookkeeping."
    )

    @field_validator("description")
    @classmethod
    def _ensure_description_not_blank(cls, v: str) -> str:
        return _require_non_blank(v, "description")

    @field_validator("approval_above_risk_level")
    @classmethod
    def _ensure_escalation_consistent(
        cls,
        v: RiskLevel | None,
        info: Any,
    ) -> RiskLevel | None:
        """Reject conflicting configuration: escalation below the floor.

        An escalation threshold below ``minimum_risk_level`` could never
        fire after the risk-floor gate (the rule would be inapplicable
        first), so the configuration is contradictory and is rejected
        rather than silently tolerated.
        """
        minimum = info.data.get("minimum_risk_level")
        if v is not None and minimum is not None and risk_rank(v) < risk_rank(minimum):
            raise ValueError(
                "approval_above_risk_level must be at or above "
                "minimum_risk_level (conflicting rule configuration)"
            )
        return v

    @field_validator("metadata")
    @classmethod
    def _ensure_metadata_valid(cls, v: dict[str, Any]) -> dict[str, Any]:
        _assert_json_compatible(v, "metadata")
        _assert_no_secrets(v, "metadata")
        return _json_clone(v)


# ---------------------------------------------------------------------------
# Policy decision
# ---------------------------------------------------------------------------


class PolicyDecision(BaseModel):
    """The auditable output of one deterministic policy evaluation.

    Records *what* was requested, *which* rule decided, *why* (a
    deterministic structured reason — never free-form AI text), the
    relevant risk/confidence context, the preserved evidence references,
    a structured evaluation trace in ``metadata``, and the additive
    ``POLICY_DECIDED`` provenance.

    This is a decision record only: constructing or returning one never
    executes the requested action.
    """

    model_config = ConfigDict(extra="forbid")

    policy_decision_id: uuid.UUID = Field(
        ...,
        description=(
            "Stable identity of this decision.  The engine derives it "
            "deterministically (UUIDv5) from the decision content and "
            "clock so identical evaluations produce identical ids."
        ),
    )
    correlation_id: uuid.UUID = Field(
        ...,
        description="The correlation this decision concerns (reference only)."
    )
    requested_action: ResponseActionType = Field(
        ...,
        description="The proposed action that was judged."
    )
    decision: PolicyDecisionStatus = Field(
        ...,
        description="ALLOWED / DENIED / REQUIRES_APPROVAL."
    )
    reason: str = Field(
        ...,
        min_length=1,
        max_length=500,
        description=(
            "Deterministic, template-built explanation naming the rule "
            "and the deciding condition.  Never LLM-generated."
        ),
    )
    policy_rule_id: str = Field(
        ...,
        min_length=3,
        max_length=POLICY_MAX_RULE_ID_LENGTH,
        description=(
            "The rule that decided (or, for no-coverage denial, the "
            "documented sentinel 'POLICY-NO-COVERAGE')."
        ),
    )
    risk_level: RiskLevel = Field(
        ...,
        description="Risk level carried from the evaluated input."
    )
    risk_score: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Risk score carried from the input when available."
    )
    confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Confidence carried from the input when available."
    )
    requires_approval: bool = Field(
        ...,
        description=(
            "True exactly when decision is REQUIRES_APPROVAL — a "
            "decision attribute, never an execution signal."
        ),
    )
    evidence: list[PolicyEvidence] = Field(
        default_factory=list,
        description=(
            "Preserved references from the input (cloned, never "
            "fabricated, never rewritten)."
        ),
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Deterministic structured evaluation trace: policy name, "
            "caller context (cloned), candidate rule ids, gate results, "
            "and decision path.  JSON-compatible and secret-free."
        ),
    )
    timestamp: datetime = Field(
        ...,
        description="Timezone-aware instant the decision was produced."
    )
    provenance: Provenance = Field(
        default=Provenance.POLICY_DECIDED,
        description=(
            "Always POLICY_DECIDED — a policy decision is never observed "
            "telemetry, a detection, correlation, risk assessment, AI "
            "investigation, attribution, recalled memory, or learned "
            "pattern."
        ),
    )

    @field_validator("timestamp")
    @classmethod
    def _ensure_timezone_aware(cls, v: datetime) -> datetime:
        return _ensure_tz_aware(v, "timestamp")

    @field_validator("provenance")
    @classmethod
    def _ensure_policy_provenance(cls, v: Provenance) -> Provenance:
        """Pin policy decisions to POLICY_DECIDED (mirror Step 11A)."""
        if v is not Provenance.POLICY_DECIDED:
            raise ValueError(
                "policy decisions must carry POLICY_DECIDED provenance; "
                f"got {v.value!r}"
            )
        return v

    @field_validator("metadata")
    @classmethod
    def _ensure_metadata_valid(cls, v: dict[str, Any]) -> dict[str, Any]:
        _assert_json_compatible(v, "metadata")
        _assert_no_secrets(v, "metadata")
        return _ensure_metadata_bounded(_json_clone(v), "metadata")

    @field_validator("evidence")
    @classmethod
    def _ensure_evidence_valid(
        cls, v: list[PolicyEvidence]
    ) -> list[PolicyEvidence]:
        if len(v) > POLICY_MAX_EVIDENCE_REFERENCES:
            raise ValueError(
                "evidence must not exceed "
                f"{POLICY_MAX_EVIDENCE_REFERENCES} items"
            )
        _assert_no_secrets(
            [item.model_dump(mode="json") for item in v],
            "evidence",
        )
        return list(v)

    @field_validator("reason")
    @classmethod
    def _ensure_reason_not_blank(cls, v: str) -> str:
        return _require_non_blank(v, "reason")


__all__ = [
    "POLICY_DECISION_NAMESPACE",
    "POLICY_MAX_EVIDENCE_REFERENCES",
    "POLICY_MAX_ROLE_LENGTH",
    "POLICY_MAX_RULE_ID_LENGTH",
    "POLICY_MAX_METADATA_DEPTH",
    "POLICY_MAX_METADATA_SERIALIZED_BYTES",
    "PolicyDecision",
    "PolicyDecisionStatus",
    "PolicyEvidence",
    "PolicyEvidenceType",
    "PolicyInput",
    "PolicyRule",
    "ResponseActionType",
    "risk_rank",
]
