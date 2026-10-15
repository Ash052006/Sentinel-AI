"""Frozen vocabulary for AI playbook generation — V3.25.

This module is the single source of truth for every closed vocabulary, bound,
capability claim, and identity derivation used by V3.25.  Nothing here talks to
a database, a clock or a network, and nothing accepts a caller-supplied string
as an action or a target.

Three design commitments are encoded structurally rather than described in
prose:

**1. A proposed action is not a thing that happened.**
Every generated artifact is pinned to ``ai_generated`` provenance, and the
lifecycle vocabulary in this module contains the post-generation states
(``APPROVED`` … ``VERIFIED``) purely so that
:data:`GENERATED_LIFECYCLES` can exclude them.  The generator can therefore
never emit ``EXECUTING``, ``EXECUTED`` or ``VERIFIED`` — not by convention, but
because those values are not reachable from the only field the generator fills.

**2. Capability is claimed, never assumed.**
SentinelAI's entire response layer is a set of sandbox/mock adapters.  The only
response actions any provider can actually act on are the six members of
``app.schemas.policy_decision.ResponseActionType``, and even those resolve to
simulation.  :data:`ACTION_CAPABILITIES` records that truth per action, and the
invariant ``capability == UNAVAILABLE`` ⟺ ``approval == NOT_EXECUTABLE`` is
enforced by the contract.  An action with no provider behind it is reported as
unavailable rather than dressed up as executable.

**3. Nothing is invented to fill a gap.**
There is no ATT&CK catalog, no successor table, no technique taxonomy and no
free-form target language.  A target exists only if a persisted row supplied
one and it passed structural validation; otherwise the run reports
``INSUFFICIENT_EVIDENCE``.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.policy_decision import ResponseActionType

#: Engine version.  Part of the configuration digest, so upgrading the engine
#: yields a new playbook identity instead of mutating a recorded proposal.
ENGINE_VERSION: Final[str] = "v3.25.0"

#: Stable namespaces for content-derived identities.  Fixed constants: changing
#: one would silently re-key every stored playbook.
PLAYBOOK_NAMESPACE: Final[uuid.UUID] = uuid.UUID("6f1d0c2a-7b3e-5d84-9f21-0c4a8e5b1d77")
PLAYBOOK_ROW_NAMESPACE: Final[uuid.UUID] = uuid.UUID(
    "b2c4e6a8-1d3f-4a5b-8c7d-9e0f1a2b3c4d"
)


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


class PlaybookLifecycle(str, Enum):
    """Full playbook lifecycle.

    V3.25 **generates** only the first two generated states.  The remaining
    states exist because the vocabulary must describe where a playbook can go
    next, and because downstream systems already own those transitions.
    """

    DRAFT = "draft"
    PROPOSED = "proposed"
    APPROVAL_REQUIRED = "approval_required"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    EXECUTED = "executed"
    VERIFICATION_REQUIRED = "verification_required"
    VERIFIED = "verified"
    FAILED = "failed"
    CANCELLED = "cancelled"


#: The only lifecycle values generation may produce.
#:
#: This is the enforcement point for "PROPOSED ≠ APPROVED ≠ EXECUTED ≠
#: VERIFIED".  A playbook that needs human authorization before anything may act
#: on it starts at ``APPROVAL_REQUIRED``; one that does not starts at
#: ``PROPOSED``.  Neither state grants permission — the Policy Decision Engine
#: and the HITL approval service remain authoritative for that.
GENERATED_LIFECYCLES: Final[frozenset[PlaybookLifecycle]] = frozenset(
    {
        PlaybookLifecycle.PROPOSED,
        PlaybookLifecycle.APPROVAL_REQUIRED,
    }
)

#: Lifecycle values that describe work someone other than the generator performed.
#: Rejected from any generated playbook.
DOWNSTREAM_ONLY_LIFECYCLES: Final[frozenset[PlaybookLifecycle]] = frozenset(
    {
        PlaybookLifecycle.APPROVED,
        PlaybookLifecycle.REJECTED,
        PlaybookLifecycle.EXECUTING,
        PlaybookLifecycle.EXECUTED,
        PlaybookLifecycle.VERIFICATION_REQUIRED,
        PlaybookLifecycle.VERIFIED,
        PlaybookLifecycle.FAILED,
        PlaybookLifecycle.CANCELLED,
        PlaybookLifecycle.DRAFT,
    }
)


class PlaybookStatus(str, Enum):
    """Session-level outcome of a generation run.

    ``INSUFFICIENT_EVIDENCE`` is a **success**.  Declining to propose a response
    is the correct outcome when no persisted source identifies a bounded target,
    and forcing an action merely to return something would be worse than
    returning nothing.
    """

    PROPOSED = "proposed"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    CONTESTED = "contested"


class ActionPriority(str, Enum):
    """Bounded, ordered action priority.

    Deliberately *not* the V2 risk score.  A high-risk incident does not imply a
    fast containment action, and copying the risk score would make priority a
    restatement of severity rather than a response judgement.
    """

    IMMEDIATE = "immediate"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


#: Ascending urgency.  Used for deterministic sort keys only.
PRIORITY_ORDER: Final[dict[ActionPriority, int]] = {
    ActionPriority.IMMEDIATE: 0,
    ActionPriority.HIGH: 1,
    ActionPriority.MEDIUM: 2,
    ActionPriority.LOW: 3,
}


class ActionCategory(str, Enum):
    """What kind of response work an action represents."""

    INVESTIGATION = "investigation"
    CONTAINMENT = "containment"
    PREVENTION = "prevention"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    VERIFICATION = "verification"


class ApprovalRequirement(str, Enum):
    """How an action relates to human authorization.

    * ``NO_APPROVAL`` — policy does not demand human authorization for this
      action class.  It is **not** a grant of permission: the Policy Decision
      Engine still evaluates every action independently.
    * ``APPROVAL_REQUIRED`` — a human must authorize before any response layer
      may act.  V3.25 recommends that requirement; it never satisfies it.
    * ``NOT_EXECUTABLE`` — SentinelAI has no execution provider for this
      capability.  Approval is moot: nothing can act on this proposal today.
    """

    NO_APPROVAL = "no_approval"
    APPROVAL_REQUIRED = "approval_required"
    NOT_EXECUTABLE = "not_executable"


class GroundingBasis(str, Enum):
    """What justifies an action.

    Rendered explicitly in the UI so a reader can see at a glance whether a
    proposal rests on something that happened, on something that may happen, or
    on both.
    """

    ESTABLISHED_EVIDENCE = "established_evidence"
    PREDICTION_SUPPORTED = "prediction_supported"
    BOTH = "both"


class EvidenceSource(str, Enum):
    """Which existing subsystem an evidence reference points at.

    Every value names a subsystem that genuinely exists.  A reference is always
    a pointer into one of them — never an embedded or fabricated record.
    """

    EVENT = "event"
    DETECTION = "detection"
    CORRELATION = "correlation"
    RISK_ASSESSMENT = "risk_assessment"
    INVESTIGATION = "investigation"
    THREAT_INTELLIGENCE = "threat_intelligence"
    INCIDENT_MEMORY = "incident_memory"
    ATTACK_PATH = "attack_path"
    DEBATE_CLAIM = "debate_claim"
    PREDICTION = "prediction"


class CapabilityStatus(str, Enum):
    """Whether SentinelAI can act on an action at all."""

    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"


class ExecutionBackend(str, Enum):
    """What would actually run if the action were ever approved and executed.

    ``MOCK_SANDBOX`` is the honest answer for every available capability in this
    release: the response and SOAR providers are simulation adapters, so even a
    fully approved ``BLOCK_IP`` would not filter a single packet.  The UI must be
    able to say so.
    """

    MOCK_SANDBOX = "mock_sandbox"
    NONE = "none"


class TargetType(str, Enum):
    """Closed target vocabulary.

    A free-form destructive target is not representable.  ``NETWORK`` and
    ``CORRELATION``/``INCIDENT`` are included because they name *scope* for
    investigation and verification actions, never a destructive scope: see
    :data:`NON_DESTRUCTIVE_ONLY_TARGETS`.
    """

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE = "file"
    PROCESS = "process"
    ENDPOINT = "endpoint"
    USER = "user"
    ACCOUNT = "account"
    TOKEN = "token"
    CREDENTIAL = "credential"
    NETWORK = "network"
    CORRELATION = "correlation"
    INCIDENT = "incident"


#: Target types that may only be attached to non-destructive actions.
#:
#: ``NETWORK`` exists so an analyst can scope an investigation, and
#: ``CORRELATION``/``INCIDENT`` so a verification step can name what it verifies.
#: None of them may address a containment, prevention, eradication or recovery
#: action — that is exactly how "block the entire network" slips into a system.
NON_DESTRUCTIVE_ONLY_TARGETS: Final[frozenset[TargetType]] = frozenset(
    {
        TargetType.NETWORK,
        TargetType.CORRELATION,
        TargetType.INCIDENT,
    }
)


class DependencyKind(str, Enum):
    """Why one action must follow another."""

    #: Evidence must be captured before the system state that produced it is
    #: destroyed.  The single most important ordering rule in containment.
    EVIDENCE_FIRST = "evidence_first"
    #: Containment must complete before its effect can be verified.
    CONTAINMENT_BEFORE_VERIFICATION = "containment_before_verification"
    #: Credential/session containment depends on knowing the credential exists.
    TARGET_DISCOVERY = "target_discovery"


class PlaybookLimitationKind(str, Enum):
    """Closed vocabulary of why a playbook is limited."""

    NO_RESOLVABLE_TARGET = "no_resolvable_target"
    NO_ESTABLISHED_EVIDENCE = "no_established_evidence"
    CAPABILITY_UNAVAILABLE = "capability_unavailable"
    CAPABILITY_SIMULATED_ONLY = "capability_simulated_only"
    DEBATE_ABSENT = "debate_absent"
    DEBATE_PARTIAL_CONSENSUS = "debate_partial_consensus"
    DEBATE_CONTESTED = "debate_contested"
    DEBATE_GRAPH_SNAPSHOT_MISMATCH = "debate_graph_snapshot_mismatch"
    PREDICTION_ABSENT = "prediction_absent"
    PREDICTION_INSUFFICIENT = "prediction_insufficient"
    CONTAINMENT_LIMITED_TO_EVIDENCE = "containment_limited_to_evidence"
    HORIZON_CAPPED = "horizon_capped"
    GRAPH_TRUNCATED = "graph_truncated"
    INPUT_SOURCE_UNAVAILABLE = "input_source_unavailable"
    NO_ATTACK_MAPPING = "no_attack_mapping"
    UNTRUSTED_CONTENT_QUARANTINED = "untrusted_content_quarantined"
    MODEL_CANDIDATES_REJECTED = "model_candidates_rejected"
    NO_ROLLBACK_AVAILABLE = "no_rollback_available"


class PlaybookConfidenceComponent(str, Enum):
    """Deterministic confidence components for a proposed action.

    The five weighted components are what *raise* confidence; the two penalty
    components are what *lower* it.  Both appear in the breakdown so a reported
    number is always fully reconstructible from the record — a confidence that
    cannot be recomputed from its own basis is not auditable.
    """

    EVIDENCE_SUPPORT = "evidence_support"
    TARGET_CERTAINTY = "target_certainty"
    PREDICTION_SUPPORT = "prediction_support"
    DEBATE_AGREEMENT = "debate_agreement"
    CAPABILITY_AVAILABILITY = "capability_availability"
    CONTRADICTION_PENALTY = "contradiction_penalty"
    EVIDENCE_GAP_PENALTY = "evidence_gap_penalty"


# ---------------------------------------------------------------------------
# Action vocabulary and capability truth table
# ---------------------------------------------------------------------------


class ActionType(str, Enum):
    """Closed, capability-oriented response action vocabulary.

    Capability-oriented rather than provider-specific on purpose: ``BLOCK_IP``
    describes what SentinelAI needs to be able to do, not which vendor product
    will do it.  The concrete provider binding lives in
    :data:`ACTION_CAPABILITIES` and is owned by the existing response layer.

    The set is deliberately small.  An action is present only because
    SentinelAI can act on it today or because its absence would be a real gap in
    a bounded response workflow; "it sounds useful" is not a reason.
    """

    # -- collection / investigation (read-only; no provider needed) ----------
    COLLECT_ARTIFACT = "collect_artifact"
    COLLECT_MEMORY = "collect_memory"
    COLLECT_NETWORK_CAPTURE = "collect_network_capture"
    INCREASE_LOGGING = "increase_logging"
    SEARCH_INDICATOR = "search_indicator"
    SCAN_ENDPOINT = "scan_endpoint"
    SCAN_FILE = "scan_file"
    ADD_DETECTION_RULE = "add_detection_rule"
    # -- containment / prevention (need a real provider) --------------------
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    BLOCK_URL = "block_url"
    QUARANTINE_FILE = "quarantine_file"
    ISOLATE_ENDPOINT = "isolate_endpoint"
    DISABLE_ACCOUNT = "disable_account"
    REVOKE_SESSION = "revoke_session"
    REVOKE_TOKEN = "revoke_token"
    ROTATE_CREDENTIAL = "rotate_credential"
    RESET_CREDENTIAL = "reset_credential"
    KILL_PROCESS = "kill_process"
    DISABLE_PERSISTENCE = "disable_persistence"
    REMOVE_PERSISTENCE = "remove_persistence"
    # -- verification / recovery --------------------------------------------
    VERIFY_CONTAINMENT = "verify_containment"
    RESTORE_ENDPOINT = "restore_endpoint"
    UNBLOCK_IP = "unblock_ip"
    REENABLE_ACCOUNT = "reenable_account"


@dataclass(frozen=True)
class ActionSpec:
    """The frozen capabilities of one action.

    ``response_action`` is the bridge to the *existing* response layer: when it
    is set, the action maps onto a real ``ResponseActionType`` that the policy
    engine already judges and the response engine already dispatches.  When it is
    ``None``, SentinelAI has no execution path for the capability today, and the
    action is reported as ``UNAVAILABLE`` instead of being pretended into
    existence.
    """

    action: ActionType
    category: ActionCategory
    target_type: TargetType
    #: The matching member of the platform's existing response vocabulary, if any.
    response_action: ResponseActionType | None
    #: Default priority before any evidence-derived adjustment.
    base_priority: ActionPriority
    #: Rollback action, or ``None`` when nothing safely reverses this action.
    rollback_action: ActionType | None
    #: Whether rollback is itself a proposed capability.  Never automatic.
    rollback_supported: bool
    #: Human authorization recommended before any response layer may act.
    requires_approval: bool
    #: True when acting on this action changes system state.
    destructive: bool


def _spec(
    action: ActionType,
    category: ActionCategory,
    target_type: TargetType,
    *,
    response_action: ResponseActionType | None,
    base_priority: ActionPriority,
    rollback_action: ActionType | None = None,
    requires_approval: bool = False,
    destructive: bool = False,
) -> ActionSpec:
    """Build one spec, deriving ``rollback_supported`` from the rollback action.

    ``rollback_supported`` is deliberately *derived* rather than authored: an
    author who typed ``rollback_supported=True`` without naming an inverse action
    would be claiming a compensation path that does not exist.
    """
    return ActionSpec(
        action=action,
        category=category,
        target_type=target_type,
        response_action=response_action,
        base_priority=base_priority,
        rollback_action=rollback_action,
        rollback_supported=rollback_action is not None,
        requires_approval=requires_approval,
        destructive=destructive,
    )


#: The frozen action table.
#:
#: Truthfulness rules encoded here:
#:
#: * Only the six actions with a ``response_action`` can ever be dispatched, and
#:   every one of them resolves to a sandbox provider.
#: * Rollback is declared only where an inverse action genuinely exists in this
#:   vocabulary.  ``BLOCK_DOMAIN`` has none, so it does not claim one; a blocked
#:   domain cannot be un-blocked by any action SentinelAI can propose.
#: * Destructive actions all require approval.  Read-only investigation actions
#:   do not, which is what keeps ``NO_APPROVAL`` meaningful rather than universal.
ACTION_SPECS: Final[dict[ActionType, ActionSpec]] = {
    spec.action: spec
    for spec in (
        # Read-only. Nothing here mutates state, so no provider is required and
        # no approval is needed: these are the actions a prediction is allowed to
        # justify on its own.
        _spec(
            ActionType.COLLECT_ARTIFACT,
            ActionCategory.INVESTIGATION,
            TargetType.CORRELATION,
            response_action=None,
            base_priority=ActionPriority.HIGH,
        ),
        _spec(
            ActionType.COLLECT_MEMORY,
            ActionCategory.INVESTIGATION,
            TargetType.ENDPOINT,
            response_action=None,
            base_priority=ActionPriority.HIGH,
        ),
        _spec(
            ActionType.COLLECT_NETWORK_CAPTURE,
            ActionCategory.INVESTIGATION,
            TargetType.NETWORK,
            response_action=None,
            base_priority=ActionPriority.MEDIUM,
        ),
        _spec(
            ActionType.INCREASE_LOGGING,
            ActionCategory.INVESTIGATION,
            TargetType.ENDPOINT,
            response_action=None,
            base_priority=ActionPriority.MEDIUM,
        ),
        _spec(
            ActionType.SEARCH_INDICATOR,
            ActionCategory.INVESTIGATION,
            TargetType.NETWORK,
            response_action=None,
            base_priority=ActionPriority.MEDIUM,
        ),
        _spec(
            ActionType.SCAN_ENDPOINT,
            ActionCategory.INVESTIGATION,
            TargetType.ENDPOINT,
            response_action=None,
            base_priority=ActionPriority.MEDIUM,
        ),
        _spec(
            ActionType.SCAN_FILE,
            ActionCategory.INVESTIGATION,
            TargetType.FILE,
            response_action=None,
            base_priority=ActionPriority.MEDIUM,
        ),
        _spec(
            ActionType.ADD_DETECTION_RULE,
            ActionCategory.PREVENTION,
            TargetType.CORRELATION,
            response_action=None,
            base_priority=ActionPriority.LOW,
        ),
        # Containment and prevention with a real (sandbox) dispatch path.
        _spec(
            ActionType.BLOCK_IP,
            ActionCategory.CONTAINMENT,
            TargetType.IP,
            response_action=ResponseActionType.BLOCK_IP,
            base_priority=ActionPriority.IMMEDIATE,
            rollback_action=ActionType.UNBLOCK_IP,
            requires_approval=True,
            destructive=True,
        ),
        _spec(
            ActionType.BLOCK_DOMAIN,
            ActionCategory.CONTAINMENT,
            TargetType.DOMAIN,
            response_action=ResponseActionType.BLOCK_DOMAIN,
            base_priority=ActionPriority.IMMEDIATE,
            # No inverse action exists in this vocabulary; claiming one would be
            # inventing a compensation path.
            rollback_action=None,
            requires_approval=True,
            destructive=True,
        ),
        _spec(
            ActionType.QUARANTINE_FILE,
            ActionCategory.CONTAINMENT,
            TargetType.FILE,
            response_action=ResponseActionType.QUARANTINE_FILE,
            base_priority=ActionPriority.IMMEDIATE,
            # Restoring a quarantined file is not safely automatable.
            rollback_action=None,
            requires_approval=True,
            destructive=True,
        ),
        _spec(
            ActionType.ISOLATE_ENDPOINT,
            ActionCategory.CONTAINMENT,
            TargetType.ENDPOINT,
            response_action=ResponseActionType.ISOLATE_ENDPOINT,
            base_priority=ActionPriority.IMMEDIATE,
            rollback_action=ActionType.RESTORE_ENDPOINT,
            requires_approval=True,
            destructive=True,
        ),
        _spec(
            ActionType.DISABLE_ACCOUNT,
            ActionCategory.CONTAINMENT,
            TargetType.ACCOUNT,
            response_action=ResponseActionType.DISABLE_ACCOUNT,
            base_priority=ActionPriority.HIGH,
            rollback_action=ActionType.REENABLE_ACCOUNT,
            requires_approval=True,
            destructive=True,
        ),
        _spec(
            ActionType.REVOKE_SESSION,
            ActionCategory.CONTAINMENT,
            TargetType.TOKEN,
            # The existing response vocabulary's session termination is the
            # platform's real capability for ending an active session.
            response_action=ResponseActionType.TERMINATE_SESSION,
            base_priority=ActionPriority.HIGH,
            # A revoked session cannot be un-revoked.
            rollback_action=None,
            requires_approval=True,
            destructive=True,
        ),
        # Capabilities SentinelAI does not have today. Declared honestly as
        # UNAVAILABLE rather than omitted, so a proposal can still name the gap
        # and a reader can see what would need a provider.
        _spec(
            ActionType.BLOCK_URL,
            ActionCategory.CONTAINMENT,
            TargetType.URL,
            response_action=None,
            base_priority=ActionPriority.IMMEDIATE,
            requires_approval=True,
            destructive=True,
        ),
        _spec(
            ActionType.REVOKE_TOKEN,
            ActionCategory.CONTAINMENT,
            TargetType.TOKEN,
            response_action=None,
            base_priority=ActionPriority.HIGH,
            requires_approval=True,
            destructive=True,
        ),
        _spec(
            ActionType.ROTATE_CREDENTIAL,
            ActionCategory.ERADICATION,
            TargetType.CREDENTIAL,
            response_action=None,
            base_priority=ActionPriority.HIGH,
            requires_approval=True,
            destructive=True,
        ),
        _spec(
            ActionType.RESET_CREDENTIAL,
            ActionCategory.ERADICATION,
            TargetType.CREDENTIAL,
            response_action=None,
            base_priority=ActionPriority.HIGH,
            requires_approval=True,
            destructive=True,
        ),
        _spec(
            ActionType.KILL_PROCESS,
            ActionCategory.CONTAINMENT,
            TargetType.PROCESS,
            response_action=None,
            base_priority=ActionPriority.HIGH,
            requires_approval=True,
            destructive=True,
        ),
        _spec(
            ActionType.DISABLE_PERSISTENCE,
            ActionCategory.ERADICATION,
            TargetType.ENDPOINT,
            response_action=None,
            base_priority=ActionPriority.MEDIUM,
            requires_approval=True,
            destructive=True,
        ),
        _spec(
            ActionType.REMOVE_PERSISTENCE,
            ActionCategory.ERADICATION,
            TargetType.ENDPOINT,
            response_action=None,
            base_priority=ActionPriority.MEDIUM,
            requires_approval=True,
            destructive=True,
        ),
        # Verification and recovery.
        _spec(
            ActionType.VERIFY_CONTAINMENT,
            ActionCategory.VERIFICATION,
            TargetType.CORRELATION,
            response_action=None,
            base_priority=ActionPriority.HIGH,
        ),
        _spec(
            ActionType.RESTORE_ENDPOINT,
            ActionCategory.RECOVERY,
            TargetType.ENDPOINT,
            response_action=None,
            base_priority=ActionPriority.LOW,
            requires_approval=True,
            destructive=True,
        ),
        _spec(
            ActionType.UNBLOCK_IP,
            ActionCategory.RECOVERY,
            TargetType.IP,
            response_action=None,
            base_priority=ActionPriority.LOW,
            requires_approval=True,
            # Re-opening access to an address is itself a change of state, so a
            # prediction alone must not be able to justify it: a projection that
            # an attack will stop is not a reason to re-open a blocked host.
            destructive=True,
        ),
        _spec(
            ActionType.REENABLE_ACCOUNT,
            ActionCategory.RECOVERY,
            TargetType.ACCOUNT,
            response_action=None,
            base_priority=ActionPriority.LOW,
            requires_approval=True,
            # Same reasoning as UNBLOCK_IP: re-enabling an account re-grants
            # access, which is disruptive even though it looks restorative.
            destructive=True,
        ),
    )
}


def action_spec(action: ActionType) -> ActionSpec:
    """Return the frozen spec for ``action``."""
    return ACTION_SPECS[action]


def action_specs() -> dict[ActionType, ActionSpec]:
    """The whole frozen action table, keyed by action.

    Returned as a copy so a caller cannot mutate the table every safety property
    in this module is derived from.
    """
    return dict(ACTION_SPECS)


def capability_of(action: ActionType) -> CapabilityStatus:
    """Whether SentinelAI can dispatch this action today.

    Derived from ``response_action``, so the answer cannot drift from the
    platform's real response vocabulary.
    """
    return (
        CapabilityStatus.AVAILABLE
        if ACTION_SPECS[action].response_action is not None
        else CapabilityStatus.UNAVAILABLE
    )


def execution_backend_of(action: ActionType) -> ExecutionBackend:
    """What would actually run for this action.

    Every available capability in this release resolves to a sandbox adapter, so
    this never reports ``MOCK_SANDBOX`` only when it is true.
    """
    return (
        ExecutionBackend.MOCK_SANDBOX
        if capability_of(action) is CapabilityStatus.AVAILABLE
        else ExecutionBackend.NONE
    )


def approval_requirement_of(action: ActionType) -> ApprovalRequirement:
    """Classify an action's relationship to human authorization.

    An unavailable capability is ``NOT_EXECUTABLE``: no provider could act on it
    even if a human approved it, so reporting an approval requirement would
    imply a path that does not exist.
    """
    if capability_of(action) is CapabilityStatus.UNAVAILABLE:
        return ApprovalRequirement.NOT_EXECUTABLE
    return (
        ApprovalRequirement.APPROVAL_REQUIRED
        if ACTION_SPECS[action].requires_approval
        else ApprovalRequirement.NO_APPROVAL
    )


def is_destructive(action: ActionType) -> bool:
    return ACTION_SPECS[action].destructive


# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------


class PlaybookBounds(BaseModel):
    """Architectural bounds for one generation run.

    Bounds are checked **before** anything is persisted.  Exceeding a hard
    safety bound raises a governed error rather than silently truncating, because
    a silently shortened playbook would look like a complete one.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_graph_nodes: int = Field(default=200, ge=1, le=500)
    max_graph_edges: int = Field(default=600, ge=1, le=2000)
    max_debate_claims: int = Field(default=64, ge=1, le=500)
    max_predictions: int = Field(default=8, ge=1, le=32)
    max_candidate_actions: int = Field(default=24, ge=1, le=64)
    max_final_actions: int = Field(default=12, ge=1, le=32)
    max_steps: int = Field(
        default=20,
        ge=1,
        le=40,
        description="Maximum proposed steps in one playbook.",
    )
    max_evidence_references_per_action: int = Field(default=16, ge=1, le=32)
    max_dependencies: int = Field(default=48, ge=0, le=256)
    max_depth: int = Field(
        default=4,
        ge=1,
        le=16,
        description=(
            "Maximum depth of the forward action dependency DAG, measured as "
            "the longest chain of actions. This is a hard safety bound: a "
            "deeply chained plan is hard for an analyst to review before "
            "approving, and the remedy for exceeding it is a smaller plan, "
            "never a truncated one."
        ),
    )
    max_rationale_length: int = Field(default=1024, ge=128, le=4096)
    max_targets: int = Field(default=64, ge=1, le=256)
    max_model_candidates: int = Field(default=16, ge=0, le=64)
    max_model_output_bytes: int = Field(default=16384, ge=1024, le=65536)
    max_context_bytes: int = Field(default=65536, ge=1024, le=1048576)

    @model_validator(mode="after")
    def _steps_can_hold_the_actions(self) -> "PlaybookBounds":
        """A playbook cannot be complete if it may generate more actions than
        steps can hold."""
        if self.max_final_actions > self.max_steps:
            raise ValueError(
                "max_final_actions cannot exceed max_steps: every action occupies "
                "at least one step"
            )
        return self


DEFAULT_PLAYBOOK_BOUNDS: Final[PlaybookBounds] = PlaybookBounds()


# ---------------------------------------------------------------------------
# Confidence formula (§23)
# ---------------------------------------------------------------------------
#
# confidence = clamp01(
#       0.30 * evidence_support
#     + 0.20 * target_certainty
#     + 0.15 * prediction_support
#     + 0.15 * debate_agreement
#     + 0.20 * capability_availability
#     - contradiction_penalty
#     - evidence_gap_penalty
# )
#
# The weights sum to exactly 1.0 and every component is in [0, 1], so the
# weighted sum is in [0, 1] before the penalties.
#
# What this number is NOT: the probability that an action executes successfully,
# the incident risk score, debate consensus strength, or a V3.24 prediction
# confidence.  It answers a narrower question — *how well supported is this
# proposal?* — and it is never used to authorize anything.

WEIGHT_EVIDENCE_SUPPORT: Final[float] = 0.30
WEIGHT_TARGET_CERTAINTY: Final[float] = 0.20
WEIGHT_PREDICTION_SUPPORT: Final[float] = 0.15
WEIGHT_DEBATE_AGREEMENT: Final[float] = 0.15
WEIGHT_CAPABILITY_AVAILABILITY: Final[float] = 0.20

#: Penalty per contradicting evidence reference, capped.
CONTRADICTION_PENALTY_PER_REFERENCE: Final[float] = 0.10
MAX_CONTRADICTION_PENALTY: Final[float] = 0.30

#: Penalty per recorded evidence gap, capped.
EVIDENCE_GAP_PENALTY_PER_GAP: Final[float] = 0.05
MAX_EVIDENCE_GAP_PENALTY: Final[float] = 0.20

CONFIDENCE_PRECISION: Final[int] = 4

#: Supporting references at which evidence support saturates.
EVIDENCE_SUPPORT_SATURATION: Final[int] = 2

#: Ceiling applied to an action justified by prediction alone.
#:
#: A prediction is not a confirmed threat, so an action resting on nothing but a
#: prediction can never be reported as well-supported no matter how confident the
#: prediction was.
PREDICTION_ONLY_CONFIDENCE_CEILING: Final[float] = 0.55

#: Ceiling applied while the consumed debate is contested or partial.
DEBATE_UNSETTLED_CONFIDENCE_CEILING: Final[float] = 0.70


class ActionConfidenceBand(str, Enum):
    """Discrete band over a proposed action's support confidence."""

    VERY_LOW = "very_low"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"


CONFIDENCE_BAND_THRESHOLDS: Final[tuple[tuple[float, ActionConfidenceBand], ...]] = (
    (0.75, ActionConfidenceBand.HIGH),
    (0.50, ActionConfidenceBand.MODERATE),
    (0.30, ActionConfidenceBand.LOW),
)


def confidence_band(confidence: float) -> ActionConfidenceBand:
    """Map a bounded confidence to its band."""
    for threshold, band in CONFIDENCE_BAND_THRESHOLDS:
        if confidence >= threshold:
            return band
    return ActionConfidenceBand.VERY_LOW


# ---------------------------------------------------------------------------
# Target validation
# ---------------------------------------------------------------------------
#
# Structural validation only — no DNS, no filesystem, no network.  These are the
# same shapes the existing response validator enforces for the six dispatchable
# actions, so a target that passes here cannot be rejected downstream for a
# reason the playbook did not anticipate.

_ENDPOINT_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_DOMAIN_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
_ACCOUNT_RE = re.compile(r"^[a-z0-9._@-]{3,128}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9._:-]{3,128}$")
_CREDENTIAL_RE = re.compile(r"^[A-Za-z0-9._:/@-]{3,128}$")
_USER_RE = re.compile(r"^[a-z0-9._@-]{1,128}$")
_PROCESS_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_FILE_RE = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")
#: A bare 64-character hex value is a content digest, not a path.
#:
#: V3.25 has no hash target type and deliberately does not resolve a hash
#: indicator into a ``FILE`` target, so there is no legitimate way for one to
#: reach here.  Accepting it anyway would reintroduce precisely the ambiguity the
#: vocabulary avoids: ``quarantine_file`` is destructive, and a digest names no
#: artifact an operator could locate or restore.  Refusing the shape is the
#: truthful answer -- the value is not a path, whatever it was meant to be.
_SHA256_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_URL_RE = re.compile(r"^https?://[^\s/?#]+[^\s]*$", re.IGNORECASE)
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

#: Maximum endpoints any single containment action may name.
#:
#: A bound on scope, enforced structurally.  "Isolate these 40 hosts" is a
#: different kind of proposal from "isolate the affected host", and the second is
#: the only one an analyst can reason about before approving it.
MAX_TARGETS_PER_ACTION: Final[int] = 1


class TargetValidationError(ValueError):
    """A target failed structural validation for its target type."""


#: Placeholder prose that must never be mistaken for a real identifier.
#:
#: "everything", "unknown" and "tbd" all satisfy the identifier regexes below, so
#: a record that carried one as an account or session name would otherwise yield a
#: proposal to disable an account called ``everything``.  A target this vague is
#: not actionable, and refusing it costs nothing: no real identity is named by a
#: word from this set.
_RESERVED_PLACEHOLDER_IDENTIFIERS: Final[frozenset[str]] = frozenset(
    {
        "all",
        "allhosts",
        "any",
        "anyone",
        "anonymous",
        "default",
        "everything",
        "example",
        "global",
        "localhost",
        "none",
        "nobody",
        "n/a",
        "na",
        "nil",
        "null",
        "placeholder",
        "sample",
        "somebody",
        "someone",
        "someoneelse",
        "test",
        "testing",
        "tbd",
        "todo",
        "unknown",
        "unset",
        "whatever",
    }
)


def _reject_placeholder_identifier(value: str) -> None:
    """Raise when ``value`` is placeholder prose rather than an identifier."""
    if value.strip().lower() in _RESERVED_PLACEHOLDER_IDENTIFIERS:
        raise TargetValidationError(
            "value is placeholder prose, not a specific identifier"
        )


def validate_target_value(target_type: TargetType, raw: str) -> str:
    """Structurally validate ``raw`` for ``target_type``.

    Returns the canonical form.  Raises :class:`TargetValidationError` when the
    value is not a plausible target of that type — the caller records the target
    as unusable rather than coercing it into something adjacent.
    """
    value = (raw or "").strip()
    if not value:
        raise TargetValidationError("target must not be blank")

    try:
        if target_type is TargetType.IP:
            return str(ipaddress.ip_address(value))
        if target_type is TargetType.DOMAIN:
            # Lower-case before matching as well as before returning: DNS names
            # are case-insensitive, so rejecting "EVIL.Example.COM" outright
            # would mean a mixed-case indicator silently failed to resolve.
            canonical = value.lower()
            if len(canonical) > 253 or not _DOMAIN_RE.match(canonical):
                raise TargetValidationError("not a valid domain name")
            return canonical
        if target_type is TargetType.URL:
            if not _URL_RE.match(value):
                raise TargetValidationError("not a valid http(s) URL")
            if len(value) > 2048:
                raise TargetValidationError("URL exceeds the permitted length")
            return value
        if target_type is TargetType.FILE:
            if _SHA256_HEX_RE.match(value):
                raise TargetValidationError(
                    "a bare SHA-256 digest is not a logical file path; V3.25 has "
                    "no hash target type, so a digest cannot address a file"
                )
            if not _FILE_RE.match(value):
                raise TargetValidationError("not a safe logical file path")
            if ".." in value or value.startswith(("/", "~", "\\")):
                raise TargetValidationError("must be a relative logical path")
            if len(value) >= 2 and value[1] == ":":
                raise TargetValidationError("must not be an absolute drive path")
            return value
        if target_type is TargetType.PROCESS:
            if not _PROCESS_RE.match(value):
                raise TargetValidationError("not a valid process identifier")
            return value
        if target_type is TargetType.ENDPOINT:
            if not _ENDPOINT_RE.match(value.lower()):
                raise TargetValidationError("not a valid endpoint identifier")
            _reject_placeholder_identifier(value)
            return value.lower()
        if target_type is TargetType.USER:
            if not _USER_RE.match(value.lower()):
                raise TargetValidationError("not a valid user identifier")
            _reject_placeholder_identifier(value)
            return value.lower()
        if target_type is TargetType.ACCOUNT:
            if not _ACCOUNT_RE.match(value.lower()):
                raise TargetValidationError("not a valid account identifier")
            _reject_placeholder_identifier(value)
            return value.lower()
        if target_type in (TargetType.TOKEN, TargetType.CREDENTIAL):
            pattern = _TOKEN_RE if target_type is TargetType.TOKEN else _CREDENTIAL_RE
            if not pattern.match(value):
                raise TargetValidationError(
                    f"not a valid {target_type.value} identifier"
                )
            return value
        if target_type is TargetType.NETWORK:
            # Only a CIDR block or a single canonical address.  Never a bare
            # "the network".
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise TargetValidationError(
                    "a network target must be a single address or CIDR block"
                ) from exc
            if network.prefixlen == 0:
                # ``0.0.0.0/0`` and ``::/0`` are the whole internet, which is not
                # a scope an analyst can reason about — it is the absence of one.
                # Accepting it would let "investigate the entire internet" pass
                # structural validation as if it were a bounded request.
                raise TargetValidationError(
                    "a network target must be a bounded CIDR block; a default "
                    "route does not describe a scope"
                )
            return str(network)
        if target_type in (TargetType.CORRELATION, TargetType.INCIDENT):
            if not _UUID_RE.match(value):
                raise TargetValidationError(
                    f"a {target_type.value} target must be a UUID"
                )
            return value.lower()
    except TargetValidationError:
        raise
    except ValueError as exc:  # pragma: no cover - defensive
        raise TargetValidationError(str(exc)) from exc

    raise TargetValidationError(f"unsupported target type: {target_type.value}")


# ---------------------------------------------------------------------------
# Untrusted-content handling (§20)
# ---------------------------------------------------------------------------
#
# V3.25 never interpolates untrusted text into a rationale, and never derives an
# action from one.  These patterns exist for the *optional* model-candidate path,
# where untrusted context must reach a provider prompt: detected lines are
# replaced with a marker so an injected instruction arrives as inert data rather
# than as a directive.

#: Instruction-override phrasings.  Matched case-insensitively against a
#: whitespace-collapsed line.
INJECTION_PATTERNS: Final[tuple[re.Pattern[str], ...]] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+instructions?",
        r"disregard\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+instructions?",
        r"forget\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|rules?)",
        r"you\s+are\s+now\s+",
        r"new\s+(?:system\s+)?instructions?\s*:",
        r"system\s*(?:prompt|override)\s*:",
        r"reveal\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)",
        r"print\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)",
        r"execute\s+(?:the\s+)?following\s+(?:command|instruction)",
        r"\bact\s+as\s+(?:if\s+you\s+are\s+)?(?:an?\s+)?(?:admin|root|attacker)",
        r"bypass\s+(?:the\s+)?(?:policy|approval|hitl|safety)",
        r"disable\s+(?:all|every)\s+(?:user|account|endpoint|host|system)",
        r"shut\s*down\s+all\s+endpoints?",
        r"delete\s+all\s+files?",
        r"block\s+the\s+entire\s+network",
    )
)

#: Replacement inserted in place of a detected line.
QUARANTINED_MARKER = "[quarantined: untrusted instruction-like content]"


def quarantine_untrusted_text(text: str, *, limit: int = 512) -> tuple[str, bool]:
    """Neutralize instruction-like lines in ``text``.

    Returns ``(safe_text, detected)``.  Only whole lines that match an injection
    pattern are replaced, so ordinary log content survives intact and the caller
    can record that something was quarantined.
    """
    if not text:
        return "", False
    detected = False
    kept: list[str] = []
    for line in text.splitlines():
        collapsed = " ".join(line.split())
        if any(pattern.search(collapsed) for pattern in INJECTION_PATTERNS):
            detected = True
            kept.append(QUARANTINED_MARKER)
        else:
            kept.append(collapsed)
    safe = "\n".join(kept)[:limit]
    return safe, detected


def contains_injection_pattern(text: str) -> bool:
    """Whether ``text`` looks like an instruction-override attempt.

    Used as a defence-in-depth assertion: even if quarantining were somehow
    bypassed, a value matching this must never be treated as an instruction.
    """
    collapsed = " ".join((text or "").split())
    return any(pattern.search(collapsed) for pattern in INJECTION_PATTERNS)


# ---------------------------------------------------------------------------
# Deterministic identity (§18, §27)
# ---------------------------------------------------------------------------


def clamp01(value: float) -> float:
    """Clamp to [0, 1]."""
    return max(0.0, min(1.0, value))


def deterministic_playbook_id(
    *,
    correlation_id: uuid.UUID | str,
    graph_snapshot_digest: str,
    debate_id: uuid.UUID | str | None,
    prediction_id: uuid.UUID | str | None,
    configuration_digest: str,
) -> uuid.UUID:
    """Derive a playbook's identity.

    The conceptual identity required for V3.25:
    ``(correlation_id, graph_snapshot_digest, debate_id, prediction_id,
    playbook_configuration_digest)``.

    Every input is a content-derived or immutable reference, and current time is
    never one of them, so repeated generation over unchanged inputs resolves to
    the same playbook.  Conversely a changed graph snapshot, a new prediction or
    a reconfigured engine produces a *different* identity — an old proposal is
    never silently reused for changed circumstances.
    """
    payload = "|".join(
        (
            "playbook",
            str(correlation_id),
            graph_snapshot_digest,
            str(debate_id) if debate_id is not None else "-",
            str(prediction_id) if prediction_id is not None else "-",
            configuration_digest,
        )
    )
    return uuid.uuid5(PLAYBOOK_NAMESPACE, payload)


def deterministic_action_id(
    playbook_id: uuid.UUID | str,
    action: ActionType,
    target_reference: str,
    occurrence: int = 0,
) -> uuid.UUID:
    """Derive one action's identity from what the action *is*.

    Content-derived rather than positional, so the same logical action keeps its
    identity regardless of how many other actions surround it.  ``occurrence``
    disambiguates genuinely repeated actions (the same action on two targets).
    """
    payload = f"{playbook_id}|{action.value}|{target_reference}|{occurrence}"
    return uuid.uuid5(PLAYBOOK_NAMESPACE, payload)


def deterministic_row_id(parent: uuid.UUID, kind: str, key: str) -> uuid.UUID:
    """Derive a child-row identity from its owning playbook."""
    return uuid.uuid5(PLAYBOOK_ROW_NAMESPACE, f"{parent}|{kind}|{key}")


def playbook_configuration_digest(
    bounds: PlaybookBounds,
    *,
    allow_model_candidates: bool = False,
) -> str:
    """SHA-256 over the playbook configuration.

    Part of the playbook identity, so changing a bound — or switching the
    optional model-candidate path on — yields a new playbook identity instead of
    comparing two different configurations under one key.
    """
    payload = json.dumps(
        {
            "bounds": bounds.model_dump(mode="json"),
            "allow_model_candidates": allow_model_candidates,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(f"{ENGINE_VERSION}|{payload}".encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Dependency graph validation (§14)
# ---------------------------------------------------------------------------


class DependencyCycleError(ValueError):
    """The proposed dependency graph is not a DAG."""


def topological_order(action_ids: list[uuid.UUID], edges: dict[uuid.UUID, list[uuid.UUID]]) -> list[uuid.UUID]:
    """Deterministically order ``action_ids`` so dependencies come first.

    Kahn's algorithm with a sorted ready-set, which makes the result a function of
    the graph alone — no insertion order, no timestamps.  ``edges`` maps an action
    to the actions it depends on.

    Raises:
        DependencyCycleError: the graph contains a cycle, or names an unknown
            action.  A cycle is rejected rather than broken: silently ordering a
            cyclic plan would present an impossible sequence as a valid one.
    """
    known = set(action_ids)
    if len(known) != len(action_ids):
        raise DependencyCycleError("duplicate action id in the proposed plan")

    indegree: dict[uuid.UUID, int] = {action: 0 for action in known}
    dependents: dict[uuid.UUID, list[uuid.UUID]] = {action: [] for action in known}
    for action in sorted(known, key=str):
        for dependency in edges.get(action, []):
            if dependency not in known:
                raise DependencyCycleError(
                    f"action depends on an unknown action: {dependency}"
                )
            indegree[action] += 1
            dependents[dependency].append(action)

    ready = sorted((a for a in known if indegree[a] == 0), key=str)
    ordered: list[uuid.UUID] = []
    while ready:
        current = ready.pop(0)
        ordered.append(current)
        for dependent in sorted(dependents[current], key=str):
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                ready.append(dependent)
                ready.sort(key=str)

    if len(ordered) != len(known):
        raise DependencyCycleError(
            "the proposed action dependencies contain a cycle; a playbook must be "
            "a directed acyclic graph"
        )
    return ordered


# ---------------------------------------------------------------------------
# Machine-readable vocabulary
# ---------------------------------------------------------------------------


def vocabulary_document() -> dict[str, Any]:
    """Machine-readable dump of the frozen vocabulary, capabilities and bounds."""
    return {
        "engine_version": ENGINE_VERSION,
        "lifecycle": [member.value for member in PlaybookLifecycle],
        "generated_lifecycles": sorted(
            member.value for member in GENERATED_LIFECYCLES
        ),
        "downstream_only_lifecycles": sorted(
            member.value for member in DOWNSTREAM_ONLY_LIFECYCLES
        ),
        "status": [member.value for member in PlaybookStatus],
        "action_types": [member.value for member in ActionType],
        "target_types": [member.value for member in TargetType],
        "action_categories": [member.value for member in ActionCategory],
        "approval_requirements": [member.value for member in ApprovalRequirement],
        "action_priorities": [member.value for member in ActionPriority],
        "grounding_basis": [member.value for member in GroundingBasis],
        "evidence_sources": [member.value for member in EvidenceSource],
        "capability_status": [member.value for member in CapabilityStatus],
        "execution_backend": [member.value for member in ExecutionBackend],
        "dependency_kinds": [member.value for member in DependencyKind],
        "limitation_kinds": [member.value for member in PlaybookLimitationKind],
        "actions": {
            action.value: {
                "category": spec.category.value,
                "target_type": spec.target_type.value,
                "capability": capability_of(action).value,
                "execution_backend": execution_backend_of(action).value,
                "approval_requirement": approval_requirement_of(action).value,
                "response_action": (
                    spec.response_action.value if spec.response_action else None
                ),
                "base_priority": spec.base_priority.value,
                "destructive": spec.destructive,
                "rollback_supported": spec.rollback_supported,
                "rollback_action": (
                    spec.rollback_action.value if spec.rollback_action else None
                ),
            }
            for action, spec in sorted(ACTION_SPECS.items(), key=lambda kv: kv[0].value)
        },
        "confidence_formula": {
            "expression": (
                "clamp01(0.30*evidence_support + 0.20*target_certainty + "
                "0.15*prediction_support + 0.15*debate_agreement + "
                "0.20*capability_availability - contradiction_penalty - "
                "evidence_gap_penalty)"
            ),
            "weights": {
                PlaybookConfidenceComponent.EVIDENCE_SUPPORT.value: WEIGHT_EVIDENCE_SUPPORT,
                PlaybookConfidenceComponent.TARGET_CERTAINTY.value: WEIGHT_TARGET_CERTAINTY,
                PlaybookConfidenceComponent.PREDICTION_SUPPORT.value: WEIGHT_PREDICTION_SUPPORT,
                PlaybookConfidenceComponent.DEBATE_AGREEMENT.value: WEIGHT_DEBATE_AGREEMENT,
                PlaybookConfidenceComponent.CAPABILITY_AVAILABILITY.value: WEIGHT_CAPABILITY_AVAILABILITY,
            },
            "contradiction_penalty_per_reference": CONTRADICTION_PENALTY_PER_REFERENCE,
            "max_contradiction_penalty": MAX_CONTRADICTION_PENALTY,
            "evidence_gap_penalty_per_gap": EVIDENCE_GAP_PENALTY_PER_GAP,
            "max_evidence_gap_penalty": MAX_EVIDENCE_GAP_PENALTY,
            "evidence_support_saturation": EVIDENCE_SUPPORT_SATURATION,
            "prediction_only_confidence_ceiling": PREDICTION_ONLY_CONFIDENCE_CEILING,
            "debate_unsettled_confidence_ceiling": DEBATE_UNSETTLED_CONFIDENCE_CEILING,
            "precision": CONFIDENCE_PRECISION,
            "meaning": (
                "How well supported this proposal is. Not a probability of "
                "successful execution, not a risk score, not debate confidence, "
                "and not a prediction confidence."
            ),
        },
        "bounds": DEFAULT_PLAYBOOK_BOUNDS.model_dump(mode="json"),
        "statements": [
            "V3.25 generates proposed response playbooks; it does not execute them.",
            "A proposed action is not a thing that happened.",
            "PROPOSED is not APPROVED, APPROVED is not EXECUTED, and EXECUTED is "
            "not VERIFIED.",
            "The Policy Decision Engine and HITL approval service remain "
            "authoritative; this engine can only recommend that approval is "
            "required.",
            "Every execution capability in this release is a sandbox adapter.",
            "No ATT&CK catalog, technique taxonomy or successor table is embedded.",
        ],
    }


__all__ = [
    "ACTION_SPECS",
    "action_specs",
    "DEFAULT_PLAYBOOK_BOUNDS",
    "DOWNSTREAM_ONLY_LIFECYCLES",
    "ENGINE_VERSION",
    "GENERATED_LIFECYCLES",
    "INJECTION_PATTERNS",
    "MAX_TARGETS_PER_ACTION",
    "NON_DESTRUCTIVE_ONLY_TARGETS",
    "PLAYBOOK_NAMESPACE",
    "PLAYBOOK_ROW_NAMESPACE",
    "PRIORITY_ORDER",
    "QUARANTINED_MARKER",
    "ActionCategory",
    "ActionConfidenceBand",
    "ActionPriority",
    "ActionSpec",
    "ActionType",
    "ApprovalRequirement",
    "CapabilityStatus",
    "DependencyCycleError",
    "DependencyKind",
    "EvidenceSource",
    "ExecutionBackend",
    "GroundingBasis",
    "PlaybookConfidenceComponent",
    "PlaybookLimitationKind",
    "PlaybookLifecycle",
    "PlaybookStatus",
    "TargetType",
    "TargetValidationError",
    "action_spec",
    "approval_requirement_of",
    "capability_of",
    "clamp01",
    "confidence_band",
    "contains_injection_pattern",
    "deterministic_action_id",
    "deterministic_playbook_id",
    "deterministic_row_id",
    "execution_backend_of",
    "is_destructive",
    "playbook_configuration_digest",
    "quarantine_untrusted_text",
    "topological_order",
    "validate_target_value",
    "vocabulary_document",
]