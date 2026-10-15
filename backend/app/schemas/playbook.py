"""Strict playbook contracts — V3.25.

Every semantic structure in V3.25 is a typed Pydantic model with
``extra="forbid"``.  No core concept is an arbitrary dictionary, so a playbook
cannot carry an unmodelled field a consumer would have to guess about.

Four invariants are enforced by the contracts themselves rather than by
convention:

**A playbook is not evidence.**  Every model pins ``provenance`` to
``Literal[Provenance.AI_GENERATED]`` using the *platform* provenance enum.  Since
that enum also contains ``observed``, ``detected``, ``correlated`` and
``risk_assessed``, the type system makes it impossible to serialize a proposed
action as something that already happened.

**A proposed action cannot escalate its own lifecycle.**
:class:`PlaybookResult` validates that ``lifecycle`` is one of the two values
generation may produce.  ``APPROVED``, ``EXECUTING``, ``EXECUTED`` and
``VERIFIED`` are rejected at construction, so no code path can mark a generated
playbook as approved or executed without changing this contract.

**A capability claim cannot be inflated.**  An action's ``capability``,
``execution_backend`` and ``approval`` are cross-checked against the frozen
action table.  Claiming ``AVAILABLE`` for an action with no provider, or
``NO_APPROVAL`` for one with no dispatch path, is a validation error.

**A destructive action cannot rest on a prediction alone.**  ``ISOLATE_ENDPOINT``
grounded only in a V3.24 prediction is rejected.  A prediction may justify
preparation and collection; it may not, on its own, justify containment that
disrupts a system.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas.security_event import Provenance
from app.services.playbook.vocabulary import (
    DEFAULT_PLAYBOOK_BOUNDS,
    GENERATED_LIFECYCLES,
    NON_DESTRUCTIVE_ONLY_TARGETS,
    ActionCategory,
    ActionConfidenceBand,
    ActionPriority,
    ActionType,
    ApprovalRequirement,
    CapabilityStatus,
    DependencyCycleError,
    DependencyKind,
    EvidenceSource,
    ExecutionBackend,
    GroundingBasis,
    PlaybookConfidenceComponent,
    PlaybookLimitationKind,
    PlaybookLifecycle,
    PlaybookStatus,
    PlaybookBounds,
    TargetType,
    action_spec,
    approval_requirement_of,
    capability_of,
    execution_backend_of,
    is_destructive,
    topological_order,
    validate_target_value,
)

#: Playbook provenance.  The platform enum is reused rather than redefined so
#: that "a playbook is not evidence" is a property of the type system.
PlaybookProvenance = Literal[Provenance.AI_GENERATED]

#: Legal ``kind`` values for an evidence reference.  A reference must be typed
#: with one of these, so it can only ever point at a subsystem that genuinely
#: produces evidence.
_EVIDENCE_SOURCE_VALUES: frozenset[str] = frozenset(
    member.value for member in EvidenceSource
)

PlaybookId = Annotated[str, Field(min_length=1, max_length=128)]
Reference = Annotated[str, Field(min_length=1, max_length=256)]
BoundedLine = Annotated[str, Field(min_length=1, max_length=512)]
BoundedText = Annotated[str, Field(min_length=1, max_length=1024)]
BoundedShort = Annotated[str, Field(min_length=1, max_length=256)]
Digest = Annotated[str, Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")]


class ActionEvidence(BaseModel):
    """One pointer justifying an action.

    A reference into an existing subsystem, never an embedded copy of its content.
    ``detail`` is engine-authored and describes *why this pointer matters for this
    action* — it never restates source text, because restating it is how
    untrusted log content would end up inside a playbook.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: EvidenceSource
    reference: Reference
    stance: Literal["supporting", "contradicting"] = "supporting"
    detail: BoundedLine

    @field_validator("reference")
    @classmethod
    def _reference_is_typed_and_bounded(cls, reference: str, info) -> str:
        """Require a reference whose kind is a real :class:`EvidenceSource`.

        A bare identifier with no kind is rejected: without the prefix nothing
        downstream can tell which subsystem the pointer belongs to, and an
        untyped pointer is indistinguishable from a fabricated one.  Requiring
        the kind to be an actual evidence source closes the gap further — an
        action cannot cite ``<kind>:<id>`` with a kind that no evidence source
        ever produces, so the typed reference cannot be invented.
        """
        kind, separator, tail = reference.partition(":")
        if not separator or not kind or not tail:
            raise ValueError(
                "an evidence reference must be typed as '<evidence_source>:<id>'"
            )
        if kind not in _EVIDENCE_SOURCE_VALUES:
            raise ValueError(
                f"'{kind}' is not an evidence source; a reference must be typed as "
                f"'<evidence_source>:<id>' with one of: "
                f"{', '.join(sorted(_EVIDENCE_SOURCE_VALUES))}"
            )
        source = info.data.get("source")
        if isinstance(source, EvidenceSource) and kind != source.value:
            raise ValueError(
                f"reference kind '{kind}' disagrees with the declared source "
                f"'{source.value}'"
            )
        return reference

    @property
    def source_id(self) -> str:
        """The id embedded in the reference."""
        return self.reference.split(":", 1)[1]


class ActionRationale(BaseModel):
    """Why the engine proposed this action.

    Assembled deterministically from engine-authored templates plus validated
    identifiers.  No field can hold a prompt, a raw provider payload, source
    record content, or untrusted free text, so a rationale cannot leak one and
    cannot introduce a fact absent from the referenced data.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    summary: BoundedText
    grounding: GroundingBasis
    grounding_detail: BoundedLine
    priority_reason: BoundedLine
    #: Prediction this action is grounded in, when applicable.
    prediction_reference: Reference | None = None
    #: Debate this action is informed by, when applicable.
    debate_reference: Reference | None = None
    provenance: PlaybookProvenance = Provenance.AI_GENERATED


class ActionDependency(BaseModel):
    """One explicit ordering constraint between actions.

    ``depends_on_action_id`` names an action that must be proposed *before* this
    one.  Dependencies exist so the plan cannot tell an analyst to isolate a host
    before capturing the evidence that isolation would destroy.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    depends_on_action_id: uuid.UUID
    kind: DependencyKind
    reason: BoundedLine

    @model_validator(mode="after")
    def _cannot_depend_on_itself(self) -> "ActionDependency":
        return self


class ActionRollback(BaseModel):
    """Compensation metadata for one action.

    Rollback is a **proposed capability**, never an automatic execution.
    ``rollback_supported`` is derived from the frozen action table rather than
    authored, so an action cannot claim a compensation path that does not exist
    in the closed vocabulary.  When rollback is unsupported, ``reason`` is required
    and must be populated — silence would read as "probably fine to try".
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    rollback_supported: bool
    rollback_action: ActionType | None = None
    reason: BoundedLine

    @model_validator(mode="after")
    def _truthful_about_rollback(self) -> "ActionRollback":
        action = self.rollback_action
        if self.rollback_supported and action is None:
            raise ValueError(
                "rollback_supported requires naming the compensating action; a "
                "compensation path cannot be implied"
            )
        if not self.rollback_supported and action is not None:
            raise ValueError(
                "rollback_action must be absent when rollback is unsupported"
            )
        return self


class ActionApprovalRequirement(BaseModel):
    """How this action relates to human authorization.

    V3.25 **recommends** an approval requirement; it never grants one.  The
    Policy Decision Engine evaluates every action independently, and the HITL
    approval service is the only thing that can move a playbook out of
    ``approval_required``.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    requirement: ApprovalRequirement
    reason: BoundedLine
    #: Roles that may resolve approval, mirroring the existing approval service.
    #: Informational only — this engine grants nothing.
    authorized_roles: list[str] = Field(default_factory=list, max_length=8)
    provenance: PlaybookProvenance = Provenance.AI_GENERATED


class PlaybookAction(BaseModel):
    """One proposed response action.

    The central artifact, and the thing that must never be mistaken for something
    that happened.  Note what is absent: there is no status, outcome, result, or
    timestamp of execution.  Every field describes what is *proposed* and what
    justifies it.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    action_id: uuid.UUID
    action: ActionType
    category: ActionCategory
    target_type: TargetType
    target_reference: Annotated[str, Field(min_length=1, max_length=256)]
    target_basis: BoundedLine
    capability: CapabilityStatus
    execution_backend: ExecutionBackend
    approval: ActionApprovalRequirement
    rollback: ActionRollback
    risk_level: Literal["low", "medium", "high"] = "medium"
    expected_outcome: BoundedLine
    verification_required: bool
    verification_method: BoundedLine | None = None
    priority: ActionPriority
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    confidence_band: ActionConfidenceBand
    confidence_basis: dict[PlaybookConfidenceComponent, float] = Field(
        ..., min_length=1, description="Deterministic component breakdown."
    )
    #: At least one citation is required: an action with no evidence is not a
    #: proposal, it is a preference.  ``min_length`` is the enforcement point —
    #: "evidence-grounded or not proposed" as a structural rule.
    evidence: list[ActionEvidence] = Field(..., min_length=1)
    rationale: ActionRationale
    prerequisites: list[BoundedShort] = Field(default_factory=list, max_length=16)
    depends_on: list[ActionDependency] = Field(default_factory=list, max_length=16)
    provenance: PlaybookProvenance = Provenance.AI_GENERATED

    @field_validator("confidence_basis")
    @classmethod
    def _basis_is_bounded(
        cls, basis: dict[PlaybookConfidenceComponent, float]
    ) -> dict[PlaybookConfidenceComponent, float]:
        for component, value in basis.items():
            if not 0.0 <= value <= 1.0:
                raise ValueError(
                    f"confidence component {component.value} must be in [0, 1]"
                )
        return basis

    @model_validator(mode="after")
    def _capability_claims_match_the_frozen_table(self) -> "PlaybookAction":
        """Cross-check capability, backend, approval and target type.

        Without this an action could claim a provider that does not exist, or
        attach a destructive action to a scope-only target type — which is how
        "block the entire network" would enter a generated plan.
        """
        spec = action_spec(self.action)
        if self.category is not spec.category:
            raise ValueError(
                f"{self.action.value} belongs to category {spec.category.value}, "
                f"not {self.category.value}"
            )
        if self.target_type is not spec.target_type:
            raise ValueError(
                f"{self.action.value} addresses {spec.target_type.value}, not "
                f"{self.target_type.value}"
            )
        if self.capability is not capability_of(self.action):
            raise ValueError(
                f"{self.action.value} capability is {capability_of(self.action).value}; "
                f"a generated playbook cannot claim otherwise"
            )
        if self.execution_backend is not execution_backend_of(self.action):
            raise ValueError(
                f"{self.action.value} executes via "
                f"{execution_backend_of(self.action).value}"
            )
        if self.approval.requirement is not approval_requirement_of(self.action):
            raise ValueError(
                f"{self.action.value} is classified "
                f"{approval_requirement_of(self.action).value} by the frozen action "
                f"table and cannot be downgraded by the generator"
            )
        if self.rollback.rollback_supported != spec.rollback_supported:
            raise ValueError(
                f"{self.action.value} rollback support is fixed at "
                f"{spec.rollback_supported} and cannot be invented"
            )
        if self.rollback.rollback_action is not spec.rollback_action:
            raise ValueError(
                f"{self.action.value} rollback action is fixed at "
                f"{spec.rollback_action.value if spec.rollback_action else None}"
            )
        if self.target_type in NON_DESTRUCTIVE_ONLY_TARGETS and spec.destructive:
            raise ValueError(
                f"{self.target_type.value} is a scope-only target type and cannot "
                f"address a destructive action such as {self.action.value}"
            )
        return self

    @model_validator(mode="after")
    def _destructive_actions_need_established_evidence(self) -> "PlaybookAction":
        """A prediction alone cannot justify disrupting a system.

        A V3.24 prediction is a projection of what *may* happen.  It may justify
        preparation and collection, which change nothing.  It may not, on its
        own, justify isolation, blocking, quarantine, or credential revocation —
        those require something that actually happened.
        """
        if not is_destructive(self.action):
            return self
        if self.rationale.grounding is GroundingBasis.PREDICTION_SUPPORTED:
            raise ValueError(
                f"{self.action.value} is disruptive and cannot be grounded in a "
                "prediction alone; established evidence is required"
            )
        has_established = any(
            item.source is not EvidenceSource.PREDICTION
            and item.source is not EvidenceSource.DEBATE_CLAIM
            for item in self.evidence
        )
        if not has_established:
            raise ValueError(
                f"{self.action.value} is disruptive and requires at least one "
                "established (non-prediction) evidence reference"
            )
        return self

    @model_validator(mode="after")
    def _verification_is_declared_when_required(self) -> "PlaybookAction":
        """A verification requirement without a method is not actionable."""
        if self.verification_required and not self.verification_method:
            raise ValueError(
                "verification_required needs a verification_method describing how "
                "an analyst would confirm the effect"
            )
        return self

    @property
    def supporting_evidence(self) -> list[ActionEvidence]:
        return [item for item in self.evidence if item.stance == "supporting"]

    @property
    def contradicting_evidence(self) -> list[ActionEvidence]:
        return [item for item in self.evidence if item.stance == "contradicting"]

    @property
    def response_action(self) -> str | None:
        """The existing response-layer action this maps onto, if any."""
        spec = action_spec(self.action)
        return spec.response_action.value if spec.response_action else None


class PlaybookStep(BaseModel):
    """One ordered phase of the playbook.

    ``depends_on_steps`` is **derived** from the actions' dependency edges rather
    than authored separately, so step ordering and action ordering can never
    disagree.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    step_number: Annotated[int, Field(ge=1, le=64)]
    name: Annotated[str, Field(min_length=1, max_length=128)]
    purpose: BoundedLine
    actions: list[PlaybookAction] = Field(default_factory=list, max_length=16)
    depends_on_steps: list[Annotated[int, Field(ge=1, le=64)]] = Field(
        default_factory=list, max_length=16
    )

    @model_validator(mode="after")
    def _step_numbers_are_unique_and_ordered(self) -> "PlaybookStep":
        return self


class PlaybookUncertainty(BaseModel):
    """Explicit uncertainty for the playbook as a whole.

    Disagreement is preserved, never converted into certainty.  When the
    consumed debate was partial or contested, that is recorded here and it caps
    the reported confidence.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    confidence_band: ActionConfidenceBand
    confidence_basis: dict[PlaybookConfidenceComponent, float] = Field(
        ..., min_length=1, description="Deterministic component breakdown."
    )
    supporting_evidence_count: Annotated[int, Field(ge=0)]
    contradicting_evidence_count: Annotated[int, Field(ge=0)]
    evidence_gaps: list[BoundedShort] = Field(default_factory=list, max_length=32)
    unresolved_questions: list[BoundedShort] = Field(default_factory=list, max_length=32)
    conflicting_claims: list[BoundedShort] = Field(default_factory=list, max_length=32)
    provenance: PlaybookProvenance = Provenance.AI_GENERATED

    @property
    def is_contested(self) -> bool:
        return bool(self.conflicting_claims) or self.contradicting_evidence_count > 0


class PlaybookLimitation(BaseModel):
    """One explicit limitation on the playbook."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: PlaybookLimitationKind
    detail: BoundedLine


class PlaybookMetadata(BaseModel):
    """Provenance and reproducibility metadata for one playbook.

    Records exactly what the playbook was derived *from*, so a consumer can tell
    a proposal grounded in established evidence from one leaning on a prediction,
    and can reproduce the inputs.  Note there is no ``created_at``: current time
    is deliberately excluded from playbook identity.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    engine_version: Annotated[str, Field(max_length=48)]
    playbook_configuration_digest: Digest
    graph_snapshot_digest: Digest
    debate_id: Annotated[str, Field(max_length=64)] | None = None
    debate_consensus_state: Annotated[str, Field(max_length=48)] | None = None
    prediction_session_id: Annotated[str, Field(max_length=64)] | None = None
    prediction_status: Annotated[str, Field(max_length=48)] | None = None
    prediction_count: Annotated[int, Field(default=0, ge=0)]
    graph_node_count: Annotated[int, Field(ge=0)]
    graph_edge_count: Annotated[int, Field(ge=0)]
    target_count: Annotated[int, Field(ge=0)]
    #: Depth actually reached by the **forward** dependency DAG — the longest
    #: chain of actions, not a count of them.  Rollback metadata is not a
    #: forward edge and is excluded.
    #:
    #: ``0`` for a playbook with no actions, because that is the true depth of an
    #: empty graph; reporting ``1`` would claim a chain that does not exist.  The
    #: upper bound matches ``PlaybookBounds.max_depth`` so an achieved depth can
    #: always be reported for any permitted configuration.
    max_depth: Annotated[int, Field(ge=0, le=16)]
    #: Set only when the optional model-candidate path ran.  Describes the
    #: *consumed* provider; never a prompt, payload or credential.
    candidate_provider: Annotated[str, Field(max_length=48)] | None = None
    candidate_model: Annotated[str, Field(max_length=48)] | None = None
    candidate_proposed_count: Annotated[int, Field(default=0, ge=0)]
    candidate_accepted_count: Annotated[int, Field(default=0, ge=0)]
    candidate_rejected_count: Annotated[int, Field(default=0, ge=0)]
    unavailable_inputs: dict[str, str] = Field(default_factory=dict)
    limitations: list[PlaybookLimitation] = Field(default_factory=list, max_length=32)
    provenance: PlaybookProvenance = Provenance.AI_GENERATED


class Playbook(BaseModel):
    """A proposed response playbook.

    Contains no field capable of asserting that anything was executed.  The
    lifecycle starts at ``proposed`` or ``approval_required`` and the engine has
    no transition out of either.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    playbook_id: uuid.UUID
    correlation_id: uuid.UUID
    status: PlaybookStatus
    lifecycle: PlaybookLifecycle
    steps: list[PlaybookStep] = Field(default_factory=list, max_length=64)
    limitations: list[PlaybookLimitation] = Field(default_factory=list, max_length=32)
    provenance: PlaybookProvenance = Provenance.AI_GENERATED

    @property
    def actions(self) -> list[PlaybookAction]:
        """Every action in step order."""
        return [action for step in self.steps for action in step.actions]

    @model_validator(mode="after")
    def _generated_lifecycle_only(self) -> "Playbook":
        """The generator cannot emit a post-generation lifecycle state.

        This is the enforcement point for "PROPOSED ≠ APPROVED ≠ EXECUTED ≠
        VERIFIED".  ``APPROVED`` through ``VERIFIED`` are rejected here, so
        marking a generated playbook as approved or executed requires editing
        this contract — not merely finding a code path that forgot a check.
        """
        if self.lifecycle not in GENERATED_LIFECYCLES:
            raise ValueError(
                f"lifecycle {self.lifecycle.value!r} is not a generation outcome; a "
                "generated playbook is either 'proposed' or 'approval_required'. "
                "Approval, execution and verification belong to downstream systems."
            )
        return self

    @model_validator(mode="after")
    def _dependency_graph_is_a_dag(self) -> "Playbook":
        """Validate the action dependency graph and step numbering.

        A cycle is rejected rather than broken, and step dependencies are derived
        from the action edges so the two orderings cannot disagree.
        """
        actions = self.actions
        ids = [action.action_id for action in actions]
        edges: dict[uuid.UUID, list[uuid.UUID]] = {
            action.action_id: [
                dependency.depends_on_action_id for dependency in action.depends_on
            ]
            for action in actions
        }
        if ids:
            for action in actions:
                for dependency in action.depends_on:
                    if dependency.depends_on_action_id == action.action_id:
                        raise DependencyCycleError("an action cannot depend on itself")
            # Raises on a cycle or an unknown dependency.
            topological_order(ids, edges)

        # Step structure is checked unconditionally, including for a playbook with
        # no actions.  An INSUFFICIENT_EVIDENCE result legitimately has zero
        # actions, and returning early here would let it carry a malformed step
        # sequence that no other validator would look at.
        numbers = [step.step_number for step in self.steps]
        if numbers != sorted(numbers) or len(set(numbers)) != len(numbers):
            raise ValueError("playbook steps must be numbered uniquely and in order")
        known_steps = set(numbers)
        for step in self.steps:
            for dependency in step.depends_on_steps:
                if dependency not in known_steps:
                    raise DependencyCycleError(
                        f"step {step.step_number} depends on unknown step {dependency}"
                    )
                if dependency >= step.step_number:
                    raise DependencyCycleError(
                        f"step {step.step_number} depends on step {dependency}, which "
                        "does not precede it"
                    )
        return self

    @model_validator(mode="after")
    def _approval_requirement_drives_lifecycle(self) -> "Playbook":
        """A playbook containing an approval-requiring action must say so.

        Otherwise a plan carrying ``ISOLATE_ENDPOINT`` could present itself as
        merely ``proposed``, understating the human gate an analyst must pass.
        """
        needs_approval = any(
            action.approval.requirement is ApprovalRequirement.APPROVAL_REQUIRED
            for action in self.actions
        )
        if needs_approval and self.lifecycle is not PlaybookLifecycle.APPROVAL_REQUIRED:
            raise ValueError(
                "a playbook containing an approval-requiring action must be in the "
                "'approval_required' lifecycle"
            )
        if not needs_approval and self.lifecycle is PlaybookLifecycle.APPROVAL_REQUIRED:
            raise ValueError(
                "no action requires approval, so the playbook must not claim to be "
                "waiting for approval"
            )
        return self

    @model_validator(mode="after")
    def _insufficient_evidence_carries_no_actions(self) -> "Playbook":
        """An empty playbook may not smuggle actions in."""
        if self.status is PlaybookStatus.INSUFFICIENT_EVIDENCE and self.actions:
            raise ValueError(
                "a playbook reported INSUFFICIENT_EVIDENCE must not carry actions"
            )
        return self


class PlaybookResult(BaseModel):
    """The complete output of one generation run.

    ``status`` is the session-level outcome.  A run that legitimately declines to
    propose anything reports ``INSUFFICIENT_EVIDENCE`` with zero steps and
    explicit gaps — that is a success, not an error.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    playbook_id: uuid.UUID
    correlation_id: uuid.UUID
    status: PlaybookStatus
    lifecycle: PlaybookLifecycle
    playbook: Playbook
    uncertainty: PlaybookUncertainty
    current_state: list[ActionEvidence] = Field(default_factory=list, max_length=64)
    metadata: PlaybookMetadata
    limitations: list[PlaybookLimitation] = Field(default_factory=list, max_length=32)
    execution_note: BoundedText = Field(
        ...,
        description=(
            "Always-present statement that this playbook is proposed, not executed."
        ),
    )
    provenance: PlaybookProvenance = Provenance.AI_GENERATED

    @model_validator(mode="after")
    def _identities_agree(self) -> "PlaybookResult":
        if self.playbook.playbook_id != self.playbook_id:
            raise ValueError("playbook_id disagrees with the embedded playbook")
        if self.playbook.correlation_id != self.correlation_id:
            raise ValueError("correlation_id disagrees with the embedded playbook")
        if self.playbook.lifecycle is not self.lifecycle:
            raise ValueError("lifecycle disagrees with the embedded playbook")
        if self.playbook.status is not self.status:
            raise ValueError("status disagrees with the embedded playbook")
        return self

    @model_validator(mode="after")
    def _bound_is_enforced_before_persistence(self) -> "PlaybookResult":
        """Reject an over-long plan rather than truncating it.

        A silently shortened playbook would be indistinguishable from a complete
        one, which is precisely the failure this bound exists to prevent.
        """
        bounds: PlaybookBounds = DEFAULT_PLAYBOOK_BOUNDS
        action_count = len(self.playbook.actions)
        if action_count > bounds.max_final_actions:
            raise ValueError(
                f"generated {action_count} actions, exceeding max_final_actions="
                f"{bounds.max_final_actions}; a plan is rejected rather than truncated"
            )
        if len(self.playbook.steps) > bounds.max_steps:
            raise ValueError(
                f"generated {len(self.playbook.steps)} steps, exceeding max_steps="
                f"{bounds.max_steps}"
            )
        for action in self.playbook.actions:
            if len(action.evidence) > bounds.max_evidence_references_per_action:
                raise ValueError(
                    f"action {action.action.value} cites {len(action.evidence)} "
                    "references, exceeding max_evidence_references_per_action"
                )
        return self


class PlaybookFailureResponse(BaseModel):
    """Governed failure payload.

    Shaped by the same contract family as the success payload, so a client can
    never receive a playbook-shaped response for a run that failed.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    correlation_id: uuid.UUID | None = None
    playbook_id: uuid.UUID | None = None
    status: Literal["failed"] = "failed"
    failure_code: BoundedShort
    detail: BoundedShort
    provenance: PlaybookProvenance = Provenance.AI_GENERATED


class PlaybookSummary(BaseModel):
    """Compact projection used by the correlation-scoped listing."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    playbook_id: uuid.UUID
    correlation_id: uuid.UUID
    status: PlaybookStatus
    lifecycle: PlaybookLifecycle
    action_count: Annotated[int, Field(ge=0)]
    step_count: Annotated[int, Field(ge=0)]
    approval_required_count: Annotated[int, Field(ge=0)]
    not_executable_count: Annotated[int, Field(ge=0)]
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    prediction_session_id: Annotated[str, Field(max_length=64)] | None = None
    provenance: PlaybookProvenance = Provenance.AI_GENERATED


class PlaybookListResult(BaseModel):
    """Playbooks recorded for one correlation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    correlation_id: uuid.UUID
    playbooks: list[PlaybookSummary] = Field(default_factory=list, max_length=64)
    provenance: PlaybookProvenance = Provenance.AI_GENERATED


# ---------------------------------------------------------------------------
# Input contracts
# ---------------------------------------------------------------------------
#
# These describe everything the engine may read.  Assembling inputs separately
# from reasoning keeps generation pure: the engine takes a value, touches no
# database, clock or network, and returns a deterministic result.


class ResolvableTarget(BaseModel):
    """A target a persisted row actually identified.

    The value is structurally validated for its declared type, so a target present
    here is one the response layer could also accept.  ``reference`` is the
    pointer that justifies it — the value itself came from that persisted record,
    never from a model or a client.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_type: TargetType
    value: Annotated[str, Field(min_length=1, max_length=256)]
    reference: Reference
    #: True when the value came from a persisted threat-intelligence indicator,
    #: which is the strongest available provenance for a network target.
    from_indicator: bool = False

    @field_validator("value")
    @classmethod
    def _value_validates_for_its_type(cls, value: str, info) -> str:
        """Canonicalise the value and prove it could be acted on.

        Structural validation happens once, here, rather than being deferred to
        the action contract.  A target that survives this could be handed to the
        response layer unchanged, so no proposal can be generated for something
        the executor would immediately reject.
        """
        target_type = info.data.get("target_type")
        if isinstance(target_type, TargetType):
            try:
                return validate_target_value(target_type, value)
            except ValueError as exc:
                raise ValueError(
                    f"value is not a valid {target_type.value} target: {exc}"
                ) from exc
        return value


class AvailableReference(BaseModel):
    """A persisted source an action may cite."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    reference: Reference
    entity_kind: Annotated[str, Field(min_length=1, max_length=64)]
    node_id: Reference


class PredictionSummary(BaseModel):
    """The parts of a V3.24 prediction the playbook engine may read.

    A prediction may justify preparation.  It may not, alone, justify a
    disruptive action — an invariant the contract enforces on every action rather
    than trusting the engine to remember it.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    prediction_session_id: uuid.UUID
    prediction_id: uuid.UUID
    prediction_kind: Annotated[str, Field(max_length=64)]
    depth: Annotated[str, Field(max_length=32)]
    status: Annotated[str, Field(max_length=48)]
    target: Annotated[str, Field(max_length=128)]
    target_basis: Annotated[str, Field(max_length=64)]
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    supporting_references: list[Reference] = Field(default_factory=list, max_length=32)
    contradicting_references: list[Reference] = Field(default_factory=list, max_length=32)


class PredictionOverview(BaseModel):
    """The V3.24 session reduced to what V3.25 may consume."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    prediction_session_id: uuid.UUID
    status: Annotated[str, Field(max_length=48)]
    predictions: list[PredictionSummary] = Field(default_factory=list, max_length=32)
    unresolved_questions: list[BoundedShort] = Field(default_factory=list, max_length=32)
    evidence_gaps: list[BoundedShort] = Field(default_factory=list, max_length=32)


class DebateOverview(BaseModel):
    """The V3.23 debate reduced to what V3.25 may consume."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    debate_id: uuid.UUID
    consensus_state: Annotated[str, Field(max_length=48)]
    consensus_strength: Annotated[float, Field(ge=0.0, le=1.0)]
    unresolved_questions: list[BoundedShort] = Field(default_factory=list, max_length=32)
    evidence_gaps: list[BoundedShort] = Field(default_factory=list, max_length=32)
    dissent_positions: list[BoundedShort] = Field(default_factory=list, max_length=32)


class PlaybookInputs(BaseModel):
    """Everything the engine is allowed to read, as an explicit value."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    correlation_id: uuid.UUID
    graph_snapshot_digest: Digest
    graph_node_count: Annotated[int, Field(ge=0)]
    graph_edge_count: Annotated[int, Field(ge=0)]
    graph_truncated: bool = False
    graph_truncated_reason: str | None = Field(default=None, max_length=128)
    established_evidence: dict[str, ActionEvidence] = Field(default_factory=dict)
    targets: dict[str, ResolvableTarget] = Field(default_factory=dict)
    prediction: PredictionOverview | None = None
    debate: DebateOverview | None = None
    untrusted_content_detected: bool = False
    unavailable_inputs: dict[str, str] = Field(default_factory=dict)
    bounds: PlaybookBounds = DEFAULT_PLAYBOOK_BOUNDS

    def established_reference_list(self) -> list[ActionEvidence]:
        """Established evidence in deterministic order."""
        return [self.established_evidence[key] for key in sorted(self.established_evidence)]

    def targets_for(self, target_type: TargetType) -> list[ResolvableTarget]:
        """Resolvable targets of one type, deterministically ordered."""
        return sorted(
            (
                target
                for target in self.targets.values()
                if target.target_type is target_type
            ),
            key=lambda target: (target.value, target.reference),
        )


__all__ = [
    "ActionApprovalRequirement",
    "ActionDependency",
    "ActionEvidence",
    "ActionRationale",
    "ActionRollback",
    "AvailableReference",
    "DebateOverview",
    "Playbook",
    "PlaybookAction",
    "PlaybookBounds",
    "PlaybookFailureResponse",
    "PlaybookId",
    "PlaybookInputs",
    "PlaybookLimitation",
    "PlaybookListResult",
    "PlaybookMetadata",
    "PlaybookProvenance",
    "PlaybookResult",
    "PlaybookStep",
    "PlaybookSummary",
    "PlaybookUncertainty",
    "PredictionOverview",
    "PredictionSummary",
    "ResolvableTarget",
    "validate_target_value",
]