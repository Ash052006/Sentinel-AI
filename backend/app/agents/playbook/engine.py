"""Deterministic playbook generation — V3.25.

This is the reasoning step, and it is a *pure function*: it takes
:class:`PlaybookInputs`, touches no database, clock or network, and returns a
:class:`PlaybookResult`.  Reproducibility is the point — the same inputs produce
the same playbook, byte for byte, so a stored proposal can always be re-derived
and audited.

How a plan is built
-------------------

1. **Sufficiency.**  If nothing established can be resolved to a target, the run
   reports ``INSUFFICIENT_EVIDENCE`` with zero actions and explicit gaps.  That is
   a successful answer, not a failure: an honest "not enough to act on" is more
   useful than a thin plan built from a prediction.

2. **Candidate actions.**  For every action whose target type the persisted
   indicators can resolve, a candidate is built.  Each candidate carries the
   evidence that justifies it, and its capability, backend, approval requirement
   and rollback are read from the frozen table rather than chosen.

3. **Grounding.**  A candidate is grounded in established evidence when a
   persisted detection, indicator or correlation supports it.  When only a V3.24
   prediction supports it, the grounding is marked ``PREDICTION_SUPPORTED``, the
   confidence is capped, and the *destructive* ones are rejected outright — the
   action contract enforces that independently.

4. **Confidence.**  Computed from five weighted components less two capped
   penalties, then banded.  Every component is retained in the breakdown so the
   number can be recomputed by hand from the record.

5. **Ordering.**  Containment and prevention come before verification, and
   evidence preservation is forced ahead of anything that could destroy it.  The
   result is a DAG, topologically ordered, partitioned into numbered steps.

6. **Lifecycle.**  ``APPROVAL_REQUIRED`` if any action requires human
   authorization, otherwise ``PROPOSED``.  There is no third outcome, and no code
   here can mark a playbook approved or executed.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from app.schemas.playbook import (
    ActionApprovalRequirement,
    ActionDependency,
    ActionEvidence,
    ActionRationale,
    ActionRollback,
    DebateOverview,
    Playbook,
    PlaybookAction,
    PlaybookInputs,
    PlaybookLimitation,
    PlaybookMetadata,
    PlaybookResult,
    PlaybookStep,
    PlaybookUncertainty,
    PredictionOverview,
    ResolvableTarget,
)
from app.services.playbook.exceptions import (
    PlaybookBoundsError,
    PlaybookDependencyError,
)
from app.services.playbook.vocabulary import (
    CONTRADICTION_PENALTY_PER_REFERENCE,
    CONFIDENCE_PRECISION,
    DEFAULT_PLAYBOOK_BOUNDS,
    DEBATE_UNSETTLED_CONFIDENCE_CEILING,
    EVIDENCE_GAP_PENALTY_PER_GAP,
    EVIDENCE_SUPPORT_SATURATION,
    ENGINE_VERSION,
    MAX_CONTRADICTION_PENALTY,
    MAX_EVIDENCE_GAP_PENALTY,
    PREDICTION_ONLY_CONFIDENCE_CEILING,
    PRIORITY_ORDER,
    WEIGHT_CAPABILITY_AVAILABILITY,
    WEIGHT_DEBATE_AGREEMENT,
    WEIGHT_EVIDENCE_SUPPORT,
    WEIGHT_PREDICTION_SUPPORT,
    WEIGHT_TARGET_CERTAINTY,
    ActionCategory,
    ActionConfidenceBand,
    ActionPriority,
    ActionType,
    ApprovalRequirement,
    CapabilityStatus,
    DependencyKind,
    EvidenceSource,
    GroundingBasis,
    PlaybookBounds,
    PlaybookConfidenceComponent,
    PlaybookLifecycle,
    PlaybookLimitationKind,
    PlaybookStatus,
    action_spec,
    action_specs,
    approval_requirement_of,
    capability_of,
    clamp01,
    confidence_band,
    deterministic_action_id,
    deterministic_playbook_id,
    execution_backend_of,
    playbook_configuration_digest,
    topological_order,
)

#: Always present on every result.  A playbook that omits this would let a
#: consumer mistake a proposal for a record of work already done.
EXECUTION_NOTE = (
    "Proposed only. No action in this playbook has been executed, approved, or "
    "verified. Execution remains the responsibility of the policy decision "
    "engine, human approval, and the response layer."
)

#: Action categories whose actions must precede verification.
_PRE_VERIFICATION: frozenset[ActionCategory] = frozenset(
    {
        ActionCategory.CONTAINMENT,
        ActionCategory.PREVENTION,
        ActionCategory.ERADICATION,
        ActionCategory.RECOVERY,
    }
)

#: Categories considered "response", used for the verification dependency.
_RESPONSE_CATEGORIES: frozenset[ActionCategory] = frozenset(
    {
        ActionCategory.CONTAINMENT,
        ActionCategory.PREVENTION,
        ActionCategory.ERADICATION,
    }
)

#: Steps in output order.
_STEP_SEQUENCE: tuple[tuple[ActionCategory, str, str], ...] = (
    (
        ActionCategory.INVESTIGATION,
        "Evidence preservation and scoping",
        "Collect and preserve what is already observed before anything changes it.",
    ),
    (
        ActionCategory.CONTAINMENT,
        "Containment",
        "Limit ongoing impact on the resolved targets.",
    ),
    (
        ActionCategory.PREVENTION,
        "Prevention",
        "Stop recurrence at the affected boundaries.",
    ),
    (
        ActionCategory.ERADICATION,
        "Eradication",
        "Remove the cause once it is contained.",
    ),
    (
        ActionCategory.RECOVERY,
        "Recovery",
        "Restore affected capability.",
    ),
    (
        ActionCategory.VERIFICATION,
        "Verification",
        "Confirm the effect of the proposed actions.",
    ),
)


#: Actions that exist only to *undo* another action.
#:
#: The frozen table names exactly three: ``UNBLOCK_IP``, ``REENABLE_ACCOUNT`` and
#: ``RESTORE_ENDPOINT``.  They are reachable as rollback *metadata* on the action
#: they compensate, and that is the only place the deterministic generator puts
#: them.
#:
#: Emitting ``BLOCK_IP`` and ``UNBLOCK_IP`` as two consecutive forward actions
#: would produce a plan that reads "block it, then immediately unblock it" to
#: anything that walks the steps in order.  That defeats the containment the
#: block was proposed for.  Recovery is not a forward phase of a response; it is
#: a separate, human-initiated decision after verification, which is why it is
#: modelled as compensation rather than as the next step.
COMPENSATION_ACTIONS: frozenset[ActionType] = frozenset(
    spec.rollback_action
    for spec in action_specs().values()
    if spec.rollback_action is not None
)


# ---------------------------------------------------------------------------
# Implementation
# ---------------------------------------------------------------------------


@dataclass
class _Candidate:
    """One considered action, before ordering and step assignment."""

    action: ActionType
    target: ResolvableTarget
    evidence: list[ActionEvidence]
    grounding: GroundingBasis
    prediction_reference: str | None
    debate_reference: str | None
    confidence: float
    basis: dict[PlaybookConfidenceComponent, float]
    expected_outcome: str
    priority: ActionPriority
    verification_required: bool
    verification_method: str | None
    action_id: uuid.UUID = field(default_factory=uuid.uuid4)
    depends_on: list[ActionDependency] = field(default_factory=list)

    @property
    def spec(self):  # noqa: ANN201 - ActionSpec, imported lazily for readability
        return action_spec(self.action)


class PlaybookEngine:
    """Generates a proposed playbook from assembled inputs.

    Pure: construction takes only configuration.  Every decision the engine makes
    is a function of :class:`PlaybookInputs`, so two runs over identical inputs
    produce identical output — including action ids, step numbering and every
    reported confidence.
    """

    def __init__(
        self,
        *,
        bounds: PlaybookBounds = DEFAULT_PLAYBOOK_BOUNDS,
        allow_model_candidates: bool = False,
    ) -> None:
        self._bounds = bounds
        self._allow_model_candidates = allow_model_candidates

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    @property
    def configuration_digest(self) -> str:
        """Digest over everything that would change a result."""
        return playbook_configuration_digest(
            self._bounds,
            allow_model_candidates=self._allow_model_candidates,
        )

    def generate(self, inputs: PlaybookInputs) -> PlaybookResult:
        """Produce a proposed playbook, or an explicit refusal to."""
        configuration_digest = self.configuration_digest
        playbook_id = deterministic_playbook_id(
            correlation_id=inputs.correlation_id,
            graph_snapshot_digest=inputs.graph_snapshot_digest,
            debate_id=inputs.debate.debate_id if inputs.debate else None,
            prediction_id=(
                inputs.prediction.prediction_session_id
                if inputs.prediction
                else None
            ),
            configuration_digest=configuration_digest,
        )
        limitations = self._base_limitations(inputs)
        candidates = self._candidates(inputs, playbook_id)

        if not candidates:
            return self._insufficient(
                inputs, playbook_id, configuration_digest, limitations
            )

        self._enforce_candidate_bounds(candidates)
        actions = [self._materialise(candidate) for candidate in candidates]
        actions = self._order(actions)
        # Depth is checked *before* steps are built so the bound governs the
        # dependency structure rather than the step presentation, and it is
        # checked *after* ordering because ordering is what adds the implied
        # edges a reviewer would actually have to follow.
        forward_depth = self._enforce_depth(actions)
        steps = self._steps(actions)

        approval_required = any(
            action.approval.requirement is ApprovalRequirement.APPROVAL_REQUIRED
            for action in actions
        )
        lifecycle = (
            PlaybookLifecycle.APPROVAL_REQUIRED
            if approval_required
            else PlaybookLifecycle.PROPOSED
        )
        status = (
            PlaybookStatus.CONTESTED
            if self._is_contested(inputs, actions)
            else PlaybookStatus.PROPOSED
        )

        playbook = Playbook(
            playbook_id=playbook_id,
            correlation_id=inputs.correlation_id,
            status=status,
            lifecycle=lifecycle,
            steps=steps,
            limitations=limitations,
        )
        uncertainty = self._uncertainty(inputs, actions, status)
        metadata = PlaybookMetadata(
            engine_version=ENGINE_VERSION,
            playbook_configuration_digest=configuration_digest,
            graph_snapshot_digest=inputs.graph_snapshot_digest,
            debate_id=str(inputs.debate.debate_id) if inputs.debate else None,
            debate_consensus_state=(
                inputs.debate.consensus_state if inputs.debate else None
            ),
            prediction_session_id=(
                str(inputs.prediction.prediction_session_id)
                if inputs.prediction
                else None
            ),
            prediction_status=inputs.prediction.status if inputs.prediction else None,
            prediction_count=(
                len(inputs.prediction.predictions) if inputs.prediction else 0
            ),
            graph_node_count=inputs.graph_node_count,
            graph_edge_count=inputs.graph_edge_count,
            target_count=len(inputs.targets),
            max_depth=forward_depth,
            unavailable_inputs=inputs.unavailable_inputs,
            limitations=limitations,
        )
        return PlaybookResult(
            playbook_id=playbook_id,
            correlation_id=inputs.correlation_id,
            status=status,
            lifecycle=lifecycle,
            playbook=playbook,
            uncertainty=uncertainty,
            current_state=inputs.established_reference_list()[
                : self._bounds.max_evidence_references_per_action
            ],
            metadata=metadata,
            limitations=limitations,
            execution_note=EXECUTION_NOTE,
        )

    # ------------------------------------------------------------------
    # Step 1: sufficiency
    # ------------------------------------------------------------------

    def _insufficient(
        self,
        inputs: PlaybookInputs,
        playbook_id: uuid.UUID,
        configuration_digest: str,
        limitations: list[PlaybookLimitation],
    ) -> PlaybookResult:
        """Report that no grounded action could be proposed.

        A zero-action playbook with named gaps.  This is the honest outcome when
        the evidence does not resolve to an actionable target, and it is
        preferable to a plan whose confidence quietly rests on a prediction.
        """
        if not inputs.established_evidence:
            limitations.append(
                PlaybookLimitation(
                    kind=PlaybookLimitationKind.NO_ESTABLISHED_EVIDENCE,
                    detail=(
                        "no persisted detection, indicator or correlation record "
                        "was available to ground an action"
                    ),
                )
            )
        if not inputs.targets:
            limitations.append(
                PlaybookLimitation(
                    kind=PlaybookLimitationKind.NO_RESOLVABLE_TARGET,
                    detail=(
                        "no persisted indicator resolved to a target that passes "
                        "structural validation"
                    ),
                )
            )
        gaps = sorted(
            {
                *(inputs.debate.evidence_gaps if inputs.debate else []),
                *(inputs.prediction.evidence_gaps if inputs.prediction else []),
                "no established indicator resolved to an addressable target",
            }
        )[:32]
        questions = sorted(
            {
                *(inputs.debate.unresolved_questions if inputs.debate else []),
                *(inputs.prediction.unresolved_questions if inputs.prediction else []),
            }
        )[:32]
        uncertainty = PlaybookUncertainty(
            confidence=0.0,
            confidence_band=ActionConfidenceBand.VERY_LOW,
            confidence_basis={
                PlaybookConfidenceComponent.EVIDENCE_SUPPORT: 0.0,
                PlaybookConfidenceComponent.TARGET_CERTAINTY: 0.0,
                PlaybookConfidenceComponent.PREDICTION_SUPPORT: 0.0,
                PlaybookConfidenceComponent.DEBATE_AGREEMENT: 0.0,
                PlaybookConfidenceComponent.CAPABILITY_AVAILABILITY: 0.0,
                PlaybookConfidenceComponent.CONTRADICTION_PENALTY: 0.0,
                PlaybookConfidenceComponent.EVIDENCE_GAP_PENALTY: MAX_EVIDENCE_GAP_PENALTY,
            },
            supporting_evidence_count=len(inputs.established_evidence),
            contradicting_evidence_count=0,
            evidence_gaps=gaps,
            unresolved_questions=questions,
            conflicting_claims=[],
        )
        empty = Playbook(
            playbook_id=playbook_id,
            correlation_id=inputs.correlation_id,
            status=PlaybookStatus.INSUFFICIENT_EVIDENCE,
            lifecycle=PlaybookLifecycle.PROPOSED,
            steps=[],
            limitations=limitations,
        )
        metadata = PlaybookMetadata(
            engine_version=ENGINE_VERSION,
            playbook_configuration_digest=configuration_digest,
            graph_snapshot_digest=inputs.graph_snapshot_digest,
            debate_id=str(inputs.debate.debate_id) if inputs.debate else None,
            debate_consensus_state=(
                inputs.debate.consensus_state if inputs.debate else None
            ),
            prediction_session_id=(
                str(inputs.prediction.prediction_session_id)
                if inputs.prediction
                else None
            ),
            prediction_status=inputs.prediction.status if inputs.prediction else None,
            prediction_count=(
                len(inputs.prediction.predictions) if inputs.prediction else 0
            ),
            graph_node_count=inputs.graph_node_count,
            graph_edge_count=inputs.graph_edge_count,
            target_count=len(inputs.targets),
            # A zero-action playbook has no forward chain, so its measured depth
            # is 0 rather than 1.
            max_depth=0,
            unavailable_inputs=inputs.unavailable_inputs,
            limitations=limitations,
        )
        return PlaybookResult(
            playbook_id=playbook_id,
            correlation_id=inputs.correlation_id,
            status=PlaybookStatus.INSUFFICIENT_EVIDENCE,
            lifecycle=PlaybookLifecycle.PROPOSED,
            playbook=empty,
            uncertainty=uncertainty,
            current_state=inputs.established_reference_list()[
                : self._bounds.max_evidence_references_per_action
            ],
            metadata=metadata,
            limitations=limitations,
            execution_note=EXECUTION_NOTE,
        )

    # ------------------------------------------------------------------
    # Step 2/3: candidates and grounding
    # ------------------------------------------------------------------

    def _candidates(
        self,
        inputs: PlaybookInputs,
        playbook_id: uuid.UUID,
    ) -> list[_Candidate]:
        """Build one candidate per resolvable (action, target) pair."""
        candidates: list[_Candidate] = []
        occurrence: dict[tuple[ActionType, str], int] = {}

        for action in self._applicable_actions(inputs):
            for target in inputs.targets_for(action_spec(action).target_type):
                key = (action, target.reference)
                index = occurrence.get(key, 0)
                occurrence[key] = index + 1
                candidate = self._candidate(
                    inputs, action, target, playbook_id, index
                )
                if candidate is not None:
                    candidates.append(candidate)

        return sorted(
            candidates,
            key=lambda item: (item.action.value, item.target.value, str(item.action_id)),
        )

    def _applicable_actions(self, inputs: PlaybookInputs) -> list[ActionType]:
        """Which actions may appear as *forward* steps.

        Derived from the targets actually present rather than from a hand-written
        list, so an action becomes proposable automatically when a target of its
        type appears and never otherwise.

        Compensation actions are excluded unconditionally.  They describe undoing
        a forward action, so proposing one as a forward step would emit
        ``BLOCK_IP`` immediately followed by ``UNBLOCK_IP`` and hand a downstream
        reader a plan whose net effect is nothing.  A compensation action is still
        reachable — it is carried as rollback metadata on the action it undoes,
        which is where a reviewer looks for it.
        """
        present = {target.target_type for target in inputs.targets.values()}
        return [
            action
            for action in ActionType
            if action_spec(action).target_type in present
            and action not in COMPENSATION_ACTIONS
        ]

    def _candidate(
        self,
        inputs: PlaybookInputs,
        action: ActionType,
        target: ResolvableTarget,
        playbook_id: uuid.UUID,
        occurrence: int,
    ) -> _Candidate | None:
        """Build one candidate, or decline it.

        Returns ``None`` when the action cannot be grounded.  Two cases matter:

        * **No support at all.**  Nothing persisted refers to this target.  There
          is no proposal to make.
        * **Prediction-only support for a disruptive action.**  The action
          requires state to change on the strength of a projection.  Rejected
          here *and* independently by the action contract, so the rule holds even
          if this call site is bypassed.
        """
        supporting = self._supporting_evidence(inputs, target)
        prediction_reference = self._prediction_reference(inputs, target)
        if not supporting and prediction_reference is None:
            return None

        spec = action_spec(action)
        prediction_only = not supporting and prediction_reference is not None
        if prediction_only and spec.destructive:
            return None

        evidence = list(supporting)
        if prediction_reference is not None:
            evidence.append(
                ActionEvidence(
                    source=EvidenceSource.PREDICTION,
                    reference=f"{EvidenceSource.PREDICTION.value}:{prediction_reference}",
                    detail="projected continuation used for preparation only",
                    stance="supporting",
                )
            )
        grounding = (
            GroundingBasis.ESTABLISHED_EVIDENCE
            if supporting
            else GroundingBasis.PREDICTION_SUPPORTED
        )
        basis = self._confidence_basis(
            inputs, action, target, grounding, len(evidence)
        )
        confidence = self._confidence(basis, grounding, inputs)
        return _Candidate(
            action=action,
            target=target,
            evidence=evidence[: self._bounds.max_evidence_references_per_action],
            grounding=grounding,
            prediction_reference=prediction_reference,
            debate_reference=(
                f"{EvidenceSource.DEBATE_CLAIM.value}:{inputs.debate.debate_id}"
                if inputs.debate
                else None
            ),
            confidence=confidence,
            basis=basis,
            expected_outcome=(
                "the projected continuation does not materialise on this target"
                if prediction_only
                else "the observed indicators for this target stop recurring"
            ),
            priority=spec.base_priority,
            verification_required=spec.category
            in _RESPONSE_CATEGORIES | {ActionCategory.VERIFICATION},
            verification_method=(
                "confirm the threat indicators for this target are no longer observed"
                if spec.category in _RESPONSE_CATEGORIES
                else "confirm the requested artifacts are available"
            ),
            action_id=deterministic_action_id(
                playbook_id, action, target.reference, occurrence
            ),
        )

    @staticmethod
    def _supporting_evidence(
        inputs: PlaybookInputs,
        target: ResolvableTarget,
    ) -> list[ActionEvidence]:
        """Established evidence that actually concerns this target.

        Scoped deliberately.  The correlation as a whole is not support for every
        action: an indicator for one host does not justify blocking a different
        one.  The target's own reference is matched, plus the correlation-level
        records that establish that this cluster is under investigation at all.
        """
        correlation_sources = {
            EvidenceSource.DETECTION,
            EvidenceSource.CORRELATION,
            EvidenceSource.RISK_ASSESSMENT,
        }
        matched: list[ActionEvidence] = []
        for reference in sorted(inputs.established_evidence):
            evidence = inputs.established_evidence[reference]
            if evidence.reference == target.reference or evidence.source in correlation_sources:
                matched.append(evidence)
        return matched

    @staticmethod
    def _prediction_reference(
        inputs: PlaybookInputs,
        target: ResolvableTarget,
    ) -> str | None:
        """The prediction addressing this target, when one exists.

        Matched on the canonical target value so a prediction about
        ``198.51.100.7`` can support a plan for that same host, and no other.
        """
        if inputs.prediction is None:
            return None
        for prediction in inputs.prediction.predictions:
            if prediction.target == target.value:
                return str(prediction.prediction_id)
        return None

    # ------------------------------------------------------------------
    # Step 4: confidence
    # ------------------------------------------------------------------

    def _confidence_basis(
        self,
        inputs: PlaybookInputs,
        action: ActionType,
        target: ResolvableTarget,
        grounding: GroundingBasis,
        evidence_count: int,
    ) -> dict[PlaybookConfidenceComponent, float]:
        """Compute the five components and two penalties for one candidate."""
        contradicting = sum(
            1
            for item in self._supporting_evidence(inputs, target)
            if item.stance == "contradicting"
        )
        gaps = 0
        if inputs.debate is not None:
            gaps += len(inputs.debate.evidence_gaps)
        if inputs.prediction is not None:
            gaps += len(inputs.prediction.evidence_gaps)
        return {
            # Saturates: a third supporting reference adds nothing, which keeps a
            # large correlation from inflating confidence by sheer volume.
            PlaybookConfidenceComponent.EVIDENCE_SUPPORT: min(
                1.0, evidence_count / EVIDENCE_SUPPORT_SATURATION
            ),
            # A value straight from a persisted indicator is about as certain as a
            # target can get: it was normalised, deduplicated and persisted.
            PlaybookConfidenceComponent.TARGET_CERTAINTY: 1.0
            if target.from_indicator
            else 0.5,
            PlaybookConfidenceComponent.PREDICTION_SUPPORT: self._prediction_support(
                inputs, target
            ),
            PlaybookConfidenceComponent.DEBATE_AGREEMENT: self._debate_agreement(inputs),
            # 1.0 only when a provider exists for this specific action.  A
            # capability SentinelAI cannot perform must never look fully
            # supported, however good the evidence is.
            PlaybookConfidenceComponent.CAPABILITY_AVAILABILITY: 1.0
            if capability_of(action) is CapabilityStatus.AVAILABLE
            else 0.0,
            PlaybookConfidenceComponent.CONTRADICTION_PENALTY: min(
                MAX_CONTRADICTION_PENALTY,
                contradicting * CONTRADICTION_PENALTY_PER_REFERENCE,
            ),
            PlaybookConfidenceComponent.EVIDENCE_GAP_PENALTY: min(
                MAX_EVIDENCE_GAP_PENALTY, gaps * EVIDENCE_GAP_PENALTY_PER_GAP
            ),
        }

    @staticmethod
    def _prediction_support(
        inputs: PlaybookInputs, target: ResolvableTarget
    ) -> float:
        """Confidence of the prediction about this target, or zero."""
        if inputs.prediction is None:
            return 0.0
        for prediction in inputs.prediction.predictions:
            if prediction.target == target.value:
                return prediction.confidence
        return 0.0

    @staticmethod
    def _debate_agreement(inputs: PlaybookInputs) -> float:
        """Consensus strength, or zero when no debate was consumed."""
        if inputs.debate is None:
            return 0.0
        return inputs.debate.consensus_strength

    @staticmethod
    def _confidence(
        basis: dict[PlaybookConfidenceComponent, float],
        grounding: GroundingBasis,
        inputs: PlaybookInputs,
    ) -> float:
        """Combine the basis into one number, rounded for reproducibility."""
        weighted = (
            WEIGHT_EVIDENCE_SUPPORT * basis[PlaybookConfidenceComponent.EVIDENCE_SUPPORT]
            + WEIGHT_TARGET_CERTAINTY
            * basis[PlaybookConfidenceComponent.TARGET_CERTAINTY]
            + WEIGHT_PREDICTION_SUPPORT
            * basis[PlaybookConfidenceComponent.PREDICTION_SUPPORT]
            + WEIGHT_DEBATE_AGREEMENT * basis[PlaybookConfidenceComponent.DEBATE_AGREEMENT]
            + WEIGHT_CAPABILITY_AVAILABILITY
            * basis[PlaybookConfidenceComponent.CAPABILITY_AVAILABILITY]
            - basis[PlaybookConfidenceComponent.CONTRADICTION_PENALTY]
            - basis[PlaybookConfidenceComponent.EVIDENCE_GAP_PENALTY]
        )
        value = clamp01(weighted)
        if grounding is GroundingBasis.PREDICTION_SUPPORTED:
            value = min(value, PREDICTION_ONLY_CONFIDENCE_CEILING)
        if inputs.debate is not None and inputs.debate.consensus_state.lower() in {
            "partial",
            "contested",
            "no_consensus",
        }:
            value = min(value, DEBATE_UNSETTLED_CONFIDENCE_CEILING)
        return round(value, CONFIDENCE_PRECISION)

    def _uncertainty(
        self,
        inputs: PlaybookInputs,
        actions: list[PlaybookAction],
        status: PlaybookStatus,
    ) -> PlaybookUncertainty:
        """Aggregate the playbook-level uncertainty record.

        The playbook's own confidence is the mean of its actions', because a plan
        is only as well supported as its weakest significant step.  Recorded gaps
        and dissent are carried through verbatim rather than summarized away.
        """
        supporting = sum(
            len({item.reference for item in action.evidence if item.stance == "supporting"})
            for action in actions
        )
        contradicting = sum(
            len({item.reference for item in action.evidence if item.stance == "contradicting"})
            for action in actions
        )
        basis = dict(actions[0].confidence_basis) if actions else {}
        if actions:
            for component in basis:
                basis[component] = round(
                    sum(action.confidence_basis.get(component, 0.0) for action in actions)
                    / len(actions),
                    4,
                )
        confidence = round(
            sum(action.confidence for action in actions) / len(actions), 4
        )
        conflicting: list[str] = []
        if inputs.debate is not None:
            conflicting.extend(inputs.debate.dissent_positions)
        if inputs.prediction is not None and inputs.prediction.status.lower() == "contested":
            conflicting.append("the consumed prediction session is contested")
        return PlaybookUncertainty(
            confidence=confidence,
            confidence_band=confidence_band(confidence),
            confidence_basis=basis,
            supporting_evidence_count=supporting,
            contradicting_evidence_count=contradicting,
            evidence_gaps=sorted(
                {
                    *(inputs.debate.evidence_gaps if inputs.debate else []),
                    *(inputs.prediction.evidence_gaps if inputs.prediction else []),
                }
            )[:32],
            unresolved_questions=sorted(
                {
                    *(inputs.debate.unresolved_questions if inputs.debate else []),
                    *(inputs.prediction.unresolved_questions if inputs.prediction else []),
                }
            )[:32],
            conflicting_claims=sorted(set(conflicting))[:32],
        )

    # ------------------------------------------------------------------
    # Step 5: materialisation, ordering, steps
    # ------------------------------------------------------------------

    def _materialise(self, candidate: _Candidate) -> PlaybookAction:
        """Turn a candidate into a validated :class:`PlaybookAction`."""
        spec = candidate.spec
        capability = capability_of(candidate.action)
        approval = ActionApprovalRequirement(
            requirement=approval_requirement_of(candidate.action),
            reason=(
                "this action changes system state and requires human authorization "
                "under the response policy"
                if spec.requires_approval or capability.value == "available"
                else "no execution path exists for this capability"
            ),
            authorized_roles=["SOC_ANALYST"],
        )
        rollback = ActionRollback(
            rollback_supported=spec.rollback_supported,
            rollback_action=spec.rollback_action,
            reason=(
                "the inverse action is in the closed vocabulary and is proposed "
                "separately; it is never performed automatically"
                if spec.rollback_supported
                else "nothing in the closed vocabulary safely reverses this action"
            ),
        )
        return PlaybookAction(
            action_id=candidate.action_id,
            action=candidate.action,
            category=spec.category,
            target_type=spec.target_type,
            target_reference=candidate.target.reference,
            target_basis=(
                "persisted threat-intelligence indicator"
                if candidate.target.from_indicator
                else "validated indicator value"
            ),
            capability=capability,
            execution_backend=execution_backend_of(candidate.action),
            approval=approval,
            rollback=rollback,
            risk_level="high" if spec.destructive else "low",
            expected_outcome=candidate.expected_outcome,
            verification_required=candidate.verification_required,
            verification_method=candidate.verification_method,
            priority=candidate.priority,
            confidence=candidate.confidence,
            confidence_band=confidence_band(candidate.confidence),
            confidence_basis=candidate.basis,
            evidence=candidate.evidence,
            rationale=ActionRationale(
                summary=(
                    f"Propose {candidate.action.value} on {candidate.target.value}, "
                    f"grounded in {len(candidate.evidence)} persisted reference(s)."
                ),
                grounding=candidate.grounding,
                grounding_detail=(
                    "established persisted evidence names this target"
                    if candidate.grounding
                    is GroundingBasis.ESTABLISHED_EVIDENCE
                    else "only a projected continuation supports this target"
                ),
                priority_reason=(
                    f"base priority {spec.base_priority.value} for category "
                    f"{spec.category.value}, with approval "
                    f"{approval.requirement.value}"
                ),
                prediction_reference=(
                    f"{EvidenceSource.PREDICTION.value}:{candidate.prediction_reference}"
                    if candidate.prediction_reference
                    else None
                ),
                debate_reference=candidate.debate_reference,
            ),
            depends_on=candidate.depends_on,
        )

    def _order(self, actions: list[PlaybookAction]) -> list[PlaybookAction]:
        """Impose the safety ordering constraints.

        Two rules, both about not destroying evidence before capturing it:

        * investigation/collection precedes containment, prevention, eradication
          and recovery;
        * verification depends on every response action.

        Existing model-proposed edges are preserved and merged, so the engine
        only ever *adds* an ordering constraint it can justify.
        """
        by_category: dict[ActionCategory, list[PlaybookAction]] = {}
        for action in actions:
            by_category.setdefault(action.category, []).append(action)

        response_actions = [
            action
            for category in sorted(_RESPONSE_CATEGORIES, key=lambda c: c.value)
            for action in by_category.get(category, [])
        ]
        verification = by_category.get(ActionCategory.VERIFICATION, [])
        pre_response = [
            action
            for category in sorted(_PRE_VERIFICATION, key=lambda c: c.value)
            for action in by_category.get(category, [])
        ]
        investigation = by_category.get(ActionCategory.INVESTIGATION, [])

        edges: dict[uuid.UUID, list[ActionDependency]] = {
            action.action_id: list(action.depends_on) for action in actions
        }
        dependency_budget = self._bounds.max_dependencies
        for action in response_actions + pre_response:
            for source in investigation:
                if source.action_id == action.action_id:
                    continue
                if any(
                    item.depends_on_action_id == source.action_id
                    for item in edges[action.action_id]
                ):
                    continue
                if dependency_budget <= 0:
                    raise PlaybookBoundsError(
                        f"implied dependencies exceed max_dependencies="
                        f"{self._bounds.max_dependencies}"
                    )
                dependency_budget -= 1
                edges[action.action_id].append(
                    ActionDependency(
                        depends_on_action_id=source.action_id,
                        kind=DependencyKind.EVIDENCE_FIRST,
                        reason="preserve observed artifacts before changing state",
                    )
                )
        for action in verification:
            for source in response_actions:
                if source.action_id == action.action_id:
                    continue
                if any(
                    item.depends_on_action_id == source.action_id
                    for item in edges[action.action_id]
                ):
                    continue
                if dependency_budget <= 0:
                    raise PlaybookBoundsError(
                        f"implied dependencies exceed max_dependencies="
                        f"{self._bounds.max_dependencies}"
                    )
                dependency_budget -= 1
                edges[action.action_id].append(
                    ActionDependency(
                        depends_on_action_id=source.action_id,
                        kind=DependencyKind.CONTAINMENT_BEFORE_VERIFICATION,
                        reason="verify the effect of the proposed response",
                    )
                )

        # ``edges`` carries the annotated ``ActionDependency`` records the
        # contract stores; the traversal needs bare ids. Projecting here rather
        # than inline keeps the two shapes from being confused — passing the
        # records directly made every dependency look like an unknown action.
        traversal: dict[uuid.UUID, list[uuid.UUID]] = {
            action_id: [item.depends_on_action_id for item in items]
            for action_id, items in edges.items()
        }
        ordered_ids = topological_order(
            [action.action_id for action in actions], traversal
        )
        position = {action_id: index for index, action_id in enumerate(ordered_ids)}
        # Deterministic tie-break inside a topological layer.
        return sorted(
            (
                action.model_copy(update={"depends_on": edges[action.action_id]})
                for action in actions
            ),
            key=lambda action: (
                position[action.action_id],
                PRIORITY_ORDER[action.priority],
                action.action.value,
                str(action.action_id),
            ),
        )

    def _enforce_depth(self, actions: list[PlaybookAction]) -> int:
        """Reject a forward graph deeper than ``max_depth``.

        A hard safety bound, and one that raises rather than trims.  Dropping the
        deepest actions would produce a shorter plan that *looks* complete while
        quietly omitting containment the analyst expected to review, which is the
        exact failure mode the bound exists to prevent.  The remedy is a smaller
        or flatter plan, reached by changing the bounds or the inputs.
        """
        depth = self._forward_depth(actions)
        if depth > self._bounds.max_depth:
            raise PlaybookBoundsError(
                f"forward dependency depth {depth} exceeds max_depth="
                f"{self._bounds.max_depth}; refusing to truncate the playbook, "
                "because a shortened plan would read as a complete one"
            )
        return depth

    def _steps(self, actions: list[PlaybookAction]) -> list[PlaybookStep]:
        """Group the ordered actions into numbered steps."""
        steps: list[PlaybookStep] = []
        number = 0
        previous_numbers: list[int] = []
        by_category: dict[ActionCategory, list[PlaybookAction]] = {}
        for action in actions:
            by_category.setdefault(action.category, []).append(action)

        for category, name, purpose in _STEP_SEQUENCE:
            bucket = by_category.get(category)
            if not bucket:
                continue
            if len(steps) + 1 > self._bounds.max_steps:
                raise PlaybookBoundsError(
                    f"generated {len(steps) + 1} steps, exceeding max_steps="
                    f"{self._bounds.max_steps}"
                )
            number += 1
            steps.append(
                PlaybookStep(
                    step_number=number,
                    name=name,
                    purpose=purpose,
                    actions=bucket,
                    depends_on_steps=list(previous_numbers),
                )
            )
            previous_numbers.append(number)

        remaining = [
            action
            for category in sorted(
                (set(by_category) - {entry[0] for entry in _STEP_SEQUENCE}),
                key=lambda c: c.value,
            )
            for action in by_category[category]
        ]
        if remaining:
            number += 1
            steps.append(
                PlaybookStep(
                    step_number=number,
                    name="Additional actions",
                    purpose="Remaining proposals in the closed vocabulary.",
                    actions=remaining,
                    depends_on_steps=list(previous_numbers),
                )
            )
        return steps

    # ------------------------------------------------------------------
    # Bounds, limitations, misc
    # ------------------------------------------------------------------

    def _enforce_candidate_bounds(self, candidates: list[_Candidate]) -> None:
        """Reject an over-wide run rather than picking a subset.

        Choosing which candidates to keep would be a silent judgement about which
        evidence matters most — exactly the decision the generator should not be
        making on its own.
        """
        if len(candidates) > self._bounds.max_final_actions:
            raise PlaybookBoundsError(
                f"{len(candidates)} candidate actions exceed max_final_actions="
                f"{self._bounds.max_final_actions}; the run is refused rather than "
                "silently truncated"
            )

    @staticmethod
    def _base_limitations(inputs: PlaybookInputs) -> list[PlaybookLimitation]:
        """Limitations that describe the run itself, independent of its actions."""
        limitations: list[PlaybookLimitation] = []
        if inputs.graph_truncated:
            limitations.append(
                PlaybookLimitation(
                    kind=PlaybookLimitationKind.GRAPH_TRUNCATED,
                    detail=(
                        f"the V2 graph traversal was truncated "
                        f"({inputs.graph_truncated_reason or 'no reason recorded'}); "
                        "the plan may not cover every related entity"
                    ),
                )
            )
        if inputs.untrusted_content_detected:
            limitations.append(
                PlaybookLimitation(
                    kind=PlaybookLimitationKind.UNTRUSTED_CONTENT_QUARANTINED,
                    detail=(
                        "instruction-like text was detected in source labels and was "
                        "not propagated into this playbook"
                    ),
                )
            )
        if inputs.debate is None:
            limitations.append(
                PlaybookLimitation(
                    kind=PlaybookLimitationKind.DEBATE_ABSENT,
                    detail="no V3.23 debate was available to inform interpretation",
                )
            )
        elif inputs.debate.consensus_state.lower() in {"partial", "contested"}:
            limitations.append(
                PlaybookLimitation(
                    kind=(
                        PlaybookLimitationKind.DEBATE_PARTIAL_CONSENSUS
                        if inputs.debate.consensus_state.lower() == "partial"
                        else PlaybookLimitationKind.DEBATE_CONTESTED
                    ),
                    detail=(
                        "the consumed debate reached "
                        f"{inputs.debate.consensus_state}; confidence is capped and "
                        "dissenting positions are preserved"
                    ),
                )
            )
        if inputs.prediction is None:
            limitations.append(
                PlaybookLimitation(
                    kind=PlaybookLimitationKind.PREDICTION_ABSENT,
                    detail="no V3.24 prediction session was available",
                )
            )
        unavailable = sorted(inputs.unavailable_inputs)
        if unavailable:
            limitations.append(
                PlaybookLimitation(
                    kind=PlaybookLimitationKind.INPUT_SOURCE_UNAVAILABLE,
                    detail=(
                        f"{len(unavailable)} input source(s) unavailable or excluded: "
                        + ", ".join(unavailable[:8])
                    ),
                )
            )
        return limitations

    def _is_contested(
        self,
        inputs: PlaybookInputs,
        actions: list[PlaybookAction],
    ) -> bool:
        """Whether disagreement in the inputs warrants a ``CONTESTED`` status."""
        if inputs.debate is not None and inputs.debate.consensus_state.lower() == "contested":
            return True
        if inputs.prediction is not None and inputs.prediction.status.lower() == "contested":
            return True
        return any(action.contradicting_evidence for action in actions)

    @staticmethod
    def _forward_depth(actions: list[PlaybookAction]) -> int:
        """Longest dependency chain in the **forward** action graph.

        Depth is the number of actions on the longest path, so a lone action has
        depth 1 and ``A -> B -> C`` has depth 3.  It is *not* the action count:
        ``A -> B`` and ``A -> C`` is depth 2 however many actions follow.

        Rollback metadata is deliberately excluded.  Compensation is not a
        forward edge, so it must not consume depth budget or let a plan pass the
        bound that would fail if the same actions were chained forward.

        Deterministic and iterative: the graph is walked in topological order, so
        the result does not depend on set or dict iteration order, and a deep
        chain cannot exhaust the interpreter stack.
        """
        if not actions:
            return 0

        edges: dict[uuid.UUID, list[uuid.UUID]] = {
            action.action_id: [
                dependency.depends_on_action_id for dependency in action.depends_on
            ]
            for action in actions
        }
        order = topological_order([action.action_id for action in actions], edges)
        depth: dict[uuid.UUID, int] = {}
        for action_id in order:
            # ``order`` is topological, so every dependency is already resolved.
            dependencies = edges[action_id]
            depth[action_id] = 1 + max(
                (depth[dependency] for dependency in dependencies), default=0
            )
        return max(depth.values(), default=0)


__all__ = ["COMPENSATION_ACTIONS", "EXECUTION_NOTE", "PlaybookEngine"]