"""The deterministic attack prediction engine — V3.24.

Answers exactly one question: *given the evidence-grounded security state we
actually hold, what future attack progression is plausible next?*

Design commitments, all enforced in code rather than documented as intent:

* **Pure.**  The engine takes a :class:`PredictionInputs` value and touches no
  database, clock, network, or model.  Identical inputs therefore always produce
  identical output — candidate ordering, prediction ids, evidence ordering,
  confidence, and final serialization (§16).

* **No LLM.**  V3.24 requires no provider call, so it is fully testable offline
  and cannot be degraded by a quota or outage (§14).  ``provider``/``model`` in
  the result metadata describe the *consumed debate*, never a call this engine
  made.  If a future version adds an LLM proposal stage, it must reuse the V3.23
  provider abstraction and pass through the same deterministic validation.

* **No successor model.**  There is no table mapping technique X to technique
  Y.  A stage is predicted only when persisted data or a resolved debate
  hypothesis *names* it.  This is what keeps "attackers usually do X next" out
  of the reasoning (§13).

* **Grounded or silent.**  A candidate with no resolvable persisted reference is
  never emitted.  When nothing qualifies, the engine returns a successful
  ``INSUFFICIENT_EVIDENCE`` session with explicit limitations rather than a
  guess (§10, §46).

* **Contradictions preserved.**  Contrary references are emitted alongside
  supporting ones and lower confidence or move the prediction to ``CONTESTED``.
  They are never suppressed or netted away (§12).

* **Bounded before output.**  Bounds are checked before any result is built, so
  an oversized input raises a governed error instead of silently truncating
  (§18).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from app.schemas.attack_prediction import (
    AttackPrediction,
    AttackTechnique,
    AvailableReference,
    DebateHypothesis,
    ObservedTechnique,
    PredictionEvidence,
    PredictionInputs,
    PredictionLimitation,
    PredictionMetadata,
    PredictionRationale,
    PredictionResult,
    PredictionUncertainty,
)
from app.services.prediction.exceptions import PredictionBoundsError
from app.services.prediction.vocabulary import (
    CONSENSUS_DEBATE_SUPPORT,
    CONTESTED_THRESHOLD,
    CONTRADICTION_PENALTY_PER_REFERENCE,
    CONFIDENCE_PRECISION,
    DEBATE_ONLY_CONFIDENCE_CEILING,
    ENGINE_VERSION,
    EVIDENCE_DIVERSITY_SATURATION,
    EVIDENCE_SUPPORT_SATURATION,
    LOW_CONFIDENCE_THRESHOLD,
    MAX_CONTRADICTION_PENALTY,
    NAMED_HYPOTHESIS_BONUS,
    STAGE_PRIORITY,
    STAGE_VOCABULARY,
    TARGET_SPECIFICITY,
    WEIGHT_EVIDENCE_DIVERSITY,
    WEIGHT_EVIDENCE_SUPPORT,
    WEIGHT_DEBATE_SUPPORT,
    WEIGHT_TARGET_SPECIFICITY,
    ConfidenceBasis,
    EvidenceStance,
    EvidenceSupport,
    LimitationKind,
    PredictionBasis,
    PredictionDepth,
    PredictionKind,
    PredictionStatus,
    StageVocabularyEntry,
    TargetBasis,
    confidence_band,
    deterministic_prediction_id,
    mentions_stage,
    prediction_configuration_digest,
)

#: Attached to every session.  Not a limitation the engine derives — a standing
#: statement of what the artifact is.
PREDICTIONS_ARE_NOT_EVIDENCE = (
    "Predictions are not evidence. This is a bounded analytical hypothesis about "
    "plausible future activity; it does not assert that any predicted activity occurred."
)

RAG_IS_NOT_EVIDENCE = (
    "RAG knowledge is contextual knowledge, not security evidence, and is never "
    "cited as support for a prediction."
)


def _clamp01(value: float) -> float:
    return 0.0 if value < 0.0 else 1.0 if value > 1.0 else value


def _round(value: float) -> float:
    """Round to the fixed confidence precision for serialization stability."""
    return round(value, CONFIDENCE_PRECISION)


class _Candidate:
    """An internal, validated prediction candidate.

    Not a public contract: it exists only between candidate discovery and
    confidence computation.  By construction every candidate already carries at
    least one resolvable persisted reference, so a candidate can never be
    emitted without grounding.
    """

    __slots__ = (
        "entry",
        "depth",
        "basis",
        "target_basis",
        "technique",
        "supporting",
        "contradicting",
        "named_hypothesis",
        "debate_agreement",
    )

    def __init__(
        self,
        *,
        entry: StageVocabularyEntry,
        depth: PredictionDepth,
        basis: PredictionBasis,
        target_basis: TargetBasis,
        technique: ObservedTechnique | None,
        supporting: list[PredictionEvidence],
        contradicting: list[PredictionEvidence],
        named_hypothesis: DebateHypothesis | None,
        debate_agreement: float | None,
    ) -> None:
        self.entry = entry
        self.depth = depth
        self.basis = basis
        self.target_basis = target_basis
        self.technique = technique
        self.supporting = supporting
        self.contradicting = contradicting
        self.named_hypothesis = named_hypothesis
        self.debate_agreement = debate_agreement

    @property
    def supporting_refs(self) -> tuple[str, ...]:
        return tuple(sorted({e.reference for e in self.supporting}))

    def evidence_support(self) -> EvidenceSupport:
        """Classify where this candidate's support resolves.

        ``PERSISTED_EVIDENCE`` when a persisted ATT&CK mapping backs the stage;
        ``MIXED`` when one exists alongside debate support; otherwise
        ``DEBATE_CLAIM`` when the only support is a debated interpretation, which
        is capped in confidence.
        """
        if self.basis is PredictionBasis.PERSISTED_ATTACK_MAPPING:
            return EvidenceSupport.PERSISTED_EVIDENCE
        if self.technique is not None:
            return EvidenceSupport.MIXED
        return EvidenceSupport.DEBATE_CLAIM


class _Discovery:
    """The outcome of candidate discovery: a horizon-limited set plus the truth.

    ``grounded_total`` is the number of distinct grounded stages found *before*
    the horizon was applied.  Keeping it is what lets the engine say "N grounded
    stages existed, the horizon emitted M" instead of quietly returning the
    truncated set as if it were everything.  A capped horizon that is not
    disclosed would misrepresent a bounded result as a complete one.
    """

    __slots__ = ("candidates", "grounded_total")

    def __init__(self, candidates: list[_Candidate], grounded_total: int) -> None:
        self.candidates = candidates
        self.grounded_total = grounded_total


class AttackPredictionEngine:
    """Deterministic, evidence-grounded prediction of plausible next progression.

    Stateless and reusable: it holds no mutable state, so concurrent calls cannot
    influence each other.
    """

    engine_version = ENGINE_VERSION

    # -- public entry point -------------------------------------------------

    def predict(self, inputs: PredictionInputs) -> PredictionResult:
        """Produce the deterministic prediction result for ``inputs``.

        Raises:
            PredictionBoundsError: an architectural bound was exceeded.  Checked
                before any result is constructed.
        """
        self._enforce_input_bounds(inputs)

        metadata = self._build_metadata(inputs)
        current_state = self._build_current_state(inputs)
        observed_ids = self._ordered_technique_ids(inputs)

        discovery = self._discover_candidates(inputs)
        candidates = discovery.candidates
        grounded_total = discovery.grounded_total
        predictions = self._materialize(inputs, candidates)

        limitations = list(metadata.limitations)
        if not predictions:
            # Declining to speculate is a correct outcome.  Say so explicitly,
            # with the reason, instead of emitting a narrative.
            limitations.append(
                PredictionLimitation(
                    kind=LimitationKind.INPUT_SOURCE_UNAVAILABLE,
                    detail=(
                        "No persisted ATT&CK mapping and no resolved debate hypothesis "
                        "names a plausible next stage, so no prediction was emitted. "
                        "The engine does not speculate from general attack knowledge."
                    ),
                )
            )
        elif grounded_total > len(candidates) or len(candidates) > len(predictions):
            # The horizon or the emission bound withheld candidates that were
            # genuinely grounded.  Reporting that is the whole point: an
            # undisclosed truncated set reads as "these were the only plausible
            # stages", which the evidence does not support.
            withheld = grounded_total - len(predictions)
            horizon = inputs.bounds.max_depth
            emission = inputs.bounds.max_predictions_emitted
            limitations.append(
                PredictionLimitation(
                    kind=LimitationKind.HORIZON_CAPPED,
                    detail=(
                        f"{grounded_total} grounded candidate stage(s) were found; "
                        f"the architectural horizon max_depth={horizon} and emission "
                        f"bound max_predictions_emitted={emission} permitted "
                        f"{len(predictions)} to be emitted, so {withheld} grounded "
                        "candidate(s) were withheld. The emitted set is explicitly "
                        "incomplete."
                    ),
                )
            )

        status = (
            PredictionStatus.PREDICTED
            if predictions
            else PredictionStatus.INSUFFICIENT_EVIDENCE
        )

        return PredictionResult(
            prediction_session_id=self.session_id(inputs),
            correlation_id=inputs.correlation_id,
            status=status,
            predictions=predictions,
            current_state=current_state,
            observed_techniques=observed_ids,
            metadata=metadata,
            limitations=limitations,
            limitations_note=PREDICTIONS_ARE_NOT_EVIDENCE,
        )

    def session_id(self, inputs: PredictionInputs) -> uuid.UUID:
        """Deterministic session identity for ``inputs``."""
        from app.services.prediction.vocabulary import deterministic_session_id

        return deterministic_session_id(
            correlation_id=inputs.correlation_id,
            graph_snapshot_digest=inputs.graph_snapshot_digest,
            debate_id=inputs.debate.debate_id if inputs.debate else None,
            configuration_digest=prediction_configuration_digest(inputs.bounds),
        )

    # -- bounds (§18) --------------------------------------------------------

    def _enforce_input_bounds(self, inputs: PredictionInputs) -> None:
        """Reject oversized inputs *before* producing anything.

        Raising rather than truncating is the point: a caller must never be able
        to mistake a clipped analysis for a complete one.
        """
        bounds = inputs.bounds
        if inputs.graph_node_count > bounds.max_graph_nodes:
            raise PredictionBoundsError(
                f"graph node count {inputs.graph_node_count} exceeds "
                f"max_graph_nodes={bounds.max_graph_nodes}"
            )
        if inputs.graph_edge_count > bounds.max_graph_edges:
            raise PredictionBoundsError(
                f"graph edge count {inputs.graph_edge_count} exceeds "
                f"max_graph_edges={bounds.max_graph_edges}"
            )
        if inputs.debate is not None and len(inputs.debate.hypotheses) > bounds.max_debate_claims:
            raise PredictionBoundsError(
                f"debate claim count {len(inputs.debate.hypotheses)} exceeds "
                f"max_debate_claims={bounds.max_debate_claims}"
            )
        if len(inputs.observed_techniques) > bounds.max_technique_observations:
            raise PredictionBoundsError(
                f"observed technique count {len(inputs.observed_techniques)} exceeds "
                f"max_technique_observations={bounds.max_technique_observations}"
            )

    # -- metadata ------------------------------------------------------------

    def _build_metadata(self, inputs: PredictionInputs) -> PredictionMetadata:
        limitations: list[PredictionLimitation] = []
        for surface, reason in sorted(inputs.unavailable_inputs.items()):
            limitations.append(
                PredictionLimitation(
                    kind=LimitationKind.INPUT_SOURCE_UNAVAILABLE,
                    detail=f"{surface} unavailable: {reason}",
                )
            )
        if inputs.graph_truncated:
            limitations.append(
                PredictionLimitation(
                    kind=LimitationKind.GRAPH_TRUNCATED,
                    detail=(
                        "the consumed V3.22 graph snapshot was truncated "
                        f"(reason={inputs.graph_truncated_reason or 'unspecified'}), "
                        "so some connected evidence was not available to this analysis"
                    ),
                )
            )
        if not inputs.observed_techniques:
            limitations.append(
                PredictionLimitation(
                    kind=LimitationKind.NO_PERSISTED_TECHNIQUE,
                    detail=(
                        "no persisted ATT&CK technique mapping exists on this "
                        "correlation's detections, so no predicted stage can carry "
                        "a technique id"
                    ),
                )
            )
        if inputs.debate is None:
            limitations.append(
                PredictionLimitation(
                    kind=LimitationKind.NO_DEBATE_ARTIFACT,
                    detail=(
                        "no persisted V3.23 debate was available for this correlation; "
                        "predictions rest on persisted evidence alone"
                    ),
                )
            )

        debate = inputs.debate
        return PredictionMetadata(
            engine_version=self.engine_version,
            prediction_configuration_digest=prediction_configuration_digest(inputs.bounds),
            graph_snapshot_digest=inputs.graph_snapshot_digest,
            debate_id=str(debate.debate_id) if debate else None,
            debate_consensus_state=debate.consensus_state if debate else None,
            debate_provider=debate.provider if debate else None,
            debate_model=debate.model if debate else None,
            graph_node_count=inputs.graph_node_count,
            graph_edge_count=inputs.graph_edge_count,
            observed_technique_count=len(inputs.observed_techniques),
            max_depth=inputs.bounds.max_depth,
            unavailable_inputs=dict(sorted(inputs.unavailable_inputs.items())),
            limitations=limitations,
        )

    def _build_current_state(self, inputs: PredictionInputs) -> list[PredictionEvidence]:
        """Persisted evidence defining the current state, in deterministic order.

        Ordered by ``(entity_kind, reference)`` so the projection is stable
        across runs and across insertion order.
        """
        items = [
            PredictionEvidence(
                reference=ref.reference,
                entity_kind=ref.entity_kind,
                node_id=ref.node_id,
                stance=EvidenceStance.SUPPORTING,
                detail="persisted evidence in the current security state",
            )
            for ref in inputs.available_references()
        ]
        items.sort(key=lambda e: (e.entity_kind, e.reference))
        return items

    def _ordered_technique_ids(self, inputs: PredictionInputs) -> list[str]:
        return sorted(inputs.observed_techniques)

    # -- candidate discovery (§10, §11, §13) --------------------------------

    def _discover_candidates(self, inputs: PredictionInputs) -> _Discovery:
        """Build grounded candidates, highest-priority stage first.

        A stage qualifies only when something in the database names it *and*
        that naming is traceable to at least one resolvable persisted reference.
        There is deliberately no fallback that constructs a candidate from
        attack knowledge alone.

        The returned set is already truncated to the horizon: at most
        ``max_depth`` candidates, the first ``IMMEDIATE`` and the second
        ``SUBSEQUENT``.  Truncating *here* rather than at materialization time
        is what guarantees no emitted prediction can carry a depth outside the
        horizon — assigning depths to the first two while still emitting the
        third would leave extra candidates claiming to be the immediate next
        stage, which is a different and contradictory claim.
        """
        candidates: dict[PredictionKind, _Candidate] = {}

        self._candidates_from_persisted_mappings(inputs, candidates)
        self._candidates_from_debate(inputs, candidates)

        if len(candidates) > inputs.bounds.max_candidate_predictions:
            raise PredictionBoundsError(
                f"{len(candidates)} grounded candidate stages exceeds "
                f"max_candidate_predictions="
                f"{inputs.bounds.max_candidate_predictions}"
            )

        ordered: list[_Candidate] = []
        for kind in STAGE_PRIORITY:
            candidate = candidates.get(kind)
            if candidate is not None:
                ordered.append(candidate)

        grounded_total = len(ordered)
        horizon = ordered[: inputs.bounds.max_depth]
        for index, candidate in enumerate(horizon):
            candidate.depth = (
                PredictionDepth.IMMEDIATE if index == 0 else PredictionDepth.SUBSEQUENT
            )
        return _Discovery(horizon, grounded_total)

    def _candidates_from_persisted_mappings(
        self,
        inputs: PredictionInputs,
        candidates: dict[PredictionKind, _Candidate],
    ) -> None:
        """Stages named by a persisted ATT&CK mapping on a real detection.

        A technique name is matched against the closed stage tokens.  Only
        techniques read from persisted detection rows are considered, and the
        resulting citation is the detection reference itself.
        """
        for technique_id in self._ordered_technique_ids(inputs):
            technique = inputs.observed_techniques[technique_id]
            label = technique.technique_name
            if not label:
                continue
            for kind in STAGE_PRIORITY:
                entry = STAGE_VOCABULARY[kind]
                if kind in candidates or not mentions_stage(label, entry):
                    continue
                supporting = self._evidence_for_refs(
                    inputs,
                    technique.supporting_refs,
                    stance=EvidenceStance.SUPPORTING,
                    detail=f"persisted ATT&CK mapping {technique_id} on this detection",
                    limit=inputs.bounds.max_evidence_references_per_prediction,
                )
                if not supporting:
                    # Unresolvable citations mean no grounding: skip rather than
                    # emit a prediction whose support cannot be followed.
                    continue
                candidates[kind] = _Candidate(
                    entry=entry,
                    depth=PredictionDepth.IMMEDIATE,
                    basis=PredictionBasis.PERSISTED_ATTACK_MAPPING,
                    target_basis=TargetBasis.PERSISTED_ATTACK_MAPPING,
                    technique=technique,
                    supporting=supporting,
                    contradicting=[],
                    named_hypothesis=None,
                    debate_agreement=None,
                )
                break

    def _candidates_from_debate(
        self,
        inputs: PredictionInputs,
        candidates: dict[PredictionKind, _Candidate],
    ) -> None:
        """Stages named by debate hypotheses whose citations resolve.

        A debate hypothesis is an *interpretation*, not a fact.  It can support a
        prediction but is treated as ``DEBATE_HYPOTHESIS`` basis and is capped in
        confidence unless persisted evidence also supports the stage.
        """
        debate = inputs.debate
        if debate is None:
            return
        if debate.consensus_state == "insufficient_evidence":
            # The debate itself declined to reason; nothing to lean on.
            return

        for kind in STAGE_PRIORITY:
            if kind in candidates:
                continue
            entry = STAGE_VOCABULARY[kind]
            named = [
                hypothesis
                for hypothesis in debate.hypotheses
                if mentions_stage(hypothesis.statement, entry)
            ]
            if not named:
                continue
            chosen = self._pick_hypothesis(named)
            supporting = self._evidence_for_refs(
                inputs,
                chosen.supporting_refs,
                stance=EvidenceStance.SUPPORTING,
                detail="cited by a debate hypothesis whose references resolve to persisted evidence",
                limit=inputs.bounds.max_evidence_references_per_prediction,
            )
            if not supporting:
                continue
            contradicting = self._evidence_for_refs(
                inputs,
                chosen.contesting_refs,
                stance=EvidenceStance.CONTRADICTING,
                detail="cited against this hypothesis by debate dissent or counterargument",
                limit=inputs.bounds.max_evidence_references_per_prediction,
            )
            supporting = [e for e in supporting if e.reference not in {c.reference for c in contradicting}]
            if not supporting:
                continue
            candidates[kind] = _Candidate(
                entry=entry,
                depth=PredictionDepth.IMMEDIATE,
                basis=PredictionBasis.DEBATE_HYPOTHESIS,
                target_basis=TargetBasis.DEBATE_REFERENCED,
                technique=None,
                supporting=supporting,
                contradicting=contradicting,
                named_hypothesis=chosen,
                debate_agreement=debate.consensus_strength,
            )

    def _pick_hypothesis(self, hypotheses: list[DebateHypothesis]) -> DebateHypothesis:
        """Choose deterministically among hypotheses naming the same stage.

        Highest confidence wins, ties broken by hypothesis id, so the choice never
        depends on list order.
        """
        return sorted(
            hypotheses,
            key=lambda h: (-h.confidence, h.hypothesis_id),
        )[0]

    def _evidence_for_refs(
        self,
        inputs: PredictionInputs,
        references: list[str],
        *,
        stance: EvidenceStance,
        detail: str,
        limit: int,
    ) -> list[PredictionEvidence]:
        """Resolve references to citations, dropping any that do not resolve.

        A fake or stale reference is dropped rather than trusted.  Dropping is
        silent by design *here* because it happens before any candidate exists:
        a stage whose entire citation set fails to resolve is discarded by the
        caller, so nothing is ever emitted ungrounded.
        """
        resolved: list[PredictionEvidence] = []
        for reference in sorted(dict.fromkeys(references)):
            available = inputs.evidence_refs.get(reference)
            if available is None:
                continue
            resolved.append(
                PredictionEvidence(
                    reference=available.reference,
                    entity_kind=available.entity_kind,
                    node_id=available.node_id,
                    stance=stance,
                    detail=detail,
                )
            )
            if len(resolved) >= limit:
                break
        return resolved

    # -- confidence (§17) ----------------------------------------------------

    def _confidence(self, candidate: _Candidate, inputs: PredictionInputs) -> tuple[float, dict[ConfidenceBasis, float]]:
        """Compute bounded, deterministic confidence for one candidate.

        ``confidence = clamp01(sum(weight * component) - contradiction_penalty)``
        with weights summing to 1.0 and every component in [0, 1], so the result
        is bounded by construction.  No sampled or clock-dependent term.
        """
        supporting_count = len(candidate.supporting)
        evidence_support = min(1.0, supporting_count / EVIDENCE_SUPPORT_SATURATION)

        distinct_kinds = len({e.entity_kind for e in candidate.supporting})
        evidence_diversity = min(1.0, distinct_kinds / EVIDENCE_DIVERSITY_SATURATION)

        debate_support = 0.0
        debate = inputs.debate
        if debate is not None:
            debate_support = CONSENSUS_DEBATE_SUPPORT.get(debate.consensus_state, 0.0)
            if candidate.named_hypothesis is not None:
                debate_support = min(1.0, debate_support + NAMED_HYPOTHESIS_BONUS)
            if candidate.basis is PredictionBasis.PERSISTED_ATTACK_MAPPING:
                # A persisted mapping supports the stage on its own; the debate is
                # corroboration, not the source.
                debate_support = max(debate_support, 0.0)

        specificity = TARGET_SPECIFICITY[candidate.target_basis.value]

        penalty = min(
            MAX_CONTRADICTION_PENALTY,
            CONTRADICTION_PENALTY_PER_REFERENCE * len(candidate.contradicting),
        )

        weighted = (
            WEIGHT_EVIDENCE_SUPPORT * evidence_support
            + WEIGHT_EVIDENCE_DIVERSITY * evidence_diversity
            + WEIGHT_DEBATE_SUPPORT * debate_support
            + WEIGHT_TARGET_SPECIFICITY * specificity
        )
        confidence = _clamp01(weighted - penalty)

        if candidate.evidence_support() is EvidenceSupport.DEBATE_CLAIM:
            # Debate words alone can never produce a confident prediction.
            confidence = min(confidence, DEBATE_ONLY_CONFIDENCE_CEILING)

        basis = {
            ConfidenceBasis.EVIDENCE_SUPPORT: _round(evidence_support),
            ConfidenceBasis.EVIDENCE_DIVERSITY: _round(evidence_diversity),
            ConfidenceBasis.DEBATE_SUPPORT: _round(debate_support),
            ConfidenceBasis.TARGET_SPECIFICITY: _round(specificity),
            ConfidenceBasis.CONTRADICTION_PENALTY: _round(penalty),
        }
        return _round(confidence), basis

    # -- materialization -----------------------------------------------------

    def _materialize(
        self,
        inputs: PredictionInputs,
        candidates: list[_Candidate],
    ) -> list[AttackPrediction]:
        """Turn validated candidates into contract-validated predictions."""
        emitted: list[AttackPrediction] = []
        for candidate in candidates:
            if len(emitted) >= inputs.bounds.max_predictions_emitted:
                break
            emitted.append(self._materialize_one(inputs, candidate))
        return emitted

    def _materialize_one(
        self,
        inputs: PredictionInputs,
        candidate: _Candidate,
    ) -> AttackPrediction:
        confidence, basis = self._confidence(candidate, inputs)
        support_kind = candidate.evidence_support()
        status = self._status(candidate, confidence)

        technique = self._technique(candidate)
        uncertainty = PredictionUncertainty(
            confidence=confidence,
            confidence_band=confidence_band(confidence),
            confidence_basis=basis,
            supporting_evidence=candidate.supporting,
            contradicting_evidence=candidate.contradicting,
            evidence_gaps=self._evidence_gaps(inputs),
            unresolved_questions=self._unresolved_questions(inputs),
            evidence_support=support_kind,
            limitations=self._limitations(inputs, candidate, confidence),
        )
        rationale = PredictionRationale(
            summary=self._summary(candidate, confidence),
            basis=candidate.basis,
            basis_detail=self._basis_detail(candidate),
            observed_techniques=self._ordered_technique_ids(inputs),
            debate_agreement=candidate.debate_agreement,
        )
        return AttackPrediction(
            prediction_id=deterministic_prediction_id(
                correlation_id=inputs.correlation_id,
                prediction_kind=candidate.entry.kind,
                depth=candidate.depth,
                target=candidate.entry.label,
                technique_id=candidate.technique.technique_id if candidate.technique else None,
                supporting_refs=candidate.supporting_refs,
                debate_id=inputs.debate.debate_id if inputs.debate else None,
            ),
            prediction_kind=candidate.entry.kind,
            depth=candidate.depth,
            status=status,
            target=candidate.entry.label,
            target_basis=candidate.target_basis,
            technique=technique,
            rationale=rationale,
            uncertainty=uncertainty,
        )

    def _status(self, candidate: _Candidate, confidence: float) -> PredictionStatus:
        if len(candidate.contradicting) >= CONTESTED_THRESHOLD:
            return PredictionStatus.CONTESTED
        if confidence < LOW_CONFIDENCE_THRESHOLD:
            return PredictionStatus.LOW_CONFIDENCE
        return PredictionStatus.PREDICTED

    def _technique(self, candidate: _Candidate) -> AttackTechnique:
        """Build the ATT&CK target, carrying forward only persisted identifiers."""
        if candidate.technique is not None:
            return AttackTechnique(
                technique_id=candidate.technique.technique_id,
                technique_name=candidate.technique.technique_name,
                tactic=candidate.technique.tactic,
                technique_id_reason=(
                    "carried forward from the persisted detection mapping that "
                    "names this stage"
                ),
            )
        return AttackTechnique(
            technique_id=None,
            technique_name=None,
            tactic=None,
            technique_id_reason=(
                "no persisted ATT&CK mapping names this predicted stage, so no "
                "technique id is asserted; the stage is a labelled category only"
            ),
        )

    def _limitations(
        self,
        inputs: PredictionInputs,
        candidate: _Candidate,
        confidence: float,
    ) -> list[PredictionLimitation]:
        limitations: list[PredictionLimitation] = [
            PredictionLimitation(
                kind=LimitationKind.NO_PERSISTED_ATTACK_MAPPING,
                detail=(
                    "no ATT&CK technique id is asserted for this stage because no "
                    "persisted mapping supplies one; ATT&CK identifiers are never "
                    "synthesized"
                ),
            )
        ]
        if candidate.technique is None:
            limitations.append(
                PredictionLimitation(
                    kind=LimitationKind.ANALYTICAL_INFERENCE_ONLY,
                    detail=(
                        "the stage label is inferred from named evidence rather than "
                        "from a persisted technique mapping"
                    ),
                )
            )
        if candidate.basis is PredictionBasis.DEBATE_HYPOTHESIS:
            # A debate-backed candidate always has a debate: this branch is only
            # reachable when one supplied the naming.  Reporting
            # NO_DEBATE_ARTIFACT here would be self-contradictory, so the kind is
            # chosen from the consensus that actually exists.
            consensus = inputs.debate.consensus_state if inputs.debate else None
            kind = (
                LimitationKind.DEBATE_CONTESTED
                if consensus == "contested"
                else LimitationKind.DEBATE_INSUFFICIENT_EVIDENCE
                if consensus == "insufficient_evidence"
                else LimitationKind.ANALYTICAL_INFERENCE_ONLY
            )
            detail = (
                "support rests on a debated interpretation rather than a persisted "
                "fact; a debate hypothesis can name a plausible stage but cannot "
                "establish that it occurred"
            )
            if consensus == "contested":
                detail = (
                    "support rests on a debate that did not reach consensus, so the "
                    "agents disagreed about whether this stage is plausible"
                )
            elif consensus == "insufficient_evidence":
                detail = (
                    "the debate itself concluded there was insufficient evidence, so "
                    "this stage rests on a hypothesis the debate did not endorse"
                )
            limitations.append(
                PredictionLimitation(kind=kind, detail=detail)
            )
        if len({e.entity_kind for e in candidate.supporting}) == 1:
            limitations.append(
                PredictionLimitation(
                    kind=LimitationKind.SINGLE_SOURCE_EVIDENCE,
                    detail=(
                        "all supporting citations resolve to a single kind of "
                        "persisted source, so independent corroboration is absent"
                    ),
                )
            )
        if not candidate.contradicting:
            limitations.append(
                PredictionLimitation(
                    kind=LimitationKind.NO_CONTRADICTING_EVIDENCE_AVAILABLE,
                    detail=(
                        "no contradicting evidence was available to weigh against "
                        "this prediction; absence of contradiction is not confirmation"
                    ),
                )
            )
        if inputs.debate is None:
            limitations.append(
                PredictionLimitation(
                    kind=LimitationKind.NO_DEBATE_ARTIFACT,
                    detail=(
                        "no V3.23 debate was available, so this prediction could not "
                        "be checked against competing interpretations"
                    ),
                )
            )
        return limitations

    def _evidence_gaps(self, inputs: PredictionInputs) -> list[str]:
        gaps: list[str] = sorted(inputs.unavailable_inputs.values())
        if inputs.debate is not None:
            gaps.extend(sorted(inputs.debate.evidence_gaps))
        if inputs.graph_truncated:
            gaps.append(
                "the consumed graph snapshot was truncated, so some connected "
                "evidence was not evaluated"
            )
        if not inputs.observed_techniques:
            gaps.append(
                "no persisted ATT&CK technique mapping exists for this correlation's "
                "detections, so predicted stages cannot be expressed as techniques"
            )
        gaps.append(RAG_IS_NOT_EVIDENCE)
        # Stable, bounded, no duplicates.
        return list(dict.fromkeys(gaps))[:32]

    def _unresolved_questions(self, inputs: PredictionInputs) -> list[str]:
        questions: list[str] = []
        if inputs.debate is not None:
            questions.extend(sorted(inputs.debate.unresolved_questions))
            questions.extend(
                f"open dissent: {position}" for position in sorted(inputs.debate.dissent_positions)
            )
        return list(dict.fromkeys(questions))[:32]

    def _summary(self, candidate: _Candidate, confidence: float) -> str:
        percent = round(confidence * 100)
        basis_text = (
            "a persisted ATT&CK mapping on this correlation's detections"
            if candidate.basis is PredictionBasis.PERSISTED_ATTACK_MAPPING
            else "a debate hypothesis whose citations resolve to persisted evidence"
        )
        return (
            f"{candidate.entry.label.capitalize()} is a plausible next stage "
            f"({percent}% prediction confidence), supported by {basis_text}. "
            "This is a prediction and does not assert that the activity occurred."
        )

    def _basis_detail(self, candidate: _Candidate) -> str:
        if candidate.basis is PredictionBasis.PERSISTED_ATTACK_MAPPING:
            technique_id = candidate.technique.technique_id if candidate.technique else None
            return (
                f"persisted ATT&CK technique {technique_id} is mapped on "
                f"{len(candidate.supporting)} detection citation(s) in this correlation"
            )
        if candidate.named_hypothesis is not None:
            return (
                "named by debate hypothesis "
                f"{candidate.named_hypothesis.hypothesis_id}, whose "
                f"{len(candidate.named_hypothesis.supporting_refs)} citation(s) "
                "resolve to persisted evidence"
            )
        return "supported by persisted evidence in the current security state"


__all__ = [
    "PREDICTIONS_ARE_NOT_EVIDENCE",
    "RAG_IS_NOT_EVIDENCE",
    "AttackPredictionEngine",
]