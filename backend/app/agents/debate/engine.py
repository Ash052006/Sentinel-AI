"""The V3.23 multi-agent debate engine.

Orchestration::

    bounded V3.22 graph
        -> EvidenceCatalog (closed, bounded set of citable references)
        -> engine-derived DebateFacts (facts are computed, never modelled)
        -> ROUND 0  shared evidence context        (no model call)
        -> ROUND 1  independent agent assessments (5 model calls)
        -> ROUND 2  cross-agent arguments          (5 model calls)
        -> ROUND 3  counterarguments / challenges  (5 model calls)
        -> ROUND 4  reconciliation -> consensus    (no model call)
        -> DebateSession

Design commitments, all enforced in code rather than convention:

**Facts are derived, not modelled.**  :mod:`app.agents.debate.evidence` computes
every ``DebateFact`` mechanically from the persisted V2 entities the graph
represents.  The model output contract has no field for a fact, so a provider
cannot assert one.

**Evidence references are closed.**  Every reference an agent may cite must
resolve through the :class:`EvidenceCatalog` built from the bounded graph.  A
fabricated identifier rejects the entire agent output rather than being dropped,
because a silently-dropped citation would hide the fabrication.

**Rounds are bounded and finite.**  Exactly the rounds in ``MODEL_ROUNDS`` run,
then reconciliation.  There is no loop condition a model can influence and no
path that adds a fifth round.

**Consensus and confidence are computed, not generated.**  Neither is
model-authored.  The leading hypothesis is selected from what agents actually
raised using deterministic tie-breaks, and confidence is a documented function
of agreement, evidence support, evidence completeness, and contradiction — so
the same structured input always yields the same result, and the result can be
audited without re-running the provider.

**A failure never becomes a debate.**  If an agent's output is malformed, cites
a fabricated reference, or the provider is unavailable, the engine raises a
governed failure.  There is no partial-consensus scoring over whichever agents
happened to succeed.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Callable

from pydantic import ValidationError

from app.agents.debate.evidence import (
    EvidenceCatalog,
    derive_evidence_gaps,
    derive_facts,
    graph_snapshot_digest,
)
from app.agents.debate.exceptions import (
    DebateBoundsError,
    DebateContextError,
    DebateEvidenceError,
    DebateModelOutputError,
    DebateModelValidationError,
    DebatePartialFailureError,
    DebateSecretSafetyError,
    failure_code,
)
from app.agents.debate.model_output import (
    DEBATE_ARGUMENTS_JSON_SCHEMA,
    DEBATE_ASSESSMENT_JSON_SCHEMA,
    DEBATE_COUNTERARGUMENTS_JSON_SCHEMA,
    DebateArgumentsOutput,
    DebateAssessmentOutput,
    DebateCounterargumentsOutput,
)
from app.agents.debate.prompt import (
    build_debate_prompt,
    render_evidence_catalog,
)
from app.agents.debate.runtime import DebateRuntime
from app.agents.debate.vocabulary import (
    CONFIDENCE_WEIGHT_AGREEMENT,
    CONFIDENCE_WEIGHT_COMPLETENESS,
    CONFIDENCE_WEIGHT_EVIDENCE_SUPPORT,
    CONTRADICTION_SATURATION,
    DEFAULT_BOUNDS,
    MAX_CONTRADICTION_PENALTY,
    MIN_EVIDENCE_COMPLETENESS_FOR_CONSENSUS,
    SUPPORTING_EVIDENCE_SATURATION,
    AgentRole,
    AgentRoleSpec,
    ArgumentStance,
    ClaimKind,
    ConsensusState,
    DebateBounds,
    DebateStatus,
    RoundKind,
    WeaknessKind,
    agent_roster,
    configuration_digest,
    deterministic_argument_id,
    deterministic_counterargument_id,
    deterministic_debate_id,
    deterministic_hypothesis_id,
    deterministic_observation_id,
    normalize_claim,
)
from app.agents.investigation._safety import assert_no_secrets
from app.schemas.debate import (
    AgentAssessment,
    ConsensusAssessment,
    DebateAgent,
    DebateArgument,
    DebateClaim,
    DebateCounterargument,
    DebateDissent,
    DebateMetadata,
    DebateRound,
    DebateSession,
    EvidenceReference,
    EvidenceScope,
)
from app.schemas.security_event import Provenance
from app.services.knowledge_graph.queries import BoundedGraph

logger = logging.getLogger(__name__)

#: Bumped only when the debate's structure changes in a way that makes previous
#: stored results non-comparable.  Recorded in metadata for auditability.
ENGINE_VERSION = "v3.23.0"

_AGENT_ID_PREFIX = "agent:"


def agent_id_for(role: AgentRole) -> str:
    """Stable agent identity string."""
    return f"{_AGENT_ID_PREFIX}{role.value}"


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


class DebateEngine:
    """Runs one bounded, deterministic multi-agent debate."""

    def __init__(
        self,
        *,
        runtime: DebateRuntime,
        bounds: DebateBounds = DEFAULT_BOUNDS,
        knowledge_provider: Callable[[], str] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if runtime is None:
            raise DebateContextError("a debate engine requires a runtime")
        self._runtime = runtime
        self._bounds = bounds
        self._knowledge_provider = knowledge_provider
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    @property
    def provider_name(self) -> str:
        return self._runtime.provider_name

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(
        self,
        graph: BoundedGraph,
        *,
        correlation_id: uuid.UUID,
        unavailable_entity_types: dict[str, str] | None = None,
    ) -> DebateSession:
        """Execute the bounded debate over *graph*."""
        if graph is None:
            raise DebateContextError("a debate requires a bounded graph")
        if len(graph.nodes) == 0:
            raise DebateContextError(
                "a debate requires at least one evidence entity; the supplied "
                "graph is empty"
            )

        roster = self._bounded_roster()
        bounds = self._bounds

        # -- ROUND 0: shared evidence context (no model call) -------------
        catalog = EvidenceCatalog.from_graph(graph, bounds=bounds)
        facts = derive_facts(graph, catalog)
        gaps = derive_evidence_gaps(catalog, unavailable_entity_types)
        catalog_json = render_evidence_catalog(catalog)
        snapshot_digest = graph_snapshot_digest(graph)

        rounds: list[DebateRound] = [
            DebateRound(
                round_number=0,
                round_kind=RoundKind.ROUND_ZERO,
                summary=(
                    f"Shared evidence context: {len(catalog)} citable "
                    f"references across {graph.node_count} graph entities, "
                    f"with {len(facts)} engine-derived facts."
                ),
                agent_ids=[agent_id_for(spec.role) for spec in roster],
            )
        ]

        agents = [
            DebateAgent(
                agent_id=agent_id_for(spec.role),
                role=spec.role,
                display_name=spec.display_name,
                objective=spec.objective,
                focus_node_types=list(spec.focus_node_types),
            )
            for spec in roster
        ]

        knowledge = self._knowledge_provider() if self._knowledge_provider else ""

        # -- ROUND 1: independent assessments ----------------------------
        assessments = self._round_one(roster, catalog, catalog_json, facts, knowledge)
        rounds.append(
            DebateRound(
                round_number=1,
                round_kind=RoundKind.ROUND_ONE,
                summary=(
                    f"{len(assessments)} agents produced independent "
                    f"assessments over the shared evidence."
                ),
                agent_ids=[a.agent_id for a in assessments],
            )
        )

        # -- ROUND 2: cross-agent arguments ------------------------------
        hypothesis_brief = _render_hypothesis_brief(assessments)
        arguments, unresolved_questions = self._round_two(
            roster, catalog, catalog_json, facts, knowledge, hypothesis_brief
        )
        rounds.append(
            DebateRound(
                round_number=2,
                round_kind=RoundKind.ROUND_TWO,
                summary=(
                    f"{len(arguments)} cross-agent arguments were raised against "
                    f"the hypotheses from round 1."
                ),
                agent_ids=[agent_id_for(spec.role) for spec in roster],
                argument_ids=[a.argument_id for a in arguments],
            )
        )

        # -- ROUND 3: counterarguments -----------------------------------
        argument_brief = _render_argument_brief(arguments)
        counterarguments = self._round_three(
            roster, catalog, catalog_json, facts, knowledge, argument_brief
        )
        rounds.append(
            DebateRound(
                round_number=3,
                round_kind=RoundKind.ROUND_THREE,
                summary=(
                    f"{len(counterarguments)} counterarguments challenged the "
                    f"arguments from round 2."
                ),
                agent_ids=[agent_id_for(spec.role) for spec in roster],
                counterargument_ids=[c.counterargument_id for c in counterarguments],
            )
        )

        # Computed exactly once.  The digest is both part of the deterministic
        # debate id and a recorded metadata field, so deriving it twice would
        # create a way for the recorded value and the id to disagree.
        config_digest = configuration_digest(
            bounds,
            tuple(s.role for s in roster),
            self._runtime.provider_name,
            self._runtime.model_name,
        )

        # -- ROUND 4: deterministic reconciliation -----------------------
        consensus, unresolved = self._reconcile(
            assessments=assessments,
            arguments=arguments,
            counterarguments=counterarguments,
            catalog=catalog,
            evidence_gaps=gaps,
            unresolved_questions=unresolved_questions,
        )
        rounds.append(
            DebateRound(
                round_number=4,
                round_kind=RoundKind.ROUND_FOUR,
                summary=(
                    f"Reconciliation produced {consensus.state.value} at "
                    f"confidence {consensus.confidence:.2f} with "
                    f"{len(consensus.dissent)} recorded dissent entr"
                    f"{'y' if len(consensus.dissent) == 1 else 'ies'}."
                ),
            )
        )

        session = DebateSession(
            debate_id=deterministic_debate_id(
                correlation_id, snapshot_digest, config_digest
            ),
            correlation_id=correlation_id,
            status=DebateStatus.COMPLETED,
            agents=agents,
            facts=facts,
            assessments=assessments,
            arguments=arguments,
            counterarguments=counterarguments,
            rounds=rounds,
            consensus=consensus,
            evidence_scope=EvidenceScope(
                correlation_id=str(correlation_id),
                graph_node_count=graph.node_count,
                graph_edge_count=graph.edge_count,
                evidence_reference_count=len(catalog),
                node_type_counts=catalog.kind_counts(),
                graph_truncated=bool(graph.truncated),
                graph_truncated_reason=graph.truncated_reason,
                unavailable_entity_types=dict(unavailable_entity_types or {}),
            ),
            metadata=DebateMetadata(
                provider=self._runtime.provider_name,
                model=self._runtime.model_name,
                engine_version=ENGINE_VERSION,
                configuration_digest=config_digest,
                graph_snapshot_digest=snapshot_digest,
                graph_node_count=graph.node_count,
                graph_edge_count=graph.edge_count,
                agent_count=len(roster),
                max_rounds=bounds.max_rounds,
                observations_count=sum(len(a.observations) for a in assessments),
                hypotheses_count=sum(len(a.hypotheses) for a in assessments),
                arguments_count=len(arguments),
                counterarguments_count=len(counterarguments),
                prompt_bytes=len(catalog_json.encode("utf-8")),
                created_at=self._clock().isoformat(),
            ),
            limitations=gaps,
        )
        logger.info(
            "debate.completed correlation=%s state=%s confidence=%.3f "
            "agents=%d arguments=%d counterarguments=%d",
            correlation_id,
            consensus.state.value,
            consensus.confidence,
            len(agents),
            len(arguments),
            len(counterarguments),
        )
        return session

    # ------------------------------------------------------------------
    # Round implementations
    # ------------------------------------------------------------------

    def _bounded_roster(self) -> list[AgentRoleSpec]:
        roster = agent_roster()
        if len(roster) > self._bounds.max_agents:
            raise DebateBoundsError(
                f"the agent roster has {len(roster)} members which exceeds "
                f"max_agents={self._bounds.max_agents}"
            )
        return roster

    def _invoke(
        self,
        *,
        role: AgentRole,
        spec: AgentRoleSpec,
        round_kind: RoundKind,
        catalog_json: str,
        facts: list[Any],
        knowledge: str,
        prior_rounds_json: str,
        schema: dict[str, Any],
    ) -> dict[str, Any]:
        """Build a prompt, call the provider, parse strictly."""
        prompt = build_debate_prompt(
            role=role,
            spec=spec,
            round_kind=round_kind,
            catalog_json=catalog_json,
            facts=facts,
            prior_rounds_json=prior_rounds_json,
            knowledge_content=knowledge,
            bounds=self._bounds,
        )
        raw = self._runtime.complete(prompt, schema)
        return self._parse_strict(raw)

    @staticmethod
    def _parse_strict(raw_text: str) -> dict[str, Any]:
        """Strict JSON parse: no fences, no prose, no repair."""
        if not isinstance(raw_text, str):
            raise DebateModelOutputError("provider returned a non-string response")
        text = raw_text.strip()
        if not text:
            raise DebateModelOutputError(
                "model output is empty; it is rejected rather than treated as "
                "an assessment"
            )
        if len(text.encode("utf-8")) > DEFAULT_BOUNDS.max_model_output_bytes:
            raise DebateModelOutputError(
                "model output exceeds the configured size bound; it is "
                "rejected rather than truncated"
            )
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise DebateModelOutputError(
                f"model output is not strict JSON: {exc.msg}"
            ) from exc
        if not isinstance(parsed, dict):
            raise DebateModelOutputError(
                "model output must be a single JSON object; received "
                f"{type(parsed).__name__}"
            )
        return parsed

    @staticmethod
    def _assert_secret_free(payload: Any, label: str) -> None:
        try:
            assert_no_secrets(payload, label)
        except ValueError as exc:
            raise DebateSecretSafetyError(
                f"refusing to accept {label} containing credential-shaped content"
            ) from exc

    def _validate(self, model_cls: type, parsed: dict[str, Any], label: str) -> Any:
        try:
            output = model_cls.model_validate(parsed)
        except ValidationError as exc:
            raise DebateModelValidationError(
                f"{label} failed the output contract ({len(exc.errors())} "
                "issue(s)); the output is rejected rather than truncated"
            ) from exc
        self._assert_secret_free(output.model_dump_json(), label)
        return output

    def _round_one(
        self,
        roster: list[AgentRoleSpec],
        catalog: EvidenceCatalog,
        catalog_json: str,
        facts: list[Any],
        knowledge: str,
    ) -> list[AgentAssessment]:
        """Each agent assesses the shared evidence independently."""
        assessments: list[AgentAssessment] = []
        failures: list[tuple[str, Exception]] = []

        for spec in roster:
            try:
                parsed = self._invoke(
                    role=spec.role,
                    spec=spec,
                    round_kind=RoundKind.ROUND_ONE,
                    catalog_json=catalog_json,
                    facts=facts,
                    knowledge=knowledge,
                    prior_rounds_json="",
                    schema=DEBATE_ASSESSMENT_JSON_SCHEMA,
                )
                output = self._validate(
                    DebateAssessmentOutput, parsed, f"{spec.role.value} assessment"
                )
                assessments.append(
                    self._build_assessment(spec, output, catalog)
                )
            except Exception as exc:  # noqa: BLE001 - classified below
                logger.warning(
                    "debate agent failed in round 1: role=%s error=%s",
                    spec.role.value,
                    type(exc).__name__,
                )
                failures.append((spec.role.value, exc))
                if not isinstance(exc, Exception):  # pragma: no cover
                    raise

        if failures:
            raise _partial_failure(1, failures)
        # Debate-wide caps are enforced after the round so that a roster of
        # individually reasonable agents still cannot collectively overrun the
        # session budget. Failing here is deliberate: silently trimming claims
        # would drop reasoning the roster actually produced.
        self._check_roster_totals(assessments)
        return sorted(assessments, key=lambda a: a.role.value)

    def _check_roster_totals(self, assessments: list[AgentAssessment]) -> None:
        """Enforce the session-wide observation and hypothesis caps."""
        observations = sum(len(a.observations) for a in assessments)
        if observations > self._bounds.max_total_observations:
            raise DebateBoundsError(
                f"round 1 produced {observations} observations across the "
                f"roster which exceeds max_total_observations="
                f"{self._bounds.max_total_observations}"
            )
        hypotheses = sum(len(a.hypotheses) for a in assessments)
        if hypotheses > self._bounds.max_total_hypotheses:
            raise DebateBoundsError(
                f"round 1 produced {hypotheses} hypotheses across the roster "
                f"which exceeds max_total_hypotheses="
                f"{self._bounds.max_total_hypotheses}"
            )

    def _build_assessment(
        self,
        spec: AgentRoleSpec,
        output: DebateAssessmentOutput,
        catalog: EvidenceCatalog,
    ) -> AgentAssessment:
        """Resolve evidence references and assemble one agent's assessment.

        Any unresolvable reference raises, failing the whole assessment closed.
        """
        observations: list[DebateClaim] = []
        for item in output.observations:
            resolved = catalog.resolve_all(item.evidence_references)
            observations.append(
                DebateClaim(
                    claim_id=str(deterministic_observation_id(spec.role, item.statement)),
                    claim_kind=ClaimKind.OBSERVATION,
                    statement=item.statement,
                    evidence_references=resolved,
                    confidence=item.confidence,
                    provenance=Provenance.AI_GENERATED,
                    author_role=spec.role,
                )
            )
        if len(observations) > self._bounds.max_observations_per_agent:
            raise DebateBoundsError(
                f"{spec.role.value} returned {len(observations)} observations "
                f"which exceeds max_observations_per_agent="
                f"{self._bounds.max_observations_per_agent}"
            )

        hypotheses: list[DebateClaim] = []
        for item in output.hypotheses:
            resolved = catalog.resolve_all(item.evidence_references)
            hypotheses.append(
                DebateClaim(
                    claim_id=str(deterministic_hypothesis_id(item.statement)),
                    claim_kind=ClaimKind.HYPOTHESIS,
                    statement=item.statement,
                    evidence_references=resolved,
                    confidence=item.confidence,
                    provenance=Provenance.AI_GENERATED,
                    author_role=spec.role,
                )
            )
        if len(hypotheses) > self._bounds.max_hypotheses_per_agent:
            raise DebateBoundsError(
                f"{spec.role.value} returned {len(hypotheses)} hypotheses which "
                f"exceeds max_hypotheses_per_agent="
                f"{self._bounds.max_hypotheses_per_agent}"
            )

        cited = sorted(
            {
                ref.reference
                for claim in (*observations, *hypotheses)
                for ref in claim.evidence_references
            }
        )
        limitations = list(output.limitations.limitations)

        return AgentAssessment(
            agent_id=agent_id_for(spec.role),
            role=spec.role,
            objective=spec.objective,
            observations=sorted(observations, key=lambda c: (c.statement, c.claim_id)),
            hypotheses=sorted(hypotheses, key=lambda c: (c.statement, c.claim_id)),
            confidence=output.confidence,
            evidence_references=catalog.resolve_all(cited) if cited else [],
            limitations=limitations,
            provenance=Provenance.AI_GENERATED,
        )

    def _round_two(
        self,
        roster: list[AgentRoleSpec],
        catalog: EvidenceCatalog,
        catalog_json: str,
        facts: list[Any],
        knowledge: str,
        hypothesis_brief: str,
    ) -> tuple[list[DebateArgument], list[str]]:
        """Each agent argues for or against the hypotheses it was shown.

        Returns the arguments plus the questions agents reported as
        unanswerable from the available evidence.
        """
        valid_hypothesis_ids = _hypothesis_ids(hypothesis_brief)
        arguments: list[DebateArgument] = []
        unresolved_questions: set[str] = set()
        failures: list[tuple[str, Exception]] = []
        seen: set[str] = set()

        for spec in roster:
            try:
                parsed = self._invoke(
                    role=spec.role,
                    spec=spec,
                    round_kind=RoundKind.ROUND_TWO,
                    catalog_json=catalog_json,
                    facts=facts,
                    knowledge=knowledge,
                    prior_rounds_json=hypothesis_brief,
                    schema=DEBATE_ARGUMENTS_JSON_SCHEMA,
                )
                output = self._validate(
                    DebateArgumentsOutput, parsed, f"{spec.role.value} arguments"
                )
                unresolved_questions.update(output.unresolved_questions)
                for item in output.arguments:
                    if item.target_hypothesis_id not in valid_hypothesis_ids:
                        raise DebateEvidenceError(
                            f"{spec.role.value} targeted hypothesis_id "
                            f"{item.target_hypothesis_id!r} which was not raised "
                            "in round 1; the entire output is rejected"
                        )
                    resolved = catalog.resolve_all(item.evidence_references)
                    # The id must be derivable from the persisted fields, so it
                    # uses the normalized role rather than the raw agent-id
                    # string the model happened to supply.
                    target_role = _role_from_agent_id(item.target_agent_id)
                    argument = DebateArgument(
                        argument_id=str(
                            deterministic_argument_id(
                                round_kind=RoundKind.ROUND_TWO,
                                author_role=spec.role,
                                target_role=target_role,
                                target_hypothesis_id=item.target_hypothesis_id,
                                statement=item.statement,
                            )
                        ),
                        round_kind=RoundKind.ROUND_TWO,
                        author_agent_id=agent_id_for(spec.role),
                        author_role=spec.role,
                        target_agent_id=item.target_agent_id,
                        target_role=target_role,
                        target_hypothesis_id=item.target_hypothesis_id,
                        stance=ArgumentStance(item.stance),
                        statement=item.statement,
                        evidence_references=resolved,
                        provenance=Provenance.AI_GENERATED,
                    )
                    if argument.argument_id in seen:
                        continue
                    seen.add(argument.argument_id)
                    arguments.append(argument)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "debate agent failed in round 2: role=%s error=%s",
                    spec.role.value,
                    type(exc).__name__,
                )
                failures.append((spec.role.value, exc))

        if failures:
            raise _partial_failure(2, failures)
        if len(arguments) > self._bounds.max_total_arguments:
            raise DebateBoundsError(
                f"round 2 produced {len(arguments)} arguments which exceeds "
                f"max_total_arguments={self._bounds.max_total_arguments}"
            )
        questions = sorted(unresolved_questions)
        if len(questions) > self._bounds.max_unresolved_questions:
            raise DebateBoundsError(
                f"round 2 produced {len(questions)} unresolved questions which "
                f"exceeds max_unresolved_questions="
                f"{self._bounds.max_unresolved_questions}"
            )
        return sorted(arguments, key=lambda a: a.argument_id), questions

    def _round_three(
        self,
        roster: list[AgentRoleSpec],
        catalog: EvidenceCatalog,
        catalog_json: str,
        facts: list[Any],
        knowledge: str,
        argument_brief: str,
    ) -> list[DebateCounterargument]:
        """Each agent challenges the arguments it was shown."""
        valid_argument_ids = _argument_ids(argument_brief)
        counterarguments: list[DebateCounterargument] = []
        failures: list[tuple[str, Exception]] = []
        seen: set[str] = set()

        for spec in roster:
            try:
                parsed = self._invoke(
                    role=spec.role,
                    spec=spec,
                    round_kind=RoundKind.ROUND_THREE,
                    catalog_json=catalog_json,
                    facts=facts,
                    knowledge=knowledge,
                    prior_rounds_json=argument_brief,
                    schema=DEBATE_COUNTERARGUMENTS_JSON_SCHEMA,
                )
                output = self._validate(
                    DebateCounterargumentsOutput,
                    parsed,
                    f"{spec.role.value} counterarguments",
                )
                for item in output.counterarguments:
                    if item.target_argument_id not in valid_argument_ids:
                        raise DebateEvidenceError(
                            f"{spec.role.value} targeted argument_id "
                            f"{item.target_argument_id!r} which was not raised in "
                            "round 2; the entire output is rejected"
                        )
                    # Required and non-empty: this is what stops the skeptic
                    # from manufacturing doubt with nothing to point at.
                    resolved = catalog.resolve_all(item.evidence_references)
                    counterargument = DebateCounterargument(
                        counterargument_id=str(
                            deterministic_counterargument_id(
                                target_argument_id=uuid.UUID(
                                    item.target_argument_id
                                ),
                                author_role=spec.role,
                                statement=item.statement,
                            )
                        ),
                        round_kind=RoundKind.ROUND_THREE,
                        author_agent_id=agent_id_for(spec.role),
                        author_role=spec.role,
                        target_argument_id=item.target_argument_id,
                        weakness=WeaknessKind(item.weakness),
                        statement=item.statement,
                        evidence_references=resolved,
                        provenance=Provenance.AI_GENERATED,
                    )
                    if counterargument.counterargument_id in seen:
                        continue
                    seen.add(counterargument.counterargument_id)
                    counterarguments.append(counterargument)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "debate agent failed in round 3: role=%s error=%s",
                    spec.role.value,
                    type(exc).__name__,
                )
                failures.append((spec.role.value, exc))

        if failures:
            raise _partial_failure(3, failures)
        if len(counterarguments) > self._bounds.max_total_counterarguments:
            raise DebateBoundsError(
                f"round 3 produced {len(counterarguments)} counterarguments "
                f"which exceeds "
                f"max_total_counterarguments="
                f"{self._bounds.max_total_counterarguments}"
            )
        return sorted(counterarguments, key=lambda c: c.counterargument_id)

    # ------------------------------------------------------------------
    # ROUND 4 — deterministic reconciliation
    # ------------------------------------------------------------------

    def _reconcile(
        self,
        *,
        assessments: list[AgentAssessment],
        arguments: list[DebateArgument],
        counterarguments: list[DebateCounterargument],
        catalog: EvidenceCatalog,
        evidence_gaps: list[str],
        unresolved_questions: list[str],
    ) -> tuple[ConsensusAssessment, list[str]]:
        """Compute consensus, dissent, and confidence deterministically.

        Nothing here is model-authored.  The leading hypothesis is chosen by
        (distinct supporting agents, distinct supporting evidence, normalized
        statement) in that order — a total order, so the result never depends on
        iteration or model output order.
        """
        total_agents = len(assessments)

        # Group hypotheses raised in round 1 by normalized statement.
        groups: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"hypothesis_id": "", "statement": "", "roles": set(), "refs": set()}
        )
        for assessment in assessments:
            for claim in assessment.hypotheses:
                key = normalize_claim(claim.statement)
                entry = groups[key]
                if not entry["hypothesis_id"]:
                    entry["hypothesis_id"] = claim.claim_id
                    entry["statement"] = claim.statement
                entry["roles"].add(assessment.role)
                entry["refs"].update(
                    ref.reference for ref in claim.evidence_references
                )

        # Rank with a total order so ties never depend on dict ordering.
        ranked = sorted(
            groups.items(),
            key=lambda item: (
                -len(item[1]["roles"]),
                -len(item[1]["refs"]),
                item[0],
            ),
        )

        all_cited_refs: set[str] = {
            ref.reference
            for assessment in assessments
            for claim in (*assessment.observations, *assessment.hypotheses)
            for ref in claim.evidence_references
        }
        completeness = _clamp01(len(all_cited_refs) / max(1, len(catalog)))

        if not ranked or not all_cited_refs:
            # Nothing was actually cited by anyone: there is no basis for a
            # leading hypothesis, and reporting one would be inventing one.
            return (
                ConsensusAssessment(
                    state=ConsensusState.INSUFFICIENT_EVIDENCE,
                    leading_hypothesis=None,
                    leading_hypothesis_id=None,
                    supporting_arguments=[],
                    opposing_arguments=[],
                    consensus_strength=0.0,
                    confidence=0.0,
                    dissent=[],
                    unresolved_questions=sorted(unresolved_questions),
                    evidence_gaps=sorted(evidence_gaps),
                    evidence_references=[],
                ),
                sorted(unresolved_questions),
            )

        leading_key, leading = ranked[0]
        leading_id = leading["hypothesis_id"]
        supporting_roles: set[str] = {role.value for role in leading["roles"]}

        supporting = [
            a
            for a in arguments
            if a.target_hypothesis_id == leading_id
            and a.stance is ArgumentStance.SUPPORTS
        ]
        opposing = [
            a
            for a in arguments
            if a.target_hypothesis_id == leading_id
            and a.stance is ArgumentStance.OPPOSES
        ]
        supporting_argument_ids = {a.argument_id for a in supporting}
        contradicting_counterarguments = [
            c for c in counterarguments if c.target_argument_id in supporting_argument_ids
        ]

        # -- Confidence: documented, deterministic -------------------------
        agreement = _clamp01(len(supporting_roles) / max(1, total_agents))
        evidence_support = _clamp01(
            len(leading["refs"]) / SUPPORTING_EVIDENCE_SATURATION
        )
        contradiction = _clamp01(
            (len(opposing) + len(contradicting_counterarguments))
            / CONTRADICTION_SATURATION
        )
        raw = (
            CONFIDENCE_WEIGHT_AGREEMENT * agreement
            + CONFIDENCE_WEIGHT_EVIDENCE_SUPPORT * evidence_support
            + CONFIDENCE_WEIGHT_COMPLETENESS * completeness
        )
        confidence = _clamp01(
            raw * (1.0 - MAX_CONTRADICTION_PENALTY * contradiction)
        )
        consensus_strength = agreement

        # -- State ---------------------------------------------------------
        unresolved = sorted(unresolved_questions)
        if (
            len(supporting_roles) == total_agents
            and not opposing
            and not contradicting_counterarguments
            and not unresolved
            and completeness >= MIN_EVIDENCE_COMPLETENESS_FOR_CONSENSUS
        ):
            state = ConsensusState.CONSENSUS
        elif agreement > 0.5:
            state = ConsensusState.PARTIAL_CONSENSUS
        elif (
            completeness < MIN_EVIDENCE_COMPLETENESS_FOR_CONSENSUS
            and evidence_gaps
        ):
            # Agreement about thin evidence is not evidence of much; when the
            # graph is materially incomplete, say so rather than implying the
            # debate was well-founded.
            state = ConsensusState.INSUFFICIENT_EVIDENCE
        else:
            state = ConsensusState.CONTESTED

        # -- Dissent: every position that did not carry -------------------
        dissent: list[DebateDissent] = []
        for argument in opposing:
            dissent.append(
                DebateDissent(
                    dissent_id=str(
                        deterministic_counterargument_id(
                            target_argument_id=uuid.UUID(argument.argument_id),
                            author_role=argument.author_role,
                            statement=argument.statement,
                        )
                    ),
                    raised_by_role=argument.author_role,
                    position=argument.statement,
                    reason=(
                        f"opposes the leading hypothesis on "
                        f"{len(argument.evidence_references)} cited reference(s)"
                    ),
                    evidence_references=list(argument.evidence_references),
                )
            )
        for counterargument in contradicting_counterarguments:
            dissent.append(
                DebateDissent(
                    dissent_id=counterargument.counterargument_id,
                    raised_by_role=counterargument.author_role,
                    position=counterargument.statement,
                    reason=f"counterargument ({counterargument.weakness.value})",
                    evidence_references=list(counterargument.evidence_references),
                )
            )
        for key, entry in ranked[1:]:
            dissent.append(
                DebateDissent(
                    dissent_id=str(
                        deterministic_counterargument_id(
                            target_argument_id=uuid.UUID(entry["hypothesis_id"]),
                            author_role=AgentRole.SKEPTIC,
                            statement=f"alternative reading: {entry['statement']}",
                        )
                    ),
                    raised_by_role=AgentRole.SKEPTIC,
                    position=entry["statement"],
                    reason=(
                        f"alternative hypothesis supported by "
                        f"{len(entry['roles'])} of {total_agents} agents"
                    ),
                    evidence_references=catalog.resolve_all(sorted(entry["refs"]))
                    if entry["refs"]
                    else [],
                )
            )

        dissent = _dedupe_dissent(dissent)[: self._bounds.max_dissent_entries]

        consensus_refs = sorted(
            {
                ref.reference
                for argument in (*supporting, *opposing)
                for ref in argument.evidence_references
            }
        )

        consensus = ConsensusAssessment(
            state=state,
            leading_hypothesis=leading["statement"],
            leading_hypothesis_id=str(leading_id),
            supporting_arguments=supporting,
            opposing_arguments=opposing,
            consensus_strength=consensus_strength,
            confidence=confidence,
            dissent=dissent,
            unresolved_questions=unresolved,
            evidence_gaps=sorted(evidence_gaps),
            evidence_references=catalog.resolve_all(consensus_refs),
        )
        return consensus, unresolved


# ----------------------------------------------------------------------
# Brief rendering — deterministic, and the validation source of truth
# ----------------------------------------------------------------------


def _render_hypothesis_brief(assessments: list[AgentAssessment]) -> str:
    """Serialize the round-2 brief and record which ids are legitimate."""
    payload = []
    seen: set[str] = set()
    for assessment in sorted(assessments, key=lambda a: a.role.value):
        for claim in sorted(assessment.hypotheses, key=lambda c: c.claim_id):
            if claim.claim_id in seen:
                continue
            seen.add(claim.claim_id)
            payload.append(
                {
                    "hypothesis_id": claim.claim_id,
                    "raised_by_agent_id": assessment.agent_id,
                    "raised_by_role": assessment.role.value,
                    "statement": claim.statement,
                    "evidence_references": sorted(
                        ref.reference for ref in claim.evidence_references
                    ),
                }
            )
    return json.dumps(
        {"hypotheses": payload}, sort_keys=True, indent=2, default=str
    )


def _render_argument_brief(arguments: list[DebateArgument]) -> str:
    payload = [
        {
            "argument_id": argument.argument_id,
            "author_role": argument.author_role.value,
            "stance": argument.stance.value,
            "target_hypothesis_id": argument.target_hypothesis_id,
            "statement": argument.statement,
            "evidence_references": sorted(
                ref.reference for ref in argument.evidence_references
            ),
        }
        for argument in sorted(arguments, key=lambda a: a.argument_id)
    ]
    return json.dumps({"arguments": payload}, sort_keys=True, indent=2, default=str)


def _hypothesis_ids(brief_json: str) -> set[str]:
    """The hypothesis ids an agent was actually shown.

    Read back from the serialized brief so validation cannot drift from what
    the model was told.
    """
    payload = json.loads(brief_json)
    return {str(item["hypothesis_id"]) for item in payload.get("hypotheses", [])}


def _argument_ids(brief_json: str) -> set[str]:
    payload = json.loads(brief_json)
    return {str(item["argument_id"]) for item in payload.get("arguments", [])}


def _role_from_agent_id(agent_id: str) -> AgentRole:
    """Map an agent id string back to its role, failing closed."""
    candidate = str(agent_id).removeprefix(_AGENT_ID_PREFIX)
    for role in AgentRole:
        if role.value == candidate:
            return role
    raise DebateEvidenceError(
        f"target_agent_id {agent_id!r} is not a known debate agent"
    )


def _dedupe_dissent(entries: list[DebateDissent]) -> list[DebateDissent]:
    deduped: dict[str, DebateDissent] = {}
    for entry in entries:
        deduped.setdefault(entry.dissent_id, entry)
    return sorted(deduped.values(), key=lambda d: d.dissent_id)


__all__ = ["ENGINE_VERSION", "DebateEngine", "agent_id_for"]


def _partial_failure(
    round_number: int, failures: list[tuple[str, Exception]]
) -> DebatePartialFailureError:
    """Build a partial-failure error that preserves the underlying cause.

    ``failures`` is sorted by role so the reported cause is deterministic even
    when several agents fail for different reasons in the same round.
    """
    ordered = sorted(failures, key=lambda item: item[0])
    cause = ordered[0][1]
    return DebatePartialFailureError(
        f"one or more agents failed during round {round_number}; no consensus "
        f"is reported over a partial roster",
        failed_agents=tuple(role for role, _ in ordered),
        failure_code=failure_code(cause),
        cause=cause,
    )
