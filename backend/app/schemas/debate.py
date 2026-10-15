"""Multi-agent debate domain contracts — V3.23.

Strict Pydantic models for every semantic object a debate produces.  Every
model sets ``extra="forbid"`` so a provider, a serializer, or a future caller
cannot smuggle an unrepresentable field (an invented provenance, a fabricated
evidence object, an LLM "confidence" override) into a debate record.

Provenance rule (contract §21): every analytical object here is pinned to
``Provenance.AI_GENERATED``.  A debate conclusion is reasoning *over* evidence,
never the evidence itself, so it must never serialize as ``observed``,
``detected``, ``correlated``, or ``risk_assessed``.  Those values belong to the
V2 entities that genuinely produced them, and reusing one here would corrupt
its meaning.  ``ai_generated`` already means exactly this — a conclusion
inferred by an AI reasoning process — and using it requires no change to any
V2 table or its CHECK constraints.

``FACT`` claims are engine-derived (see :mod:`app.agents.debate.evidence`) and
are modelled here with ``ClaimKind.FACT``.  No model may emit that kind.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.agents.debate.vocabulary import (
    DEFAULT_BOUNDS,
    AgentRole,
    ArgumentStance,
    ClaimKind,
    ConsensusState,
    DebateStatus,
    RoundKind,
    WeaknessKind,
)
from app.schemas.security_event import Provenance

#: Bounded identifier string (a uuid5 rendered as text, or a bounded label).
BoundedId = Annotated[str, Field(min_length=1, max_length=128)]
BoundedText = Annotated[str, Field(min_length=1, max_length=1024)]
BoundedShortText = Annotated[str, Field(min_length=1, max_length=256)]


def _require_non_blank(value: str) -> str:
    if not value.strip():
        raise ValueError("must not be blank")
    return value


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


class EvidenceReference(BaseModel):
    """One pointer to a persisted V2 entity that exists in the graph.

    ``reference`` is the V3.22 graph ``source_reference`` verbatim
    (``detection:<id>``, ``event_reference:<id>``, ``correlation:<id>``, …).
    It is validated against the evidence catalog built from the bounded graph,
    so a fabricated identifier cannot be constructed into a debate.
    """

    model_config = ConfigDict(extra="forbid")

    reference: BoundedId
    entity_kind: BoundedShortText = Field(
        description="V3.22 node type this reference resolves to."
    )
    node_id: BoundedId = Field(
        description="Deterministic V3.22 graph node id (uuid5 as text)."
    )

    @field_validator("reference")
    @classmethod
    def _reference_not_blank(cls, v: str) -> str:
        return _require_non_blank(v)


class DebateFact(BaseModel):
    """A fact derived by the engine from persisted V2 evidence.

    Facts are never produced by a provider.  ``statement`` is mechanically
    generated from the bounded graph, and ``evidence_references`` names the
    exact persisted entities it was computed from, so an auditor can re-derive
    it.
    """

    model_config = ConfigDict(extra="forbid")

    fact_id: BoundedId
    claim_kind: Literal[ClaimKind.FACT] = ClaimKind.FACT
    statement: BoundedText
    evidence_references: list[EvidenceReference] = Field(min_length=1)
    provenance: Literal[Provenance.OBSERVED, Provenance.DETECTED, Provenance.CORRELATED, Provenance.RISK_ASSESSED] | None = Field(
        default=None,
        description=(
            "Provenance of the *underlying V2 entity* this fact was computed "
            "from, never of the fact as reasoning.  Null when the fact spans "
            "entities of mixed provenance."
        ),
    )

    @field_validator("statement")
    @classmethod
    def _statement_not_blank(cls, v: str) -> str:
        return _require_non_blank(v)


class DebateClaim(BaseModel):
    """One model-produced analytical claim about the evidence.

    ``claim_kind`` may only ever be ``observation`` or ``hypothesis``.  An
    ``observation`` must cite at least one evidence reference — a description
    of what the evidence shows that cites nothing is not a description, it is
    an assertion.
    """

    model_config = ConfigDict(extra="forbid")

    claim_id: BoundedId
    claim_kind: Literal[ClaimKind.OBSERVATION, ClaimKind.HYPOTHESIS]
    statement: BoundedText
    evidence_references: list[EvidenceReference] = Field(
        max_length=DEFAULT_BOUNDS.max_evidence_references_per_claim
    )
    confidence: float = Field(ge=0.0, le=1.0)
    provenance: Literal[Provenance.AI_GENERATED] = Provenance.AI_GENERATED
    author_role: AgentRole

    @field_validator("statement")
    @classmethod
    def _statement_not_blank(cls, v: str) -> str:
        return _require_non_blank(v)

    @model_validator(mode="after")
    def _observations_must_be_evidenced(self) -> "DebateClaim":
        if (
            self.claim_kind is ClaimKind.OBSERVATION
            and not self.evidence_references
        ):
            raise ValueError(
                "an observation must cite at least one evidence reference; a "
                "description of the evidence that cites nothing is an "
                "assertion, not an observation"
            )
        if self.claim_kind is ClaimKind.HYPOTHESIS and not self.evidence_references:
            raise ValueError(
                "a hypothesis must cite at least one evidence reference "
                "(supporting or contradicting); uncited speculation is not "
                "admissible"
            )
        return self


# ---------------------------------------------------------------------------
# Agents and assessments
# ---------------------------------------------------------------------------


class DebateAgent(BaseModel):
    """One specialized debate agent, independently representable."""

    model_config = ConfigDict(extra="forbid")

    agent_id: BoundedId = Field(
        description="Stable agent identity, e.g. 'agent:detection_analyst'."
    )
    role: AgentRole
    display_name: BoundedShortText
    objective: BoundedText
    focus_node_types: list[str] = Field(default_factory=list)

    @field_validator("display_name", "objective")
    @classmethod
    def _not_blank(cls, v: str) -> str:
        return _require_non_blank(v)


class AgentAssessment(BaseModel):
    """One agent's independent round-1 assessment of the shared evidence."""

    model_config = ConfigDict(extra="forbid")

    agent_id: BoundedId
    role: AgentRole
    objective: BoundedText
    observations: list[DebateClaim] = Field(
        max_length=DEFAULT_BOUNDS.max_observations_per_agent
    )
    hypotheses: list[DebateClaim] = Field(
        max_length=DEFAULT_BOUNDS.max_hypotheses_per_agent
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="The agent's own calibrated confidence in its assessment.",
    )
    evidence_references: list[EvidenceReference] = Field(
        max_length=DEFAULT_BOUNDS.max_evidence_references
    )
    limitations: list[BoundedShortText] = Field(
        max_length=DEFAULT_BOUNDS.max_limitations_per_agent,
        description=(
            "What this agent could not establish from the supplied evidence. "
            "Required to be non-empty when the agent's evidence surface is "
            "absent, so silence is never mistaken for a clean review."
        ),
    )
    provenance: Literal[Provenance.AI_GENERATED] = Provenance.AI_GENERATED

    @model_validator(mode="after")
    def _hypotheses_must_be_hypotheses(self) -> "AgentAssessment":
        for claim in self.observations:
            if claim.claim_kind is not ClaimKind.OBSERVATION:
                raise ValueError("an assessment observation must be an observation")
        for claim in self.hypotheses:
            if claim.claim_kind is not ClaimKind.HYPOTHESIS:
                raise ValueError("an assessment hypothesis must be a hypothesis")
        if not self.limitations and not self.evidence_references:
            raise ValueError(
                "an agent that cites no evidence must state at least one "
                "limitation; an empty assessment with no caveat would read as "
                "a clean bill of health"
            )
        return self


# ---------------------------------------------------------------------------
# Arguments and counterarguments
# ---------------------------------------------------------------------------


class DebateArgument(BaseModel):
    """One agent's position on a hypothesis raised by another agent."""

    model_config = ConfigDict(extra="forbid")

    argument_id: BoundedId
    round_kind: Literal[RoundKind.ROUND_TWO]
    author_agent_id: BoundedId
    author_role: AgentRole
    target_agent_id: BoundedId
    target_role: AgentRole
    target_hypothesis_id: BoundedId
    stance: ArgumentStance
    statement: BoundedText
    evidence_references: list[EvidenceReference] = Field(
        min_length=1,
        max_length=DEFAULT_BOUNDS.max_evidence_references_per_claim,
        description="Real persisted evidence backing this argument.",
    )
    provenance: Literal[Provenance.AI_GENERATED] = Provenance.AI_GENERATED

    @field_validator("statement")
    @classmethod
    def _statement_not_blank(cls, v: str) -> str:
        return _require_non_blank(v)


class DebateCounterargument(BaseModel):
    """One agent's challenge to an existing argument.

    ``evidence_references`` is required and non-empty.  This is what stops the
    skeptic from manufacturing doubt: a challenge must point at something real.
    """

    model_config = ConfigDict(extra="forbid")

    counterargument_id: BoundedId
    round_kind: Literal[RoundKind.ROUND_THREE]
    author_agent_id: BoundedId
    author_role: AgentRole
    target_argument_id: BoundedId
    weakness: WeaknessKind
    statement: BoundedText
    evidence_references: list[EvidenceReference] = Field(
        min_length=1,
        max_length=DEFAULT_BOUNDS.max_evidence_references_per_claim,
    )
    provenance: Literal[Provenance.AI_GENERATED] = Provenance.AI_GENERATED

    @field_validator("statement")
    @classmethod
    def _statement_not_blank(cls, v: str) -> str:
        return _require_non_blank(v)


# ---------------------------------------------------------------------------
# Consensus
# ---------------------------------------------------------------------------


class DebateDissent(BaseModel):
    """One recorded position that did not carry the consensus.

    Dissent is retained rather than discarded: a debate that hides the losing
    argument is not auditable.
    """

    model_config = ConfigDict(extra="forbid")

    dissent_id: BoundedId
    raised_by_role: AgentRole
    position: BoundedText
    reason: BoundedShortText
    evidence_references: list[EvidenceReference] = Field(default_factory=list)
    provenance: Literal[Provenance.AI_GENERATED] = Provenance.AI_GENERATED

    @field_validator("position", "reason")
    @classmethod
    def _not_blank(cls, v: str) -> str:
        return _require_non_blank(v)


class ConsensusAssessment(BaseModel):
    """The deterministic reconciliation produced in the final round.

    None of these fields are model-authored.  ``leading_hypothesis`` is selected
    by the engine from the hypotheses agents actually raised; ``confidence`` is
    computed by a documented formula from agreement, evidence support,
    completeness, and contradiction.  That is why the result is reproducible
    and auditable rather than a second opaque model opinion.
    """

    model_config = ConfigDict(extra="forbid")

    state: ConsensusState
    leading_hypothesis: str | None = Field(
        default=None,
        description=(
            "The hypothesis the engine selected as leading, or null when no "
            "hypothesis was raised."
        ),
    )
    leading_hypothesis_id: BoundedId | None = None
    supporting_arguments: list[DebateArgument] = Field(
        max_length=DEFAULT_BOUNDS.max_total_arguments
    )
    opposing_arguments: list[DebateArgument] = Field(
        max_length=DEFAULT_BOUNDS.max_total_arguments
    )
    consensus_strength: float = Field(
        ge=0.0,
        le=1.0,
        description="How much of the agent roster supports the leading hypothesis.",
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Deterministically computed; never a blind average of agents.",
    )
    dissent: list[DebateDissent] = Field(
        max_length=DEFAULT_BOUNDS.max_dissent_entries
    )
    unresolved_questions: list[BoundedText] = Field(
        max_length=DEFAULT_BOUNDS.max_unresolved_questions
    )
    evidence_gaps: list[BoundedText] = Field(
        max_length=DEFAULT_BOUNDS.max_evidence_gaps,
        description=(
            "Entity kinds or evidence classes the debate needed and the graph "
            "could not supply."
        ),
    )
    evidence_references: list[EvidenceReference] = Field(
        max_length=DEFAULT_BOUNDS.max_evidence_references
    )
    provenance: Literal[Provenance.AI_GENERATED] = Provenance.AI_GENERATED

    @model_validator(mode="after")
    def _consensus_requires_hypothesis(self) -> "ConsensusAssessment":
        if self.state is ConsensusState.INSUFFICIENT_EVIDENCE and (
            self.leading_hypothesis is not None
        ):
            # Not an error: insufficient evidence can still name the best
            # available reading.  But a non-insufficient state with no leading
            # hypothesis would be incoherent.
            return self
        if (
            self.state is not ConsensusState.INSUFFICIENT_EVIDENCE
            and self.leading_hypothesis is None
        ):
            raise ValueError(
                f"consensus state {self.state.value} requires a leading hypothesis"
            )
        return self


# ---------------------------------------------------------------------------
# Rounds and session
# ---------------------------------------------------------------------------


class DebateRound(BaseModel):
    """One bounded round of the debate lifecycle."""

    model_config = ConfigDict(extra="forbid")

    round_number: int = Field(ge=0, le=DEFAULT_BOUNDS.max_rounds)
    round_kind: RoundKind
    summary: BoundedText
    agent_ids: list[BoundedId] = Field(default_factory=list)
    argument_ids: list[BoundedId] = Field(default_factory=list)
    counterargument_ids: list[BoundedId] = Field(default_factory=list)

    @field_validator("summary")
    @classmethod
    def _summary_not_blank(cls, v: str) -> str:
        return _require_non_blank(v)


class EvidenceScope(BaseModel):
    """The bounded evidence the debate was allowed to reason over."""

    model_config = ConfigDict(extra="forbid")

    correlation_id: BoundedId
    graph_node_count: int = Field(ge=0)
    graph_edge_count: int = Field(ge=0)
    evidence_reference_count: int = Field(ge=0)
    node_type_counts: dict[str, int] = Field(default_factory=dict)
    graph_truncated: bool = False
    graph_truncated_reason: str | None = None
    unavailable_entity_types: dict[str, str] = Field(default_factory=dict)


class DebateMetadata(BaseModel):
    """Non-secret provenance about how a debate was produced.

    Deliberately excludes the prompt text, the provider endpoint, the API key,
    and any raw provider response.  Only stable, non-secret identifiers are
    recorded so an auditor can reproduce the run without a secret ever being
    persisted.
    """

    model_config = ConfigDict(extra="forbid")

    provider: BoundedShortText
    model: BoundedShortText | None = None
    engine_version: BoundedShortText
    configuration_digest: BoundedId
    graph_snapshot_digest: BoundedId
    graph_node_count: int = Field(ge=0)
    graph_edge_count: int = Field(ge=0)
    agent_count: int = Field(ge=1)
    max_rounds: int = Field(ge=1, le=DEFAULT_BOUNDS.max_rounds)
    observations_count: int = Field(ge=0)
    hypotheses_count: int = Field(ge=0)
    arguments_count: int = Field(ge=0)
    counterarguments_count: int = Field(ge=0)
    prompt_bytes: int = Field(ge=0)
    created_at: str | None = Field(
        default=None,
        description=(
            "Wall-clock creation time.  Excluded from the deterministic "
            "content digest: it is metadata, not debate content."
        ),
    )
    provenance: Literal[Provenance.AI_GENERATED] = Provenance.AI_GENERATED


class DebateSession(BaseModel):
    """The complete result of one multi-agent debate."""

    model_config = ConfigDict(extra="forbid")

    debate_id: uuid.UUID
    correlation_id: uuid.UUID
    status: DebateStatus
    agents: list[DebateAgent] = Field(min_length=1)
    facts: list[DebateFact] = Field(default_factory=list)
    assessments: list[AgentAssessment] = Field(min_length=1)
    arguments: list[DebateArgument] = Field(default_factory=list)
    counterarguments: list[DebateCounterargument] = Field(default_factory=list)
    rounds: list[DebateRound] = Field(min_length=1)
    consensus: ConsensusAssessment
    evidence_scope: EvidenceScope
    metadata: DebateMetadata
    limitations: list[BoundedShortText] = Field(default_factory=list)

    @model_validator(mode="after")
    def _session_is_internally_consistent(self) -> "DebateSession":
        if self.status is DebateStatus.COMPLETED:
            declared = {agent.agent_id for agent in self.agents}
            assessed = {assessment.agent_id for assessment in self.assessments}
            if declared != assessed:
                raise ValueError(
                    "every declared agent must have exactly one assessment; "
                    f"declared={sorted(declared)} assessed={sorted(assessed)}"
                )
        if len(self.rounds) > DEFAULT_BOUNDS.max_rounds + 1:
            raise ValueError(
                f"a debate may not exceed {DEFAULT_BOUNDS.max_rounds} model "
                "rounds plus the shared-evidence round"
            )
        numbers = [round_.round_number for round_ in self.rounds]
        if numbers != sorted(numbers) or len(set(numbers)) != len(numbers):
            raise ValueError("rounds must be uniquely and monotonically ordered")
        return self


# ---------------------------------------------------------------------------
# API responses
# ---------------------------------------------------------------------------


class DebateFailureResponse(BaseModel):
    """An honest governed failure.  Never a synthesized consensus."""

    model_config = ConfigDict(extra="forbid")

    debate_id: uuid.UUID | None = None
    correlation_id: uuid.UUID | None = None
    status: Literal[DebateStatus.FAILED] = DebateStatus.FAILED
    failure_code: BoundedShortText
    detail: BoundedShortText
    provenance: Literal[Provenance.AI_GENERATED] = Provenance.AI_GENERATED


__all__ = [
    "AgentAssessment",
    "ConsensusAssessment",
    "DebateAgent",
    "DebateArgument",
    "DebateClaim",
    "DebateCounterargument",
    "DebateDissent",
    "DebateFact",
    "DebateFailureResponse",
    "DebateMetadata",
    "DebateRound",
    "DebateSession",
    "EvidenceReference",
    "EvidenceScope",
]