"""Closed debate vocabulary, bounds, and deterministic identity — V3.23.

This module is the single authority for *what may exist* in a multi-agent
debate.  Nothing outside the registries declared here may be persisted or
serialized as part of a debate; construction validates against them first.

The central design decision lives here, in
:data:`ModelClaimKind`: **the model can never declare a fact.**

``FACT`` is not a member of the model's claim vocabulary.  Facts are *derived
by the engine* from the bounded V3.22 knowledge graph
(:mod:`app.agents.debate.evidence`), which means a hallucinating, confused, or
adversarial model cannot manufacture a fact even if it tries — there is no
field in which to put one, and any field it invents is rejected by
``extra="forbid"``.  This is what makes "facts cannot be silently promoted from
unsupported hypotheses" a structural property rather than a convention.

Claim kinds:

``FACT``
    Mechanically derived by the engine from persisted V2 evidence via the
    knowledge graph.  Never produced by a model.
``OBSERVATION``
    A model's description of what the cited evidence literally shows.  Must
    cite at least one real evidence reference or it is rejected.
``HYPOTHESIS``
    An interpretation that goes beyond the evidence.  Explicitly not a fact.
    Must cite at least one real evidence reference (supporting or
    contradicting) or it is rejected as ungrounded speculation.

Determinism rules:

* Every identifier is a ``uuid5`` over normalized content, so identical
  structured input always yields identical identifiers.
* Agent order, hypothesis order, argument order, and dissent order are all
  defined by sorted deterministic keys — never by dict iteration order,
  database row order, or model output order alone.
* Nothing here reads the clock or a random source.
"""

from __future__ import annotations

import re
import unicodedata
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any, Final

# ---------------------------------------------------------------------------
# Namespace
# ---------------------------------------------------------------------------

#: Fixed namespace for every deterministic debate identifier.  Frozen: changing
#: it would renumber every persisted debate, so it must never be regenerated.
DEBATE_NAMESPACE: Final[uuid.UUID] = uuid.UUID(
    "b7e2f4a1-9c3d-4a5e-8f10-2d6b8c0a1e93"
)


# ---------------------------------------------------------------------------
# Claim kinds — the fact/hypothesis boundary
# ---------------------------------------------------------------------------


class ClaimKind(str, Enum):
    """How a claim relates to the evidence.

    ``FACT`` is engine-derived only.  ``ModelClaimKind`` is the subset a
    provider is permitted to emit, and it deliberately excludes ``FACT``.
    """

    FACT = "fact"
    OBSERVATION = "observation"
    HYPOTHESIS = "hypothesis"


class ModelClaimKind(str, Enum):
    """Claim kinds a model may emit.  ``FACT`` is intentionally absent."""

    OBSERVATION = "observation"
    HYPOTHESIS = "hypothesis"


#: The exact set a provider may emit.  Used to validate raw model payloads
#: before they are even handed to Pydantic, so an attempt to return "fact" is
#: rejected as an out-of-vocabulary claim rather than silently downgraded.
MODEL_ALLOWED_CLAIM_KINDS: Final[frozenset[str]] = frozenset(
    kind.value for kind in ModelClaimKind
)


class ArgumentStance(str, Enum):
    """Whether an argument supports or opposes the hypothesis it targets."""

    SUPPORTS = "supports"
    OPPOSES = "opposes"


class WeaknessKind(str, Enum):
    """How a counterargument undercuts its target argument.

    These are the specific ways a hypothesis can be *weakened*.  ``SKEPTIC``
    exists so the skeptic's reasoning is auditable rather than a generic
    "I disagree".
    """

    CONTRADICTORY_EVIDENCE = "contradictory_evidence"
    WEAK_EVIDENCE = "weak_evidence"
    MISSING_EVIDENCE = "missing_evidence"
    ALTERNATIVE_EXPLANATION = "alternative_explanation"
    OVERCONFIDENCE = "overconfidence"
    UNSUPPORTED_ASSUMPTION = "unsupported_assumption"


# ---------------------------------------------------------------------------
# Agent roles
# ---------------------------------------------------------------------------


class AgentRole(str, Enum):
    """The bounded set of specialized debate agents.

    Five roles, each with a genuinely different evidence surface.  A larger
    roster would add correlated opinions of the same evidence, not new
    information, so the set is deliberately small.
    """

    DETECTION_ANALYST = "detection_analyst"
    THREAT_INTELLIGENCE_ANALYST = "threat_intelligence_analyst"
    BEHAVIORAL_ANALYST = "behavioral_analyst"
    INCIDENT_INVESTIGATOR = "incident_investigator"
    SKEPTIC = "skeptic"


@dataclass(frozen=True)
class AgentRoleSpec:
    """Static description of one debate agent."""

    role: AgentRole
    #: Stable, human-facing display name.
    display_name: str
    #: What this agent is trying to establish, in one sentence.
    objective: str
    #: The V3.22 node types this agent is primarily responsible for.  Used to
    #: build its focused evidence view and to report when its evidence surface
    #: is empty (an honest "no evidence" rather than a fabricated opinion).
    focus_node_types: tuple[str, ...]
    #: Role-specific instructions appended to the shared debate policy.
    focus_instructions: str
    #: Whether this agent is expected to produce counterarguments.  The skeptic
    #: always may; others may challenge but are not required to.
    challenges_by_default: bool = False


AGENT_ROLES: Final[dict[AgentRole, AgentRoleSpec]] = {
    AgentRole.DETECTION_ANALYST: AgentRoleSpec(
        role=AgentRole.DETECTION_ANALYST,
        display_name="Detection Analyst",
        objective=(
            "Establish exactly what the persisted detections prove, and "
            "nothing beyond it."
        ),
        focus_node_types=("DETECTION", "CORRELATION"),
        focus_instructions=(
            "Focus on what the persisted detection results actually "
            "establish: which rules fired, how many distinct rules "
            "contributed, the recorded detection confidence, and how the "
            "detections relate to each other.  Several detections sharing "
            "one underlying event is a fact about rule coverage, not seven "
            "separate incidents, and must be described that way.  Do not "
            "infer attacker intent, campaign identity, or maliciousness "
            "beyond what the detection rows support."
        ),
    ),
    AgentRole.THREAT_INTELLIGENCE_ANALYST: AgentRoleSpec(
        role=AgentRole.THREAT_INTELLIGENCE_ANALYST,
        display_name="Threat Intelligence Analyst",
        objective=(
            "Report what threat intelligence does and does not contribute to "
            "this situation."
        ),
        focus_node_types=("THREAT_INDICATOR",),
        focus_instructions=(
            "Focus on persisted threat-intelligence indicators and their "
            "recorded properties.  Report provider agreement or disagreement "
            "only when a persisted record states it.  If there are no "
            "indicator nodes in the evidence, say so plainly and treat the "
            "absence of threat intelligence as an evidence gap — never fill "
            "it with recalled knowledge of well-known threat actors, and "
            "never assert an indicator is malicious without a persisted "
            "record saying so."
        ),
    ),
    AgentRole.BEHAVIORAL_ANALYST: AgentRoleSpec(
        role=AgentRole.BEHAVIORAL_ANALYST,
        display_name="Behavioral Analyst",
        objective=(
            "Explain the behaviour implied by the connected evidence, and "
            "name the behaviour that is missing."
        ),
        focus_node_types=("EVENT", "DETECTION", "CORRELATION"),
        focus_instructions=(
            "Focus on behaviour visible across the connected graph: how "
            "events relate to detections, how detections cluster into the "
            "correlation, and any persisted temporal ordering.  Describe only "
            "process, network, or file behaviour that the persisted records "
            "actually carry.  Never invent an attack step, a missing stage, "
            "or a technique that no persisted record supports — an absent "
            "stage is an evidence gap, not a finding."
        ),
    ),
    AgentRole.INCIDENT_INVESTIGATOR: AgentRoleSpec(
        role=AgentRole.INCIDENT_INVESTIGATOR,
        display_name="Incident Investigator",
        objective=(
            "Synthesize an independent incident interpretation and separate "
            "what is established from what is merely likely."
        ),
        focus_node_types=(
            "CORRELATION",
            "RISK_ASSESSMENT",
            "INCIDENT_REPORT",
            "INCIDENT_MEMORY",
        ),
        focus_instructions=(
            "Focus on the whole incident picture: the correlated activity, "
            "any persisted risk assessment, and any downstream persisted "
            "record such as an incident report or recalled memory.  Separate "
            "explicitly between what is established, what is likely, and "
            "what remains unknown.  Do not convert a recorded risk score "
            "into a malicious verdict: SentinelAI risk scores are "
            "danger-confidence assessments and are not verdicts."
        ),
    ),
    AgentRole.SKEPTIC: AgentRoleSpec(
        role=AgentRole.SKEPTIC,
        display_name="Skeptic / Contrarian",
        objective=(
            "Actively attempt to disprove or weaken the leading "
            "interpretation."
        ),
        focus_node_types=(),
        focus_instructions=(
            "Your job is to weaken the strongest interpretation.  Search "
            "for contradictory evidence, weak or thin evidence, missing "
            "evidence, alternative benign explanations, overconfident "
            "claims, and unsupported assumptions.  Critically: you must NOT "
            "invent negative evidence.  You may only cite evidence that is "
            "present in the supplied evidence catalog, and every "
            "counterargument you raise must cite at least one real reference. "
            "If the leading interpretation genuinely survives your scrutiny, "
            "say so — manufactured doubt is as wrong as manufactured "
            "confidence.  A counterargument asserting that evidence is "
            "*missing* is only admissible when the cited evidence shows an "
            "actual limitation rather than merely failing to support the "
            "claim."
        ),
        challenges_by_default=True,
    ),
}


def agent_roster() -> list[AgentRoleSpec]:
    """The deterministic agent roster.

    Ordered by ``role.value`` so the roster — and therefore every downstream
    ordering — is stable regardless of declaration or dict order.
    """
    return sorted(AGENT_ROLES.values(), key=lambda spec: spec.role.value)


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


class RoundKind(str, Enum):
    """The bounded debate lifecycle.

    ``ROUND_ZERO`` is the shared evidence context and involves no model call.
    Rounds one through four are the maximum debate depth; there is no fifth
    round and no unbounded loop.
    """

    ROUND_ZERO = "round_0_shared_evidence"
    ROUND_ONE = "round_1_independent_assessments"
    ROUND_TWO = "round_2_cross_agent_arguments"
    ROUND_THREE = "round_3_counterarguments"
    ROUND_FOUR = "round_4_reconciliation"


#: Rounds that invoke a model, in execution order.
MODEL_ROUNDS: Final[tuple[RoundKind, ...]] = (
    RoundKind.ROUND_ONE,
    RoundKind.ROUND_TWO,
    RoundKind.ROUND_THREE,
)


class DebateStatus(str, Enum):
    """Lifecycle status of a debate session."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# ---------------------------------------------------------------------------
# Consensus
# ---------------------------------------------------------------------------


class ConsensusState(str, Enum):
    """The closed set of final debate states.

    ``CONSENSUS`` deliberately does **not** mean "every agent agreed".  It is
    reserved for the case where the leading hypothesis is independently
    supported by every agent, is unopposed by any argument, and leaves no
    unresolved question.  Anything weaker is reported honestly as partial,
    contested, or insufficient.
    """

    CONSENSUS = "consensus"
    PARTIAL_CONSENSUS = "partial_consensus"
    CONTESTED = "contested"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


# ---------------------------------------------------------------------------
# Bounds — every limit rejects, never truncates
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DebateBounds:
    """Hard limits applied to one debate.

    Validated on construction so a misconfigured bound can never silently
    widen a debate.  Every bound is enforced **before** the corresponding
    object is persisted or returned, and a model response that exceeds a bound
    is rejected outright rather than trimmed.
    """

    max_agents: int = 8
    max_rounds: int = 4
    max_evidence_references: int = 500
    max_observations_per_agent: int = 12
    max_hypotheses_per_agent: int = 8
    max_arguments_per_agent: int = 8
    max_counterarguments_per_agent: int = 8
    max_total_arguments: int = 64
    max_total_counterarguments: int = 64
    max_total_hypotheses: int = 40
    max_total_observations: int = 60
    max_evidence_references_per_claim: int = 32
    max_claim_text_length: int = 1024
    max_limitations_per_agent: int = 8
    max_unresolved_questions: int = 32
    max_evidence_gaps: int = 32
    max_dissent_entries: int = 32
    max_model_output_bytes: int = 48 * 1024
    #: Maximum serialized evidence catalog handed to the model.
    max_evidence_catalog_bytes: int = 96 * 1024

    def __post_init__(self) -> None:
        for name in (
            "max_agents",
            "max_rounds",
            "max_evidence_references",
            "max_observations_per_agent",
            "max_hypotheses_per_agent",
            "max_arguments_per_agent",
            "max_counterarguments_per_agent",
            "max_total_arguments",
            "max_total_counterarguments",
            "max_total_hypotheses",
            "max_total_observations",
            "max_evidence_references_per_claim",
            "max_claim_text_length",
            "max_limitations_per_agent",
            "max_unresolved_questions",
            "max_evidence_gaps",
            "max_dissent_entries",
            "max_model_output_bytes",
            "max_evidence_catalog_bytes",
        ):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} must be at least 1")
        if self.max_rounds > len(MODEL_ROUNDS) + 1:
            raise ValueError(
                f"max_rounds must not exceed the {len(MODEL_ROUNDS) + 1} "
                "defined rounds; the debate lifecycle is bounded by design"
            )

    @property
    def is_standard(self) -> bool:
        """True when these are the documented default bounds."""
        return self == DEFAULT_BOUNDS


DEFAULT_BOUNDS: Final[DebateBounds] = DebateBounds()


# ---------------------------------------------------------------------------
# Confidence saturation constants
# ---------------------------------------------------------------------------

#: Distinct supporting evidence references at which a hypothesis is treated
#: as fully evidence-supported for scoring purposes.  Deterministic: raising
#: this does not silently rescale existing scores beyond the cap.
SUPPORTING_EVIDENCE_SATURATION: Final[int] = 4

#: Total arguments/counterarguments at which the contradiction penalty is
#: maximal.  The penalty never exceeds ``MAX_CONTRADICTION_PENALTY``.
CONTRADICTION_SATURATION: Final[int] = 4

#: Confidence is reduced by at most this fraction when contradiction is maximal.
MAX_CONTRADICTION_PENALTY: Final[float] = 0.5

#: Deterministic weights for the confidence formula.  They sum to 1.0.
CONFIDENCE_WEIGHT_AGREEMENT: Final[float] = 0.45
CONFIDENCE_WEIGHT_EVIDENCE_SUPPORT: Final[float] = 0.35
CONFIDENCE_WEIGHT_COMPLETENESS: Final[float] = 0.20

#: Below this fraction of available evidence references cited, the debate is
#: reported as INSUFFICIENT_EVIDENCE regardless of agent agreement.  Agreement
#: about thin evidence is not evidence of much.
MIN_EVIDENCE_COMPLETENESS_FOR_CONSENSUS: Final[float] = 0.34


# ---------------------------------------------------------------------------
# Normalization + deterministic identity
# ---------------------------------------------------------------------------

_WHITESPACE: Final[re.Pattern[str]] = re.compile(r"\s+")
#: Trailing punctuation is dropped so "…behavior." and "…behavior" are the
#: same hypothesis for agreement counting.
_TRAILING_PUNCT: Final[re.Pattern[str]] = re.compile(r"[^a-z0-9]+$")


def normalize_claim(text: str) -> str:
    """Normalize claim text into a deterministic comparison key.

    NFKC-normalizes (so visually identical Unicode compares equal), lowercases,
    collapses whitespace, and strips trailing punctuation.  Two claims sharing
    a normalized key are treated as the *same* claim for independent-agreement
    counting.

    This is exact-match agreement, deliberately: the engine does not attempt
    semantic similarity, because an embedding-based match would be
    non-deterministic and would let near-duplicate phrasing masquerade as
    independent corroboration.
    """
    if not isinstance(text, str):
        raise VocabularyError(f"claim text must be a string; got {type(text).__name__}")
    folded = unicodedata.normalize("NFKC", text).strip().lower()
    folded = _WHITESPACE.sub(" ", folded)
    return _TRAILING_PUNCT.sub("", folded)


def deterministic_claim_id(prefix: str, *parts: str) -> uuid.UUID:
    """Return a stable id for a content-derived debate object."""
    normalized = "|".join(normalize_claim(part) for part in parts)
    return uuid.uuid5(DEBATE_NAMESPACE, f"{prefix}|{normalized}")


def deterministic_hypothesis_id(statement: str) -> uuid.UUID:
    """Stable id for a hypothesis, keyed on its normalized statement."""
    return deterministic_claim_id("hypothesis", statement)


def deterministic_observation_id(role: AgentRole, statement: str) -> uuid.UUID:
    """Stable id for an observation, keyed on role plus normalized statement."""
    return deterministic_claim_id("observation", role.value, statement)


def deterministic_argument_id(
    *,
    round_kind: RoundKind,
    author_role: AgentRole,
    target_role: str,
    target_hypothesis_id: str,
    statement: str,
) -> uuid.UUID:
    """Stable id for an argument."""
    return uuid.uuid5(
        DEBATE_NAMESPACE,
        "|".join(
            [
                "argument",
                round_kind.value,
                author_role.value,
                normalize_claim(target_role),
                str(target_hypothesis_id),
                normalize_claim(statement),
            ]
        ),
    )


def deterministic_counterargument_id(
    *,
    target_argument_id: uuid.UUID,
    author_role: AgentRole,
    statement: str,
) -> uuid.UUID:
    """Stable id for a counterargument."""
    return uuid.uuid5(
        DEBATE_NAMESPACE,
        "|".join(
            [
                "counterargument",
                str(target_argument_id),
                author_role.value,
                normalize_claim(statement),
            ]
        ),
    )


def deterministic_fact_id(statement: str) -> uuid.UUID:
    """Stable id for an engine-derived fact."""
    return deterministic_claim_id("fact", statement)


def deterministic_debate_id(
    correlation_id: uuid.UUID | str,
    graph_snapshot_digest: str,
    config_digest: str,
) -> uuid.UUID:
    """Stable session identity.

    Two debates over the same correlation, the same immutable graph snapshot,
    and the same configuration resolve to the same id — which is what makes
    ``POST`` idempotent instead of accumulating duplicate analytical state.
    """
    return uuid.uuid5(
        DEBATE_NAMESPACE,
        f"session|{correlation_id}|{graph_snapshot_digest}|{config_digest}",
    )


def configuration_digest(
    bounds: DebateBounds,
    roster: tuple[AgentRole, ...],
    provider: str,
    model: str | None,
) -> str:
    """Stable digest of the debate configuration.

    Covers everything that can change a debate's *reasoning*, so a
    configuration change produces a new debate identity rather than silently
    colliding with an existing stored result.

    ``provider`` and ``model`` are part of this digest because they change what
    the debate says: a Gemini ``gemini-3.8-flash`` debate and a Groq
    ``openai/gpt-oss-120b`` debate over the same correlation and the same
    immutable graph snapshot are genuinely different analytical artifacts, and
    returning either one for a request that asked for the other would be wrong
    in both directions — the stored conclusion would be attributed to a model
    that never produced it.

    Both are required rather than optional so a call site cannot forget them
    and silently produce a digest that ignores the reasoning backend.
    ``model`` may be ``None`` (a provider that reports no model); that is a
    distinct, stable value rather than a wildcard.
    """
    import hashlib
    import json

    payload = {
        "bounds": {
            field: getattr(bounds, field)
            for field in sorted(bounds.__dataclass_fields__)
        },
        "roster": sorted(role.value for role in roster),
        "provider": provider,
        "model": model,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Vocabulary errors
# ---------------------------------------------------------------------------


class VocabularyError(ValueError):
    """Raised when something outside the closed debate vocabulary is used."""


# ---------------------------------------------------------------------------
# Self-description
# ---------------------------------------------------------------------------


def vocabulary_document() -> dict[str, Any]:
    """Machine-readable description of the closed debate vocabulary.

    Exposed by the API so the agent roster, claim kinds, consensus states, and
    bounds are auditable without reading the source.
    """
    return {
        "agent_roles": [
            {
                "role": spec.role.value,
                "display_name": spec.display_name,
                "objective": spec.objective,
                "focus_node_types": list(spec.focus_node_types),
                "challenges_by_default": spec.challenges_by_default,
            }
            for spec in agent_roster()
        ],
        "claim_kinds": [kind.value for kind in ClaimKind],
        "model_allowed_claim_kinds": sorted(MODEL_ALLOWED_CLAIM_KINDS),
        "round_kinds": [kind.value for kind in RoundKind],
        "model_rounds": [kind.value for kind in MODEL_ROUNDS],
        "consensus_states": [state.value for state in ConsensusState],
        "argument_stances": [stance.value for stance in ArgumentStance],
        "weakness_kinds": [weakness.value for weakness in WeaknessKind],
        "statuses": [status.value for status in DebateStatus],
        "bounds": {
            field: getattr(DEFAULT_BOUNDS, field)
            for field in sorted(DEFAULT_BOUNDS.__dataclass_fields__)
        },
        "confidence": {
            "weights": {
                "agreement": CONFIDENCE_WEIGHT_AGREEMENT,
                "evidence_support": CONFIDENCE_WEIGHT_EVIDENCE_SUPPORT,
                "completeness": CONFIDENCE_WEIGHT_COMPLETENESS,
            },
            "supporting_evidence_saturation": SUPPORTING_EVIDENCE_SATURATION,
            "contradiction_saturation": CONTRADICTION_SATURATION,
            "max_contradiction_penalty": MAX_CONTRADICTION_PENALTY,
            "min_evidence_completeness_for_consensus": (
                MIN_EVIDENCE_COMPLETENESS_FOR_CONSENSUS
            ),
        },
        "provenance": "ai_generated",
        "notes": (
            "Debate output is analytical reasoning, not security evidence. "
            "FACT claims are derived by the engine from persisted V2 evidence "
            "via the knowledge graph and are never produced by a model."
        ),
    }


__all__ = [
    "CONFIDENCE_WEIGHT_AGREEMENT",
    "CONFIDENCE_WEIGHT_COMPLETENESS",
    "CONFIDENCE_WEIGHT_EVIDENCE_SUPPORT",
    "CONTRADICTION_SATURATION",
    "DEBATE_NAMESPACE",
    "DEFAULT_BOUNDS",
    "MAX_CONTRADICTION_PENALTY",
    "MIN_EVIDENCE_COMPLETENESS_FOR_CONSENSUS",
    "MODEL_ALLOWED_CLAIM_KINDS",
    "MODEL_ROUNDS",
    "SUPPORTING_EVIDENCE_SATURATION",
    "AGENT_ROLES",
    "AgentRole",
    "AgentRoleSpec",
    "ArgumentStance",
    "ClaimKind",
    "ConsensusState",
    "DebateBounds",
    "DebateStatus",
    "ModelClaimKind",
    "RoundKind",
    "VocabularyError",
    "WeaknessKind",
    "agent_roster",
    "configuration_digest",
    "deterministic_argument_id",
    "deterministic_claim_id",
    "deterministic_counterargument_id",
    "deterministic_debate_id",
    "deterministic_fact_id",
    "deterministic_hypothesis_id",
    "deterministic_observation_id",
    "normalize_claim",
    "vocabulary_document",
]