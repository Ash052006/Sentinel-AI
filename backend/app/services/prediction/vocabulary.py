"""Closed prediction vocabulary, bounds, formula constants, and identity — V3.24.

Everything a prediction is *allowed* to say is declared here.  This module
knows nothing about the knowledge graph, the debate engine, or any database: it
is the frozen vocabulary that the engine, the contracts, and persistence share.

Four properties are load-bearing and enforced by construction, not convention:

1. **A prediction is never evidence.**  No enumeration in this module contains
   ``observed``, ``detected``, ``correlated``, ``risk_assessed``, or any other
   evidence provenance.  Contracts pin ``Literal[Provenance.AI_GENERATED]`` using
   the *platform* provenance enum, so a prediction cannot be serialized as a V2
   fact even by accident.

2. **ATT&CK identifiers are never invented.**  ``validate_technique_id`` is the
   only door a technique id may pass through, and callers may only pass values
   read out of persisted rows.  No ATT&CK catalog is embedded here: that would
   mean asserting technique membership from memory, which §9/§10 forbid.

3. **There is no progression table.**  Nothing maps technique X to technique Y.
   Such a table would be exactly the "attackers usually do X next" reasoning
   §13 forbids treating as evidence.  A stage can therefore only be predicted
   when something *in the database* names it.

4. **Identity is content-derived.**  ``deterministic_prediction_id`` and
   ``deterministic_session_id`` are ``uuid5`` over the inputs that justify a
   prediction.  No wall-clock participates, so identical inputs are the same
   artifact.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field, model_validator

#: Frozen namespace for V3.24 session and prediction identifiers.
#:
#: Deliberately distinct from the V3.23 debate namespace and the V3.22 graph
#: namespace, so no prediction id can collide with — or be mistaken for — a
#: debate id or a graph node id.
PREDICTION_NAMESPACE: Final[uuid.UUID] = uuid.UUID(
    "c4f1a8d2-5e6b-49a1-9d77-3c5e8a2b4f16"
)

#: Namespace for derived child-row identifiers.
PREDICTION_ROW_NAMESPACE: Final[uuid.UUID] = uuid.UUID(
    "9a4c2e77-1b83-4f65-8e02-7d4a9c6b3e58"
)

ENGINE_VERSION: Final[str] = "v3.24.0"


# ---------------------------------------------------------------------------
# Prediction outcome vocabulary
# ---------------------------------------------------------------------------


class PredictionStatus(str, Enum):
    """Closed prediction outcome.

    ``INSUFFICIENT_EVIDENCE`` is a first-class *success*.  Declining to
    speculate is a correct prediction outcome and is explicitly preferred over
    emitting a plausible-sounding narrative (§10, §46).
    """

    PREDICTED = "PREDICTED"
    LOW_CONFIDENCE = "LOW_CONFIDENCE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    CONTESTED = "CONTESTED"


class PredictionKind(str, Enum):
    """Closed category of predicted progression.

    A prediction names a *class* of future activity.  Mapping a class to an
    ATT&CK technique is never asserted unless a persisted mapping supplies one.
    """

    NEXT_TACTIC = "NEXT_TACTIC"
    NEXT_TECHNIQUE = "NEXT_TECHNIQUE"
    NEXT_ACTIVITY = "NEXT_ACTIVITY"
    ESCALATION = "ESCALATION"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    PERSISTENCE = "PERSISTENCE"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    EXFILTRATION = "EXFILTRATION"
    COMMAND_AND_CONTROL = "COMMAND_AND_CONTROL"


class PredictionDepth(str, Enum):
    """Position of a prediction within the bounded horizon.

    ``IMMEDIATE`` is depth 1 (a plausible next stage of the current state).
    ``SUBSEQUENT`` is depth 2, emitted only when a second distinct stage is
    itself named by resolved evidence.  There is no deeper member: the horizon
    is architecturally capped at two (§19).
    """

    IMMEDIATE = "immediate"
    SUBSEQUENT = "subsequent"

    @property
    def depth(self) -> int:
        """1-based depth within the prediction horizon."""
        return 1 if self is PredictionDepth.IMMEDIATE else 2


class PredictionBasis(str, Enum):
    """Why a candidate prediction was permitted to exist.

    This is the mechanism that stops "attackers usually do X next" from acting
    as evidence.  A candidate with no basis is never constructed; every basis
    names something that exists in the database.
    """

    #: The stage is backed by a persisted ATT&CK mapping on a real detection row
    #: present in this correlation's V3.22 graph.
    PERSISTED_ATTACK_MAPPING = "persisted_attack_mapping"

    #: The stage is named by a debate hypothesis whose own citations resolve to
    #: persisted evidence.  A debate claim is an *interpretation*: it can support
    #: a prediction but is never treated as a fact.
    DEBATE_HYPOTHESIS = "debate_hypothesis"

    #: The stage is connected by a persisted graph relationship between real
    #: entities.
    PERSISTED_RELATIONSHIP = "persisted_relationship"

    #: A labelled analytical inference over the above.  Always carries an
    #: explicit limitation and never claims an ATT&CK technique id.
    ANALYTICAL_HYPOTHESIS = "analytical_hypothesis"


class TargetBasis(str, Enum):
    """How the named target was identified.

    Lets a consumer distinguish "we persisted this technique" from "a debate
    hypothesis used these words" from "we inferred the label", without reading
    prose.
    """

    PERSISTED_ATTACK_MAPPING = "persisted_attack_mapping"
    DEBATE_REFERENCED = "debate_referenced"
    ANALYTICAL_HYPOTHESIS = "analytical_hypothesis"


class ConfidenceBand(str, Enum):
    """Discrete band over :attr:`PredictionUncertainty.confidence`.

    Kept separate from :class:`PredictionStatus` deliberately.  Prediction
    confidence means "the proposed future progression is plausible".  Debate
    confidence, per-agent confidence and the V2 risk score are *different*
    quantities and are never folded into this number (§17).
    """

    VERY_LOW = "very_low"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"


class ConfidenceBasis(str, Enum):
    """Machine-readable breakdown of how confidence was computed."""

    EVIDENCE_SUPPORT = "evidence_support"
    EVIDENCE_DIVERSITY = "evidence_diversity"
    DEBATE_SUPPORT = "debate_support"
    TARGET_SPECIFICITY = "target_specificity"
    CONTRADICTION_PENALTY = "contradiction_penalty"


class EvidenceSupport(str, Enum):
    """Where a prediction's supporting citations resolve.

    ``PERSISTED_EVIDENCE`` is the only value that can carry a prediction to
    ``PREDICTED`` on its own.  A prediction supported purely by ``DEBATE_CLAIM``
    is capped by :data:`DEBATE_ONLY_CONFIDENCE_CEILING`, because a debate
    hypothesis is an interpretation and not a fact (§6, §11).
    """

    PERSISTED_EVIDENCE = "persisted_evidence"
    DEBATE_CLAIM = "debate_claim"
    MIXED = "mixed"


class EvidenceStance(str, Enum):
    """Whether a citation supports or contradicts a prediction."""

    SUPPORTING = "supporting"
    CONTRADICTING = "contradicting"


class LimitationKind(str, Enum):
    """Closed vocabulary of why a prediction is limited."""

    NO_PERSISTED_ATTACK_MAPPING = "no_persisted_attack_mapping"
    NO_DEBATE_ARTIFACT = "no_debate_artifact"
    DEBATE_INSUFFICIENT_EVIDENCE = "debate_insufficient_evidence"
    DEBATE_CONTESTED = "debate_contested"
    SINGLE_SOURCE_EVIDENCE = "single_source_evidence"
    NO_CONTRADICTING_EVIDENCE_AVAILABLE = "no_contradicting_evidence_available"
    GRAPH_TRUNCATED = "graph_truncated"
    INPUT_SOURCE_UNAVAILABLE = "input_source_unavailable"
    HORIZON_CAPPED = "horizon_capped"
    ANALYTICAL_INFERENCE_ONLY = "analytical_inference_only"
    NO_PERSISTED_TECHNIQUE = "no_persisted_technique"


# ---------------------------------------------------------------------------
# Confidence formula constants (§17)
# ---------------------------------------------------------------------------
#
# confidence = clamp01(
#       W_ES * evidence_support
#     + W_ED * evidence_diversity
#     + W_DS * debate_support
#     + W_TS * target_specificity
#     - contradiction_penalty
# )
#
# Bounded by construction: weights sum to exactly 1.0 and every component is in
# [0, 1], so the weighted sum is in [0, 1] before the penalty.  Deterministic:
# no sampling, no clock.  Documented: exposed in vocabulary_document().

WEIGHT_EVIDENCE_SUPPORT: Final[float] = 0.35
WEIGHT_EVIDENCE_DIVERSITY: Final[float] = 0.20
WEIGHT_DEBATE_SUPPORT: Final[float] = 0.25
WEIGHT_TARGET_SPECIFICITY: Final[float] = 0.20

#: Debate consensus state -> debate-support contribution.  Read as "how far a
#: prediction may lean on the debate's interpretation".  ``insufficient_evidence``
#: contributes almost nothing on purpose.
CONSENSUS_DEBATE_SUPPORT: Final[dict[str, float]] = {
    "consensus": 0.80,
    "partial_consensus": 0.60,
    "contested": 0.30,
    "insufficient_evidence": 0.10,
}

#: Extra debate support when the stage is explicitly named by a hypothesis.
NAMED_HYPOTHESIS_BONUS: Final[float] = 0.20

#: Penalty per contradicting reference, capped.  Counted rather than weighted:
#: one contradiction should not outvote a real evidence base, but several should.
CONTRADICTION_PENALTY_PER_REFERENCE: Final[float] = 0.25
MAX_CONTRADICTION_PENALTY: Final[float] = 0.50

#: Target-specificity contribution by target basis.
TARGET_SPECIFICITY: Final[dict[str, float]] = {
    TargetBasis.PERSISTED_ATTACK_MAPPING.value: 1.00,
    TargetBasis.DEBATE_REFERENCED.value: 0.50,
    TargetBasis.ANALYTICAL_HYPOTHESIS.value: 0.25,
}

#: Supporting citations required to saturate the evidence-support term.
EVIDENCE_SUPPORT_SATURATION: Final[int] = 2

#: Distinct supporting entity kinds required to saturate the diversity term.
EVIDENCE_DIVERSITY_SATURATION: Final[int] = 3

#: Confidence at or below which a supported prediction is reported
#: ``LOW_CONFIDENCE`` rather than ``PREDICTED``.
LOW_CONFIDENCE_THRESHOLD: Final[float] = 0.35

#: Contradicting-reference count at which a prediction is reported
#: ``CONTESTED``.
CONTESTED_THRESHOLD: Final[int] = 2

#: Ceiling applied when support is debate-only, so a verbose debate can never
#: manufacture a confident prediction out of words.
DEBATE_ONLY_CONFIDENCE_CEILING: Final[float] = 0.50

#: Confidence is rounded to this many decimals before serialization, so float
#: representation can never make two otherwise identical runs differ.
CONFIDENCE_PRECISION: Final[int] = 4

#: MITRE ATT&CK technique identifier *shape*.  Membership in the real ATT&CK
#: catalog is deliberately not asserted: doing so would mean embedding a catalog
#: release here.  A technique id may only enter a prediction by being read from a
#: persisted row, and then only if it matches this pattern.
TECHNIQUE_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def validate_technique_id(technique_id: str | None) -> str | None:
    """Return ``technique_id`` when well-formed, else ``None``.

    Malformed values are *dropped*, never repaired, so a hallucinated or
    corrupted identifier cannot reach a prediction.
    """
    if technique_id is None:
        return None
    candidate = technique_id.strip().upper()
    if not TECHNIQUE_ID_PATTERN.match(candidate):
        return None
    return candidate


# ---------------------------------------------------------------------------
# Bounds (§18)
# ---------------------------------------------------------------------------


class PredictionBounds(BaseModel):
    """Architectural bounds for one prediction run.

    Enforced *before* any persistence or mutation.  Exceeding a bound is an
    explicit governed failure or an explicitly flagged bounded result — never a
    silent truncation presented as complete.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_graph_nodes: int = Field(default=200, ge=1, le=500)
    max_graph_edges: int = Field(default=600, ge=1, le=2000)
    max_debate_claims: int = Field(default=64, ge=1, le=500)
    max_candidate_predictions: int = Field(default=8, ge=1, le=32)
    max_evidence_references_per_prediction: int = Field(default=16, ge=1, le=32)
    max_predictions_emitted: int = Field(default=4, ge=1, le=32)
    max_depth: int = Field(default=2, ge=1, le=2)
    max_context_bytes: int = Field(default=65536, ge=1024, le=1048576)
    max_technique_observations: int = Field(default=64, ge=1, le=256)

    @model_validator(mode="after")
    def _enforce_horizon(self) -> "PredictionBounds":
        """Reject a depth horizon the architecture does not support.

        Declared as a ``model_validator`` rather than ``__post_init__`` on
        purpose: Pydantic v2 does not call ``__post_init__`` on a
        ``BaseModel``, so a check written there would never run and a
        ``max_depth=1`` configuration would silently take effect.
        """
        if self.max_depth != 2:
            raise ValueError(
                "max_depth is architecturally capped at 2: V3.24 forecasts at most a "
                "plausible next stage and one subsequent stage (§19)."
            )
        return self


DEFAULT_PREDICTION_BOUNDS: Final[PredictionBounds] = PredictionBounds()


# ---------------------------------------------------------------------------
# Closed stage vocabulary (§9, §10)
# ---------------------------------------------------------------------------
#
# A predicted stage is identified by matching a **closed** token set against
# evidence and debate text.  This is a labelling vocabulary, not a model of how
# attacks progress, and it deliberately contains no successor rules.  The
# consequence is honest: V3.24 answers "what did the recorded state or the debate
# explicitly point at?" and answers INSUFFICIENT_EVIDENCE whenever nothing is
# named.


@dataclass(frozen=True)
class StageVocabularyEntry:
    """One closed predicted-stage label and the tokens that identify it."""

    kind: PredictionKind
    label: str
    tokens: frozenset[str]


STAGE_VOCABULARY: Final[dict[PredictionKind, StageVocabularyEntry]] = {
    PredictionKind.CREDENTIAL_ACCESS: StageVocabularyEntry(
        kind=PredictionKind.CREDENTIAL_ACCESS,
        label="credential access",
        tokens=frozenset(
            {
                "credential access",
                "credential theft",
                "credential harvesting",
                "steal credentials",
                "credential material",
                "credential dumping",
                "os credential dumping",
                "credentials from password stores",
                "unsecured credentials",
            }
        ),
    ),
    PredictionKind.LATERAL_MOVEMENT: StageVocabularyEntry(
        kind=PredictionKind.LATERAL_MOVEMENT,
        label="lateral movement",
        tokens=frozenset(
            {
                "lateral movement",
                "movement between hosts",
                "remote services",
                "remote file copy",
            }
        ),
    ),
    PredictionKind.PERSISTENCE: StageVocabularyEntry(
        kind=PredictionKind.PERSISTENCE,
        label="persistence",
        tokens=frozenset(
            {
                "persistence",
                "persistence mechanism",
                "establish persistence",
                "maintain access",
                "boot or logon autostart",
                "boot or logon initialization scripts",
                "create or modify system process",
            }
        ),
    ),
    PredictionKind.ESCALATION: StageVocabularyEntry(
        kind=PredictionKind.ESCALATION,
        label="privilege escalation",
        tokens=frozenset(
            {
                "privilege escalation",
                "elevation of privilege",
                "escalate privileges",
                "exploitation for privilege escalation",
                "abuse elevation control mechanism",
            }
        ),
    ),
    PredictionKind.EXFILTRATION: StageVocabularyEntry(
        kind=PredictionKind.EXFILTRATION,
        label="data exfiltration",
        tokens=frozenset(
            {
                "exfiltration",
                "data exfiltration",
                "data theft",
                "stage data",
                "exfiltration over web service",
                "exfiltration over alternative protocol",
            }
        ),
    ),
    PredictionKind.COMMAND_AND_CONTROL: StageVocabularyEntry(
        kind=PredictionKind.COMMAND_AND_CONTROL,
        label="command and control",
        tokens=frozenset(
            {
                "command and control",
                "command and control channel",
                "c2 channel",
                "c2 server",
                "c2 infrastructure",
                "beaconing",
            }
        ),
    ),
    PredictionKind.NEXT_TACTIC: StageVocabularyEntry(
        kind=PredictionKind.NEXT_TACTIC,
        label="next tactic escalation",
        tokens=frozenset({"next tactic", "tactic escalation", "tactic change"}),
    ),
    PredictionKind.NEXT_TECHNIQUE: StageVocabularyEntry(
        kind=PredictionKind.NEXT_TECHNIQUE,
        label="next attack technique",
        tokens=frozenset(
            {"next technique", "technique escalation", "next attack technique"}
        ),
    ),
    PredictionKind.NEXT_ACTIVITY: StageVocabularyEntry(
        kind=PredictionKind.NEXT_ACTIVITY,
        label="subsequent adversary activity",
        tokens=frozenset(
            {
                "next activity",
                "subsequent activity",
                "follow on activity",
                "follow on stage",
            }
        ),
    ),
}

#: Deterministic resolution order when several stage labels are named at once.
#: Fixed so candidate ordering never depends on dict or input ordering.
#: Stage tokens are plain descriptive labels only.  No ATT&CK technique id
#: appears here — a ``T####`` literal would be ATT&CK knowledge baked into the
#: engine, which is precisely what §9 forbids.  A stage is recognised from words
#: a persisted row or a debate actually wrote.
STAGE_PRIORITY: Final[tuple[PredictionKind, ...]] = (
    PredictionKind.CREDENTIAL_ACCESS,
    PredictionKind.LATERAL_MOVEMENT,
    PredictionKind.PERSISTENCE,
    PredictionKind.ESCALATION,
    PredictionKind.EXFILTRATION,
    PredictionKind.COMMAND_AND_CONTROL,
    PredictionKind.NEXT_TACTIC,
    PredictionKind.NEXT_TECHNIQUE,
    PredictionKind.NEXT_ACTIVITY,
)


def normalize_label(text: str) -> str:
    """Normalize text for closed-vocabulary matching.

    Case-folded, separator runs collapsed to a single space, whitespace
    collapsed.  Total and side-effect free.
    """
    folded = text.casefold()
    for separator in ("-", "_", "/", "|", "\t", "\n"):
        folded = folded.replace(separator, " ")
    return " ".join(folded.split())


def mentions_stage(text: str, entry: StageVocabularyEntry) -> bool:
    """True when ``text`` names ``entry``'s stage using its closed token set.

    Word-boundary matching against normalized text, so a token never fires
    inside a longer unrelated word.
    """
    normalized = normalize_label(text)
    return any(
        re.search(rf"(?<!\w){re.escape(token)}(?!\w)", normalized) for token in entry.tokens
    )


# ---------------------------------------------------------------------------
# Deterministic identity (§16, §24)
# ---------------------------------------------------------------------------


def deterministic_prediction_id(
    *,
    correlation_id: uuid.UUID | str,
    prediction_kind: PredictionKind,
    depth: PredictionDepth,
    target: str,
    technique_id: str | None,
    supporting_refs: tuple[str, ...],
    debate_id: uuid.UUID | str | None,
) -> uuid.UUID:
    """Derive a prediction's content identity.

    Excludes confidence, status, and ordering — those are outputs, not identity.
    Includes only what *justifies* the prediction, so the same justification
    always yields the same id and a changed justification yields a new
    prediction rather than a mutated one.
    """
    payload = "|".join(
        (
            "prediction",
            str(correlation_id),
            prediction_kind.value,
            str(depth.depth),
            target,
            technique_id or "-",
            ",".join(sorted(supporting_refs)),
            str(debate_id) if debate_id is not None else "-",
        )
    )
    return uuid.uuid5(PREDICTION_NAMESPACE, payload)


def deterministic_session_id(
    *,
    correlation_id: uuid.UUID | str,
    graph_snapshot_digest: str,
    debate_id: uuid.UUID | str | None,
    configuration_digest: str,
) -> uuid.UUID:
    """Derive a prediction session's identity.

    The conceptual identity required for V3.24:
    ``(correlation_id, graph_snapshot_digest, debate_id,
    prediction_configuration_digest)``.  Current time is never an input, so
    repeated execution over unchanged inputs is the same session.
    """
    payload = "|".join(
        (
            "session",
            str(correlation_id),
            graph_snapshot_digest,
            str(debate_id) if debate_id is not None else "-",
            configuration_digest,
        )
    )
    return uuid.uuid5(PREDICTION_NAMESPACE, payload)


def deterministic_row_id(parent: uuid.UUID, kind: str, key: str) -> uuid.UUID:
    """Derive a child-row identity from its owning session."""
    return uuid.uuid5(PREDICTION_ROW_NAMESPACE, f"{parent}|{kind}|{key}")


def prediction_configuration_digest(bounds: PredictionBounds) -> str:
    """SHA-256 over the prediction configuration.

    Part of the session identity, so changing a bound yields a new session
    rather than comparing two different configurations.
    """
    payload = json.dumps(
        bounds.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(f"{ENGINE_VERSION}|{payload}".encode("utf-8")).hexdigest()


def confidence_band(confidence: float) -> ConfidenceBand:
    """Map a bounded confidence to its discrete band."""
    if confidence >= 0.75:
        return ConfidenceBand.HIGH
    if confidence >= 0.50:
        return ConfidenceBand.MODERATE
    if confidence >= LOW_CONFIDENCE_THRESHOLD:
        return ConfidenceBand.LOW
    return ConfidenceBand.VERY_LOW


def vocabulary_document() -> dict[str, Any]:
    """Machine-readable dump of the frozen vocabulary, formula, and bounds."""
    return {
        "engine_version": ENGINE_VERSION,
        "prediction_status": [m.value for m in PredictionStatus],
        "prediction_kind": [m.value for m in PredictionKind],
        "prediction_depth": [m.value for m in PredictionDepth],
        "prediction_basis": [m.value for m in PredictionBasis],
        "target_basis": [m.value for m in TargetBasis],
        "confidence_band": [m.value for m in ConfidenceBand],
        "confidence_basis": [m.value for m in ConfidenceBasis],
        "evidence_support": [m.value for m in EvidenceSupport],
        "evidence_stance": [m.value for m in EvidenceStance],
        "limitation_kind": [m.value for m in LimitationKind],
        "stages": {
            kind.value: {
                "label": entry.label,
                "tokens": sorted(entry.tokens),
            }
            for kind, entry in STAGE_VOCABULARY.items()
        },
        "stage_priority": [k.value for k in STAGE_PRIORITY],
        "confidence_formula": {
            "expression": (
                "clamp01(0.35*evidence_support + 0.20*evidence_diversity + "
                "0.25*debate_support + 0.20*target_specificity - contradiction_penalty)"
            ),
            "weights": {
                ConfidenceBasis.EVIDENCE_SUPPORT.value: WEIGHT_EVIDENCE_SUPPORT,
                ConfidenceBasis.EVIDENCE_DIVERSITY.value: WEIGHT_EVIDENCE_DIVERSITY,
                ConfidenceBasis.DEBATE_SUPPORT.value: WEIGHT_DEBATE_SUPPORT,
                ConfidenceBasis.TARGET_SPECIFICITY.value: WEIGHT_TARGET_SPECIFICITY,
            },
            "consensus_debate_support": dict(CONSENSUS_DEBATE_SUPPORT),
            "named_hypothesis_bonus": NAMED_HYPOTHESIS_BONUS,
            "contradiction_penalty_per_reference": CONTRADICTION_PENALTY_PER_REFERENCE,
            "max_contradiction_penalty": MAX_CONTRADICTION_PENALTY,
            "target_specificity": dict(TARGET_SPECIFICITY),
            "evidence_support_saturation": EVIDENCE_SUPPORT_SATURATION,
            "evidence_diversity_saturation": EVIDENCE_DIVERSITY_SATURATION,
            "low_confidence_threshold": LOW_CONFIDENCE_THRESHOLD,
            "contested_threshold": CONTESTED_THRESHOLD,
            "debate_only_confidence_ceiling": DEBATE_ONLY_CONFIDENCE_CEILING,
            "precision": CONFIDENCE_PRECISION,
        },
        "bounds": DEFAULT_PREDICTION_BOUNDS.model_dump(mode="json"),
        "statements": [
            "Predictions are not evidence.",
            "The engine does not claim predicted activity occurred.",
            "RAG knowledge is contextual knowledge, not security evidence.",
            "No ATT&CK catalog is embedded; a predicted stage carries no technique "
            "id unless a persisted detection supplied one.",
            "No successor/progression table exists, so a stage is predicted only "
            "when persisted data or a resolved debate hypothesis names it.",
        ],
    }


__all__ = [
    "CONSENSUS_DEBATE_SUPPORT",
    "CONFIDENCE_PRECISION",
    "CONTRADICTION_PENALTY_PER_REFERENCE",
    "CONTESTED_THRESHOLD",
    "DEFAULT_PREDICTION_BOUNDS",
    "DEBATE_ONLY_CONFIDENCE_CEILING",
    "ENGINE_VERSION",
    "EVIDENCE_DIVERSITY_SATURATION",
    "EVIDENCE_SUPPORT_SATURATION",
    "LOW_CONFIDENCE_THRESHOLD",
    "MAX_CONTRADICTION_PENALTY",
    "NAMED_HYPOTHESIS_BONUS",
    "PREDICTION_NAMESPACE",
    "PREDICTION_ROW_NAMESPACE",
    "STAGE_PRIORITY",
    "STAGE_VOCABULARY",
    "TARGET_SPECIFICITY",
    "TECHNIQUE_ID_PATTERN",
    "WEIGHT_EVIDENCE_DIVERSITY",
    "WEIGHT_EVIDENCE_SUPPORT",
    "WEIGHT_DEBATE_SUPPORT",
    "WEIGHT_TARGET_SPECIFICITY",
    "ConfidenceBand",
    "ConfidenceBasis",
    "EvidenceStance",
    "EvidenceSupport",
    "LimitationKind",
    "PredictionBasis",
    "PredictionBounds",
    "PredictionDepth",
    "PredictionKind",
    "PredictionStatus",
    "StageVocabularyEntry",
    "TargetBasis",
    "confidence_band",
    "deterministic_prediction_id",
    "deterministic_row_id",
    "deterministic_session_id",
    "mentions_stage",
    "normalize_label",
    "prediction_configuration_digest",
    "validate_technique_id",
    "vocabulary_document",
]