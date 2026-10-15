"""Strict prediction contracts — V3.24.

Every semantic structure in V3.24 is a typed Pydantic model with
``extra="forbid"``.  No core concept is an arbitrary dictionary, so a prediction
cannot carry an unmodelled field that a consumer would have to guess about.

Two invariants are enforced by the contracts rather than by convention:

* **Prediction ≠ evidence.**  Every model pins ``provenance`` to
  ``Literal[Provenance.AI_GENERATED]`` using the *platform* provenance enum.
  Because that enum also contains ``observed``, ``detected``, ``correlated`` and
  ``risk_assessed``, the type system itself makes it impossible to serialize a
  prediction as a piece of evidence (§4).

* **A cited reference must resolve.**  ``PredictionEvidence`` mirrors the V3.23
  ``{reference, entity_kind, node_id}`` pointer shape so both systems resolve
  references identically, and adds an explicit ``stance``.  It carries no source
  content: a prediction points at evidence, it never copies it.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas.security_event import Provenance
from app.services.prediction.vocabulary import (
    DEFAULT_PREDICTION_BOUNDS,
    ConfidenceBand,
    ConfidenceBasis,
    EvidenceStance,
    EvidenceSupport,
    LimitationKind,
    PredictionBasis,
    PredictionBounds,
    PredictionDepth,
    PredictionKind,
    PredictionStatus,
    TargetBasis,
    validate_technique_id,
)

#: Prediction provenance.  The platform enum is reused rather than redefined so
#: that "a prediction is not evidence" is a property of the type system.
PredictionProvenance = Literal[Provenance.AI_GENERATED]

PredictionId = Annotated[str, Field(min_length=1, max_length=128)]
Reference = Annotated[str, Field(min_length=1, max_length=128)]
BoundedLine = Annotated[str, Field(min_length=1, max_length=512)]
BoundedText = Annotated[str, Field(min_length=1, max_length=1024)]
BoundedShort = Annotated[str, Field(min_length=1, max_length=256)]
Digest = Annotated[str, Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")]


class AttackTechnique(BaseModel):
    """The ATT&CK target of a prediction.

    ``technique_id`` is optional by design.  A ``None`` id means the prediction
    asserts a *category* of future activity rather than a specific technique,
    and ``technique_id_reason`` must state why.  An id is present only when one
    was read from persisted evidence and passed
    :func:`~app.services.prediction.vocabulary.validate_technique_id`; the model
    re-validates the shape so a caller cannot bypass that door.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    technique_id: str | None = Field(
        default=None,
        min_length=4,
        max_length=10,
        description="Persisted ATT&CK technique id, or None when unsupported.",
    )
    technique_name: str | None = Field(default=None, max_length=128)
    tactic: str | None = Field(default=None, max_length=64)
    technique_id_reason: BoundedLine = Field(
        ...,
        description="Why this id is present or absent; never left implicit.",
    )

    @field_validator("technique_id")
    @classmethod
    def _id_shape_is_valid(cls, technique_id: str | None) -> str | None:
        """Refuse any id that is not ATT&CK-shaped.

        Shape only — membership in the real ATT&CK catalog is deliberately not
        asserted, because no catalog is embedded.  A malformed id is rejected
        outright rather than repaired: silently rewriting ``"T-1003"`` into a
        plausible-looking id would fabricate a reference that no persisted row
        contains.
        """
        if technique_id is None:
            return None
        if validate_technique_id(technique_id) is None:
            raise ValueError(
                "technique_id must match the ATT&CK technique shape; an id is "
                "only ever carried forward from persisted evidence"
            )
        return technique_id

    @property
    def is_persisted(self) -> bool:
        """True when a technique id was carried forward from persisted data."""
        return self.technique_id is not None


class PredictionEvidence(BaseModel):
    """One citation supporting or contradicting a prediction.

    A pointer to a persisted source, never a copy of it.  ``detail`` is a short,
    secret-safe explanation of why this citation matters for *this* prediction.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    reference: Reference
    entity_kind: Annotated[str, Field(min_length=1, max_length=64)]
    node_id: Reference
    stance: EvidenceStance
    detail: BoundedLine
    provenance: PredictionProvenance = Provenance.AI_GENERATED

    @property
    def source_entity_id(self) -> str | None:
        """The source id embedded in ``reference``, when present."""
        _, sep, tail = self.reference.partition(":")
        return tail if sep and tail else None


class PredictionLimitation(BaseModel):
    """One explicit limitation on a prediction."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: LimitationKind
    detail: BoundedLine


class PredictionRationale(BaseModel):
    """Why the engine emitted this prediction.

    Assembled deterministically from resolved evidence and debate state.  There
    is no field capable of holding a prompt, a raw provider payload, or source
    record content, so a rationale cannot leak one.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    summary: BoundedText
    basis: PredictionBasis
    basis_detail: BoundedLine
    observed_techniques: list[str] = Field(default_factory=list, max_length=32)
    debate_agreement: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "Consensus strength of the supporting debate, copied verbatim and kept "
            "separate from prediction confidence."
        ),
    )
    provenance: PredictionProvenance = Provenance.AI_GENERATED


class PredictionUncertainty(BaseModel):
    """Explicit uncertainty for one prediction.

    Contradicting evidence is never suppressed or netted away: it is carried
    alongside supporting evidence and is what can move a prediction to
    ``CONTESTED`` (§12).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    confidence_band: ConfidenceBand
    confidence_basis: dict[ConfidenceBasis, float] = Field(
        ..., min_length=1, description="Deterministic component breakdown."
    )
    supporting_evidence: list[PredictionEvidence] = Field(default_factory=list, max_length=32)
    contradicting_evidence: list[PredictionEvidence] = Field(default_factory=list, max_length=32)
    evidence_gaps: list[BoundedShort] = Field(default_factory=list, max_length=32)
    unresolved_questions: list[BoundedShort] = Field(default_factory=list, max_length=32)
    evidence_support: EvidenceSupport
    limitations: list[PredictionLimitation] = Field(default_factory=list, max_length=32)
    provenance: PredictionProvenance = Provenance.AI_GENERATED

    @model_validator(mode="after")
    def _bands_and_stances_agree(self) -> PredictionUncertainty:
        for item in self.supporting_evidence:
            if item.stance is not EvidenceStance.SUPPORTING:
                raise ValueError("supporting_evidence must carry SUPPORTING stance")
        for item in self.contradicting_evidence:
            if item.stance is not EvidenceStance.CONTRADICTING:
                raise ValueError("contradicting_evidence must carry CONTRADICTING stance")
        overlap = {e.reference for e in self.supporting_evidence} & {
            e.reference for e in self.contradicting_evidence
        }
        if overlap:
            raise ValueError(
                f"a reference cannot both support and contradict one prediction: {sorted(overlap)}"
            )
        return self

    @property
    def is_contested(self) -> bool:
        from app.services.prediction.vocabulary import CONTESTED_THRESHOLD

        return len(self.contradicting_evidence) >= CONTESTED_THRESHOLD


class AttackPrediction(BaseModel):
    """One predicted future progression.

    The central artifact.  It has no field capable of asserting that anything
    occurred — no status, severity, or outcome.  Only a prediction of what is
    plausible *next*.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    prediction_id: uuid.UUID
    prediction_kind: PredictionKind
    depth: PredictionDepth
    status: PredictionStatus
    target: Annotated[str, Field(min_length=1, max_length=128)]
    target_basis: TargetBasis
    technique: AttackTechnique
    rationale: PredictionRationale
    uncertainty: PredictionUncertainty
    provenance: PredictionProvenance = Provenance.AI_GENERATED

    @property
    def confidence(self) -> float:
        """Plausibility that the predicted progression occurs."""
        return self.uncertainty.confidence

    @model_validator(mode="after")
    def _status_matches_evidence(self) -> AttackPrediction:
        from app.services.prediction.vocabulary import CONTESTED_THRESHOLD

        supporting = len(self.uncertainty.supporting_evidence)
        contradicting = len(self.uncertainty.contradicting_evidence)
        if self.status is PredictionStatus.INSUFFICIENT_EVIDENCE and supporting:
            raise ValueError(
                "a prediction with supporting evidence must not be reported as "
                "INSUFFICIENT_EVIDENCE"
            )
        if self.status is PredictionStatus.INSUFFICIENT_EVIDENCE and contradicting:
            raise ValueError(
                "INSUFFICIENT_EVIDENCE must not be paired with contradicting evidence"
            )
        if self.status is PredictionStatus.CONTESTED and contradicting < CONTESTED_THRESHOLD:
            raise ValueError(
                f"CONTESTED requires at least {CONTESTED_THRESHOLD} contradicting "
                "references; contradictions are never suppressed"
            )
        return self


class PredictionMetadata(BaseModel):
    """Analytical metadata for one prediction session.

    Records what the prediction was derived *from*, so a consumer can tell a
    prediction grounded in persisted evidence from one that leaned on a debate,
    and can reproduce the inputs exactly.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    engine_version: Annotated[str, Field(max_length=48)]
    prediction_configuration_digest: Digest
    graph_snapshot_digest: Digest
    debate_id: Annotated[str, Field(max_length=64)] | None = None
    debate_consensus_state: Annotated[str, Field(max_length=48)] | None = None
    debate_provider: Annotated[str, Field(max_length=48)] | None = None
    debate_model: Annotated[str, Field(max_length=48)] | None = None
    graph_node_count: Annotated[int, Field(ge=0)]
    graph_edge_count: Annotated[int, Field(ge=0)]
    observed_technique_count: Annotated[int, Field(ge=0)]
    max_depth: Annotated[int, Field(ge=1, le=2)]
    unavailable_inputs: dict[str, str] = Field(
        default_factory=dict, description="Declared-unavailable inputs with reasons."
    )
    limitations: list[PredictionLimitation] = Field(default_factory=list, max_length=32)
    provenance: PredictionProvenance = Provenance.AI_GENERATED


class PredictionResult(BaseModel):
    """The complete output of one prediction session.

    ``status`` is the session-level outcome.  A session that legitimately
    refuses to speculate reports ``INSUFFICIENT_EVIDENCE`` with an empty
    ``predictions`` list and explicit limitations — that is a success, not an
    error.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    prediction_session_id: uuid.UUID
    correlation_id: uuid.UUID
    status: PredictionStatus
    predictions: list[AttackPrediction] = Field(default_factory=list, max_length=32)
    current_state: list[PredictionEvidence] = Field(
        default_factory=list,
        max_length=64,
        description="Persisted evidence that defines the current security state.",
    )
    observed_techniques: list[str] = Field(
        default_factory=list, max_length=32, description="Persisted ATT&CK technique ids."
    )
    metadata: PredictionMetadata
    limitations: list[PredictionLimitation] = Field(default_factory=list, max_length=32)
    limitations_note: BoundedShort = Field(
        ...,
        description="Always-present statement that predictions are not evidence.",
    )
    provenance: PredictionProvenance = Provenance.AI_GENERATED

    @model_validator(mode="after")
    def _session_status_is_consistent(self) -> PredictionResult:
        if self.status is PredictionStatus.INSUFFICIENT_EVIDENCE and self.predictions:
            raise ValueError(
                "a session reported INSUFFICIENT_EVIDENCE must not carry predictions"
            )
        if self.predictions and self.status is PredictionStatus.INSUFFICIENT_EVIDENCE:
            raise ValueError("predictions cannot accompany an insufficient-evidence session")
        for prediction in self.predictions:
            if prediction.status is PredictionStatus.INSUFFICIENT_EVIDENCE:
                raise ValueError(
                    "an individual prediction with supporting evidence must not be "
                    "reported INSUFFICIENT_EVIDENCE"
                )
        return self


class PredictionFailureResponse(BaseModel):
    """Governed failure payload.

    Shaped by the same contract family as the success payload, so a client can
    never receive a prediction-shaped response for a failed run.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    correlation_id: uuid.UUID | None = None
    prediction_session_id: uuid.UUID | None = None
    status: Literal["failed"] = "failed"
    failure_code: BoundedShort
    detail: BoundedShort
    provenance: PredictionProvenance = Provenance.AI_GENERATED


# ---------------------------------------------------------------------------
# Input contracts
# ---------------------------------------------------------------------------
#
# These describe everything the engine may read.  Assembling inputs separately
# from reasoning keeps the predictive step pure: the engine takes a value,
# touches no database, clock, or network, and returns a deterministic result.


class ObservedTechnique(BaseModel):
    """An ATT&CK technique actually persisted on a detection in this correlation.

    Constructed only by reading a real detection row.  ``supporting_refs`` are
    the graph references of the detections carrying the mapping, so a technique
    claim is always traceable to specific persisted rows.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    technique_id: Annotated[str, Field(min_length=4, max_length=10)]
    technique_name: str | None = Field(default=None, max_length=128)
    tactic: str | None = Field(default=None, max_length=64)
    supporting_refs: list[Reference] = Field(default_factory=list, max_length=32)
    detection_count: Annotated[int, Field(default=0, ge=0)]

    @field_validator("technique_id")
    @classmethod
    def _id_shape_is_valid(cls, technique_id: str) -> str:
        """Enforce the ATT&CK shape at the engine's input boundary.

        This is the second door onto a technique id, and it matters: without it
        a malformed persisted value would reach the engine and then fail
        *inside* output construction as a raw ``ValidationError``, turning
        corrupt input into an opaque 500 instead of a governed refusal here.
        The value is normalized (so a persisted ``"t1021"`` reads consistently
        as ``"T1021"``) but never invented.
        """
        normalized = validate_technique_id(technique_id)
        if normalized is None:
            raise ValueError(
                "observed technique_id must match the ATT&CK technique shape; only "
                "an id read from a persisted detection row may appear here"
            )
        return normalized

    @property
    def support_breadth(self) -> int:
        """Distinct detections independently carrying this technique."""
        return len(self.supporting_refs)


class AvailableReference(BaseModel):
    """A persisted source a prediction may cite."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    reference: Reference
    entity_kind: Annotated[str, Field(min_length=1, max_length=64)]
    node_id: Reference


class DebateHypothesis(BaseModel):
    """One debate hypothesis, reduced to what prediction may consume."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hypothesis_id: PredictionId
    statement: BoundedText
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    category_label: Annotated[str, Field(max_length=64)]
    supporting_refs: list[Reference] = Field(default_factory=list, max_length=32)
    contesting_refs: list[Reference] = Field(default_factory=list, max_length=32)


class DebateSummary(BaseModel):
    """The parts of a V3.23 debate the prediction engine is allowed to read.

    A reduced, explicit view rather than the whole session, so the engine cannot
    accidentally come to depend on debate internals it has no business using
    (§6, §42).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    debate_id: uuid.UUID
    consensus_state: Annotated[str, Field(max_length=48)]
    consensus_strength: Annotated[float, Field(ge=0.0, le=1.0)]
    leading_hypothesis: BoundedText | None = None
    unresolved_questions: list[BoundedShort] = Field(default_factory=list, max_length=32)
    evidence_gaps: list[BoundedShort] = Field(default_factory=list, max_length=32)
    dissent_positions: list[BoundedShort] = Field(default_factory=list, max_length=32)
    provider: Annotated[str, Field(max_length=48)]
    model: str | None = Field(default=None, max_length=48)
    hypotheses: list[DebateHypothesis] = Field(default_factory=list, max_length=64)


class PredictionInputs(BaseModel):
    """Everything the engine is allowed to read, as an explicit value."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    correlation_id: uuid.UUID
    graph_snapshot_digest: Digest
    graph_node_count: Annotated[int, Field(ge=0)]
    graph_edge_count: Annotated[int, Field(ge=0)]
    graph_truncated: bool = False
    graph_truncated_reason: str | None = Field(default=None, max_length=64)
    observed_techniques: dict[str, ObservedTechnique] = Field(default_factory=dict)
    evidence_refs: dict[str, AvailableReference] = Field(default_factory=dict)
    debate: DebateSummary | None = None
    unavailable_inputs: dict[str, str] = Field(default_factory=dict)
    bounds: PredictionBounds = DEFAULT_PREDICTION_BOUNDS

    def available_references(self) -> list[AvailableReference]:
        """Resolvable references in deterministic order."""
        return [self.evidence_refs[key] for key in sorted(self.evidence_refs)]


__all__ = [
    "AttackPrediction",
    "AttackTechnique",
    "AvailableReference",
    "DebateHypothesis",
    "DebateSummary",
    "ObservedTechnique",
    "PredictionEvidence",
    "PredictionFailureResponse",
    "PredictionInputs",
    "PredictionLimitation",
    "PredictionMetadata",
    "PredictionProvenance",
    "PredictionRationale",
    "PredictionResult",
    "PredictionUncertainty",
]