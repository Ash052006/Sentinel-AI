"""Strict model-output contract for the V3.23 debate agents.

A debate agent may only emit the *reasoning* half of a debate.  The evidence
half is supplied by the engine.  Concretely, this contract makes the
following structurally unrepresentable:

* **A fact.**  ``observation_kind`` accepts only ``observation`` and
  ``hypothesis``; there is no ``fact`` field anywhere.  Facts are derived
  mechanically by :mod:`app.agents.debate.evidence`.  A model that tries to
  assert a fact is either producing an evidenced observation (checked against
  the catalog) or an explicit hypothesis — never a fact.
* **An evidence object.**  Agents supply reference *strings* only.  The engine
  resolves them against the closed catalog and owns the resulting typed
  :class:`~app.schemas.debate.EvidenceReference`.  An agent therefore cannot
  describe its own evidence, attach its own provenance to it, or invent one.
* **Provenance.**  Absent by design; the engine pins every claim to
  ``ai_generated``.
* **Confidence on the final result.**  ``confidence`` here is the agent's own
  view of its assessment.  The debate's reported confidence is computed
  deterministically by the engine from agreement, evidence support,
  completeness, and contradiction — never taken from a model.
* **Ids, timestamps, counters, verdict words.**  All are assigned or computed
  by the engine from sorted, content-derived keys.

``extra="forbid"`` throughout, and every list and string is bounded.  Bounds
**reject** rather than truncate, so an oversized or malformed response fails
closed instead of silently producing a smaller debate that looks complete.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.agents.debate.vocabulary import (
    DEFAULT_BOUNDS,
    MODEL_ALLOWED_CLAIM_KINDS,
    ArgumentStance,
    WeaknessKind,
)


def _require_non_blank(value: str) -> str:
    if not value.strip():
        raise ValueError("must not be blank")
    return value


def _require_maximum(value: str, maximum: int) -> str:
    if len(value) > maximum:
        raise ValueError(
            f"exceeds the maximum length of {maximum} characters; the output "
            "is rejected rather than truncated"
        )
    return value


# ---------------------------------------------------------------------------
# Round 1 — independent assessment
# ---------------------------------------------------------------------------


class ModelObservation(BaseModel):
    """A model-proposed observation or hypothesis.

    ``observation_kind`` is deliberately a two-value literal rather than an enum
    that includes ``fact``: the absence of ``fact`` is the control.
    """

    model_config = ConfigDict(extra="forbid")

    observation_kind: Literal["observation", "hypothesis"]
    statement: str = Field(min_length=1, max_length=DEFAULT_BOUNDS.max_claim_text_length)
    evidence_references: list[str] = Field(
        max_length=DEFAULT_BOUNDS.max_evidence_references_per_claim,
        description=(
            "Reference strings copied verbatim from the supplied evidence "
            "catalog.  Resolution is enforced by the engine; an unknown "
            "reference rejects the entire output."
        ),
    )
    confidence: float = Field(ge=0.0, le=1.0)

    @field_validator("observation_kind")
    @classmethod
    def _kind_is_allowed(cls, v: str) -> str:
        if v not in MODEL_ALLOWED_CLAIM_KINDS:
            raise ValueError(
                f"claim kind {v!r} is not permitted; a debate agent may "
                f"produce only {sorted(MODEL_ALLOWED_CLAIM_KINDS)} — facts are "
                "derived by the engine from persisted evidence"
            )
        return v

    @field_validator("statement")
    @classmethod
    def _statement_valid(cls, v: str) -> str:
        _require_non_blank(v)
        return _require_maximum(v, DEFAULT_BOUNDS.max_claim_text_length)

    def model_post_init(self, _context: object) -> None:
        # An observation that cites nothing is an assertion wearing an
        # observation's label, so it is rejected structurally.
        if self.observation_kind == "observation" and not self.evidence_references:
            raise ValueError(
                "an observation must cite at least one evidence reference from "
                "the supplied catalog"
            )
        if not self.evidence_references:
            raise ValueError(
                "every claim must cite at least one evidence reference "
                "(supporting or contradicting); uncited speculation is not "
                "admissible in a debate"
            )


class ModelLimitations(BaseModel):
    """The model's own account of what it could not establish."""

    model_config = ConfigDict(extra="forbid")

    limitations: list[str] = Field(
        max_length=DEFAULT_BOUNDS.max_limitations_per_agent
    )

    @field_validator("limitations")
    @classmethod
    def _items_valid(cls, v: list[str]) -> list[str]:
        for item in v:
            _require_non_blank(item)
            _require_maximum(item, DEFAULT_BOUNDS.max_claim_text_length)
        return v


class DebateAssessmentOutput(BaseModel):
    """Round-1 output: one agent's independent view of the shared evidence."""

    model_config = ConfigDict(extra="forbid")

    observations: list[ModelObservation] = Field(
        max_length=DEFAULT_BOUNDS.max_observations_per_agent
    )
    hypotheses: list[ModelObservation] = Field(
        max_length=DEFAULT_BOUNDS.max_hypotheses_per_agent
    )
    limitations: ModelLimitations
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="The agent's own confidence in its assessment.",
    )

    @field_validator("observations")
    @classmethod
    def _observations_are_observations(cls, v: list[ModelObservation]) -> list[ModelObservation]:
        for item in v:
            if item.observation_kind != "observation":
                raise ValueError(
                    "the 'observations' array may contain only items with "
                    "observation_kind='observation'"
                )
        return v

    @field_validator("hypotheses")
    @classmethod
    def _hypotheses_are_hypotheses(cls, v: list[ModelObservation]) -> list[ModelObservation]:
        for item in v:
            if item.observation_kind != "hypothesis":
                raise ValueError(
                    "the 'hypotheses' array may contain only items with "
                    "observation_kind='hypothesis'"
                )
        return v

    @field_validator("confidence")
    @classmethod
    def _confidence_is_number(cls, v: float) -> float:
        if v != v:  # NaN
            raise ValueError("confidence must be a real number")
        return v


# ---------------------------------------------------------------------------
# Round 2 — cross-agent arguments
# ---------------------------------------------------------------------------


class ModelArgument(BaseModel):
    """A model-proposed position on another agent's hypothesis."""

    model_config = ConfigDict(extra="forbid")

    stance: Literal["supports", "opposes"]
    target_hypothesis_id: str = Field(
        min_length=1,
        max_length=128,
        description=(
            "The 'hypothesis_id' copied from the debate brief.  Resolution is "
            "enforced by the engine; an unknown id rejects the entire output."
        ),
    )
    target_agent_id: str = Field(min_length=1, max_length=128)
    statement: str = Field(min_length=1, max_length=DEFAULT_BOUNDS.max_claim_text_length)
    evidence_references: list[str] = Field(
        min_length=1,
        max_length=DEFAULT_BOUNDS.max_evidence_references_per_claim,
        description="At least one real reference backing this argument.",
    )

    @field_validator("statement")
    @classmethod
    def _statement_valid(cls, v: str) -> str:
        _require_non_blank(v)
        return _require_maximum(v, DEFAULT_BOUNDS.max_claim_text_length)

    @field_validator("stance")
    @classmethod
    def _stance_valid(cls, v: str) -> str:
        if v not in {s.value for s in ArgumentStance}:
            raise ValueError(f"unsupported stance {v!r}")
        return v


class DebateArgumentsOutput(BaseModel):
    """Round-2 output: cross-agent arguments plus open questions."""

    model_config = ConfigDict(extra="forbid")

    arguments: list[ModelArgument] = Field(
        max_length=DEFAULT_BOUNDS.max_arguments_per_agent
    )
    unresolved_questions: list[str] = Field(
        max_length=DEFAULT_BOUNDS.max_unresolved_questions
    )

    @field_validator("unresolved_questions")
    @classmethod
    def _questions_valid(cls, v: list[str]) -> list[str]:
        for item in v:
            _require_non_blank(item)
            _require_maximum(item, DEFAULT_BOUNDS.max_claim_text_length)
        return v


# ---------------------------------------------------------------------------
# Round 3 — counterarguments
# ---------------------------------------------------------------------------


class ModelCounterargument(BaseModel):
    """A model-proposed challenge to an existing argument.

    ``evidence_references`` is ``min_length=1`` for every weakness kind,
    including ``missing_evidence``.  That is the control that stops the skeptic
    from manufacturing doubt out of nothing: a challenge must point at
    something real that is present in the catalog.
    """

    model_config = ConfigDict(extra="forbid")

    target_argument_id: str = Field(min_length=1, max_length=128)
    weakness: Literal[
        "contradictory_evidence",
        "weak_evidence",
        "missing_evidence",
        "alternative_explanation",
        "overconfidence",
        "unsupported_assumption",
    ]
    statement: str = Field(min_length=1, max_length=DEFAULT_BOUNDS.max_claim_text_length)
    evidence_references: list[str] = Field(
        min_length=1,
        max_length=DEFAULT_BOUNDS.max_evidence_references_per_claim,
    )

    @field_validator("statement")
    @classmethod
    def _statement_valid(cls, v: str) -> str:
        _require_non_blank(v)
        return _require_maximum(v, DEFAULT_BOUNDS.max_claim_text_length)

    @field_validator("weakness")
    @classmethod
    def _weakness_valid(cls, v: str) -> str:
        if v not in {w.value for w in WeaknessKind}:
            raise ValueError(f"unsupported weakness kind {v!r}")
        return v


class DebateCounterargumentsOutput(BaseModel):
    """Round-3 output: challenges to round-2 arguments."""

    model_config = ConfigDict(extra="forbid")

    counterarguments: list[ModelCounterargument] = Field(
        max_length=DEFAULT_BOUNDS.max_counterarguments_per_agent
    )


# ---------------------------------------------------------------------------
# JSON Schema handed to Gemini as its structured-output response schema
# ---------------------------------------------------------------------------

_OBSERVATION_SCHEMA: dict = {
    "type": "OBJECT",
    "properties": {
        "observation_kind": {"type": "STRING", "enum": ["observation", "hypothesis"]},
        "statement": {"type": "STRING"},
        "evidence_references": {"type": "ARRAY", "items": {"type": "STRING"}},
        "confidence": {"type": "NUMBER"},
    },
    "required": ["observation_kind", "statement", "evidence_references", "confidence"],
}

DEBATE_ASSESSMENT_JSON_SCHEMA: dict = {
    "type": "OBJECT",
    "properties": {
        "observations": {"type": "ARRAY", "items": _OBSERVATION_SCHEMA},
        "hypotheses": {"type": "ARRAY", "items": _OBSERVATION_SCHEMA},
        "limitations": {
            "type": "OBJECT",
            "properties": {
                "limitations": {"type": "ARRAY", "items": {"type": "STRING"}}
            },
            "required": ["limitations"],
        },
        "confidence": {"type": "NUMBER"},
    },
    "required": ["observations", "hypotheses", "limitations", "confidence"],
}

DEBATE_ARGUMENTS_JSON_SCHEMA: dict = {
    "type": "OBJECT",
    "properties": {
        "arguments": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "stance": {"type": "STRING", "enum": ["supports", "opposes"]},
                    "target_hypothesis_id": {"type": "STRING"},
                    "target_agent_id": {"type": "STRING"},
                    "statement": {"type": "STRING"},
                    "evidence_references": {
                        "type": "ARRAY",
                        "items": {"type": "STRING"},
                    },
                },
                "required": [
                    "stance",
                    "target_hypothesis_id",
                    "target_agent_id",
                    "statement",
                    "evidence_references",
                ],
            },
        },
        "unresolved_questions": {"type": "ARRAY", "items": {"type": "STRING"}},
    },
    "required": ["arguments", "unresolved_questions"],
}

DEBATE_COUNTERARGUMENTS_JSON_SCHEMA: dict = {
    "type": "OBJECT",
    "properties": {
        "counterarguments": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "target_argument_id": {"type": "STRING"},
                    "weakness": {
                        "type": "STRING",
                        "enum": [w.value for w in WeaknessKind],
                    },
                    "statement": {"type": "STRING"},
                    "evidence_references": {
                        "type": "ARRAY",
                        "items": {"type": "STRING"},
                    },
                },
                "required": [
                    "target_argument_id",
                    "weakness",
                    "statement",
                    "evidence_references",
                ],
            },
        }
    },
    "required": ["counterarguments"],
}


__all__ = [
    "DEBATE_ARGUMENTS_JSON_SCHEMA",
    "DEBATE_ASSESSMENT_JSON_SCHEMA",
    "DEBATE_COUNTERARGUMENTS_JSON_SCHEMA",
    "DebateArgumentsOutput",
    "DebateAssessmentOutput",
    "DebateCounterargumentsOutput",
    "ModelArgument",
    "ModelCounterargument",
    "ModelLimitations",
    "ModelObservation",
]