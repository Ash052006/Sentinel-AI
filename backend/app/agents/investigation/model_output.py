"""Strict model-output contract for the Step 12C AI Investigation Agent.

Gemini may only produce the information necessary to construct
:class:`~app.schemas.investigation.InvestigationFinding` and
:class:`~app.schemas.investigation.InvestigationObservation` objects.  The
agent — never the model — owns authoritative fields (investigation id,
provenance, evidence records, timestamps, risk, correlation/detection
identities).

This module therefore defines a tightly bounded representation of the
model's allowed output:

* ``findings`` — type, title, optional summary, confidence in [0.0, 1.0],
  and evidence-id references (referencing supplied context evidence only —
  resolution is enforced by the agent).
* ``observations`` — type and text only (the agent assigns AI_GENERATED
  provenance per Step 12A semantics).

The contract forbids unknown fields (``extra="forbid"``): provenance,
evidence objects, ids, timestamps, risk scores, incidents, MITRE mappings,
and response actions are structurally unrepresentable.  Bounds **reject**
rather than truncate; the constants below are compatible with the Step 12A /
12B limits (never increasing them).

``INVESTIGATION_MODEL_JSON_SCHEMA`` is the JSON-Schema description sent to
Gemini as its structured-output ``responseSchema``; the Pydantic contract
below remains the authoritative validation of the actual returned payload.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Output bounds — reject, never truncate.
# ---------------------------------------------------------------------------

#: Maximum number of findings the model may return.
MAX_MODEL_FINDINGS = 20

#: Maximum number of observations the model may return.
MAX_MODEL_OBSERVATIONS = 20

#: Maximum number of evidence references a single finding may carry
#: (each reference is one supplied-context evidence id).
MAX_MODEL_EVIDENCE_REFERENCES = 64

#: Maximum length of any single string the model may return (labels,
#: titles, summaries, observation text).  Matches the Step 12B context
#: string bound; never increased.
MAX_MODEL_STRING_LENGTH = 4096

#: Maximum serialized size of the complete model output.
MAX_MODEL_OUTPUT_BYTES = 64 * 1024


# ---------------------------------------------------------------------------
# Model output contract
# ---------------------------------------------------------------------------


def _ensure_not_blank(value: str) -> str:
    stripped = value.strip()
    if not stripped:
        raise ValueError("must not be blank")
    return value


class ModelFindingOutput(BaseModel):
    """A model-proposed finding conclusion (provenance is never accepted)."""

    model_config = ConfigDict(extra="forbid")

    finding_type: str = Field(
        min_length=1,
        max_length=MAX_MODEL_STRING_LENGTH,
        description="Machine-readable conclusion label.",
    )
    title: str = Field(
        min_length=1,
        max_length=MAX_MODEL_STRING_LENGTH,
        description="Concise human-readable conclusion label.",
    )
    summary: str | None = Field(
        default=None,
        max_length=MAX_MODEL_STRING_LENGTH,
        description="Optional short structured summary.",
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Finding confidence in [0.0, 1.0].",
    )
    evidence_ids: list[uuid.UUID] = Field(
        max_length=MAX_MODEL_EVIDENCE_REFERENCES,
        description=(
            "References to supplied-context evidence ids.  Resolution is "
            "enforced by the agent."
        ),
    )

    @field_validator("finding_type")
    @classmethod
    def _type_not_blank(cls, v: str) -> str:
        return _ensure_not_blank(v)

    @field_validator("title")
    @classmethod
    def _title_not_blank(cls, v: str) -> str:
        return _ensure_not_blank(v)

    @field_validator("summary")
    @classmethod
    def _summary_not_blank(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return _ensure_not_blank(v)


class ModelObservationOutput(BaseModel):
    """A model-proposed investigation observation (type + text only)."""

    model_config = ConfigDict(extra="forbid")

    observation_type: str = Field(
        min_length=1,
        max_length=MAX_MODEL_STRING_LENGTH,
        description="Machine-readable observation label.",
    )
    observation_text: str = Field(
        min_length=1,
        max_length=MAX_MODEL_STRING_LENGTH,
        description="The structured contextual statement.",
    )

    @field_validator("observation_type")
    @classmethod
    def _type_not_blank(cls, v: str) -> str:
        return _ensure_not_blank(v)

    @field_validator("observation_text")
    @classmethod
    def _text_not_blank(cls, v: str) -> str:
        return _ensure_not_blank(v)


class InvestigationModelOutput(BaseModel):
    """The complete, strictly-validated content Gemini may produce."""

    model_config = ConfigDict(extra="forbid")

    findings: list[ModelFindingOutput] = Field(
        max_length=MAX_MODEL_FINDINGS,
        description="Findings in the model's order; refs resolved by agent.",
    )
    observations: list[ModelObservationOutput] = Field(
        max_length=MAX_MODEL_OBSERVATIONS,
        description="Observations in the model's order.",
    )

    @model_validator(mode="after")
    def _enforce_total_size_bound(self) -> "InvestigationModelOutput":
        size = len(self.model_dump_json().encode("utf-8"))
        if size > MAX_MODEL_OUTPUT_BYTES:
            raise ValueError(
                "model output exceeds "
                f"MAX_MODEL_OUTPUT_BYTES={MAX_MODEL_OUTPUT_BYTES} "
                f"(serialized size {size}); the output is rejected "
                "rather than truncated"
            )
        return self


# ---------------------------------------------------------------------------
# JSON Schema handed to Gemini as its structured-output response schema.
# ---------------------------------------------------------------------------

INVESTIGATION_MODEL_JSON_SCHEMA: dict = {
    "type": "OBJECT",
    "properties": {
        "findings": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "finding_type": {"type": "STRING"},
                    "title": {"type": "STRING"},
                    "summary": {"type": "STRING"},
                    "confidence": {"type": "NUMBER"},
                    "evidence_ids": {
                        "type": "ARRAY",
                        "items": {"type": "STRING"},
                    },
                },
                "required": [
                    "finding_type",
                    "title",
                    "summary",
                    "confidence",
                    "evidence_ids",
                ],
            },
        },
        "observations": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "observation_type": {"type": "STRING"},
                    "observation_text": {"type": "STRING"},
                },
                "required": ["observation_type", "observation_text"],
            },
        },
    },
    "required": ["findings", "observations"],
}