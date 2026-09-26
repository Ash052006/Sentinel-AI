"""Strict model-output contract for the V2.20 incident report generator.

The LLM may only produce the free-form prose an incident report needs; the
application — never the model — owns authoritative fields (report id,
correlation identity, provenance, evidence catalog, deterministic section
records, timestamps, risk, availability).

This module defines a tightly bounded representation of the model's allowed
output (mirroring ``app/agents/investigation/model_output.py`` conventions):

* ``title`` / ``executive_summary`` / ``incident_overview`` /
  ``investigation_summary`` / ``attribution_summary`` /
  ``threat_hunting_summary`` / ``response_summary`` — bounded prose.
* ``findings`` — bounded findings whose ``evidence_references`` cite supplied
  catalog reference ids only (resolution is enforced by the generator).
* ``limitations`` / ``recommended_follow_up`` — bounded string lists.

The contract forbids unknown fields (``extra="forbid"``): provenance, ids,
timestamps, risk scores, response actions, and raw evidence are structurally
unrepresentable.  Bounds **reject** rather than truncate.

``INCIDENT_REPORT_MODEL_JSON_SCHEMA`` is the JSON-Schema description sent to
Gemini as its structured-output ``responseSchema`` (the same Gemini
OBJECT/ARRAY/STRING/NUMBER format used by the Step 12C investigation
agent); the Pydantic contract below remains the authoritative validation of
the returned payload.
"""

from __future__ import annotations

import json

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.incident_report import (
    MAX_REPORT_FINDINGS,
    MAX_REPORT_FINDING_EVIDENCE_REFERENCES,
    MAX_REPORT_FOLLOW_UP_ITEMS,
    MAX_REPORT_LIMITATIONS,
    MAX_REPORT_PROSE_LENGTH,
    MAX_REPORT_STRING_LENGTH,
    MAX_REPORT_TITLE_LENGTH,
    ReportFinding,
)


# ---------------------------------------------------------------------------
# Output bounds — reject, never truncate.
# ---------------------------------------------------------------------------

#: Maximum serialized size of the complete model output.
MAX_REPORT_MODEL_OUTPUT_BYTES = 256 * 1024


# ---------------------------------------------------------------------------
# Model output contract (strict, extra-forbidden).
# ---------------------------------------------------------------------------


class IncidentReportModelOutput(BaseModel):
    """The complete, strictly-validated content Gemini may produce."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(
        min_length=1,
        max_length=MAX_REPORT_TITLE_LENGTH,
        description="Concise report title.",
    )
    executive_summary: str = Field(
        min_length=1,
        max_length=MAX_REPORT_PROSE_LENGTH,
        description="AI-grounded executive summary.",
    )
    incident_overview: str = Field(
        min_length=1,
        max_length=MAX_REPORT_PROSE_LENGTH,
        description="AI prose overview grounded in the incident facts.",
    )
    investigation_summary: str = Field(
        min_length=1,
        max_length=MAX_REPORT_PROSE_LENGTH,
        description="AI overview of investigation availability.",
    )
    attribution_summary: str = Field(
        min_length=1,
        max_length=MAX_REPORT_PROSE_LENGTH,
        description="AI overview of attribution availability.",
    )
    threat_hunting_summary: str = Field(
        min_length=1,
        max_length=MAX_REPORT_PROSE_LENGTH,
        description="AI summary of the actual completed hunts provided.",
    )
    response_summary: str = Field(
        min_length=1,
        max_length=MAX_REPORT_PROSE_LENGTH,
        description="AI summary of the persisted policy/approval/SOAR records.",
    )
    findings: list[ReportFinding] = Field(
        default_factory=list,
        max_length=MAX_REPORT_FINDINGS,
        description="Findings in the model's order; catalog refs resolved by "
        "the generator.",
    )
    limitations: list[str] = Field(
        default_factory=list,
        max_length=MAX_REPORT_LIMITATIONS,
        description="AI-stated limitations over unavailable/bounded sources.",
    )
    recommended_follow_up: list[str] = Field(
        default_factory=list,
        max_length=MAX_REPORT_FOLLOW_UP_ITEMS,
        description="Evidence-grounded follow-up items.",
    )

    @model_validator(mode="after")
    def _enforce_total_size_bound(self) -> "IncidentReportModelOutput":
        size = len(self.model_dump_json().encode("utf-8"))
        if size > MAX_REPORT_MODEL_OUTPUT_BYTES:
            raise ValueError(
                "model output exceeds "
                f"MAX_REPORT_MODEL_OUTPUT_BYTES={MAX_REPORT_MODEL_OUTPUT_BYTES} "
                f"(serialized size {size}); the output is rejected rather "
                "than truncated"
            )
        return self


# ---------------------------------------------------------------------------
# JSON Schema handed to Gemini as its structured-output response schema.
# ---------------------------------------------------------------------------

INCIDENT_REPORT_MODEL_JSON_SCHEMA: dict = {
    "type": "OBJECT",
    "properties": {
        "title": {"type": "STRING"},
        "executive_summary": {"type": "STRING"},
        "incident_overview": {"type": "STRING"},
        "investigation_summary": {"type": "STRING"},
        "attribution_summary": {"type": "STRING"},
        "threat_hunting_summary": {"type": "STRING"},
        "response_summary": {"type": "STRING"},
        "findings": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "title": {"type": "STRING"},
                    "summary": {"type": "STRING"},
                    "evidence_references": {
                        "type": "ARRAY",
                        "items": {"type": "STRING"},
                    },
                },
                "required": ["title", "summary", "evidence_references"],
            },
        },
        "limitations": {"type": "ARRAY", "items": {"type": "STRING"}},
        "recommended_follow_up": {"type": "ARRAY", "items": {"type": "STRING"}},
    },
    "required": [
        "title",
        "executive_summary",
        "incident_overview",
        "investigation_summary",
        "attribution_summary",
        "threat_hunting_summary",
        "response_summary",
        "findings",
        "limitations",
        "recommended_follow_up",
    ],
}


def parse_model_output(text: str) -> IncidentReportModelOutput:
    """Strictly parse *text* into the validated model-output contract.

    Raises:
        ReportValidationError: when the payload is malformed JSON or fails
            the strict contract (extra fields, out-of-range sizes, invalid
            reference ids, etc.).
    """
    from app.services.reporting.errors import ReportValidationError

    try:
        data = json.loads(text)
    except (TypeError, ValueError) as exc:
        raise ReportValidationError(
            "the model output was not valid JSON"
        ) from exc
    if not isinstance(data, dict):
        raise ReportValidationError(
            "the model output must be a single JSON object"
        )
    try:
        return IncidentReportModelOutput.model_validate(data)
    except Exception as exc:
        # Pydantic validation errors are safe (field paths only), but we
        # never echo raw provider payloads; surface the first reason only.
        reasons = getattr(exc, "errors", None)
        detail = "the model output failed strict validation"
        if callable(reasons):
            first = reasons()[0] if reasons() else None
            if first is not None:
                loc = ".".join(str(part) for part in first.get("loc", ()))
                msg = str(first.get("msg", ""))
                detail = f"{detail}: {loc}: {msg}"
        raise ReportValidationError(detail) from exc


__all__ = [
    "MAX_REPORT_MODEL_OUTPUT_BYTES",
    "IncidentReportModelOutput",
    "INCIDENT_REPORT_MODEL_JSON_SCHEMA",
    "parse_model_output",
]