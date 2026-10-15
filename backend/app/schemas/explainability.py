"""Evidence-Grounded Explainability contract.

Defines the validated response of the Explainability capability: a
deterministic, source-backed explanation of *why* SentinelAI reached a
conclusion about a correlation, together with an optional AI narrative whose
every claim resolves to a real, referenced piece of evidence.

The contract exists so the platform can **explain its reasoning without
inventing evidence**:

* **Grounded, not generated** — every ``DimensionExplanation`` is derived from
  already-persisted SentinelAI records (correlation, detections, risk
  assessment, approvals, SOAR executions).  A dimension that has no persisted
  source is reported as ``unavailable``/``none_found`` with an explicit reason
  — never fabricated prose.  The AI never authors these dimensions.
* **AI is an explainer, never a source** — the optional AI narrative reuses the
  Step 12A :class:`~app.schemas.investigation.InvestigationFinding` /
  ``InvestigationObservation`` / ``InvestigationEvidence`` contracts.  Findings
  are pinned ``AI_GENERATED`` and may only *reference* evidence that exists on
  the result; the model cannot add evidence.
* **Unsupported claims are flagged** — an AI finding that cites no evidence is
  surfaced in ``unsupported_claims`` rather than presented as grounded.
* **Provenance honesty** — each dimension carries the provenance of the source
  it describes (``CORRELATED`` / ``DETECTED`` / ``RISK_ASSESSED`` /
  ``APPROVAL_REVIEWED`` / ``RESPONSE_EXECUTED`` / ``RECALLED``), while the
  overall result is pinned ``AI_GENERATED`` exactly like an ``InvestigationResult``.
* **Secret-safe** — every metadata/claim payload is strict JSON, deeply cloned,
  and rejects credential-shaped content, mirroring the Step 9A/10A/11A/12A
  boundaries.

Pipeline::

    persisted records (correlation / members / detections / risk /
        approvals / SOAR / memory)
            -> ExplanationService  (deterministic dimensions)
            + InvestigationAgent    (optional AI narrative)
                -> ExplainabilityResult (this contract)
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from app.schemas.investigation import (
    InvestigationEvidence,
    InvestigationFinding,
    InvestigationObservation,
)
from app.schemas.security_event import Provenance

#: Forbidden credential-shaped strings re-checked at this boundary.  Kept in
#: lock-step with the Step 9A / 10A / 11A / 12A contracts.
_SECRET_PATTERNS = ("api_key", "authorization", "bearer", "secret")


def _assert_json_compatible(value: Any, field: str) -> None:
    try:
        json.dumps(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be JSON-compatible: {exc}") from exc


def _assert_no_secrets(value: Any, field: str) -> None:
    serialized = json.dumps(value).lower()
    for pattern in _SECRET_PATTERNS:
        if pattern in serialized:
            raise ValueError(
                f"{field} must not contain secrets ('{pattern}' detected)"
            )


def _json_clone(value: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(value))


def _require_non_blank(value: str, field: str) -> str:
    stripped = value.strip()
    if not stripped:
        raise ValueError(f"{field} must not be blank")
    return stripped


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ExplanationStatus(str, Enum):
    """Overall outcome of one explanation request.

    * ``explained`` — grounded dimensions were produced and, when requested,
      the AI narrative succeeded.
    * ``insufficient_evidence`` — grounded dimensions were produced but no AI
      narrative was requested or the model produced no usable conclusion.
    * ``ai_unavailable`` — the grounded dimensions are complete; the AI
      narrative could not be produced (provider not configured/timeout/
      failure).  Degrade honestly rather than fail the request.
    """

    EXPLAINED = "explained"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    AI_UNAVAILABLE = "ai_unavailable"


class ExplanationDimension(str, Enum):
    """The security concepts an explanation accounts for."""

    DETECTION = "detection"
    CORRELATION = "correlation"
    RISK = "risk"
    MITRE = "mitre"
    POLICY = "policy"
    RESPONSE = "response"
    AUDIT = "audit"


class DimensionCoverage(str, Enum):
    """How completely a dimension could be grounded in persisted records.

    * ``grounded`` — one or more persisted records back this dimension.
    * ``none_found`` — the source exists but holds nothing for this
      correlation (e.g. no approval requests were ever raised).
    * ``unavailable`` — the platform persists no source for this dimension
      (e.g. MITRE technique mappings); the gap is stated, never invented.
    """

    GROUNDED = "grounded"
    NONE_FOUND = "none_found"
    UNAVAILABLE = "unavailable"


# ---------------------------------------------------------------------------
# Dimension claim
# ---------------------------------------------------------------------------


class ExplanationClaim(BaseModel):
    """One deterministic statement plus the evidence that supports it.

    ``text`` is assembled by the platform from persisted values only.  A claim
    that carries ``evidence_ids`` is verifiable against the result's evidence;
    a claim with none is a summary statement (e.g. a count) and is never
    presented as an interpretation.
    """

    text: str = Field(..., min_length=1)
    evidence_ids: list[uuid.UUID] = Field(default_factory=list)

    @field_validator("text")
    @classmethod
    def _ensure_not_blank(cls, v: str) -> str:
        return _require_non_blank(v, "claim text")


# ---------------------------------------------------------------------------
# Dimension explanation
# ---------------------------------------------------------------------------


class DimensionExplanation(BaseModel):
    """Deterministic, source-backed explanation of one security concept.

    The AI never authors this structure: it is assembled by the platform from
    persisted records.  ``reference_ids`` are the domain identities the
    dimension cites (correlation/detection/risk-assessment/approval/SOAR ids)
    so a reader can follow every statement back to its source record.
    """

    dimension: ExplanationDimension
    coverage: DimensionCoverage
    title: str = Field(..., min_length=1)
    summary: str = Field(..., min_length=1)
    provenance: Provenance = Field(
        ...,
        description=(
            "Provenance of the records this dimension describes.  Never "
            "AI_GENERATED — the AI does not produce deterministic dimensions."
        ),
    )
    claims: list[ExplanationClaim] = Field(default_factory=list)
    reference_ids: list[uuid.UUID] = Field(default_factory=list)
    unavailable_reason: str | None = Field(default=None)

    @field_validator("title", "summary")
    @classmethod
    def _ensure_not_blank(cls, v: str) -> str:
        return _require_non_blank(v, "title/summary")

    @field_validator("provenance")
    @classmethod
    def _ensure_not_ai_generated(cls, v: Provenance) -> Provenance:
        if v is Provenance.AI_GENERATED:
            raise ValueError(
                "deterministic explanation dimensions must not carry "
                "AI_GENERATED provenance"
            )
        return v

    @field_validator("unavailable_reason")
    @classmethod
    def _ensure_reason_not_blank(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return _require_non_blank(v, "unavailable_reason")

    @model_validator(mode="after")
    def _ensure_coverage_consistency(self) -> "DimensionExplanation":
        if self.coverage is DimensionCoverage.UNAVAILABLE:
            if not self.unavailable_reason:
                raise ValueError(
                    "an unavailable dimension must state an "
                    "unavailable_reason"
                )
        elif self.unavailable_reason is not None:
            raise ValueError(
                "only an unavailable dimension may carry an "
                "unavailable_reason"
            )
        return self


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------


class ExplainabilityResult(BaseModel):
    """The complete, validated output of one explanation request.

    * ``correlation_id`` — the correlation being explained (a reference).
    * ``generated_at`` — timezone-aware instant the explanation was built.
    * ``dimensions`` — deterministic, source-backed explanations.
    * ``narrative`` — the optional AI conclusions (Step 12A findings).  Empty
      when no AI narrative was requested or the provider was unavailable.
    * ``evidence`` — the source-backed evidence available to the AI; every
      finding's ``evidence_ids`` resolve here.
    * ``unsupported_claims`` — AI finding titles that cite no evidence.  These
      are explicitly flagged rather than presented as grounded.
    * ``limitations`` — deterministic, human-readable statements of what the
      platform could not ground.
    * ``provenance`` — always ``AI_GENERATED`` (this is an explanation of the
      pipeline's reasoning, not new telemetry).
    """

    correlation_id: uuid.UUID
    generated_at: datetime
    status: ExplanationStatus
    dimensions: list[DimensionExplanation] = Field(default_factory=list)
    ai_provider: str | None = Field(default=None)
    ai_model: str | None = Field(default=None)
    narrative: list[InvestigationFinding] = Field(default_factory=list)
    observations: list[InvestigationObservation] = Field(default_factory=list)
    evidence: list[InvestigationEvidence] = Field(default_factory=list)
    unsupported_claims: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    provenance: Provenance = Field(default=Provenance.AI_GENERATED)

    @field_validator("generated_at")
    @classmethod
    def _ensure_timezone_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError(
                "generated_at must be timezone-aware; naive timestamps are "
                "not accepted"
            )
        return v

    @field_validator("metadata")
    @classmethod
    def _ensure_metadata_valid(cls, v: dict[str, Any]) -> dict[str, Any]:
        _assert_json_compatible(v, "metadata")
        _assert_no_secrets(v, "metadata")
        return _json_clone(v)

    @field_validator("provenance")
    @classmethod
    def _ensure_ai_generated_provenance(cls, v: Provenance) -> Provenance:
        if v is not Provenance.AI_GENERATED:
            raise ValueError(
                "explainability results are AI-generated explanations of the "
                "pipeline's reasoning and must carry AI_GENERATED provenance; "
                f"got {v.value!r}"
            )
        return v


class ExplanationRequest(BaseModel):
    """Request body for an on-demand explanation.

    ``use_ai`` requests the optional AI narrative in addition to the
    deterministic, source-backed dimensions.  When ``False`` only grounded
    dimensions are returned (status ``insufficient_evidence``).  The body never
    carries a role or authorization claim — those come from the authenticated
    user.
    """

    use_ai: bool = Field(
        default=True,
        description=(
            "Also produce the AI narrative.  AI failures degrade gracefully "
            "to status 'ai_unavailable' with the deterministic dimensions "
            "intact."
        ),
    )


__all__ = [
    "ExplanationStatus",
    "ExplanationDimension",
    "DimensionCoverage",
    "ExplanationClaim",
    "DimensionExplanation",
    "ExplanationRequest",
    "ExplainabilityResult",
]
