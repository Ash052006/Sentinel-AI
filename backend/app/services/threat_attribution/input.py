"""Threat Attribution Engine input contract — Step 15.

Defines the *explicit structured attribution signal* the Step 15 engine
consumes.  Inspecting the completed SentinelAI contracts shows that no
upstream contract (Detection, Correlation, Risk, Investigation 12A/12B,
Knowledge 13, or Threat Intelligence) currently exposes a structured
attribution target field — there is no ``threat_actor`` / ``malware_family``
/ ``campaign`` column anywhere.  The engine therefore refuses to guess
identifiers from prose, geolocation, risk, detection tags, provider payload
text, or RAG relevance (documented in ``docs/development/threat_attribution_engine.md``),
and instead requires callers to declare explicit attribution claims.

An :class:`AttributionClaim` is a single structured statement of the form
*"the referenced source evidence supports/conflicts attributing the
correlated activity to target T (as a threat-group / malware-family / ...
with identifier I)."*  Every candidate target the engine may emit MUST come
from such a claim — the engine cannot and does not invent targets.

The claim's evidence is provenance-aware and references an existing source
record exactly like the Step 14 ``AttributionEvidence`` map:

* ``OBSERVED`` / ``ENRICHED`` / ``RECONSTRUCTED`` → ``event_id``
* ``DETECTED`` → ``detection_id``
* ``CORRELATED`` → ``correlation_id``
* ``RISK_ASSESSED`` → ``risk_assessment_id``
* ``AI_GENERATED`` → ``investigation_id``
* ``ATTRIBUTION_ASSESSED`` → **forbidden** (an attribution hypothesis is a
  conclusion, never a source signal)

:class:`AttributionContext` carries optional, *observation-only* context
(risk level, investigation confidence, RAG document count).  These fields
are validated and bounded but are **never consulted by the attribution
policy**; they exist so callers can prove (and tests can assert) that the
engine is independent of risk scoring, investigation confidence, and RAG.
Secrets are rejected by the *engine* as :class:`AttributionSafetyError`;
this contract validates JSON-safety, bounds, cloning, and reference
coherence only.
"""

from __future__ import annotations

import json
import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from app.schemas.security_event import Provenance
from app.schemas.threat_attribution import (
    AttributionTargetType,
    MAX_ATTRIBUTION_LABEL_LENGTH,
    MAX_ATTRIBUTION_METADATA_DEPTH,
    MAX_ATTRIBUTION_METADATA_SERIALIZED_BYTES,
    MAX_ATTRIBUTION_TARGET_IDENTIFIER_LENGTH,
)
from app.schemas.risk import RiskLevel

# ---------------------------------------------------------------------------
# Engine-level bounds (Step 15)
# ---------------------------------------------------------------------------

#: Maximum number of structured attribution claims per input.  Equal to the
#: Step 14 ``MAX_ATTRIBUTION_EVIDENCE_ITEMS`` bound because each claim maps
#: to exactly one attribution evidence record.
MAX_ATTRIBUTION_CLAIMS = 250

#: Maximum nested metadata depth, mirrors the Step 14 metadata bound.
MAX_CLAIM_METADATA_DEPTH = MAX_ATTRIBUTION_METADATA_DEPTH

#: Maximum serialized metadata size, mirrors the Step 14 metadata bound.
MAX_CLAIM_METADATA_SERIALIZED_BYTES = MAX_ATTRIBUTION_METADATA_SERIALIZED_BYTES


# ---------------------------------------------------------------------------
# Structural helpers (lock-step with the Step 14 / 12B helper sets)
# ---------------------------------------------------------------------------


def _assert_json_compatible(value: Any, field: str) -> None:
    try:
        json.dumps(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be JSON-compatible: {exc}") from exc


def _json_clone(value: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(value))


def _container_depth(value: Any) -> int:
    if isinstance(value, dict):
        return 1 + max((_container_depth(child) for child in value.values()), default=0)
    if isinstance(value, (list, tuple)):
        return 1 + max((_container_depth(child) for child in value), default=0)
    return 0


def _bound_string(value: Any, field: str, max_length: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a non-blank string")
    stripped = value.strip()
    if not stripped:
        raise ValueError(f"{field} must not be blank")
    if len(stripped) > max_length:
        raise ValueError(
            f"{field} exceeds the maximum length of {max_length} characters"
        )
    return stripped


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class AttributionRelation(str, Enum):
    """Whether a claim's evidence supports or conflicts with a target."""

    SUPPORTS = "supports"
    CONFLICTS = "conflicts"


# ---------------------------------------------------------------------------
# Attribution claim
# ---------------------------------------------------------------------------


class AttributionClaim(BaseModel):
    """One explicit structured attribution signal.

    ``"the referenced evidence supports/conflicts attributing the activity
    to <target_type> '<target_identifier>'."``  The target is explicit and
    named; the engine never fabricates it, and a claim with
    ``target_type = unknown`` is rejected by the engine as an unsupported
    signal.
    """

    model_config = {"extra": "ignore"}

    claim_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    target_type: AttributionTargetType = Field(
        ...,
        description="Category of the named candidate (never 'unknown' here).",
    )
    target_identifier: str = Field(
        ...,
        description="Explicit, bounded, secret-free identifier of the candidate.",
    )
    relationship: AttributionRelation = Field(
        default=AttributionRelation.SUPPORTS,
        description="Whether this claim's evidence supports or conflicts with the target.",
    )
    evidence_type: str = Field(
        ...,
        description="Short machine-readable label for the evidence kind.",
    )
    provenance: Provenance = Field(
        ...,
        description="Source provenance backing the evidence reference.",
    )
    event_id: uuid.UUID | None = None
    detection_id: uuid.UUID | None = None
    correlation_id: uuid.UUID | None = None
    risk_assessment_id: uuid.UUID | None = None
    investigation_id: uuid.UUID | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("target_identifier")
    @classmethod
    def _target_identifier_bounded(cls, v: Any) -> str:
        return _bound_string(
            v, "target_identifier", MAX_ATTRIBUTION_TARGET_IDENTIFIER_LENGTH
        )

    @field_validator("evidence_type")
    @classmethod
    def _evidence_type_bounded(cls, v: Any) -> str:
        return _bound_string(v, "evidence_type", MAX_ATTRIBUTION_LABEL_LENGTH)

    @field_validator("metadata")
    @classmethod
    def _metadata_valid(cls, v: Any) -> dict[str, Any]:
        if v is None:
            return {}
        _assert_json_compatible(v, "claim metadata")
        if _container_depth(v) > MAX_CLAIM_METADATA_DEPTH:
            raise ValueError("claim metadata exceeds the maximum nesting depth")
        if len(json.dumps(v)) > MAX_CLAIM_METADATA_SERIALIZED_BYTES:
            raise ValueError(
                "claim metadata exceeds the maximum serialized size of "
                f"{MAX_CLAIM_METADATA_SERIALIZED_BYTES} bytes"
            )
        return _json_clone(v)

    @field_validator("provenance")
    @classmethod
    def _source_provenance_only(cls, v: Any) -> Provenance:
        if v is Provenance.ATTRIBUTION_ASSESSED:
            raise ValueError(
                "an attribution claim must be source-backed; ATTRIBUTION_ASSESSED "
                "provenance is a conclusion, never a source signal"
            )
        return v

    @model_validator(mode="after")
    def _ensure_reference_coherent(self) -> "AttributionClaim":
        required = {
            Provenance.OBSERVED: "event_id",
            Provenance.ENRICHED: "event_id",
            Provenance.RECONSTRUCTED: "event_id",
            Provenance.DETECTED: "detection_id",
            Provenance.CORRELATED: "correlation_id",
            Provenance.RISK_ASSESSED: "risk_assessment_id",
            Provenance.AI_GENERATED: "investigation_id",
        }
        needed = required.get(self.provenance)
        if needed is not None and getattr(self, needed) is None:
            raise ValueError(
                f"{self.provenance.value} attribution claim must reference "
                f"{needed}; a provenance category cannot be attached without "
                "its matching source identity"
            )
        return self


# ---------------------------------------------------------------------------
# Observation-only context (never consulted by the policy)
# ---------------------------------------------------------------------------


class AttributionContext(BaseModel):
    """Optional context noted by the caller but never used for attribution.

    These fields exist so a caller can attach the surrounding pipeline
    state (risk level, investigation confidence, RAG document count) to the
    request.  The Step 15 policy explicitly never reads them: risk scoring,
    investigation confidence, and RAG relevance are independent of
    attribution and must not influence its result.
    """

    model_config = {"extra": "ignore"}

    risk_level: RiskLevel | None = Field(
        default=None,
        description="Observation-only; never consulted by the attribution policy.",
    )
    investigation_confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Observation-only; never consulted by the attribution policy.",
    )
    rag_documents_retrieved: int | None = Field(
        default=None,
        ge=0,
        description="Observation-only; never consulted by the attribution policy.",
    )


# ---------------------------------------------------------------------------
# Engine input
# ---------------------------------------------------------------------------


class ThreatAttributionInput(BaseModel):
    """Validated input to the Step 15 Threat Attribution Engine.

    Contains only structured information the engine is allowed to use: the
    correlation anchor (``correlation_id``), an explicit, bounded list of
    attribution claims, and optional observation-only context that the
    policy never reads.
    """

    model_config = {"extra": "ignore"}

    correlation_id: uuid.UUID = Field(...)
    claims: list[AttributionClaim] = Field(default_factory=list)
    context: AttributionContext | None = Field(default=None)

    @field_validator("claims")
    @classmethod
    def _claims_bounded(cls, v: list[AttributionClaim]) -> list[AttributionClaim]:
        if len(v) > MAX_ATTRIBUTION_CLAIMS:
            raise ValueError(
                f"attribution input exceeds the maximum of "
                f"{MAX_ATTRIBUTION_CLAIMS} claims"
            )
        return v