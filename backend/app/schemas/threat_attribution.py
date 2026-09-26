"""Step 14 Threat Attribution domain contract.

**Scope.** This module defines the *domain contract* for representing
threat-attribution hypotheses and assessments.  It deliberately contains
**no attribution logic**: it does not determine attribution, calculate
attribution confidence, call an LLM, query RAG knowledge, persist
attribution assessments, expose an API, or perform response or
mitigation.  It only validates and transports the structured shape that a
future attribution engine may fill.

**Contract policy.** The contract does **not** assume attribution is
always possible.

- An assessment carries an explicit ``AttributionStatus`` chosen by the
  caller (``attributed``, ``partially_supported``, ``uncertain``,
  ``insufficient_evidence``, ``conflicting``, ``unattributed``).
- ``status`` is categorical and is **never derived** from ``confidence``
  or from hypothesis counts.  A hypothesis with ``confidence == 0.8`` can
  coexist with an assessment whose ``status`` is ``uncertain``; nothing in
  this module converts, aggregates, or infers one from the other.
- Confidence is a single per-hypothesis concept bounded to ``[0, 1]``.  It
  is fully independent of risk, detection, investigation, and relevance
  scores; no score conversion or normalized-scoring formula exists here.
- Conflicting evidence is *supported* (a hypothesis may cite evidence both
  for and against it) but is **never auto-resolved**: both lists are
  preserved and a reference may not appear on both sides of the same
  hypothesis.
- Attribution hypotheses are *assessments over available evidence* and
  must never be treated as independently observed security facts.  Every
  hypothesis and the assessment itself is pinned to
  ``Provenance.ATTRIBUTION_ASSESSED``.

**Evidence model.** Attribution evidence is a typed, provenance-aware
reference to an existing source object in the pipeline:

- ``OBSERVED`` / ``ENRICHED`` / ``RECONSTRUCTED`` require ``event_id``
- ``DETECTED`` requires ``detection_id``
- ``CORRELATED`` requires ``correlation_id``
- ``RISK_ASSESSED`` requires ``risk_assessment_id``
- ``AI_GENERATED`` requires ``investigation_id`` (investigator-produced
  reasoning is a contextual reference, and the authoritative
  ``InvestigationResult.investigation_id`` is used, not a synthesized
  result identifier)
- ``ATTRIBUTION_ASSESSED`` is **forbidden** on evidence: an attribution
  hypothesis is a conclusion, not a source of evidence.

AI-generated reasoning is therefore never treated as automatic source
evidence; it may only be *referenced* with explicit ``AI_GENERATED``
provenance, and its role must be defensible by the future attribution
engine.

**Provenance.** This contract reuses the global ``Provenance`` enum from
:mod:`app.schemas.security_event`; it does not create a duplicate.  The
additive member ``attribution_assessed`` was introduced there,
backward-compatibly, with regression tests for all prior provenance
values.  See the enum docstring for the reasoning.

**Unknown fields.** Pydantic's default ``extra="ignore"`` policy is used
exactly as everywhere else in the SentinelAI schemas (this is asserted by
``TestUnknownFields`` in the Step 12A contract tests).  No
``extra="forbid"`` is introduced.

**Determinism.** Module state is immutable after construction; there is no
hidden clock (the assessment ``timestamp`` must be supplied explicitly)
and no sorting or deduplication mutates list order.  Identical inputs
produce identical ``model_dump_json()`` output.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from enum import Enum
from math import isfinite
from typing import Any

from pydantic import (
    BaseModel,
    Field,
    model_validator,
    field_validator,
)

from app.schemas.security_event import Provenance

# ---------------------------------------------------------------------------
# Bound constants
# ---------------------------------------------------------------------------
# These are hard contract limits, not configuration: values that exceed
# them are REJECTED (never truncated), preserving deterministic, bounded
# output.

MAX_ATTRIBUTION_HYPOTHESES = 10
MAX_ATTRIBUTION_EVIDENCE_ITEMS = 250
MAX_ATTRIBUTION_TARGET_IDENTIFIER_LENGTH = 256
MAX_ATTRIBUTION_LABEL_LENGTH = 512
MAX_ATTRIBUTION_METADATA_DEPTH = 8
MAX_ATTRIBUTION_METADATA_SERIALIZED_BYTES = 4 * 1024

# ---------------------------------------------------------------------------
# Secret / JSON safety helpers
#
# These local helpers mirror the canonical secret and JSON-safety patterns
# used by every staged schema contract (Steps 11A risk, 12A investigation,
# 12B/12C context, Step 13 knowledge).  They are deliberately re-declared
# in this module (rather than imported across modules) so each staged
# contract stays self-contained and testable in isolation; they are kept
# in lock-step with the canonical set.
# ---------------------------------------------------------------------------

_SECRET_PATTERNS = (
    "api_key",
    "authorization",
    "bearer",
    "secret",
    "password",
    "cookie",
    "session_token",
    "jwt",
)


def _assert_no_secrets(obj: Any, label: str) -> None:
    """Reject secret-shaped content anywhere in *obj*.

    Matching the canonical Step 13 behavior, the content is serialized and
    scanned as text, so secret-shaped *values* (e.g. a target identifier
    whose name contains ``secret``) are rejected exactly like secret-shaped
    keys.  This is a shape-based scan: a benign-looking value under a
    field named ``password`` is still rejected if the field name appears
    in the serialized content.
    """
    serialized = json.dumps(obj).lower()
    for pattern in _SECRET_PATTERNS:
        if pattern in serialized:
            raise ValueError(
                f"{label} must not contain secret-shaped content "
                "('{pattern}'); secrets are rejected, never redacted".format(
                    pattern=pattern
                )
            )


def _is_json_compatible(value: Any, depth: int = 0) -> bool:
    """True when *value* is recursively JSON-compatible and depth-bounded.

    Rejects sets, bytes, arbitrary objects, ``NaN``/``Infinity`` and
    excessive nesting.  Cycles cannot reach this validator on Pydantic
    model input (an input containing a cycle must be an already-instantiated
    mutable object; after validation it is deep-cloned so such state can
    never be serialized).
    """
    if isinstance(value, dict):
        if depth >= MAX_ATTRIBUTION_METADATA_DEPTH:
            return False
        return all(
            isinstance(k, str) and _is_json_compatible(v, depth + 1)
            for k, v in value.items()
        )
    if isinstance(value, list):
        if depth >= MAX_ATTRIBUTION_METADATA_DEPTH:
            return False
        return all(_is_json_compatible(v, depth + 1) for v in value)
    if isinstance(value, bool):
        return True
    if isinstance(value, (int, float)):
        if isinstance(value, float) and not isfinite(value):
            return False
        return True
    if value is None:
        return True
    if isinstance(value, str):
        return True
    return False


def _assert_json_compatible(obj: Any, label: str) -> None:
    """Reject values Python cannot strictly JSON-serialize.

    ``json.dumps`` first (canonical Step 13 pattern) rejects sets, bytes,
    arbitrary objects, and reference cycles; the structural check then
    rejects ``NaN``/``Infinity`` and excessive nesting depth.  This is a
    rejection, never a repair.
    """
    try:
        json.dumps(obj)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"{label} must be JSON-compatible: {exc}"
        ) from exc
    if not _is_json_compatible(obj):
        raise ValueError(
            f"{label} must be JSON-compatible (no sets, bytes, arbitrary "
            "objects, NaN, Infinity or excessive depth)"
        )


def _json_clone(obj: Any) -> Any:
    """Deep clone via JSON round-trip to guarantee input isolation.

    Unhashable, non-JSON values were already rejected by the JSON
    validator, so the JSON round-trip always succeeds for validated input.
    """
    if isinstance(obj, (dict, list)):
        return json.loads(json.dumps(obj))
    return obj


def _bound_label(value: Any, field: str, max_length: int = MAX_ATTRIBUTION_LABEL_LENGTH) -> str:
    """Reject blank (whitespace-only) text and bound its length.

    Mirrors the Step 12A ``_require_non_blank`` behavior (whitespace-only
    text is rejected and returned text is stripped) while adding the
    Step 13-style length bound.  Content is never truncated.
    """
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


class AttributionStatus(str, Enum):
    """Categorical outcome of a threat-attribution assessment.

    Purely descriptive: the status is supplied by the caller and is never
    derived from confidence values or from hypothesis/evidence counts.
    """

    ATTRIBUTED = "attributed"
    PARTIALLY_SUPPORTED = "partially_supported"
    UNCERTAIN = "uncertain"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    CONFLICTING = "conflicting"
    UNATTRIBUTED = "unattributed"


class AttributionTargetType(str, Enum):
    """Category of thing an attribution hypothesis points at."""

    THREAT_ACTOR = "threat_actor"
    THREAT_GROUP = "threat_group"
    MALWARE_FAMILY = "malware_family"
    CAMPAIGN = "campaign"
    INFRASTRUCTURE = "infrastructure"
    TECHNIQUE_CLUSTER = "technique_cluster"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


class AttributionEvidence(BaseModel):
    """A single provenance-aware reference to an existing source object.

    A hypothesis cites evidence by this object's ``evidence_id``.  The
    evidence itself references an already-existing pipeline object (event,
    detection, correlation, risk assessment, or investigation result);
    this contract does not embed or re-derive that data.
    """

    model_config = {"extra": "ignore"}

    evidence_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    evidence_type: str = Field(description="Short, bounded label for the evidence kind.")
    provenance: Provenance = Field(
        description="Backs the evidence with an existing source object."
    )
    event_id: uuid.UUID | None = None
    detection_id: uuid.UUID | None = None
    correlation_id: uuid.UUID | None = None
    risk_assessment_id: uuid.UUID | None = None
    investigation_id: uuid.UUID | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("evidence_type")
    @classmethod
    def _ensure_evidence_type_bound(cls, v: Any) -> str:
        label = _bound_label(v, "evidence_type")
        _assert_no_secrets(label, "evidence_type")
        return label

    @field_validator("metadata")
    @classmethod
    def _ensure_metadata_safe(cls, v: Any) -> dict[str, Any]:
        if v is None:
            return {}
        _assert_json_compatible(v, "evidence metadata")
        _assert_no_secrets(v, "evidence metadata")
        if len(json.dumps(v)) > MAX_ATTRIBUTION_METADATA_SERIALIZED_BYTES:
            raise ValueError(
                "evidence metadata exceeds the maximum serialized size of "
                f"{MAX_ATTRIBUTION_METADATA_SERIALIZED_BYTES} bytes"
            )
        return _json_clone(v)

    @model_validator(mode="after")
    def _ensure_provenance_coherent(self) -> "AttributionEvidence":
        """Enforce the provenance-to-reference map and forbidden values.

        Attribution evidence references *existing* pipeline objects only;
        it never references an attribution assessment (attribution
        hypotheses are conclusions over evidence, not evidence itself).
        """
        if self.provenance is Provenance.ATTRIBUTION_ASSESSED:
            raise ValueError(
                "attribution evidence must never carry ATTRIBUTION_ASSESSED "
                "provenance: an attribution hypothesis is a conclusion over "
                "evidence, not a source of evidence"
            )
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
                f"{self.provenance.value} attribution evidence must "
                f"reference {needed}; a provenance category cannot be "
                "attached without its matching source identity"
            )
        return self


# ---------------------------------------------------------------------------
# Hypothesis
# ---------------------------------------------------------------------------


class AttributionHypothesis(BaseModel):
    """A single evidence-grounded attribution hypothesis.

    Names a target category and identifier, binds a single ``confidence``
    in ``[0, 1]``, and cites supporting and conflicting attribution
    evidence by ``evidence_id``.  Conflicting evidence is preserved, never
    auto-resolved; a reference may not appear on both sides of the same
    hypothesis.
    """

    model_config = {"extra": "ignore"}

    hypothesis_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    target_type: AttributionTargetType
    target_identifier: str = Field(description="Bounded, secret-free identifier.")
    confidence: float = Field(ge=0.0, le=1.0, description="Single per-hypothesis confidence.")
    supporting_evidence_ids: list[uuid.UUID] = Field(default_factory=list)
    conflicting_evidence_ids: list[uuid.UUID] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    provenance: Provenance = Field(default=Provenance.ATTRIBUTION_ASSESSED)

    @field_validator("target_identifier")
    @classmethod
    def _ensure_target_identifier_bound(cls, v: Any) -> str:
        label = _bound_label(v, "target_identifier", MAX_ATTRIBUTION_TARGET_IDENTIFIER_LENGTH)
        _assert_no_secrets(label, "target_identifier")
        return label

    @field_validator("confidence", mode="before")
    @classmethod
    def _ensure_confidence_finite(cls, v: Any) -> Any:
        if isinstance(v, bool):
            raise ValueError("confidence must be a finite floating-point number")
        if isinstance(v, (int, float)) and not isfinite(v):
            raise ValueError("confidence must be finite")
        return v

    @field_validator("metadata")
    @classmethod
    def _ensure_metadata_safe(cls, v: Any) -> dict[str, Any]:
        if v is None:
            return {}
        _assert_json_compatible(v, "hypothesis metadata")
        _assert_no_secrets(v, "hypothesis metadata")
        if len(json.dumps(v)) > MAX_ATTRIBUTION_METADATA_SERIALIZED_BYTES:
            raise ValueError(
                "hypothesis metadata exceeds the maximum serialized size of "
                f"{MAX_ATTRIBUTION_METADATA_SERIALIZED_BYTES} bytes"
            )
        return _json_clone(v)

    @field_validator("provenance")
    @classmethod
    def _ensure_attribution_pinned(cls, v: Any) -> Provenance:
        if v is not Provenance.ATTRIBUTION_ASSESSED:
            raise ValueError(
                "an attribution hypothesis must be pinned to "
                "ATTRIBUTION_ASSESSED provenance; it is an assessment over "
                "evidence, never observed telemetry"
            )
        return v

    @model_validator(mode="after")
    def _ensure_no_self_conflict(self) -> "AttributionHypothesis":
        """Reject a reference cited as both supporting and conflicting."""
        overlap = set(self.supporting_evidence_ids) & set(self.conflicting_evidence_ids)
        if overlap:
            sorted_ids = sorted(str(i) for i in overlap)
            raise ValueError(
                f"evidence references {sorted_ids} cannot be both supporting "
                "and conflicting in the same attribution hypothesis; "
                "conflicting evidence is preserved but never auto-resolved"
            )
        return self

    @model_validator(mode="after")
    def _ensure_secret_free(self) -> "AttributionHypothesis":
        _assert_no_secrets(self.model_dump_json(), "attribution hypothesis")
        return self


# ---------------------------------------------------------------------------
# Assessment
# ---------------------------------------------------------------------------


class AttributionAssessment(BaseModel):
    """Root of a threat-attribution assessment.

    Anchored to the pipeline by a required ``correlation_id`` (mirroring
    the risk and investigation contracts) and pinned to
    ``Provenance.ATTRIBUTION_ASSESSED``.  The categorical ``status`` is
    caller-supplied and never derived from confidence or hypothesis
    counts.  Every hypothesis evidence reference must resolve to an
    evidence item carried by this assessment.
    """

    model_config = {"extra": "ignore"}

    attribution_assessment_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    correlation_id: uuid.UUID
    status: AttributionStatus
    hypotheses: list[AttributionHypothesis] = Field(
        default_factory=list,
        description=(
            "Bounded list of attribution hypotheses "
            f"(max {MAX_ATTRIBUTION_HYPOTHESES})."
        ),
    )
    evidence: list[AttributionEvidence] = Field(
        default_factory=list,
        description=(
            "Bounded list of typed, provenance-aware evidence "
            f"(max {MAX_ATTRIBUTION_EVIDENCE_ITEMS})."
        ),
    )
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime
    provenance: Provenance = Field(default=Provenance.ATTRIBUTION_ASSESSED)

    @field_validator("timestamp", mode="before")
    @classmethod
    def _reject_numeric_timestamp(cls, v: Any) -> Any:
        """Reject numeric/bool coercion of datetime inputs.

        Pydantic otherwise interprets a float as an epoch timestamp (so a
        misspelled numeric value silently becomes a date); the contract
        rejects that coercion instead of accepting it.
        """
        if isinstance(v, (int, float, bool)) and not isinstance(v, datetime):
            raise ValueError("timestamp must be a datetime, not a numeric value")
        return v

    @field_validator("timestamp")
    @classmethod
    def _ensure_aware_timestamp(cls, v: Any) -> datetime:
        if not isinstance(v, datetime):
            raise ValueError("timestamp must be a datetime")
        if v.tzinfo is None or v.utcoffset() is None:
            raise ValueError(
                "timestamp must be timezone-aware (naive datetimes are rejected)"
            )
        return v

    @field_validator("evidence")
    @classmethod
    def _ensure_evidence_bounded(cls, v: Any) -> list[AttributionEvidence]:
        if len(v) > MAX_ATTRIBUTION_EVIDENCE_ITEMS:
            raise ValueError(
                f"assessment evidence exceeds the maximum of "
                f"{MAX_ATTRIBUTION_EVIDENCE_ITEMS} items"
            )
        return v

    @field_validator("hypotheses")
    @classmethod
    def _ensure_hypotheses_bounded(cls, v: Any) -> list[AttributionHypothesis]:
        if len(v) > MAX_ATTRIBUTION_HYPOTHESES:
            raise ValueError(
                f"assessment hypotheses exceed the maximum of "
                f"{MAX_ATTRIBUTION_HYPOTHESES} hypotheses"
            )
        return v

    @field_validator("metadata")
    @classmethod
    def _ensure_metadata_safe(cls, v: Any) -> dict[str, Any]:
        if v is None:
            return {}
        _assert_json_compatible(v, "assessment metadata")
        _assert_no_secrets(v, "assessment metadata")
        if len(json.dumps(v)) > MAX_ATTRIBUTION_METADATA_SERIALIZED_BYTES:
            raise ValueError(
                "assessment metadata exceeds the maximum serialized size of "
                f"{MAX_ATTRIBUTION_METADATA_SERIALIZED_BYTES} bytes"
            )
        return _json_clone(v)

    @field_validator("provenance")
    @classmethod
    def _ensure_attribution_pinned(cls, v: Any) -> Provenance:
        if v is not Provenance.ATTRIBUTION_ASSESSED:
            raise ValueError(
                "an attribution assessment must be pinned to "
                "ATTRIBUTION_ASSESSED provenance"
            )
        return v

    @model_validator(mode="after")
    def _ensure_evidence_references_resolve(self) -> "AttributionAssessment":
        """Every hypothesis evidence reference must resolve locally."""
        present = {str(e.evidence_id) for e in self.evidence}
        missing: set[str] = set()
        for h in self.hypotheses:
            for ref in [*h.supporting_evidence_ids, *h.conflicting_evidence_ids]:
                if str(ref) not in present:
                    missing.add(str(ref))
        if missing:
            raise ValueError(
                "attribution assessment hypotheses reference evidence not "
                f"present in this assessment: {sorted(missing)}"
            )
        return self

    @model_validator(mode="after")
    def _ensure_secret_free(self) -> "AttributionAssessment":
        _assert_no_secrets(self.model_dump_json(), "attribution assessment")
        return self