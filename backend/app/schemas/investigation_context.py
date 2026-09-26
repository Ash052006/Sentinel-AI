"""Investigation Context Contract and Builder — Step 12B.

Defines the validated, bounded, deterministic representation of the
**inputs** to a future AI investigation, and a pure builder that converts
already-existing SentinelAI domain outputs into that representation.

This module is the **trust boundary** between trusted SentinelAI domain
data and the future AI Investigation Agent (Step 12C)::

    CorrelationResult
          +
    RiskAssessment
          +
    Detection evidence
          +
    Threat-intelligence/enrichment context
          |
          v
    InvestigationContextBuilder      (Step 12B — this module)
          |
          v
    InvestigationContext             (Step 12B — this module)
          |
          v
    [Future AI Investigation Agent]  (Step 12C)

Design principles (mirroring the existing SentinelAI contracts — Step 9A
detection, Step 9I detection-to-correlation, Step 10A correlation, Step
11A risk, Step 11D risk query, Step 12A investigation):

* **Allowlisting** — the builder never serializes a whole source object
  with ``model_dump()``/``model_dump_json()``; each source type maps
  through an explicit field allowlist so future internal fields can never
  leak into the AI context.
* **Contract only** — no investigation, no inference, no findings, no
  observations-as-conclusions, no persistence, no API, no LLM/prompt
  templates.  The builder carries *data*; it performs no analysis.
* **Provenance-preserving** — every evidence-bearing context item keeps
  its source provenance.  Nothing is ever upgraded, downgraded, or
  relabelled: ``RECONSTRUCTED`` stays ``RECONSTRUCTED``, ``ENRICHED`` stays
  ``ENRICHED``, ``DETECTED``/``CORRELATED``/``RISK_ASSESSED`` are pinned,
  and undeclared origins are never claimed as ``OBSERVED``.
* **DATA != INSTRUCTION** — security telemetry (log strings, indicator
  values, provider result payloads, metadata) is carried as structured
  data.  It is never wrapped in prompt instructions, never concatenated
  into a control string, and can never alter context policy, provenance,
  bounds, or risk.
* **Bounded** — explicit, documented constants bound list sizes, string
  lengths, metadata depth/size, and the total serialized context.  All
  bounds **reject** rather than silently truncate security evidence.
* **Secret-safe** — the repository refuse-to-carry policy
  (``api_key``/``authorization``/``bearer``/``secret``) is extended at this
  AI trust boundary with credential families explicitly demanded by
  Step 12B (``password``/``cookie``/``session_token``/``jwt``).
* **Deterministic & immutable** — identical inputs produce byte-identical
  serialization; the builder never mutates sources and never shares
  mutable state with them; no current time or random value affects the
  security content (identity and context-created-at bookkeeping are
  injectable).
* **Dependency-light** — stdlib + Pydantic + existing SentinelAI domain
  schemas only.  No SQLAlchemy, FastAPI, Kafka, HTTP clients, or AI
  frameworks.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable, Literal, Mapping

from pydantic import BaseModel, Field, field_validator, model_validator

from app.schemas.correlation import CorrelationResult, CorrelationStatus
from app.schemas.detection import DetectionResult, DetectionSeverity, RuleType
from app.schemas.detection_correlation import (
    DetectionCorrelationBatch,
    DetectionCorrelationInput,
    to_correlation_input,
)
from app.schemas.detection_query import DetectionResultRecord
from app.schemas.enriched_event import EnrichmentResult
from app.schemas.incident_memory import MAX_MEMORY_SOURCES, MemoryType
from app.schemas.incident_memory_query import IncidentMemoryRecord
from app.schemas.investigation import InvestigationEvidence
from app.schemas.risk import RiskAssessment, RiskLevel
from app.schemas.security_event import Provenance
from app.schemas.threat_intelligence_agent import (
    ThreatIntelligenceAnalysis,
)
from app.services.threat_intelligence.types import IndicatorType


# ---------------------------------------------------------------------------
# Bounds — explicit, documented, conservative limits for the AI context.
# ---------------------------------------------------------------------------

#: Maximum number of correlation member references carried into the context.
#: A correlation with more members than this is refused, never truncated:
#: dropping members would hide security evidence from the investigation.
MAX_CORRELATION_MEMBERS = 1000

#: Maximum number of detection records carried into the context.  Refused
#: above the cap so a caller must bound detection bursts deterministically.
MAX_DETECTIONS = 500

#: Maximum number of threat-intelligence indicators carried into the context.
MAX_TI_INDICATORS = 500

#: Maximum number of threat-intelligence provider results carried into the
#: context (provider results plus skipped lookups).
MAX_TI_PROVIDER_RESULTS = 500

#: Maximum number of isolated provider failures carried into the context.
MAX_TI_FAILURES = 250

#: Maximum number of enrichment results carried into the context.
MAX_ENRICHMENTS = 500

#: Maximum number of caller-declared event-provenance entries accepted.
MAX_EVENT_PROVENANCE_ENTRIES = 2048

#: Maximum length of any single string carried into the context.  Applies to
#: rule identifiers, indicator values, provider names, source fields,
#: enrichment sources, and provider failure messages.  Attacker-controlled
#: strings longer than this are refused, not truncated.
MAX_STRING_LENGTH = 4096

#: Maximum container nesting depth for any structured payload (metadata,
#: evidence, enrichment value, provider result data).  The root container of
#: a payload is depth 1; a payload nested nine containers deep is refused.
MAX_METADATA_DEPTH = 8

#: Maximum serialized size of a single structured payload (metadata,
#: evidence, enrichment value, provider result data): 64 KiB.
MAX_METADATA_SERIALIZED_BYTES = 64 * 1024

#: Maximum total serialized size of the complete InvestigationContext
#: (including evidence, metadata, and all structured sections): 512 KiB.
MAX_CONTEXT_TOTAL_BYTES = 512 * 1024

#: Maximum number of derived evidence records in the context.  The context
#: derives at most one evidence record per correlation, one per risk
#: assessment, one per detection, one per TI indicator, and one per TI
#: provider result — bounded by the section caps above.
MAX_EVIDENCE_ITEMS = 2 + MAX_DETECTIONS + MAX_TI_INDICATORS + MAX_TI_PROVIDER_RESULTS

#: Maximum number of historical incident-memory references an
#: InvestigationContext may carry.  Mirrors the Step 13 RAG ``top_k`` bound:
#: an investigation recalls a small, bounded set of past incidents as
#: background reference, and a larger feed would exceed that purpose.
#: Requests above the cap are refused, never silently truncated.
MAX_INCIDENT_MEMORY_REFERENCES = 10


# ---------------------------------------------------------------------------
# Context-builder errors (deterministic, sanitized).
#
# Pure adapters elsewhere in the repository (e.g. ``to_correlation_input``)
# raise TypeError/ValueError.  Bounds violations use a focused
# ``ValueError`` subclass so callers can catch a single deterministic
# error type without inventing parallel handling.
# ---------------------------------------------------------------------------


class InvestigationContextError(ValueError):
    """Base error for InvestigationContext construction."""


class InvestigationContextBoundError(InvestigationContextError):
    """A documented context bound was exceeded; the context was refused.

    Messages are sanitized and contain only section names and counts —
    never payload content, credentials, or internal state.
    """


# ---------------------------------------------------------------------------
# Secret-safety helpers.
#
# Refuse-to-carry semantics are exactly the repository convention from the
# Step 9A / 9I / 10A / 11A contracts.  The boundary here is the AI trust
# boundary, so the base pattern set is extended with the credential
# families Step 12B explicitly requires to be tested (passwords, cookies,
# session tokens, JWTs).  This is an additive, documented extension at this
# boundary only; earlier contracts are unchanged.
# ---------------------------------------------------------------------------

#: Forbidden credential-shaped strings, kept in lock-step with
#: ``app/schemas/detection.py`` / ``app/schemas/correlation.py`` /
#: ``app/schemas/risk.py``:
_BASE_SECRET_PATTERNS = ("api_key", "authorization", "bearer", "secret")

#: The full pattern set applied at the AI trust boundary (base policy plus
#: the Step 12B-required credential families).
_SECRET_PATTERNS = _BASE_SECRET_PATTERNS + (
    "password",
    "cookie",
    "session_token",
    "jwt",
)


def _assert_json_compatible(value: Any, field: str) -> None:
    """Raise ValueError when *value* is not strictly JSON-serializable."""
    try:
        json.dumps(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"{field} must be JSON-compatible: {exc}"
        ) from exc


def _assert_no_secrets(value: Any, field: str) -> None:
    """Raise ValueError when *value* contains common secret patterns."""
    serialized = json.dumps(value).lower()
    for pattern in _SECRET_PATTERNS:
        if pattern in serialized:
            raise ValueError(
                f"{field} must not contain secrets ('{pattern}' detected)"
            )


def _json_clone(value: dict[str, Any]) -> dict[str, Any]:
    """Return an independent, JSON-compatible deep copy of *value*."""
    return json.loads(json.dumps(value))


def _container_depth(value: Any) -> int:
    """Measure the deepest container-nesting chain.

    The root of a payload counts as depth 1; nested containers add one
    level each.  Scalars contribute nothing.  Cycles are impossible because
    JSON compatibility is asserted before this is called.
    """
    if isinstance(value, dict):
        return 1 + max(
            (_container_depth(child) for child in value.values()),
            default=0,
        )
    if isinstance(value, (list, tuple)):
        return 1 + max(
            (_container_depth(child) for child in value),
            default=0,
        )
    return 0


def _assert_json_compatible_control_payload(
    value: dict[str, Any], field: str
) -> None:
    """A structured payload must be JSON-safe, secret-free, bounded."""
    _assert_json_compatible(value, field)
    _assert_no_secrets(value, field)
    depth = _container_depth(value)
    if depth > MAX_METADATA_DEPTH:
        raise InvestigationContextBoundError(
            f"{field} exceeds MAX_METADATA_DEPTH={MAX_METADATA_DEPTH} "
            f"(nesting depth {depth})"
        )
    size = len(json.dumps(value).encode("utf-8"))
    if size > MAX_METADATA_SERIALIZED_BYTES:
        raise InvestigationContextBoundError(
            f"{field} exceeds MAX_METADATA_SERIALIZED_BYTES="
            f"{MAX_METADATA_SERIALIZED_BYTES} (serialized size {size})"
        )


def _validate_control_payload(
    value: dict[str, Any], field: str
) -> dict[str, Any]:
    """Validate a structured payload and return an independent clone."""
    _assert_json_compatible_control_payload(value, field)
    return _json_clone(value)


def _validate_optional_control_payload(
    value: dict[str, Any] | None, field: str
) -> dict[str, Any]:
    """Validate an optional structured payload; ``None`` becomes ``{}``."""
    if value is None:
        return _json_clone({})
    return _validate_control_payload(value, field)


def _require_non_blank(value: str, field: str) -> str:
    """Reject blank strings; return the value unchanged (already
    canonicalized by its source contract)."""
    if not value.strip():
        raise ValueError(f"{field} must not be blank")
    return value


def _bound_string(value: str, field: str, *, allow_blank: bool = False) -> str:
    """Enforce the context string bound without altering the value."""
    if not value:
        raise ValueError(f"{field} must not be empty")
    if not allow_blank:
        _require_non_blank(value, field)
    if len(value) > MAX_STRING_LENGTH:
        raise InvestigationContextBoundError(
            f"{field} exceeds MAX_STRING_LENGTH={MAX_STRING_LENGTH} "
            f"(length {len(value)})"
        )
    return value


def _bound_optional_string(
    value: str | None, field: str, *, allow_blank: bool = True
) -> str | None:
    """Bound an optional string; ``None`` passes through unchanged."""
    if value is None:
        return None
    return _bound_string(value, field, allow_blank=allow_blank)


# ---------------------------------------------------------------------------
# Input availability — explicit missing-data policy.
#
# Distinguishes "not provided" (the caller did not supply this input) from
# "checked and none found" (an explicitly empty set was supplied) so the
# future agent never fabricates an absence it did not observe.
# ---------------------------------------------------------------------------


class InputAvailability(str, Enum):
    """Whether and how a source section is present in the context."""

    PROVIDED = "provided"
    NOT_PROVIDED = "not_provided"
    NONE_FOUND = "none_found"


class ContextInputAvailability(BaseModel):
    """Structural record of which investigation inputs are present.

    * ``correlation`` — always ``PROVIDED`` (a context is anchored to one).
    * ``risk_assessment`` — ``PROVIDED`` or ``NOT_PROVIDED`` (an optional
      single object; `none found` does not apply).
    * ``detections`` / ``enrichments`` — ``PROVIDED`` when at least one
      item was supplied, ``NONE_FOUND`` when an explicitly empty set was
      supplied, ``NOT_PROVIDED`` when the parameter was omitted.
    * ``historical_memories`` — ``PROVIDED`` when at least one historical
      incident-memory reference was supplied, ``NONE_FOUND`` when an
      explicitly empty set was supplied (retrieval ran and matched
      nothing), ``NOT_PROVIDED`` when no memory reference retrieval was
      supplied at all.
    * ``threat_intelligence`` — ``PROVIDED`` when an analysis object was
      supplied, ``NOT_PROVIDED`` otherwise.  Whether results exist inside
      the analysis is read from its own structural fields (indicator lists,
      provider result lists, and the preserved lookup counters); an empty
      analysis is "provided, no indicators", never "no threat intelligence
      exists".
    """

    correlation: InputAvailability = Field(
        default=InputAvailability.PROVIDED,
        description="Correlation is always present in a valid context.",
    )
    risk_assessment: InputAvailability = Field(
        default=InputAvailability.NOT_PROVIDED,
        description=(
            "PROVIDED when a risk assessment was supplied; NOT_PROVIDED "
            "otherwise.  Absence is never an observed fact."
        ),
    )
    detections: InputAvailability = Field(
        default=InputAvailability.NOT_PROVIDED,
        description=(
            "PROVIDED / NONE_FOUND (explicitly empty) / NOT_PROVIDED."
        ),
    )
    historical_memories: InputAvailability = Field(
        default=InputAvailability.NOT_PROVIDED,
        description=(
            "PROVIDED / NONE_FOUND (explicitly empty retrieval) / "
            "NOT_PROVIDED.  Absent historical memory is never an observed "
            "fact."
        ),
    )
    threat_intelligence: InputAvailability = Field(
        default=InputAvailability.NOT_PROVIDED,
        description="PROVIDED when a ThreatIntelligenceAnalysis was supplied.",
    )
    enrichments: InputAvailability = Field(
        default=InputAvailability.NOT_PROVIDED,
        description="PROVIDED / NONE_FOUND (explicitly empty) / NOT_PROVIDED.",
    )

    @field_validator("correlation")
    @classmethod
    def _correlation_always_provided(cls, v: InputAvailability) -> InputAvailability:
        if v is not InputAvailability.PROVIDED:
            raise ValueError(
                "correlation is required and must be PROVIDED in any "
                "valid InvestigationContext"
            )
        return v


# ---------------------------------------------------------------------------
# Event provenance inventory.
# ---------------------------------------------------------------------------


class EventProvenanceContext(BaseModel):
    """The provenance of one referenced security event, copied verbatim from
    the event subsystem's own record (the caller declares it via the
    builder's ``event_provenance`` mapping).

    Preserves the distinction the pipeline already enforces: an event whose
    record says ``RECONSTRUCTED`` stays ``RECONSTRUCTED`` here — it must
    never be downgraded to ``OBSERVED``.  Events whose provenance was not
    declared are omitted entirely (absence is not an observed fact).
    """

    event_id: uuid.UUID = Field(
        ...,
        description="Identity of the security event whose provenance is recorded.",
    )
    provenance: Provenance = Field(
        ...,
        description=(
            "The event record's provenance (OBSERVED / ENRICHED / "
            "RECONSTRUCTED, etc.), preserved verbatim."
        ),
    )


# ---------------------------------------------------------------------------
# Correlation context
# ---------------------------------------------------------------------------


class CorrelationMemberContext(BaseModel):
    """Controlled representation of one correlation member.

    A member is the correlation's own analytical reference to a detection;
    it carries the correlation's provenance (``CORRELATED``), never the
    provenance of any member detection or event.
    """

    detection_id: uuid.UUID = Field(
        ...,
        description="Detection identity, preserved exactly.",
    )
    event_id: uuid.UUID = Field(
        ...,
        description="Source event identity, preserved exactly.",
    )
    timestamp: datetime = Field(
        ...,
        description="Member detection timestamp (timezone-aware).",
    )
    provenance: Provenance = Field(
        default=Provenance.CORRELATED,
        description=(
            "Correlation membership is a correlation conclusion and is "
            "always CORRELATED."
        ),
    )

    @field_validator("timestamp")
    @classmethod
    def _ensure_timezone_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError(
                "timestamp must be timezone-aware; "
                "naive (UTC-less) timestamps are not accepted"
            )
        return v

    @field_validator("provenance")
    @classmethod
    def _correlated_only(cls, v: Provenance) -> Provenance:
        if v is not Provenance.CORRELATED:
            raise ValueError(
                "correlation members are correlation conclusions and must "
                f"carry CORRELATED provenance; got {v.value!r}"
            )
        return v


class CorrelationContext(BaseModel):
    """Controlled representation of a Step 10A ``CorrelationResult``."""

    correlation_id: uuid.UUID = Field(
        ...,
        description="Correlation identity, preserved exactly.",
    )
    status: CorrelationStatus = Field(
        ...,
        description="Neutral lifecycle status, preserved exactly.",
    )
    confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Correlation confidence in [0.0, 1.0], preserved exactly.",
    )
    members: list[CorrelationMemberContext] = Field(
        ...,
        description=(
            "Correlation members in source order, duplicates preserved."
        ),
    )
    evidence: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured correlation evidence (allowlisted as-is).",
    )
    timestamp: datetime = Field(
        ...,
        description="Correlation establishment timestamp (timezone-aware).",
    )
    provenance: Provenance = Field(
        default=Provenance.CORRELATED,
        description="Always CORRELATED (pinned, mirroring Step 10A).",
    )

    @field_validator("timestamp")
    @classmethod
    def _ensure_timezone_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError(
                "timestamp must be timezone-aware; "
                "naive (UTC-less) timestamps are not accepted"
            )
        return v

    @field_validator("evidence")
    @classmethod
    def _evidence_payload(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_control_payload(v, "correlation evidence")

    @field_validator("members")
    @classmethod
    def _members_bounded(cls, v: list[CorrelationMemberContext]) -> list[CorrelationMemberContext]:
        if len(v) > MAX_CORRELATION_MEMBERS:
            raise InvestigationContextBoundError(
                f"correlation members exceed MAX_CORRELATION_MEMBERS="
                f"{MAX_CORRELATION_MEMBERS} (got {len(v)})"
            )
        return v

    @field_validator("provenance")
    @classmethod
    def _correlated_only(cls, v: Provenance) -> Provenance:
        if v is not Provenance.CORRELATED:
            raise ValueError(
                "correlation context is a correlation conclusion and must "
                f"carry CORRELATED provenance; got {v.value!r}"
            )
        return v


# ---------------------------------------------------------------------------
# Risk context
# ---------------------------------------------------------------------------


class RiskContext(BaseModel):
    """Controlled representation of a Step 11A ``RiskAssessment``.

    The builder never recalculates the score, derives the level, or
    reinterprets confidence: every number here is carried verbatim.  Risk
    score and investigation confidence remain distinct concepts that are
    never merged.
    """

    risk_assessment_id: uuid.UUID = Field(
        ...,
        description="Assessment identity, preserved exactly.",
    )
    correlation_id: uuid.UUID = Field(
        ...,
        description="Evaluated correlation identity, preserved exactly.",
    )
    score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Risk score in [0.0, 1.0], preserved verbatim.",
    )
    level: RiskLevel = Field(
        ...,
        description="Risk level, preserved verbatim (never re-derived).",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Assessment confidence in [0.0, 1.0], preserved verbatim.",
    )
    factors: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Structured risk factors (allowlisted, re-validated).",
    )
    evidence: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Structured risk evidence (allowlisted, re-validated).",
    )
    timestamp: datetime = Field(
        ...,
        description="Assessment timestamp (timezone-aware).",
    )
    provenance: Provenance = Field(
        default=Provenance.RISK_ASSESSED,
        description="Always RISK_ASSESSED (pinned, mirroring Step 11A).",
    )

    @field_validator("timestamp")
    @classmethod
    def _ensure_timezone_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError(
                "timestamp must be timezone-aware; "
                "naive (UTC-less) timestamps are not accepted"
            )
        return v

    @field_validator("factors")
    @classmethod
    def _factors_payloads(cls, v: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [_validate_control_payload(item, "risk factor") for item in v]

    @field_validator("evidence")
    @classmethod
    def _evidence_payloads(cls, v: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [_validate_control_payload(item, "risk evidence") for item in v]

    @field_validator("provenance")
    @classmethod
    def _risk_assessed_only(cls, v: Provenance) -> Provenance:
        if v is not Provenance.RISK_ASSESSED:
            raise ValueError(
                "risk context is an assessment conclusion and must carry "
                f"RISK_ASSESSED provenance; got {v.value!r}"
            )
        return v


# ---------------------------------------------------------------------------
# Detection context
# ---------------------------------------------------------------------------


class DetectionContext(BaseModel):
    """Controlled representation of a detection crossing into the context.

    Detection identity, event identity, rule identity, severity,
    confidence, evidence, and metadata are preserved.  Nothing is
    reinterpreted: detection output is never turned into risk, and a
    detection is always ``DETECTED``.
    """

    detection_id: uuid.UUID = Field(
        ...,
        description="Detection identity, preserved exactly.",
    )
    event_id: uuid.UUID = Field(
        ...,
        description="Source event identity, preserved exactly.",
    )
    rule_id: str = Field(
        ...,
        description="Rule identity (allowlisted, bounded).",
    )
    rule_type: RuleType = Field(
        ...,
        description="Rule engine type, preserved exactly.",
    )
    rule_version: str | None = Field(
        default=None,
        description="Rule version when known, preserved exactly.",
    )
    severity: DetectionSeverity = Field(
        ...,
        description="Rule-author severity, preserved exactly.",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Detection confidence in [0.0, 1.0], preserved exactly.",
    )
    evidence: dict[str, Any] = Field(
        ...,
        description="Structured match evidence (allowlisted as-is).",
    )
    metadata: dict[str, Any] = Field(
        ...,
        description="Structured evaluation metadata (allowlisted as-is).",
    )
    timestamp: datetime = Field(
        ...,
        description="Detection evaluation timestamp (timezone-aware).",
    )
    provenance: Provenance = Field(
        default=Provenance.DETECTED,
        description="Always DETECTED (pinned, mirroring Step 9A/9I).",
    )

    @field_validator("timestamp")
    @classmethod
    def _ensure_timezone_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError(
                "timestamp must be timezone-aware; "
                "naive (UTC-less) timestamps are not accepted"
            )
        return v

    @field_validator("rule_id")
    @classmethod
    def _rule_id_bounded(cls, v: str) -> str:
        return _bound_string(v, "detection rule_id")

    @field_validator("rule_version")
    @classmethod
    def _rule_version_bounded(cls, v: str | None) -> str | None:
        return _bound_optional_string(v, "detection rule_version")

    @field_validator("evidence")
    @classmethod
    def _evidence_payload(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_control_payload(v, "detection evidence")

    @field_validator("metadata")
    @classmethod
    def _metadata_payload(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_control_payload(v, "detection metadata")

    @field_validator("provenance")
    @classmethod
    def _detected_only(cls, v: Provenance) -> Provenance:
        if v is not Provenance.DETECTED:
            raise ValueError(
                "detection context is an analytical conclusion and must "
                f"carry DETECTED provenance; got {v.value!r}"
            )
        return v


# ---------------------------------------------------------------------------
# Threat-intelligence context
# ---------------------------------------------------------------------------


class IndicatorContext(BaseModel):
    """One extracted indicator carried as untrusted structured data.

    The indicator value is an attacker-controllable string that entered
    the pipeline from event fields.  It is preserved verbatim as data.
    The provenance reflects the *source event record's* provenance,
    resolved by the builder: a value extracted from a ``RECONSTRUCTED``
    event stays ``RECONSTRUCTED`` and is never relabelled ``OBSERVED``.
    When the event's provenance was not declared, the origin is
    ``None`` — explicitly undeclared, never asserted as observed.
    """

    indicator: str = Field(
        ...,
        description="The indicator value (untrusted data, preserved verbatim).",
    )
    indicator_type: IndicatorType = Field(
        ...,
        description="Indicator classification, preserved exactly.",
    )
    source_field: str = Field(
        ...,
        description="Event field the value was extracted from.",
    )
    source_context: str = Field(
        ...,
        description="Coarse origin context in the event.",
    )
    provenance: Provenance | None = Field(
        default=None,
        description=(
            "Source event-record provenance when declared (OBSERVED, "
            "ENRICHED, RECONSTRUCTED); None when undeclared.  Never "
            "fabricated."
        ),
    )

    @field_validator("indicator")
    @classmethod
    def _indicator_bounded(cls, v: str) -> str:
        return _bound_string(v, "indicator value")

    @field_validator("source_field")
    @classmethod
    def _source_field_bounded(cls, v: str) -> str:
        return _bound_string(v, "indicator source_field")

    @field_validator("source_context")
    @classmethod
    def _source_context_bounded(cls, v: str) -> str:
        return _bound_string(v, "indicator source_context")

    @field_validator("provenance")
    @classmethod
    def _source_origin_only(cls, v: Provenance | None) -> Provenance | None:
        if v is None:
            return None
        if v not in (Provenance.OBSERVED, Provenance.ENRICHED, Provenance.RECONSTRUCTED):
            raise ValueError(
                "indicator provenance must be a source-origin provenance "
                "(OBSERVED / ENRICHED / RECONSTRUCTED) or None; got "
                f"{v.value!r}"
            )
        return v


class ProviderResultContext(BaseModel):
    """One external threat-intelligence result carried as structured data.

    The provider payload (``data``) is attacker/provider-controlled and is
    preserved verbatim as data.  Provenance is ``ENRICHED`` — external
    intelligence is never labelled observed or reconstructed.  Nothing
    here invents a verdict or upgrades confidence.
    """

    provider: str = Field(
        ...,
        description="Provider name, preserved exactly.",
    )
    indicator_value: str = Field(
        ...,
        description="The indicator that was looked up (untrusted data).",
    )
    indicator_type: IndicatorType = Field(
        ...,
        description="Indicator classification, preserved exactly.",
    )
    found: bool = Field(
        ...,
        description="Whether the provider had information about the indicator.",
    )
    confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Provider confidence in [0.0, 1.0], preserved exactly.",
    )
    data: dict[str, Any] = Field(
        default_factory=dict,
        description="Provider payload (allowlisted as-is, bounded).",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Provider metadata (allowlisted as-is, bounded).",
    )
    timestamp: datetime = Field(
        ...,
        description="Lookup timestamp (timezone-aware).",
    )
    provenance: Provenance = Field(
        default=Provenance.ENRICHED,
        description="Always ENRICHED (external intelligence, never observed).",
    )

    @field_validator("timestamp")
    @classmethod
    def _ensure_timezone_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError(
                "timestamp must be timezone-aware; "
                "naive (UTC-less) timestamps are not accepted"
            )
        return v

    @field_validator("provider")
    @classmethod
    def _provider_bounded(cls, v: str) -> str:
        return _bound_string(v, "provider name")

    @field_validator("indicator_value")
    @classmethod
    def _indicator_bounded(cls, v: str) -> str:
        return _bound_string(v, "provider indicator value")

    @field_validator("data")
    @classmethod
    def _data_payload(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_control_payload(v, "provider result data")

    @field_validator("metadata")
    @classmethod
    def _metadata_payload(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_control_payload(v, "provider result metadata")

    @field_validator("provenance")
    @classmethod
    def _enriched_only(cls, v: Provenance) -> Provenance:
        if v is not Provenance.ENRICHED:
            raise ValueError(
                "provider results are external enrichment and must carry "
                f"ENRICHED provenance; got {v.value!r}"
            )
        return v


class ProviderLookupContext(BaseModel):
    """A provider association whose lookup was not performed / had no result.

    This is structural bookkeeping: it records *which* provider was not
    asked for *which* indicator.  It asserts no information about the
    indicator — it is never evidence, so it carries a provider name and
    indicator value only (both untrusted data), and no provenance claim.
    """

    provider: str = Field(
        ...,
        description="Provider that was not consulted.",
    )
    indicator_value: str = Field(
        ...,
        description="Indicator that was not looked up (untrusted data).",
    )
    indicator_type: IndicatorType = Field(
        ...,
        description="Indicator classification, preserved exactly.",
    )

    @field_validator("provider")
    @classmethod
    def _provider_bounded(cls, v: str) -> str:
        return _bound_string(v, "provider name")

    @field_validator("indicator_value")
    @classmethod
    def _indicator_bounded(cls, v: str) -> str:
        return _bound_string(v, "skipped indicator value")


class ProviderFailureContext(BaseModel):
    """A structured, secret-safe record of one isolated provider failure.

    Reproduced as-is from ``ProviderFailure`` (which already excludes API
    keys, headers, and raw HTTP responses).  ``message`` is treated as
    untrusted data and bounded, never executed, and never exposed beyond
    the context.
    """

    provider: str = Field(
        ...,
        description="Provider that failed.",
    )
    indicator: str = Field(
        ...,
        description="Indicator that was being looked up (untrusted data).",
    )
    indicator_type: IndicatorType = Field(
        ...,
        description="Indicator classification, preserved exactly.",
    )
    error_type: str = Field(
        ...,
        description="Short failure category, preserved exactly.",
    )
    message: str = Field(
        ...,
        description="Secret-safe failure message (untrusted data, bounded).",
    )
    retryable: bool = Field(
        ...,
        description="Whether the failure is likely transient.",
    )

    @field_validator("provider")
    @classmethod
    def _provider_bounded(cls, v: str) -> str:
        return _bound_string(v, "provider name")

    @field_validator("indicator")
    @classmethod
    def _indicator_bounded(cls, v: str) -> str:
        return _bound_string(v, "failure indicator value")

    @field_validator("error_type")
    @classmethod
    def _error_type_bounded(cls, v: str) -> str:
        return _bound_string(v, "failure error_type")

    @field_validator("message")
    @classmethod
    def _message_bounded(cls, v: str) -> str:
        return _bound_string(v, "failure message", allow_blank=True)


class ThreatIntelligenceContext(BaseModel):
    """Controlled representation of a Step 8A ``ThreatIntelligenceAnalysis``.

    Indicators, provider results, skipped lookups, isolated failures, and
    execution counters are preserved without inventing a verdict or
    upgrading confidence, and provider failure never becomes a negative or
    positive verdict.
    """

    event_id: uuid.UUID = Field(
        ...,
        description="Analyzed event identity, preserved exactly.",
    )
    indicators: list[IndicatorContext] = Field(
        default_factory=list,
        description="Extracted indicators (deduplicated by the source agent).",
    )
    provider_results: list[ProviderResultContext] = Field(
        default_factory=list,
        description="Provider results in source order.",
    )
    skipped_lookups: list[ProviderLookupContext] = Field(
        default_factory=list,
        description="Provider associations with no result (bookkeeping).",
    )
    failures: list[ProviderFailureContext] = Field(
        default_factory=list,
        description="Isolated provider failures in source order.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Execution counters (allowlisted, bounded).",
    )

    @field_validator("indicators")
    @classmethod
    def _indicators_bounded(cls, v: list[IndicatorContext]) -> list[IndicatorContext]:
        if len(v) > MAX_TI_INDICATORS:
            raise InvestigationContextBoundError(
                f"threat-intelligence indicators exceed MAX_TI_INDICATORS="
                f"{MAX_TI_INDICATORS} (got {len(v)})"
            )
        return v

    @field_validator("provider_results")
    @classmethod
    def _results_bounded(cls, v: list[ProviderResultContext]) -> list[ProviderResultContext]:
        if len(v) > MAX_TI_PROVIDER_RESULTS:
            raise InvestigationContextBoundError(
                f"threat-intelligence provider results exceed "
                f"MAX_TI_PROVIDER_RESULTS={MAX_TI_PROVIDER_RESULTS} (got {len(v)})"
            )
        return v

    @field_validator("skipped_lookups")
    @classmethod
    def _skipped_bounded(cls, v: list[ProviderLookupContext]) -> list[ProviderLookupContext]:
        if len(v) > MAX_TI_PROVIDER_RESULTS:
            raise InvestigationContextBoundError(
                f"threat-intelligence skipped lookups exceed "
                f"MAX_TI_PROVIDER_RESULTS={MAX_TI_PROVIDER_RESULTS} (got {len(v)})"
            )
        return v

    @field_validator("failures")
    @classmethod
    def _failures_bounded(cls, v: list[ProviderFailureContext]) -> list[ProviderFailureContext]:
        if len(v) > MAX_TI_FAILURES:
            raise InvestigationContextBoundError(
                f"threat-intelligence failures exceed MAX_TI_FAILURES="
                f"{MAX_TI_FAILURES} (got {len(v)})"
            )
        return v

    @field_validator("metadata")
    @classmethod
    def _metadata_payload(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_control_payload(v, "threat intelligence metadata")


# ---------------------------------------------------------------------------
# Enrichment context
# ---------------------------------------------------------------------------


class EnrichmentContext(BaseModel):
    """Controlled representation of one ``EnrichmentResult``.

    The enrichment ``value`` is provider-controlled data and is preserved
    verbatim as structured data; provenance is ``ENRICHED``.
    """

    enrichment_id: uuid.UUID = Field(
        ...,
        description="Enrichment identity, preserved exactly.",
    )
    enrichment_type: str = Field(
        ...,
        description="Enrichment category, preserved exactly.",
    )
    source: str = Field(
        ...,
        description="Enrichment origin, preserved exactly.",
    )
    value: dict[str, Any] = Field(
        ...,
        description="Structured enrichment payload (allowlisted as-is).",
    )
    confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Enrichment confidence in [0.0, 1.0], preserved exactly.",
    )
    timestamp: datetime = Field(
        ...,
        description="Enrichment timestamp (timezone-aware).",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Enrichment metadata (allowlisted as-is; None becomes {}).",
    )
    provenance: Provenance = Field(
        default=Provenance.ENRICHED,
        description="Always ENRICHED (external/additional intelligence).",
    )

    @field_validator("timestamp")
    @classmethod
    def _ensure_timezone_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError(
                "timestamp must be timezone-aware; "
                "naive (UTC-less) timestamps are not accepted"
            )
        return v

    @field_validator("enrichment_type")
    @classmethod
    def _type_bounded(cls, v: str) -> str:
        return _bound_string(v, "enrichment_type")

    @field_validator("source")
    @classmethod
    def _source_bounded(cls, v: str) -> str:
        return _bound_string(v, "enrichment source")

    @field_validator("value")
    @classmethod
    def _value_payload(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_control_payload(v, "enrichment value")

    @field_validator("metadata")
    @classmethod
    def _metadata_payload(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_control_payload(v, "enrichment metadata")

    @field_validator("provenance")
    @classmethod
    def _enriched_only(cls, v: Provenance) -> Provenance:
        if v is not Provenance.ENRICHED:
            raise ValueError(
                "enrichment context is external intelligence and must carry "
                f"ENRICHED provenance; got {v.value!r}"
            )
        return v


# ---------------------------------------------------------------------------
# Historical incident-memory context (Step 20)
#
# A persisted incident memory enters the investigation context as
# background/reference information — never as evidence.  See
# incident_memory_investigation_integration.md for the full contract.
# ---------------------------------------------------------------------------


class IncidentMemoryReferenceContext(BaseModel):
    """One historical incident memory carried as background reference data.

    This is the Step 20 integration record: a persisted incident memory
    (read through the Step 18 query service as an ``IncidentMemoryRecord``)
    enters the investigation context as **historical reference material**,
    never as evidence.

    * ``memory_id`` — the Step 16 identity of the persisted memory.
    * ``is_historical_reference`` — pinned ``True``: the record permanently
      declares that it is recalled background reference data and that intent
      cannot be silently reclassified.
    * ``memory_type`` / ``title`` / ``summary`` / ``confidence`` /
      ``correlation_id`` — the memory's own Step 16/18 values, preserved
      exactly.
    * ``created_at`` — the memory's own persistence instant.  Historical
      timestamps are never replaced by the investigation's current-time
      bookkeeping.
    * ``provenance`` — pinned ``RECALLED``: memory is historical recall and
      can never masquerade as ``OBSERVED`` / ``ENRICHED`` /
      ``RECONSTRUCTED`` / ``DETECTED`` / ``CORRELATED`` /
      ``RISK_ASSESSED``.
    * ``sources`` — the memory's own per-source references as stored (each
      item keeps its verbatim per-source provenance).
    * ``memory_metadata`` — the memory's own envelope metadata as stored.

    Structured payloads are cloned and re-validated through the control-
    payload policy (JSON-compatible, secret-free, bounded).  Unlike the
    evidence-carrying sections, a memory reference is **never** indexed into
    ``InvestigationContext.evidence`` — memory is contextual reference, not
    a derived evidence record.
    """

    memory_id: uuid.UUID = Field(
        ...,
        description="Step 16 identity of the persisted incident memory.",
    )
    is_historical_reference: Literal[True] = Field(
        default=True,
        description=(
            "Pinned True: this record is historical background reference "
            "material by construction and can never be reclassified as "
            "observed evidence."
        ),
    )
    memory_type: MemoryType = Field(
        ...,
        description="The memory's Step 16 memory type, preserved exactly.",
    )
    title: str = Field(
        ...,
        description="The memory's bounded title, preserved exactly.",
    )
    summary: str = Field(
        ...,
        description=(
            "The memory's bounded summary as stored (empty string when the "
            "envelope carried none)."
        ),
    )
    correlation_id: uuid.UUID | None = Field(
        default=None,
        description="The memory's own correlation reference, when stored.",
    )
    created_at: datetime = Field(
        ...,
        description=(
            "The memory's own persistence instant (timezone-aware).  "
            "Historical — never replaced by the context's current time."
        ),
    )
    confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "The memory's Step 16 confidence in [0.0, 1.0], or None.  "
            "Bookkeeping only; never a risk score."
        ),
    )
    provenance: Provenance = Field(
        default=Provenance.RECALLED,
        description=(
            "Pinned RECALLED: incident memory is historical recall and can "
            "never masquerade as an observed/analytical evidence provenance."
        ),
    )
    sources: list[dict[str, Any]] = Field(
        default_factory=list,
        description=(
            "The memory's own per-source references as stored (redacted, "
            "secret-free); each item keeps its verbatim per-source "
            "provenance."
        ),
    )
    memory_metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "The memory's own envelope metadata as stored (redacted, "
            "secret-free; includes the deterministic contract timestamp)."
        ),
    )

    @field_validator("created_at")
    @classmethod
    def _ensure_timezone_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError(
                "created_at must be timezone-aware; naive (UTC-less) "
                "timestamps are not accepted"
            )
        return v

    @field_validator("title")
    @classmethod
    def _title_bounded(cls, v: str) -> str:
        return _bound_string(v, "incident memory title")

    @field_validator("summary")
    @classmethod
    def _summary_bounded(cls, v: str) -> str:
        return _bound_string(v, "incident memory summary", allow_blank=True)

    @field_validator("provenance")
    @classmethod
    def _recalled_only(cls, v: Provenance) -> Provenance:
        if v is not Provenance.RECALLED:
            raise ValueError(
                "historical incident memory is recall and must carry "
                f"RECALLED provenance; got {v.value!r}"
            )
        return v

    @field_validator("sources")
    @classmethod
    def _sources_payloads(
        cls, v: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        if len(v) > MAX_MEMORY_SOURCES:
            raise InvestigationContextBoundError(
                f"incident memory sources exceed MAX_MEMORY_SOURCES="
                f"{MAX_MEMORY_SOURCES} (got {len(v)})"
            )
        return [
            _validate_control_payload(item, "incident memory source")
            for item in v
        ]

    @field_validator("memory_metadata")
    @classmethod
    def _metadata_payload(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_control_payload(v, "incident memory metadata")


# ---------------------------------------------------------------------------
# InvestigationContext root
# ---------------------------------------------------------------------------


class InvestigationContext(BaseModel):
    """The complete, validated result of Step 12B.

    This is the **input** representation for the future AI Investigation
    Agent.  It carries:

    * ``correlation`` — the anchored correlation (required).
    * ``risk_assessment`` — the evaluated risk assessment (optional).
    * ``detections`` — allowlisted detection records (optional).
    * ``threat_intelligence`` / ``enrichments`` — allowlisted external
      context (optional).
    * ``historical_memories`` — allowlisted historical incident-memory
      references (Step 20, optional).  Background/reference data only,
      never indexed into ``evidence``.
    * ``event_provenance`` — verbatim event-record provenance for the
      referenced events the caller declared (sorted for determinism).
    * ``evidence`` — mechanical, provenance-aware evidence records
      (Step 12A ``InvestigationEvidence``) indexing each carried source.
      Findings and observations are *not* created: they are investigation
      output, which belongs to the future agent.
    * ``input_availability`` — explicit provided / not-provided / none-found
      record.
    * ``metadata`` — bookkeeping (schema version, truncation markers —
      empty under the reject policy) merged with caller metadata.
    * ``context_created_at`` — context-construction bookkeeping timestamp
      that is explicitly **not** security evidence.

    The model validates JSON compatibility, secret safety, metadata
    bounds, section bounds, and the total serialized-size bound on every
    construction, without delegating to ``eval``/``exec``/``pickle``.
    """

    investigation_id: uuid.UUID = Field(
        ...,
        description=(
            "Stable identity of the investigation this context prepares "
            "for.  Supplied by the caller for deterministic builds."
        ),
    )
    context_created_at: datetime = Field(
        ...,
        description=(
            "Context-construction bookkeeping instant (timezone-aware).  "
            "Explicitly NOT security evidence."
        ),
    )
    input_availability: ContextInputAvailability = Field(
        ...,
        description="Which inputs were provided / not provided / none found.",
    )
    correlation: CorrelationContext = Field(
        ...,
        description="The anchored correlation.",
    )
    risk_assessment: RiskContext | None = Field(
        default=None,
        description="Risk assessment, when supplied.",
    )
    detections: list[DetectionContext] = Field(
        default_factory=list,
        description="Detection records in source order.",
    )
    threat_intelligence: ThreatIntelligenceContext | None = Field(
        default=None,
        description="Threat-intelligence analysis, when supplied.",
    )
    enrichments: list[EnrichmentContext] = Field(
        default_factory=list,
        description="Enrichment results in source order.",
    )
    historical_memories: list[IncidentMemoryReferenceContext] = Field(
        default_factory=list,
        description=(
            "Historical incident-memory references (Step 20) in the "
            "retrieval's deterministic order.  Background reference data "
            "only — never indexed into ``evidence``."
        ),
    )
    event_provenance: list[EventProvenanceContext] = Field(
        default_factory=list,
        description=(
            "Declared event-record provenance, sorted by event_id for "
            "deterministic serialization."
        ),
    )
    evidence: list[InvestigationEvidence] = Field(
        default_factory=list,
        description=(
            "Mechanical provenance-aware evidence records indexing the "
            "carried sources (Step 12A contract)."
        ),
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Bookkeeping merged with caller metadata (bounded).",
    )

    @field_validator("context_created_at")
    @classmethod
    def _context_created_at_tz_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError(
                "context_created_at must be timezone-aware; "
                "naive (UTC-less) timestamps are not accepted"
            )
        return v

    @field_validator("detections")
    @classmethod
    def _detections_bounded(cls, v: list[DetectionContext]) -> list[DetectionContext]:
        if len(v) > MAX_DETECTIONS:
            raise InvestigationContextBoundError(
                f"detections exceed MAX_DETECTIONS={MAX_DETECTIONS} (got {len(v)})"
            )
        return v

    @field_validator("enrichments")
    @classmethod
    def _enrichments_bounded(cls, v: list[EnrichmentContext]) -> list[EnrichmentContext]:
        if len(v) > MAX_ENRICHMENTS:
            raise InvestigationContextBoundError(
                f"enrichments exceed MAX_ENRICHMENTS={MAX_ENRICHMENTS} (got {len(v)})"
            )
        return v

    @field_validator("historical_memories")
    @classmethod
    def _historical_memories_bounded(
        cls, v: list[IncidentMemoryReferenceContext]
    ) -> list[IncidentMemoryReferenceContext]:
        if len(v) > MAX_INCIDENT_MEMORY_REFERENCES:
            raise InvestigationContextBoundError(
                f"historical incident memories exceed "
                f"MAX_INCIDENT_MEMORY_REFERENCES="
                f"{MAX_INCIDENT_MEMORY_REFERENCES} (got {len(v)})"
            )
        return v

    @field_validator("event_provenance")
    @classmethod
    def _event_provenance_bounded(
        cls, v: list[EventProvenanceContext]
    ) -> list[EventProvenanceContext]:
        if len(v) > MAX_EVENT_PROVENANCE_ENTRIES:
            raise InvestigationContextBoundError(
                f"event provenance entries exceed MAX_EVENT_PROVENANCE_ENTRIES="
                f"{MAX_EVENT_PROVENANCE_ENTRIES} (got {len(v)})"
            )
        return v

    @field_validator("evidence")
    @classmethod
    def _evidence_bounded(cls, v: list[InvestigationEvidence]) -> list[InvestigationEvidence]:
        if len(v) > MAX_EVIDENCE_ITEMS:
            raise InvestigationContextBoundError(
                f"derived evidence exceeds MAX_EVIDENCE_ITEMS="
                f"{MAX_EVIDENCE_ITEMS} (got {len(v)})"
            )
        return v

    @field_validator("metadata")
    @classmethod
    def _metadata_payload(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_control_payload(v, "context metadata")

    @model_validator(mode="after")
    def _enforce_total_size_bound(self) -> "InvestigationContext":
        """The complete serialized context must respect the total byte cap.

        Deterministic: ``model_dump_json()`` output depends only on the
        validated content (identities and timestamps are already fixed).
        """
        size = len(self.model_dump_json().encode("utf-8"))
        if size > MAX_CONTEXT_TOTAL_BYTES:
            raise InvestigationContextBoundError(
                f"InvestigationContext exceeds MAX_CONTEXT_TOTAL_BYTES="
                f"{MAX_CONTEXT_TOTAL_BYTES} (serialized size {size})"
            )
        return self


# ---------------------------------------------------------------------------
# Deterministic derived-evidence identities.
#
# The Step 12A ``InvestigationEvidence.evidence_id`` is a uuid4 default.  To
# keep 12B serialization byte-identical for identical inputs, the builder
# derives each evidence id deterministically from the source reference via
# uuid5 under a fixed namespace.  The namespace is fixed and not
# security-relevant.
# ---------------------------------------------------------------------------

_EVIDENCE_NAMESPACE = uuid.UUID("a3f2b4c0-8c11-4a40-9b1e-2f6d7e0c5a92")


def _evidence_id(source_key: str) -> uuid.UUID:
    """Deterministic evidence identity derived from a source reference."""
    return uuid.uuid5(_EVIDENCE_NAMESPACE, source_key)


# ---------------------------------------------------------------------------
# InvestigationContextBuilder
# ---------------------------------------------------------------------------


class InvestigationContextBuilder:
    """Pure, deterministic builder from SentinelAI domain outputs to
    :class:`InvestigationContext`.

    The builder:

    * extracts only allowlisted fields from each source type;
    * preserves provenance, identifiers, timestamps, and structured
      evidence;
    * excludes secrets (refuse-to-carry), internal implementation details,
      ORM objects, auth/session state, and database-specific fields;
    * applies deterministic bounds (reject policy — never truncates);
    * never mutates its sources and never shares mutable state with them;
    * never calculates risk, never derives confidence, never creates
      findings or observations, never performs reasoning, and never calls
      an AI model.

    It is stateless: ``build`` is the only public entry point and all
    private helpers are side-effect free.
    """

    def build(
        self,
        *,
        correlation: CorrelationResult | None = None,
        risk_assessment: RiskAssessment | None = None,
        detections: (
            DetectionCorrelationBatch
            | Iterable[
                DetectionCorrelationInput | DetectionResult | DetectionResultRecord
            ]
            | None
        ) = None,
        threat_intelligence: ThreatIntelligenceAnalysis | None = None,
        enrichments: Iterable[EnrichmentResult] | None = None,
        historical_memories: Iterable[IncidentMemoryRecord] | None = None,
        event_provenance: Mapping[uuid.UUID, Provenance] | None = None,
        investigation_id: uuid.UUID | None = None,
        context_created_at: datetime | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> InvestigationContext:
        """Produce an :class:`InvestigationContext` from domain outputs.

        Args:
            correlation: The Step 10A ``CorrelationResult`` the context is
                anchored to.  Required.
            risk_assessment: An optional Step 11A ``RiskAssessment``.
            detections: An optional ``DetectionCorrelationBatch`` or an
                iterable of ``DetectionCorrelationInput`` /
                ``DetectionResult`` (matched) / ``DetectionResultRecord``.
                A non-match ``DetectionResult`` is refused (existing
                Step 9I contract semantics via ``to_correlation_input``).
            threat_intelligence: An optional Step 8A
                ``ThreatIntelligenceAnalysis``.
            enrichments: An optional iterable of ``EnrichmentResult``.
            historical_memories: Optional iterable of Step 18
                ``IncidentMemoryRecord`` read models (retrieved through the
                Step 18 ``IncidentMemoryQueryService`` — the builder itself
                never accesses the database).  Each becomes an explicit
                historical background reference and is **never** indexed
                into ``evidence``.  An explicitly empty iterable records
                ``NONE_FOUND``; ``None`` records ``NOT_PROVIDED``.
            event_provenance: Optional mapping of referenced ``event_id`` to
                the event record's own ``Provenance``.  Declared entries are
                preserved verbatim (a ``RECONSTRUCTED`` event stays
                ``RECONSTRUCTED``); undeclared origins are never claimed as
                observed.
            investigation_id: Identity for the context; auto-generated
                (uuid4) when omitted.  Supply it for deterministic builds.
            context_created_at: Bookkeeping instant; defaults to "now" when
                omitted (injectable clock for deterministic builds).  It is
                explicitly not security evidence.
            metadata: Optional caller metadata merged under reserved
                bookkeeping keys.  Reserved keys are refused.

        Raises:
            TypeError: if a source is not a supported type.
            ValueError: if a source is invalid (e.g. an unmatched detection)
                or violates a source contract.
            InvestigationContextBoundError: if a documented bound is
                exceeded (messages are sanitized).
        """
        correlation_context = self._build_correlation(correlation)
        risk_context = self._build_risk(risk_assessment)
        detections_provided = detections is not None
        detections_input = self._coerce_detections(detections)
        self._check_count(
            len(detections_input),
            MAX_DETECTIONS,
            "MAX_DETECTIONS",
            "detections",
        )
        detection_contexts = [
            self._build_detection(item) for item in detections_input
        ]
        ti_context = (
            self._build_threat_intelligence(threat_intelligence)
            if threat_intelligence is not None
            else None
        )
        enrichments_provided = enrichments is not None
        enrichment_inputs = self._coerce_enrichments(enrichments)
        self._check_count(
            len(enrichment_inputs),
            MAX_ENRICHMENTS,
            "MAX_ENRICHMENTS",
            "enrichments",
        )
        enrichment_contexts = [
            self._build_enrichment(item) for item in enrichment_inputs
        ]
        memories_provided = historical_memories is not None
        memory_inputs = self._coerce_historical_memories(historical_memories)
        self._check_count(
            len(memory_inputs),
            MAX_INCIDENT_MEMORY_REFERENCES,
            "MAX_INCIDENT_MEMORY_REFERENCES",
            "historical incident memories",
        )
        memory_contexts = [
            self._build_historical_memory(record) for record in memory_inputs
        ]
        declared = self._coerce_event_provenance(event_provenance)
        event_provenance_context = self._build_event_provenance(
            correlation, detections_input, threat_intelligence, declared
        )
        evidence = self._build_evidence(
            correlation,
            risk_assessment,
            detections_input,
            threat_intelligence,
            declared,
        )
        if len(evidence) > MAX_EVIDENCE_ITEMS:
            raise InvestigationContextBoundError(
                f"derived evidence exceeds MAX_EVIDENCE_ITEMS="
                f"{MAX_EVIDENCE_ITEMS} (got {len(evidence)})"
            )

        investigation_context = InvestigationContext(
            investigation_id=investigation_id or uuid.uuid4(),
            context_created_at=context_created_at or datetime.now(timezone.utc),
            input_availability=self._availability(
                risk_assessment,
                detections_input,
                detections_provided,
                threat_intelligence,
                enrichment_inputs,
                enrichments_provided,
                memory_inputs,
                memories_provided,
            ),
            correlation=correlation_context,
            risk_assessment=risk_context,
            detections=detection_contexts,
            threat_intelligence=ti_context,
            enrichments=enrichment_contexts,
            historical_memories=memory_contexts,
            event_provenance=event_provenance_context,
            evidence=evidence,
            metadata=self._merge_metadata(metadata),
        )
        return investigation_context

    # -- Errors ----------------------------------------------------------

    @staticmethod
    def _check_count(
        count: int, limit: int, bound_name: str, section: str
    ) -> None:
        if count > limit:
            raise InvestigationContextBoundError(
                f"{section} exceed {bound_name}={limit} (got {count}); "
                "the context was refused rather than truncated"
            )

    @staticmethod
    def _coerce_event_provenance(
        declared: Mapping[uuid.UUID, Provenance] | None,
    ) -> dict[uuid.UUID, Provenance]:
        if declared is None:
            return {}
        if not isinstance(declared, Mapping):
            raise TypeError(
                "event_provenance must be a Mapping of event_id to Provenance; "
                f"received {type(declared).__module__}.{type(declared).__qualname__}"
            )
        entries: dict[uuid.UUID, Provenance] = {}
        for key, value in declared.items():
            if not isinstance(value, Provenance):
                raise TypeError(
                    "event_provenance values must be Provenance; received "
                    f"{type(value).__module__}.{type(value).__qualname__}"
                )
            entries[key] = value
        if len(entries) > MAX_EVENT_PROVENANCE_ENTRIES:
            raise InvestigationContextBoundError(
                f"event provenance entries exceed MAX_EVENT_PROVENANCE_ENTRIES="
                f"{MAX_EVENT_PROVENANCE_ENTRIES} (got {len(entries)})"
            )
        return entries

    @staticmethod
    def _coerce_enrichments(
        enrichments: Iterable[EnrichmentResult] | None,
    ) -> list[EnrichmentResult]:
        if enrichments is None:
            return []
        if isinstance(enrichments, EnrichmentResult):
            enrichments = [enrichments]
        items = list(enrichments)
        for item in items:
            if not isinstance(item, EnrichmentResult):
                raise TypeError(
                    "enrichments must be EnrichmentResult records; received "
                    f"{type(item).__module__}.{type(item).__qualname__}"
                )
        return items

    @staticmethod
    def _coerce_historical_memories(
        memories: Iterable[IncidentMemoryRecord] | None,
    ) -> list[IncidentMemoryRecord]:
        if memories is None:
            return []
        if isinstance(memories, IncidentMemoryRecord):
            memories = [memories]
        try:
            items = list(memories)
        except TypeError:
            raise TypeError(
                "historical_memories must be an IncidentMemoryRecord or an "
                "iterable of IncidentMemoryRecord read models; received "
                f"{type(memories).__module__}.{type(memories).__qualname__}"
            )
        for item in items:
            if not isinstance(item, IncidentMemoryRecord):
                raise TypeError(
                    "historical_memories must contain only "
                    "IncidentMemoryRecord read models; received "
                    f"{type(item).__module__}.{type(item).__qualname__}"
                )
        return list(items)

    @staticmethod
    def _coerce_detections(
        detections: (
            DetectionCorrelationBatch
            | Iterable[
                DetectionCorrelationInput | DetectionResult | DetectionResultRecord
            ]
            | None
        ),
    ) -> list[DetectionCorrelationInput]:
        if detections is None:
            return []
        if isinstance(detections, DetectionCorrelationBatch):
            items = list(detections.detections)
        elif isinstance(detections, DetectionCorrelationInput) or isinstance(
            detections, (DetectionResult, DetectionResultRecord)
        ):
            items = [detections]
        else:
            try:
                items = list(detections)
            except TypeError:
                raise TypeError(
                    "detections must be a DetectionCorrelationBatch, a "
                    "DetectionCorrelationInput, a matched DetectionResult, a "
                    "DetectionResultRecord, or an iterable of those; received "
                    f"{type(detections).__module__}.{type(detections).__qualname__}"
                )
        converted: list[DetectionCorrelationInput] = []
        for item in items:
            if isinstance(item, DetectionCorrelationInput):
                converted.append(item)
            elif isinstance(item, (DetectionResult, DetectionResultRecord)):
                converted.append(to_correlation_input(item))
            else:
                raise TypeError(
                    "detections must be DetectionCorrelationInput, a matched "
                    "DetectionResult, a DetectionResultRecord, or a "
                    "DetectionCorrelationBatch; received "
                    f"{type(item).__module__}.{type(item).__qualname__}"
                )
        return converted

    @staticmethod
    def _availability(
        risk_assessment: RiskAssessment | None,
        detections_input: list[DetectionCorrelationInput],
        detections_provided: bool,
        threat_intelligence: ThreatIntelligenceAnalysis | None,
        enrichment_inputs: list[EnrichmentResult],
        enrichments_provided: bool,
        memory_inputs: list[IncidentMemoryRecord],
        memories_provided: bool,
    ) -> ContextInputAvailability:
        return ContextInputAvailability(
            risk_assessment=(
                InputAvailability.PROVIDED
                if risk_assessment is not None
                else InputAvailability.NOT_PROVIDED
            ),
            detections=(
                InputAvailability.PROVIDED
                if detections_input
                else (
                    InputAvailability.NONE_FOUND
                    if detections_provided
                    else InputAvailability.NOT_PROVIDED
                )
            ),
            historical_memories=(
                InputAvailability.PROVIDED
                if memory_inputs
                else (
                    InputAvailability.NONE_FOUND
                    if memories_provided
                    else InputAvailability.NOT_PROVIDED
                )
            ),
            threat_intelligence=(
                InputAvailability.PROVIDED
                if threat_intelligence is not None
                else InputAvailability.NOT_PROVIDED
            ),
            enrichments=(
                InputAvailability.PROVIDED
                if enrichment_inputs
                else (
                    InputAvailability.NONE_FOUND
                    if enrichments_provided
                    else InputAvailability.NOT_PROVIDED
                )
            ),
        )

    @staticmethod
    def _merge_metadata(metadata: Mapping[str, Any] | None) -> dict[str, Any]:
        bookkeeping = {
            "context_schema_version": "1.0.0",
            "truncation": [],
        }
        if metadata is None:
            return _validate_control_payload(bookkeeping, "context metadata")
        if not isinstance(metadata, Mapping):
            raise TypeError(
                "metadata must be a Mapping; received "
                f"{type(metadata).__module__}.{type(metadata).__qualname__}"
            )
        reserved = bookkeeping.keys() & metadata.keys()
        if reserved:
            raise InvestigationContextError(
                "reserved context metadata key(s) cannot be overridden: "
                + ", ".join(sorted(reserved))
            )
        merged = dict(bookkeeping)
        merged.update(metadata)
        return _validate_control_payload(merged, "context metadata")

    # -- Source adapters -------------------------------------------------

    @staticmethod
    def _build_correlation(
        correlation: CorrelationResult | None,
    ) -> CorrelationContext:
        if correlation is None:
            raise TypeError(
                "correlation is required to build an InvestigationContext; "
                "received None"
            )
        if not isinstance(correlation, CorrelationResult):
            raise TypeError(
                "correlation must be a CorrelationResult; received "
                f"{type(correlation).__module__}.{type(correlation).__qualname__}"
            )
        if len(correlation.members) > MAX_CORRELATION_MEMBERS:
            raise InvestigationContextBoundError(
                f"correlation members exceed MAX_CORRELATION_MEMBERS="
                f"{MAX_CORRELATION_MEMBERS} (got {len(correlation.members)})"
            )
        return CorrelationContext(
            correlation_id=correlation.correlation_id,
            status=correlation.status,
            confidence=correlation.confidence,
            members=[
                CorrelationMemberContext(
                    detection_id=member.detection_id,
                    event_id=member.event_id,
                    timestamp=member.timestamp,
                )
                for member in correlation.members
            ],
            evidence=_json_clone(correlation.evidence),
            timestamp=correlation.timestamp,
            provenance=correlation.provenance,
        )

    @staticmethod
    def _build_risk(risk_assessment: RiskAssessment | None) -> RiskContext | None:
        if risk_assessment is None:
            return None
        if not isinstance(risk_assessment, RiskAssessment):
            raise TypeError(
                "risk_assessment must be a RiskAssessment; received "
                f"{type(risk_assessment).__module__}.{type(risk_assessment).__qualname__}"
            )
        return RiskContext(
            risk_assessment_id=risk_assessment.risk_assessment_id,
            correlation_id=risk_assessment.correlation_id,
            score=risk_assessment.score,
            level=risk_assessment.level,
            confidence=risk_assessment.confidence,
            factors=[
                _json_clone(factor.model_dump())
                for factor in risk_assessment.factors
            ],
            evidence=[
                _json_clone(item.model_dump())
                for item in risk_assessment.evidence
            ],
            timestamp=risk_assessment.timestamp,
            provenance=risk_assessment.provenance,
        )

    @staticmethod
    def _build_detection(item: DetectionCorrelationInput) -> DetectionContext:
        if not isinstance(item, DetectionCorrelationInput):
            raise TypeError(
                "detection adapter accepts DetectionCorrelationInput; received "
                f"{type(item).__module__}.{type(item).__qualname__}"
            )
        return DetectionContext(
            detection_id=item.detection_id,
            event_id=item.event_id,
            rule_id=item.rule_id,
            rule_type=item.rule_type,
            rule_version=item.rule_version,
            severity=item.severity,
            confidence=item.confidence,
            evidence=_json_clone(item.evidence),
            metadata=_json_clone(item.metadata),
            timestamp=item.timestamp,
            provenance=item.provenance,
        )

    @staticmethod
    def _build_threat_intelligence(
        analysis: ThreatIntelligenceAnalysis,
    ) -> ThreatIntelligenceContext:
        if not isinstance(analysis, ThreatIntelligenceAnalysis):
            raise TypeError(
                "threat_intelligence must be a ThreatIntelligenceAnalysis; "
                "received "
                f"{type(analysis).__module__}.{type(analysis).__qualname__}"
            )
        indicator_count = len(analysis.indicators)
        result_count = len(analysis.results)
        failure_count = len(analysis.failures)
        if indicator_count > MAX_TI_INDICATORS:
            raise InvestigationContextBoundError(
                f"threat-intelligence indicators exceed MAX_TI_INDICATORS="
                f"{MAX_TI_INDICATORS} (got {indicator_count})"
            )
        if result_count > MAX_TI_PROVIDER_RESULTS:
            raise InvestigationContextBoundError(
                f"threat-intelligence associations exceed MAX_TI_PROVIDER_RESULTS="
                f"{MAX_TI_PROVIDER_RESULTS} (got {result_count})"
            )
        if failure_count > MAX_TI_FAILURES:
            raise InvestigationContextBoundError(
                f"threat-intelligence failures exceed MAX_TI_FAILURES="
                f"{MAX_TI_FAILURES} (got {failure_count})"
            )
        indicators = [
            IndicatorContext(
                indicator=indicator.indicator,
                indicator_type=indicator.indicator_type,
                source_field=indicator.source_field,
                source_context=indicator.source_context,
            )
            for indicator in analysis.indicators
        ]
        provider_results: list[ProviderResultContext] = []
        skipped: list[ProviderLookupContext] = []
        for association in analysis.results:
            if association.result is None:
                skipped.append(
                    ProviderLookupContext(
                        provider=association.provider,
                        indicator_value=association.indicator.indicator,
                        indicator_type=association.indicator.indicator_type,
                    )
                )
                continue
            result = association.result
            provider_results.append(
                ProviderResultContext(
                    provider=result.provider,
                    indicator_value=result.indicator.value,
                    indicator_type=result.indicator.indicator_type,
                    found=result.found,
                    confidence=result.confidence,
                    data=_json_clone(result.data),
                    metadata=_json_clone(result.metadata or {}),
                    timestamp=result.timestamp,
                )
            )
        if len(skipped) > MAX_TI_PROVIDER_RESULTS:
            raise InvestigationContextBoundError(
                f"threat-intelligence skipped lookups exceed "
                f"MAX_TI_PROVIDER_RESULTS={MAX_TI_PROVIDER_RESULTS} "
                f"(got {len(skipped)})"
            )
        failures = [
            ProviderFailureContext(
                provider=failure.provider,
                indicator=failure.indicator,
                indicator_type=failure.indicator_type,
                error_type=failure.error_type,
                message=failure.message,
                retryable=failure.retryable,
            )
            for failure in analysis.failures
        ]
        return ThreatIntelligenceContext(
            event_id=analysis.event_id,
            indicators=indicators,
            provider_results=provider_results,
            skipped_lookups=skipped,
            failures=failures,
            metadata=_json_clone(analysis.metadata.model_dump()),
        )

    @staticmethod
    def _build_enrichment(item: EnrichmentResult) -> EnrichmentContext:
        if not isinstance(item, EnrichmentResult):
            raise TypeError(
                "enrichment adapter accepts EnrichmentResult; received "
                f"{type(item).__module__}.{type(item).__qualname__}"
            )
        return EnrichmentContext(
            enrichment_id=item.enrichment_id,
            enrichment_type=item.enrichment_type,
            source=item.source,
            value=_json_clone(item.value),
            confidence=item.confidence,
            timestamp=item.timestamp,
            metadata=_json_clone(item.metadata or {}),
            provenance=Provenance.ENRICHED,
        )

    @staticmethod
    def _build_historical_memory(
        record: IncidentMemoryRecord,
    ) -> IncidentMemoryReferenceContext:
        """Adapt one Step 18 read model into a historical reference.

        Only the memory's own identity, kind, safe representation, and
        provenance-bearing structured content are carried.  The record is
        never mutated, and no ``InvestigationEvidence`` record is derived —
        memory is background reference, not evidence.
        """
        if not isinstance(record, IncidentMemoryRecord):
            raise TypeError(
                "historical memory adapter accepts IncidentMemoryRecord; "
                "received "
                f"{type(record).__module__}.{type(record).__qualname__}"
            )
        return IncidentMemoryReferenceContext(
            memory_id=record.memory_id,
            memory_type=record.memory_type,
            title=record.title,
            summary=record.summary,
            correlation_id=record.correlation_id,
            created_at=record.created_at,
            confidence=record.confidence,
            sources=[_json_clone(source) for source in record.sources],
            memory_metadata=_json_clone(record.memory_metadata),
        )

    @staticmethod
    def _build_event_provenance(
        correlation: CorrelationResult,
        detections: list[DetectionCorrelationInput],
        threat_intelligence: ThreatIntelligenceAnalysis | None,
        declared: Mapping[uuid.UUID, Provenance],
    ) -> list[EventProvenanceContext]:
        referenced: set[uuid.UUID] = set()
        for member in correlation.members:
            referenced.add(member.event_id)
        for detection in detections:
            referenced.add(detection.event_id)
        if threat_intelligence is not None:
            referenced.add(threat_intelligence.event_id)
        present = referenced & set(declared.keys())
        ordered = sorted(present, key=lambda e: str(e))
        return [
            EventProvenanceContext(event_id=event_id, provenance=declared[event_id])
            for event_id in ordered
        ]

    @staticmethod
    def _resolve_event_origin(
        event_id: uuid.UUID,
        declared: Mapping[uuid.UUID, Provenance],
    ) -> Provenance | None:
        """Return the declared source-event provenance, or None when
        undeclared.  Never fabricates an ``OBSERVED`` claim."""
        origin = declared.get(event_id)
        if origin is None:
            return None
        return origin

    def _build_evidence(
        self,
        correlation: CorrelationResult,
        risk_assessment: RiskAssessment | None,
        detections: list[DetectionCorrelationInput],
        threat_intelligence: ThreatIntelligenceAnalysis | None,
        declared: Mapping[uuid.UUID, Provenance],
    ) -> list[InvestigationEvidence]:
        """Mechanically index the carried sources as Step 12A evidence.

        Evidence provenance follows the Step 12A coherence rules: CORRELATED
        references the correlation, RISK_ASSESSED the assessment, DETECTED
        the detection, and OBSERVED / ENRICHED / RECONSTRUCTED the event.  A
        TI indicator gets an evidence record only when its source-event
        provenance was declared (never fabricating an observed claim).
        """
        evidence: list[InvestigationEvidence] = []
        evidence.append(
            InvestigationEvidence(
                evidence_id=_evidence_id(
                    f"correlated|correlation|{correlation.correlation_id}"
                ),
                evidence_type="correlation_result",
                provenance=Provenance.CORRELATED,
                correlation_id=correlation.correlation_id,
            )
        )
        if risk_assessment is not None:
            evidence.append(
                InvestigationEvidence(
                    evidence_id=_evidence_id(
                        f"risk_assessed|assessment|{risk_assessment.risk_assessment_id}"
                    ),
                    evidence_type="risk_assessment",
                    provenance=Provenance.RISK_ASSESSED,
                    risk_assessment_id=risk_assessment.risk_assessment_id,
                )
            )
        for detection in detections:
            evidence.append(
                InvestigationEvidence(
                    evidence_id=_evidence_id(
                        f"detected|detection|{detection.detection_id}"
                    ),
                    evidence_type="detection_result",
                    provenance=Provenance.DETECTED,
                    detection_id=detection.detection_id,
                )
            )
        if threat_intelligence is not None:
            for indicator in threat_intelligence.indicators:
                origin = self._resolve_event_origin(
                    threat_intelligence.event_id, declared
                )
                if origin is None:
                    continue
                evidence.append(
                    InvestigationEvidence(
                        evidence_id=_evidence_id(
                            "source_origin|indicator|"
                            f"{threat_intelligence.event_id}|"
                            f"{indicator.indicator_type.value}|{indicator.indicator}"
                        ),
                        evidence_type="threat_intelligence_indicator",
                        provenance=origin,
                        event_id=threat_intelligence.event_id,
                    )
                )
            for association in threat_intelligence.results:
                if association.result is None:
                    continue
                evidence.append(
                    InvestigationEvidence(
                        evidence_id=_evidence_id(
                            "enriched|provider_lookup|"
                            f"{threat_intelligence.event_id}|"
                            f"{association.result.provider}|"
                            f"{association.result.indicator.value}"
                        ),
                        evidence_type="threat_intelligence_provider_lookup",
                        provenance=Provenance.ENRICHED,
                        event_id=threat_intelligence.event_id,
                    )
                )
        return evidence