"""Step 16 Incident Memory foundation — domain contract.

**Scope.** This module defines the *domain contract* for representing
reusable historical knowledge extracted from completed security incidents
and investigations.  It deliberately contains **no memory logic**: it does
not decide which memories to produce, does not assemble memories from
pipeline objects, calls no LLM/RAG, persists nothing, exposes no API, and
performs no response or mitigation.  It only validates and transports the
structured, bounded shape that the deterministic memory extraction layer
(future Step 16 engine, see ``app/services/incident_memory/``) may fill.

**Memory semantics.** An :class:`IncidentMemory` is **historical memory**,
never current evidence.  The whole memory record is pinned to the additive
``Provenance.RECALLED`` value so it can never silently masquerade as an
observed / enriched / reconstructed / detected / correlated / risk-assessed
/ ai-generated / attribution-assessed *current* fact.  Its
:class:`MemorySource` references, in contrast, always retain the **original
provenance** of the information they cite (``OBSERVED`` … through
``ATTRIBUTION_ASSESSED``).  Provenance is never silently converted: a
memory assembled from an AI investigation finding keeps ``AI_GENERATED`` +
the ``investigation_id`` reference; one assembled from telemetry keeps
``OBSERVED`` + the ``event_id`` reference.

**Explicitness.** Every fact that memory may carry (indicator, entity,
attack technique, finding, action, outcome) is explicitly supplied by the
caller as structured information.  Nothing is inferred from prose, and no
attacker / IP / domain / malware / technique / action / outcome / verdict
is ever invented here.  Content items reference their origin via
``source_ids`` that must resolve to the memory's own sources.

**Safety invariants.** Memory is fail-closed: secret-shaped content is
rejected (never redacted), timestamps must be timezone-aware, confidence is
bounded to ``[0.0, 1.0]`` and finite (never boolean-coerced, never derived from
risk / detection / attribution confidence), metadata is JSON-safe and
bounded, every list is bounded, and over-limit input is **rejected**
(never truncated).

**Determinism.** Module state is immutable after construction; there is no
hidden clock (``created_at`` must be supplied explicitly) and no
sorting/deduplication mutates list order.  Identical inputs produce
identical ``model_dump_json()`` output.
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
    field_validator,
    model_validator,
)

from app.schemas.security_event import Provenance

# ---------------------------------------------------------------------------
# Bound constants
# ---------------------------------------------------------------------------
# These are hard contract limits, not configuration: values that exceed
# them are REJECTED (never truncated), preserving deterministic, bounded
# output.  Values are chosen conservatively and consistently with the
# existing staged contracts (attribution / investigation / knowledge).

MAX_MEMORY_TITLE_LENGTH = 128
MAX_MEMORY_SUMMARY_LENGTH = 2048
MAX_MEMORY_LABEL_LENGTH = 512
MAX_MEMORY_IDENTIFIER_LENGTH = 256
MAX_MEMORY_VALUE_LENGTH = 512
MAX_MEMORY_TECHNIQUE_CODE_LENGTH = 128
MAX_MEMORY_SOURCES = 64
MAX_MEMORY_INDICATORS = 128
MAX_MEMORY_ENTITIES = 128
MAX_MEMORY_TECHNIQUES = 64
MAX_MEMORY_FINDINGS = 64
MAX_MEMORY_ACTIONS = 64
MAX_MEMORY_METADATA_DEPTH = 8
MAX_MEMORY_METADATA_SERIALIZED_BYTES = 4 * 1024

#: A content item may cite at most this many distinct memory sources.
MAX_MEMORY_SOURCE_REFERENCES_PER_ITEM = MAX_MEMORY_SOURCES

# ---------------------------------------------------------------------------
# Secret / JSON safety helpers
#
# These local helpers mirror the canonical secret and JSON-safety patterns
# used by every staged schema contract (risk 11A, investigation 12A,
# context 12B/12C, knowledge 13, attribution 14).  They are deliberately
# re-declared in this module so the contract stays self-contained and
# testable in isolation; they are kept in lock-step with the canonical set.
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

    The content is serialized and scanned as text, so secret-shaped
    *values* are rejected exactly like secret-shaped keys.  This is a
    shape-based scan: a benign-looking value under a field whose name
    appears in the serialized content is still rejected.  Secrets are
    rejected, never redacted.
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



class _SecretScannedRecord(BaseModel):
    """Leak-free whole-record secret scan shared by every content record.

    Works exactly like the envelope: the record is scanned as serialized
    text so secret-shaped content anywhere in it is rejected -- and never
    echoed back into the error message.  Standalone content records (a
    memory source, an indicator value, ...) must be just as safe on their
    own as they are nested under an envelope.
    """

    _secret_scan_label: str = "memory record"

    @model_validator(mode="after")
    def _scan_record_secret_free(self: "_SecretScannedRecord") -> "_SecretScannedRecord":
        serialized = json.dumps(
            self.model_dump(mode="json")
        ).lower()
        for pattern in _SECRET_PATTERNS:
            if pattern in serialized:
                raise ValueError(
                    "{} must not contain secret-shaped content ('{}'); "
                    "secrets are rejected, never redacted".format(
                        self._secret_scan_label, pattern
                    )
                )
        return self


def _is_json_compatible(value: Any, depth: int = 0) -> bool:
    """True when *value* is recursively JSON-compatible and depth-bounded.

    Rejects sets, bytes, arbitrary objects, ``NaN``/``Infinity`` and
    excessive nesting.
    """
    if isinstance(value, dict):
        if depth >= MAX_MEMORY_METADATA_DEPTH:
            return False
        return all(
            isinstance(k, str) and _is_json_compatible(v, depth + 1)
            for k, v in value.items()
        )
    if isinstance(value, list):
        if depth >= MAX_MEMORY_METADATA_DEPTH:
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

    ``json.dumps`` first (canonical pattern) rejects sets, bytes, arbitrary
    objects, and reference cycles; the structural check then rejects
    ``NaN``/``Infinity`` and excessive nesting depth.  This is a rejection,
    never a repair.
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

    Guarantees the contract never shares mutable state with the caller.
    """
    return json.loads(json.dumps(obj))


# ---------------------------------------------------------------------------
# Memory type
# ---------------------------------------------------------------------------


class MemoryType(str, Enum):
    """Deterministic category of a reusable historical memory record.

    The taxonomy is deliberately small and justified by what a completed
    investigation actually produced: a summary of what happened, the
    indicators observed, an attack technique pattern, a structured
    conclusion (finding), and what was done and how it went (action +
    outcome).  Categories are not added for future speculation; new values
    can be added additively in later versions.
    """

    INCIDENT_SUMMARY = "incident_summary"
    INDICATOR_OBSERVATION = "indicator_observation"
    ATTACK_PATTERN = "attack_pattern"
    INVESTIGATION_FINDING = "investigation_finding"
    MITIGATION_OUTCOME = "mitigation_outcome"


# ---------------------------------------------------------------------------
# Memory source reference
# ---------------------------------------------------------------------------


class MemorySource(_SecretScannedRecord):
    """A provenance-aware reference to the origin of remembered information.

    Memory retains *where its information came from*.  A source references
    exactly one existing SentinelAI identity and keeps the ORIGINAL
    provenance of that information:

    * ``OBSERVED`` / ``ENRICHED`` / ``RECONSTRUCTED`` → ``event_id``
    * ``DETECTED`` → ``detection_id``
    * ``CORRELATED`` → ``correlation_id``
    * ``RISK_ASSESSED`` → ``risk_assessment_id``
    * ``AI_GENERATED`` → ``investigation_id`` (a memory taken from an AI
      investigation finding retains this reference; ``finding_id`` may add
      the specific finding)
    * ``ATTRIBUTION_ASSESSED`` → ``attribution_assessment_id``
    * ``RECALLED`` → **forbidden**: memory remembers its past via original
      provenance; it never pretends a source is itself historical memory.
    * ``LEARNED`` → **forbidden**: a derived historical learning/consolidation
      is not an *original* provenance an incident was gathered from; it would
      never be the source of remembered information.

    Provenance is never silently converted from one value to another.
    """

    model_config = {"extra": "ignore"}

    source_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    provenance: Provenance = Field(
        ...,
        description="Original provenance of the remembered information.",
    )
    label: str | None = Field(
        default=None,
        description="Optional machine-readable label naming what was cited.",
    )
    event_id: uuid.UUID | None = None
    detection_id: uuid.UUID | None = None
    correlation_id: uuid.UUID | None = None
    risk_assessment_id: uuid.UUID | None = None
    investigation_id: uuid.UUID | None = None
    attribution_assessment_id: uuid.UUID | None = None
    finding_id: uuid.UUID | None = Field(
        default=None,
        description="Specific AI investigation finding reference (AI_GENERATED only).",
    )
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("label")
    @classmethod
    def _label_bounded(cls, v: Any) -> str | None:
        if v is None:
            return None
        return _bound_string(v, "source label", MAX_MEMORY_LABEL_LENGTH)

    @field_validator("metadata")
    @classmethod
    def _metadata_valid(cls, v: Any) -> dict[str, Any]:
        if v is None:
            return {}
        _assert_json_compatible(v, "source metadata")
        _assert_no_secrets(v, "source metadata")
        if len(json.dumps(v)) > MAX_MEMORY_METADATA_SERIALIZED_BYTES:
            raise ValueError(
                "source metadata exceeds the maximum serialized size of "
                f"{MAX_MEMORY_METADATA_SERIALIZED_BYTES} bytes"
            )
        return _json_clone(v)

    @field_validator("provenance")
    @classmethod
    def _source_provenance_not_recalled(cls, v: Provenance) -> Provenance:
        """A memory source is the *origin* of information, not memory itself."""
        if v is Provenance.RECALLED:
            raise ValueError(
                "a memory source reference cannot be RECALLED; sources "
                "retain the original provenance of the information they "
                "cite"
            )
        if v is Provenance.LEARNED:
            raise ValueError(
                "a memory source reference cannot be LEARNED; sources "
                "retain the original provenance of the information they "
                "cite, never a derived learning/consolidation result"
            )
        return v

    @model_validator(mode="after")
    def _ensure_reference_coherent(self) -> "MemorySource":
        """Provenance must be backed by its matching reference."""
        required = {
            Provenance.ENRICHED: "event_id",
            Provenance.RECONSTRUCTED: "event_id",
            Provenance.DETECTED: "detection_id",
            Provenance.CORRELATED: "correlation_id",
            Provenance.RISK_ASSESSED: "risk_assessment_id",
            Provenance.AI_GENERATED: "investigation_id",
            Provenance.ATTRIBUTION_ASSESSED: "attribution_assessment_id",
        }
        needed = required.get(self.provenance)
        if needed is not None and getattr(self, needed) is None:
            raise ValueError(
                f"{self.provenance.value} memory source must reference "
                f"{needed}; a provenance category cannot be attached "
                "without its matching source identity"
            )
        if self.finding_id is not None and self.provenance is not Provenance.AI_GENERATED:
            raise ValueError(
                "finding_id references a specific AI investigation finding "
                "and is only valid for AI_GENERATED sources"
            )
        return self


# ---------------------------------------------------------------------------
# Content value models (explicit structured information only)
# ---------------------------------------------------------------------------


class MemoryIndicator(_SecretScannedRecord):
    """A historically observed indicator value, explicitly supplied.

    Carries no inventive analysis: the type and value are exactly what the
    caller supplied, and the ``indicator_id``/``source_ids`` keep it
    traceable and bound to its origins.
    """

    model_config = {"extra": "ignore"}

    indicator_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    indicator_type: str = Field(...)
    value: str = Field(...)
    source_ids: list[uuid.UUID] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("indicator_type")
    @classmethod
    def _type_bounded(cls, v: Any) -> str:
        return _bound_string(v, "indicator_type", MAX_MEMORY_LABEL_LENGTH)

    @field_validator("value")
    @classmethod
    def _value_bounded(cls, v: Any) -> str:
        return _bound_string(v, "indicator value", MAX_MEMORY_VALUE_LENGTH)

    @field_validator("source_ids")
    @classmethod
    def _source_ids_bounded(cls, v: list[uuid.UUID]) -> list[uuid.UUID]:
        if len(v) > MAX_MEMORY_SOURCE_REFERENCES_PER_ITEM:
            raise ValueError(
                "indicator source_ids exceed the maximum of "
                f"{MAX_MEMORY_SOURCE_REFERENCES_PER_ITEM} references"
            )
        return list(v)

    @field_validator("metadata")
    @classmethod
    def _metadata_valid(cls, v: Any) -> dict[str, Any]:
        return _bounded_metadata(v, "indicator metadata")


class MemoryEntity(_SecretScannedRecord):
    """An explicitly supplied entity involved in the remembered incident.

    Only identifiers explicitly supplied become memory.  Memory never
    invents attackers, hosts, or other actors.
    """

    model_config = {"extra": "ignore"}

    entity_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    entity_type: str = Field(...)
    identifier: str = Field(...)
    source_ids: list[uuid.UUID] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("entity_type")
    @classmethod
    def _type_bounded(cls, v: Any) -> str:
        return _bound_string(v, "entity_type", MAX_MEMORY_LABEL_LENGTH)

    @field_validator("identifier")
    @classmethod
    def _identifier_bounded(cls, v: Any) -> str:
        return _bound_string(v, "entity identifier", MAX_MEMORY_IDENTIFIER_LENGTH)

    @field_validator("source_ids")
    @classmethod
    def _source_ids_bounded(cls, v: list[uuid.UUID]) -> list[uuid.UUID]:
        if len(v) > MAX_MEMORY_SOURCE_REFERENCES_PER_ITEM:
            raise ValueError(
                "entity source_ids exceed the maximum of "
                f"{MAX_MEMORY_SOURCE_REFERENCES_PER_ITEM} references"
            )
        return list(v)

    @field_validator("metadata")
    @classmethod
    def _metadata_valid(cls, v: Any) -> dict[str, Any]:
        return _bounded_metadata(v, "entity metadata")


class MemoryTechnique(_SecretScannedRecord):
    """An explicitly supplied attack-technique pattern (e.g. an ATT&CK-style
    code).  The code and optional name are exactly what the caller supplied;
    no technique is ever inferred from behavior.
    """

    model_config = {"extra": "ignore"}

    technique_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    technique_code: str = Field(...)
    name: str | None = None
    source_ids: list[uuid.UUID] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("technique_code")
    @classmethod
    def _code_bounded(cls, v: Any) -> str:
        return _bound_string(v, "technique_code", MAX_MEMORY_TECHNIQUE_CODE_LENGTH)

    @field_validator("name")
    @classmethod
    def _name_bounded(cls, v: Any) -> str | None:
        if v is None:
            return None
        return _bound_string(v, "technique name", MAX_MEMORY_LABEL_LENGTH)

    @field_validator("source_ids")
    @classmethod
    def _source_ids_bounded(cls, v: list[uuid.UUID]) -> list[uuid.UUID]:
        if len(v) > MAX_MEMORY_SOURCE_REFERENCES_PER_ITEM:
            raise ValueError(
                "technique source_ids exceed the maximum of "
                f"{MAX_MEMORY_SOURCE_REFERENCES_PER_ITEM} references"
            )
        return list(v)

    @field_validator("metadata")
    @classmethod
    def _metadata_valid(cls, v: Any) -> dict[str, Any]:
        return _bounded_metadata(v, "technique metadata")


class MemoryFinding(_SecretScannedRecord):
    """A structured conclusion from a completed investigation.

    Confidence is independent: bounded to [0, 1], finite, never
    boolean-coerced, and never derived from risk / detection / attribution
    confidence.
    """

    model_config = {"extra": "ignore"}

    finding_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    finding_type: str = Field(...)
    title: str = Field(...)
    summary: str | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    source_ids: list[uuid.UUID] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("finding_type")
    @classmethod
    def _type_bounded(cls, v: Any) -> str:
        return _bound_string(v, "finding_type", MAX_MEMORY_LABEL_LENGTH)

    @field_validator("title")
    @classmethod
    def _title_bounded(cls, v: Any) -> str:
        return _bound_string(v, "finding title", MAX_MEMORY_TITLE_LENGTH)

    @field_validator("summary")
    @classmethod
    def _summary_bounded(cls, v: Any) -> str | None:
        if v is None:
            return None
        return _bound_string(v, "finding summary", MAX_MEMORY_SUMMARY_LENGTH)

    @field_validator("confidence", mode="before")
    @classmethod
    def _confidence_finite(cls, v: Any) -> Any:
        if isinstance(v, bool):
            raise ValueError("confidence must be a finite floating-point number")
        if isinstance(v, (int, float)) and not isfinite(v):
            raise ValueError("confidence must be finite")
        return v

    @field_validator("source_ids")
    @classmethod
    def _source_ids_bounded(cls, v: list[uuid.UUID]) -> list[uuid.UUID]:
        if len(v) > MAX_MEMORY_SOURCE_REFERENCES_PER_ITEM:
            raise ValueError(
                "finding source_ids exceed the maximum of "
                f"{MAX_MEMORY_SOURCE_REFERENCES_PER_ITEM} references"
            )
        return list(v)

    @field_validator("metadata")
    @classmethod
    def _metadata_valid(cls, v: Any) -> dict[str, Any]:
        return _bounded_metadata(v, "finding metadata")


class MemoryAction(_SecretScannedRecord):
    """An explicitly supplied mitigation / response action taken.

    Memory records *what was done*, never infers a recommended response.
    """

    model_config = {"extra": "ignore"}

    action_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    action_type: str = Field(...)
    description: str | None = None
    source_ids: list[uuid.UUID] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("action_type")
    @classmethod
    def _type_bounded(cls, v: Any) -> str:
        return _bound_string(v, "action_type", MAX_MEMORY_LABEL_LENGTH)

    @field_validator("description")
    @classmethod
    def _description_bounded(cls, v: Any) -> str | None:
        if v is None:
            return None
        return _bound_string(v, "action description", MAX_MEMORY_SUMMARY_LENGTH)

    @field_validator("source_ids")
    @classmethod
    def _source_ids_bounded(cls, v: list[uuid.UUID]) -> list[uuid.UUID]:
        if len(v) > MAX_MEMORY_SOURCE_REFERENCES_PER_ITEM:
            raise ValueError(
                "action source_ids exceed the maximum of "
                f"{MAX_MEMORY_SOURCE_REFERENCES_PER_ITEM} references"
            )
        return list(v)

    @field_validator("metadata")
    @classmethod
    def _metadata_valid(cls, v: Any) -> dict[str, Any]:
        return _bounded_metadata(v, "action metadata")


class MemoryOutcome(_SecretScannedRecord):
    """An explicitly supplied result of the remembered mitigation activity."""

    model_config = {"extra": "ignore"}

    outcome_status: str = Field(...)
    summary: str | None = None
    source_ids: list[uuid.UUID] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("outcome_status")
    @classmethod
    def _status_bounded(cls, v: Any) -> str:
        return _bound_string(v, "outcome_status", MAX_MEMORY_LABEL_LENGTH)

    @field_validator("summary")
    @classmethod
    def _summary_bounded(cls, v: Any) -> str | None:
        if v is None:
            return None
        return _bound_string(v, "outcome summary", MAX_MEMORY_SUMMARY_LENGTH)

    @field_validator("source_ids")
    @classmethod
    def _source_ids_bounded(cls, v: list[uuid.UUID]) -> list[uuid.UUID]:
        if len(v) > MAX_MEMORY_SOURCE_REFERENCES_PER_ITEM:
            raise ValueError(
                "outcome source_ids exceed the maximum of "
                f"{MAX_MEMORY_SOURCE_REFERENCES_PER_ITEM} references"
            )
        return list(v)

    @field_validator("metadata")
    @classmethod
    def _metadata_valid(cls, v: Any) -> dict[str, Any]:
        return _bounded_metadata(v, "outcome metadata")


# ---------------------------------------------------------------------------
# Incident memory
# ---------------------------------------------------------------------------


class IncidentMemory(BaseModel):
    """One historical memory record assembled from a completed incident.

    Pinned to ``Provenance.RECALLED``: the whole record is explicitly
    historical memory/context and can never masquerade as current observed
    evidence.  Provenance of the underlying information lives on the
    ``sources`` (original provenance preserved); content items reference
    those sources via ``source_ids`` (every reference must resolve).
    """

    model_config = {"extra": "ignore"}

    memory_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    memory_type: MemoryType = Field(...)
    title: str = Field(...)
    summary: str | None = None
    correlation_id: uuid.UUID | None = None
    sources: list[MemorySource] = Field(default_factory=list)
    indicators: list[MemoryIndicator] = Field(default_factory=list)
    entities: list[MemoryEntity] = Field(default_factory=list)
    techniques: list[MemoryTechnique] = Field(default_factory=list)
    findings: list[MemoryFinding] = Field(default_factory=list)
    actions: list[MemoryAction] = Field(default_factory=list)
    outcome: MemoryOutcome | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    created_at: datetime = Field(...)
    metadata: dict[str, Any] = Field(default_factory=dict)
    provenance: Provenance = Field(default=Provenance.RECALLED)

    @field_validator("title")
    @classmethod
    def _title_bounded(cls, v: Any) -> str:
        return _bound_string(v, "memory title", MAX_MEMORY_TITLE_LENGTH)

    @field_validator("summary")
    @classmethod
    def _summary_bounded(cls, v: Any) -> str | None:
        if v is None:
            return None
        return _bound_string(v, "memory summary", MAX_MEMORY_SUMMARY_LENGTH)

    @field_validator("confidence", mode="before")
    @classmethod
    def _confidence_finite(cls, v: Any) -> Any:
        if isinstance(v, bool):
            raise ValueError("confidence must be a finite floating-point number")
        if isinstance(v, (int, float)) and not isfinite(v):
            raise ValueError("confidence must be finite")
        return v

    @field_validator("sources")
    @classmethod
    def _sources_bounded(cls, v: list[MemorySource]) -> list[MemorySource]:
        if len(v) > MAX_MEMORY_SOURCES:
            raise ValueError(
                f"memory sources exceed the maximum of {MAX_MEMORY_SOURCES}"
            )
        _assert_list_secret_free(v, "sources")
        return v

    @field_validator("indicators")
    @classmethod
    def _indicators_bounded(cls, v: list[MemoryIndicator]) -> list[MemoryIndicator]:
        if len(v) > MAX_MEMORY_INDICATORS:
            raise ValueError(
                f"memory indicators exceed the maximum of "
                f"{MAX_MEMORY_INDICATORS}"
            )
        _assert_list_secret_free(v, "indicators")
        return v

    @field_validator("entities")
    @classmethod
    def _entities_bounded(cls, v: list[MemoryEntity]) -> list[MemoryEntity]:
        if len(v) > MAX_MEMORY_ENTITIES:
            raise ValueError(
                f"memory entities exceed the maximum of {MAX_MEMORY_ENTITIES}"
            )
        _assert_list_secret_free(v, "entities")
        return v

    @field_validator("techniques")
    @classmethod
    def _techniques_bounded(cls, v: list[MemoryTechnique]) -> list[MemoryTechnique]:
        if len(v) > MAX_MEMORY_TECHNIQUES:
            raise ValueError(
                f"memory techniques exceed the maximum of "
                f"{MAX_MEMORY_TECHNIQUES}"
            )
        _assert_list_secret_free(v, "techniques")
        return v

    @field_validator("findings")
    @classmethod
    def _findings_bounded(cls, v: list[MemoryFinding]) -> list[MemoryFinding]:
        if len(v) > MAX_MEMORY_FINDINGS:
            raise ValueError(
                f"memory findings exceed the maximum of {MAX_MEMORY_FINDINGS}"
            )
        _assert_list_secret_free(v, "findings")
        return v

    @field_validator("actions")
    @classmethod
    def _actions_bounded(cls, v: list[MemoryAction]) -> list[MemoryAction]:
        if len(v) > MAX_MEMORY_ACTIONS:
            raise ValueError(
                f"memory actions exceed the maximum of {MAX_MEMORY_ACTIONS}"
            )
        _assert_list_secret_free(v, "actions")
        return v

    @field_validator("outcome")
    @classmethod
    def _outcome_secret_free(cls, v: MemoryOutcome | None) -> MemoryOutcome | None:
        if v is not None:
            _assert_no_secrets(v.model_dump(mode="json"), "outcome")
        return v

    @field_validator("metadata")
    @classmethod
    def _metadata_valid(cls, v: Any) -> dict[str, Any]:
        return _bounded_metadata(v, "memory metadata")

    @field_validator("created_at")
    @classmethod
    def _ensure_timezone_aware(cls, v: datetime) -> datetime:
        """Reject naive (timezone-unaware) timestamps."""
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError(
                "created_at must be timezone-aware; naive (UTC-less) "
                "timestamps are not accepted"
            )
        return v

    @field_validator("provenance")
    @classmethod
    def _ensure_recalled_pinned(cls, v: Provenance) -> Provenance:
        """Memory is historical context, never current evidence."""
        if v is not Provenance.RECALLED:
            raise ValueError(
                "an incident memory is historical memory/context and must "
                "carry RECALLED provenance; it can never masquerade as "
                "current evidence"
            )
        return v

    @model_validator(mode="after")
    def _ensure_record_secret_free(self) -> "IncidentMemory":
        """The whole historical record is secret-screened once more.

        Fail-closed and lock-step with the staged contracts: a secret in
        the title, summary, or any other serialized field is rejected
        (never redacted), so a memory record can never be created carrying
        credential-shaped content even when it bypassed a list or metadata
        field validator.
        """
        _assert_no_secrets(self.model_dump(mode="json"), "incident memory")
        return self

    @model_validator(mode="after")
    def _ensure_source_references_resolve(self) -> "IncidentMemory":
        """Every content ``source_ids`` reference must resolve to a source.

        All content-item references must name a source carried by this
        memory; an unresolvable reference would be a dangling or fabricated
        citation, so it is rejected deterministically.
        """
        present = {str(source.source_id) for source in self.sources}
        collections: list[tuple[str, list]] = [
            ("indicator", list(self.indicators)),
            ("entity", list(self.entities)),
            ("technique", list(self.techniques)),
            ("finding", list(self.findings)),
            ("action", list(self.actions)),
        ]
        missing: list[str] = []
        for kind, items in collections:
            for item in items:
                for reference in getattr(item, "source_ids"):
                    if str(reference) not in present:
                        missing.append(f"{kind}:{reference}")
        if self.outcome is not None:
            for reference in self.outcome.source_ids:
                if str(reference) not in present:
                    missing.append(f"outcome:{reference}")
        if missing:
            raise ValueError(
                "memory content references must resolve to the memory's "
                "sources; unresolved: " + ", ".join(sorted(missing))
            )
        return self


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


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


def _bounded_metadata(value: Any, label: str) -> dict[str, Any]:
    if value is None:
        return {}
    _assert_json_compatible(value, label)
    _assert_no_secrets(value, label)
    if len(json.dumps(value)) > MAX_MEMORY_METADATA_SERIALIZED_BYTES:
        raise ValueError(
            f"{label} exceeds the maximum serialized size of "
            f"{MAX_MEMORY_METADATA_SERIALIZED_BYTES} bytes"
        )
    return _json_clone(value)


def _assert_list_secret_free(items: list[BaseModel], label: str) -> None:
    """Defence-in-depth: a whole content list is secret-screened once more."""
    _assert_no_secrets(
        [item.model_dump(mode="json") for item in items], label
    )