"""Step 22 — Incident Memory Learning & Consolidation domain contract.

**Scope.** This module defines the *domain contract* for representing
deterministic, evidence-grounded **learning / consolidation results** derived
from explicitly available ``recalled`` incident memories (the Step 18
:class:`~app.schemas.incident_memory_query.IncidentMemoryRecord` view over the
Step 17 persistence layer).  It deliberately contains **no learning logic**
and **no query logic**: it does not decide which consolidations to produce,
reads no database, calls no LLM/RAG, persists nothing, exposes no API, and
performs no response or mitigation.  It only validates and transports the
structured, bounded shape that the deterministic learning service
(``app/services/incident_memory_learning.py``) fills.

**Learning semantics.** An :class:`IncidentMemoryLearning` record is a
**derived historical consolidation**, never current evidence and never an
original memory.  It summarises an explicit, reproducible pattern over the
historical record: a recurring memory type, a repeated observed indicator,
technique or mitigation action, a repeated explicit outcome status, or a
repeated source-provenance relationship — together with the supporting
``memory_id`` references, the distinct-memory occurrence count, the first/last
occurrence instants, and a support-count-derived confidence.  The whole record
is pinned to the additive ``Provenance.LEARNED`` value so it can never silently
masquerade as an observed / enriched / reconstructed / detected / correlated /
risk-assessed / ai-generated / attribution-assessed *current* fact, and never
as an original ``RECALLED`` memory.  It is **not** ``InvestigationEvidence``:
the only memory identities it carries are the historical
``supporting_memory_ids`` references.

**Explicitness.** Every fact a learning record carries is derived strictly
from fields that exist in the Step 16/18 incident-memory contract (memory
type, structured indicators/techniques/actions/outcomes/sources).  Nothing is
inferred from prose, and no attacker / IP / domain / malware / technique /
action / outcome / verdict is ever invented here.  Absent fields stay absent:
a memory without an explicit outcome is counted as *missing*, never converted
to a success/failure, and conflicting explicit outcome statuses are preserved
alongside one another (never resolved by majority).

**Safety invariants.** Learning is fail-closed, matching the staged-contract
convention: secret-shaped content is rejected (never redacted), timestamps
must be timezone-aware, confidence is bounded to ``[0.0, 1.0]`` and finite,
metadata is JSON-safe and bounded, every list is bounded, and over-limit
input is **rejected** (never truncated).

**Determinism.** Module state is immutable after construction; there is no
hidden clock (``created_at``, ``first_seen`` and ``last_seen`` are supplied
explicitly and may be injected by the service for deterministic tests) and
no sorting/deduplication mutates list order after construction
(``supporting_memory_ids`` is a strictly-ascending, duplicate-free canonical
list; ``outcome_statuses`` likewise).  Identical inputs produce identical
``model_dump_json()`` output.
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

from app.schemas.incident_memory import (
    _assert_json_compatible,
    _assert_no_secrets,
    _bound_string,
    _json_clone,
)
from app.schemas.security_event import Provenance

# ---------------------------------------------------------------------------
# Bound constants
# ---------------------------------------------------------------------------
# These are hard contract limits, not configuration: values that exceed
# them are REJECTED (never truncated), preserving deterministic, bounded
# output.  Values are chosen conservatively and consistently with the
# existing staged contracts (incident memory / attribution / investigation /
# knowledge).

#: Maximum serialized length of a canonical learning pattern key.
MAX_LEARNING_PATTERN_KEY_LENGTH = 2048

#: Maximum length of a consolidated learning pattern value.  Mirrors the
#: Step 16 label cap so any value that satisfied the memory contract is
#: representable here.
MAX_LEARNING_PATTERN_VALUE_LENGTH = 512

#: Maximum JSON nesting depth of learning metadata.
MAX_LEARNING_METADATA_DEPTH = 8

#: Maximum serialized size (bytes) of learning metadata.
MAX_LEARNING_METADATA_SERIALIZED_BYTES = 4 * 1024

#: Maximum number of ``supporting_memory_ids`` a single learning record may
#: carry.  Oversized support sets are REJECTED, never silently truncated.
MAX_LEARNING_SUPPORTING_MEMORY_REFERENCES = 1000

#: Maximum number of learning records in one consolidation result.
MAX_LEARNING_OUTPUT_RECORDS = 2000


# ---------------------------------------------------------------------------
# Learning type
# ---------------------------------------------------------------------------


class LearningType(str, Enum):
    """Deterministic category of a derived historical consolidation.

    The taxonomy (additive, like every staged SentinelAI taxonomy) names the
    explicit, reproducible pattern the learning layer reads off the existing
    incident-memory contract.  Each value maps to a documented field of the
    Step 16/18 contract:

    * ``recurring_memory_type``     — a memory type repeated across memories.
    * ``recurring_indicator``       — an exact ``(indicator_type, value)``
      pair repeated across memories' ``indicators``.
    * ``recurring_technique``       — an exact ``technique_code`` repeated
      across memories' ``techniques``.
    * ``recurring_action``          — an exact ``action_type`` repeated across
      memories' ``actions``.
    * ``recurring_outcome``         — an exact ``outcome_status`` repeated
      across memories that carry an explicit outcome.
    * ``recurring_source_provenance`` — a source provenance value repeated
      across memories' ``sources``.

    This is consolidation over explicit historical memory, never a
    prediction, never attack attribution, and never a policy/rule/playbook
    change.  Categories the Step 16 contract cannot express (e.g. an event
    category or detection rule identifier, which the memory contract does
    not carry) are deliberately out of scope and are not fabricated here.
    """

    RECURRING_MEMORY_TYPE = "recurring_memory_type"
    RECURRING_INDICATOR = "recurring_indicator"
    RECURRING_TECHNIQUE = "recurring_technique"
    RECURRING_ACTION = "recurring_action"
    RECURRING_OUTCOME = "recurring_outcome"
    RECURRING_SOURCE_PROVENANCE = "recurring_source_provenance"


# ---------------------------------------------------------------------------
# Outcome consolidation
# ---------------------------------------------------------------------------


class LearningOutcomeInfo(BaseModel):
    """Explicit outcome consolidation across a pattern's supporting memories.

    Built strictly from the Step 16 ``MemoryOutcome`` contract as
    persisted/queried: a supporting memory either carries an explicit outcome
    (``outcomes`` non-empty, carrying an ``outcome_status`` string) or does
    not (no outcome).  The Step 16 contract leaves ``outcome_status`` as a
    bounded free string — it is never interpreted as a success/failure
    verdict here.  Explicit statuses are consolidated verbatim and
    **preserved alongside one another** (conflicting statuses are never
    resolved by majority); memories without an outcome stay missing.
    """

    explicit_outcome_count: int = Field(
        ...,
        ge=0,
        description=(
            "Number of supporting memories that carry an explicit outcome "
            "(non-empty Step 16 outcomes payload)."
        ),
    )
    missing_outcome_count: int = Field(
        ...,
        ge=0,
        description=(
            "Number of supporting memories that carry NO explicit outcome "
            "(empty Step 16 outcomes payload).  Missing stays missing: these "
            "memories are never assigned a success/failure."
        ),
    )
    outcome_statuses: list[str] = Field(
        ...,
        description=(
            "Unique explicit Step 16 outcome_status strings found across the "
            "supporting memories, ascending and duplicate-free.  Conflicting "
            "statuses appear side by side, never resolved by majority."
        ),
    )

    @field_validator("outcome_statuses")
    @classmethod
    def _statuses_canonical(cls, v: list[str]) -> list[str]:
        normalized: list[str] = []
        for status in v:
            bounded = _bound_string(
                status, "outcome_status", MAX_LEARNING_PATTERN_VALUE_LENGTH
            )
            if bounded in normalized:
                raise ValueError(
                    "outcome_statuses must not contain duplicates"
                )
            normalized.append(bounded)
        if normalized != sorted(normalized):
            raise ValueError(
                "outcome_statuses must be ascending and duplicate-free"
            )
        return normalized

    @model_validator(mode="after")
    def _presence_coherent(self) -> "LearningOutcomeInfo":
        """Explicitly-present statuses iff at least one explicit outcome."""
        if self.explicit_outcome_count == 0 and self.outcome_statuses:
            raise ValueError(
                "outcome_statuses must be empty when no supporting memory "
                "carries an explicit outcome"
            )
        if self.explicit_outcome_count > 0 and not self.outcome_statuses:
            raise ValueError(
                "outcome_statuses must be non-empty when supporting memories "
                "carry explicit outcomes"
            )
        return self


# ---------------------------------------------------------------------------
# Learning record
# ---------------------------------------------------------------------------


class IncidentMemoryLearning(BaseModel):
    """One deterministic, evidence-grounded historical consolidation.

    Carries exactly the consolidation service produced: a canonical pattern
    key, the exact consolidated value, the bounded ordered list of
    supporting ``memory_id`` references, the distinct-memory occurrence
    count, the first/last occurrence instants, the explicit outcome
    consolidation, the support-count-derived confidence, deterministic
    policy metadata, and ``Provenance.LEARNED`` provenance.

    These records are **not** ``InvestigationEvidence``: the only memory
    identities they carry are historical ``supporting_memory_ids``
    references; there are no ``evidence_id`` / ``evidence_type`` fields and
    no detection / correlation / risk-assessment / attribution identities as
    evidence.
    """

    model_config = {"extra": "ignore"}

    learning_id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        description=(
            "Unique identity of this learning record.  Minted by the "
            "consolidation service (injectable for deterministic tests)."
        ),
    )
    learning_type: LearningType = Field(
        ...,
        description="Deterministic learning category of this consolidation.",
    )
    pattern_key: str = Field(
        ...,
        description=(
            "Canonical, deterministic key identifying the consolidated "
            "pattern within its learning type (see the service policy for "
            "the exact construction)."
        ),
    )
    pattern_value: str = Field(
        ...,
        description=(
            "The exact consolidated value read from the incident-memory "
            "contract (e.g. an indicator value, technique code, action "
            "type, outcome status, memory-type value or source provenance)."
        ),
    )
    supporting_memory_ids: list[uuid.UUID] = Field(
        default_factory=list,
        description=(
            "Historical incident memory references backing this "
            "consolidation, ascending and duplicate-free.  References to "
            "downstream histories, never evidence identifiers."
        ),
    )
    occurrence_count: int = Field(
        ...,
        ge=1,
        description=(
            "Number of distinct supporting memories exhibiting the pattern.  "
            "Always equal to len(supporting_memory_ids)."
        ),
    )
    first_seen: datetime = Field(
        ...,
        description="Earliest created_at instant among the supporting memories (UTC).",
    )
    last_seen: datetime = Field(
        ...,
        description="Latest created_at instant among the supporting memories (UTC).",
    )
    outcome: LearningOutcomeInfo = Field(
        ...,
        description=(
            "Explicit outcome consolidation built from the supporting "
            "memories' Step 16 outcomes (never interpreted or majority-"
            "resolved)."
        ),
    )
    confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "Deterministic support-count-derived confidence in [0.0, 1.0]: "
            "min(1.0, occurrence_count / saturation).  Independent from any "
            "risk / detection / investigation / attribution confidence."
        ),
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Policy-built, deterministic, secret-free record metadata.",
    )
    provenance: Provenance = Field(
        default=Provenance.LEARNED,
        description=(
            "Pinned to LEARNED: a learning record is a derived historical "
            "consolidation, never current telemetry, never original memory, "
            "never evidence."
        ),
    )
    created_at: datetime = Field(
        ...,
        description="When this learning record was derived (UTC, timezone-aware).",
    )

    @field_validator("pattern_key")
    @classmethod
    def _pattern_key_bounded(cls, v: Any) -> str:
        return _bound_string(
            v, "pattern_key", MAX_LEARNING_PATTERN_KEY_LENGTH
        )

    @field_validator("pattern_value")
    @classmethod
    def _pattern_value_bounded(cls, v: Any) -> str:
        return _bound_string(
            v, "pattern_value", MAX_LEARNING_PATTERN_VALUE_LENGTH
        )

    @field_validator("supporting_memory_ids")
    @classmethod
    def _supporting_memory_ids_canonical(
        cls, v: list[uuid.UUID]
    ) -> list[uuid.UUID]:
        if len(v) > MAX_LEARNING_SUPPORTING_MEMORY_REFERENCES:
            raise ValueError(
                "supporting_memory_ids exceed the maximum of "
                f"{MAX_LEARNING_SUPPORTING_MEMORY_REFERENCES} references"
            )
        ids = list(v)
        for index, value in enumerate(ids):
            if isinstance(value, str):
                try:
                    ids[index] = uuid.UUID(value)
                except (TypeError, ValueError) as exc:
                    raise ValueError(
                        "supporting_memory_ids must be valid UUIDs"
                    ) from exc
        if len(set(ids)) != len(ids):
            raise ValueError(
                "supporting_memory_ids must be duplicate-free"
            )
        if ids != sorted(ids):
            raise ValueError(
                "supporting_memory_ids must be ascending"
            )
        return ids

    @field_validator("confidence", mode="before")
    @classmethod
    def _confidence_finite(cls, v: Any) -> Any:
        if isinstance(v, bool):
            raise ValueError("confidence must be a finite floating-point number")
        if isinstance(v, (int, float)) and not isfinite(v):
            raise ValueError("confidence must be finite")
        return v

    @field_validator("first_seen")
    @classmethod
    def _first_seen_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError(
                "first_seen must be timezone-aware; naive (UTC-less) "
                "timestamps are not accepted"
            )
        return v

    @field_validator("last_seen")
    @classmethod
    def _last_seen_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError(
                "last_seen must be timezone-aware; naive (UTC-less) "
                "timestamps are not accepted"
            )
        return v

    @field_validator("created_at")
    @classmethod
    def _created_at_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError(
                "created_at must be timezone-aware; naive (UTC-less) "
                "timestamps are not accepted"
            )
        return v

    @field_validator("metadata")
    @classmethod
    def _metadata_valid(cls, v: Any) -> dict[str, Any]:
        if v is None:
            return {}
        _assert_json_compatible(v, "learning record metadata")
        _assert_no_secrets(v, "learning record metadata")
        if len(json.dumps(v)) > MAX_LEARNING_METADATA_SERIALIZED_BYTES:
            raise ValueError(
                "learning record metadata exceeds the maximum serialized "
                f"size of {MAX_LEARNING_METADATA_SERIALIZED_BYTES} bytes"
            )
        return _json_clone(v)

    @field_validator("provenance")
    @classmethod
    def _ensure_learned_pinned(cls, v: Provenance) -> Provenance:
        """A learning record is derived historical analysis, nothing else."""
        if v is not Provenance.LEARNED:
            raise ValueError(
                "an incident memory learning record is a derived historical "
                "consolidation and must carry LEARNED provenance; it can "
                "never masquerade as current evidence, as original memory, "
                "or as any analytical provenance it is not"
            )
        return v

    @model_validator(mode="after")
    def _consolidation_coherent(self) -> "IncidentMemoryLearning":
        if len(self.supporting_memory_ids) != self.occurrence_count:
            raise ValueError(
                "occurrence_count must equal the number of supporting "
                "memory references"
            )
        if self.last_seen < self.first_seen:
            raise ValueError(
                "last_seen must not precede first_seen"
            )
        expected = (
            self.outcome.explicit_outcome_count
            + self.outcome.missing_outcome_count
        )
        if expected != self.occurrence_count:
            raise ValueError(
                "explicit_outcome_count + missing_outcome_count must equal "
                "the occurrence count"
            )
        return self

    @model_validator(mode="after")
    def _ensure_record_secret_free(self) -> "IncidentMemoryLearning":
        """The whole learning record is secret-screened once more.

        Fail-closed and lock-step with the staged contracts: a secret-shaped
        string anywhere in the serialized record is rejected (never
        redacted), so a learning record can never be created carrying
        credential-shaped content.
        """
        _assert_no_secrets(
            self.model_dump(mode="json"), "incident memory learning record"
        )
        return self


# ---------------------------------------------------------------------------
# Consolidation result envelope
# ---------------------------------------------------------------------------


class IncidentMemoryLearningResult(BaseModel):
    """One deterministic consolidation run over a bounded memory corpus.

    A read-only, in-memory domain result: it is never persisted, exposes no
    API, and is not ``InvestigationEvidence``.  ``memory_count`` is the
    number of persisted memories consolidated (the bounded corpus);
    ``record_count`` equals ``len(records)``.
    """

    model_config = {"extra": "ignore"}

    memory_count: int = Field(
        ...,
        ge=0,
        description="Number of persisted incident memories consolidated.",
    )
    record_count: int = Field(
        ...,
        ge=0,
        description="Number of learning records produced (== len(records)).",
    )
    records: list[IncidentMemoryLearning] = Field(
        default_factory=list,
        description=(
            "Deterministically ordered learning records, grouped by "
            "learning type in enum order and key-sorted within each type."
        ),
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Policy-built run metadata (bounds, formula, thresholds).",
    )
    created_at: datetime = Field(
        ...,
        description="When the consolidation ran (UTC, timezone-aware).",
    )

    @field_validator("records")
    @classmethod
    def _records_bounded(cls, v: list[IncidentMemoryLearning]) -> list[IncidentMemoryLearning]:
        if len(v) > MAX_LEARNING_OUTPUT_RECORDS:
            raise ValueError(
                "learning records exceed the maximum of "
                f"{MAX_LEARNING_OUTPUT_RECORDS}"
            )
        return v

    @field_validator("metadata")
    @classmethod
    def _metadata_valid(cls, v: Any) -> dict[str, Any]:
        if v is None:
            return {}
        _assert_json_compatible(v, "learning result metadata")
        _assert_no_secrets(v, "learning result metadata")
        if len(json.dumps(v)) > MAX_LEARNING_METADATA_SERIALIZED_BYTES:
            raise ValueError(
                "learning result metadata exceeds the maximum serialized "
                f"size of {MAX_LEARNING_METADATA_SERIALIZED_BYTES} bytes"
            )
        return _json_clone(v)

    @field_validator("created_at")
    @classmethod
    def _created_at_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError(
                "created_at must be timezone-aware; naive (UTC-less) "
                "timestamps are not accepted"
            )
        return v

    @model_validator(mode="after")
    def _envelope_coherent(self) -> "IncidentMemoryLearningResult":
        if self.record_count != len(self.records):
            raise ValueError(
                "record_count must equal the number of records"
            )
        _assert_no_secrets(
            self.model_dump(mode="json"), "incident memory learning result"
        )
        return self