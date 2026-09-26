"""Correlation Domain Contract — Step 10A.

Defines the foundational **domain contract** for the future Correlation
subsystem: the validated Pydantic representation of a single correlation
result and its membership references.

Detection answers *"what individual detection rules matched this
event?"*.  Correlation will eventually answer *"which detections/events are
related to the same security activity, attack sequence, entity, or
incident?"*.  This module defines the objects a future correlation engine
will produce and consume.  It **does not answer the second question** — it
contains no correlation algorithm, no grouping, and no relationship
inference.

Design principles:

* **Contract only** — no correlation agent, no correlation algorithm, no
  time windows, no IP/user/process matching, no attack-chain detection,
  no risk scoring, no incidents, no data model for MITRE ATT&CK, no
  database, no API, no message bus, no LLM.  A future Correlation Agent
  will consume the Step 9I ``DetectionCorrelationBatch`` and produce
  ``CorrelationResult`` objects shaped by this contract.
* **Algorithm-neutral** — the model never hardcodes what makes detections
  correlate.  Membership and evidence are the future engine's decisions;
  the contract only validates and preserves them.
* **Referencing, not duplicating** — a correlation references detections
  by ``detection_id`` (and their source events by ``event_id``).  It never
  stores whole detection records; the detection subsystem remains the
  source of truth.
* **Traceable** — ``correlation_id -> members[] -> detection_id /
  event_id``.  No source identity is regenerated, replaced, or silently
  deduplicated.
* **Provenance-aware** — correlation output is a derived analytical
  conclusion and carries ``Provenance.CORRELATED`` (an additive member of
  the existing global ``Provenance`` enum).  It is never labelled
  observed / enriched / reconstructed / detected.
* **Structured & secret-safe** — evidence and metadata are strict
  JSON-compatible payloads that reject credential-shaped content.
* **Deterministic** — the contract and its adapter never generate
  membership, never reorder input, and never mutate their inputs.

Relationship to the pipeline::

    DetectionCorrelationInput[]          (Step 9I)
        -> DetectionCorrelationBatch     (Step 9I)
            -> [future Correlation Engine]
                -> CorrelationResult     (Step 10A — this module)
                    -> [future Correlation Persistence / API]

The final architecture after 10A remains::

    DetectionCorrelationInput
        -> DetectionCorrelationBatch
        -> 10A Correlation Domain Contract
        -> [Future Correlation Agent]
        -> [Future Correlation Persistence]
        -> [Future Correlation API]
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Iterable

from pydantic import BaseModel, Field, field_validator

from app.schemas.detection_correlation import DetectionCorrelationInput
from app.schemas.security_event import Provenance


# ---------------------------------------------------------------------------
# Secret-safety helpers (mirror the Step 9A / 9I detection contract patterns)
# ---------------------------------------------------------------------------

#: Forbidden credential-shaped strings re-checked at the correlation
#: boundary.  Kept in lock-step with ``app/schemas/detection.py``.
_SECRET_PATTERNS = ("api_key", "authorization", "bearer", "secret")


def _assert_json_compatible(value: Any, field: str) -> None:
    """Raise ValueError when *value* is not strictly JSON-serializable."""
    try:
        json.dumps(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"{field} must be JSON-compatible: {exc}"
        ) from exc


def _assert_no_secrets(value: Any, field: str) -> None:
    """Raise ValueError when *value* contains common secret patterns.

    Defence-in-depth: the primary protection is that evidence/metadata are
    structured payloads.  This re-check keeps credential-shaped keys
    (API keys, authorization headers, bearer tokens, JWTs) out of the
    correlation contract.
    """
    serialized = json.dumps(value).lower()
    for pattern in _SECRET_PATTERNS:
        if pattern in serialized:
            raise ValueError(
                f"{field} must not contain secrets ('{pattern}' detected)"
            )


# ---------------------------------------------------------------------------
# Correlation status
# ---------------------------------------------------------------------------


class CorrelationStatus(str, Enum):
    """Lifecycle state of a correlation result.

    The values are deliberately **neutral bookkeeping**:

    * ``candidate`` — the correlation has been proposed but is not yet
      formally tracked or resolved.  ``CANDIDATE`` is the initial state
      of a new correlation; it asserts nothing about whether the
      correlated activity is malicious.
    * ``active`` — the correlation is currently tracked; its lifecycle is
      still open.
    * ``closed`` — the correlation's lifecycle has ended.  ``CLOSED`` is
      record-keeping only and carries no verdict.

    No value asserts a verdict about the underlying activity, and no value
    implies that confirmation/rejection logic exists yet.  Verdicts
    (``malicious``, ``benign``, ``true_positive``, ``false_positive``) are
    intentionally excluded — they belong to downstream judgment layers.
    """

    CANDIDATE = "candidate"
    ACTIVE = "active"
    CLOSED = "closed"
# ---------------------------------------------------------------------------
# Correlation membership
# ---------------------------------------------------------------------------


class CorrelationMember(BaseModel):
    """A reference to one detection belonging to a correlation.

    A member is a **reference**, never a copy of the detection record:

    * ``detection_id`` preserves the Step 9A ``DetectionResult`` / Step 9I
      ``DetectionCorrelationInput`` detection identity exactly.
    * ``event_id`` preserves the originating ``SecurityEvent`` identity.
    * ``timestamp`` is the member detection's own evaluation timestamp and
      provides a descriptive temporal boundary of that detection.  It does
      **not** imply that temporal proximity establishes correlation.

    Duplicate ``detection_id`` / ``event_id`` values across members are
    allowed and preserved as-is: membership and uniqueness are decisions
    of the future correlation engine, and this contract never silently
    deduplicates or reorders its input.
    """

    detection_id: uuid.UUID = Field(
        ...,
        description=(
            "Exact identity of the detection in this correlation.  "
            "Preserved from the detection subsystem; never regenerated."
        ),
    )
    event_id: uuid.UUID = Field(
        ...,
        description=(
            "Exact identity of the source security event for this "
            "detection.  Preserved; never replaced with a correlation/"
            "incident/alert identifier."
        ),
    )
    timestamp: datetime = Field(
        ...,
        description=(
            "Timezone-aware timestamp of the member detection itself.  "
            "A descriptive temporal boundary, not correlation evidence."
        ),
    )

    @field_validator("timestamp")
    @classmethod
    def _ensure_timezone_aware(cls, v: datetime) -> datetime:
        """Reject naive (timezone-unaware) timestamps."""
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError(
                "timestamp must be timezone-aware; "
                "naive (UTC-less) timestamps are not accepted"
            )
        return v
# ---------------------------------------------------------------------------
# Correlation result
# ---------------------------------------------------------------------------


class CorrelationResult(BaseModel):
    """A single validated correlation result.

    ``CorrelationResult`` represents *one* correlation: a stable identity
    (``correlation_id``), a set of detection memberships, a lifecycle
    status, an optional correlation-level confidence, structured evidence
    and metadata, and ``CORRELATED`` provenance.

    It expresses **no algorithm**: it does not say how members were
    chosen, whether two detections "match", what time window applies, or
    anything about the future engine.  It only validates and preserves the
    shape of an engine-produced result.

    Computed views (derived, never stored):

    * ``detection_ids`` — the exact detection references, in member order,
      duplicates preserved.
    * ``event_ids`` — the exact event references, in member order,
      duplicates preserved.
    * ``first_seen_at`` / ``last_seen_at`` — descriptive temporal
      boundaries derived from member timestamps.  They summarise the
      correlated detections; they never prove correlation.
    """

    correlation_id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        description=(
            "Stable identity of this correlation.  Distinct from "
            "detection_id, event_id, and incident_id.  Auto-generated "
            "when not supplied; generating the identity is identity "
            "generation, not correlation logic."
        ),
    )
    members: list[CorrelationMember] = Field(
        ...,
        min_length=1,
        description=(
            "Detections belonging to this correlation, in the order "
            "supplied by the (future) correlation engine.  A valid "
            "completed correlation references at least one detection.  "
            "Duplicate detection/event references are preserved exactly."
        ),
    )
    status: CorrelationStatus = Field(
        default=CorrelationStatus.CANDIDATE,
        description=(
            "Neutral lifecycle state of the correlation (candidate / "
            "active / closed).  Bookkeeping only; never a verdict."
        ),
    )
    confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "Correlation-level confidence in the correlation itself, "
            "bounded to [0.0, 1.0].  A different concept from the "
            "confidence of any member detection: it is never an "
            "aggregate or reinterpretation of detection confidence, and "
            "it is not a risk score.  Absent when the engine produced no "
            "numeric confidence."
        ),
    )
    evidence: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Structured JSON-compatible information supporting the "
            "correlation.  This contract defines no evidence semantics; "
            "the future engine decides what evidence means.  Must never "
            "contain secrets."
        ),
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Open-ended JSON-compatible metadata about the correlation.  "
            "Must not encode future-layer decisions and must never "
            "contain secrets."
        ),
    )
    timestamp: datetime = Field(
        ...,
        description=(
            "Timezone-aware instant at which the correlation was "
            "established.  Descriptive bookkeeping, not evidence."
        ),
    )
    provenance: Provenance = Field(
        default=Provenance.CORRELATED,
        description=(
            "Provenance marker.  Correlations are derived analytical "
            "conclusions and are always CORRELATED; they are never "
            "observed / enriched / reconstructed / detected telemetry."
        ),
    )
# -- Computed views ------------------------------------------------------

    @property
    def detection_ids(self) -> tuple[uuid.UUID, ...]:
        """Exact detection references, in member order, duplicates kept."""
        return tuple(member.detection_id for member in self.members)

    @property
    def event_ids(self) -> tuple[uuid.UUID, ...]:
        """Exact event references, in member order, duplicates kept."""
        return tuple(member.event_id for member in self.members)

    @property
    def first_seen_at(self) -> datetime:
        """Earliest member detection timestamp (descriptive boundary)."""
        return min(member.timestamp for member in self.members)

    @property
    def last_seen_at(self) -> datetime:
        """Latest member detection timestamp (descriptive boundary)."""
        return max(member.timestamp for member in self.members)

    # -- Validators ----------------------------------------------------------

    @field_validator("timestamp")
    @classmethod
    def _ensure_timezone_aware(cls, v: datetime) -> datetime:
        """Reject naive (timezone-unaware) timestamps."""
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError(
                "timestamp must be timezone-aware; "
                "naive (UTC-less) timestamps are not accepted"
            )
        return v

    @field_validator("evidence")
    @classmethod
    def _ensure_evidence_valid(
        cls, v: dict[str, Any]
    ) -> dict[str, Any]:
        """Evidence must be JSON-compatible, secret-free, and independent.

        The validator also returns a fresh JSON round-trip clone so a
        ``CorrelationResult`` never shares mutable state with the caller's
        payload (nested independence), regardless of how it was built.
        """
        _assert_json_compatible(v, "evidence")
        _assert_no_secrets(v, "evidence")
        return json.loads(json.dumps(v))

    @field_validator("metadata")
    @classmethod
    def _ensure_metadata_valid(
        cls, v: dict[str, Any]
    ) -> dict[str, Any]:
        """Metadata must be JSON-compatible, secret-free, and independent."""
        _assert_json_compatible(v, "metadata")
        _assert_no_secrets(v, "metadata")
        return json.loads(json.dumps(v))

    @field_validator("provenance")
    @classmethod
    def _ensure_correlated_provenance(cls, v: Provenance) -> Provenance:
        """A correlation result is always a derived analytical conclusion.

        Mirroring the Step 9I boundary (which enforces ``DETECTED`` for
        detection transport), the correlation contract enforces
        ``CORRELATED``: a correlation is never observed, enriched,
        reconstructed, or a detection.
        """
        if v is not Provenance.CORRELATED:
            raise ValueError(
                "correlation results are derived analytical conclusions "
                "and must carry CORRELATED provenance; got "
                f"{v.value!r}"
            )
        return v


# ---------------------------------------------------------------------------
# Pure adapter (contract definition of the boundary)
# ---------------------------------------------------------------------------


def to_correlation_members(
    inputs: Iterable[DetectionCorrelationInput],
) -> list[CorrelationMember]:
    """Mechanically harvest member references from caller-selected 9I inputs.

    This is a **pure transformation**: deterministic, side-effect free,
    and non-mutating.  It never reads a database, never touches a
    repository/persistence service, and never performs correlation.

    Membership is decided entirely by the **caller**: the caller chooses
    *which* :class:`~app.schemas.detection_correlation.DetectionCorrelationInput`
    records to pass.  This function only extracts the reference fields
    (``detection_id``, ``event_id``, ``timestamp``); it never groups
    detections, never compares event/IP/user/process values, never applies
    a time window, never deduplicates, and never reorders.

    Raises:
        TypeError: if any element is not a ``DetectionCorrelationInput``.
    """
    members: list[CorrelationMember] = []
    for item in inputs:
        if not isinstance(item, DetectionCorrelationInput):
            raise TypeError(
                "to_correlation_members accepts only "
                "DetectionCorrelationInput records; received "
                f"{type(item).__module__}.{type(item).__qualname__}"
            )
        members.append(
            CorrelationMember(
                detection_id=item.detection_id,
                event_id=item.event_id,
                timestamp=item.timestamp,
            )
        )
    return members