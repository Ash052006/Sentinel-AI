"""Detection-to-Correlation Contract — Step 9I.

Defines the **information boundary** between the completed Detection
subsystem and the future Correlation Agent.

Detection answers *"what individual detection rules matched this
event?"*.  Correlation will eventually answer *"which detections/events
are related to the same possible attack, activity sequence, entity, or
incident?"*.  This module **does not answer the second question** — it
only defines the validated, JSON-compatible representation of a single
detection (or an ordered set of detections) that may be handed to the
future Correlation Agent.

Design principles:

* **Boundary only** — no correlation logic, no temporal/entity grouping,
  no attack-sequence inference, no scoring, no incident creation, no
  database access, no API endpoints, no message bus, no LLM.
* **Derived, not competing** — every field has a real source in the
  existing Step 9A :class:`~app.schemas.detection.DetectionResult`
  authoring contract and/or the Step 9G read model
  :class:`~app.schemas.detection_query.DetectionResultRecord`.  This
  module introduces no new detection model.
* **Traceable** — ``detection_id``, ``event_id``, ``rule_id``,
  ``timestamp``, ``severity``, ``confidence`` and ``provenance`` are
  preserved exactly.  No new identity is generated for an existing
  detection, and the original ``event_id`` is never replaced with a
  correlation/incident/alert identifier.
* **Provenance-preserving** — detection output is analytical/derived
  information.  The contract enforces ``DETECTED`` provenance and never
  converts a detection into observed (or enriched/reconstructed)
  telemetry.
* **Structured transport** — evidence and metadata cross the boundary as
  structured JSON-compatible payloads.  The contract transports them;
  it does **not** decide what they mean.
* **No fabrication** — detection failures and non-matches are **not**
  detections.  The adapter refuses them instead of silently converting
  them into correlation input.
* **Secret-safe** — the same forbidden-pattern validation as the Step 9A
  contract applies at this boundary; credentials, API keys,
  authorization headers, bearer tokens, and JWTs must never cross.
* **Immutable by convention** — the adapter is pure, deterministic and
  side-effect free; it constructs independent representations and never
  mutates a ``DetectionResult`` / ``DetectionResultRecord``, its
  evidence, or its metadata.

Relationship to the pipeline::

    DetectionAgent
        -> DetectionAnalysis
            -> DetectionPersistenceService
                -> PostgreSQL
                    -> DetectionQueryService
                        -> DetectionResultRecord  (read model)
                        -> DetectionCorrelationInput  (this module)
                            -> [future Correlation Agent]
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any, Iterable

from pydantic import BaseModel, Field, field_validator, model_validator

from app.schemas.detection import DetectionResult, DetectionSeverity, RuleType
from app.schemas.detection_query import DetectionResultRecord
from app.schemas.security_event import Provenance


# ---------------------------------------------------------------------------
# Secret-safety helpers (mirror the Step 9A detection contract patterns)
# ---------------------------------------------------------------------------

#: Forbidden credential-shaped strings re-checked at the contract boundary.
#: Kept in lock-step with ``app/schemas/detection.py``.
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
    structured payloads that were already sanitized before persistence, and
    the Step 9A contract already rejects secrets.  This re-check keeps the
    credential-shaped keys from crossing the Detection -> Correlation
    boundary.
    """
    serialized = json.dumps(value).lower()
    for pattern in _SECRET_PATTERNS:
        if pattern in serialized:
            raise ValueError(
                f"{field} must not contain secrets ('{pattern}' detected)"
            )


def _json_clone(value: dict[str, Any]) -> dict[str, Any]:
    """Return an independent, JSON-compatible deep copy of *value*.

    Used by the adapter so the resulting contract shares no mutable state
    with the source detection model: mutating the source evidence/metadata
    after conversion can never leak into the contract, and vice versa.
    Inputs are guaranteed JSON-compatible by their source contracts.
    """
    return json.loads(json.dumps(value))
# ---------------------------------------------------------------------------
# Single-detection contract
# ---------------------------------------------------------------------------


class DetectionCorrelationInput(BaseModel):
    """One detection allowed to cross the Detection -> Correlation boundary.

    This is a **transport** representation of an existing detection: it is
    derived 1:1 from a matched Step 9A
    :class:`~app.schemas.detection.DetectionResult` or the Step 9G read
    model :class:`~app.schemas.detection_query.DetectionResultRecord`.
    The future Correlation Agent consumes these records without any
    knowledge of PostgreSQL, SQLAlchemy, repositories, persistence, or API
    routing.

    Attributes:
        detection_id: Unique identity of the detection (never regenerated).
        event_id: UUID of the originating security event (never replaced
            with a correlation/incident/alert identifier).
        timestamp: Timezone-aware instant of the detection (9A evaluation
            timestamp / persisted ``detected_at``).
        rule_id: Identity of the evaluated rule (traceable to a
            ``DetectionRule`` definition in the registry).
        rule_type: Engine type that produced the detection (``sigma`` /
            ``yara``).
        rule_version: Version of the evaluated rule when known; ``None``
            when the detection carried no version (the ``"unknown"``
            fallback is a persistence-layer convention and is not
            fabricated here).
        severity: Rule-author severity of the finding.
        confidence: Engine confidence in the match, bounded to ``[0.0, 1.0]``.
        evidence: Structured match evidence transported as-is (never
            flattened into free-form text, never reinterpreted).
        metadata: Structured evaluation metadata transported as-is.
        provenance: Always ``DETECTED`` — detection output is an analytical
            conclusion, never observed/enriched/reconstructed telemetry.
    """

    detection_id: uuid.UUID = Field(
        ...,
        description=(
            "Unique identity of the detection (Step 9A detection_id).  "
            "Never regenerated — traceability back to the original "
            "detection requires this exact value."
        ),
    )
    event_id: uuid.UUID = Field(
        ...,
        description=(
            "UUID of the originating security event.  Preserved from the "
            "detection; never replaced with a correlation, incident, or "
            "alert identifier."
        ),
    )
    timestamp: datetime = Field(
        ...,
        description=(
            "Timezone-aware instant of the detection (the 9A evaluation "
            "timestamp, or the persisted detected_at read back through "
            "the Step 9G read model)."
        ),
    )
    rule_id: str = Field(
        ...,
        min_length=1,
        description=(
            "Identity of the evaluated rule.  Traceable to a DetectionRule "
            "definition in the rule registry."
        ),
    )
    rule_type: RuleType = Field(
        ...,
        description="Engine type that produced the detection (sigma/yara).",
    )
    rule_version: str | None = Field(
        default=None,
        description=(
            "Version of the evaluated rule when the detection carried one; "
            "None when absent."
        ),
    )
    severity: DetectionSeverity = Field(
        ...,
        description="Rule-author severity of the finding (not a risk score).",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Engine confidence in the match, bounded to [0.0, 1.0].",
    )
    evidence: dict[str, Any] = Field(
        ...,
        description=(
            "Structured match evidence transported as-is (the 9A "
            "DetectionEvidence sections, or the persisted JSONB read back "
            "through the read model).  Never flattened into free-form text."
        ),
    )
    metadata: dict[str, Any] = Field(
        ...,
        description=(
            "Structured evaluation metadata transported as-is (the 9A "
            "DetectionMetadata fields, or the persisted result_metadata "
            "JSONB)."
        ),
    )
    provenance: Provenance = Field(
        default=Provenance.DETECTED,
        description=(
            "Analytical provenance of the detection output.  Always "
            "DETECTED — a detection is never observed telemetry."
        ),
    )
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

    @field_validator("provenance")
    @classmethod
    def _ensure_detected_provenance(cls, v: Provenance) -> Provenance:
        """Enforce ``DETECTED`` provenance at the boundary.

        Detection output is derived/analytical information.  All real
        sources (9A default, Step 9F CHECK-constrained persistence, Step 9G
        read model) already carry ``DETECTED``; this re-check guarantees a
        detection is never relabelled as observed/enriched/reconstructed
        telemetry when crossing into correlation.
        """
        if v != Provenance.DETECTED:
            raise ValueError(
                "detection-to-correlation input provenance must be "
                "DETECTED; detection evidence is an analytical conclusion, "
                "never observed/enriched/reconstructed telemetry"
            )
        return v

    @field_validator("evidence")
    @classmethod
    def _ensure_evidence_valid(cls, v: dict[str, Any]) -> dict[str, Any]:
        """Evidence must be JSON-compatible and secret-free."""
        _assert_json_compatible(v, "evidence")
        _assert_no_secrets(v, "evidence")
        return v

    @field_validator("metadata")
    @classmethod
    def _ensure_metadata_valid(cls, v: dict[str, Any]) -> dict[str, Any]:
        """Metadata must be JSON-compatible and secret-free."""
        _assert_json_compatible(v, "metadata")
        _assert_no_secrets(v, "metadata")
        return v
# ---------------------------------------------------------------------------
# Batch transport contract
# ---------------------------------------------------------------------------


class DetectionCorrelationBatchMetadata(BaseModel):
    """Transport bookkeeping for a :class:`DetectionCorrelationBatch`.

    The batch is a **transport envelope only**.  This metadata carries the
    count of transported detections so a consumer can verify a payload was
    not silently truncated; it contains no timestamps, groupings, or
    scores.  In particular there is no ordering field — chronological
    ordering of detections is **not** attack-sequence correlation, and the
    contract deliberately encodes no such assumption.
    """

    record_count: int = Field(
        ...,
        ge=0,
        description=(
            "Number of detections transported in the batch.  Must equal "
            "the length of the detections list."
        ),
    )


class DetectionCorrelationBatch(BaseModel):
    """An ordered set of detections transported to the future Correlation
    Agent.

    The batch **only** transports detection records:

    * it does not group detections,
    * it does not sort them into an attack sequence,
    * it does not calculate relationships,
    * it does not assign correlation/incident identifiers,
    * it does not create incidents.

    The ``detections`` list order is preserved exactly as provided (the
    adapter never reorders); if the caller supplies a deterministically
    ordered source (such as a Step 9G ``DetectionResultPage``), the batch
    inherits that deterministic order.  Duplicate ``detection_id`` values
    are transported as-is — the contract never silently deduplicates.
    """

    detections: list[DetectionCorrelationInput] = Field(
        ...,
        description=(
            "The transported detections, in the caller-provided order.  "
            "Order is transport order only — it implies no relationship "
            "between detections."
        ),
    )
    metadata: DetectionCorrelationBatchMetadata = Field(
        ...,
        description="Transport bookkeeping (record count).",
    )

    # -- Validators ----------------------------------------------------------

    @model_validator(mode="after")
    def _ensure_record_count_consistent(self) -> "DetectionCorrelationBatch":
        """The batch transport bookkeeping must agree with its payload."""
        if self.metadata.record_count != len(self.detections):
            raise ValueError(
                "batch metadata record_count="
                f"{self.metadata.record_count} does not match the number of "
                f"transported detections ({len(self.detections)})"
            )
        return self

# ---------------------------------------------------------------------------
# Pure adapters (contract definition of the boundary)
# ---------------------------------------------------------------------------


def to_correlation_input(
    result: DetectionResult | DetectionResultRecord,
) -> DetectionCorrelationInput:
    """Map one detection into a :class:`DetectionCorrelationInput`.

    This is a **pure transformation**: deterministic, side-effect free,
    and non-mutating.  It never reads from a database, never calls a
    repository/persistence service, and never performs correlation.

    Accepted inputs:

    * a matched Step 9A :class:`~app.schemas.detection.DetectionResult`
      (``matched=True``);
    * a Step 9G read model
      :class:`~app.schemas.detection_query.DetectionResultRecord`
      (persisted rows are always matches).

    Rejected inputs:

    * ``DetectionFailure`` / rule failures — failures are **not**
      detections; passing one raises :class:`TypeError`.
    * :class:`~app.schemas.detection_agent.DetectionAnalysis` — an
      analysis is a container; convert its ``results`` instead.
    * A ``DetectionResult`` with ``matched=False`` — a non-match is not a
      detection; raises :class:`ValueError`.

    Raises:
        TypeError: if *result* is neither a ``DetectionResult`` nor a
            ``DetectionResultRecord``.
        ValueError: if *result* is a non-match, or if the resulting input
            violates the contract (e.g. non-DETECTED provenance, secrets in
            evidence/metadata).
    """
    if isinstance(result, DetectionResultRecord):
        if not result.matched:
            raise ValueError(
                f"detection '{result.detection_id}' has matched=False; "
                "only matched detections cross the detection-to-correlation "
                "boundary"
            )
        return DetectionCorrelationInput(
            detection_id=result.detection_id,
            event_id=result.event_id,
            timestamp=result.detected_at,
            rule_id=result.rule_id,
            rule_type=result.rule_type,
            rule_version=result.rule_version,
            severity=result.severity,
            confidence=result.confidence,
            evidence=_json_clone(result.evidence),
            metadata=_json_clone(result.result_metadata),
            provenance=result.provenance,
        )
    if isinstance(result, DetectionResult):
        if not result.matched:
            raise ValueError(
                f"detection '{result.detection_id}' has matched=False; "
                "only matched detections cross the detection-to-correlation "
                "boundary"
            )
        return DetectionCorrelationInput(
            detection_id=result.detection_id,
            event_id=result.event_id,
            timestamp=result.timestamp,
            rule_id=result.rule_id,
            rule_type=result.rule_type,
            rule_version=result.metadata.rule_version,
            severity=result.severity,
            confidence=result.confidence,
            evidence=_json_clone(result.evidence.model_dump()),
            metadata=_json_clone(result.metadata.model_dump()),
            provenance=result.provenance,
        )
    raise TypeError(
        "to_correlation_input accepts only a matched DetectionResult or a "
        "DetectionResultRecord; received "
        f"{type(result).__module__}.{type(result).__qualname__}"
    )


def to_correlation_batch(
    results: Iterable[DetectionResult | DetectionResultRecord],
) -> DetectionCorrelationBatch:
    """Map an ordered sequence of detections into a batch envelope.

    Pure, deterministic, and non-mutating like :func:`to_correlation_input`.
    The resulting batch:

    * preserves the caller's input order (the adapter never reorders);
    * transports every detection it was given — duplicates are **not**
      removed and nothing is silently dropped;
    * performs no grouping, scoring, or correlation.

    Raises:
        TypeError: if any element is neither a ``DetectionResult`` nor a
            ``DetectionResultRecord``.
        ValueError: if any element is a non-match, or if a converted input
            violates the contract.
    """
    detections = [to_correlation_input(result) for result in results]
    return DetectionCorrelationBatch(
        detections=detections,
        metadata=DetectionCorrelationBatchMetadata(record_count=len(detections)),
    )