"""Detection Query Layer read models — Step 9G.

Read-only views over the Step 9F persistence contract
(:class:`~app.models.detection_result.DetectionResult`,
:class:`~app.models.detection_rule_failure.DetectionRuleFailure`).
These are **read models**: they describe *what the query layer returns*, not
what agents author (Step 9A/9E contracts live in :mod:`app.schemas.detection`
and :mod:`app.schemas.detection_agent`).

Design principles:

* **Read models only** — no writes, no persistence code, no API endpoints.
  Consumers build these from persisted rows via the read-only
  :class:`~app.services.detection_query.DetectionQueryService`.
* **Persisted view** — a record mirrors a database row: JSONB ``evidence`` /
  ``result_metadata`` come back as plain ``dict`` payloads, ``provenance`` is
  the ``DETECTED`` marker every persisted row carries, and timestamps are
  timezone-aware UTC instants.
* **Bounded pagination** — list operations return a 1-based page envelope
  (``items`` + ``total`` + requested ``page``/``page_size``) so callers can
  reconstruct state without an unbounded cursor.
* **Analysis is event-scoped** — detection persistence has no separate
  analysis table; an "analysis" is the set of ``detection_results`` and
  ``detection_rule_failures`` rows recorded for one ``event_id`` (see the
  Step 9F-A mapping).  ``DetectionAnalysisSummary`` is the cheap aggregate
  view; ``DetectionAnalysisRecord`` adds the full child records.
* **No secrets** — the layer never fabricates data and only surfaces what
  the persistence contract already stored (evidence/metadata were sanitized
  before write).

Relationship to the pipeline::

    DetectionPersistenceService              (Step 9F-B, writes)
        -> detection_results / detection_rule_failures   (Step 9F-A models)
            -> DetectionQueryService         (Step 9G, read-only)
                -> DetectionResultRecord / DetectionFailureRecord
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.detection import DetectionSeverity, RuleType
from app.schemas.security_event import Provenance


# ---------------------------------------------------------------------------
# Persisted-view records
# ---------------------------------------------------------------------------


class DetectionResultRecord(BaseModel):
    """Read-only view of one persisted ``detection_results`` row.

    Attribute names mirror the Step 9F-A persistence contract columns; the
    structured ``evidence`` and ``result_metadata`` JSONB payloads are exposed
    as plain dictionaries.  ``provenance`` is always ``DETECTED`` (the DB
    CHECK constraint guarantees it).
    """

    id: uuid.UUID = Field(
        ...,
        description="Primary-key UUID of the persisted detection_results row.",
    )
    event_id: uuid.UUID = Field(
        ...,
        description="UUID of the originating security event (event-scoped query key).",
    )
    detection_id: uuid.UUID = Field(
        ...,
        description=(
            "Step 9A DetectionResult.detection_id.  Unique identity of the "
            "persisted detection match."
        ),
    )
    rule_id: str = Field(
        ...,
        description="Identity of the evaluated rule.",
    )
    rule_type: RuleType = Field(
        ...,
        description="Engine type that produced the result (sigma/yara).",
    )
    rule_version: str = Field(
        ...,
        description="Version of the evaluated rule ('unknown' when absent).",
    )
    severity: DetectionSeverity = Field(
        ...,
        description="Rule-author severity of the finding.",
    )
    matched: bool = Field(
        ...,
        description="Always true; non-matches are not persisted.",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Engine confidence, bounded to [0.0, 1.0].",
    )
    evidence: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured match evidence as stored (JSONB).",
    )
    result_metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Safe, non-secret evaluation metadata as stored (JSONB).",
    )
    detected_at: datetime = Field(
        ...,
        description="When the match was detected (UTC, timezone-aware).",
    )
    provenance: Provenance = Field(
        default=Provenance.DETECTED,
        description="Evidence provenance; always DETECTED for persisted rows.",
    )
    created_at: datetime = Field(
        ...,
        description="When the row was first persisted (UTC, timezone-aware).",
    )
    updated_at: datetime = Field(
        ...,
        description="When the row was last modified (UTC, timezone-aware).",
    )


class DetectionFailureRecord(BaseModel):
    """Read-only view of one persisted ``detection_rule_failures`` row."""

    id: uuid.UUID = Field(
        ...,
        description="Primary-key UUID of the persisted failure row.",
    )
    event_id: uuid.UUID = Field(
        ...,
        description="UUID of the originating security event.",
    )
    engine: str = Field(
        ...,
        description='Engine that produced the failure ("sigma" / "yara").',
    )
    rule_id: str = Field(
        ...,
        description="Failed rule ID, or the '<engine>' sentinel for engine-level failures.",
    )
    error_type: str = Field(
        ...,
        description="Machine-readable failure category (e.g. malformed_rule).",
    )
    error_message: str = Field(
        ...,
        description="Secret-safe, bounded human-readable failure text.",
    )
    failed_at: datetime = Field(
        ...,
        description="When the failure was recorded (UTC, timezone-aware).",
    )
    provenance: Provenance = Field(
        default=Provenance.DETECTED,
        description="Evidence provenance; always DETECTED for persisted rows.",
    )
    created_at: datetime = Field(
        ...,
        description="When the row was first persisted (UTC, timezone-aware).",
    )
    updated_at: datetime = Field(
        ...,
        description="When the row was last modified (UTC, timezone-aware).",
    )


# ---------------------------------------------------------------------------
# Event-scoped analysis views
# ---------------------------------------------------------------------------


class DetectionAnalysisSummary(BaseModel):
    """Cheap aggregate view of one event's detection analysis.

    Computed from two aggregate queries (results and failures) — no child
    rows are loaded.  ``first_*``/``last_*`` time windows are ``None`` when
    the corresponding table has no row for the event.
    """

    event_id: uuid.UUID = Field(
        ...,
        description="UUID of the evaluated event; identifies the analysis.",
    )
    result_count: int = Field(
        ...,
        ge=0,
        description="Number of persisted detection matches for the event.",
    )
    failure_count: int = Field(
        ...,
        ge=0,
        description="Number of persisted rule/engine failures for the event.",
    )
    first_detected_at: datetime | None = Field(
        default=None,
        description="Earliest detected_at across the event's matches, if any.",
    )
    last_detected_at: datetime | None = Field(
        default=None,
        description="Latest detected_at across the event's matches, if any.",
    )
    first_failed_at: datetime | None = Field(
        default=None,
        description="Earliest failed_at across the event's failures, if any.",
    )
    last_failed_at: datetime | None = Field(
        default=None,
        description="Latest failed_at across the event's failures, if any.",
    )
    provenance: Provenance = Field(
        default=Provenance.DETECTED,
        description=(
            "Provenance of the analysis evidence; always DETECTED (enforced "
            "by the persistence CHECK constraints)."
        ),
    )


class DetectionAnalysisRecord(DetectionAnalysisSummary):
    """Full read view of one event's analysis, including child records.

    The children are loaded with two bulk queries (all results, all
    failures) and composed — never one query per child (no N+1).
    """

    results: list[DetectionResultRecord] = Field(
        default_factory=list,
        description="Every persisted match for the event, newest first.",
    )
    failures: list[DetectionFailureRecord] = Field(
        default_factory=list,
        description="Every persisted failure for the event, newest first.",
    )


# ---------------------------------------------------------------------------
# Pagination envelopes
# ---------------------------------------------------------------------------


class DetectionResultPage(BaseModel):
    """One 1-based page of persisted detection results."""

    items: list[DetectionResultRecord] = Field(
        ...,
        description="The page's result records, newest first.",
    )
    total: int = Field(
        ...,
        ge=0,
        description="Total number of persisted results matching the query.",
    )
    page: int = Field(
        ...,
        ge=1,
        description="Requested 1-based page number.",
    )
    page_size: int = Field(
        ...,
        ge=1,
        description="Requested maximum number of items per page.",
    )


class DetectionFailurePage(BaseModel):
    """One 1-based page of persisted detection failures."""

    items: list[DetectionFailureRecord] = Field(
        ...,
        description="The page's failure records, newest first.",
    )
    total: int = Field(
        ...,
        ge=0,
        description="Total number of persisted failures matching the query.",
    )
    page: int = Field(
        ...,
        ge=1,
        description="Requested 1-based page number.",
    )
    page_size: int = Field(
        ...,
        ge=1,
        description="Requested maximum number of items per page.",
    )