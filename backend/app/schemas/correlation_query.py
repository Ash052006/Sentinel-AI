"""Correlation Query Layer read models — Step 10D.

Read-only views over the Step 10C persistence contract
(:class:`~app.models.correlation_result.CorrelationResult`,
:class:`~app.models.correlation_member.CorrelationMember`).  These are
**read models**: they describe *what the correlation query layer returns*,
not what the Step 10A authoring contract holds or what the Step 10B agent
produces.

Design principles:

* **Read models only** — no writes, no persistence code, no API endpoints.
  Consumers build these from persisted rows via the read-only
  :class:`~app.services.correlation_query.CorrelationQueryService`.
* **Persisted view** — a record mirrors a database row: JSONB ``evidence`` /
  ``result_metadata`` come back as plain ``dict`` payloads, ``provenance`` is
  the ``CORRELATED`` marker every persisted row carries, and timestamps are
  timezone-aware UTC instants.  No derived/aggregate fields are invented; the
  Step 10A computed views (``detection_ids``, ``first_seen_at``, ...) are
  engine-side conveniences and are **not** re-emitted here.
* **Members embedded** — ``CorrelationResultRecord.members`` carries the
  correlation's persisted members in ``member_order``; the query service
  bulk-loads them (no N+1).
* **Bounded pagination** — list operations return a 1-based page envelope
  (``items`` + ``total`` + requested ``page``/``page_size``) so callers can
  reconstruct state without an unbounded cursor.
* **No secrets** — the layer only surfaces what the persistence contract
  already stored (evidence/metadata were redacted *before* write).

Relationship to the pipeline::

    CorrelationPersistenceService        (Step 10C, writes)
        -> correlation_results / correlation_members   (Step 10C-A models)
            -> CorrelationQueryService   (Step 10D, read-only)
                -> CorrelationResultRecord / CorrelationMemberRecord
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.correlation import CorrelationStatus
from app.schemas.security_event import Provenance


# ---------------------------------------------------------------------------
# Persisted-view records
# ---------------------------------------------------------------------------


class CorrelationMemberRecord(BaseModel):
    """Read-only view of one persisted ``correlation_members`` row.

    Attributes mirror the Step 10C-A column layout: a lightweight reference
    (``detection_id``, ``event_id``, ``timestamp``) plus its ``member_order``
    position.  ``timestamp`` is the member detection's own evaluation
    timestamp, timezone-aware.
    """

    id: uuid.UUID = Field(
        ...,
        description="Primary-key UUID of the persisted correlation_members row.",
    )
    correlation_id: uuid.UUID = Field(
        ...,
        description="The parent correlation this member belongs to.",
    )
    detection_id: uuid.UUID = Field(
        ...,
        description=(
            "Exact identity of the referenced detection (Step 9A / 10A "
            "detection identity, preserved; never regenerated)."
        ),
    )
    event_id: uuid.UUID = Field(
        ...,
        description=(
            "Exact identity of the source security event for this member "
            "(preserved; never replaced with a correlation/incident/alert id)."
        ),
    )
    timestamp: datetime = Field(
        ...,
        description=(
            "Timezone-aware timestamp of the member detection itself "
            "(descriptive temporal boundary, not correlation evidence)."
        ),
    )
    member_order: int = Field(
        ...,
        ge=0,
        description=(
            "0-based position of this member within its correlation; "
            "preserves the Step 10A members order exactly."
        ),
    )
    created_at: datetime = Field(
        ...,
        description="When the member row was first persisted (UTC, tz-aware).",
    )
    updated_at: datetime = Field(
        ...,
        description="When the member row was last modified (UTC, tz-aware).",
    )


class CorrelationResultRecord(BaseModel):
    """Read-only view of one persisted ``correlation_results`` row.

    Attribute names mirror the Step 10C-A persistence contract columns; the
    structured ``evidence`` and ``result_metadata`` JSONB payloads are exposed
    as plain dictionaries, ``confidence`` is ``0.0..1.0`` or ``None``, and
    ``provenance`` is always ``CORRELATED`` (the DB CHECK constraint
    guarantees it).  ``members`` are embedded in persisted ``member_order``.
    """

    id: uuid.UUID = Field(
        ...,
        description="Primary-key UUID of the persisted correlation_results row.",
    )
    correlation_id: uuid.UUID = Field(
        ...,
        description=(
            "Step 10A CorrelationResult.correlation_id.  Unique identity of "
            "the persisted correlation (the query key)."
        ),
    )
    status: CorrelationStatus = Field(
        ...,
        description=(
            "Neutral lifecycle state (candidate / active / closed); "
            "bookkeeping only, never a verdict."
        ),
    )
    confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "Correlation-level confidence, bounded to [0.0, 1.0], or None "
            "when the engine produced no numeric confidence.  Never an "
            "aggregate of detection confidence and never a risk score."
        ),
    )
    evidence: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured correlation evidence as stored (JSONB).",
    )
    result_metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Safe, non-secret correlation metadata as stored (JSONB).",
    )
    timestamp: datetime = Field(
        ...,
        description=(
            "When the correlation was established (UTC, timezone-aware)."
        ),
    )
    provenance: Provenance = Field(
        default=Provenance.CORRELATED,
        description="Evidence provenance; always CORRELATED for persisted rows.",
    )
    members: list[CorrelationMemberRecord] = Field(
        default_factory=list,
        description=(
            "The correlation's persisted members, in member_order ascending "
            "(duplicates preserved exactly as persisted)."
        ),
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
# Pagination envelope
# ---------------------------------------------------------------------------


class CorrelationPage(BaseModel):
    """One 1-based page of persisted correlations."""

    items: list[CorrelationResultRecord] = Field(
        ...,
        description="The page's correlation records, newest first.",
    )
    total: int = Field(
        ...,
        ge=0,
        description="Total number of persisted correlations matching the query.",
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