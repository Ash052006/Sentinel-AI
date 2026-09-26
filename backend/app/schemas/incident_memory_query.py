"""Incident Memory Query Layer read models — Step 18.

Read-only views over the Step 17 persistence contract
(:class:`~app.models.incident_memory.IncidentMemoryRow`).  These are
**read models**: they describe *what the incident memory query layer
returns*, not what the Step 16 authoring contract holds
(:class:`~app.schemas.incident_memory.IncidentMemory`) or what a future
Step 19 recall/retrieval engine produces.

Design principles:

* **Read models only** — no writes, no persistence code, no API endpoints.
  Consumers build these from persisted rows via the read-only
  :class:`~app.services.incident_memory_query.IncidentMemoryQueryService`.
* **Persisted view** — a record mirrors a database row.  Column names match
  the Step 17 ``incident_memories`` columns (``outcomes`` and
  ``memory_metadata``), *not* the Step 16 envelope field names
  (``outcome`` / ``metadata``).  The bounded, redacted JSONB structured
  columns (``sources`` / ``indicators`` / ``entities`` / ``techniques`` /
  ``findings`` / ``actions`` / ``outcomes`` / ``memory_metadata``) come
  back as plain ``list``/``dict`` payloads exactly as stored — these were
  already redacted and size-bounded *before* write, so the query layer only
  surfaces what the persistence contract stored; it never re-scans them
  (a re-scan would falsely reject the legitimate ``<redacted>`` markers the
  Step 17 write path installed).
* **Types re-validated at the read edge.**  ``memory_type`` and
  ``provenance`` are re-validated through the Step 16
  :class:`~app.schemas.incident_memory.MemoryType` / Step 14
  :class:`~app.schemas.security_event.Provenance` enums so a corrupt raw
  column value surfaces as a controlled query failure — never as an
  unvalidated string.  ``provenance`` is always ``RECALLED`` for persisted
  rows (database CHECK constraint); per-item provenance inside ``sources``
  is preserved verbatim.
* **Deterministic ordering** — every list orders by row ``created_at``
  descending with a stable secondary key (``memory_id`` ascending), so page
  boundaries never drift.
* **Bounded pagination** — list operations return a 1-based page envelope
  (``items`` + ``total`` + requested ``page``/``page_size``) so callers can
  reconstruct state without an unbounded cursor.
* **No secrets** — the layer only surfaces what the persistence contract
  already stored (structured JSONB was redacted/rejected *before* write).

Relationship to the pipeline::

    IncidentMemoryPersistenceService   (Step 17, writes)
        -> incident_memories           (the Step 17 row model)
            -> IncidentMemoryQueryService   (Step 18, read-only)
                -> IncidentMemoryRecord / IncidentMemoryPage
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.incident_memory import MemoryType
from app.schemas.security_event import Provenance


# ---------------------------------------------------------------------------
# Persisted-view record
# ---------------------------------------------------------------------------


class IncidentMemoryRecord(BaseModel):
    """Read-only view of one persisted ``incident_memories`` row.

    Attribute names mirror the Step 17 persistence-contract columns: the
    structured JSONB payloads (``sources`` … ``memory_metadata``) are
    exposed as plain dictionaries/lists exactly as stored, ``memory_type``
    is the Step 16 :class:`MemoryType`, ``provenance`` is always
    ``RECALLED`` (the DB CHECK constraint guarantees it), and timestamps
    are timezone-aware UTC instants.  ``created_at`` / ``updated_at`` are
    the row's own Step 17 bookkeeping instants — NOT the envelope's
    ``created_at``, which is deterministic contract metadata and is not
    re-emitted here.
    """

    id: uuid.UUID = Field(
        ...,
        description="Primary-key UUID of the persisted incident_memories row.",
    )
    memory_id: uuid.UUID = Field(
        ...,
        description=(
            "Step 16 IncidentMemory.memory_id.  Unique identity of the "
            "persisted memory (the query key); re-persists are idempotent."
        ),
    )
    memory_type: MemoryType = Field(
        ...,
        description=(
            "Step 16 MemoryType, re-validated through the enum at the read "
            "edge (stored as its raw string value).  Lifecycle bookkeeping; "
            "never a verdict."
        ),
    )
    title: str = Field(
        ...,
        description="Bounded Step 16 memory title as stored.",
    )
    summary: str = Field(
        ...,
        description=(
            "Bounded Step 16 memory summary as stored (Step 17 persists an "
            "empty string when the envelope carried none)."
        ),
    )
    correlation_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "Step 10A correlation UUID the memory derives from, as stored.  "
            "Plain nullable UUID, deliberately NOT a foreign key; NULL when "
            "the memory is not correlation-derived."
        ),
    )
    sources: list[dict[str, Any]] = Field(
        default_factory=list,
        description=(
            "Structured, redacted IncidentMemory.sources (JSONB) as stored; "
            "each item keeps its verbatim per-source provenance."
        ),
    )
    indicators: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Structured, redacted IncidentMemory.indicators (JSONB) as stored.",
    )
    entities: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Structured, redacted IncidentMemory.entities (JSONB) as stored.",
    )
    techniques: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Structured, redacted IncidentMemory.techniques (JSONB) as stored.",
    )
    findings: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Structured, redacted IncidentMemory.findings (JSONB) as stored.",
    )
    actions: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Structured, redacted IncidentMemory.actions (JSONB) as stored.",
    )
    outcomes: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Structured, redacted IncidentMemory outcome (JSONB) as stored: "
            "an empty dictionary when the envelope carried no outcome, else "
            "the single MemoryOutcome payload."
        ),
    )
    memory_metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured, redacted incident-memory envelope metadata (JSONB) as stored.",
    )
    confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "Step 16 bounded confidence in [0.0, 1.0], or None "
            "(CHECK-constrained).  Bookkeeping only, never a risk score."
        ),
    )
    provenance: Provenance = Field(
        default=Provenance.RECALLED,
        description=(
            "Envelope provenance, re-validated through the enum at the read "
            "edge; always RECALLED for persisted rows (DB CHECK constraint)."
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


class IncidentMemoryPage(BaseModel):
    """One 1-based page of persisted incident memories."""

    items: list[IncidentMemoryRecord] = Field(
        ...,
        description="The page's incident memory records, newest first.",
    )
    total: int = Field(
        ...,
        ge=0,
        description=(
            "Total number of persisted incident memories matching the query "
            "(unaffected by pagination)."
        ),
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