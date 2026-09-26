"""Incident Memory persistence model (Step 17).

This is the **persistence contract** for a single Step 16
:class:`~app.schemas.incident_memory.IncidentMemory` envelope produced by
the Step 16 extractor.

Design intent
-------------
* ``memory_id`` (the Step 16 ``IncidentMemory.memory_id``) is unique and is
  the **idempotency identity**: re-persisting the same memory is a no-op,
  while a later re-extraction that produces a fresh UUID is a new,
  legitimate historical row.
* The body of the memory — its ``sources``, ``indicators``, ``entities``,
  ``techniques``, ``findings``, ``actions``, ``outcomes`` and envelope
  ``metadata`` — is stored as **bounded, redacted JSONB** so a persisted
  memory reconstructs the *complete* validated Step 16 object exactly
  (provenance included).  JSONB is used deliberately: these are structured
  nested objects that Step 16 already validated; flattening them into
  arbitrary columns would degrade fidelity, not improve it.
* **Envelope provenance is constrained by a database CHECK constraint to
  the ``recalled`` value** so incident memory can **never** be persisted as
  observed/enriched/detected/… — Step 16 honouring Step 16's provenance
  rule that historical memory must remain identifiable as historical and
  never masquerade as current evidence.
* Each nested *source* inside ``sources`` JSONB keeps **its own original
  provenance** (``OBSERVED``/``ENRICHED``/…).  The envelope constrains the
  memory-level provenance; source-level provenance is preserved verbatim,
  never rewritten — so a recalled memory cannot silently promote a source
  to ``OBSERVED``.
* **``correlation_id`` is deliberately persisted as a domain-level UUID and
  NOT as a foreign key.**  Rationale (Step 17 FK decision): incident
  memory is a *historical, recall-derived* record whose memory-level
  ``correlation_id`` is bookkeeping identifying which Step 10A correlation
  the memory was extracted from.  The correlation may later be closed or
  removed; deleting historical memory because its correlation was deleted
  would corrupt recall.  A CHECK/ride FK would couple a historical recall
  record to a mutable analytical lifecycle that it must outlive.  The UUID
  is therefore stored as a plain nullable column with a deterministic
  index, and any correlation linkage is asserted in the persistence
  service, not the database.
* **Secret safety is preserved at the boundary.**  This table stores no
  credential-shaped keys or values: Step 17's persistence service redacts
  the structured JSONB before it is bound into the row, and an explicit
  validation rejects — never silently redacts — secret-shaped input (the
  same leak-free policy enforced by Step 16's contract).  The DB receives
  only already-redacted, non-secret structured payloads.
* ``created_at`` / ``updated_at`` are UTC, timezone-aware, descriptive
  bookkeeping (UUIDTimestampMixin), never evidence and never a verdict.

``title``/``summary`` are bounded by the same Step 16 char caps
(``MAX_MEMORY_TITLE_CHARS`` / ``MAX_MEMORY_SUMMARY_CHARS``); confidence,
when present, is CHECK-constrained to ``[0.0, 1.0]`` (a Step 16 bounded
bookkeeping value, never a risk score).
"""

from __future__ import annotations

import uuid

from sqlalchemy import CheckConstraint, DateTime, Float, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.postgres.base import Base, UUIDTimestampMixin
from app.schemas.incident_memory import MemoryType


def _memory_type_values(enum_class) -> list[str]:
    """Return the raw string values of :class:`MemoryType`."""
    return [member.value for member in enum_class]


class IncidentMemoryRow(UUIDTimestampMixin, Base):
    """A single persisted incident memory.

    Attributes:
        memory_id: Step 16 ``IncidentMemory.memory_id``.  Unique — the
            idempotency identity of persisted memory.
        memory_type: Step 16 ``MemoryType`` (bounded 5-value enum).  Stored
            as a String enum (``native_enum=False``) so the value survives
            any PostgreSQL enum-renaming step without a migration and no
            analysis layer depends on DB enum object identity.
        title: Bounded Step 16 memory title (CHECK-constrained length).
        summary: Bounded Step 16 memory summary (CHECK-constrained length).
        correlation_id: Domain-level UUID of the Step 10A correlation the
            memory derives from.  Deliberately **not** an FK (see class
            docstring / Step 17 FK decision).
        sources: Bounded, redacted, structured JSONB of
            ``IncidentMemory.sources`` (each with verbatim per-source
            provenance).
        indicators: Bounded, redacted, structured JSONB of
            ``IncidentMemory.indicators``.
        entities: Bounded, redacted, structured JSONB of
            ``IncidentMemory.entities``.
        techniques: Bounded, redacted, structured JSONB of
            ``IncidentMemory.techniques``.
        findings: Bounded, redacted, structured JSONB of
            ``IncidentMemory.findings``.
        actions: Bounded, redacted, structured JSONB of
            ``IncidentMemory.actions``.
        outcomes: Bounded, redacted, structured JSONB of
            ``IncidentMemory.outcomes``.
        memory_metadata: Bounded, redacted, structured JSONB envelope
            metadata (``IncidentMemory.metadata``).
        confidence: Optional Step 16 bounded confidence in ``[0.0, 1.0]``
            (CHECK-constrained).
        provenance: Envelope provenance, constrained to ``recalled``.
    """

    __tablename__ = "incident_memories"
    __table_args__ = (
        CheckConstraint(
            "length(title) <= 200",
            name="incident_memory_title_length",
        ),
        CheckConstraint(
            "length(summary) <= 2000",
            name="incident_memory_summary_length",
        ),
        CheckConstraint(
            "confidence IS NULL OR "
            "(confidence >= 0.0 AND confidence <= 1.0)",
            name="incident_memory_confidence_range",
        ),
        CheckConstraint(
            "provenance = 'recalled'",
            name="provenance_recalled",
        ),
    )

    memory_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        unique=True,
        index=True,
        comment=(
            "Step 16 IncidentMemory.memory_id.  Unique identity — the "
            "idempotency key for re-persists."
        ),
    )

    memory_type: Mapped[MemoryType] = mapped_column(
        String(24),
        nullable=False,
        comment=(
            "Step 16 MemoryType (5-value closed enum, stored as String).  "
            "Lifecycle/kind bookkeeping only; never a verdict."
        ),
    )

    title: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
        comment=(
            "Bounded Step 16 memory title (max 200 chars by CHECK).  "
            "Descriptive bookkeeping, never evidence."
        ),
    )

    summary: Mapped[str] = mapped_column(
        String(2000),
        nullable=False,
        comment=(
            "Bounded Step 16 memory summary (max 2000 chars by CHECK).  "
            "Descriptive bookkeeping, never evidence."
        ),
    )

    correlation_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        comment=(
            "Step 10A correlation UUID the memory derives from.  Stored as "
            "a domain-level UUID, deliberately NOT a foreign key (Step 17 "
            "FK decision): historical recall must outlive the correlation "
            "lifecycle.  NULL when the memory is not correlation-derived."
        ),
    )

    sources: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        comment=(
            "Structured, redacted Step 16 IncidentMemory.sources (JSONB).  "
            "Each source keeps its verbatim per-source provenance; never "
            "contains raw event payloads or secrets."
        ),
    )

    indicators: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        comment=(
            "Structured, redacted Step 16 IncidentMemory.indicators "
            "(JSONB).  Secret-shaped content rejected — never stored."
        ),
    )

    entities: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        comment=(
            "Structured, redacted Step 16 IncidentMemory.entities (JSONB)."
        ),
    )

    techniques: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        comment=(
            "Structured, redacted Step 16 IncidentMemory.techniques "
            "(JSONB)."
        ),
    )

    findings: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        comment=(
            "Structured, redacted Step 16 IncidentMemory.findings (JSONB)."
        ),
    )

    actions: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        comment=(
            "Structured, redacted Step 16 IncidentMemory.actions (JSONB)."
        ),
    )

    outcomes: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        comment=(
            "Structured, redacted Step 16 IncidentMemory.outcomes (JSONB)."
        ),
    )

    memory_metadata: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        comment=(
            "Structured, redacted Step 16 IncidentMemory metadata (JSONB)."
        ),
    )

    confidence: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
        comment=(
            "Optional Step 16 confidence in [0.0, 1.0] (CHECK-constrained); "
            "NULL when undefined.  Bookkeeping only, never a risk score."
        ),
    )

    provenance: Mapped[str] = mapped_column(
        String(24),
        nullable=False,
        default="recalled",
        comment=(
            "Envelope provenance.  Incident memory is historical recall and "
            "is constrained to 'recalled' by CHECK constraint; it can never "
            "be stored as observed/enriched/detected/reconstructed."
        ),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<IncidentMemoryRow id={self.id} "
            f"memory_id={self.memory_id} "
            f"memory_type={self.memory_type!r} "
            f"provenance={self.provenance!r}>"
        )
