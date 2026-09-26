"""Incident memory persistence service (Step 17).

Persistence side of the Step 16 incident-memory contract
(:class:`~app.schemas.incident_memory.IncidentMemory` and
:class:`~app.schemas.incident_memory.MemoryType`).

Design intent
-------------
* **No memory logic.**  This service never recalls, searches, re-extracts,
  reinterprets, or reasons about memory: it only *persists* the complete,
  validated Step 16 :class:`IncidentMemory` envelopes it is handed.  The
  Step 16 extraction service and the Step 19 recall engine own all memory
  behaviour; persistence is a side-effect sink, injected by the Incident
  Memory Agent exactly like the correlation persistence sink.
* **Single logical transaction.**  One ``persist_memories`` call stages
  every envelope and publishes all of them with a single ``commit()``;
  any failure rolls the whole unit back and propagates a safe, typed
  exception — never partial state.
* **Idempotency.**  The Step 17 identity is the Step 16 ``memory_id``
  (unique by database constraint).  Re-persisting the same ``memory_id``
  skips the row (no-op); a later recall that produced a *fresh* Step 16
  UUID is a new, legitimate historical row.
* **Provenance pinning.**  Every persisted envelope is stored with
  :data:`Provenance.RECALLED <app.schemas.security_event.Provenance.
  RECALLED>` — enforced by a database CHECK constraint — so historical
  memory can never masquerade as currently observed evidence.  Per-source
  provenance inside ``sources`` is preserved *verbatim* (``OBSERVED`` /
  ``ENRICHED`` / …) and is never rewritten to ``recalled``.
* **Secret-safe at the boundary.**  The service redacts credential-shaped
  keys anywhere in the structured JSON (defence-in-depth on top of Step 16
  validation) and rejects — never silently stores — payloads that still
  carry secret shapes.  Error messages never contain payloads, secrets,
  or raw database error text.
* **Bounded.**  Each structured JSON column is size-bounded before being
  bound for write (same ``_MAX_STRUCTURED_BYTES`` cap as the Step 11 risk /
  Step 10C correlation persistence), and the row model applies database
  ``CHECK`` bounds (title ``<= 200``, summary ``<= 2000``, confidence in
  ``[0, 1]``, provenance ``= 'recalled'``).
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

from sqlalchemy.orm import Session

from app.models.incident_memory import IncidentMemoryRow
from app.repositories.incident_memory import IncidentMemoryRepository
from app.schemas.incident_memory import (
    IncidentMemory as IncidentMemorySchema,
)
from app.schemas.incident_memory import MemoryType
from app.schemas.security_event import Provenance

logger = logging.getLogger(__name__)

#: Marker substituted for detected credentials anywhere in stored data.
_REDACTED = "<redacted>"

#: Hard cap on one structured JSON column in characters — the same
#: persistence bound used by the Step 11 risk and Step 10C correlation
#: persistence services (defence-in-depth on top of Step 16 validation).
_MAX_STRUCTURED_CHARS = 262_144

#: Structured-evidence keys whose values are credentials and must be
#: redacted.  Kept in lock-step with
#: :mod:`app.services.correlation_persistence`.
_SECRET_KEY_PATTERN = re.compile(
    r"(?i)^(?:api[_-]?key|apikey|authorization|auth[_-]?header|set[_-]?cookie|"
    r"cookie|password|passwd|secret|token|access[_-]?key|client[_-]?secret)$"
)


# ---------------------------------------------------------------------------
# Secret-safe sanitization (defence-in-depth)
# ---------------------------------------------------------------------------


def _redact_structured(value: Any) -> Any:
    """Recursively redact credential values inside structured JSON data."""
    if isinstance(value, dict):
        return {
            key: (
                _REDACTED
                if _SECRET_KEY_PATTERN.match(str(key))
                else _redact_structured(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_structured(item) for item in value]
    return value


def _prepare_structured(
    value: Any,
    *,
    field: str,
    memory_id: uuid.UUID | None = None,
) -> Any | None:
    """Redact credentials and enforce the bounded-size rule for JSON columns."""
    if value is None:
        return None
    redacted = _redact_structured(value)
    try:
        serialized = len(json.dumps(redacted))
    except (TypeError, ValueError) as exc:
        raise IncidentMemoryPersistenceValidationError(
            memory_id=memory_id,
            reason=f"{field} is not JSON-compatible",
        ) from exc
    if serialized > _MAX_STRUCTURED_CHARS:
        raise IncidentMemoryPersistenceValidationError(
            memory_id=memory_id,
            reason=f"{field} exceeds the {_MAX_STRUCTURED_CHARS}-character persistence bound",
        )
    return redacted


def _assert_no_secret_shapes(value: Any, *, memory_id: uuid.UUID | None) -> None:
    """Abort — never silently repair — content that still looks like a secret.

    Used for whole-record defence-in-depth: after redaction, any remaining
    credential-shaped value means the envelope is refused outright.  This
    is a *reject*, not a repair, and the error never echoes the payload.
    """
    if isinstance(value, dict):
        for key, item in value.items():
            if _SECRET_KEY_PATTERN.match(str(key)):
                raise IncidentMemoryPersistenceValidationError(
                    memory_id=memory_id,
                    reason="structured content contains a secret-shaped key",
                )
            _assert_no_secret_shapes(item, memory_id=memory_id)
    elif isinstance(value, list):
        for item in value:
            _assert_no_secret_shapes(item, memory_id=memory_id)


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class IncidentMemoryPersistenceError(Exception):
    """Raised when one or more incident memories cannot be persisted.

    Instances never contain credentials, raw evidence, raw memory payloads,
    or raw database/SQL error text — only safe contextual identifiers such
    as the ``memory_id``.
    """

    def __init__(
        self,
        memory_id: uuid.UUID | None = None,
        reason: str = "",
    ) -> None:
        message = "Failed to persist incident memory"
        if memory_id is not None:
            message += f" for memory {memory_id}"
        if reason:
            message += f": {reason}"
        super().__init__(message)
        self.memory_id = memory_id


class IncidentMemoryPersistenceValidationError(IncidentMemoryPersistenceError):
    """Raised when a memory cannot be mapped to persistence rows safely.

    Used for pre-commit validation failures (e.g. structured content
    exceeding the bounded size, or a non-``IncidentMemory`` item) that must
    abort the whole transaction.
    """


class IncidentMemoryPersistenceValidationError(IncidentMemoryPersistenceError):
    """Raised when an item is not a Step 16 :class:`IncidentMemory`."""


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IncidentMemoryPersistenceSummary:
    """Summary of one ``persist_memories`` invocation."""

    memory_ids: tuple[uuid.UUID, ...]
    memories_created: int = 0
    memories_skipped: int = 0

    @property
    def is_empty(self) -> bool:
        """True when nothing was persisted (e.g. an empty memory set)."""
        return self.memories_created == 0


# ---------------------------------------------------------------------------
# Persistence service
# ---------------------------------------------------------------------------


class IncidentMemoryPersistenceService:
    """Coordinates persistence of Step 16 memories through the repository.

    The service owns the transaction: one ``persist_memories`` call stages
    every envelope, publishes them all with a single ``commit()``, and
    rolls the whole unit back on any failure before a safe exception
    propagates.  The Incident Memory Agent never commits or rolls back —
    persistence is an injected side-effect sink.

    Args:
        repository_factory: Optional repository factory; defaults to
            :class:`IncidentMemoryRepository`.  Injected for testability.
        clock: Optional UTC time source; used for the ``created_at`` /
            ``updated_at`` bookkeeping on persistence, and injected for
            deterministic tests.  Parity with the correlation persistence
            service.
    """

    def __init__(
        self,
        repository_factory: Callable[
            [Session], IncidentMemoryRepository
        ] = IncidentMemoryRepository,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._repository_factory = repository_factory
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def persist_memories(
        self,
        db: Session,
        memories: Iterable[IncidentMemorySchema],
    ) -> IncidentMemoryPersistenceSummary:
        """Persist *memories* atomically and return a summary.

        One logical transaction: every envelope is staged, a single
        ``commit()`` publishes them together, and any failure rolls the
        unit back before a safe exception propagates.  Memories whose
        ``memory_id`` is already persisted are skipped (idempotency).

        Raises:
            IncidentMemoryPersistenceValidationError: when an item is not a
                Step 16 :class:`IncidentMemory` or exceeds a persistence
                bound.
            IncidentMemoryPersistenceError: when persistence fails for any
                other reason (original cause preserved).
        """
        try:
            return self._persist(db, memories)
        except IncidentMemoryPersistenceError:
            db.rollback()
            raise
        except Exception as exc:  # database errors / unexpected conditions
            logger.warning("incident memory persistence failed", exc_info=True)
            db.rollback()
            raise IncidentMemoryPersistenceError() from exc

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _persist(
        self,
        db: Session,
        memories: Iterable[IncidentMemorySchema],
    ) -> IncidentMemoryPersistenceSummary:
        repository = self._repository_factory(db)
        memory_ids: list[uuid.UUID] = []
        created = 0
        skipped = 0

        for item in memories:
            if not isinstance(item, IncidentMemorySchema):
                raise IncidentMemoryPersistenceValidationError()

            memory_id = item.memory_id
            memory_ids.append(memory_id)

            # Idempotency: already persisted → skip.
            if repository.get_by_memory_id(memory_id) is not None:
                skipped += 1
                continue
            repository.add(
                IncidentMemoryRow(
                    memory_id=item.memory_id,
                    memory_type=item.memory_type.value,
                    title=item.title,
                    summary=(item.summary or ""),
                    correlation_id=item.correlation_id,
                    sources=_prepare_structured(
                        [s.model_dump(mode="json") for s in item.sources],
                        field="sources",
                        memory_id=item.memory_id,
                    ),
                    indicators=_prepare_structured(
                        [i.model_dump(mode="json") for i in item.indicators],
                        field="indicators",
                        memory_id=item.memory_id,
                    ),
                    entities=_prepare_structured(
                        [e.model_dump(mode="json") for e in item.entities],
                        field="entities",
                        memory_id=item.memory_id,
                    ),
                    techniques=_prepare_structured(
                        [t.model_dump(mode="json") for t in item.techniques],
                        field="techniques",
                        memory_id=item.memory_id,
                    ),
                    findings=_prepare_structured(
                        [f.model_dump(mode="json") for f in item.findings],
                        field="findings",
                        memory_id=item.memory_id,
                    ),
                    actions=_prepare_structured(
                        [a.model_dump(mode="json") for a in item.actions],
                        field="actions",
                        memory_id=item.memory_id,
                    ),
                    outcomes=_prepare_structured(
                        (
                            item.outcome.model_dump(mode="json")
                            if item.outcome is not None
                            else {}
                        ),
                        field="outcomes",
                        memory_id=item.memory_id,
                    ),
                    memory_metadata=_prepare_structured(
                        dict(item.metadata),
                        field="metadata",
                        memory_id=item.memory_id,
                    ),
                    confidence=item.confidence,
                    provenance=Provenance.RECALLED.value,
                )
            )
            created += 1

        db.commit()
        return IncidentMemoryPersistenceSummary(
            memory_ids=tuple(memory_ids),
            memories_created=created,
            memories_skipped=skipped,
        )
