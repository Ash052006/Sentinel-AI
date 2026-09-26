"""Correlation persistence service (Step 10C-B).

Translates Step 10A :class:`~app.schemas.correlation.CorrelationResult`
objects into PostgreSQL persistence operations using the Step 10C-A
contract models (:class:`~app.models.correlation_result.CorrelationResult`,
:class:`~app.models.correlation_member.CorrelationMember`) through the
:class:`~app.repositories.correlation.CorrelationRepository`.

Pipeline:::

    CorrelationResult[]      (Step 10B CorrelationAgent output)
        ↓  (this service)
    correlation_results      (one row per correlation, keyed by correlation_id)
        ↓
    correlation_members      (one reference row per member, in member_order)

Behavioural guarantees
----------------------
* **No correlation logic.**  The service never groups, scores, or
  reinterprets correlations; it only persists completed Step 10A results.
* **Transactional.**  All work for one ``persist_correlations`` call
  commits in a single ``Session.commit()``; any failure rolls the unit back
  and raises a safe :class:`CorrelationPersistenceError` (no partial
  state).
* **Idempotent.**  Re-persisting the same correlation reuses the existing
  row: correlations are identified by their unique ``correlation_id``.
  Legitimate re-correlations (fresh ``correlation_id`` values) are
  preserved as historical rows.
* **Provenance.**  Every row is stored with ``Provenance.CORRELATED`` —
  never ``observed``/``enriched``/``reconstructed``/``detected`` (enforced
  by CHECK constraint).
* **Referencing.**  Members are stored as lightweight references to
  detections; no ``DetectionResult`` record is duplicated.
* **Secret-safe.**  Structured evidence/metadata is recursively
  key-redacted before persistence (defence-in-depth on top of the Step 10A
  validators), and error messages never contain payloads or secrets.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from sqlalchemy.orm import Session

from app.models.correlation_member import CorrelationMember
from app.models.correlation_result import CorrelationResult
from app.repositories.correlation import CorrelationRepository
from app.schemas.correlation import (
    CorrelationResult as CorrelationResultSchema,
)
from app.schemas.correlation import CorrelationStatus
from app.schemas.security_event import Provenance

logger = logging.getLogger(__name__)

#: Hard cap on serialized structured evidence/metadata (defense in depth).
_MAX_EVIDENCE_CHARS = 262_144

#: Marker substituted for detected credentials anywhere in stored data.
_REDACTED = "<redacted>"


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class CorrelationPersistenceError(Exception):
    """Raised when one or more correlations cannot be persisted.

    Instances never contain credentials, raw evidence, raw event payloads,
    or raw database/SQL error text — only safe contextual identifiers such
    as the correlation / event UUIDs.
    """

    def __init__(
        self,
        correlation_id: uuid.UUID | None = None,
        reason: str = "",
    ) -> None:
        message = "Failed to persist correlation"
        if correlation_id is not None:
            message += f" for correlation {correlation_id}"
        if reason:
            message += f": {reason}"
        super().__init__(message)
        self.correlation_id = correlation_id


class CorrelationPersistenceValidationError(CorrelationPersistenceError):
    """Raised when a result cannot be mapped to persistence rows safely.

    Used for pre-commit validation failures (e.g. evidence exceeding the
    bounded size, or a non-``CorrelationResult`` item) that must abort the
    whole transaction.
    """


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CorrelationPersistenceSummary:
    """Summary of one ``persist_correlations`` invocation."""

    correlation_ids: tuple[uuid.UUID, ...]
    correlations_created: int = 0
    correlations_skipped: int = 0
    member_counts: tuple[int, ...] = ()

    @property
    def is_empty(self) -> bool:
        """True when nothing was persisted (e.g. an empty result set)."""
        return self.correlations_created == 0


# ---------------------------------------------------------------------------
# Secret-safe sanitization (defense-in-depth)
# ---------------------------------------------------------------------------

#: Structured-evidence keys whose values are credentials and must be redacted.
#: Kept in lock-step with ``app/services/detection_persistence.py``.
_SECRET_KEY_PATTERN = re.compile(
    r"(?i)^(?:api[_-]?key|apikey|authorization|auth[_-]?header|set[_-]?cookie|"
    r"cookie|password|passwd|secret|token|access[_-]?key|client[_-]?secret)$"
)


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
    data: dict | None,
    *,
    field: str,
    correlation_id: uuid.UUID | None = None,
) -> dict | None:
    """Redact credentials and enforce the bounded-size rule for JSON columns."""
    if data is None:
        return None
    redacted = _redact_structured(data)
    try:
        serialized = len(json.dumps(redacted))
    except (TypeError, ValueError) as exc:
        # Non-JSON-compatible structured data is a validation failure: the
        # correlation cannot be stored safely as JSONB.  Never leaks the
        # offending payload into the message.
        raise CorrelationPersistenceValidationError(
            correlation_id=correlation_id,
            reason=f"{field} is not JSON-compatible",
        ) from exc
    if serialized > _MAX_EVIDENCE_CHARS:
        raise CorrelationPersistenceValidationError(
            correlation_id=correlation_id,
            reason=f"{field} exceeds the {_MAX_EVIDENCE_CHARS}-character persistence bound",
        )
    return redacted


# ---------------------------------------------------------------------------
# Persistence service
# ---------------------------------------------------------------------------


class CorrelationPersistenceService:
    """Coordinates persistence of Step 10A results through the repository.

    The service owns the transaction boundary: one ``persist_correlations``
    call stages every parent row and member reference and publishes them
    with a single ``commit()``.  The Correlation Agent never commits or
    rolls back — persistence is an injected side-effect sink.

    Args:
        repository_factory: Optional repository factory; defaults to
            :class:`CorrelationRepository`.  Injected for testability.
        clock: Optional UTC time source; reserved for parity with the
            detection persistence service.  Parent ``timestamp`` values come
            from the Step 10A result itself, so the clock is unused by the
            current persistence path.
    """

    def __init__(
        self,
        repository_factory: Callable[[Session], CorrelationRepository] = CorrelationRepository,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._repository_factory = repository_factory
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def persist_correlations(
        self,
        db: Session,
        results: list[CorrelationResultSchema],
    ) -> CorrelationPersistenceSummary:
        """Persist *results* atomically and return a summary.

        One logical transaction: every correlation (and its member
        references) is staged, a single ``commit()`` publishes them
        together, and any failure rolls the unit back before a safe
        exception propagates.  Correlations whose ``correlation_id`` is
        already persisted are skipped (idempotency).

        Raises:
            CorrelationPersistenceValidationError: when an item is not a
                ``CorrelationResult`` or exceeds a persistence bound.
            CorrelationPersistenceError: when the persistence fails for any
                other reason (original cause preserved).
        """
        try:
            return self._persist(db, results)
        except CorrelationPersistenceError:
            db.rollback()
            raise
        except Exception as exc:  # database errors / unexpected conditions
            logger.warning(
                "correlation persistence failed (%s)",
                type(exc).__name__,
            )
            db.rollback()
            raise CorrelationPersistenceError() from exc

    def persist_correlation(
        self,
        db: Session,
        result: CorrelationResultSchema,
    ) -> CorrelationPersistenceSummary:
        """Persist a single *result* atomically (convenience wrapper)."""
        return self.persist_correlations(db, [result])

    # -- internal -----------------------------------------------------------

    def _persist(
        self,
        db: Session,
        results: list[CorrelationResultSchema],
    ) -> CorrelationPersistenceSummary:
        repo = self._repository_factory(db)

        created = skipped = 0
        correlation_ids: list[uuid.UUID] = []
        member_counts: list[int] = []
        staged = False

        for result in results:
            if not isinstance(result, CorrelationResultSchema):
                raise CorrelationPersistenceValidationError(
                    reason=(
                        "each persisted item must be a CorrelationResult; "
                        f"received {type(result).__module__}."
                        f"{type(result).__qualname__}"
                    )
                )

            if repo.get_by_correlation_id(result.correlation_id) is not None:
                skipped += 1
                continue

            if not isinstance(result.status, CorrelationStatus):
                # The Step 10A schema validates "candidate" | "active" |
                # "closed" already; re-check behind model_construct-style
                # bypasses so no invented status can ever be stored.
                raise CorrelationPersistenceValidationError(
                    correlation_id=result.correlation_id,
                    reason="status must be one of candidate/active/closed",
                )

            repo.add(
                CorrelationResult(
                    correlation_id=result.correlation_id,
                    status=result.status,
                    confidence=result.confidence,
                    evidence=_prepare_structured(
                        result.evidence,
                        field="evidence",
                        correlation_id=result.correlation_id,
                    ),
                    result_metadata=_prepare_structured(
                        result.metadata,
                        field="metadata",
                        correlation_id=result.correlation_id,
                    ),
                    timestamp=result.timestamp,
                    provenance=result.provenance.value,
                )
            )
            # Flush the parent row before staging its member references.
            # Without a mapper relationship() SQLAlchemy emits child rows
            # before parent rows in one unit of work — that violates the FK
            # on enforcing stores (PostgreSQL, and SQLite under PRAGMA
            # foreign_keys=ON).  Flushing here guarantees parents exist
            # before their members are inserted, all within one transaction.
            db.flush()

            for order, member in enumerate(result.members):
                repo.add(
                    CorrelationMember(
                        correlation_id=result.correlation_id,
                        detection_id=member.detection_id,
                        event_id=member.event_id,
                        timestamp=member.timestamp,
                        member_order=order,
                    )
                )

            correlation_ids.append(result.correlation_id)
            member_counts.append(len(result.members))
            created += 1
            staged = True

        # Stage; flush so rows materialize, then publish atomically.
        if staged:
            db.flush()
            db.commit()

        return CorrelationPersistenceSummary(
            correlation_ids=tuple(correlation_ids),
            correlations_created=created,
            correlations_skipped=skipped,
            member_counts=tuple(member_counts),
        )


def persist_correlations(
    db: Session,
    results: list[CorrelationResultSchema],
) -> CorrelationPersistenceSummary:
    """Convenience wrapper: persist *results* with a default service.

    Equivalent to ``CorrelationPersistenceService().persist_correlations(
    db, results)``.
    """
    return CorrelationPersistenceService().persist_correlations(db, results)