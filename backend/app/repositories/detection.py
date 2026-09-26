"""Detection persistence + query repository (Steps 9F-B, 9G).

Write-side operations are used by the persistence service
(:mod:`app.services.detection_persistence`) to store a Step 9E
:class:`~app.schemas.detection_agent.DetectionAnalysis` in PostgreSQL
through the Step 9F-A contract models
(:class:`~app.models.detection_result.DetectionResult`,
:class:`~app.models.detection_rule_failure.DetectionRuleFailure`).

Read-side operations back the Step 9G read-only query layer
(:mod:`app.services.detection_query`): event/rule-scoped result pages,
bounded recent results, per-event failure pages, and the aggregate
overviews that compose an event's analysis summary.

Contract rules honoured here (defined in 9F-A, see
``docs/development/detection_persistence_contract.md``):

* A persisted result is identified by its unique ``detection_id``; any
  write path first checks for an existing row so that re-persisting the
  same analysis is a no-op.
* A persisted failure is identified by ``(event_id, engine, rule_id,
  error_type, error_message)``.
* The repository does **not** commit.  Transaction boundaries are owned by
  the calling service so that one analysis persists atomically (and a
  failure rolls the whole unit back).
* Reads are deterministic: every list returns a stable two-key order so a
  page boundary never exposes duplicate or missing rows between calls.

The repository has no notion of ``DetectionAnalysis`` / Step 9E semantics —
it exposes entity- and column-level operations that the services compose.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.detection_result import DetectionResult
from app.models.detection_rule_failure import DetectionRuleFailure


# ---------------------------------------------------------------------------
# Aggregate carriers (domain-neutral, derived purely from the entity tables)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ResultsOverview:
    """Aggregate view of an event's persisted detection results.

    Attributes:
        count: Number of persisted results for the event.
        first_detected_at: Earliest ``detected_at`` (``None`` if no rows).
        last_detected_at: Latest ``detected_at`` (``None`` if no rows).
    """

    count: int
    first_detected_at: datetime | None = None
    last_detected_at: datetime | None = None


@dataclass(frozen=True)
class FailuresOverview:
    """Aggregate view of an event's persisted detection failures.

    Attributes:
        count: Number of persisted failures for the event.
        first_failed_at: Earliest ``failed_at`` (``None`` if no rows).
        last_failed_at: Latest ``failed_at`` (``None`` if no rows).
    """

    count: int
    first_failed_at: datetime | None = None
    last_failed_at: datetime | None = None


class DetectionRepository:
    """Data-access layer for detection persistence.

    The repository knows nothing about ``DetectionAnalysis`` / Step 9E
    semantics.  It exposes entity- and column-level operations that the
    persistence service composes into a full analysis persistence.
    """

    def __init__(self, db: Session) -> None:
        self.db = db

    # ------------------------------------------------------------------
    # Generic
    # ------------------------------------------------------------------

    def add(self, entity) -> None:
        """Stage *entity* for insertion.  The caller owns the transaction."""
        self.db.add(entity)

    # ------------------------------------------------------------------
    # Results
    # ------------------------------------------------------------------

    def get_result_by_detection_id(
        self,
        detection_id: uuid.UUID,
    ) -> DetectionResult | None:
        """Return the persisted result for *detection_id*, if present."""
        return self.db.scalar(
            select(DetectionResult).where(
                DetectionResult.detection_id == detection_id
            )
        )

    def get_results_for_event(
        self,
        event_id: uuid.UUID,
        *,
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[DetectionResult]:
        """Return every detection match persisted for *event_id*.

        Ordering is deterministic: ``detected_at`` descending with
        ``detection_id`` ascending as the two-key tie-break, so equal
        timestamps never produce unstable page boundaries.
        """
        stmt = (
            select(DetectionResult)
            .where(DetectionResult.event_id == event_id)
            .order_by(
                DetectionResult.detected_at.desc(),
                DetectionResult.detection_id.asc(),
            )
        )
        if limit is not None:
            stmt = stmt.limit(limit)
        if offset is not None:
            stmt = stmt.offset(offset)
        return list(self.db.scalars(stmt))

    def get_results_for_rule(
        self,
        rule_id: str,
        *,
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[DetectionResult]:
        """Return every detection match persisted for *rule_id*.

        Ordering is deterministic: ``detected_at`` descending, then
        ``detection_id`` ascending.
        """
        stmt = (
            select(DetectionResult)
            .where(DetectionResult.rule_id == rule_id)
            .order_by(
                DetectionResult.detected_at.desc(),
                DetectionResult.detection_id.asc(),
            )
        )
        if limit is not None:
            stmt = stmt.limit(limit)
        if offset is not None:
            stmt = stmt.offset(offset)
        return list(self.db.scalars(stmt))

    def list_recent_results(self, *, limit: int) -> list[DetectionResult]:
        """Return the *limit* newest persisted matches across all events.

        Deterministic ``detected_at`` descending / ``detection_id`` ascending
        ordering, bounded by the caller-supplied limit (validated upstream).
        """
        stmt = (
            select(DetectionResult)
            .order_by(
                DetectionResult.detected_at.desc(),
                DetectionResult.detection_id.asc(),
            )
            .limit(limit)
        )
        return list(self.db.scalars(stmt))

    # ------------------------------------------------------------------
    # Results: counts and aggregate overviews
    # ------------------------------------------------------------------

    def count_results_for_event(self, event_id: uuid.UUID) -> int:
        """Return the total number of persisted matches for *event_id*."""
        return self.db.scalar(
            select(func.count(DetectionResult.id)).where(
                DetectionResult.event_id == event_id
            )
        )

    def count_results_for_rule(self, rule_id: str) -> int:
        """Return the total number of persisted matches for *rule_id*."""
        return self.db.scalar(
            select(func.count(DetectionResult.id)).where(
                DetectionResult.rule_id == rule_id
            )
        )

    def get_results_overview(self, event_id: uuid.UUID) -> ResultsOverview:
        """Return count and detected-time window for *event_id*'s matches."""
        row = self.db.execute(
            select(
                func.count(DetectionResult.id),
                func.min(DetectionResult.detected_at),
                func.max(DetectionResult.detected_at),
            ).where(DetectionResult.event_id == event_id)
        ).one()
        return ResultsOverview(
            count=row[0],
            first_detected_at=row[1],
            last_detected_at=row[2],
        )

    # ------------------------------------------------------------------
    # Failures
    # ------------------------------------------------------------------

    def find_existing_failure(
        self,
        *,
        event_id: uuid.UUID,
        engine: str,
        rule_id: str,
        error_type: str,
        error_message: str,
    ) -> DetectionRuleFailure | None:
        """Return a failure row matching the supplied identity attributes.

        Used by the persistence service for idempotency.  The identity of a
        persisted failure is ``(event_id, engine, rule_id, error_type,
        error_message)`` — stable across re-persists of the same analysis
        (failures carry no per-evaluation timestamp).
        """
        return self.db.scalar(
            select(DetectionRuleFailure).where(
                DetectionRuleFailure.event_id == event_id,
                DetectionRuleFailure.engine == engine,
                DetectionRuleFailure.rule_id == rule_id,
                DetectionRuleFailure.error_type == error_type,
                DetectionRuleFailure.error_message == error_message,
            )
        )

    def get_failures_for_event(
        self,
        event_id: uuid.UUID,
        *,
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[DetectionRuleFailure]:
        """Return every detection failure persisted for *event_id*.

        Ordering is deterministic: ``failed_at`` descending, then the row
        primary key ascending (failures carry no natural unique tie-break).
        """
        stmt = (
            select(DetectionRuleFailure)
            .where(DetectionRuleFailure.event_id == event_id)
            .order_by(
                DetectionRuleFailure.failed_at.desc(),
                DetectionRuleFailure.id.asc(),
            )
        )
        if limit is not None:
            stmt = stmt.limit(limit)
        if offset is not None:
            stmt = stmt.offset(offset)
        return list(self.db.scalars(stmt))

    def count_failures_for_event(self, event_id: uuid.UUID) -> int:
        """Return the total number of persisted failures for *event_id*."""
        return self.db.scalar(
            select(func.count(DetectionRuleFailure.id)).where(
                DetectionRuleFailure.event_id == event_id
            )
        )

    def get_failures_overview(self, event_id: uuid.UUID) -> FailuresOverview:
        """Return count and failure-time window for *event_id*'s failures."""
        row = self.db.execute(
            select(
                func.count(DetectionRuleFailure.id),
                func.min(DetectionRuleFailure.failed_at),
                func.max(DetectionRuleFailure.failed_at),
            ).where(DetectionRuleFailure.event_id == event_id)
        ).one()
        return FailuresOverview(
            count=row[0],
            first_failed_at=row[1],
            last_failed_at=row[2],
        )