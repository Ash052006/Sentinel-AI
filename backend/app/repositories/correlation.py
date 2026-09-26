"""Correlation persistence + query repository (Steps 10C-B, 10D).

Write-side operations are used by the persistence service
(:mod:`app.services.correlation_persistence`) to store Step 10A
:class:`~app.schemas.correlation.CorrelationResult` objects in PostgreSQL
through the Step 10C-A contract models
(:class:`~app.models.correlation_result.CorrelationResult`,
:class:`~app.models.correlation_member.CorrelationMember`).

Read-side operations back the Step 10D read-only query layer
(:mod:`app.services.correlation_query`): correlation detail, detection- and
event-scoped pages, bounded recent correlations, and database-side counts.

Contract rules honoured here (defined in 10C-A):

* A persisted correlation is identified by its unique ``correlation_id``;
  any write path first checks for an existing row so that re-persisting the
  same correlation is a no-op.
* Members belong to their parent correlation and are always read back in
  ``member_order`` (Step 10A member order is preserved exactly).
* The repository does **not** commit.  Transaction boundaries are owned by
  the calling service so that one batch of correlations persists atomically
  (and a failure rolls the whole unit back).
* Reads are deterministic: every list returns a stable two-key order
  (``timestamp`` descending, ``correlation_id`` ascending) so a page
  boundary never exposes duplicate or missing rows between calls.

The repository has no notion of ``CorrelationResult`` / Step 10A semantics —
it exposes entity- and column-level operations that the service composes.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.correlation_member import CorrelationMember
from app.models.correlation_result import CorrelationResult


class CorrelationRepository:
    """Data-access layer for correlation persistence.

    The repository knows nothing about ``CorrelationResult`` / Step 10A
    semantics.  It exposes entity- and column-level operations that the
    persistence service composes into a full correlation persistence.
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
    # Correlations
    # ------------------------------------------------------------------

    def get_by_correlation_id(
        self,
        correlation_id: uuid.UUID,
    ) -> CorrelationResult | None:
        """Return the persisted correlation for *correlation_id*, if any.

        Used by the persistence service for idempotency and by callers that
        need to confirm a correlation exists before reacting to it.
        """
        return self.db.scalar(
            select(CorrelationResult).where(
                CorrelationResult.correlation_id == correlation_id
            )
        )

    def get_members_for_correlation(
        self,
        correlation_id: uuid.UUID,
    ) -> list[CorrelationMember]:
        """Return every member row of *correlation_id*, in member order.

        Ordering is deterministic: ``member_order`` ascending.  An unknown
        correlation returns ``[]``.
        """
        return list(
            self.db.scalars(
                select(CorrelationMember)
                .where(CorrelationMember.correlation_id == correlation_id)
                .order_by(CorrelationMember.member_order.asc())
            )
        )

    # ------------------------------------------------------------------
    # Correlations: read-side (Step 10D)
    # ------------------------------------------------------------------
    #
    # Every list orders by ``timestamp`` descending with ``correlation_id``
    # ascending as the two-key tie-break (correlation_id is unique, so the
    # ordering is total and page boundaries never drift).  The detection- and
    # event-scoped lists select the *distinct parent correlations* that
    # reference the id at least once, exactly as persisted.

    def get_members_for_correlations(
        self,
        correlation_ids: list[uuid.UUID],
    ) -> list[CorrelationMember]:
        """Bulk-load every member row for *correlation_ids*.

        Used by the query service to embed members into a page of
        correlations with a single query (no N+1).  Ordering is
        deterministic: parent ``correlation_id`` ascending, then
        ``member_order`` ascending.
        """
        if not correlation_ids:
            return []
        return list(
            self.db.scalars(
                select(CorrelationMember)
                .where(CorrelationMember.correlation_id.in_(correlation_ids))
                .order_by(
                    CorrelationMember.correlation_id.asc(),
                    CorrelationMember.member_order.asc(),
                )
            )
        )

    def list_correlations_for_detection(
        self,
        detection_id: uuid.UUID,
        *,
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[CorrelationResult]:
        """Return every correlation that references *detection_id*.

        Each correlation is returned at most once (distinct parents),
        regardless of how many of its members reference the detection —
        membership follows the persisted rows.  Ordering is deterministic:
        ``timestamp`` descending, ``correlation_id`` ascending.
        """
        return self._list_correlations_matching_member(
            CorrelationMember.detection_id == detection_id,
            limit=limit,
            offset=offset,
        )

    def list_correlations_for_event(
        self,
        event_id: uuid.UUID,
        *,
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[CorrelationResult]:
        """Return every correlation that references *event_id*.

        Each correlation is returned at most once (distinct parents);
        ordering is deterministic: ``timestamp`` descending,
        ``correlation_id`` ascending.
        """
        return self._list_correlations_matching_member(
            CorrelationMember.event_id == event_id,
            limit=limit,
            offset=offset,
        )

    def list_recent_correlations(
        self,
        *,
        limit: int,
    ) -> list[CorrelationResult]:
        """Return the *limit* newest persisted correlations across all rows.

        Deterministic ``timestamp`` descending / ``correlation_id`` ascending
        ordering, bounded by the caller-supplied limit (validated upstream).
        """
        stmt = (
            select(CorrelationResult)
            .order_by(
                CorrelationResult.timestamp.desc(),
                CorrelationResult.correlation_id.asc(),
            )
            .limit(limit)
        )
        return list(self.db.scalars(stmt))

    # ------------------------------------------------------------------
    # Correlations: counts (Step 10D)
    # ------------------------------------------------------------------

    def count_correlations(self) -> int:
        """Return the total number of persisted correlations."""
        return (
            self.db.scalar(select(func.count()).select_from(CorrelationResult)) or 0
        )

    def count_correlations_for_detection(self, detection_id: uuid.UUID) -> int:
        """Return the number of distinct correlations referencing *detection_id*.

        Counted on the database side over the ``correlation_members`` index.
        """
        return self._count_correlations_matching_member(
            CorrelationMember.detection_id == detection_id
        )

    def count_correlations_for_event(self, event_id: uuid.UUID) -> int:
        """Return the number of distinct correlations referencing *event_id*.

        Counted on the database side over the ``correlation_members`` index.
        """
        return self._count_correlations_matching_member(
            CorrelationMember.event_id == event_id
        )

    def _count_correlations_matching_member(self, member_filter) -> int:
        """Count the *distinct* parent correlations with a matching member row.

        Counting distinct correlation ids keeps the count aligned with the
        qualifying list call (a correlation containing the id several times
        is counted once).  The distinct-correlation subquery is wrapped in a
        plain ``count(*)`` aggregate so the integer result is never passed
        through the UUID column's result processor.
        """
        distinct_parents = (
            select(func.distinct(CorrelationMember.correlation_id))
            .where(member_filter)
            .subquery()
        )
        return (
            self.db.scalar(select(func.count()).select_from(distinct_parents)) or 0
        )

    # -- helper ----------------------------------------------------------

    def _list_correlations_matching_member(
        self,
        member_filter,
        *,
        limit: int | None,
        offset: int | None,
    ) -> list[CorrelationResult]:
        """List the distinct parent correlations with a matching member row.

        The ``IN`` subquery selects the correlation ids that reference the
        member column once, so a correlation containing the id several times
        still appears exactly once; parent ordering is fully deterministic.
        """
        member_ids = select(CorrelationMember.correlation_id).where(member_filter)
        stmt = (
            select(CorrelationResult)
            .where(CorrelationResult.correlation_id.in_(member_ids))
            .order_by(
                CorrelationResult.timestamp.desc(),
                CorrelationResult.correlation_id.asc(),
            )
        )
        if limit is not None:
            stmt = stmt.limit(limit)
        if offset is not None:
            stmt = stmt.offset(offset)
        return list(self.db.scalars(stmt))