"""Risk assessment persistence + query repository (Steps 11C-B, 11D).

Write-side operations are used by the persistence service
(:mod:`app.services.risk_persistence`) to store Step 11A
:class:`~app.schemas.risk.RiskAssessment` objects in PostgreSQL through the
Step 11C-A contract model (:class:`~app.models.risk_assessment.RiskAssessment`).

Read-side operations back the Step 11D read-only query layer
(:mod:`app.services.risk_query`): assessment detail, correlation-scoped
pages, bounded recent assessments, and database-side counts.

Contract rules honoured here (defined in 11C-A):

* A persisted assessment is identified by its unique ``risk_assessment_id``;
  any write path first checks for an existing row so that re-persisting the
  same assessment is a no-op.  The read path keys on the same identity.
* ``correlation_id`` is **not** unique: a persisted correlation may
  legitimately carry multiple assessments over time (historical semantics),
  so correlation-scoped reads return every matching assessment.
* The repository does **not** commit.  Transaction boundaries are owned by
  the calling service so that one batch of assessments persists atomically
  (and a failure rolls the whole unit back).
* Reads are deterministic: every list returns a stable two-key order
  (``timestamp`` descending, ``risk_assessment_id`` ascending) so a page
  boundary never exposes duplicate or missing rows between calls.

The repository has no notion of ``RiskAssessment`` / Step 11A semantics — it
exposes entity- and column-level operations that the service composes.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.risk_assessment import RiskAssessment


class RiskRepository:
    """Data-access layer for risk-assessment persistence.

    The repository knows nothing about ``RiskAssessment`` / Step 11A
    semantics.  It exposes entity- and column-level operations that the
    persistence service composes into a full risk persistence.
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
    # Assessments
    # ------------------------------------------------------------------

    def get_by_risk_assessment_id(
        self,
        risk_assessment_id: uuid.UUID,
    ) -> RiskAssessment | None:
        """Return the persisted assessment for *risk_assessment_id*, if any.

        Used by the persistence service for idempotency (re-persisting the
        same assessment identity is a no-op) and by the Step 11D query layer
        for assessment detail reads.
        """
        return self.db.scalar(
            select(RiskAssessment).where(
                RiskAssessment.risk_assessment_id == risk_assessment_id
            )
        )

    # ------------------------------------------------------------------
    # Assessments: read-side (Step 11D)
    # ------------------------------------------------------------------
    #
    # Every list orders by ``timestamp`` descending with
    # ``risk_assessment_id`` ascending as the two-key tie-break
    # (risk_assessment_id is unique, so the ordering is total and page
    # boundaries never drift).

    def list_assessments_for_correlation(
        self,
        correlation_id: uuid.UUID,
        *,
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[RiskAssessment]:
        """Return every persisted assessment of *correlation_id*.

        A correlation may carry several historical assessments (11C-A
        semantics), so this returns **all** matching rows.  Ordering is
        deterministic: ``timestamp`` descending, ``risk_assessment_id``
        ascending.
        """
        stmt = (
            select(RiskAssessment)
            .where(RiskAssessment.correlation_id == correlation_id)
            .order_by(
                RiskAssessment.timestamp.desc(),
                RiskAssessment.risk_assessment_id.asc(),
            )
        )
        if limit is not None:
            stmt = stmt.limit(limit)
        if offset is not None:
            stmt = stmt.offset(offset)
        return list(self.db.scalars(stmt))

    def list_recent_assessments(
        self,
        *,
        limit: int,
    ) -> list[RiskAssessment]:
        """Return the *limit* newest persisted assessments across all rows.

        Deterministic ``timestamp`` descending / ``risk_assessment_id``
        ascending ordering, bounded by the caller-supplied limit (validated
        upstream).
        """
        stmt = (
            select(RiskAssessment)
            .order_by(
                RiskAssessment.timestamp.desc(),
                RiskAssessment.risk_assessment_id.asc(),
            )
            .limit(limit)
        )
        return list(self.db.scalars(stmt))

    # ------------------------------------------------------------------
    # Assessments: counts (Step 11D)
    # ------------------------------------------------------------------

    def count_assessments(self) -> int:
        """Return the total number of persisted assessments."""
        return (
            self.db.scalar(select(func.count()).select_from(RiskAssessment)) or 0
        )

    def count_assessments_for_correlation(self, correlation_id: uuid.UUID) -> int:
        """Return the number of persisted assessments of *correlation_id*.

        Counted on the database side over the ``correlation_id`` index.
        """
        return (
            self.db.scalar(
                select(func.count()).select_from(RiskAssessment).where(
                    RiskAssessment.correlation_id == correlation_id
                )
            )
            or 0
        )