"""Approval workflow persistence + query repository (V2.16).

Write-side operations back the approval service: idempotent creation of a
request for a ``REQUIRES_APPROVAL`` decision, and **conditional** resolution
transitions whose ``WHERE status = 'pending' AND expires_at > now`` clause is
the concurrency guard — at most one simultaneous transition wins, and an
expired pending request can never be approved.

Read-side operations back the approval query layer: detail, status-scoped
pages, bounded recent feeds, and database-side counts.

Contract rules honoured here:

* ``approval_id`` and ``policy_decision_id`` are both unique: one policy
  decision has exactly one approval lifecycle, and re-creating a request
  for an already-resolved decision is a no-op (or a conflict), never a
  second row.
* The repository does **not** commit.  Transaction boundaries are owned by
  the calling service so one creation batch (or one resolution + response
  execution) commits atomically.
* Reads are deterministic: every list orders by ``requested_at``
  descending with ``id`` ascending as the two-key tie-break so a page
  boundary never exposes duplicate or missing rows between calls.
* Expiry is lazy: ``expire_overdue`` marks long-overdue resolves in one
  database-side statement; there is no scheduler.

The repository has no notion of :class:`~app.schemas.approval.ApprovalRecord`
semantics — it exposes entity- and column-level operations the service
composes.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.models.approval_request import ApprovalRequestRow


class ApprovalRepository:
    """Data-access layer for approval-request persistence."""

    def __init__(self, db: Session) -> None:
        self.db = db

    # ------------------------------------------------------------------
    # Generic
    # ------------------------------------------------------------------

    def add(self, entity: ApprovalRequestRow) -> None:
        """Stage *entity* for insertion.  The caller owns the transaction."""
        self.db.add(entity)

    # ------------------------------------------------------------------
    # Identity reads
    # ------------------------------------------------------------------

    def get_by_approval_id(
        self,
        approval_id: uuid.UUID,
    ) -> ApprovalRequestRow | None:
        """Return the persisted request for *approval_id*, if any."""
        return self.db.scalar(
            select(ApprovalRequestRow).where(
                ApprovalRequestRow.approval_id == approval_id
            )
        )

    def get_by_policy_decision_id(
        self,
        policy_decision_id: uuid.UUID,
    ) -> ApprovalRequestRow | None:
        """Return the persisted request for *policy_decision_id*, if any."""
        return self.db.scalar(
            select(ApprovalRequestRow).where(
                ApprovalRequestRow.policy_decision_id == policy_decision_id
            )
        )

    # ------------------------------------------------------------------
    # Conditional resolution (the concurrency guard)
    # ------------------------------------------------------------------

    def resolve_pending(
        self,
        approval_id: uuid.UUID,
        *,
        now: datetime,
        target_status: str,
        resolved_by: uuid.UUID,
        resolution_reason: str,
    ) -> ApprovalRequestRow | None:
        """Atomically move the *approval_id* request to *target_status*.

        Only a **pending, not-yet-expired** request transitions; the single
        ``UPDATE ... WHERE status = 'pending' AND expires_at > now`` is the
        concurrency guard — exactly one of several simultaneous humans wins.
        Returns the transitioned row, or ``None`` when nothing matched.

        The caller commits; ``updated_at`` is set explicitly because a Core
        statement does not trigger the ORM ``onupdate`` hook.
        """
        result = self.db.execute(
            update(ApprovalRequestRow)
            .where(
                ApprovalRequestRow.approval_id == approval_id,
                ApprovalRequestRow.status == "pending",
                ApprovalRequestRow.expires_at > now,
            )
            .values(
                status=target_status,
                resolved_at=now,
                resolved_by=resolved_by,
                resolution_reason=resolution_reason,
                updated_at=now,
            )
        )
        if result.rowcount == 0:
            return None
        return self.get_by_approval_id(approval_id)

    def expire_overdue(self, *, now: datetime) -> int:
        """Mark all still-pending, already-expired requests as ``expired``.

        Lazy reconciliation (no scheduler); run before reads and transitions
        so an overdue pending request never surfaces as actionable.  Returns
        how many rows were expired.
        """
        result = self.db.execute(
            update(ApprovalRequestRow)
            .where(
                ApprovalRequestRow.status == "pending",
                ApprovalRequestRow.expires_at <= now,
            )
            .values(
                status="expired",
                resolved_at=now,
                resolved_by=None,
                resolution_reason="approval request exceeded its pending TTL",
                updated_at=now,
            )
        )
        return int(result.rowcount or 0)

    # ------------------------------------------------------------------
    # Read-side
    # ------------------------------------------------------------------

    def count_rows(self, *, status: str | None = None) -> int:
        """Return the number of requests, optionally filtered by *status*."""
        stmt = select(func.count()).select_from(ApprovalRequestRow)
        if status is not None:
            stmt = stmt.where(ApprovalRequestRow.status == status)
        return int(self.db.scalar(stmt) or 0)

    def list_page(
        self,
        *,
        limit: int,
        offset: int,
        status: str | None = None,
    ) -> list[ApprovalRequestRow]:
        """Return one deterministic page of requests, newest first.

        Ordering is ``requested_at`` descending with ``id`` ascending as the
        tie-break (id is unique, so the order is total and page boundaries
        never drift).
        """
        stmt = select(ApprovalRequestRow).order_by(
            ApprovalRequestRow.requested_at.desc(),
            ApprovalRequestRow.id.asc(),
        )
        if status is not None:
            stmt = stmt.where(ApprovalRequestRow.status == status)
        return list(self.db.scalars(stmt.limit(limit).offset(offset)))

    def list_recent(
        self,
        *,
        limit: int,
        status: str | None = None,
    ) -> list[ApprovalRequestRow]:
        """Return the *limit* newest requests, optionally *status*-filtered."""
        stmt = select(ApprovalRequestRow).order_by(
            ApprovalRequestRow.requested_at.desc(),
            ApprovalRequestRow.id.asc(),
        )
        if status is not None:
            stmt = stmt.where(ApprovalRequestRow.status == status)
        return list(self.db.scalars(stmt.limit(limit)))

    def list_for_correlation(
        self,
        correlation_id: uuid.UUID,
        *,
        limit: int | None = None,
    ) -> list[ApprovalRequestRow]:
        """Return every approval request for *correlation_id*, newest first.

        Deterministic ordering mirrors the other reads (``requested_at``
        descending with ``id`` ascending as the tie-break).  Used by the
        V2.20 report context builder.
        """
        stmt = (
            select(ApprovalRequestRow)
            .where(ApprovalRequestRow.correlation_id == correlation_id)
            .order_by(
                ApprovalRequestRow.requested_at.desc(),
                ApprovalRequestRow.id.asc(),
            )
        )
        if limit is not None:
            stmt = stmt.limit(limit)
        return list(self.db.scalars(stmt))