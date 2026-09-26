"""SOAR persistence + query repository (V2.18).

Write-side operations back the SOAR service: idempotent playbook
registration (seed sync), immutable execution persistence, and bounded
step persistence.

Read-side operations back the SOAR query layer: playbook detail/pages,
execution detail/pages, and deterministic page boundaries.

Contract rules honoured here:

* ``execution_id`` and ``idempotency_key`` are both unique: an identical,
  already-processed governed submission is never re-executed.
* The repository does **not** commit.  Transaction boundaries are owned by
  the calling service so one execution batch commits atomically with its
  step rows.
* Reads are deterministic: every list orders by ``created_at`` descending
  with ``id`` ascending as the two-key tie-break so page boundaries never
  drift.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.soar_execution import SoarExecutionRow
from app.models.soar_playbook import SoarPlaybookRow
from app.models.soar_playbook_version import SoarPlaybookVersionRow
from app.models.soar_step_execution import SoarStepExecutionRow


class SoarRepository:
    """Data-access layer for SOAR persistence."""

    def __init__(self, db: Session) -> None:
        self.db = db

    # ------------------------------------------------------------------
    # Generic
    # ------------------------------------------------------------------

    def add(self, entity: object) -> None:
        """Stage *entity* for insertion.  The caller owns the transaction."""
        self.db.add(entity)

    # ------------------------------------------------------------------
    # Playbooks
    # ------------------------------------------------------------------

    def get_playbook_by_id(self, playbook_id: str) -> SoarPlaybookRow | None:
        return self.db.scalar(
            select(SoarPlaybookRow).where(SoarPlaybookRow.playbook_id == playbook_id)
        )

    def get_playbook_version_row(
        self,
        playbook_id: str,
        version: str,
    ) -> SoarPlaybookVersionRow | None:
        return self.db.scalar(
            select(SoarPlaybookVersionRow).where(
                SoarPlaybookVersionRow.playbook_id == playbook_id,
                SoarPlaybookVersionRow.version == version,
            )
        )

    def get_playbook_version_by_version_id(
        self,
        version_id: uuid.UUID,
    ) -> SoarPlaybookVersionRow | None:
        return self.db.scalar(
            select(SoarPlaybookVersionRow).where(
                SoarPlaybookVersionRow.version_id == version_id
            )
        )

    def count_playbooks(self) -> int:
        return int(self.db.scalar(select(func.count()).select_from(SoarPlaybookRow)) or 0)

    def list_playbooks(
        self,
        *,
        limit: int,
        offset: int,
    ) -> list[SoarPlaybookRow]:
        return list(
            self.db.scalars(
                select(SoarPlaybookRow)
                .order_by(SoarPlaybookRow.created_at.desc(), SoarPlaybookRow.id.asc())
                .limit(limit)
                .offset(offset)
            )
        )

    # ------------------------------------------------------------------
    # Executions
    # ------------------------------------------------------------------

    def get_execution_by_execution_id(
        self,
        execution_id: uuid.UUID,
    ) -> SoarExecutionRow | None:
        return self.db.scalar(
            select(SoarExecutionRow).where(
                SoarExecutionRow.execution_id == execution_id
            )
        )

    def get_execution_by_idempotency_key(
        self,
        idempotency_key: str,
    ) -> SoarExecutionRow | None:
        return self.db.scalar(
            select(SoarExecutionRow).where(
                SoarExecutionRow.idempotency_key == idempotency_key
            )
        )

    def count_executions(self, *, status: str | None = None) -> int:
        stmt = select(func.count()).select_from(SoarExecutionRow)
        if status is not None:
            stmt = stmt.where(SoarExecutionRow.status == status)
        return int(self.db.scalar(stmt) or 0)

    def list_executions(
        self,
        *,
        limit: int,
        offset: int,
        status: str | None = None,
    ) -> list[SoarExecutionRow]:
        stmt = select(SoarExecutionRow).order_by(
            SoarExecutionRow.created_at.desc(),
            SoarExecutionRow.id.asc(),
        )
        if status is not None:
            stmt = stmt.where(SoarExecutionRow.status == status)
        return list(self.db.scalars(stmt.limit(limit).offset(offset)))

    def get_execution_steps(
        self,
        execution_row_id: uuid.UUID,
    ) -> list[SoarStepExecutionRow]:
        return list(
            self.db.scalars(
                select(SoarStepExecutionRow)
                .where(SoarStepExecutionRow.execution_id == execution_row_id)
                .order_by(SoarStepExecutionRow.step_number.asc())
            )
        )

    def list_for_correlation(
        self,
        correlation_id: uuid.UUID,
        *,
        limit: int | None = None,
    ) -> list[SoarExecutionRow]:
        """Return every execution for *correlation_id*, newest first.

        Deterministic ordering mirrors the other reads (``created_at``
        descending with ``id`` ascending as the tie-break).  Used by the
        V2.20 report context builder.
        """
        stmt = (
            select(SoarExecutionRow)
            .where(SoarExecutionRow.correlation_id == correlation_id)
            .order_by(
                SoarExecutionRow.created_at.desc(),
                SoarExecutionRow.id.asc(),
            )
        )
        if limit is not None:
            stmt = stmt.limit(limit)
        return list(self.db.scalars(stmt))