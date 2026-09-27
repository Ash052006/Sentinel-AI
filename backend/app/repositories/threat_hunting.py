"""Threat Hunting persistence repository — V2.19.

Thin data-access layer over the four persisted hunt tables.  No business
logic lives here: lifecycle transitions are CAS-style
(``WHERE status = <expected>`` so a hunt can only ever run once), and the
engine's artifacts are persisted as bounded batches.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Sequence

from sqlalchemy import Select, delete, func, select
from sqlalchemy.orm import Session

from app.models.threat_hunt import (
    ThreatHuntEvidenceRow,
    ThreatHuntFindingRow,
    ThreatHuntRow,
    ThreatHuntTimelineItemRow,
)
from app.schemas.threat_hunting import (
    ThreatHuntStatus,
    HUNT_DEFAULT_PAGE_SIZE,
    HUNT_MAX_PAGE_SIZE,
)


def _bounded_page(page: int, page_size: int) -> tuple[int, int]:
    page = max(1, page)
    page_size = min(max(1, page_size), HUNT_MAX_PAGE_SIZE)
    return page, page_size


def create_hunt(
    db: Session,
    *,
    hunt_id: uuid.UUID,
    name: str,
    description: str,
    hunt_type: str,
    start_time: datetime,
    end_time: datetime,
    created_by: uuid.UUID,
    created_by_role: str,
    filters: list[dict[str, Any]],
) -> ThreatHuntRow:
    """Persist a new hunt in the ``draft`` lifecycle state."""
    row = ThreatHuntRow(
        hunt_id=str(hunt_id),
        name=name,
        description=description,
        hunt_type=hunt_type,
        status=ThreatHuntStatus.DRAFT.value,
        start_time=start_time,
        end_time=end_time,
        created_by=created_by,
        created_by_role=created_by_role,
        filters=filters,
        result_count=0,
        finding_count=0,
        timeline_count=0,
    )
    db.add(row)
    db.flush()
    return row


def get_hunt(db: Session, hunt_id: uuid.UUID) -> ThreatHuntRow | None:
    return db.scalar(
        select(ThreatHuntRow).where(ThreatHuntRow.hunt_id == str(hunt_id))
    )


def list_hunts(
    db: Session,
    *,
    status: str | None = None,
    hunt_type: str | None = None,
    page: int = 1,
    page_size: int = HUNT_DEFAULT_PAGE_SIZE,
) -> tuple[list[ThreatHuntRow], int]:
    """Page hunt summaries newest-first."""
    page, page_size = _bounded_page(page, page_size)
    base: Select = select(ThreatHuntRow)
    count_base: Select = select(func.count(ThreatHuntRow.hunt_id))
    if status is not None:
        where = ThreatHuntRow.status == status
        base = base.where(where)
        count_base = count_base.where(where)
    if hunt_type is not None:
        where = ThreatHuntRow.hunt_type == hunt_type
        base = base.where(where)
        count_base = count_base.where(where)
    total = db.scalar(count_base) or 0
    items = list(
        db.scalars(
            # ``created_at`` alone is not a total order: rows sharing a
            # timestamp (fixed-clock runs, bulk imports, same-microsecond
            # inserts) can be returned in any order, so LIMIT/OFFSET may
            # repeat or skip a row across pages.  ``hunt_id`` is the
            # primary key and breaks the tie deterministically.
            base.order_by(
                ThreatHuntRow.created_at.desc(), ThreatHuntRow.hunt_id.desc()
            )
            .limit(page_size)
            .offset((page - 1) * page_size)
        ).all()
    )
    return items, total


def cas_transition(
    db: Session, hunt_id: uuid.UUID, expected: ThreatHuntStatus, target: ThreatHuntStatus
) -> bool:
    """Compare-and-swap lifecycle transition.

    Returns ``True`` only for the caller that wins the contest.  This is
    the single choke point that guarantees a hunt executes exactly once.
    """
    from sqlalchemy import update

    result = db.execute(
        update(ThreatHuntRow)
        .where(
            ThreatHuntRow.hunt_id == str(hunt_id),
            ThreatHuntRow.status == expected.value,
        )
        .values(status=target.value)
    )
    db.flush()
    return result.rowcount == 1


def stamp_run_started(db: Session, hunt_id: uuid.UUID, started_at: datetime) -> None:
    db.execute(
        ThreatHuntRow.__table__.update()
        .where(ThreatHuntRow.hunt_id == str(hunt_id))
        .values(started_at=started_at)
    )
    db.flush()


def stamp_run_finished(
    db: Session,
    hunt_id: uuid.UUID,
    *,
    target: ThreatHuntStatus,
    completed_at: datetime,
    result_count: int,
    finding_count: int,
    timeline_count: int,
    error_code: str | None = None,
    error_message: str | None = None,
) -> None:
    db.execute(
        ThreatHuntRow.__table__.update()
        .where(ThreatHuntRow.hunt_id == str(hunt_id))
        .values(
            status=target.value,
            completed_at=completed_at,
            result_count=result_count,
            finding_count=finding_count,
            timeline_count=timeline_count,
            error_code=error_code,
            error_message=error_message,
        )
    )
    db.flush()


def persist_artifacts(
    db: Session,
    *,
    hunt_id: uuid.UUID,
    evidence: Sequence[dict[str, Any]],
    findings: Sequence[dict[str, Any]],
    timeline_items: Sequence[dict[str, Any]],
) -> int:
    """Persist the completed run's evidence/findings/timeline in one batch.

    Insert-on-conflict semantics are intentionally skipped: artifacts are
    only ever written for a hunt that CAS-transitioned into ``running``, so
    the batch cannot collide with a previous run.
    """
    db.execute(
        delete(ThreatHuntEvidenceRow).where(ThreatHuntEvidenceRow.hunt_id == str(hunt_id))
    )
    db.execute(
        delete(ThreatHuntFindingRow).where(ThreatHuntFindingRow.hunt_id == str(hunt_id))
    )
    db.execute(
        delete(ThreatHuntTimelineItemRow).where(
            ThreatHuntTimelineItemRow.hunt_id == str(hunt_id)
        )
    )
    db.bulk_insert_mappings(ThreatHuntEvidenceRow, list(evidence))
    db.bulk_insert_mappings(ThreatHuntFindingRow, list(findings))
    db.bulk_insert_mappings(ThreatHuntTimelineItemRow, list(timeline_items))
    db.flush()
    return len(evidence) + len(findings) + len(timeline_items)


def list_evidence(
    db: Session, hunt_id: uuid.UUID, *, page: int, page_size: int
) -> tuple[list[ThreatHuntEvidenceRow], int]:
    page, page_size = _bounded_page(page, page_size)
    base = ThreatHuntEvidenceRow.hunt_id == str(hunt_id)
    total = db.scalar(
        select(func.count()).select_from(ThreatHuntEvidenceRow).where(base)
    ) or 0
    items = list(
        db.scalars(
            select(ThreatHuntEvidenceRow)
            .where(base)
            # ``observed_at`` alone is not a total order; tie-break on the
            # primary key so LIMIT/OFFSET cannot duplicate or skip a row.
            .order_by(
                ThreatHuntEvidenceRow.observed_at.asc().nullslast(),
                ThreatHuntEvidenceRow.evidence_id.asc(),
            )
            .limit(page_size)
            .offset((page - 1) * page_size)
        ).all()
    )
    return items, total


def list_findings(
    db: Session, hunt_id: uuid.UUID, *, page: int, page_size: int
) -> tuple[list[ThreatHuntFindingRow], int]:
    page, page_size = _bounded_page(page, page_size)
    base = ThreatHuntFindingRow.hunt_id == str(hunt_id)
    total = db.scalar(
        select(func.count()).select_from(ThreatHuntFindingRow).where(base)
    ) or 0
    items = list(
        db.scalars(
            select(ThreatHuntFindingRow)
            .where(base)
            .order_by(ThreatHuntFindingRow.finding_id.asc())
            .limit(page_size)
            .offset((page - 1) * page_size)
        ).all()
    )
    return items, total


def list_timeline(
    db: Session, hunt_id: uuid.UUID, *, page: int, page_size: int
) -> tuple[list[ThreatHuntTimelineItemRow], int]:
    page, page_size = _bounded_page(page, page_size)
    base = ThreatHuntTimelineItemRow.hunt_id == str(hunt_id)
    total = db.scalar(
        select(func.count()).select_from(ThreatHuntTimelineItemRow).where(base)
    ) or 0
    items = list(
        db.scalars(
            select(ThreatHuntTimelineItemRow)
            .where(base)
            .order_by(
                ThreatHuntTimelineItemRow.observed_at.asc().nullslast(),
                ThreatHuntTimelineItemRow.timeline_item_id.asc(),
            )
            .limit(page_size)
            .offset((page - 1) * page_size)
        ).all()
    )
    return items, total


def list_hunts_with_evidence_for_correlation(
    db: Session,
    correlation_id: uuid.UUID,
    *,
    limit: int = 20,
) -> list[tuple[ThreatHuntRow, list[ThreatHuntEvidenceRow]]]:
    """Return hunts citing *correlation_id* plus their matching evidence rows.

    Read-only helper backing the V2.21 attack-path projection.  A hunt is
    included when at least one persisted evidence row cites the correlation
    (via ``correlation_id``).  Deterministic ordering mirrors
    :func:`list_hunts`: ``start_time`` descending with ``hunt_id``
    ascending; evidence rows sort by ``observed_at`` ascending (nulls
    last) with ``evidence_id`` as the tie-break.  ``limit`` bounds the
    number of hunts returned (not the evidence rows).
    """
    correlation = str(correlation_id)
    evidence_rows = list(
        db.scalars(
            select(ThreatHuntEvidenceRow)
            .where(ThreatHuntEvidenceRow.correlation_id == correlation)
            .order_by(
                ThreatHuntEvidenceRow.observed_at.asc().nullslast(),
                ThreatHuntEvidenceRow.evidence_id.asc(),
            )
        ).all()
    )
    if not evidence_rows:
        return []
    hunt_ids = {row.hunt_id for row in evidence_rows if row.hunt_id}
    hunt_order: dict[str, ThreatHuntRow] = {}
    if hunt_ids:
        for row in db.scalars(
            select(ThreatHuntRow)
            .where(ThreatHuntRow.hunt_id.in_(hunt_ids))
            .order_by(
                ThreatHuntRow.start_time.desc(),
                ThreatHuntRow.hunt_id.asc(),
            )
        ):
            hunt_order[row.hunt_id] = row
    evidence_by_hunt: dict[str, list[ThreatHuntEvidenceRow]] = {}
    for row in evidence_rows:
        if row.hunt_id in hunt_order:
            evidence_by_hunt.setdefault(row.hunt_id, []).append(row)
    return [
        (hunt, evidence_by_hunt[hunt.hunt_id])
        for hunt in hunt_order.values()
    ][:limit]


def delete_hunt(db: Session, hunt_id: uuid.UUID) -> bool:
    result = db.execute(
        delete(ThreatHuntRow).where(ThreatHuntRow.hunt_id == str(hunt_id))
    )
    db.flush()
    return result.rowcount == 1


__all__ = [
    "create_hunt",
    "get_hunt",
    "list_hunts",
    "cas_transition",
    "stamp_run_started",
    "stamp_run_finished",
    "persist_artifacts",
    "list_evidence",
    "list_findings",
    "list_timeline",
    "list_hunts_with_evidence_for_correlation",
    "delete_hunt",
]