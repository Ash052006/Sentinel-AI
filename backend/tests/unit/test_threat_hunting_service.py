"""Threat Hunting service tests (V2.19) — lifecycle & persistence.

Runs the full ``ThreatHuntService`` against the same SQLAlchemy models for
PostgreSQL (SQLite-rendered; see :mod:`tests.unit.threat_hunt_test_helpers`).
Covers the create/list/get lifecycle, run-once CAS semantics (completed and
failed terminal states), cancel of a non-terminal draft, the bounded read
pages, page clamps, and the audit trail each transition writes.
"""

from __future__ import annotations

import uuid
from datetime import timedelta, timezone

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database.postgres.base import Base
from app.models.audit_log import AuditLog
from app.models.threat_hunt import (
    ThreatHuntEvidenceRow,
    ThreatHuntFindingRow,
    ThreatHuntRow,
    ThreatHuntTimelineItemRow,
)
from app.schemas.threat_hunting import (
    HUNT_MAX_PAGE_SIZE,
    HuntType,
    ThreatHuntCreate,
)
from app.services.threat_hunting import ThreatHuntService
from app.services.threat_hunting.errors import (
    HuntAlreadyCancelledError,
    HuntAlreadyCompletedError,
    HuntAlreadyFailedError,
    HuntLimitError,
    HuntNotFoundError,
    HuntStateError,
)
from tests.unit.threat_hunt_test_helpers import (
    NOW,
    ACTOR_ID,
    a_detection,
    seed_actor,
)

START = NOW - timedelta(days=1)
END = NOW + timedelta(days=1)


@pytest.fixture()
def db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = Session(engine)
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _create_payload(**overrides) -> ThreatHuntCreate:
    payload: dict = {
        "name": "Draft review hunt",
        "hunt_type": HuntType.DETECTION_REVIEW.value,
        "description": "Revisit persisted detection history.",
        "start_time": START,
        "end_time": END,
        "filters": [],
    }
    payload.update(overrides)
    return ThreatHuntCreate(**payload)


class TestLifecycle:
    def test_create_persists_draft_with_filters(
        self, db: Session
    ) -> None:
        actor = seed_actor(db)
        from app.schemas.threat_hunting import HuntFilter, HuntFilterField, HuntOperator

        payload = _create_payload(
            filters=[
                HuntFilter(
                    field=HuntFilterField.SEVERITY.value,
                    operator=HuntOperator.IN.value,
                    values=["high", "critical"],
                )
            ]
        )
        detail = ThreatHuntService.create(db, actor=actor, payload=payload)

        assert detail.status.value == "draft"
        assert detail.hunt_type == HuntType.DETECTION_REVIEW
        assert detail.description == payload.description
        assert len(detail.filters) == 1
        assert detail.filters[0].field.value == "severity"
        assert detail.filters[0].set_values == ["high", "critical"]
        assert detail.result_count == 0
        assert detail.finding_count == 0
        assert detail.start_time.replace(tzinfo=timezone.utc) == START

        row = db.get(ThreatHuntRow, str(detail.hunt_id))
        assert row is not None
        assert row.created_by == actor.id

    def test_get_unknown_hunt_404(self, db: Session) -> None:
        actor = seed_actor(db)
        with pytest.raises(HuntNotFoundError):
            ThreatHuntService.get(db, actor=actor, hunt_id=uuid.uuid4())

    def test_run_empty_window_completes_with_summary_finding(
        self, db: Session
    ) -> None:
        actor = seed_actor(db)
        detail = ThreatHuntService.create(
            db, actor=actor, payload=_create_payload()
        )
        started = ThreatHuntService.run(db, actor=actor, hunt_id=detail.hunt_id)

        assert started.status.value == "completed"
        assert started.started_at is not None
        assert started.completed_at is not None
        assert started.error_code is None
        assert started.result_count == 0
        assert started.timeline_count == 0

        findings = ThreatHuntService.list_findings(
            db, actor=actor, hunt_id=detail.hunt_id
        )
        assert findings.total == 1  # always-present summary finding
        assert findings.items[0].context["evidence_count"] == 0

    def test_run_persists_evidence_findings_timeline(
        self, db: Session
    ) -> None:
        actor = seed_actor(db)
        a_detection(
            db, event_id=uuid.uuid4(), detection_id=uuid.uuid4(),
            rule_id="RULE-A", severity="high", at=NOW,
        )
        db.commit()
        detail = ThreatHuntService.create(
            db, actor=actor, payload=_create_payload()
        )
        completed = ThreatHuntService.run(db, actor=actor, hunt_id=detail.hunt_id)

        assert completed.status.value == "completed"
        assert completed.result_count == 1
        assert completed.timeline_count == 1
        # 1 rule finding + summary
        finding_page = ThreatHuntService.list_findings(
            db, actor=actor, hunt_id=detail.hunt_id, page_size=50
        )
        assert finding_page.total == 2

        evidence = ThreatHuntService.list_evidence(
            db, actor=actor, hunt_id=detail.hunt_id
        )
        assert evidence.total == 1
        assert evidence.items[0].provenance == "detected"
        assert evidence.items[0].severity == "high"
        assert evidence.items[0].reference_id is not None

        timeline = ThreatHuntService.list_timeline(
            db, actor=actor, hunt_id=detail.hunt_id
        )
        assert timeline.total == 1
        assert timeline.items[0].evidence_type.value == "detection"
        assert timeline.items[0].evidence_id == evidence.items[0].evidence_id

    def test_rerun_completed_hunt_is_conflict(self, db: Session) -> None:
        actor = seed_actor(db)
        detail = ThreatHuntService.create(
            db, actor=actor, payload=_create_payload()
        )
        ThreatHuntService.run(db, actor=actor, hunt_id=detail.hunt_id)
        with pytest.raises(HuntAlreadyCompletedError):
            ThreatHuntService.run(db, actor=actor, hunt_id=detail.hunt_id)

    def test_cancel_draft_then_cancel_conflict(self, db: Session) -> None:
        actor = seed_actor(db)
        detail = ThreatHuntService.create(
            db, actor=actor, payload=_create_payload()
        )
        cancelled = ThreatHuntService.cancel(
            db, actor=actor, hunt_id=detail.hunt_id
        )
        assert cancelled.status.value == "cancelled"
        with pytest.raises(HuntAlreadyCancelledError):
            ThreatHuntService.cancel(db, actor=actor, hunt_id=detail.hunt_id)

    def test_run_cancelled_hunt_is_conflict(self, db: Session) -> None:
        actor = seed_actor(db)
        detail = ThreatHuntService.create(
            db, actor=actor, payload=_create_payload()
        )
        ThreatHuntService.cancel(db, actor=actor, hunt_id=detail.hunt_id)
        with pytest.raises(HuntAlreadyCancelledError):
            ThreatHuntService.run(db, actor=actor, hunt_id=detail.hunt_id)

    def test_cancel_completed_hunt_is_state_conflict(self, db: Session) -> None:
        actor = seed_actor(db)
        detail = ThreatHuntService.create(
            db, actor=actor, payload=_create_payload()
        )
        ThreatHuntService.run(db, actor=actor, hunt_id=detail.hunt_id)
        with pytest.raises(HuntStateError):
            ThreatHuntService.cancel(db, actor=actor, hunt_id=detail.hunt_id)

    def test_run_unknown_hunt_not_found(self, db: Session) -> None:
        actor = seed_actor(db)
        with pytest.raises(HuntNotFoundError):
            ThreatHuntService.run(db, actor=actor, hunt_id=uuid.uuid4())

    def test_limit_exceeded_fails_hunt_and_blocks_rerun(
        self, db: Session
    ) -> None:
        actor = seed_actor(db)
        from app.schemas.threat_hunting import HUNT_SURFACE_CAP

        for i in range(HUNT_SURFACE_CAP + 1):
            a_detection(
                db, event_id=uuid.uuid4(), detection_id=uuid.uuid4(),
                rule_id=f"RULE-{i}", at=NOW + timedelta(seconds=i),
            )
        db.commit()
        detail = ThreatHuntService.create(
            db, actor=actor, payload=_create_payload()
        )

        with pytest.raises(HuntLimitError):
            ThreatHuntService.run(db, actor=actor, hunt_id=detail.hunt_id)

        failed = ThreatHuntService.get(db, actor=actor, hunt_id=detail.hunt_id)
        assert failed.status.value == "failed"
        assert failed.error_code == "LIMITS_EXCEEDED"
        assert failed.error_message and "matched" in failed.error_message
        assert failed.completed_at is not None

        with pytest.raises(HuntAlreadyFailedError):
            ThreatHuntService.run(db, actor=actor, hunt_id=detail.hunt_id)


class TestListing:
    def test_list_filters_by_status_and_hunt_type(self, db: Session) -> None:
        actor = seed_actor(db)
        draft = ThreatHuntService.create(
            db, actor=actor, payload=_create_payload(name="draft-hunt")
        )
        other_type = ThreatHuntService.create(
            db,
            actor=actor,
            payload=_create_payload(
                name="auth-hunt",
                hunt_type=HuntType.AUTHENTICATION_ANOMALY.value,
            ),
        )
        ThreatHuntService.cancel(db, actor=actor, hunt_id=draft.hunt_id)

        from app.schemas.threat_hunting import ThreatHuntStatus

        cancelled_page = ThreatHuntService.list(
            db, actor=actor, status_filter=ThreatHuntStatus.CANCELLED
        )
        assert cancelled_page.total == 1
        assert cancelled_page.items[0].hunt_id == draft.hunt_id
        draft_ref = ThreatHuntService.get(
            db, actor=actor, hunt_id=other_type.hunt_id
        )
        assert draft_ref is not None

        type_page = ThreatHuntService.list(
            db, actor=actor, hunt_type_filter=HuntType.AUTHENTICATION_ANOMALY
        )
        assert type_page.total == 1
        assert type_page.items[0].hunt_id == other_type.hunt_id

    def test_page_size_is_clamped(self, db: Session) -> None:
        actor = seed_actor(db)
        ThreatHuntService.create(db, actor=actor, payload=_create_payload())
        page = ThreatHuntService.list(
            db, actor=actor, page=1, page_size=9999
        )
        assert page.page_size == HUNT_MAX_PAGE_SIZE


class TestAuditTrail:
    def test_transitions_are_audited(self, db: Session) -> None:
        actor = seed_actor(db)
        detail = ThreatHuntService.create(
            db, actor=actor, payload=_create_payload()
        )
        ThreatHuntService.run(db, actor=actor, hunt_id=detail.hunt_id)
        ThreatHuntService.cancel(
            db,
            actor=actor,
            hunt_id=(
                ThreatHuntService.create(
                    db, actor=actor, payload=_create_payload(name="c")
                )
            ).hunt_id,
        )

        actions = list(
            db.execute(
                select(AuditLog.action)
                .where(AuditLog.resource == "threat_hunts")
                .distinct()
            ).scalars()
        )
        assert "threat_hunt.created" in actions
        assert "threat_hunt.executed" in actions
        assert "threat_hunt.completed" in actions
        assert "threat_hunt.cancelled" in actions

    def test_versioned_counts_empty_before_run(self, db: Session) -> None:
        actor = seed_actor(db)
        detail = ThreatHuntService.create(
            db, actor=actor, payload=_create_payload()
        )
        row = db.get(ThreatHuntRow, str(detail.hunt_id))
        assert row.result_count == 0
        assert row.finding_count == 0
        count = db.scalar(
            select(func.count()).select_from(ThreatHuntEvidenceRow)
        ) or 0
        assert count == 0
        count = db.scalar(
            select(func.count()).select_from(ThreatHuntFindingRow)
        ) or 0
        assert count == 0
        count = db.scalar(
            select(func.count()).select_from(ThreatHuntTimelineItemRow)
        ) or 0
        assert count == 0