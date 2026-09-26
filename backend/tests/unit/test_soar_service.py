"""SOAR service tests (V2.18) — persistence through the repository.

Runs the full service against the same SQLAlchemy models used in
production (PostgreSQL ``JSONB`` rendered as JSON for SQLite via the
test-only type-compiler adapter; see :mod:`tests.unit.soar_test_helpers`).

Covered here: idempotent seed sync, execute/persist/read/cancel lifecycle,
idempotency dedup at the persistence layer, status-filtered listing,
dry-run with zero persistence, and the RBAC role surfaces.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.dialects.sqlite.base import SQLiteTypeCompiler
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

if not hasattr(SQLiteTypeCompiler, "visit_JSONB"):
    SQLiteTypeCompiler.visit_JSONB = lambda self, type_, **kw: "JSON"  # noqa: E731

from app.database.postgres.base import Base
from app.models.soar_execution import SoarExecutionRow
from app.models.soar_playbook import SoarPlaybookRow
from app.models.soar_playbook_version import SoarPlaybookVersionRow
from app.models.soar_step_execution import SoarStepExecutionRow
from app.schemas.policy_decision import PolicyDecisionStatus
from app.schemas.soar import SoarExecutionStatus
from app.services.soar import (
    SOAR_MUTATION_ROLES,
    SOAR_READ_ROLES,
    SoarConflictError,
    SoarNotFoundError,
    SoarService,
    SoarValidationError,
)
from tests.unit.soar_test_helpers import a_request

TZ = timezone.utc
FIXED = datetime(2026, 9, 24, 9, 0, 0, tzinfo=TZ)

ACTOR_ID = uuid.UUID("11111111-2222-3333-4444-555555555555")
ACTOR_ROLE = "admin"


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


@pytest.fixture()
def service() -> SoarService:
    return SoarService()


def _count(db, model) -> int:
    return int(db.scalar(select(func.count()).select_from(model)))


class TestSeedSync:
    def test_seed_is_idempotent(self, db, service) -> None:
        assert service.sync_seed_playbooks(db, clock=lambda: FIXED) == 7
        assert service.sync_seed_playbooks(db, clock=lambda: FIXED) == 0
        assert _count(db, SoarPlaybookRow) == 7
        assert _count(db, SoarPlaybookVersionRow) == 7
        # the block_ip seed is the documented single-step playbook
        row = db.execute(
            select(SoarPlaybookRow).where(SoarPlaybookRow.playbook_id == "block_ip")
        ).scalar_one()
        assert row.enabled is True
        assert len(row.steps) == 1

    def test_list_playbooks_persists_seed(self, db, service) -> None:
        page = service.list_playbooks(db, clock=lambda: FIXED)
        assert page.total == 7
        assert page.page == 1
        ids = {item.playbook_id for item in page.items}
        assert ids == {
            "block_ip",
            "block_domain",
            "quarantine_file",
            "disable_account",
            "terminate_session",
            "isolate_endpoint",
            "endpoint_containment",
        }

    def test_get_playbook_by_id(self, db, service) -> None:
        record = service.get_playbook(db, "block_ip", clock=lambda: FIXED)
        assert record.playbook_id == "block_ip"
        assert record.steps[0].operation.value == "block_ip"
        assert record.version == "1.0.0"

    def test_get_unknown_playbook_404(self, db, service) -> None:
        with pytest.raises(SoarNotFoundError):
            service.get_playbook(db, "ghost", clock=lambda: FIXED)


class TestExecuteLifecycle:
    def test_execute_allowed_persists_succeeded(self, db, service) -> None:
        record = service.execute(
            db,
            a_request(),
            actor_user_id=ACTOR_ID,
            actor_role=ACTOR_ROLE,
            clock=lambda: FIXED,
        )
        assert record.status is SoarExecutionStatus.SUCCEEDED
        assert record.created_by_role == ACTOR_ROLE
        assert record.created_by == ACTOR_ID
        assert len(record.steps) == 1
        assert _count(db, SoarExecutionRow) == 1
        assert _count(db, SoarStepExecutionRow) == 1

        fetched = service.get_execution(db, record.execution_id)
        assert fetched.execution_id == record.execution_id
        assert fetched.status is SoarExecutionStatus.SUCCEEDED
        assert len(fetched.steps) == 1

    def test_duplicate_submission_never_duplicated(self, db, service) -> None:
        body = a_request()
        first = service.execute(
            db,
            body,
            actor_user_id=ACTOR_ID,
            actor_role=ACTOR_ROLE,
            clock=lambda: FIXED,
        )
        second = service.execute(
            db,
            body,
            actor_user_id=ACTOR_ID,
            actor_role=ACTOR_ROLE,
            clock=lambda: FIXED,
        )
        assert first.execution_id == second.execution_id
        assert _count(db, SoarExecutionRow) == 1
        assert _count(db, SoarStepExecutionRow) == 1

    def test_denied_decision_persists_rejected_without_steps(self, db, service) -> None:
        record = service.execute(
            db,
            a_request(status=PolicyDecisionStatus.DENIED),
            actor_user_id=ACTOR_ID,
            actor_role=ACTOR_ROLE,
            clock=lambda: FIXED,
        )
        assert record.status is SoarExecutionStatus.REJECTED
        assert record.error_code == "POLICY_DENIED"
        assert record.steps == []
        assert _count(db, SoarExecutionRow) == 1
        assert _count(db, SoarStepExecutionRow) == 0

    def test_pending_approval_records_pending(self, db, service) -> None:
        record = service.execute(
            db,
            a_request(status=PolicyDecisionStatus.REQUIRES_APPROVAL),
            actor_user_id=ACTOR_ID,
            actor_role=ACTOR_ROLE,
            clock=lambda: FIXED,
        )
        assert record.status is SoarExecutionStatus.PENDING
        assert record.error_code == "APPROVAL_NOT_GIVEN"
        assert _count(db, SoarStepExecutionRow) == 0

    def test_unknown_playbook_is_422_style_validation(self, db, service) -> None:
        with pytest.raises(SoarValidationError, match="no registered playbook"):
            service.execute(
                db,
                a_request(playbook_id="ghost"),
                actor_user_id=ACTOR_ID,
                actor_role=ACTOR_ROLE,
                clock=lambda: FIXED,
            )


class TestListExecutions:
    def test_list_newest_first_with_steps(self, db, service) -> None:
        for _ in range(3):
            service.execute(
                db,
                a_request(),
                actor_user_id=ACTOR_ID,
                actor_role=ACTOR_ROLE,
                clock=lambda: FIXED,
            )
        page = service.list_executions(db)
        assert page.total == 3
        assert len(page.items) == 3
        assert all(len(item.steps) == 1 for item in page.items)

    def test_status_filter(self, db, service) -> None:
        service.execute(
            db,
            a_request(status=PolicyDecisionStatus.DENIED),
            actor_user_id=ACTOR_ID,
            actor_role=ACTOR_ROLE,
            clock=lambda: FIXED,
        )
        service.execute(
            db,
            a_request(),
            actor_user_id=ACTOR_ID,
            actor_role=ACTOR_ROLE,
            clock=lambda: FIXED,
        )
        rejected = service.list_executions(db, status=SoarExecutionStatus.REJECTED)
        assert rejected.total == 1
        assert rejected.items[0].error_code == "POLICY_DENIED"
        succeeded = service.list_executions(db, status=SoarExecutionStatus.SUCCEEDED)
        assert succeeded.total == 1

    def test_page_bounds(self, db, service) -> None:
        with pytest.raises(SoarValidationError):
            service.list_executions(db, page=0)
        with pytest.raises(SoarValidationError):
            service.list_executions(db, page_size=201)


class TestCancel:
    def test_cancel_pending(self, db, service) -> None:
        record = service.execute(
            db,
            a_request(status=PolicyDecisionStatus.REQUIRES_APPROVAL),
            actor_user_id=ACTOR_ID,
            actor_role=ACTOR_ROLE,
            clock=lambda: FIXED,
        )
        cancelled = service.cancel(
            db,
            record.execution_id,
            actor_user_id=ACTOR_ID,
            actor_role=ACTOR_ROLE,
            clock=lambda: FIXED,
        )
        assert cancelled.status is SoarExecutionStatus.CANCELLED
        assert cancelled.completed_at == FIXED

    def test_cancel_is_idempotent_for_cancelled(self, db, service) -> None:
        record = service.execute(
            db,
            a_request(status=PolicyDecisionStatus.REQUIRES_APPROVAL),
            actor_user_id=ACTOR_ID,
            actor_role=ACTOR_ROLE,
            clock=lambda: FIXED,
        )
        service.cancel(
            db,
            record.execution_id,
            actor_user_id=ACTOR_ID,
            actor_role=ACTOR_ROLE,
            clock=lambda: FIXED,
        )
        again = service.cancel(
            db,
            record.execution_id,
            actor_user_id=ACTOR_ID,
            actor_role=ACTOR_ROLE,
            clock=lambda: FIXED,
        )
        assert again.status is SoarExecutionStatus.CANCELLED

    def test_cancel_terminal_execution_conflicts(self, db, service) -> None:
        record = service.execute(
            db,
            a_request(),
            actor_user_id=ACTOR_ID,
            actor_role=ACTOR_ROLE,
            clock=lambda: FIXED,
        )
        with pytest.raises(SoarConflictError, match="cannot be cancelled"):
            service.cancel(
                db,
                record.execution_id,
                actor_user_id=ACTOR_ID,
                actor_role=ACTOR_ROLE,
                clock=lambda: FIXED,
            )

    def test_cancel_unknown_execution_404(self, db, service) -> None:
        with pytest.raises(SoarNotFoundError):
            service.cancel(
                db,
                uuid.uuid4(),
                actor_user_id=ACTOR_ID,
                actor_role=ACTOR_ROLE,
                clock=lambda: FIXED,
            )

    def test_get_unknown_execution_404(self, db, service) -> None:
        with pytest.raises(SoarNotFoundError):
            service.get_execution(db, uuid.uuid4())


class TestDryRun:
    def test_dry_run_persists_nothing(self, db, service) -> None:
        result = service.dry_run(
            db,
            a_request(),
            actor_user_id=ACTOR_ID,
            actor_role=ACTOR_ROLE,
            clock=lambda: FIXED,
        )
        assert result.simulated is True
        assert result.status is SoarExecutionStatus.SUCCEEDED
        assert _count(db, SoarExecutionRow) == 0
        assert _count(db, SoarStepExecutionRow) == 0

    def test_dry_run_rejected_projection(self, db, service) -> None:
        result = service.dry_run(
            db,
            a_request(status=PolicyDecisionStatus.DENIED),
            actor_user_id=ACTOR_ID,
            actor_role=ACTOR_ROLE,
            clock=lambda: FIXED,
        )
        assert result.status is SoarExecutionStatus.REJECTED
        assert result.steps == []


class TestRoleSurfaces:
    def test_read_and_mutation_role_sets(self) -> None:
        assert set(SOAR_READ_ROLES) == {"admin", "analyst", "ciso"}
        assert set(SOAR_MUTATION_ROLES) == {"admin"}