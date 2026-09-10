import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.services.audit_service import log_action


def _count_logs(db: Session) -> int:
    return db.execute(select(func.count(AuditLog.id))).scalar_one()


class TestAuditService:
    def test_log_action_creates_record(
        self, db_session: Session, admin_user
    ):
        """The service persists an audit record with provided fields."""
        before = _count_logs(db_session)

        entry = log_action(
            db=db_session,
            action="test.action",
            user_id=admin_user.id,
            resource="test-resource",
            details="some detail",
            ip_address="203.0.113.1",
        )

        assert entry is not None
        assert entry.id is not None
        assert entry.action == "test.action"
        assert entry.user_id == admin_user.id
        assert entry.resource == "test-resource"
        assert entry.details == "some detail"
        assert entry.ip_address == "203.0.113.1"
        assert _count_logs(db_session) == before + 1

    def test_log_action_allows_nullable_fields(self, db_session: Session):
        """All optional fields default to None without error."""
        before = _count_logs(db_session)

        entry = log_action(
            db=db_session,
            action="test.minimal",
        )

        assert entry is not None
        assert entry.user_id is None
        assert entry.resource is None
        assert entry.details is None
        assert entry.ip_address is None
        assert _count_logs(db_session) == before + 1

    def test_log_action_persists_immediately(self, db_session: Session):
        """A record written by a committed service call is queryable via a new
        session, proving it is committed and not pending on an open tx."""
        entry = log_action(
            db=db_session,
            action="test.durable",
            details="durable record",
        )

        assert entry is not None

        # New session reads it back.
        from app.database.postgres.session import SessionLocal as TestSessionLocal

        with TestSessionLocal() as fresh:
            found = fresh.execute(
                select(AuditLog).where(AuditLog.id == entry.id)
            ).scalar_one()
            assert found.action == "test.durable"

    def test_log_action_returns_none_and_rolls_back_on_failure(
        self, db_session: Session, monkeypatch
    ):
        """The service must not raise; it returns None and rolls back on failure."""
        before = _count_logs(db_session)

        def fail_commit():
            raise RuntimeError("db unavailable")

        monkeypatch.setattr(db_session, "commit", fail_commit)

        result = log_action(
            db=db_session,
            action="test.failure",
        )

        assert result is None
        # Nothing was committed; count unchanged.
        assert _count_logs(db_session) == before
