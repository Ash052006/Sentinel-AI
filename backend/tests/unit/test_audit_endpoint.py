import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.services.audit_service import log_action
from tests.conftest import auth_header


def _count_for_action(db: Session, action: str) -> int:
    return len(
        db.execute(select(AuditLog).where(AuditLog.action == action)).scalars().all()
    )


class TestAuditIntegration:
    def test_successful_login_creates_audit_record(
        self, client: TestClient, db_session: Session, admin_user
    ):
        before = _count_for_action(db_session, "auth.login.success")
        response = client.post(
            "/api/auth/login",
            json={"email": admin_user.email, "password": "TestPassword123!"},
        )
        assert response.status_code == 200
        assert _count_for_action(db_session, "auth.login.success") == before + 1

    def test_failed_login_creates_audit_record(
        self, client: TestClient, db_session: Session, admin_user
    ):
        before = _count_for_action(db_session, "auth.login.failed")
        response = client.post(
            "/api/auth/login",
            json={"email": admin_user.email, "password": "WrongPassword!"},
        )
        assert response.status_code == 401
        assert _count_for_action(db_session, "auth.login.failed") == before + 1

    def test_successful_registration_creates_audit_record(
        self, client: TestClient, db_session: Session
    ):
        before = _count_for_action(db_session, "auth.register.success")
        email = f"audit-register-{uuid.uuid4().hex[:8]}@example.com"
        response = client.post(
            "/api/auth/register",
            json={"email": email, "password": "TestPassword123!"},
        )
        assert response.status_code == 201
        assert _count_for_action(db_session, "auth.register.success") == before + 1

    def test_admin_can_retrieve_audit_logs(
        self, client: TestClient, admin_token: str
    ):
        response = client.get(
            "/api/audit/logs", headers=auth_header(admin_token)
        )
        assert response.status_code == 200
        body = response.json()
        assert "items" in body
        assert "total" in body
        assert body["skip"] == 0
        assert body["limit"] == 50
        # Newest records first
        created = [item["created_at"] for item in body["items"]]
        assert created == sorted(created, reverse=True)

    def test_analyst_cannot_retrieve_audit_logs(
        self, client: TestClient, analyst_token: str
    ):
        response = client.get(
            "/api/audit/logs", headers=auth_header(analyst_token)
        )
        assert response.status_code == 403
        assert response.json()["detail"] == "Insufficient permissions"

    def test_unauthenticated_user_cannot_retrieve_audit_logs(
        self, client: TestClient
    ):
        response = client.get("/api/audit/logs")
        assert response.status_code == 401

    def test_audit_records_do_not_expose_sensitive_material(
        self, client: TestClient, db_session: Session, admin_token: str, admin_user
    ):
        # Ensure at least one sensitive action is recorded.
        client.post(
            "/api/auth/login",
            json={"email": admin_user.email, "password": "TestPassword123!"},
        )

        response = client.get(
            "/api/audit/logs?limit=100", headers=auth_header(admin_token)
        )
        assert response.status_code == 200

        for item in response.json()["items"]:
            serialized = str(item)
            assert "password" not in serialized.lower()
            assert "jwt" not in serialized.lower()
            assert "access_token" not in serialized.lower()

    def test_pagination_works(
        self, client: TestClient, db_session: Session, admin_token: str
    ):
        # Seed some records for deterministic pagination behavior.
        for i in range(3):
            log_action(db=db_session, action=f"pagination.test.{i}")

        response = client.get(
            "/api/audit/logs?skip=0&limit=2", headers=auth_header(admin_token)
        )
        assert response.status_code == 200
        body = response.json()
        assert len(body["items"]) == 2
        assert body["skip"] == 0
        assert body["limit"] == 2

        second = client.get(
            "/api/audit/logs?skip=2&limit=2", headers=auth_header(admin_token)
        )
        assert second.status_code == 200
        second_body = second.json()
        assert len(second_body["items"]) >= 1
        assert second_body["skip"] == 2
        assert second_body["limit"] == 2
