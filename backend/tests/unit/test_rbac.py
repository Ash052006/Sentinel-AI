import pytest
from fastapi.testclient import TestClient

from tests.conftest import auth_header


# ─────────────────────────────────────────────
# GET /api/users/me — returns role name
# ─────────────────────────────────────────────

class TestGetMe:
    def test_returns_role_name_for_admin(
        self, client: TestClient, admin_token: str, admin_user
    ):
        response = client.get(
            "/api/users/me", headers=auth_header(admin_token)
        )
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == admin_user.email
        assert data["is_active"] is True
        assert data["role"] == "admin"
        assert "role_id" not in data

    def test_returns_role_name_for_analyst(
        self, client: TestClient, analyst_token: str, analyst_user
    ):
        response = client.get(
            "/api/users/me", headers=auth_header(analyst_token)
        )
        assert response.status_code == 200
        assert response.json()["role"] == "analyst"


# ─────────────────────────────────────────────
# GET /api/users/admin-test — admin only
# ─────────────────────────────────────────────

class TestAdminOnlyEndpoint:
    def test_admin_succeeds(
        self, client: TestClient, admin_token: str
    ):
        """A: Valid JWT + admin → admin endpoint succeeds."""
        response = client.get(
            "/api/users/admin-test", headers=auth_header(admin_token)
        )
        assert response.status_code == 200
        assert response.json()["message"] == "Admin access granted"

    def test_analyst_forbidden(
        self, client: TestClient, analyst_token: str
    ):
        """B: Valid JWT + analyst → admin endpoint returns 403."""
        response = client.get(
            "/api/users/admin-test", headers=auth_header(analyst_token)
        )
        assert response.status_code == 403
        assert response.json()["detail"] == "Insufficient permissions"

    def test_ciso_forbidden(
        self, client: TestClient, ciso_token: str
    ):
        """C: Valid JWT + ciso → admin endpoint returns 403."""
        response = client.get(
            "/api/users/admin-test", headers=auth_header(ciso_token)
        )
        assert response.status_code == 403
        assert response.json()["detail"] == "Insufficient permissions"

    def test_no_token_unauthorized(self, client: TestClient):
        """D: No JWT → protected endpoint returns 401."""
        response = client.get("/api/users/admin-test")
        assert response.status_code == 401


# ─────────────────────────────────────────────
# GET /api/users/security-test — multi-role
# ─────────────────────────────────────────────

class TestMultiRoleEndpoint:
    def test_admin_succeeds(
        self, client: TestClient, admin_token: str
    ):
        """E: Valid JWT + admin → multi-role endpoint succeeds."""
        response = client.get(
            "/api/users/security-test", headers=auth_header(admin_token)
        )
        assert response.status_code == 200
        assert response.json()["message"] == "Security team access granted"

    def test_analyst_succeeds(
        self, client: TestClient, analyst_token: str
    ):
        """E: Valid JWT + analyst → multi-role endpoint succeeds."""
        response = client.get(
            "/api/users/security-test", headers=auth_header(analyst_token)
        )
        assert response.status_code == 200
        assert response.json()["message"] == "Security team access granted"

    def test_ciso_succeeds(
        self, client: TestClient, ciso_token: str
    ):
        """E: Valid JWT + ciso → multi-role endpoint succeeds."""
        response = client.get(
            "/api/users/security-test", headers=auth_header(ciso_token)
        )
        assert response.status_code == 200
        assert response.json()["message"] == "Security team access granted"

    def test_no_token_unauthorized(self, client: TestClient):
        """D: No JWT → protected endpoint returns 401."""
        response = client.get("/api/users/security-test")
        assert response.status_code == 401
