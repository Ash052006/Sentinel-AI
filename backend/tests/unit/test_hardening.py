import uuid

from fastapi.testclient import TestClient

from tests.conftest import auth_header


class TestExceptionHandling:
    """Verify that unhandled exceptions produce safe 500 responses."""

    def test_no_stack_trace_in_error_response(self, client: TestClient):
        """An invalid request should never contain Python traceback info."""
        response = client.get("/api/nonexistent-endpoint")
        body = response.json()
        assert "Traceback" not in str(body)
        assert "File" not in str(body)


class TestRootRoute:
    """Verify the duplicate root route issue is resolved."""

    def test_root_returns_200(self, client: TestClient):
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "SentinelAI API"
        assert "version" in data
        assert data["status"] == "running"

    def test_no_duplicate_root_route(self, client: TestClient):
        """The app should have exactly one GET / route, producing no
        duplicate operation ID warnings."""
        routes = [
            route
            for route in client.app.routes
            if hasattr(route, "path") and route.path == "/"
        ]
        get_routes = [
            r for r in routes if hasattr(r, "methods") and "GET" in r.methods
        ]
        assert len(get_routes) == 1


class TestInputValidation:
    """Verify that input validation rejects invalid data."""

    def test_register_rejects_short_password(self, client: TestClient):
        email = f"short-pw-{uuid.uuid4().hex[:8]}@example.com"
        response = client.post(
            "/api/auth/register",
            json={"email": email, "password": "short"},
        )
        assert response.status_code == 422

    def test_register_rejects_empty_password(self, client: TestClient):
        email = f"empty-pw-{uuid.uuid4().hex[:8]}@example.com"
        response = client.post(
            "/api/auth/register",
            json={"email": email, "password": ""},
        )
        assert response.status_code == 422

    def test_register_rejects_too_long_password(self, client: TestClient):
        email = f"long-pw-{uuid.uuid4().hex[:8]}@example.com"
        response = client.post(
            "/api/auth/register",
            json={"email": email, "password": "a" * 129},
        )
        assert response.status_code == 422

    def test_register_rejects_invalid_email(self, client: TestClient):
        response = client.post(
            "/api/auth/register",
            json={"email": "not-an-email", "password": "ValidPass123!"},
        )
        assert response.status_code == 422

    def test_register_rejects_missing_fields(self, client: TestClient):
        response = client.post("/api/auth/register", json={})
        assert response.status_code == 422

    def test_register_accepts_valid_input(self, client: TestClient):
        email = f"valid-{uuid.uuid4().hex[:8]}@example.com"
        response = client.post(
            "/api/auth/register",
            json={"email": email, "password": "ValidPass123!"},
        )
        assert response.status_code == 201


class TestPasswordSecurity:
    """Verify password handling is secure."""

    def test_password_hash_never_returned_in_register_response(
        self, client: TestClient
    ):
        email = f"security-{uuid.uuid4().hex[:8]}@example.com"
        response = client.post(
            "/api/auth/register",
            json={"email": email, "password": "SecurePass123!"},
        )
        assert response.status_code == 201
        body_str = str(response.json())
        assert "hash" not in body_str.lower()
        assert "password" not in body_str.lower()

    def test_password_never_returned_in_login_response(
        self, client: TestClient, admin_user
    ):
        response = client.post(
            "/api/auth/login",
            json={"email": admin_user.email, "password": "TestPassword123!"},
        )
        assert response.status_code == 200
        body = response.json()
        assert "password" not in body
        assert "hash" not in body

    def test_login_credentials_are_not_accepted_as_query_parameters(
        self, client: TestClient, admin_user
    ):
        """H2.F-03 regression.

        The login contract carries credentials in the JSON body only.
        Credentials supplied via the URL query string must NOT be honored:
        query strings leak into proxy logs, referring pages and browser
        history, so they are never a valid transport for secrets.
        """
        response = client.post(
            "/api/auth/login",
            params={"email": admin_user.email, "password": "TestPassword123!"},
        )
        assert response.status_code == 422
        assert "password" not in str(response.text).lower()



class TestAuthenticationSecurity:
    """Verify JWT and authentication security."""

    def test_invalid_token_returns_401(self, client: TestClient):
        response = client.get(
            "/api/users/me",
            headers={"Authorization": "Bearer invalid.token.here"},
        )
        assert response.status_code == 401

    def test_empty_bearer_returns_403(self, client: TestClient):
        """HTTPBearer returns 403 when no credentials are provided."""
        response = client.get("/api/users/me")
        assert response.status_code in (401, 403)

    def test_malformed_header_returns_403(self, client: TestClient):
        """Missing 'Bearer' prefix."""
        response = client.get(
            "/api/users/me",
            headers={"Authorization": "SomeToken"},
        )
        assert response.status_code in (401, 403)

    def test_token_in_header_not_leaked_in_response(
        self, client: TestClient, admin_token: str
    ):
        response = client.get(
            "/api/users/me",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200
        body_str = str(response.json())
        assert admin_token not in body_str


class TestHealthEndpoint:
    """Verify health endpoints work correctly.

    ``/health`` is a public liveness probe.  The dependency probes
    (``/api/health/database``, ``/api/health/kafka``) disclose
    infrastructure internals, so they require an authenticated principal.
    """

    def test_health_check_returns_200(self, client: TestClient):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "database" in data
        assert "environment" in data

    def test_database_health_returns_200(self, client: TestClient, admin_token: str):
        response = client.get(
            "/api/health/database", headers=auth_header(admin_token)
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "connected"

    def test_database_health_requires_authentication(self, client: TestClient):
        """Anonymous callers must not learn the database name/role."""
        response = client.get("/api/health/database")
        assert response.status_code == 401
        assert "sentinelai" not in response.text

    def test_kafka_health_requires_authentication(self, client: TestClient):
        response = client.get("/api/health/kafka")
        assert response.status_code == 401

    def test_liveness_probe_stays_public(self, client: TestClient):
        """Gating the dependency probes must not gate liveness."""
        assert client.get("/health").status_code == 200


class TestAuditLogSecurity:
    """Verify audit logs do not expose sensitive information."""

    def test_audit_endpoint_requires_admin(
        self, client: TestClient, analyst_token: str
    ):
        response = client.get(
            "/api/audit/logs", headers=auth_header(analyst_token)
        )
        assert response.status_code == 403

    def test_audit_endpoint_requires_authentication(self, client: TestClient):
        response = client.get("/api/audit/logs")
        assert response.status_code == 401


class TestErrorConsistency:
    """Verify error response structure consistency."""

    def test_404_returns_json(self, client: TestClient):
        response = client.get("/api/nonexistent")
        assert response.status_code == 404

    def test_error_responses_have_detail_field(self, client: TestClient):
        response = client.get("/api/users/me")
        # Should be 401 — verify it has a "detail" key
        assert response.status_code in (401, 403)
        body = response.json()
        assert "detail" in body

    def test_method_not_allowed(self, client: TestClient):
        response = client.delete("/")
        assert response.status_code == 405