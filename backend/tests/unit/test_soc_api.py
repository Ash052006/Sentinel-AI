"""Natural Language SOC API-layer tests (Step 23).

The Singular HTTP surface ``POST /api/soc/query`` is exercised through the
full stack the project's API tests already use — JWT -> FastAPI
(``TestClient(app)``) -> route -> engine:

* authentication and RBAC enforcement (admin/analyst/ciso allowed, all
  other authenticated roles denied);
* request-body validation (blank / oversized / extra fields -> 422);
* sanitized error mapping on the whole SOC error hierarchy;
* the structured response envelope over the wire;
* the route wired to a *real* :class:`SOCQueryService` end to end (with a
  fake parser + stub executor table, no database or network).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

import app.api.routes.soc as soc_routes
from app.core.security import create_access_token, hash_password
from app.models.role import Role
from app.models.user import User
from app.schemas.soc_query import (
    SOC_MAX_QUERY_LENGTH,
    SOCExecutionMode,
    SOCOperation,
    SOCQueryResponse,
    SOCResource,
)
from app.services.soc.errors import (
    SOCConfigurationError,
    SOCError,
    SOCExecutionError,
    SOCInputValidationError,
    SOCIntentValidationError,
    SOCInternalError,
    SOCModelOutputError,
    SOCProviderError,
    SOCSafetyError,
)
from app.services.soc.engine import SOCQueryService
from app.services.soc.executor import SOCQueryExecutor
from app.services.soc.parser import SOCIntentParser, SOCParseResult
from app.services.soc.registry import QueryHandler
from tests.conftest import auth_header

from soc_test_helpers import FakeRecord, NOW, make_response


class FakeEngine:
    """Route stand-in that records queries and returns/fails deterministically."""

    def __init__(
        self,
        response: SOCQueryResponse | None = None,
        error: SOCError | None = None,
    ) -> None:
        self._response = response or make_response()
        self._error = error
        self.queries: list[str] = []

    def query(self, db, user_query: str) -> SOCQueryResponse:
        self.queries.append(user_query)
        if self._error is not None:
            raise self._error
        return self._response


@pytest.fixture(scope="session")
def outsider_token(db_session: Session, _ensure_roles) -> str:
    """JWT for an authenticated user outside the SOC roles."""
    role = db_session.execute(
        select(Role).where(Role.name == "viewer")
    ).scalar_one_or_none()
    if role is None:
        role = Role(name="viewer", description="read-only non-SOC role")
        db_session.add(role)
        db_session.commit()
        db_session.refresh(role)
    email = f"test-soc-viewer-{uuid.uuid4().hex[:8]}@example.com"
    user = User(
        email=email,
        password_hash=hash_password("TestPassword123!"),
        is_active=True,
        role_id=role.id,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return create_access_token(str(user.id))


# ---------------------------------------------------------------------------
# 1. Authentication + RBAC
# ---------------------------------------------------------------------------


class TestAuthenticationAndRbac:
    def test_no_token_unauthorized(self, client: TestClient) -> None:
        assert (
            client.post("/api/soc/query", json={"query": "recent detections"}).status_code
            == 401
        )

    def test_invalid_token_rejected(self, client: TestClient) -> None:
        headers = {"Authorization": "Bearer not-a-real-jwt"}
        resp = client.post(
            "/api/soc/query",
            json={"query": "recent detections"},
            headers=headers,
        )
        assert resp.status_code == 401

    def test_viewer_forbidden(
        self, client: TestClient, outsider_token: str
    ) -> None:
        resp = client.post(
            "/api/soc/query",
            json={"query": "recent detections"},
            headers=auth_header(outsider_token),
        )
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Insufficient permissions"

    @pytest.mark.parametrize("token_fixture", ["admin_token", "analyst_token", "ciso_token"])
    def test_soc_roles_allowed(
        self,
        client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
        request: pytest.FixtureRequest,
        token_fixture: str,
    ) -> None:
        token = request.getfixturevalue(token_fixture)
        fake = FakeEngine(response=make_response())
        monkeypatch.setattr(soc_routes, "_soc", fake)
        resp = client.post(
            "/api/soc/query",
            json={"query": "file listing"},
            headers=auth_header(token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["read_only"] is True
        assert data["intent"]["operation"] == "recent"
        assert fake.queries == ["file listing"]


# ---------------------------------------------------------------------------
# 2. Request-body validation
# ---------------------------------------------------------------------------


class TestBodyValidation:
    @pytest.fixture(autouse=True)
    def _fake(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(soc_routes, "_soc", FakeEngine())

    def test_blank_query_422(self, client: TestClient, admin_token: str) -> None:
        for body in ({"query": ""}, {"query": "   "}):
            resp = client.post(
                "/api/soc/query", json=body, headers=auth_header(admin_token)
            )
            assert resp.status_code == 422

    def test_oversized_query_422(self, client: TestClient, admin_token: str) -> None:
        resp = client.post(
            "/api/soc/query",
            json={"query": "a" * (SOC_MAX_QUERY_LENGTH + 1)},
            headers=auth_header(admin_token),
        )
        assert resp.status_code == 422

    def test_missing_query_422(self, client: TestClient, admin_token: str) -> None:
        resp = client.post(
            "/api/soc/query", json={}, headers=auth_header(admin_token)
        )
        assert resp.status_code == 422

    def test_extra_fields_rejected(self, client: TestClient, admin_token: str) -> None:
        resp = client.post(
            "/api/soc/query",
            json={"query": "recent", "hidden": "x"},
            headers=auth_header(admin_token),
        )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 3. Sanitized error mapping
# ---------------------------------------------------------------------------


class TestErrorMapping:
    @pytest.mark.parametrize(
        "error,expected",
        [
            (SOCInputValidationError("bad input"), 422),
            (SOCSafetyError("credential-shaped content rejected"), 422),
            (SOCIntentValidationError("unsupported operation"), 422),
            (SOCModelOutputError("malformed output"), 422),
            (SOCProviderError("provider down", provider="gemini"), 503),
            (SOCConfigurationError("no api key"), 503),
            (SOCExecutionError("data unavailable"), 503),
            (SOCInternalError("unexpected"), 500),
        ],
    )
    def test_mapped_status_codes(
        self,
        client: TestClient,
        admin_token: str,
        monkeypatch: pytest.MonkeyPatch,
        error: SOCError,
        expected: int,
    ) -> None:
        monkeypatch.setattr(soc_routes, "_soc", FakeEngine(error=error))
        resp = client.post(
            "/api/soc/query",
            json={"query": "recent detections"},
            headers=auth_header(admin_token),
        )
        assert resp.status_code == expected
        # The wire error never echoes raw provider/user data or internals.
        assert "gemini" not in resp.text
        assert "recent detections" not in resp.text


# ---------------------------------------------------------------------------
# 4. Route wired to a real SOCQueryService
# ---------------------------------------------------------------------------


class TestRealEngineThroughRoute:
    @pytest.fixture()
    def real_engine(self) -> SOCQueryService:
        class FixedParser(SOCIntentParser):
            @property
            def provider_name(self) -> str:
                return "gemini"

            @property
            def model_name(self) -> str | None:
                return "gemini-2.0-flash"

            def parse(self, user_query: str) -> SOCParseResult:
                import json

                return SOCParseResult(
                    raw_text=json.dumps(
                        {"resource": "detections", "operation": "recent", "limit": 2}
                    ),
                    provider="gemini",
                    model="gemini-2.0-flash",
                )

        def recent(db, *, limit=50):
            return [
                FakeRecord(id="d1"),
                FakeRecord(id="d2"),
            ][:limit]

        handlers = {
            (SOCResource.DETECTIONS, SOCOperation.RECENT): QueryHandler(
                resource=SOCResource.DETECTIONS,
                operation=SOCOperation.RECENT,
                mode=SOCExecutionMode.RECENT_FEED,
                id_field=None,
                allowed_filters=frozenset(),
                call=recent,
                collect=lambda records: records,
            )
        }
        return SOCQueryService(
            parser=FixedParser(),
            executor=SOCQueryExecutor(handlers=handlers),
            clock=lambda: NOW,
        )

    def test_end_to_end_response(
        self,
        client: TestClient,
        admin_token: str,
        monkeypatch: pytest.MonkeyPatch,
        real_engine: SOCQueryService,
    ) -> None:
        monkeypatch.setattr(soc_routes, "_soc", real_engine)
        resp = client.post(
            "/api/soc/query",
            json={"query": "show me recent detections"},
            headers=auth_header(admin_token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["read_only"] is True
        assert data["found"] is True
        assert data["count"] == 2
        assert data["intent"]["resource"] == "detections"
        assert data["intent"]["operation"] == "recent"
        assert data["metadata"]["parser_provider"] == "gemini"
        assert data["metadata"]["parser_model"] == "gemini-2.0-flash"
        assert data["semantics"] == ["detection_results"]
        assert data["items"] == [
            {"id": "d1", "level": None, "memory_type": None},
            {"id": "d2", "level": None, "memory_type": None},
        ]
        assert "Returned 2 recent detections." in data["note"]
        # recorded_at serializes as timezone-aware datetime string.
        services_time = datetime.fromisoformat(data["metadata"]["recorded_at"])
        assert services_time.tzinfo is not None

    def test_unconfigured_gemini_returns_503_not_500(
        self,
        client: TestClient,
        admin_token: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from app.core.config import settings

        monkeypatch.setattr(settings, "gemini_api_key", "")
        monkeypatch.setattr(soc_routes, "_soc", None)
        resp = client.post(
            "/api/soc/query",
            json={"query": "recent detections"},
            headers=auth_header(admin_token),
        )
        assert resp.status_code == 503