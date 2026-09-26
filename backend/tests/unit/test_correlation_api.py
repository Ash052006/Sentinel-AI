"""Correlation API layer behavior tests (Step 10E).

Exercises the read-only correlation endpoints through the full integration
stack the project already uses for API tests — JWT -> FastAPI
(``TestClient(app)``) -> route -> :class:`CorrelationQueryService` ->
repository -> PostgreSQL:

* authentication and RBAC enforcement on every correlation endpoint;
* exact-lookup 404 vs. empty-collection 200 semantics;
* HTTP-level and service-level parameter validation (422);
* deterministic ordering and bounded pagination;
* route ordering — ``/recent`` never resolves as ``/{correlation_id}``;
* sanitized database-failure responses (503) with no internals leaked;
* secret redaction preserved end-to-end through the response;
* strict read-only behavior (no writes, no mutation, no non-GET methods).

Rows are seeded through the real :class:`CorrelationPersistenceService`
against the same shared test database the existing API tests use, so the
end-to-end path (including PostgreSQL ``JSONB`` round-trips) is exercised.
"""

from __future__ import annotations

import inspect
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

import app.api.routes.correlations as correlations_routes
from app.core.security import create_access_token, hash_password
from app.models.correlation_member import CorrelationMember as CorrelationMemberRow
from app.models.correlation_result import CorrelationResult as CorrelationResultRow
from app.models.role import Role
from app.models.user import User
from app.schemas.correlation import (
    CorrelationMember,
    CorrelationResult,
    CorrelationStatus,
)
from app.schemas.security_event import Provenance
from app.services.correlation_persistence import CorrelationPersistenceService
from app.services.correlation_query import (
    MAX_PAGE_SIZE,
    CorrelationQueryError,
    CorrelationQueryValidationError,
)
from tests.conftest import auth_header

# ---------------------------------------------------------------------------
# Deterministic fixture data / seeding helpers
# ---------------------------------------------------------------------------

BASE = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)


def _ts(hours: float = 0.0) -> datetime:
    """Deterministic timezone-aware timestamp offset from BASE."""
    return BASE + timedelta(hours=hours)


def _correlation(
    *,
    correlation_id: uuid.UUID | None = None,
    members: tuple[tuple[uuid.UUID, uuid.UUID, datetime], ...] = (),
    status: CorrelationStatus = CorrelationStatus.ACTIVE,
    confidence: float | None = 0.9,
    evidence: dict | None = None,
    metadata: dict | None = None,
    timestamp: datetime | None = None,
) -> CorrelationResult:
    """Build a Step 10A CorrelationResult contract object."""
    return CorrelationResult(
        correlation_id=correlation_id or uuid.uuid4(),
        members=[
            CorrelationMember(detection_id=d, event_id=e, timestamp=t)
            for d, e, t in members
        ],
        status=status,
        confidence=confidence,
        evidence=evidence or {"signals": ["same_host"], "safe": 1},
        metadata=metadata or {},
        timestamp=timestamp or _ts(0),
        provenance=Provenance.CORRELATED,
    )


def _persist(db: Session, correlations: list[CorrelationResult]) -> None:
    """Persist *correlations* through the real persistence service."""
    CorrelationPersistenceService().persist_correlations(db, correlations)


def _count(db: Session, model) -> int:
    """Count every persisted row of *model*."""
    return db.scalar(select(func.count()).select_from(model))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def ds(db_session: Session) -> SimpleNamespace:
    """A function-scoped seeded dataset of persisted correlations.

    * ``detection_a``: referenced by ``c1`` and ``c2`` (2 correlations).
    * ``detection_b``: referenced by ``c1`` and ``c3`` (2 correlations).
    * ``event_id``: referenced by every member (3 correlations).
    * ``c1`` bridges both detections (2 members), giving a distinct-parent
      query-parity dataset.
    * ``c2`` carries secret-shaped metadata keys so end-to-end redaction is
      verified through the API response.
    """
    detection_a = uuid.uuid4()
    detection_b = uuid.uuid4()
    event_id = uuid.uuid4()

    c1 = _correlation(
        members=(
            (detection_a, event_id, _ts(-1)),
            (detection_b, event_id, _ts(0)),
        ),
        timestamp=_ts(0),
        confidence=0.91,
    )
    c2 = _correlation(
        members=((detection_a, event_id, _ts(0)),),
        timestamp=_ts(1),
        confidence=0.4,
        metadata={
            "region": "eu",
            "token": "sk_test_abc",
            "password": "hunter2",
            "auth_header": "Basic xyz12",
            "apikey": "ak_12345",
        },
    )
    c3 = _correlation(
        members=((detection_b, event_id, _ts(1)),),
        timestamp=_ts(2),
        confidence=None,
        status=CorrelationStatus.CLOSED,
    )
    _persist(db_session, [c1, c2, c3])

    return SimpleNamespace(
        detection_a=detection_a,
        detection_b=detection_b,
        event_id=event_id,
        c1=c1.correlation_id,
        c2=c2.correlation_id,
        c3=c3.correlation_id,
    )


@pytest.fixture()
def detection_page_dataset(db_session: Session) -> SimpleNamespace:
    """Five correlations for one fresh detection (deterministic pagination)."""
    detection_id = uuid.uuid4()
    event_id = uuid.uuid4()
    ids = [uuid.uuid4() for _ in range(5)]
    correlations = [
        _correlation(
            correlation_id=ids[i],
            members=((detection_id, event_id, _ts(i)),),
            timestamp=_ts(i),
        )
        for i in range(5)
    ]
    _persist(db_session, correlations)
    return SimpleNamespace(detection_id=detection_id, ids=ids)


@pytest.fixture(scope="session")
def outsider_token(db_session: Session, _ensure_roles) -> str:
    """JWT for an authenticated user outside the SOC roles (admin/analyst/ciso)."""
    role = db_session.execute(
        select(Role).where(Role.name == "viewer")
    ).scalar_one_or_none()
    if role is None:
        role = Role(name="viewer", description="read-only non-SOC role")
        db_session.add(role)
        db_session.commit()
        db_session.refresh(role)

    email = f"test-viewer-{uuid.uuid4().hex[:8]}@example.com"
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


@pytest.fixture()
def all_correlation_urls() -> list[str]:
    """One request per correlation endpoint, each a safe/valid request."""
    random = uuid.uuid4()
    return [
        "/api/correlations/recent",
        f"/api/correlations/detection/{random}",
        f"/api/correlations/event/{random}",
        f"/api/correlations/{random}",
    ]


# ---------------------------------------------------------------------------
# 1. Authentication enforcement
# ---------------------------------------------------------------------------


class TestAuthentication:
    def test_every_endpoint_requires_a_token(
        self, client: TestClient, all_correlation_urls: list[str]
    ) -> None:
        for url in all_correlation_urls:
            assert client.get(url).status_code == 401, url

    def test_invalid_token_rejected(
        self, client: TestClient, all_correlation_urls: list[str]
    ) -> None:
        headers = {"Authorization": "Bearer not-a-real-jwt"}
        for url in all_correlation_urls:
            assert client.get(url, headers=headers).status_code == 401, url

    def test_auth_is_checked_before_lookup(
        self, client: TestClient, ds: SimpleNamespace
    ) -> None:
        """Even a valid correlation_id is rejected without a token (401)."""
        assert client.get(f"/api/correlations/{ds.c1}").status_code == 401


# ---------------------------------------------------------------------------
# 2. RBAC authorization
# ---------------------------------------------------------------------------


class TestAuthorization:
    @pytest.mark.parametrize("token_fixture", ["admin_token", "analyst_token", "ciso_token"])
    def test_soc_roles_can_access_every_endpoint(
        self,
        client: TestClient,
        all_correlation_urls: list[str],
        request: pytest.FixtureRequest,
        token_fixture: str,
    ) -> None:
        token = request.getfixturevalue(token_fixture)
        for url in all_correlation_urls:
            response = client.get(url, headers=auth_header(token))
            # Exact lookups on unknown ids 404; collections return 200.
            assert response.status_code in (200, 404), (url, response.status_code)

    def test_outsider_role_forbidden(
        self, client: TestClient, outsider_token: str
    ) -> None:
        response = client.get(
            "/api/correlations/recent", headers=auth_header(outsider_token)
        )
        assert response.status_code == 403
        assert response.json()["detail"] == "Insufficient permissions"

    def test_rbac_enforced_on_every_endpoint(
        self, client: TestClient, outsider_token: str, all_correlation_urls: list[str]
    ) -> None:
        for url in all_correlation_urls:
            response = client.get(url, headers=auth_header(outsider_token))
            assert response.status_code == 403, url


# ---------------------------------------------------------------------------
# 3. Single correlation lookup
# ---------------------------------------------------------------------------


class TestGetCorrelation:
    def test_authenticated_user_retrieves_correlation(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        response = client.get(
            f"/api/correlations/{ds.c1}", headers=auth_header(admin_token)
        )
        assert response.status_code == 200
        body = response.json()
        assert body["correlation_id"] == str(ds.c1)
        assert body["status"] == "active"
        assert body["confidence"] == 0.91
        assert body["evidence"] == {"signals": ["same_host"], "safe": 1}
        assert body["result_metadata"] == {}
        assert body["provenance"] == "correlated"
        assert body["id"]
        assert body["created_at"]
        assert body["updated_at"]
        assert body["timestamp"]

    def test_response_has_correct_schema(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        body = client.get(
            f"/api/correlations/{ds.c3}", headers=auth_header(admin_token)
        ).json()
        assert body.keys() == {
            "id",
            "correlation_id",
            "status",
            "confidence",
            "evidence",
            "result_metadata",
            "timestamp",
            "provenance",
            "members",
            "created_at",
            "updated_at",
        }
        assert body["status"] == "closed"
        assert body["confidence"] is None

    def test_members_included_in_persisted_order(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        body = client.get(
            f"/api/correlations/{ds.c1}", headers=auth_header(admin_token)
        ).json()
        assert [m["detection_id"] for m in body["members"]] == [
            str(ds.detection_a),
            str(ds.detection_b),
        ]
        assert [m["member_order"] for m in body["members"]] == [0, 1]
        assert {m["event_id"] for m in body["members"]} == {str(ds.event_id)}
        member_keys = {"id", "correlation_id", "detection_id", "event_id",
                       "timestamp", "member_order", "created_at", "updated_at"}
        assert all(set(m) == member_keys for m in body["members"])
        assert all(m["timestamp"] for m in body["members"])

    def test_missing_correlation_returns_404(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            f"/api/correlations/{uuid.uuid4()}", headers=auth_header(admin_token)
        )
        assert response.status_code == 404
        assert response.json()["detail"] == "Correlation not found"

    def test_invalid_correlation_id_rejected(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            "/api/correlations/not-a-uuid", headers=auth_header(admin_token)
        )
        assert response.status_code == 422


# ---------------------------------------------------------------------------
# 4. Detection-scoped correlations
# ---------------------------------------------------------------------------


class TestDetectionCorrelations:
    def test_detection_query_returns_results(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        response = client.get(
            f"/api/correlations/detection/{ds.detection_a}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 2
        assert body["page"] == 1
        assert body["page_size"] == 50
        assert [item["correlation_id"] for item in body["items"]] == [
            str(ds.c2),
            str(ds.c1),
        ]

    def test_distinct_parent_returns_shared_correlation_once(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        """c1 spans both detections but appears once per detection query."""
        body = client.get(
            f"/api/correlations/detection/{ds.detection_b}",
            headers=auth_header(admin_token),
        ).json()
        assert body["total"] == 2
        assert [item["correlation_id"] for item in body["items"]] == [
            str(ds.c3),
            str(ds.c1),
        ]

    def test_detection_with_no_correlations_returns_200_empty(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            f"/api/correlations/detection/{uuid.uuid4()}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200
        body = response.json()
        assert body["items"] == []
        assert body["total"] == 0

    def test_invalid_detection_id_rejected(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            "/api/correlations/detection/not-a-uuid",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 422

    def test_detection_pagination_is_deterministic(
        self, client: TestClient, detection_page_dataset: SimpleNamespace, admin_token: str
    ) -> None:
        first = client.get(
            f"/api/correlations/detection/{detection_page_dataset.detection_id}?page=1&page_size=2",
            headers=auth_header(admin_token),
        ).json()
        second = client.get(
            f"/api/correlations/detection/{detection_page_dataset.detection_id}?page=2&page_size=2",
            headers=auth_header(admin_token),
        ).json()
        third = client.get(
            f"/api/correlations/detection/{detection_page_dataset.detection_id}?page=3&page_size=2",
            headers=auth_header(admin_token),
        ).json()

        expected = [str(cid) for cid in detection_page_dataset.ids[::-1]]
        actual = (
            [item["correlation_id"] for item in first["items"]]
            + [item["correlation_id"] for item in second["items"]]
            + [item["correlation_id"] for item in third["items"]]
        )
        assert actual == expected
        assert first["total"] == second["total"] == third["total"] == 5
        assert len(first["items"]) == 2
        assert len(second["items"]) == 2
        assert len(third["items"]) == 1


# ---------------------------------------------------------------------------
# 5. Event-scoped correlations
# ---------------------------------------------------------------------------


class TestEventCorrelations:
    def test_event_query_returns_results(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        response = client.get(
            f"/api/correlations/event/{ds.event_id}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 3
        assert body["page"] == 1
        assert body["page_size"] == 50
        assert [item["correlation_id"] for item in body["items"]] == [
            str(ds.c3),
            str(ds.c2),
            str(ds.c1),
        ]

    def test_event_with_no_correlations_returns_200_empty(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            f"/api/correlations/event/{uuid.uuid4()}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200
        body = response.json()
        assert body["items"] == []
        assert body["total"] == 0

    def test_invalid_event_id_rejected(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            "/api/correlations/event/not-a-uuid",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 422

    def test_event_ordering_is_deterministic(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        body = client.get(
            f"/api/correlations/event/{ds.event_id}",
            headers=auth_header(admin_token),
        ).json()
        stamps = [item["timestamp"] for item in body["items"]]
        assert stamps == sorted(stamps, reverse=True)

    def test_event_members_embedded(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        body = client.get(
            f"/api/correlations/event/{ds.event_id}",
            headers=auth_header(admin_token),
        ).json()
        by_id = {item["correlation_id"]: item for item in body["items"]}
        assert len(by_id[str(ds.c1)]["members"]) == 2
        assert len(by_id[str(ds.c2)]["members"]) == 1
        assert len(by_id[str(ds.c3)]["members"]) == 1


# ---------------------------------------------------------------------------
# 6. Recent correlations feed
# ---------------------------------------------------------------------------


class TestRecentCorrelations:
    def test_recent_returns_results(
        self, client: TestClient, db_session: Session, admin_token: str
    ) -> None:
        # The recent feed orders by ``timestamp`` DESC then ``correlation_id``
        # ASC and returns at most the requested limit.  The shared session
        # database accumulates rows across runs, so many historical markers
        # already share the newest timestamp; a fresh random correlation_id
        # can therefore fall outside the returned top-*limit* rows.  Pin the
        # marker to the documented deterministic tie-break: a fixed, minimal
        # correlation_id always ranks first among timestamp ties, so the
        # marker is guaranteed membership in the feed.
        marker_event = uuid.uuid4()
        marker = _correlation(
            correlation_id=uuid.UUID(int=1),
            members=((uuid.uuid4(), marker_event, _ts(1)),),
            timestamp=_ts(10_000),
        )
        _persist(db_session, [marker])

        response = client.get(
            "/api/correlations/recent?limit=10", headers=auth_header(admin_token)
        )
        assert response.status_code == 200
        body = response.json()
        assert isinstance(body, list)
        assert len(body) >= 1
        assert str(marker.correlation_id) in {item["correlation_id"] for item in body}
        assert all("correlation_id" in item and "members" in item for item in body)

    def test_recent_respects_bounded_limit(
        self, client: TestClient, admin_token: str
    ) -> None:
        limited = client.get(
            "/api/correlations/recent?limit=2", headers=auth_header(admin_token)
        ).json()
        assert len(limited) == 2

        full = client.get(
            "/api/correlations/recent?limit=200", headers=auth_header(admin_token)
        )
        assert full.status_code == 200
        assert len(full.json()) <= 200

    def test_recent_ordering_is_deterministic(
        self, client: TestClient, admin_token: str
    ) -> None:
        body = client.get(
            "/api/correlations/recent?limit=200", headers=auth_header(admin_token)
        ).json()
        stamps = [item["timestamp"] for item in body]
        assert stamps == sorted(stamps, reverse=True)

    def test_recent_invalid_limit_rejected(
        self, client: TestClient, admin_token: str
    ) -> None:
        for limit in ("0", "-1", "201"):
            response = client.get(
                f"/api/correlations/recent?limit={limit}",
                headers=auth_header(admin_token),
            )
            assert response.status_code == 422, limit


# ---------------------------------------------------------------------------
# 7. Pagination validation (HTTP-level contract)
# ---------------------------------------------------------------------------


class TestPaginationValidation:
    def test_invalid_page_rejected(
        self, client: TestClient, admin_token: str
    ) -> None:
        detection = uuid.uuid4()
        for page in ("0", "-1", "abc"):
            response = client.get(
                f"/api/correlations/detection/{detection}?page={page}",
                headers=auth_header(admin_token),
            )
            assert response.status_code == 422, page

    def test_invalid_page_size_rejected(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            f"/api/correlations/event/{uuid.uuid4()}?page_size=0",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 422

    def test_excessive_page_size_rejected(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            f"/api/correlations/event/{uuid.uuid4()}?page_size=201",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 422

    def test_page_size_upper_bound_accepted(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            f"/api/correlations/event/{uuid.uuid4()}?page_size={MAX_PAGE_SIZE}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# 8. Route ordering — /recent never resolves as /{correlation_id}
# ---------------------------------------------------------------------------


class TestRouteCollision:
    def test_recent_resolves_to_recent_endpoint(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            "/api/correlations/recent", headers=auth_header(admin_token)
        )
        assert response.status_code == 200
        body = response.json()
        assert isinstance(body, list)  # a feed, never a single record


# ---------------------------------------------------------------------------
# 9. Error handling & sanitization
# ---------------------------------------------------------------------------


class TestErrorSanitization:
    def test_database_failure_becomes_safe_503(
        self, client: TestClient, admin_token: str, monkeypatch
    ) -> None:
        class _BrokenService:
            def get_correlation(self, db, correlation_id):
                raise CorrelationQueryError(reason="simulated database failure")

        monkeypatch.setattr(correlations_routes, "_service", _BrokenService())
        response = client.get(
            f"/api/correlations/{uuid.uuid4()}", headers=auth_header(admin_token)
        )
        assert response.status_code == 503
        assert response.json() == {"detail": "Correlation data is unavailable"}

    def test_database_failure_leaks_no_internals(
        self, client: TestClient, admin_token: str, monkeypatch
    ) -> None:
        class _BrokenService:
            def list_recent_correlations(self, db, *, limit=50):
                raise CorrelationQueryError(reason="simulated failure")

        monkeypatch.setattr(correlations_routes, "_service", _BrokenService())
        response = client.get(
            "/api/correlations/recent", headers=auth_header(admin_token)
        )
        assert response.status_code == 503
        raw = response.text.lower()
        for fragment in ("sqlalchemy", "psycopg", "traceback", "exception", "postgres"):
            assert fragment not in raw

    def test_service_validation_error_maps_to_422(
        self, client: TestClient, admin_token: str, monkeypatch
    ) -> None:
        class _RejectingService:
            def list_correlations_for_detection(
                self, db, detection_id, *, page=1, page_size=50
            ):
                raise CorrelationQueryValidationError(
                    reason="page_size must not exceed 200"
                )

        monkeypatch.setattr(correlations_routes, "_service", _RejectingService())
        response = client.get(
            f"/api/correlations/detection/{uuid.uuid4()}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 422
        assert "page_size" in response.json()["detail"]


# ---------------------------------------------------------------------------
# 10. Security — redaction survives end-to-end through the response
# ---------------------------------------------------------------------------


class TestSecretRedaction:
    def test_secret_shaped_metadata_remains_redacted(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        body = client.get(
            f"/api/correlations/{ds.c2}", headers=auth_header(admin_token)
        ).json()
        metadata = body["result_metadata"]
        assert metadata["token"] == "<redacted>"
        assert metadata["password"] == "<redacted>"
        assert metadata["auth_header"] == "<redacted>"
        assert metadata["apikey"] == "<redacted>"
        assert metadata["region"] == "eu"

    def test_raw_credentials_never_appear_in_response(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        raw = client.get(
            f"/api/correlations/{ds.c2}", headers=auth_header(admin_token)
        ).text
        for credential in ("sk_test_abc", "hunter2", "Basic xyz12", "ak_12345"):
            assert credential not in raw

    def test_response_exposes_no_database_internals(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        response = client.get(
            f"/api/correlations/{ds.c1}", headers=auth_header(admin_token)
        )
        raw = response.text.lower()
        for fragment in ("sqlalchemy", "psycopg", "postgres", "traceback", "exception"):
            assert fragment not in raw


# ---------------------------------------------------------------------------
# 11. Read-only contract and mutation checks
# ---------------------------------------------------------------------------


class TestReadOnlyContract:
    def test_api_does_not_mutate_persisted_records(
        self,
        client: TestClient,
        db_session: Session,
        ds: SimpleNamespace,
        admin_token: str,
    ) -> None:
        before_results = _count(db_session, CorrelationResultRow)
        before_members = _count(db_session, CorrelationMemberRow)

        urls = [
            f"/api/correlations/{ds.c1}",
            f"/api/correlations/detection/{ds.detection_a}",
            f"/api/correlations/event/{ds.event_id}",
            "/api/correlations/recent",
        ]
        for url in urls:
            assert client.get(url, headers=auth_header(admin_token)).status_code == 200

        assert _count(db_session, CorrelationResultRow) == before_results
        assert _count(db_session, CorrelationMemberRow) == before_members

    def test_no_mutation_endpoints_exist(self, client: TestClient) -> None:
        spec = client.get("/openapi.json").json()
        for path in spec["paths"]:
            if "correlation" in path:
                assert set(spec["paths"][path]) == {"get"}, path

    def test_no_write_methods_accepted(
        self, client: TestClient, admin_token: str
    ) -> None:
        for method in ("post", "put", "patch", "delete"):
            response = getattr(client, method)(
                "/api/correlations/recent", headers=auth_header(admin_token)
            )
            assert response.status_code == 405, method


# ---------------------------------------------------------------------------
# 12. Architecture — routes delegate to the query service only
# ---------------------------------------------------------------------------


class TestArchitecture:
    def test_route_delegates_to_query_service(
        self, client: TestClient, admin_token: str, monkeypatch
    ) -> None:
        correlation_id = uuid.uuid4()
        called_with = []

        class _ProbeService:
            def get_correlation(self, db, cid):
                called_with.append(cid)
                return {
                    "id": str(uuid.uuid4()),
                    "correlation_id": str(correlation_id),
                    "status": "active",
                    "confidence": 0.5,
                    "evidence": {},
                    "result_metadata": {},
                    "timestamp": "2026-09-01T12:00:00Z",
                    "provenance": "correlated",
                    "members": [],
                    "created_at": "2026-09-01T12:00:00Z",
                    "updated_at": "2026-09-01T12:00:00Z",
                }

        monkeypatch.setattr(correlations_routes, "_service", _ProbeService())
        response = client.get(
            f"/api/correlations/{correlation_id}", headers=auth_header(admin_token)
        )
        assert response.status_code == 200
        assert response.json()["correlation_id"] == str(correlation_id)
        assert called_with == [correlation_id]

    def test_route_source_has_no_direct_database_access(self) -> None:
        """The route module must not perform raw SQLAlchemy operations."""
        source = inspect.getsource(correlations_routes)
        for forbidden in (
            "db.query",
            "select(",
            "insert(",
            "update(",
            "delete(",
            ".commit(",
            ".rollback(",
            ".flush(",
            "session.execute",
        ):
            assert forbidden not in source, forbidden


# ---------------------------------------------------------------------------
# 13. OpenAPI / router registration
# ---------------------------------------------------------------------------


class TestOpenApiRegistration:
    EXPECTED_PATHS = {
        "/api/correlations/{correlation_id}",
        "/api/correlations/recent",
        "/api/correlations/detection/{detection_id}",
        "/api/correlations/event/{event_id}",
    }

    def test_router_registered_under_existing_api_prefix(
        self, client: TestClient
    ) -> None:
        spec = client.get("/openapi.json").json()
        # Scoped to the correlation API's own prefix: Step 11E legitimately
        # registers ``/api/risk-assessments/correlation/{correlation_id}``
        # (its correlation-scoped read path), which also contains the word
        # "correlation" but belongs to a different router.
        correlation_paths = {
            path
            for path in spec["paths"]
            if path.startswith("/api/correlations") and "correlation" in path.lower()
        }
        assert correlation_paths == self.EXPECTED_PATHS

    def test_every_correlation_operation_requires_bearer_auth(
        self, client: TestClient
    ) -> None:
        spec = client.get("/openapi.json").json()
        for path in self.EXPECTED_PATHS:
            operation = spec["paths"][path]["get"]
            assert operation["security"] == [{"HTTPBearer": []}], path
            assert operation["tags"] == ["Correlations"], path

    def test_correlation_paths_expose_no_other_methods(
        self, client: TestClient
    ) -> None:
        spec = client.get("/openapi.json").json()
        for path in self.EXPECTED_PATHS:
            assert set(spec["paths"][path]) == {"get"}, path

    def test_operation_ids_are_unique(self, client: TestClient) -> None:
        spec = client.get("/openapi.json").json()
        operation_ids = [
            operation["operationId"]
            for path in spec["paths"]
            for operation in spec["paths"][path].values()
        ]
        assert len(operation_ids) == len(set(operation_ids))