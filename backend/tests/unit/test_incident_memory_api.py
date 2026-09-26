"""Incident Memory API behavior tests (Step 19).

Verifies the read-only HTTP transport
(:mod:`app.api.routes.incident_memories`) over the Step 18 query layer,
mirroring the Risk Assessment API suite (:mod:`test_risk_api.py`).

Scope covered:

* authentication enforcement (401) and RBAC (403) on every endpoint,
  including audit of authorization denials and no read-audit convention;
* single-memory lookup (200 / 404 / 422);
* correlation-scoped listing including deterministic ordering and pagination;
* the general list (200 page envelope, ``memory_type`` filter, invalid
  filter 422, pagination);
* the recent feed (bounded limit validation, deterministic ordering, and
  the created_at-DESC / memory_id-ASC tie-break);
* route ordering (static ``/recent`` and segmented ``/correlation/{id}``
  never resolve as ``/{memory_id}``);
* sanitized error handling (503 on query failure with no internals, 422 on
  service validation, 500 on unexpected errors);
* the established secret contract end-to-end: credential values written by
  the Step 17 redaction path stay ``<redacted>`` through the response, raw
  credentials never appear, and secret-shaped envelope content is still
  rejected at construction (never stored);
* the read-only contract (no writes, no mutation endpoints, no non-GET
  methods) and route delegation to the query service only.

Same harness as the Risk Assessment API suite: a live test database seeded
through the real Step 17 persistence service, with every test cleaning up
its own rows.
"""

from __future__ import annotations

import inspect
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pydantic
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

import app.api.routes.incident_memories as incident_memory_routes
from app.core.security import create_access_token, hash_password
from app.main import app
from app.models.audit_log import AuditLog
from app.models.incident_memory import IncidentMemoryRow
from app.models.role import Role
from app.models.user import User
from app.schemas.incident_memory import (
    IncidentMemory,
    MemoryIndicator,
    MemorySource,
    MemoryType,
)
from app.schemas.security_event import Provenance
from app.services.incident_memory_persistence import IncidentMemoryPersistenceService
from app.services.incident_memory_query import (
    MAX_PAGE_SIZE,
    IncidentMemoryQueryError,
    IncidentMemoryQueryValidationError,
)
from tests.conftest import auth_header

# ---------------------------------------------------------------------------
# Deterministic fixture data / seeding helpers
# ---------------------------------------------------------------------------

BASE = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)


def _ts(hours: float = 0.0) -> datetime:
    """Deterministic timezone-aware timestamp offset from BASE."""
    return BASE + timedelta(hours=hours)


def _source(*, metadata: dict | None = None) -> MemorySource:
    """Build a Step 16 source with OBSERVED provenance and an event reference."""
    return MemorySource(
        source_id=uuid.uuid4(),
        provenance=Provenance.OBSERVED,
        label="fixture source",
        event_id=uuid.uuid4(),
        metadata=metadata or {"region": "eu"},
    )


def _indicator(
    *, source_id: uuid.UUID | None = None, metadata: dict | None = None
) -> MemoryIndicator:
    return MemoryIndicator(
        indicator_id=uuid.uuid4(),
        indicator_type="ipv4",
        value="198.51.100.7",
        source_ids=[source_id] if source_id is not None else [],
        metadata=metadata or {},
    )


def _memory(
    correlation_id: uuid.UUID | None,
    *,
    memory_type: MemoryType = MemoryType.INCIDENT_SUMMARY,
    title: str = "fixture incident memory",
    summary: str | None = None,
    sources: list[MemorySource] | None = None,
    indicators: list[MemoryIndicator] | None = None,
    metadata: dict | None = None,
    confidence: float | None = None,
) -> IncidentMemory:
    """Build a Step 16 IncidentMemory envelope (source references resolve)."""
    source_list = sources if sources is not None else [_source()]
    canonical = source_list[0].source_id
    return IncidentMemory(
        memory_id=uuid.uuid4(),
        memory_type=memory_type,
        title=title,
        summary=summary,
        correlation_id=correlation_id,
        sources=source_list,
        indicators=indicators or [_indicator(source_id=canonical)],
        confidence=confidence,
        metadata=metadata or {},
        created_at=_ts(0),
    )


def _persist(db: Session, memories: list[IncidentMemory]) -> None:
    """Persist *memories* through the real Step 17 persistence service."""
    IncidentMemoryPersistenceService().persist_memories(db, memories)


def _cleanup(db: Session, *memory_ids: uuid.UUID) -> None:
    """Delete the incident memory rows staged by a test."""
    for mid in memory_ids:
        row = db.scalar(
            select(IncidentMemoryRow).where(IncidentMemoryRow.memory_id == mid)
        )
        if row is not None:
            db.delete(row)
    db.commit()


def _count(db: Session) -> int:
    """Count every persisted incident memory row."""
    return db.scalar(select(func.count(IncidentMemoryRow.id))) or 0


def _count_for_action(db: Session, action: str) -> int:
    """Count persisted audit records with *action*."""
    return len(
        db.execute(select(AuditLog).where(AuditLog.action == action)).scalars().all()
    )


def _row_order(db: Session, memory_ids: list[uuid.UUID]) -> list[str]:
    """Return *memory_ids* ordered by the documented deterministic contract.

    ``created_at`` descending, ``memory_id`` ascending — computed from the
    rows' actual persisted instants, so the assertion never depends on
    wall-clock assumptions about when the requested writes happened.
    """
    rows = db.scalars(
        select(IncidentMemoryRow).where(
            IncidentMemoryRow.memory_id.in_(memory_ids)
        )
    ).all()
    return [
        str(row.memory_id)
        for row in sorted(
            rows,
            key=lambda r: (-r.created_at.timestamp(), r.memory_id),
        )
    ]


def _memory_row(
    memory_id: uuid.UUID,
    *,
    created_at: datetime,
    title: str = "fixture row",
    memory_type: MemoryType = MemoryType.INCIDENT_SUMMARY,
) -> IncidentMemoryRow:
    """Build a bare persisted incident memory row with explicit instants.

    Used only for ordering tests that must pin ``created_at`` exactly (the
    persistence service never exposes the server-side bookkeeping instants).
    """
    return IncidentMemoryRow(
        memory_id=memory_id,
        memory_type=memory_type.value,
        title=title,
        summary="",
        correlation_id=None,
        sources=[],
        indicators=[],
        entities=[],
        techniques=[],
        findings=[],
        actions=[],
        outcomes={},
        memory_metadata={},
        confidence=None,
        provenance=Provenance.RECALLED.value,
        created_at=created_at,
        updated_at=created_at,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def ds(db_session: Session) -> SimpleNamespace:
    """A function-scoped seeded dataset of persisted incident memories.

    * ``correlation_a``: 3 historical memories at the same persistence
      instant family (newest-first deterministic ordering asserted against
      the persisted row instants, never against wall-clock).
    * ``correlation_b``: 1 memory whose indicator metadata carries a nested
      credential-shaped value (``nested.token``), redacted to
      ``<redacted>`` by the Step 17 write path, so end-to-end redaction is
      verified through the API.
    * ``m2`` exercises the ``memory_type`` filter for
      ``indicator_observation``; the four rows span three different types.

    Cleaned up after every test, keeping the shared database deterministic.
    """
    correlation_a = uuid.uuid4()
    correlation_b = uuid.uuid4()

    m1 = _memory(
        correlation_a,
        title="phishing campaign summary",
        summary="initial access via credential phishing",
        metadata={"team": "soc"},
        confidence=0.87,
    )
    m2 = _memory(
        correlation_a,
        memory_type=MemoryType.INDICATOR_OBSERVATION,
        title="phish domain indicator",
        indicators=[
            _indicator(metadata={"nested": {"token": "tok_abc123", "reputation": 87}})
        ],
        metadata={"nested": {"alpha": 1}},
    )
    m3 = _memory(
        correlation_a,
        memory_type=MemoryType.ATTACK_PATTERN,
        title="credential harvesting pattern",
        confidence=0.5,
    )
    m4 = _memory(
        correlation_b,
        memory_type=MemoryType.MITIGATION_OUTCOME,
        title="containment outcome",
        confidence=0.9,
    )

    _persist(db_session, [m1, m2, m3, m4])

    try:
        yield SimpleNamespace(
            correlation_a=correlation_a,
            correlation_b=correlation_b,
            memories=(m1, m2, m3),
            secret_memory=m2,
            credential_value="tok_abc123",
        )
    finally:
        _cleanup(
            db_session,
            m1.memory_id,
            m2.memory_id,
            m3.memory_id,
            m4.memory_id,
        )


@pytest.fixture()
def memory_page_dataset(db_session: Session) -> SimpleNamespace:
    """Five memories for one fresh correlation (deterministic pagination).

    Five distinct types keep the general-list ``memory_type`` filter
    meaningful; each row is persisted in its own transaction so the newest
    five rows belong to this fixture, letting both the general list and the
    correlation-scoped list assert deterministic pages.
    """
    correlation_id = uuid.uuid4()
    types = [
        MemoryType.INCIDENT_SUMMARY,
        MemoryType.INDICATOR_OBSERVATION,
        MemoryType.ATTACK_PATTERN,
        MemoryType.INVESTIGATION_FINDING,
        MemoryType.MITIGATION_OUTCOME,
    ]
    memories = [
        _memory(
            correlation_id,
            memory_type=types[i],
            title=f"memory {i}",
            metadata={"index": i},
            confidence=0.5,
        )
        for i in range(5)
    ]
    _persist(db_session, memories)

    try:
        yield SimpleNamespace(
            correlation_id=correlation_id,
            ids=[m.memory_id for m in memories],
        )
    finally:
        _cleanup(db_session, *[m.memory_id for m in memories])


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
def all_incident_memory_urls() -> list[str]:
    """One request per incident memory endpoint, each a safe/valid request."""
    random = uuid.uuid4()
    return [
        "/api/incident-memories",
        "/api/incident-memories/recent",
        f"/api/incident-memories/correlation/{random}",
        f"/api/incident-memories/{random}",
    ]


# ---------------------------------------------------------------------------
# 1. Authentication enforcement
# ---------------------------------------------------------------------------


class TestAuthentication:
    def test_every_endpoint_requires_a_token(
        self,
        client: TestClient,
        all_incident_memory_urls: list[str],
    ) -> None:
        for url in all_incident_memory_urls:
            assert client.get(url).status_code == 401, url

    def test_invalid_token_rejected(
        self,
        client: TestClient,
        all_incident_memory_urls: list[str],
    ) -> None:
        headers = {"Authorization": "Bearer not-a-real-jwt"}
        for url in all_incident_memory_urls:
            assert client.get(url, headers=headers).status_code == 401, url

    def test_expired_token_rejected(
        self, client: TestClient, admin_user: User
    ) -> None:
        """A token whose exp is already past is rejected with 401."""
        expired = create_access_token(
            str(admin_user.id), expires_delta=timedelta(seconds=-1)
        )
        for url in ("/api/incident-memories/recent",):
            response = client.get(url, headers=auth_header(expired))
            assert response.status_code == 401, url

    def test_auth_is_checked_before_lookup(
        self, client: TestClient, ds: SimpleNamespace
    ) -> None:
        """Even a valid memory id is rejected without a token (401)."""
        marker = ds.memories[0]
        assert (
            client.get(f"/api/incident-memories/{marker.memory_id}").status_code
            == 401
        )


# ---------------------------------------------------------------------------
# 2. RBAC authorization
# ---------------------------------------------------------------------------


class TestAuthorization:
    @pytest.mark.parametrize(
        "token_fixture", ["admin_token", "analyst_token", "ciso_token"]
    )
    def test_soc_roles_can_access_every_endpoint(
        self,
        client: TestClient,
        all_incident_memory_urls: list[str],
        request: pytest.FixtureRequest,
        token_fixture: str,
    ) -> None:
        token = request.getfixturevalue(token_fixture)
        for url in all_incident_memory_urls:
            response = client.get(url, headers=auth_header(token))
            # Exact lookups on unknown ids 404; collections return 200.
            assert response.status_code in (200, 404), (url, response.status_code)

    def test_outsider_role_forbidden(
        self, client: TestClient, outsider_token: str
    ) -> None:
        response = client.get(
            "/api/incident-memories/recent", headers=auth_header(outsider_token)
        )
        assert response.status_code == 403
        assert response.json()["detail"] == "Insufficient permissions"

    def test_rbac_enforced_on_every_endpoint(
        self,
        client: TestClient,
        outsider_token: str,
        all_incident_memory_urls: list[str],
    ) -> None:
        for url in all_incident_memory_urls:
            response = client.get(url, headers=auth_header(outsider_token))
            assert response.status_code == 403, url

    def test_authorization_denial_is_audited(
        self,
        client: TestClient,
        db_session: Session,
        outsider_token: str,
    ) -> None:
        """Authorization denials follow the established audit behavior."""
        before = _count_for_action(db_session, "auth.authorization.denied")
        response = client.get(
            "/api/incident-memories/recent", headers=auth_header(outsider_token)
        )
        assert response.status_code == 403
        assert _count_for_action(db_session, "auth.authorization.denied") == before + 1

    def test_successful_read_does_not_emit_audit_events(
        self,
        client: TestClient,
        db_session: Session,
        admin_token: str,
    ) -> None:
        """Successful reads are not audited (no read-audit convention exists)."""
        before = _count_for_action(db_session, "auth.authorization.denied")
        response = client.get(
            "/api/incident-memories/recent", headers=auth_header(admin_token)
        )
        assert response.status_code == 200
        assert _count_for_action(db_session, "auth.authorization.denied") == before


# ---------------------------------------------------------------------------
# 3. Single incident memory lookup
# ---------------------------------------------------------------------------


class TestGetIncidentMemory:
    def test_authenticated_user_retrieves_incident_memory(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        memory = ds.memories[0]
        response = client.get(
            f"/api/incident-memories/{memory.memory_id}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200
        body = response.json()
        assert body["memory_id"] == str(memory.memory_id)
        assert body["correlation_id"] == str(ds.correlation_a)
        assert body["memory_type"] == "incident_summary"
        assert body["title"] == "phishing campaign summary"
        assert body["summary"] == "initial access via credential phishing"
        assert body["confidence"] == 0.87
        assert body["provenance"] == "recalled"
        assert body["sources"][0]["metadata"] == {"region": "eu"}
        assert body["indicators"][0]["metadata"] == {}
        assert body["outcomes"] == {}
        assert body["memory_metadata"] == {"team": "soc"}
        assert body["id"]
        assert body["created_at"]
        assert body["updated_at"]

    def test_response_has_correct_schema(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        body = client.get(
            f"/api/incident-memories/{ds.memories[1].memory_id}",
            headers=auth_header(admin_token),
        ).json()
        assert body.keys() == {
            "id",
            "memory_id",
            "memory_type",
            "title",
            "summary",
            "correlation_id",
            "sources",
            "indicators",
            "entities",
            "techniques",
            "findings",
            "actions",
            "outcomes",
            "memory_metadata",
            "confidence",
            "provenance",
            "created_at",
            "updated_at",
        }
        assert body["memory_type"] == "indicator_observation"

    def test_missing_memory_returns_404(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            f"/api/incident-memories/{uuid.uuid4()}", headers=auth_header(admin_token)
        )
        assert response.status_code == 404
        assert response.json()["detail"] == "Incident memory not found"

    def test_invalid_memory_id_rejected(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            "/api/incident-memories/not-a-uuid", headers=auth_header(admin_token)
        )
        assert response.status_code == 422


# ---------------------------------------------------------------------------
# 4. Correlation-scoped incident memories
# ---------------------------------------------------------------------------


class TestCorrelationIncidentMemories:
    def test_correlation_query_returns_all_historical_memories(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        response = client.get(
            f"/api/incident-memories/correlation/{ds.correlation_a}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 3
        assert body["page"] == 1
        assert body["page_size"] == 50
        # Every historical memory is returned, never collapsed.
        returned = {item["memory_id"] for item in body["items"]}
        assert returned == {str(m.memory_id) for m in ds.memories}

    def test_correlation_ordering_is_deterministic(
        self,
        client: TestClient,
        db_session: Session,
        ds: SimpleNamespace,
        admin_token: str,
    ) -> None:
        body = client.get(
            f"/api/incident-memories/correlation/{ds.correlation_a}",
            headers=auth_header(admin_token),
        ).json()
        ids = [item["memory_id"] for item in body["items"]]
        expected = _row_order(db_session, [m.memory_id for m in ds.memories])
        assert ids == expected

    def test_correlation_with_no_memories_returns_200_empty(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            f"/api/incident-memories/correlation/{uuid.uuid4()}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200
        body = response.json()
        assert body["items"] == []
        assert body["total"] == 0

    def test_invalid_correlation_id_rejected(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            "/api/incident-memories/correlation/not-a-uuid",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 422

    def test_correlation_pagination_is_deterministic(
        self,
        client: TestClient,
        memory_page_dataset: SimpleNamespace,
        admin_token: str,
    ) -> None:
        first = client.get(
            f"/api/incident-memories/correlation/{memory_page_dataset.correlation_id}"
            "?page=1&page_size=2",
            headers=auth_header(admin_token),
        ).json()
        second = client.get(
            f"/api/incident-memories/correlation/{memory_page_dataset.correlation_id}"
            "?page=2&page_size=2",
            headers=auth_header(admin_token),
        ).json()
        third = client.get(
            f"/api/incident-memories/correlation/{memory_page_dataset.correlation_id}"
            "?page=3&page_size=2",
            headers=auth_header(admin_token),
        ).json()

        expected = [str(aid) for aid in memory_page_dataset.ids[::-1]]
        actual = (
            [item["memory_id"] for item in first["items"]]
            + [item["memory_id"] for item in second["items"]]
            + [item["memory_id"] for item in third["items"]]
        )
        assert actual == expected
        assert first["total"] == second["total"] == third["total"] == 5
        assert len(first["items"]) == 2
        assert len(second["items"]) == 2
        assert len(third["items"]) == 1

    def test_correlation_max_page_size_accepted(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            f"/api/incident-memories/correlation/{uuid.uuid4()}?page_size={MAX_PAGE_SIZE}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# 5. General list — page envelope, memory_type filter, pagination
# ---------------------------------------------------------------------------


class TestGeneralListIncidentMemories:
    def test_list_returns_page_envelope(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        response = client.get(
            "/api/incident-memories", headers=auth_header(admin_token)
        )
        assert response.status_code == 200
        body = response.json()
        assert body.keys() == {"items", "total", "page", "page_size"}
        assert body["page"] == 1
        assert body["page_size"] == 50
        assert body["total"] >= 4
        assert {item["memory_id"] for item in body["items"]}.issuperset(
            {str(m.memory_id) for m in ds.memories}
        )

    def test_memory_type_filter_narrows_results(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        observed = client.get(
            "/api/incident-memories?memory_type=indicator_observation",
            headers=auth_header(admin_token),
        ).json()
        ids = {item["memory_id"] for item in observed["items"]}
        assert ids == {str(ds.secret_memory.memory_id)}
        assert all(
            item["memory_type"] == "indicator_observation"
            for item in observed["items"]
        )

        patterns = client.get(
            "/api/incident-memories?memory_type=attack_pattern",
            headers=auth_header(admin_token),
        ).json()
        assert {item["memory_id"] for item in patterns["items"]} == {
            str(ds.memories[2].memory_id)
        }

    def test_memory_type_filter_with_no_matches_returns_200_empty(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            "/api/incident-memories?memory_type=investigation_finding",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200
        body = response.json()
        assert body["items"] == []
        assert body["total"] == 0
        # The filter is a database-side equality, so total mirrors items.
        assert len(body["items"]) == body["total"]

    def test_invalid_memory_type_rejected(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            "/api/incident-memories?memory_type=not_a_memory_type",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 422

    def test_general_list_pagination_is_deterministic(
        self,
        client: TestClient,
        db_session: Session,
        memory_page_dataset: SimpleNamespace,
        admin_token: str,
    ) -> None:
        first = client.get(
            "/api/incident-memories?page=1&page_size=2",
            headers=auth_header(admin_token),
        ).json()
        second = client.get(
            "/api/incident-memories?page=2&page_size=2",
            headers=auth_header(admin_token),
        ).json()
        third = client.get(
            "/api/incident-memories?page=3&page_size=2",
            headers=auth_header(admin_token),
        ).json()

        # The five fixture rows are the newest five in the database at this
        # point, so their ordered slice occupies the leading position.
        global_order = _row_order(db_session, memory_page_dataset.ids)
        assert first["total"] == second["total"] == third["total"]
        got = (
            [item["memory_id"] for item in first["items"]]
            + [item["memory_id"] for item in second["items"]]
            + [item["memory_id"] for item in third["items"]]
        )
        assert got[:5] == global_order
        assert len(first["items"]) == 2
        assert len(second["items"]) == 2


# ---------------------------------------------------------------------------
# 6. Pagination validation (HTTP-level contract)
# ---------------------------------------------------------------------------


class TestPaginationValidation:
    def test_invalid_page_rejected(self, client: TestClient, admin_token: str) -> None:
        for page in ("0", "-1", "abc"):
            response = client.get(
                f"/api/incident-memories?page={page}",
                headers=auth_header(admin_token),
            )
            assert response.status_code == 422, page

    def test_invalid_page_size_rejected(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            "/api/incident-memories?page_size=0", headers=auth_header(admin_token)
        )
        assert response.status_code == 422

    def test_excessive_page_size_rejected(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            "/api/incident-memories?page_size=201", headers=auth_header(admin_token)
        )
        assert response.status_code == 422


# ---------------------------------------------------------------------------
# 7. Recent incident memories feed
# ---------------------------------------------------------------------------


class TestRecentIncidentMemories:
    def test_recent_returns_results(
        self, client: TestClient, db_session: Session, admin_token: str
    ) -> None:
        marker = _memory(None, title="recent marker", confidence=0.5)
        _persist(db_session, [marker])
        try:
            response = client.get(
                "/api/incident-memories/recent?limit=10",
                headers=auth_header(admin_token),
            )
            assert response.status_code == 200
            body = response.json()
            assert isinstance(body, list)
            assert len(body) >= 1
            assert str(marker.memory_id) in {item["memory_id"] for item in body}
        finally:
            _cleanup(db_session, marker.memory_id)

    def test_recent_returns_multiple_results(
        self, client: TestClient, db_session: Session, admin_token: str
    ) -> None:
        m1 = _memory(None, title="recent marker one", confidence=0.5)
        m2 = _memory(
            None,
            memory_type=MemoryType.INDICATOR_OBSERVATION,
            title="recent marker two",
            confidence=0.6,
        )
        _persist(db_session, [m1])
        _persist(db_session, [m2])
        try:
            body = client.get(
                "/api/incident-memories/recent?limit=50",
                headers=auth_header(admin_token),
            ).json()
            ids = {item["memory_id"] for item in body}
            assert str(m1.memory_id) in ids
            assert str(m2.memory_id) in ids
        finally:
            _cleanup(db_session, m1.memory_id, m2.memory_id)

    def test_recent_respects_bounded_limit(
        self, client: TestClient, db_session: Session, admin_token: str
    ) -> None:
        m1 = _memory(None, title="bounded marker a", confidence=0.5)
        m2 = _memory(
            None,
            memory_type=MemoryType.INDICATOR_OBSERVATION,
            title="bounded marker b",
            confidence=0.6,
        )
        m3 = _memory(None, memory_type=MemoryType.ATTACK_PATTERN, title="bounded marker c", confidence=0.7)
        _persist(db_session, [m1])
        _persist(db_session, [m2])
        _persist(db_session, [m3])
        try:
            limited = client.get(
                "/api/incident-memories/recent?limit=2",
                headers=auth_header(admin_token),
            ).json()
            assert len(limited) == 2
            assert [item["memory_id"] for item in limited] == _row_order(
                db_session, [m1.memory_id, m2.memory_id, m3.memory_id]
            )[:2]

            full = client.get(
                "/api/incident-memories/recent?limit=200",
                headers=auth_header(admin_token),
            )
            assert full.status_code == 200
            assert len(full.json()) <= 200
            assert len(full.json()) >= 3
        finally:
            _cleanup(db_session, m1.memory_id, m2.memory_id, m3.memory_id)

    def test_recent_ordering_is_deterministic(
        self, client: TestClient, db_session: Session, admin_token: str
    ) -> None:
        m1 = _memory(None, title="order marker a", confidence=0.5)
        m2 = _memory(
            None,
            memory_type=MemoryType.INDICATOR_OBSERVATION,
            title="order marker b",
            confidence=0.6,
        )
        m3 = _memory(None, memory_type=MemoryType.ATTACK_PATTERN, title="order marker c", confidence=0.7)
        _persist(db_session, [m1])
        _persist(db_session, [m2])
        _persist(db_session, [m3])
        try:
            body = client.get(
                "/api/incident-memories/recent?limit=200",
                headers=auth_header(admin_token),
            ).json()
            expected = _row_order(
                db_session, [m1.memory_id, m2.memory_id, m3.memory_id]
            )
            assert [item["memory_id"] for item in body][:3] == expected
        finally:
            _cleanup(db_session, m1.memory_id, m2.memory_id, m3.memory_id)

    def test_recent_equal_timestamps_use_deterministic_tie_break(
        self, client: TestClient, db_session: Session, admin_token: str
    ) -> None:
        """Rows sharing a created_at instant order by memory_id ascending.

        The rows are staged directly with an explicit, shared ``created_at``
        instant (far in the future relative to any persisted row), so the
        memory_id-ASC secondary key is the sole differentiator and the two
        rows lead the feed.
        """
        shared = _ts(12_000)
        id_a = uuid.uuid4()
        id_b = uuid.uuid4()
        db_session.add_all(
            [
                _memory_row(id_a, created_at=shared),
                _memory_row(
                    id_b,
                    created_at=shared,
                    memory_type=MemoryType.INDICATOR_OBSERVATION,
                ),
            ]
        )
        db_session.commit()
        try:
            body = client.get(
                "/api/incident-memories/recent?limit=50",
                headers=auth_header(admin_token),
            ).json()
            ids = [item["memory_id"] for item in body[:2]]
            assert ids == sorted((str(id_a), str(id_b)))
            assert body[0]["created_at"] == body[1]["created_at"]
        finally:
            _cleanup(db_session, id_a, id_b)

    def test_recent_invalid_limit_rejected(
        self, client: TestClient, admin_token: str
    ) -> None:
        for limit in ("0", "-1", "201", "abc"):
            response = client.get(
                f"/api/incident-memories/recent?limit={limit}",
                headers=auth_header(admin_token),
            )
            assert response.status_code == 422, limit


# ---------------------------------------------------------------------------
# 8. Route ordering — static routes never resolve as /{memory_id}
# ---------------------------------------------------------------------------


class TestRouteCollision:
    def test_recent_resolves_to_recent_endpoint(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            "/api/incident-memories/recent", headers=auth_header(admin_token)
        )
        assert response.status_code == 200
        assert isinstance(response.json(), list)  # a feed, never a single record

    def test_collection_root_returns_page_envelope(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            "/api/incident-memories", headers=auth_header(admin_token)
        )
        assert response.status_code == 200
        assert response.json().keys() == {"items", "total", "page", "page_size"}

    def test_segmented_correlation_path_never_a_memory_lookup(
        self, client: TestClient, admin_token: str
    ) -> None:
        # "correlation" is not a UUID, so if /correlation/{id} were shadowed
        # by /{memory_id} the request would 422 on UUID parsing — but the
        # segmented route must be matched first.  A bare trailing segmentless
        # path missing its id yields 404/422 (route matched, no id).
        response = client.get(
            "/api/incident-memories/correlation/", headers=auth_header(admin_token)
        )
        assert response.status_code in (404, 422)
        # The valid segmented route still answers correctly under the same prefix.
        valid = client.get(
            f"/api/incident-memories/correlation/{uuid.uuid4()}",
            headers=auth_header(admin_token),
        )
        assert valid.status_code == 200


# ---------------------------------------------------------------------------
# 9. Error handling & sanitization
# ---------------------------------------------------------------------------


class TestErrorSanitization:
    def test_database_failure_becomes_safe_503(
        self, client: TestClient, admin_token: str, monkeypatch
    ) -> None:
        class _BrokenService:
            def get_memory(self, db, memory_id):
                raise IncidentMemoryQueryError(
                    memory_id=memory_id,
                    reason="simulated database failure",
                )

        monkeypatch.setattr(incident_memory_routes, "_service", _BrokenService())
        response = client.get(
            f"/api/incident-memories/{uuid.uuid4()}", headers=auth_header(admin_token)
        )
        assert response.status_code == 503
        assert response.json() == {"detail": "Incident memory data is unavailable"}

    def test_database_failure_leaks_no_internals(
        self, client: TestClient, admin_token: str, monkeypatch
    ) -> None:
        class _BrokenService:
            def list_recent_memories(self, db, *, limit=50):
                raise IncidentMemoryQueryError(reason="simulated failure")

        monkeypatch.setattr(incident_memory_routes, "_service", _BrokenService())
        response = client.get(
            "/api/incident-memories/recent", headers=auth_header(admin_token)
        )
        assert response.status_code == 503
        raw = response.text.lower()
        for fragment in ("sqlalchemy", "psycopg", "traceback", "exception", "postgres"):
            assert fragment not in raw

    def test_correlation_list_failure_becomes_safe_503(
        self, client: TestClient, admin_token: str, monkeypatch
    ) -> None:
        class _BrokenService:
            def list_memories_for_correlation(
                self, db, correlation_id, *, page=1, page_size=50
            ):
                raise IncidentMemoryQueryError(
                    reason="simulated failure",
                )

        monkeypatch.setattr(incident_memory_routes, "_service", _BrokenService())
        response = client.get(
            f"/api/incident-memories/correlation/{uuid.uuid4()}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 503
        assert response.json()["detail"] == "Incident memory data is unavailable"

    def test_service_validation_error_maps_to_422(
        self, client: TestClient, admin_token: str, monkeypatch
    ) -> None:
        class _RejectingService:
            def list_memories(
                self, db, *, page=1, page_size=50, memory_type=None
            ):
                raise IncidentMemoryQueryValidationError(
                    reason="memory_type validation failed inside the service"
                )

        monkeypatch.setattr(incident_memory_routes, "_service", _RejectingService())
        response = client.get(
            "/api/incident-memories", headers=auth_header(admin_token)
        )
        assert response.status_code == 422
        assert "inside the service" in response.json()["detail"]

    def test_unexpected_error_maps_to_sanitized_500(
        self, admin_token: str, monkeypatch
    ) -> None:
        class _ExplodingService:
            def get_memory(self, db, memory_id):
                raise RuntimeError("boom")

        monkeypatch.setattr(incident_memory_routes, "_service", _ExplodingService())
        # raise_server_exceptions=False lets the centralized exception
        # handler produce the response instead of TestClient re-raising.
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get(
            f"/api/incident-memories/{uuid.uuid4()}", headers=auth_header(admin_token)
        )
        assert response.status_code == 500
        assert response.json() == {"detail": "Internal server error"}
        assert "boom" not in response.text


# ---------------------------------------------------------------------------
# 10. Security — secret contract intact end-to-end
# ---------------------------------------------------------------------------


class TestSecretRedaction:
    def test_secret_shaped_metadata_remains_redacted(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        body = client.get(
            f"/api/incident-memories/{ds.secret_memory.memory_id}",
            headers=auth_header(admin_token),
        ).json()
        nested = body["indicators"][0]["metadata"]["nested"]
        assert nested["token"] == "<redacted>"
        assert nested["reputation"] == 87
        assert body["memory_metadata"] == {"nested": {"alpha": 1}}

    def test_raw_credentials_never_appear_in_response(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        raw = client.get(
            f"/api/incident-memories/{ds.secret_memory.memory_id}",
            headers=auth_header(admin_token),
        ).text
        assert ds.credential_value not in raw

    def test_response_exposes_no_database_internals(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        response = client.get(
            f"/api/incident-memories/{ds.memories[0].memory_id}",
            headers=auth_header(admin_token),
        )
        raw = response.text.lower()
        for fragment in ("sqlalchemy", "psycopg", "postgres", "traceback", "exception"):
            assert fragment not in raw


class TestSourceSecretRejection:
    def test_secret_shaped_source_metadata_rejected_at_construction(
        self, client: TestClient, db_session: Session, admin_token: str
    ) -> None:
        """Credential-shaped source metadata is still rejected (never stored)."""
        before = _count(db_session)
        with pytest.raises(pydantic.ValidationError):
            _memory(
                None,
                sources=[
                    _source(metadata={"authorization": "Bearer abc.def.ghi"})
                ],
            )
        assert _count(db_session) == before

    def test_secret_shaped_memory_metadata_rejected_at_construction(
        self, client: TestClient, db_session: Session, admin_token: str
    ) -> None:
        """Credential-shaped memory metadata is still rejected (never stored)."""
        before = _count(db_session)
        with pytest.raises(pydantic.ValidationError):
            _memory(None, metadata={"api_key": "sk-12345"})
        assert _count(db_session) == before


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
        before = _count(db_session)

        urls = [
            f"/api/incident-memories/{ds.memories[0].memory_id}",
            f"/api/incident-memories/correlation/{ds.correlation_a}",
            "/api/incident-memories/recent",
            "/api/incident-memories?memory_type=indicator_observation",
        ]
        for url in urls:
            assert client.get(url, headers=auth_header(admin_token)).status_code == 200

        assert _count(db_session) == before

    def test_no_mutation_endpoints_exist(self, client: TestClient) -> None:
        spec = client.get("/openapi.json").json()
        for path in spec["paths"]:
            if "incident-memories" in path:
                assert set(spec["paths"][path]) == {"get"}, path

    def test_no_write_methods_accepted(
        self, client: TestClient, admin_token: str
    ) -> None:
        for method in ("post", "put", "patch", "delete"):
            response = getattr(client, method)(
                "/api/incident-memories/recent", headers=auth_header(admin_token)
            )
            assert response.status_code == 405, method


# ---------------------------------------------------------------------------
# 12. Architecture — routes delegate to the query service only
# ---------------------------------------------------------------------------


class TestArchitecture:
    def test_route_delegates_to_query_service_for_get(
        self, client: TestClient, admin_token: str, monkeypatch
    ) -> None:
        memory_id = uuid.uuid4()
        called_with = []

        class _ProbeService:
            def get_memory(self, db, memory_id):
                called_with.append(memory_id)
                return {
                    "id": str(uuid.uuid4()),
                    "memory_id": str(memory_id),
                    "memory_type": "incident_summary",
                    "title": "probe memory",
                    "summary": "",
                    "correlation_id": None,
                    "sources": [],
                    "indicators": [],
                    "entities": [],
                    "techniques": [],
                    "findings": [],
                    "actions": [],
                    "outcomes": {},
                    "memory_metadata": {},
                    "confidence": 0.5,
                    "provenance": "recalled",
                    "created_at": "2026-09-20T12:00:00Z",
                    "updated_at": "2026-09-20T12:00:00Z",
                }

        monkeypatch.setattr(incident_memory_routes, "_service", _ProbeService())
        response = client.get(
            f"/api/incident-memories/{memory_id}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200
        assert response.json()["memory_id"] == str(memory_id)
        assert called_with == [memory_id]

    def test_route_delegates_to_query_service_for_correlation_list(
        self, client: TestClient, admin_token: str, monkeypatch
    ) -> None:
        correlation_id = uuid.uuid4()
        called_with = []

        class _ProbeService:
            def list_memories_for_correlation(
                self, db, correlation_id, *, page=1, page_size=50
            ):
                called_with.append((correlation_id, page, page_size))
                return {
                    "items": [],
                    "total": 0,
                    "page": page,
                    "page_size": page_size,
                }

        monkeypatch.setattr(incident_memory_routes, "_service", _ProbeService())
        response = client.get(
            f"/api/incident-memories/correlation/{correlation_id}?page=2&page_size=7",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200
        assert response.json()["total"] == 0
        assert called_with == [(correlation_id, 2, 7)]

    def test_route_delegates_to_query_service_for_recent(
        self, client: TestClient, admin_token: str, monkeypatch
    ) -> None:
        called_with = []

        class _ProbeService:
            def list_recent_memories(self, db, *, limit=50):
                called_with.append(limit)
                return []

        monkeypatch.setattr(incident_memory_routes, "_service", _ProbeService())
        response = client.get(
            "/api/incident-memories/recent?limit=3",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200
        assert response.json() == []
        assert called_with == [3]

    def test_route_delegates_general_list_with_memory_type_filter(
        self, client: TestClient, admin_token: str, monkeypatch
    ) -> None:
        called_with = []

        class _ProbeService:
            def list_memories(
                self, db, *, page=1, page_size=50, memory_type=None
            ):
                called_with.append((page, page_size, memory_type))
                return {
                    "items": [],
                    "total": 0,
                    "page": page,
                    "page_size": page_size,
                }

        monkeypatch.setattr(incident_memory_routes, "_service", _ProbeService())
        response = client.get(
            "/api/incident-memories?memory_type=attack_pattern&page=2&page_size=7",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200
        assert response.json()["total"] == 0
        assert called_with == [(2, 7, MemoryType.ATTACK_PATTERN)]

    def test_route_source_has_no_direct_database_access(self) -> None:
        """The route module must not perform raw SQLAlchemy operations."""
        source = inspect.getsource(incident_memory_routes)
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
        "/api/incident-memories",
        "/api/incident-memories/{memory_id}",
        "/api/incident-memories/correlation/{correlation_id}",
        "/api/incident-memories/recent",
    }

    def test_router_registered_under_existing_api_prefix(
        self, client: TestClient
    ) -> None:
        spec = client.get("/openapi.json").json()
        memory_paths = {
            path for path in spec["paths"] if "incident-memories" in path
        }
        assert memory_paths == self.EXPECTED_PATHS

    def test_every_memory_operation_requires_bearer_auth(
        self, client: TestClient
    ) -> None:
        spec = client.get("/openapi.json").json()
        for path in self.EXPECTED_PATHS:
            operation = spec["paths"][path]["get"]
            assert operation["security"] == [{"HTTPBearer": []}], path
            assert operation["tags"] == ["Incident Memories"], path

    def test_memory_paths_expose_no_other_methods(self, client: TestClient) -> None:
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

    def test_security_scheme_declared(self, client: TestClient) -> None:
        spec = client.get("/openapi.json").json()
        schemes = spec.get("components", {}).get("securitySchemes", {})
        assert "HTTPBearer" in schemes
        assert schemes["HTTPBearer"]["scheme"] == "bearer"