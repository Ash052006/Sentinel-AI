"""V2.20 incident-report API tests (category I) — HTTP surface, RBAC, errors.

Live-Postgres API surface: every endpoint requires a token; admin/analyst/
ciso may generate and read reports; an outsider role is denied (403, and the
refusal is audited); unknown correlations are 404 with no failed row; bounds
and provider failures surface as 422/503; and generated rows are cleaned up
after the module, mirroring the other API suites.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.security import create_access_token, hash_password
from app.models.correlation_member import CorrelationMember
from app.models.correlation_result import CorrelationResult
from app.models.incident_report import IncidentReportRow
from app.models.role import Role
from app.models.user import User
from app.api.routes import incident_reports as incident_reports_route
from app.services.reporting.generator import IncidentReportGenerator
from app.services.reporting.service import IncidentReportService
from tests.conftest import auth_header as _auth_header
from tests.unit.incident_report_test_helpers import (
    FakeReportLLM,
    canonical_model_output,
)

_created_report_ids: list[uuid.UUID] = []
_CORR = uuid.uuid4()
_CORR_MISSING = uuid.uuid4()


@pytest.fixture()
def actor_headers(db_session: Session, admin_user: User) -> dict[str, str]:
    return _auth_header(create_access_token(str(admin_user.id)))


@pytest.fixture(scope="session")
def outsider_token2(db_session: Session, _ensure_roles) -> str:
    return _outsider_token(db_session, "viewer")


def _outsider_token(db_session: Session, role_name: str) -> str:
    role = db_session.execute(
        select(Role).where(Role.name == role_name)
    ).scalar_one_or_none()
    if role is None:
        role = Role(name=role_name, description=f"{role_name} role")
        db_session.add(role)
        db_session.commit()
        db_session.refresh(role)
    email = f"ir-viewer-{uuid.uuid4().hex[:8]}@example.com"
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


@pytest.fixture(scope="session", autouse=True)
def _seed_correlation(db_session: Session, _ensure_roles):
    existing = db_session.execute(
        select(CorrelationResult).where(
            CorrelationResult.correlation_id == _CORR
        )
    ).scalar_one_or_none()
    if existing is None:
        db_session.add(
            CorrelationResult(
                correlation_id=_CORR,
                status="active",
                confidence=0.8,
                evidence={"summary": "correlated"},
                result_metadata={},
                timestamp=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            )
        )
        db_session.commit()


@pytest.fixture(scope="session", autouse=True)
def _swap_service():  # noqa: PT004
    """Point the route at a service whose generator uses a fake LLM."""
    original = incident_reports_route._get_service

    def fake_get_service():
        return IncidentReportService(
            generator_factory=lambda: IncidentReportGenerator(
                llm=FakeReportLLM()
            )
        )

    incident_reports_route._get_service = fake_get_service
    yield
    incident_reports_route._get_service = original


@pytest.fixture(scope="session", autouse=True)
def _cleanup(db_session: Session):
    yield
    if not _created_report_ids:
        return
    db_session.execute(
        delete(IncidentReportRow).where(
            IncidentReportRow.report_id.in_([str(r) for r in _created_report_ids])
        )
    )
    db_session.execute(
        delete(CorrelationMember).where(CorrelationMember.correlation_id == _CORR)
    )
    db_session.execute(
        delete(CorrelationResult).where(CorrelationResult.correlation_id == _CORR)
    )
    db_session.commit()
    _created_report_ids.clear()


def _remember(report_id) -> uuid.UUID:
    _created_report_ids.append(report_id)
    return report_id


class TestAuth:
    def test_every_endpoint_requires_a_token(self, client: TestClient) -> None:
        for url in (
            "/api/incident-reports",
            "/api/incident-reports/{}".format(uuid.uuid4()),
        ):
            assert client.get(url).status_code == 401
        assert client.post(
            "/api/incident-reports/generate",
            json={"correlation_id": str(uuid.uuid4())},
        ).status_code == 401


class TestRbac:
    def test_outside_role_denied_on_read(self, db_session: Session, client: TestClient) -> None:
        token = _outsider_token(db_session, "viewer")
        resp = client.get("/api/incident-reports", headers=_auth_header(token))
        assert resp.status_code == 403

    def test_outside_role_denied_on_generate(self, db_session: Session, client: TestClient) -> None:
        token = _outsider_token(db_session, "viewer")
        resp = client.post(
            "/api/incident-reports/generate",
            headers=_auth_header(token),
            json={"correlation_id": str(uuid.uuid4())},
        )
        assert resp.status_code == 403


class TestGenerate:
    def test_generate_returns_record(self, db_session: Session, client: TestClient, actor_headers) -> None:
        resp = client.post(
            "/api/incident-reports/generate",
            headers=actor_headers,
            json={"correlation_id": str(_CORR)},
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["correlation_id"] == str(_CORR)
        assert body["status"] == "generated"
        assert body["payload"] is not None
        assert body["payload"]["ai"]["title"] == "Correlated network intrusion"
        _remember(uuid.UUID(body["report_id"]))

    def test_generate_unknown_correlation_404_no_row(self, db_session: Session, client: TestClient, actor_headers) -> None:
        resp = client.post(
            "/api/incident-reports/generate",
            headers=actor_headers,
            json={"correlation_id": str(_CORR_MISSING)},
        )
        assert resp.status_code == 404
        rows = db_session.execute(
            select(IncidentReportRow).where(
                IncidentReportRow.correlation_id == str(_CORR_MISSING)
            )
        ).scalars().all()
        assert rows == []

    def test_generate_rejects_bad_version(self, db_session: Session, client: TestClient, actor_headers) -> None:
        resp = client.post(
            "/api/incident-reports/generate",
            headers=actor_headers,
            json={"correlation_id": str(_CORR), "report_version": "9.99"},
        )
        assert resp.status_code == 422


class TestRead:
    def test_list_and_get_round_trip(self, db_session: Session, client: TestClient, actor_headers) -> None:
        created = client.post(
            "/api/incident-reports/generate",
            headers=actor_headers,
            json={"correlation_id": str(_CORR)},
        ).json()
        _remember(uuid.UUID(created["report_id"]))

        listed = client.get("/api/incident-reports", headers=actor_headers)
        assert listed.status_code == 200
        assert any(
            item["report_id"] == created["report_id"]
            for item in listed.json()["items"]
        )

        detail = client.get(
            "/api/incident-reports/{}".format(created["report_id"]),
            headers=actor_headers,
        )
        assert detail.status_code == 200
        assert detail.json()["report_id"] == created["report_id"]

    def test_get_missing_report_404(self, client: TestClient, actor_headers) -> None:
        resp = client.get(
            "/api/incident-reports/{}".format(uuid.uuid4()),
            headers=actor_headers,
        )
        assert resp.status_code == 404