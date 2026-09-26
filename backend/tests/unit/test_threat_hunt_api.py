"""Threat Hunting API tests (V2.19) — HTTP surface, RBAC, error semantics.

The governed analyst surface exercised against the real Postgres database:

* authentication is required on every endpoint (401 without/with a bad
  token);
* ``admin`` / ``analyst`` / ``ciso`` may read and run hunts; an outsider
  ``viewer`` role is denied everywhere (403) and the refusal is audited;
* create/run/cancel lifecycle with the run-once CAS contract surfaced as
  409 conflicts, unknown hunts as 404, malformed grammar / bounds as 422;
* bounded evidence/findings/timeline reads that never escape the cap;
* the OpenAPI surface exposes read + governed-mutation routes only.

Test-created hunts (and their child rows) are removed at the end of the
module, mirroring the other API suites.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.security import create_access_token, hash_password
from app.models.role import Role
from app.models.threat_hunt import (
    ThreatHuntEvidenceRow,
    ThreatHuntFindingRow,
    ThreatHuntRow,
    ThreatHuntTimelineItemRow,
)
from app.models.user import User
from tests.conftest import auth_header as _auth_header

NOW = datetime.now(timezone.utc)
START = NOW - timedelta(days=1)
END = NOW + timedelta(days=1)

_created_hunt_ids: list[uuid.UUID] = []


@pytest.fixture(scope="session")
def outsider_token(db_session: Session, _ensure_roles) -> str:
    role = db_session.execute(
        select(Role).where(Role.name == "viewer")
    ).scalar_one_or_none()
    if role is None:
        role = Role(name="viewer", description="read-only non-SOC role")
        db_session.add(role)
        db_session.commit()
        db_session.refresh(role)
    email = f"test-hunt-viewer-{uuid.uuid4().hex[:8]}@example.com"
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
def _register_test_hunts(db_session: Session):
    yield
    if not _created_hunt_ids:
        return
    hunt_ids = [str(h) for h in _created_hunt_ids]
    for model in (
        ThreatHuntTimelineItemRow,
        ThreatHuntFindingRow,
        ThreatHuntEvidenceRow,
    ):
        db_session.execute(
            delete(model).where(model.hunt_id.in_(hunt_ids))
        )
    db_session.execute(
        delete(ThreatHuntRow).where(ThreatHuntRow.hunt_id.in_(hunt_ids))
    )
    db_session.commit()
    _created_hunt_ids.clear()


def _remember(hunt_id: uuid.UUID) -> uuid.UUID:
    _created_hunt_ids.append(hunt_id)
    return hunt_id


def _payload(**overrides) -> dict:
    data = {
        "name": "API review hunt",
        "hunt_type": "detection_review",
        "description": "Guarded HTTP surface verification.",
        "start_time": START.isoformat(),
        "end_time": END.isoformat(),
        "filters": [],
    }
    data.update(overrides)
    return data


class TestAuth:
    def test_every_endpoint_requires_a_token(self, client: TestClient) -> None:
        get_urls = [
            "/api/threat-hunts",
            "/api/threat-hunts/{}".format(uuid.uuid4()),
            "/api/threat-hunts/{}/evidence".format(uuid.uuid4()),
            "/api/threat-hunts/{}/findings".format(uuid.uuid4()),
            "/api/threat-hunts/{}/timeline".format(uuid.uuid4()),
        ]
        post_urls = [
            "/api/threat-hunts",
            "/api/threat-hunts/{}/run".format(uuid.uuid4()),
            "/api/threat-hunts/{}/cancel".format(uuid.uuid4()),
        ]
        for url in get_urls:
            assert client.get(url).status_code == 401, url
        for url in post_urls:
            assert client.post(url, json={}).status_code == 401, url

    def test_invalid_token_rejected(self, client: TestClient) -> None:
        headers = {"Authorization": "Bearer not-a-token"}
        assert client.get("/api/threat-hunts", headers=headers).status_code == 401
        assert client.post(
            "/api/threat-hunts", json=_payload(), headers=headers
        ).status_code == 401


class TestAuthorization:
    @pytest.mark.parametrize("token_fixture", ["admin_token", "analyst_token", "ciso_token"])
    def test_soc_roles_can_read_and_create_and_run(
        self, client: TestClient, request: pytest.FixtureRequest, token_fixture: str
    ) -> None:
        headers = _auth_header(request.getfixturevalue(token_fixture))
        assert client.get("/api/threat-hunts", headers=headers).status_code == 200
        created = client.post(
            "/api/threat-hunts", json=_payload(), headers=headers
        )
        assert created.status_code == 201
        hunt_id = uuid.UUID(created.json()["hunt_id"])
        _remember(hunt_id)
        assert client.get(
            f"/api/threat-hunts/{hunt_id}", headers=headers
        ).status_code == 200
        ran = client.post(
            f"/api/threat-hunts/{hunt_id}/run", headers=headers
        )
        assert ran.status_code == 200
        assert ran.json()["status"] == "completed"

    def test_outsider_role_denied_everywhere(
        self, client: TestClient, outsider_token: str
    ) -> None:
        headers = _auth_header(outsider_token)
        assert client.get("/api/threat-hunts", headers=headers).status_code == 403
        assert client.post(
            "/api/threat-hunts", json=_payload(), headers=headers
        ).status_code == 403


class TestCreate:
    def test_create_returns_draft_and_echoes_filters(
        self, client: TestClient, admin_token: str
    ) -> None:
        body = _payload(
            name="echo-filters",
            filters=[
                {"field": "rule_id", "operator": "equals", "value": "RULE-1"}
            ],
        )
        response = client.post(
            "/api/threat-hunts", json=body, headers=_auth_header(admin_token)
        )
        assert response.status_code == 201
        record = response.json()
        _remember(uuid.UUID(record["hunt_id"]))
        assert record["status"] == "draft"
        assert record["result_count"] == 0
        assert record["filters"][0]["field"] == "rule_id"
        assert record["filters"][0]["operator"] == "equals"
        assert record["filters"][0]["value"] == "RULE-1"

    def test_missing_token_field_422(self, client: TestClient, admin_token: str) -> None:
        body = _payload(name="x")
        body.pop("hunt_type")
        assert client.post(
            "/api/threat-hunts", json=body, headers=_auth_header(admin_token)
        ).status_code == 422

    def test_secret_name_422(self, client: TestClient, admin_token: str) -> None:
        assert client.post(
            "/api/threat-hunts",
            json=_payload(name="leaks api_key"),
            headers=_auth_header(admin_token),
        ).status_code == 422

    def test_unknown_filter_field_422(self, client: TestClient, admin_token: str) -> None:
        body = _payload(
            name="bad-field",
            filters=[{"field": "title", "operator": "equals", "value": "Recon"}],
        )
        assert client.post(
            "/api/threat-hunts", json=body, headers=_auth_header(admin_token)
        ).status_code == 422

    def test_field_not_allowed_for_hunt_type_422(
        self, client: TestClient, admin_token: str
    ) -> None:
        body = _payload(
            name="cross-field",
            filters=[
                {"field": "indicator_value", "operator": "equals", "value": "1.2.3.4"}
            ],
        )
        assert client.post(
            "/api/threat-hunts", json=body, headers=_auth_header(admin_token)
        ).status_code == 422

    def test_window_beyond_720_hours_422(
        self, client: TestClient, admin_token: str
    ) -> None:
        body = _payload(
            name="far-window",
            start_time=NOW.isoformat(),
            end_time=(NOW + timedelta(hours=721)).isoformat(),
        )
        assert client.post(
            "/api/threat-hunts", json=body, headers=_auth_header(admin_token)
        ).status_code == 422


class TestRunCancelLifecycle:
    def test_run_completed_then_conflict(self, client: TestClient, admin_token: str) -> None:
        created = client.post(
            "/api/threat-hunts", json=_payload(), headers=_auth_header(admin_token)
        ).json()
        hunt_id = created["hunt_id"]
        _remember(uuid.UUID(hunt_id))

        ran = client.post(
            f"/api/threat-hunts/{hunt_id}/run", headers=_auth_header(admin_token)
        )
        assert ran.status_code == 200
        assert ran.json()["status"] == "completed"

        again = client.post(
            f"/api/threat-hunts/{hunt_id}/run", headers=_auth_header(admin_token)
        )
        assert again.status_code == 409

    def test_run_unknown_hunt_404(self, client: TestClient, admin_token: str) -> None:
        assert client.post(
            f"/api/threat-hunts/{uuid.uuid4()}/run",
            headers=_auth_header(admin_token),
        ).status_code == 404

    def test_cancel_draft_then_conflict(
        self, client: TestClient, admin_token: str
    ) -> None:
        created = client.post(
            "/api/threat-hunts", json=_payload(), headers=_auth_header(admin_token)
        ).json()
        hunt_id = created["hunt_id"]
        _remember(uuid.UUID(hunt_id))
        cancelled = client.post(
            f"/api/threat-hunts/{hunt_id}/cancel", headers=_auth_header(admin_token)
        )
        assert cancelled.status_code == 200
        assert cancelled.json()["status"] == "cancelled"
        again = client.post(
            f"/api/threat-hunts/{hunt_id}/cancel", headers=_auth_header(admin_token)
        )
        assert again.status_code == 409

    def test_cancel_completed_conflicts(
        self, client: TestClient, admin_token: str
    ) -> None:
        created = client.post(
            "/api/threat-hunts", json=_payload(), headers=_auth_header(admin_token)
        ).json()
        hunt_id = created["hunt_id"]
        _remember(uuid.UUID(hunt_id))
        client.post(f"/api/threat-hunts/{hunt_id}/run", headers=_auth_header(admin_token))
        assert client.post(
            f"/api/threat-hunts/{hunt_id}/cancel", headers=_auth_header(admin_token)
        ).status_code == 409

    def test_cancel_unknown_hunt_404(self, client: TestClient, admin_token: str) -> None:
        assert client.post(
            f"/api/threat-hunts/{uuid.uuid4()}/cancel",
            headers=_auth_header(admin_token),
        ).status_code == 404


class TestReads:
    def _completed_hunt(self, client: TestClient, admin_token: str) -> str:
        created = client.post(
            "/api/threat-hunts", json=_payload(), headers=_auth_header(admin_token)
        ).json()
        hunt_id = created["hunt_id"]
        _remember(uuid.UUID(hunt_id))
        client.post(f"/api/threat-hunts/{hunt_id}/run", headers=_auth_header(admin_token))
        return hunt_id

    def test_evidence_findings_timeline_pages(
        self, client: TestClient, admin_token: str
    ) -> None:
        hunt_id = self._completed_hunt(client, admin_token)
        headers = _auth_header(admin_token)

        evidence = client.get(f"/api/threat-hunts/{hunt_id}/evidence", headers=headers)
        assert evidence.status_code == 200
        assert evidence.json()["total"] == 0
        assert evidence.json()["items"] == []

        findings = client.get(f"/api/threat-hunts/{hunt_id}/findings", headers=headers)
        assert findings.status_code == 200
        assert findings.json()["total"] == 1  # always-present summary finding

        timeline = client.get(f"/api/threat-hunts/{hunt_id}/timeline", headers=headers)
        assert timeline.status_code == 200
        assert timeline.json()["total"] == 0

    def test_unknown_hunt_reads_404(self, client: TestClient, admin_token: str) -> None:
        hunt_id = uuid.uuid4()
        headers = _auth_header(admin_token)
        assert client.get(
            f"/api/threat-hunts/{hunt_id}", headers=headers
        ).status_code == 404
        assert client.get(
            f"/api/threat-hunts/{hunt_id}/evidence", headers=headers
        ).status_code == 404
        assert client.get(
            f"/api/threat-hunts/{hunt_id}/findings", headers=headers
        ).status_code == 404
        assert client.get(
            f"/api/threat-hunts/{hunt_id}/timeline", headers=headers
        ).status_code == 404

    def test_page_params_bounded_422(self, client: TestClient, admin_token: str) -> None:
        headers = _auth_header(admin_token)
        assert client.get(
            "/api/threat-hunts?page=0", headers=headers
        ).status_code == 422
        assert client.get(
            "/api/threat-hunts?page_size=5000", headers=headers
        ).status_code == 422

    def test_list_and_status_filter(self, client: TestClient, admin_token: str) -> None:
        headers = _auth_header(admin_token)
        response = client.get("/api/threat-hunts", headers=headers)
        assert response.status_code == 200
        listing = response.json()
        assert listing["page"] == 1
        assert listing["page_size"] == 50
        assert len(listing["items"]) == listing["total"]
        created = client.post(
            "/api/threat-hunts", json=_payload(name="draft-only"), headers=headers
        ).json()
        hunt_id = created["hunt_id"]
        _remember(uuid.UUID(hunt_id))
        drafts = client.get(
            "/api/threat-hunts?status=draft", headers=headers
        ).json()
        matches = [i for i in drafts["items"] if i["hunt_id"] == hunt_id]
        assert matches and matches[0]["status"] == "draft"


class TestOpenApi:
    def test_threat_hunt_paths_present(self, client: TestClient) -> None:
        spec = client.get("/openapi.json").json()
        paths = set(spec["paths"])
        assert "/api/threat-hunts" in paths
        assert "/api/threat-hunts/{hunt_id}" in paths
        assert "/api/threat-hunts/{hunt_id}/run" in paths
        assert "/api/threat-hunts/{hunt_id}/cancel" in paths
        assert "/api/threat-hunts/{hunt_id}/evidence" in paths
        assert "/api/threat-hunts/{hunt_id}/findings" in paths
        assert "/api/threat-hunts/{hunt_id}/timeline" in paths
        assert set(spec["paths"]["/api/threat-hunts"]) == {"get", "post"}
        assert set(spec["paths"]["/api/threat-hunts/{hunt_id}/run"]) == {"post"}
        assert set(spec["paths"]["/api/threat-hunts/{hunt_id}/cancel"]) == {"post"}

    def test_no_execution_surfaces(self, client: TestClient) -> None:
        spec = client.get("/openapi.json").json()
        for path in spec["paths"]:
            if "/threat-hunts" not in path:
                continue
            assert "execute" not in path
            assert "quarantine" not in path
            assert "block" not in path
            assert set(spec["paths"][path]) <= {"get", "post"}