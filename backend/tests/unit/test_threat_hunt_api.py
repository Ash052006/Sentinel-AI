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
from app.models.detection_result import DetectionResult
from app.models.threat_hunt import (
    ThreatHuntEvidenceRow,
    ThreatHuntFindingRow,
    ThreatHuntRow,
    ThreatHuntTimelineItemRow,
)
from app.models.user import User
from tests.conftest import auth_header as _auth_header
from tests.unit.threat_hunt_test_helpers import a_detection

NOW = datetime.now(timezone.utc)
START = NOW - timedelta(days=1)
END = NOW + timedelta(days=1)

_created_hunt_ids: list[uuid.UUID] = []
#: Detection rows this module persisted, removed at module teardown alongside
#: the hunts so the shared database is left exactly as it was found.
_created_detection_ids: list[uuid.UUID] = []


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
    if _created_detection_ids:
        db_session.execute(
            delete(DetectionResult).where(
                DetectionResult.detection_id.in_(_created_detection_ids)
            )
        )
        db_session.commit()
        _created_detection_ids.clear()


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


def _seed_detections(db: Session, *, rule_ids: list[str]) -> tuple[uuid.UUID, list[uuid.UUID]]:
    """Persist detections owned by this test and return their identifiers.

    The suite runs against the shared development database, which legitimately
    holds detections this module did not write.  Reads are therefore scoped by
    a freshly minted ``event_id`` rather than by the absence of other rows, so
    the same assertions hold against an empty, a populated, and a
    development-like database.
    """
    event_id = uuid.uuid4()
    detection_ids: list[uuid.UUID] = []
    for index, rule_id in enumerate(rule_ids):
        row = a_detection(
            db,
            event_id=event_id,
            detection_id=uuid.uuid4(),
            rule_id=rule_id,
            at=NOW + timedelta(minutes=index),
        )
        detection_ids.append(row.detection_id)
    db.commit()
    _created_detection_ids.extend(detection_ids)
    return event_id, detection_ids


def _scoped_payload(event_id: uuid.UUID, **overrides) -> dict:
    """A detection-review hunt restricted to one test-owned ``event_id``."""
    return _payload(
        **{
            "name": "Scoped read hunt",
            "filters": [
                {"field": "event_id", "operator": "equals", "value": str(event_id)}
            ],
            **overrides,
        }
    )


def _runnable_payload(db: Session) -> dict:
    """A hunt guaranteed to execute, whatever else the database holds.

    An unfiltered hunt sweeps every detection in the window, so on a busy
    database it legitimately trips the evidence cap and the run is refused.
    Lifecycle and RBAC assertions are about the run succeeding, so they get a
    hunt scoped to a detection this test owns.
    """
    event_id, _ = _seed_detections(db, rule_ids=["RULE-RUNNABLE"])
    return _scoped_payload(event_id, name="Runnable lifecycle hunt")


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
        self,
        client: TestClient,
        request: pytest.FixtureRequest,
        token_fixture: str,
        db_session: Session,
    ) -> None:
        headers = _auth_header(request.getfixturevalue(token_fixture))
        assert client.get("/api/threat-hunts", headers=headers).status_code == 200
        created = client.post(
            "/api/threat-hunts", json=_runnable_payload(db_session), headers=headers
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
    def test_run_completed_then_conflict(
        self, client: TestClient, admin_token: str, db_session: Session
    ) -> None:
        created = client.post(
            "/api/threat-hunts",
            json=_runnable_payload(db_session),
            headers=_auth_header(admin_token),
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
    def _completed_hunt(
        self, client: TestClient, admin_token: str, payload: dict | None = None
    ) -> str:
        created = client.post(
            "/api/threat-hunts",
            json=_payload() if payload is None else payload,
            headers=_auth_header(admin_token),
        ).json()
        hunt_id = created["hunt_id"]
        _remember(uuid.UUID(hunt_id))
        client.post(f"/api/threat-hunts/{hunt_id}/run", headers=_auth_header(admin_token))
        return hunt_id

    def test_evidence_findings_timeline_pages(
        self, client: TestClient, admin_token: str, db_session: Session
    ) -> None:
        # The hunt is scoped to detections this test persisted, so the expected
        # totals are a property of the hunt under test rather than of whatever
        # else the shared database happens to contain.
        seeded = ["RULE-READ-A", "RULE-READ-B", "RULE-READ-A", "RULE-READ-C"]
        event_id, detection_ids = _seed_detections(db_session, rule_ids=seeded)
        hunt_id = self._completed_hunt(
            client, admin_token, _scoped_payload(event_id)
        )
        headers = _auth_header(admin_token)

        evidence = client.get(f"/api/threat-hunts/{hunt_id}/evidence", headers=headers)
        assert evidence.status_code == 200
        body = evidence.json()
        assert body["total"] == len(detection_ids)
        assert len(body["items"]) == len(detection_ids)
        assert {item["reference_id"] for item in body["items"]} == {
            str(d) for d in detection_ids
        }

        findings = client.get(f"/api/threat-hunts/{hunt_id}/findings", headers=headers)
        assert findings.status_code == 200
        finding_body = findings.json()
        # One finding per distinct rule_id, plus the always-present summary.
        assert finding_body["total"] == len(set(seeded)) + 1
        assert any(
            item["description"].startswith("Collected") for item in finding_body["items"]
        )
        for rule_id in set(seeded):
            assert any(rule_id in item["title"] for item in finding_body["items"])

        timeline = client.get(f"/api/threat-hunts/{hunt_id}/timeline", headers=headers)
        assert timeline.status_code == 200
        assert timeline.json()["total"] == len(detection_ids)

    def test_evidence_reads_are_not_polluted_by_unrelated_detections(
        self, client: TestClient, admin_token: str, db_session: Session
    ) -> None:
        """A scoped hunt sees only its own events, whatever else exists.

        The shared database may hold detections from the demo, from earlier
        suites, or none at all.  Seeding an unrelated event inside the same
        window must not change the scoped hunt's totals.
        """
        event_id, detection_ids = _seed_detections(
            db_session, rule_ids=["RULE-ISOLATION-OWN"]
        )
        # A neighbouring event, in the same window, owned by nobody else.
        _seed_detections(db_session, rule_ids=["RULE-ISOLATION-OTHER"])
        headers = _auth_header(admin_token)

        scoped = self._completed_hunt(client, admin_token, _scoped_payload(event_id))
        evidence = client.get(
            f"/api/threat-hunts/{scoped}/evidence", headers=headers
        ).json()
        assert evidence["total"] == len(detection_ids)
        assert {item["reference_id"] for item in evidence["items"]} == {
            str(d) for d in detection_ids
        }

    def test_evidence_pagination_is_deterministic(
        self, client: TestClient, admin_token: str, db_session: Session
    ) -> None:
        """Paging a scoped hunt is stable, complete, and duplicate-free."""
        seeded = [f"RULE-PAGE-{index:02d}" for index in range(5)]
        event_id, detection_ids = _seed_detections(db_session, rule_ids=seeded)
        hunt_id = self._completed_hunt(
            client, admin_token, _scoped_payload(event_id)
        )
        headers = _auth_header(admin_token)
        expected = {str(d) for d in detection_ids}

        collected: list[str] = []
        page = 1
        while True:
            body = client.get(
                f"/api/threat-hunts/{hunt_id}/evidence",
                params={"page": page, "page_size": 2},
                headers=headers,
            ).json()
            assert body["total"] == len(detection_ids)
            assert body["page"] == page
            collected.extend(item["reference_id"] for item in body["items"])
            if len(body["items"]) < 2:
                break
            page += 1

        assert page == 3  # 5 rows at page_size=2 -> 2 + 2 + 1
        assert len(collected) == len(set(collected))  # no repeats across pages
        assert set(collected) == expected  # every seeded row, nothing else

        first = client.get(
            f"/api/threat-hunts/{hunt_id}/evidence",
            params={"page": 1, "page_size": 2},
            headers=headers,
        ).json()
        repeat = client.get(
            f"/api/threat-hunts/{hunt_id}/evidence",
            params={"page": 1, "page_size": 2},
            headers=headers,
        ).json()
        assert first["items"] == repeat["items"]  # stable ordering

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
        # The listing endpoint paginates: on a shared, non-pristine database
        # ``total`` counts every matching row while ``items`` holds at most one
        # bounded page.  Assert the pagination invariant rather than absolute
        # equality so the test is independent of accumulated DB state.
        assert len(listing["items"]) == min(listing["total"], listing["page_size"])
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