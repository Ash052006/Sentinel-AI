"""SOAR API tests (V2.18) — HTTP surface and RBAC.

Authentication on every endpoint, SOC authorization (reads: admin/analyst/
ciso; lifecycle mutations: admin-only), the execute/dry-run/cancel
contract, deterministic idempotency, and the HTTP error semantics
(401/403/404/409/422).

These tests exercise the real app against the Postgres database, exactly
as the other API suites do; test-created executions are removed at the end
of the module.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.security import create_access_token, hash_password
from app.models.role import Role
from app.models.soar_execution import SoarExecutionRow
from app.models.soar_step_execution import SoarStepExecutionRow
from app.models.user import User
from app.schemas.policy_decision import PolicyDecisionStatus
from tests.conftest import auth_header as _auth_header
from tests.unit.soar_test_helpers import a_request

_created_execution_ids: list[uuid.UUID] = []


@pytest.fixture(scope="session")
def outsider_token(db_session: Session, _ensure_roles) -> str:
    role = db_session.execute(
        select(Role).where(Role.name == "viewer")
    ).scalar_one_or_none()
    if role is None:
        role = Role(name="viewer", description="view only")
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


@pytest.fixture(scope="session", autouse=True)
def _register_test_executions(db_session: Session):
    """Record ids of executions created during tests & remove them later."""
    yield

    def _record(payload: dict, response) -> None:
        raise NotImplementedError

    del _record
    if not _created_execution_ids:
        return
    db_session.execute(
        delete(SoarStepExecutionRow).where(
            SoarStepExecutionRow.execution_id.in_(
                select(SoarExecutionRow.id).where(
                    SoarExecutionRow.execution_id.in_(_created_execution_ids)
                )
            )
        )
    )
    db_session.execute(
        delete(SoarExecutionRow).where(
            SoarExecutionRow.execution_id.in_(_created_execution_ids)
        )
    )
    db_session.commit()


def _remember(execution_id: uuid.UUID) -> uuid.UUID:
    _created_execution_ids.append(execution_id)
    return execution_id


class TestAuth:
    def test_every_endpoint_requires_a_token(self, client: TestClient) -> None:
        get_urls = [
            "/api/soar/playbooks",
            "/api/soar/playbooks/block_ip",
            "/api/soar/executions",
            "/api/soar/executions/{}".format(uuid.uuid4()),
        ]
        post_urls = [
            "/api/soar/dry-run",
            "/api/soar/executions",
            "/api/soar/executions/{}/cancel".format(uuid.uuid4()),
        ]
        for url in get_urls:
            assert client.get(url).status_code == 401, url
        for url in post_urls:
            assert client.post(url, json={}).status_code == 401, url

    def test_invalid_token_rejected(self, client: TestClient) -> None:
        headers = {"Authorization": "Bearer not-a-token"}
        assert client.get("/api/soar/playbooks", headers=headers).status_code == 401


class TestReadAuthorization:
    @pytest.mark.parametrize("token_fixture", ["admin_token", "analyst_token", "ciso_token"])
    def test_soc_roles_can_read(
        self, client: TestClient, request: pytest.FixtureRequest, token_fixture: str
    ) -> None:
        headers = _auth_header(request.getfixturevalue(token_fixture))
        assert client.get("/api/soar/playbooks", headers=headers).status_code == 200
        assert (
            client.get("/api/soar/playbooks/block_ip", headers=headers).status_code
            == 200
        )
        assert client.get("/api/soar/executions", headers=headers).status_code == 200

    def test_outsider_role_forbidden(self, client: TestClient, outsider_token: str) -> None:
        headers = _auth_header(outsider_token)
        assert client.get("/api/soar/playbooks", headers=headers).status_code == 403


class TestMutationAuthorization:
    def test_non_admin_cannot_execute(self, client: TestClient, analyst_token: str) -> None:
        body = a_request()
        assert client.post(
            "/api/soar/executions", json=body, headers=_auth_header(analyst_token)
        ).status_code == 403

    def test_non_admin_cannot_dry_run(self, client: TestClient, ciso_token: str) -> None:
        assert client.post(
            "/api/soar/dry-run", json=a_request(), headers=_auth_header(ciso_token)
        ).status_code == 403

    def test_non_admin_cannot_cancel(
        self, client: TestClient, analyst_token: str, admin_token: str
    ) -> None:
        body = a_request(status=PolicyDecisionStatus.REQUIRES_APPROVAL)
        created = client.post(
            "/api/soar/executions", json=body, headers=_auth_header(admin_token)
        ).json()
        _remember(uuid.UUID(created["execution_id"]))
        assert client.post(
            f"/api/soar/executions/{created['execution_id']}/cancel",
            headers=_auth_header(analyst_token),
        ).status_code == 403


class TestPlaybooks:
    def test_list_returns_registered_seed(self, client: TestClient, admin_token: str) -> None:
        response = client.get(
            "/api/soar/playbooks", headers=_auth_header(admin_token)
        )
        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 7
        assert body["page"] == 1
        ids = {item["playbook_id"] for item in body["items"]}
        assert "block_ip" in ids
        assert "endpoint_containment" in ids

    def test_get_one_playbook_includes_steps(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            "/api/soar/playbooks/block_ip", headers=_auth_header(admin_token)
        )
        assert response.status_code == 200
        record = response.json()
        assert record["primary_action"] == "block_ip"
        assert len(record["steps"]) == 1
        assert record["steps"][0]["provider_id"] == "firewall"

    def test_unknown_playbook_404(self, client: TestClient, admin_token: str) -> None:
        response = client.get(
            "/api/soar/playbooks/ghost", headers=_auth_header(admin_token)
        )
        assert response.status_code == 404

    def test_invalid_page_params_rejected(self, client: TestClient, admin_token: str) -> None:
        assert client.get(
            "/api/soar/playbooks?page=0", headers=_auth_header(admin_token)
        ).status_code == 422
        assert client.get(
            "/api/soar/playbooks?page_size=5000", headers=_auth_header(admin_token)
        ).status_code == 422


class TestExecuteApi:
    def test_execute_allowed_succeeds(self, client: TestClient, admin_token: str) -> None:
        body = a_request()
        response = client.post(
            "/api/soar/executions", json=body, headers=_auth_header(admin_token)
        )
        assert response.status_code == 200
        record = response.json()
        assert record["status"] == "succeeded"
        assert record["playbook_id"] == "block_ip"
        assert record["target"] == "203.0.113.7"
        assert len(record["steps"]) == 1
        assert record["steps"][0]["status"] == "succeeded"
        _remember(uuid.UUID(record["execution_id"]))

    def test_execute_is_idempotent(self, client: TestClient, admin_token: str) -> None:
        body = a_request()
        first = client.post(
            "/api/soar/executions", json=body, headers=_auth_header(admin_token)
        ).json()
        second = client.post(
            "/api/soar/executions", json=body, headers=_auth_header(admin_token)
        ).json()
        assert first["execution_id"] == second["execution_id"]
        _remember(uuid.UUID(first["execution_id"]))

    def test_execute_denied_rejected(self, client: TestClient, admin_token: str) -> None:
        body = a_request(status=PolicyDecisionStatus.DENIED)
        record = client.post(
            "/api/soar/executions", json=body, headers=_auth_header(admin_token)
        ).json()
        assert record["status"] == "rejected"
        assert record["error_code"] == "POLICY_DENIED"
        assert record["steps"] == []
        _remember(uuid.UUID(record["execution_id"]))

    def test_execute_requires_approval_pending(
        self, client: TestClient, admin_token: str
    ) -> None:
        body = a_request(status=PolicyDecisionStatus.REQUIRES_APPROVAL)
        record = client.post(
            "/api/soar/executions", json=body, headers=_auth_header(admin_token)
        ).json()
        assert record["status"] == "pending"
        assert record["error_code"] == "APPROVAL_NOT_GIVEN"
        assert record["steps"] == []
        _remember(uuid.UUID(record["execution_id"]))

    def test_execute_unknown_playbook_422(self, client: TestClient, admin_token: str) -> None:
        body = a_request(playbook_id="ghost")
        assert client.post(
            "/api/soar/executions", json=body, headers=_auth_header(admin_token)
        ).status_code == 422

    def test_execute_invalid_decision_422(self, client: TestClient, admin_token: str) -> None:
        body = a_request()
        body["decision"] = {"junk": True}
        assert client.post(
            "/api/soar/executions", json=body, headers=_auth_header(admin_token)
        ).status_code == 422


class TestDryRunApi:
    def test_dry_run_returns_simulated(self, client: TestClient, admin_token: str) -> None:
        response = client.post(
            "/api/soar/dry-run", json=a_request(), headers=_auth_header(admin_token)
        )
        assert response.status_code == 200
        body = response.json()
        assert body["simulated"] is True
        assert body["status"] == "succeeded"
        assert len(body["steps"]) == 1


class TestExecutionReads:
    def test_get_execution_by_id(self, client: TestClient, admin_token: str) -> None:
        created = client.post(
            "/api/soar/executions",
            json=a_request(),
            headers=_auth_header(admin_token),
        ).json()
        _remember(uuid.UUID(created["execution_id"]))
        response = client.get(
            f"/api/soar/executions/{created['execution_id']}",
            headers=_auth_header(admin_token),
        )
        assert response.status_code == 200
        assert response.json()["execution_id"] == created["execution_id"]

    def test_get_unknown_execution_404(self, client: TestClient, admin_token: str) -> None:
        assert client.get(
            f"/api/soar/executions/{uuid.uuid4()}",
            headers=_auth_header(admin_token),
        ).status_code == 404

    def test_list_and_status_filter(self, client: TestClient, admin_token: str) -> None:
        record = client.post(
            "/api/soar/executions",
            json=a_request(status=PolicyDecisionStatus.DENIED),
            headers=_auth_header(admin_token),
        ).json()
        _remember(uuid.UUID(record["execution_id"]))
        listing = client.get(
            "/api/soar/executions?status=rejected",
            headers=_auth_header(admin_token),
        ).json()
        assert listing["total"] >= 1
        same = [item for item in listing["items"] if item["execution_id"] == record["execution_id"]]
        assert same and same[0]["status"] == "rejected"


class TestCancelApi:
    def test_cancel_pending_flow(self, client: TestClient, admin_token: str) -> None:
        created = client.post(
            "/api/soar/executions",
            json=a_request(status=PolicyDecisionStatus.REQUIRES_APPROVAL),
            headers=_auth_header(admin_token),
        ).json()
        execution_id = created["execution_id"]
        _remember(uuid.UUID(execution_id))

        cancelled = client.post(
            f"/api/soar/executions/{execution_id}/cancel",
            headers=_auth_header(admin_token),
        )
        assert cancelled.status_code == 200
        assert cancelled.json()["status"] == "cancelled"

        # cancelling again is idempotent
        again = client.post(
            f"/api/soar/executions/{execution_id}/cancel",
            headers=_auth_header(admin_token),
        )
        assert again.status_code == 200

    def test_cancel_terminal_execution_conflicts(
        self, client: TestClient, admin_token: str
    ) -> None:
        created = client.post(
            "/api/soar/executions",
            json=a_request(),
            headers=_auth_header(admin_token),
        ).json()
        execution_id = created["execution_id"]
        _remember(uuid.UUID(execution_id))
        response = client.post(
            f"/api/soar/executions/{execution_id}/cancel",
            headers=_auth_header(admin_token),
        )
        assert response.status_code == 409

    def test_cancel_unknown_execution_404(self, client: TestClient, admin_token: str) -> None:
        assert client.post(
            f"/api/soar/executions/{uuid.uuid4()}/cancel",
            headers=_auth_header(admin_token),
        ).status_code == 404


class TestOpenApi:
    def test_soar_paths_present(self, client: TestClient) -> None:
        spec = client.get("/openapi.json").json()
        paths = set(spec["paths"])
        assert "/api/soar/playbooks" in paths
        assert "/api/soar/playbooks/{playbook_id}" in paths
        assert "/api/soar/executions" in paths
        assert "/api/soar/executions/{execution_id}" in paths
        assert "/api/soar/executions/{execution_id}/cancel" in paths
        assert "/api/soar/dry-run" in paths

    def test_no_playbook_authoring_endpoints(self, client: TestClient) -> None:
        spec = client.get("/openapi.json").json()
        for path in spec["paths"]:
            if "/api/soar/playbooks" in path:
                assert set(spec["paths"][path]) <= {"get"}, path