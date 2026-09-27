"""SOAR V2.18 end-to-end scenarios (A–E).

Live-API scenarios against the real application and Postgres, exercising
the full governed path: authorized policy decision -> execution ->
persistence -> read surface -> cancellation, plus the refusal, idempotency
and dry-run guarantees, and the V2.18 response-architecture carve-outs
(SOAR has a domain API; the Step 25 Response service itself stays
endpoint-free).

Scenarios
---------
A. Full sanctioned run — an ALLOWED decision executes the block_ip
   playbook through the sandbox firewall provider and persists a
   readable, step-bearing execution.
B. Denied never executes — a DENIED decision records REJECTED /
   POLICY_DENIED with zero steps (no provider could have been invoked).
C. Pending → cancel — a REQUIRES_APPROVAL decision with no grant is
   recorded PENDING; an admin cancels it (and may cancel again
   idempotently).
D. Idempotent submission — replaying the exact same body returns the
   same execution and persists exactly one row.
E. Dry-run purity + read-only playbook surface — a dry run projects a
   simulated run yet persists nothing; the playbook endpoints are
   GET-only; the Step 25 Response service still exposes no API surface.

Test-created execution rows are removed at the end of the module.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.main import app
from app.models.role import Role
from app.models.soar_execution import SoarExecutionRow
from app.models.soar_step_execution import SoarStepExecutionRow
from app.models.user import User
from app.schemas.policy_decision import PolicyDecisionStatus
from app.services.soar.registry import DEFAULT_SOAR_PROVIDER_REGISTRY
from tests.conftest import auth_header as _auth_header
from tests.unit.soar_test_helpers import a_decision, a_request

_created_execution_ids: list[uuid.UUID] = []


@pytest.fixture(scope="module")
def actor(db_session: Session) -> User:
    role = db_session.execute(
        select(Role).where(Role.name == "admin")
    ).scalar_one_or_none()
    assert role is not None, "admin role must exist (conftest _ensure_roles)"
    user = User(
        email=f"e2e-soar-admin-{uuid.uuid4().hex[:8]}@example.com",
        password_hash="unused",
        is_active=True,
        role_id=role.id,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(scope="module")
def headers(actor: User) -> dict[str, str]:
    from app.core.security import create_access_token

    return _auth_header(create_access_token(str(actor.id)))


@pytest.fixture(scope="module", autouse=True)
def _cleanup(db_session: Session):
    yield
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


class TestSoarE2E:
    def test_a_full_sanctioned_run(
        self, client: TestClient, headers: dict[str, str], db_session: Session
    ) -> None:
        response = client.post(
            "/api/soar/executions", json=a_request(), headers=headers
        )
        assert response.status_code == 200
        record = response.json()
        _remember(uuid.UUID(record["execution_id"]))
        assert record["status"] == "succeeded"
        assert record["simulated"] is False
        assert record["playbook_id"] == "block_ip"
        assert record["steps"][0]["provider_id"] == "firewall"
        assert record["steps"][0]["status"] == "succeeded"

        fetched = client.get(
            f"/api/soar/executions/{record['execution_id']}", headers=headers
        )
        assert fetched.status_code == 200
        assert fetched.json()["execution_id"] == record["execution_id"]

    def test_b_denied_never_executes(
        self, client: TestClient, headers: dict[str, str]
    ) -> None:
        record = client.post(
            "/api/soar/executions",
            json=a_request(status=PolicyDecisionStatus.DENIED),
            headers=headers,
        ).json()
        _remember(uuid.UUID(record["execution_id"]))
        assert record["status"] == "rejected"
        assert record["error_code"] == "POLICY_DENIED"
        assert record["steps"] == []
        assert record["target"] == "203.0.113.7"

    def test_c_pending_then_cancel(
        self, client: TestClient, headers: dict[str, str]
    ) -> None:
        created = client.post(
            "/api/soar/executions",
            json=a_request(status=PolicyDecisionStatus.REQUIRES_APPROVAL),
            headers=headers,
        ).json()
        execution_id = created["execution_id"]
        _remember(uuid.UUID(execution_id))
        assert created["status"] == "pending"
        assert created["error_code"] == "APPROVAL_NOT_GIVEN"

        cancelled = client.post(
            f"/api/soar/executions/{execution_id}/cancel", headers=headers
        )
        assert cancelled.status_code == 200
        assert cancelled.json()["status"] == "cancelled"
        assert cancelled.json()["steps"] == []

        again = client.post(
            f"/api/soar/executions/{execution_id}/cancel", headers=headers
        )
        assert again.status_code == 200

    def test_d_identical_submission_persists_once(
        self, client: TestClient, headers: dict[str, str], db_session: Session
    ) -> None:
        body = a_request()
        provider = DEFAULT_SOAR_PROVIDER_REGISTRY.provider_for("firewall")
        baseline = provider.attempt_count

        first = client.post(
            "/api/soar/executions", json=body, headers=headers
        ).json()
        _remember(uuid.UUID(first["execution_id"]))
        after_first = provider.attempt_count

        second = client.post(
            "/api/soar/executions", json=body, headers=headers
        ).json()

        # The replay must not re-run the playbook: the idempotency check has
        # to happen *before* any provider is invoked, not after (a
        # post-execution row-count check hides a real duplicate containment
        # action, because the second row is discarded either way).
        assert after_first == baseline + 1, "first submission did not execute once"
        assert provider.attempt_count == after_first, (
            "replayed submission re-invoked the provider"
        )
        assert second["execution_id"] == first["execution_id"]
        rows = db_session.execute(
            select(SoarExecutionRow).where(
                SoarExecutionRow.execution_id == first["execution_id"]
            )
        ).scalars().all()
        assert len(rows) == 1

    def test_e_dry_run_persists_nothing_and_playbooks_are_read_only(
        self, client: TestClient, headers: dict[str, str], db_session: Session
    ) -> None:
        decision = a_decision(policy_rule_id="E2E-DRY-RUN-001")
        before = db_session.execute(
            select(SoarExecutionRow).where(
                SoarExecutionRow.policy_decision_id == decision.policy_decision_id
            )
        ).scalars().all()
        assert before == []

        result = client.post(
            "/api/soar/dry-run",
            json=a_request(decision=decision),
            headers=headers,
        )
        assert result.status_code == 200
        body = result.json()
        assert body["simulated"] is True
        assert body["status"] == "succeeded"
        assert len(body["steps"]) == 1

        after = db_session.execute(
            select(SoarExecutionRow).where(
                SoarExecutionRow.policy_decision_id == decision.policy_decision_id
            )
        ).scalars().all()
        assert after == []

        spec = client.get("/openapi.json").json()
        for path in spec["paths"]:
            if path.startswith("/api/soar/playbooks"):
                assert set(spec["paths"][path]) <= {"get"}, path
        for path in spec["paths"]:
            lowered = path.lower()
            if "/api/soar/" in path:
                continue
            assert not any(
                term in lowered
                for term in (
                    "response",
                    "mitigat",
                    "block",
                    "quarantine",
                    "disable",
                    "isolate",
                    "terminate",
                    "action",
                    "execut",
                    "hitl",
                )
            ), path