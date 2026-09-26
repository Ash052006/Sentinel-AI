"""Approval Workflow API tests (V2.16).

HTTP surface of the human-in-the-loop workflow: authentication on every
endpoint, SOC-role authorization (admin/analyst/ciso)  with the
non-SOC ``viewer`` role audited-forbidden, the create/get/list/recent
contract, the approve/reject/cancel transitions, HTTP error semantics
(401/403/404/409/422), and the approved -> Response layer hand-off
reflected in the record's distinct ``response_status``.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import create_access_token, hash_password
from app.models.role import Role
from app.models.user import User
from app.schemas.policy_decision import (
    PolicyDecision,
    PolicyDecisionStatus,
    ResponseActionType,
)
from app.schemas.risk import RiskLevel
from app.services.policy.identity import (
    derive_policy_decision_id,
    policy_decision_id_content,
)
from tests.conftest import auth_header as _auth_header

TZ = timezone.utc
NOW = datetime(2026, 9, 22, 8, 0, 0, tzinfo=TZ)


def _decision(**overrides) -> PolicyDecision:
    data = {
        "correlation_id": uuid.uuid4(),
        "requested_action": ResponseActionType.BLOCK_IP,
        "decision": PolicyDecisionStatus.REQUIRES_APPROVAL,
        "reason": "Requested action block_ip requires human approval.",
        "policy_rule_id": "TEST-RULE-APPROVAL-001",
        "risk_level": RiskLevel.HIGH,
        "risk_score": 0.8,
        "confidence": 0.95,
        "requires_approval": True,
        "evidence": [],
        "metadata": {},
        "timestamp": NOW,
    }
    data.update(overrides)
    # The id must be the deterministic UUIDv5 over the decision's own
    # content — the approval workflow recomputes it and rejects any
    # mismatch (H2.F-01), so every test decision must be self-consistent.
    if "policy_decision_id" not in overrides:
        data["policy_decision_id"] = derive_policy_decision_id(
            policy_decision_id_content(
                correlation_id=data["correlation_id"],
                requested_action=data["requested_action"],
                decision=data["decision"],
                policy_rule_id=data["policy_rule_id"],
                reason=data["reason"],
                risk_level=data["risk_level"],
                risk_score=data["risk_score"],
                confidence=data["confidence"],
                timestamp=data["timestamp"],
            )
        )
    return PolicyDecision.model_validate(data)


def _create_payload(**overrides) -> dict:
    data = {
        "decision": _decision().model_dump(mode="json"),
        "target": "198.51.100.7",
        "request_note": None,
    }
    data.update(overrides)
    return data


def _decision_body(decision: PolicyDecision) -> dict:
    return _create_payload(decision=decision.model_dump(mode="json"))


def _random_approval_id() -> str:
    return str(uuid.uuid4())


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


ALL_APPROVAL_URLS = (
    "/api/approvals",
    "/api/approvals/recent",
    f"/api/approvals/{_random_approval_id()}",
    f"/api/approvals/{_random_approval_id()}/approve",
    f"/api/approvals/{_random_approval_id()}/reject",
    f"/api/approvals/{_random_approval_id()}/cancel",
)

#: Paths exercised per HTTP method (auth is enforced by a dependency that
#: runs before the endpoint body, so POST-only routes need POST here).
GET_URLS = ("/api/approvals", "/api/approvals/recent")
POST_URLS = (
    "/api/approvals",
    f"/api/approvals/{_random_approval_id()}/approve",
    f"/api/approvals/{_random_approval_id()}/reject",
    f"/api/approvals/{_random_approval_id()}/cancel",
)


class TestAuthentication:
    def test_every_endpoint_requires_a_token(self, client: TestClient) -> None:
        for url in GET_URLS:
            assert client.get(url).status_code == 401, url
        for url in POST_URLS:
            assert client.post(url).status_code == 401, url

    def test_invalid_token_rejected(self, client: TestClient) -> None:
        headers = {"Authorization": "Bearer not-a-real-jwt"}
        for url in GET_URLS:
            assert client.get(url, headers=headers).status_code == 401, url
        for url in POST_URLS:
            assert client.post(url, headers=headers).status_code == 401, url


class TestAuthorization:
    @pytest.mark.parametrize("token_fixture", ["admin_token", "analyst_token", "ciso_token"])
    def test_soc_roles_can_read_endpoints(
        self, client: TestClient, request: pytest.FixtureRequest, token_fixture: str
    ) -> None:
        token = request.getfixturevalue(token_fixture)
        for url in GET_URLS:
            assert client.get(url, headers=_auth_header(token)).status_code == 200, url
        unknown = f"/api/approvals/{_random_approval_id()}"
        assert client.get(unknown, headers=_auth_header(token)).status_code == 404

    def test_outsider_role_forbidden(self, client: TestClient, outsider_token: str) -> None:
        for url in GET_URLS:
            response = client.get(url, headers=_auth_header(outsider_token))
            assert response.status_code == 403, url
            assert response.json()["detail"] == "Insufficient permissions"

    def test_outsider_cannot_create(
        self, client: TestClient, outsider_token: str
    ) -> None:
        response = client.post(
            "/api/approvals",
            json=_create_payload(),
            headers=_auth_header(outsider_token),
        )
        assert response.status_code == 403


class TestCreate:
    def test_create_returns_201_pending(self, client: TestClient, analyst_token: str) -> None:
        response = client.post(
            "/api/approvals",
            json=_create_payload(),
            headers=_auth_header(analyst_token),
        )
        assert response.status_code == 201
        body = response.json()
        assert body["status"] == "pending"
        assert body["provenance"] == "approval_reviewed"
        assert body["action_type"] == "block_ip"
        assert body["target"] == "198.51.100.7"
        assert body["requested_by_role"] == "analyst"
        assert body["resolved_at"] is None

    def test_create_persists_note(self, client: TestClient, analyst_token: str) -> None:
        response = client.post(
            "/api/approvals",
            json=_create_payload(request_note="Review this high-risk block."),
            headers=_auth_header(analyst_token),
        )
        assert response.status_code == 201
        assert response.json()["request_note"] == "Review this high-risk block."

    def test_create_idempotent_for_same_decision(
        self, client: TestClient, analyst_token: str
    ) -> None:
        payload = _create_payload()
        first = client.post("/api/approvals", json=payload, headers=_auth_header(analyst_token))
        assert first.status_code == 201
        second = client.post("/api/approvals", json=payload, headers=_auth_header(analyst_token))
        assert second.status_code == 201
        assert second.json()["approval_id"] == first.json()["approval_id"]

    def test_non_approval_decision_rejected_422(
        self, client: TestClient, analyst_token: str
    ) -> None:
        for decision in (
            _decision(decision=PolicyDecisionStatus.ALLOWED),
            _decision(decision=PolicyDecisionStatus.DENIED),
        ):
            response = client.post(
                "/api/approvals",
                json=_decision_body(decision),
                headers=_auth_header(analyst_token),
            )
            assert response.status_code == 422, decision.decision

    def test_malformed_target_rejected_422(
        self, client: TestClient, analyst_token: str
    ) -> None:
        response = client.post(
            "/api/approvals",
            json=_create_payload(target="not-an-ip"),
            headers=_auth_header(analyst_token),
        )
        assert response.status_code == 422

    def test_missing_decision_rejected_422(
        self, client: TestClient, analyst_token: str
    ) -> None:
        response = client.post(
            "/api/approvals",
            json={"target": "198.51.100.7"},
            headers=_auth_header(analyst_token),
        )
        assert response.status_code == 422

    def test_self_inconsistent_decision_rejected_422(
        self, client: TestClient, analyst_token: str
    ) -> None:
        """H2.F-01 regression.

        A decision whose ``policy_decision_id`` does not match the
        deterministic id implied by its own content is rejected before any
        request record is created — tampering with the identity can never
        be routed, probed, or poisoned through the API.
        """
        tampered = _create_payload()
        tampered["decision"]["policy_decision_id"] = str(uuid.uuid4())
        response = client.post(
            "/api/approvals",
            json=tampered,
            headers=_auth_header(analyst_token),
        )
        assert response.status_code == 422
        assert "does not match" in response.json()["detail"]

    def test_non_policy_provenance_decision_rejected_422(
        self, client: TestClient, analyst_token: str
    ) -> None:
        """H2.F-01 regression: only POLICY_DECIDED provenance is routable."""
        payload = _create_payload()
        payload["decision"]["provenance"] = "human_supplied"
        response = client.post(
            "/api/approvals",
            json=payload,
            headers=_auth_header(analyst_token),
        )
        assert response.status_code == 422


class TestReads:
    def test_get_by_approval_id(self, client: TestClient, analyst_token: str) -> None:
        created = client.post(
            "/api/approvals",
            json=_create_payload(),
            headers=_auth_header(analyst_token),
        ).json()
        response = client.get(
            f"/api/approvals/{created['approval_id']}",
            headers=_auth_header(analyst_token),
        )
        assert response.status_code == 200
        body = response.json()
        assert body["approval_id"] == created["approval_id"]
        assert body["status"] == "pending"

    def test_unknown_approval_id_404(self, client: TestClient, analyst_token: str) -> None:
        response = client.get(
            f"/api/approvals/{_random_approval_id()}",
            headers=_auth_header(analyst_token),
        )
        assert response.status_code == 404

    def test_list_envelope_and_pagination(
        self, client: TestClient, analyst_token: str
    ) -> None:
        created = client.post(
            "/api/approvals",
            json=_create_payload(),
            headers=_auth_header(analyst_token),
        ).json()
        page = client.get(
            "/api/approvals",
            params={"page": 1, "page_size": 5},
            headers=_auth_header(analyst_token),
        )
        assert page.status_code == 200
        page_body = page.json()
        assert page_body["page"] == 1
        assert page_body["page_size"] == 5
        assert any(item["approval_id"] == created["approval_id"] for item in page_body["items"])

    def test_list_status_filter(self, client: TestClient, analyst_token: str) -> None:
        created = client.post(
            "/api/approvals",
            json=_create_payload(),
            headers=_auth_header(analyst_token),
        ).json()
        pending = client.get(
            "/api/approvals",
            params={"status": "pending"},
            headers=_auth_header(analyst_token),
        )
        assert pending.status_code == 200
        assert any(
            item["approval_id"] == created["approval_id"]
            for item in pending.json()["items"]
        )

    def test_invalid_page_params_rejected(
        self, client: TestClient, analyst_token: str
    ) -> None:
        for params in ({"page": 0}, {"page_size": 0}, {"page_size": 201}, {"limit": 0}, {"limit": 201}):
            response = client.get(
                "/api/approvals/recent" if "limit" in params else "/api/approvals",
                params=params,
                headers=_auth_header(analyst_token),
            )
            assert response.status_code == 422, params

    def test_recent_feed(self, client: TestClient, analyst_token: str) -> None:
        created = client.post(
            "/api/approvals",
            json=_create_payload(),
            headers=_auth_header(analyst_token),
        ).json()
        response = client.get(
            "/api/approvals/recent",
            params={"limit": 5, "status": "pending"},
            headers=_auth_header(analyst_token),
        )
        assert response.status_code == 200
        assert any(
            item["approval_id"] == created["approval_id"]
            for item in response.json()
        )


class TestTransitions:
    def test_approve_executes_through_response_layer(
        self, client: TestClient, analyst_token: str, ciso_token: str
    ) -> None:
        created = client.post(
            "/api/approvals",
            json=_create_payload(),
            headers=_auth_header(analyst_token),
        ).json()
        response = client.post(
            f"/api/approvals/{created['approval_id']}/approve",
            json={"comment": "Authorized after manual review."},
            headers=_auth_header(ciso_token),
        )
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "approved"
        assert body["response_status"] == "executed"
        assert body["response_provider"] == "mock"
        assert body["resolution_reason"] == "Authorized after manual review."

    def test_approve_idempotent(
        self, client: TestClient, analyst_token: str, ciso_token: str
    ) -> None:
        created = client.post(
            "/api/approvals",
            json=_create_payload(),
            headers=_auth_header(analyst_token),
        ).json()
        url = f"/api/approvals/{created['approval_id']}/approve"
        first = client.post(url, json={"comment": "grant"}, headers=_auth_header(ciso_token))
        second = client.post(url, json={"comment": "grant again"}, headers=_auth_header(ciso_token))
        assert first.status_code == 200
        assert second.status_code == 200
        assert second.json()["status"] == "approved"
        assert second.json()["response_status"] == "executed"

    def test_reject_never_executes(
        self, client: TestClient, analyst_token: str, ciso_token: str
    ) -> None:
        created = client.post(
            "/api/approvals",
            json=_create_payload(),
            headers=_auth_header(analyst_token),
        ).json()
        response = client.post(
            f"/api/approvals/{created['approval_id']}/reject",
            json={"comment": "Not enough evidence."},
            headers=_auth_header(ciso_token),
        )
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "rejected"
        assert body["response_status"] is None
        assert body["response_provider"] is None

    def test_cancel_withdraws(
        self, client: TestClient, analyst_token: str, ciso_token: str
    ) -> None:
        created = client.post(
            "/api/approvals",
            json=_create_payload(),
            headers=_auth_header(analyst_token),
        ).json()
        response = client.post(
            f"/api/approvals/{created['approval_id']}/cancel",
            json={"comment": "No longer a concern."},
            headers=_auth_header(ciso_token),
        )
        assert response.status_code == 200
        assert response.json()["status"] == "cancelled"
        assert response.json()["response_status"] is None

    def test_terminal_conflict_409(
        self, client: TestClient, analyst_token: str, ciso_token: str
    ) -> None:
        created = client.post(
            "/api/approvals",
            json=_create_payload(),
            headers=_auth_header(analyst_token),
        ).json()
        cancel_url = f"/api/approvals/{created['approval_id']}/cancel"
        assert client.post(
            cancel_url, json={"comment": "withdraw"}, headers=_auth_header(ciso_token)
        ).status_code == 200
        approve = client.post(
            f"/api/approvals/{created['approval_id']}/approve",
            json={"comment": "too late"},
            headers=_auth_header(ciso_token),
        )
        assert approve.status_code == 409

    def test_requester_cannot_resolve_own_request_422(
        self, client: TestClient, analyst_token: str
    ) -> None:
        """H2.F-04 regression: dual-control rejects self-resolution."""
        created = client.post(
            "/api/approvals",
            json=_create_payload(),
            headers=_auth_header(analyst_token),
        ).json()
        for action in ("approve", "reject", "cancel"):
            response = client.post(
                f"/api/approvals/{created['approval_id']}/{action}",
                json={"comment": f"self {action}"},
                headers=_auth_header(analyst_token),
            )
            assert response.status_code == 422, action
            assert "dual-control" in response.json()["detail"].lower()

        status = client.get(
            f"/api/approvals/{created['approval_id']}",
            headers=_auth_header(analyst_token),
        ).json()
        assert status["status"] == "pending"

    def test_unknown_approval_transition_404(
        self, client: TestClient, analyst_token: str
    ) -> None:
        response = client.post(
            f"/api/approvals/{_random_approval_id()}/approve",
            json={"comment": "nope"},
            headers=_auth_header(analyst_token),
        )
        assert response.status_code == 404

    def test_missing_comment_rejected_422(
        self, client: TestClient, analyst_token: str, ciso_token: str
    ) -> None:
        created = client.post(
            "/api/approvals",
            json=_create_payload(),
            headers=_auth_header(analyst_token),
        ).json()
        response = client.post(
            f"/api/approvals/{created['approval_id']}/approve",
            json={},
            headers=_auth_header(ciso_token),
        )
        assert response.status_code == 422