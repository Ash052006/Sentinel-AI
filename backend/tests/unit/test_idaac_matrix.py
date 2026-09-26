"""IDOR/RBAC surface matrix probes (V2 hardening).

The platform is a single-org SOC: there is no per-tenant or per-user data
isolation in the architecture, so the *security boundary is the role*
(documented contract, not a defect to paper over with invented tenancy).
These probes lock the role matrix to reality:

1. Every ID-parameterized detail route returns **404** for an unknown UUID
   (no existence oracle, no 500 crash, no cross-role data reveal).
2. Mutating surfaces are gated by the narrowest correct role set
   (SOAR execution + DAC lifecycle = admin only; DAC validate = admin+analyst;
   audit read = admin only; all SOC *read* surfaces = admin/analyst/ciso;
   non-SOC ``viewer`` = forbidden everywhere).
3. Reads inside the SOC roles are org-wide by contract: a record created by
   one SOC actor is readable by another SOC role.
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
from tests.conftest import auth_header

TZ = timezone.utc
NOW = datetime(2026, 9, 22, 8, 0, 0, tzinfo=TZ)


def _random_uuid() -> str:
    return str(uuid.uuid4())


def _decision(minimal=True, **overrides) -> PolicyDecision:
    data = {
        "correlation_id": uuid.uuid4(),
        "requested_action": ResponseActionType.BLOCK_IP,
        "decision": PolicyDecisionStatus.ALLOWED,
        "reason": "matrix probe decision",
        "policy_rule_id": "MATRIX-PROBE-RULE-001",
        "risk_level": RiskLevel.MEDIUM,
        "risk_score": 0.5,
        "confidence": 0.9,
        "requires_approval": False,
        "evidence": [],
        "metadata": {},
        "timestamp": NOW,
    }
    if not minimal:
        data.update(
            {
                "decision": PolicyDecisionStatus.REQUIRES_APPROVAL,
                "requires_approval": True,
                "reason": "Requested action block_ip requires human approval.",
                "risk_level": RiskLevel.HIGH,
                "risk_score": 0.8,
                "confidence": 0.95,
            }
        )
    data.update(overrides)
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


def _soar_execute_body(approval_id=None) -> dict:
    body = {
        "decision": _decision(minimal=False).model_dump(mode="json"),
        "target": "198.51.100.10",
    }
    if approval_id is not None:
        body["approval_id"] = approval_id
    return body


def _dac_bump_body() -> dict:
    return {
        "rule_id": f"matrix-rule-{uuid.uuid4().hex[:8]}",
        "version": "1.0.0",
        "bump_class": "MINOR",
        "change_reason": "matrix probe bump",
    }


def _dac_lifecycle_body() -> dict:
    return {
        "rule_id": f"matrix-rule-{uuid.uuid4().hex[:8]}",
        "version": "1.0.0",
    }


@pytest.fixture(scope="session")
def non_soc_user(db_session: Session, _ensure_roles) -> User:
    role = db_session.execute(select(Role).where(Role.name == "viewer")).scalar_one_or_none()
    if role is None:
        role = Role(name="viewer", description="read-only non-SOC role")
        db_session.add(role)
        db_session.commit()
        db_session.refresh(role)
    user = User(
        email=f"matrix-viewer-{uuid.uuid4().hex[:8]}@example.com",
        password_hash=hash_password("TestPassword123!"),
        is_active=True,
        role_id=role.id,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(scope="session")
def non_soc_token(non_soc_user: User) -> str:
    return create_access_token(str(non_soc_user.id))


class TestDetailRoutesUnknownUuid:
    """1 — unknown resource ids yield 404 (no oracle, no crash), for a SOC role;
    correlation/event-scoped *collection* lookups correctly return an empty,
    leak-free result list (documented list semantics, not an existence oracle)."""

    DETAIL_GET_ROUTES = [
        "/api/approvals/{}",
        "/api/threat-hunts/{}",
        "/api/threat-hunts/{}/evidence",
        "/api/threat-hunts/{}/findings",
        "/api/threat-hunts/{}/timeline",
        "/api/attack-paths/{}",
        "/api/risk-assessments/{}",
        "/api/incident-memories/{}",
        "/api/soar/executions/{}",
        "/api/soar/playbooks/{}",
        "/api/incident-reports/{}",
        "/api/detections/{}",
        "/api/detection-rules/{}",
        "/api/correlations/{}",
        "/api/detection-as-code/{}",
    ]

    COLLECTION_GET_ROUTES = [
        "/api/risk-assessments/correlation/{}",
        "/api/incident-memories/correlation/{}",
        "/api/detections/event/{}",
        "/api/detections/rule/{}",
        "/api/correlations/detection/{}",
        "/api/correlations/event/{}",
    ]

    @pytest.mark.parametrize("route", DETAIL_GET_ROUTES)
    def test_get_unknown_uuid_is_404(
        self, client: TestClient, analyst_token: str, route: str
    ):
        u = _random_uuid()
        url = route.format(u)
        resp = client.get(url, headers=auth_header(analyst_token))
        assert resp.status_code == 404, f"{route} -> {resp.status_code} {resp.text[:120]}"

    @pytest.mark.parametrize("route", COLLECTION_GET_ROUTES)
    def test_scoped_collection_lookup_unknown_uuid_is_empty(
        self, client: TestClient, analyst_token: str, route: str
    ):
        u = _random_uuid()
        url = route.format(u)
        resp = client.get(url, headers=auth_header(analyst_token))
        assert resp.status_code == 200, f"{route} -> {resp.status_code} {resp.text[:120]}"
        body = resp.json()
        assert body["items"] == []
        assert body["total"] == 0

    def test_mutation_routes_unknown_uuid_are_404(
        self, client: TestClient, analyst_token: str, admin_token: str
    ):
        u = _random_uuid()
        comment = {"comment": "uuid probe"}
        for path in ("approve", "reject", "cancel"):
            resp = client.post(
                f"/api/approvals/{u}/{path}",
                json=comment,
                headers=auth_header(analyst_token),
            )
            assert resp.status_code == 404, path
        resp = client.post(
            f"/api/threat-hunts/{u}/run", headers=auth_header(analyst_token)
        )
        assert resp.status_code == 404
        resp = client.post(
            f"/api/threat-hunts/{u}/cancel", headers=auth_header(analyst_token)
        )
        assert resp.status_code == 404
        resp = client.post(
            f"/api/soar/executions/{u}/cancel", headers=auth_header(admin_token)
        )
        assert resp.status_code == 404


class TestRoleMatrix:
    """2 — narrowest-role gating across the matrix."""

    def test_viewer_forbidden_on_soc_read_surfaces(
        self, client: TestClient, non_soc_token: str
    ):
        for url in (
            "/api/threat-hunts",
            "/api/correlations/recent",
            "/api/risk-assessments/recent",
            "/api/incident-memories/recent",
            "/api/detections/recent",
            "/api/soar/playbooks",
            "/api/approvals/recent",
        ):
            resp = client.get(url, headers=auth_header(non_soc_token))
            assert resp.status_code == 403, url

    def test_admin_only_mutation_surfaces_reject_analyst_and_ciso(
        self, client: TestClient, analyst_token: str, ciso_token: str
    ):
        soar_execute = _soar_execute_body()
        for token in (analyst_token, ciso_token):
            resp = client.post(
                "/api/soar/executions", json=soar_execute, headers=auth_header(token)
            )
            assert resp.status_code == 403, token

        analyst_calls = [
            ("/api/detection-as-code/release", _dac_lifecycle_body()),
            ("/api/detection-as-code/deploy", _dac_lifecycle_body()),
            ("/api/detection-as-code/rollback", _dac_lifecycle_body()),
            ("/api/detection-as-code/enabled", _dac_lifecycle_body()),
        ]
        for path, body in analyst_calls:
            resp = client.post(path, json=body, headers=auth_header(analyst_token))
            assert resp.status_code == 403, path

    def test_validate_is_admin_and_analyst_only(
        self, client: TestClient, analyst_token: str, ciso_token: str, admin_token: str
    ):
        body = _dac_bump_body()
        for token in (analyst_token, admin_token):
            resp = client.post(
                "/api/detection-as-code/validate", json=body, headers=auth_header(token)
            )
            # Guard admits the role; the unknown rule must then fail as 404/422,
            # never as 403.
            assert resp.status_code in (404, 422), resp.status_code
        resp = client.post(
            "/api/detection-as-code/validate", json=_dac_bump_body(), headers=auth_header(ciso_token)
        )
        assert resp.status_code == 403

    def test_audit_read_is_admin_only(self, client: TestClient, ciso_token: str):
        resp = client.get("/api/audit/logs", headers=auth_header(ciso_token))
        assert resp.status_code == 403

    def test_users_routes(self, client: TestClient, analyst_token: str, admin_token: str):
        resp = client.get("/api/users/security-test", headers=auth_header(analyst_token))
        assert resp.status_code == 200
        resp = client.get("/api/users/admin-test", headers=auth_header(analyst_token))
        assert resp.status_code == 403
        resp = client.get("/api/users/admin-test", headers=auth_header(admin_token))
        assert resp.status_code == 200


class TestOrgWideSharedReads:
    """3 — SOC reads are org-wide by contract (role boundary, not owner)."""

    def test_analyst_can_read_hunt_created_by_admin(
        self, client: TestClient, admin_token: str, analyst_token: str
    ):
        name = f"shared-hunt-{uuid.uuid4().hex[:8]}"
        resp = client.post(
            "/api/threat-hunts",
            json={
                "name": name,
                "description": "shared workspace probe",
                "hunt_type": "authentication_anomaly",
                "start_time": "2026-09-01T00:00:00Z",
                "end_time": "2026-09-22T00:00:00Z",
                "filters": [],
            },
            headers=auth_header(admin_token),
        )
        assert resp.status_code == 201, resp.text
        hunt_id = resp.json()["hunt_id"]

        resp = client.get(
            f"/api/threat-hunts/{hunt_id}", headers=auth_header(analyst_token)
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == name