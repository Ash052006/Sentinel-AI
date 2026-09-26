"""V2.21 attack-path API tests (category M) — HTTP surface, RBAC, errors.

Live-Postgres API surface: every read requires a token; admin/analyst/ciso
may fetch a correlation's graph; an outsider role is denied 403 (and the
refusal is audited); unknown correlations are 404; the response envelope
is the closed attack-path contract with per-surface availability; and all
seeded rows are cleaned up after the module (mirroring the V2.20 API
suites).  The attack-path surface is read-only: there are no mutation
endpoints.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.security import create_access_token, hash_password
from app.models.audit_log import AuditLog
from app.models.approval_request import ApprovalRequestRow
from app.models.correlation_member import CorrelationMember
from app.models.correlation_result import CorrelationResult
from app.models.detection_result import DetectionResult
from app.models.incident_memory import IncidentMemoryRow
from app.models.risk_assessment import RiskAssessment
from app.models.role import Role
from app.models.soar_execution import SoarExecutionRow
from app.models.threat_intel_indicator import ThreatIntelIndicator
from app.models.threat_intel_lookup import ThreatIntelLookup
from app.models.user import User
from tests.conftest import auth_header as _auth_header
from tests.unit.incident_report_test_helpers import a_approval, a_soar_execution
from tests.unit.threat_hunt_test_helpers import (
    NOW,
    a_correlation,
    a_detection,
    a_indicator,
    a_lookup,
    a_memory,
    a_risk,
)

_CORR = uuid.uuid4()
_CORR_MISSING = uuid.uuid4()
_DET = uuid.uuid4()
_EVENT = uuid.uuid4()
_INDICATOR_IDS: list[uuid.UUID] = []


@pytest.fixture()
def actor_headers(db_session: Session, admin_user: User) -> dict[str, str]:
    return _auth_header(create_access_token(str(admin_user.id)))


@pytest.fixture(scope="session")
def outsider_token(db_session: Session, _ensure_roles) -> str:
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
    email = f"ap-viewer-{uuid.uuid4().hex[:8]}@example.com"
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


@pytest.fixture(autouse=True)
def _seed_enriched_correlation(db_session: Session, _ensure_roles, admin_user: User):
    existing = db_session.execute(
        select(CorrelationResult).where(CorrelationResult.correlation_id == _CORR)
    ).scalar_one_or_none()
    if existing is None:
        by = admin_user.id
        a_correlation(
            db_session,
            correlation_id=_CORR,
            at=NOW,
            members=[(_DET, _EVENT, NOW, 0)],
        )
        a_detection(
            db_session,
            event_id=_EVENT,
            detection_id=_DET,
            rule_id="rule-021-ap",
            at=NOW,
        )
        indicator = a_indicator(db_session, value="203.0.113.77", indicator_type="ip")
        _INDICATOR_IDS.append(indicator.id)
        a_lookup(db_session, indicator_id=indicator.id, event_id=_EVENT)
        a_risk(db_session, risk_assessment_id=uuid.uuid4(), correlation_id=_CORR, at=NOW)
        a_memory(db_session, memory_id=uuid.uuid4(), correlation_id=_CORR, created_at=NOW)
        policy = uuid.uuid4()
        a_approval(
            db_session,
            approval_id=uuid.uuid4(),
            policy_decision_id=policy,
            correlation_id=_CORR,
            by=by,
        )
        a_soar_execution(
            db_session,
            execution_id=uuid.uuid4(),
            policy_decision_id=policy,
            correlation_id=_CORR,
            by=by,
        )
        db_session.commit()


@pytest.fixture(autouse=True)
def _cleanup(db_session: Session):
    yield
    for model, column, value in (
        (ThreatIntelLookup, ThreatIntelLookup.event_id, _EVENT),
        (CorrelationMember, CorrelationMember.correlation_id, _CORR),
        (DetectionResult, DetectionResult.detection_id, _DET),
        (RiskAssessment, RiskAssessment.correlation_id, _CORR),
        (IncidentMemoryRow, IncidentMemoryRow.correlation_id, _CORR),
        (SoarExecutionRow, SoarExecutionRow.correlation_id, _CORR),
        (ApprovalRequestRow, ApprovalRequestRow.correlation_id, _CORR),
        (CorrelationResult, CorrelationResult.correlation_id, _CORR),
    ):
        db_session.execute(delete(model).where(column == value))
    if _INDICATOR_IDS:
        db_session.execute(
            delete(ThreatIntelIndicator).where(
                ThreatIntelIndicator.id.in_(_INDICATOR_IDS)
            )
        )
    db_session.commit()


class TestAuth:
    def test_every_read_requires_a_token(self, client: TestClient) -> None:
        url = "/api/attack-paths/{}".format(uuid.uuid4())
        assert client.get(url).status_code == 401


class TestRbac:
    def test_viewer_denied_and_audited(
        self, db_session: Session, client: TestClient, outsider_token: str
    ) -> None:
        url = "/api/attack-paths/{}".format(_CORR)
        resp = client.get(url, headers=_auth_header(outsider_token))
        assert resp.status_code == 403
        audited = db_session.execute(
            select(AuditLog).where(AuditLog.action == "attack_path.unauthorized_attempt")
        ).scalars().all()
        assert any(row.details == "insufficient role" for row in audited)


class TestRead:
    def test_returns_deterministic_envelope(
        self, client: TestClient, actor_headers
    ) -> None:
        resp = client.get(
            "/api/attack-paths/{}".format(_CORR), headers=actor_headers
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["metadata"]["correlation_id"] == str(_CORR)
        assert body["metadata"]["truncated"] is False
        nodes = body["graph"]["nodes"]
        edges = body["graph"]["edges"]
        types = {n["node_type"] for n in nodes}
        assert types >= {
            "correlation",
            "detection",
            "indicator",
            "risk",
            "memory",
            "policy_decision",
            "approval",
            "soar_execution",
        }
        node_ids = {n["node_id"] for n in nodes}
        for edge in edges:
            assert edge["source_node_id"] in node_ids
            assert edge["target_node_id"] in node_ids
        assert body["metadata"]["node_count"] == len(nodes)
        assert body["metadata"]["edge_count"] == len(edges)
        assert all(
            key in body["availability"]
            for key in (
                "correlation",
                "detections",
                "indicators",
                "risk_assessment",
                "incident_memory",
                "threat_hunts",
                "policy_decisions",
                "approvals",
                "soar_executions",
                "investigation",
                "attribution",
                "security_events",
            )
        )
        assert body["availability"]["correlation"] == "provided"

    def test_unknown_correlation_404(self, client: TestClient, actor_headers) -> None:
        resp = client.get(
            "/api/attack-paths/{}".format(_CORR_MISSING),
            headers=actor_headers,
        )
        assert resp.status_code == 404

    def test_reads_never_create_rows(self, db_session: Session, actor_headers, client: TestClient) -> None:
        before = db_session.execute(
            select(SoarExecutionRow).where(SoarExecutionRow.correlation_id == _CORR)
        ).scalars().all()
        client.get("/api/attack-paths/{}".format(_CORR), headers=actor_headers)
        after = db_session.execute(
            select(SoarExecutionRow).where(SoarExecutionRow.correlation_id == _CORR)
        ).scalars().all()
        assert len(after) == len(before) == 1