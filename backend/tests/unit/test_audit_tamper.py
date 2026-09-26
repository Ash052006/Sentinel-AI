"""F-08 audit-tamper gauging probes (V2 hardening, no fixes expected inside).

The audit trail is application-level only: every row is written by one
internal writer (``audit_service.log_action``) with server-derivable
action/resource/instrumentation, and reads are gated to ``admin``.  These
probes record the exact tamper surface:

* ``B/K`` — schema bounds (varchar 100/255/45, TEXT details) and the
  absence of any integrity (hash/chain/version) column;
* ``C/D`` — actor attribution is always the JWT-authenticated actor and
  resource ids are server-derived (the client cannot choose them);
* ``E/J`` — client-supplied strings (notes, reasons) never reach audit
  metadata; the sole bounded exception is the hunt-name echo on
  ``threat_hunt.*`` events;
* ``F/I`` — no API route can create, update, or delete audit rows
  (405/404, even for ``admin``);
* ``H/L`` — read is admin-gated and every denied SOC attempt is itself
  audited with the real actor (or ``None`` when unidentifiable);
* ``G`` — the real tamper boundary: anyone owning application DB
  credentials can UPDATE/DELETE rows.  That is a documented operational
  boundary (the DB owner must protect the database), **not** a defect to
  fix by adding a pseudo-chain — the project does not ship an integrity
  chain, so this probe only proves the boundary is true.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect, select, update, delete
from sqlalchemy.orm import Session

from app.core.security import create_access_token, hash_password
from app.database.postgres.session import SessionLocal
from app.models.audit_log import AuditLog
from app.models.role import Role
from app.models.user import User
from app.schemas.policy_decision import (
    PolicyDecision,
    PolicyDecisionStatus,
    ResponseActionType,
)
from app.schemas.risk import RiskLevel
from app.services.audit_service import log_action
from app.services.policy.identity import (
    derive_policy_decision_id,
    policy_decision_id_content,
)
from tests.conftest import auth_header

TZ = timezone.utc
NOW = datetime(2026, 9, 22, 8, 0, 0, tzinfo=TZ)

AUDIT_LOGS_URL = "/api/audit/logs"


def _count(db: Session, action: str | None = None) -> int:
    stmt = select(AuditLog)
    if action is not None:
        stmt = stmt.where(AuditLog.action == action)
    return len(db.execute(stmt).scalars().all())


def _decision(**overrides) -> PolicyDecision:
    data = {
        "correlation_id": uuid.uuid4(),
        "requested_action": ResponseActionType.BLOCK_IP,
        "decision": PolicyDecisionStatus.REQUIRES_APPROVAL,
        "reason": "Requested action block_ip requires human approval.",
        "policy_rule_id": "TEST-RULE-AUDIT-PROBE-001",
        "risk_level": RiskLevel.HIGH,
        "risk_score": 0.8,
        "confidence": 0.95,
        "requires_approval": True,
        "evidence": [],
        "metadata": {},
        "timestamp": NOW,
    }
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


def _create_payload(**overrides) -> dict:
    data = {"decision": _decision().model_dump(mode="json"), "target": "198.51.100.9"}
    data.update(overrides)
    return data


@pytest.fixture(scope="session")
def viewer_user(db_session: Session, _ensure_roles) -> User:
    role = db_session.execute(select(Role).where(Role.name == "viewer")).scalar_one_or_none()
    if role is None:
        role = Role(name="viewer", description="read-only non-SOC role")
        db_session.add(role)
        db_session.commit()
        db_session.refresh(role)
    user = User(
        email=f"audit-probe-viewer-{uuid.uuid4().hex[:8]}@example.com",
        password_hash=hash_password("TestPassword123!"),
        is_active=True,
        role_id=role.id,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(scope="session")
def viewer_token(viewer_user: User) -> str:
    return create_access_token(str(viewer_user.id))


class TestAuditSchemaBounds:
    """K — storage bounds: bounded varchar metadata, unbounded TEXT detail,
    and no integrity column (so no in-DB tamper detection exists)."""

    def test_metadata_column_bounds(self, db_session: Session):
        cols = {c["name"]: c for c in inspect(db_session.bind).get_columns("audit_logs")}
        assert cols["action"]["type"].length == 100
        assert cols["resource"]["type"].length == 255
        assert cols["ip_address"]["type"].length == 45
        assert cols["details"]["type"].__class__.__name__ == "TEXT"
        assert cols["user_id"]["nullable"] is True

    def test_no_integrity_columns_exist(self, db_session: Session):
        names = {c["name"] for c in inspect(db_session.bind).get_columns("audit_logs")}
        assert {"id", "user_id", "action", "resource", "details",
                "ip_address", "created_at", "updated_at"} == names
        assert not {"hash", "checksum", "chain_id", "prev_hash", "version"} & names


class TestAuditEndpointTamperSurface:
    """B/F/I — no API route can write or mutate audit rows."""

    def test_no_create_route(self, client: TestClient, db_session: Session, admin_token: str):
        before = _count(db_session)
        forged = {
            "action": "forged.arbitrary",
            "resource": "attacker-storage",
            "details": "client-controlled",
            "user_id": str(uuid.uuid4()),
        }
        response = client.post(AUDIT_LOGS_URL, json=forged, headers=auth_header(admin_token))
        assert response.status_code == 405
        assert _count(db_session) == before
        assert _count(db_session, "forged.arbitrary") == 0

    def test_no_update_delete_on_collection(
        self, client: TestClient, db_session: Session, admin_token: str
    ):
        before = _count(db_session)
        for method in ("put", "patch", "delete"):
            resp = getattr(client, method)(AUDIT_LOGS_URL, headers=auth_header(admin_token))
            assert resp.status_code == 405, method
        assert _count(db_session) == before

    def test_no_route_by_id_even_admin(
        self, client: TestClient, db_session: Session, admin_token: str
    ):
        entry = log_action(db=db_session, action="probe.mutation.target", details="original")
        assert entry is not None
        url = f"{AUDIT_LOGS_URL}/{entry.id}"
        for method, kwargs in (
            ("get", {}),
            ("post", {"json": {"action": "x"}}),
            ("put", {"json": {"details": "tampered"}}),
            ("patch", {"json": {"details": "tampered"}}),
            ("delete", {}),
        ):
            resp = getattr(client, method)(url, **kwargs, headers=auth_header(admin_token))
            assert resp.status_code == 404, method
        row = db_session.execute(
            select(AuditLog).where(AuditLog.id == entry.id)
        ).scalar_one()
        assert row.details == "original"
        assert row.action == "probe.mutation.target"


class TestAuditActorAttribution:
    """C/D — actor and resource ids are server-side; client cannot choose them."""

    def test_approval_created_attributes_authenticated_actor(
        self, client: TestClient, db_session: Session, analyst_token: str, analyst_user: User
    ):
        payload = _create_payload()
        decision_id = payload["decision"]["policy_decision_id"]
        before = _count(db_session, "approval.created")

        resp = client.post("/api/approvals", json=payload, headers=auth_header(analyst_token))
        assert resp.status_code == 201
        approval_id = resp.json()["approval_id"]

        rows = db_session.execute(
            select(AuditLog)
            .where(AuditLog.action == "approval.created")
            .order_by(AuditLog.created_at.desc())
        ).scalars().all()
        new = [r for r in rows if r.user_id == analyst_user.id][0]
        assert len(rows) == before + 1
        assert new.user_id == analyst_user.id
        assert new.resource == f"approval:{approval_id}"
        assert new.details == f"routed decision {decision_id} for human approval"
        assert new.ip_address == "testclient"


class TestAuditClientTextIsolation:
    """E/J — operator text and secret-shaped strings never reach audit."""

    def test_secret_shaped_request_note_rejected_before_audit(
        self, client: TestClient, db_session: Session, analyst_token: str
    ):
        before = _count(db_session, "approval.created")
        secret = "SECRET_BEARER_abc123"
        resp = client.post(
            "/api/approvals",
            json=_create_payload(request_note=f"note {secret}"),
            headers=auth_header(analyst_token),
        )
        assert resp.status_code == 422
        assert _count(db_session, "approval.created") == before
        stray = db_session.execute(
            select(AuditLog).where(AuditLog.details.contains(secret))
        ).scalars().all()
        assert stray == []

    def test_approval_note_and_reason_do_not_leak_into_audit(
        self, client: TestClient, db_session: Session, analyst_token: str
    ):
        marker = f"MARKER-{uuid.uuid4().hex[:8]}"
        payload = _create_payload(
            decision=_decision(reason=f"reason {marker}").model_dump(mode="json"),
            request_note=f"note {marker}",
        )
        started = datetime.now(timezone.utc)

        resp = client.post("/api/approvals", json=payload, headers=auth_header(analyst_token))
        assert resp.status_code == 201

        rows = db_session.execute(
            select(AuditLog)
            .where(AuditLog.action == "approval.created")
            .order_by(AuditLog.created_at.desc())
        ).scalars().all()
        mine = [r for r in rows if r.created_at >= started]
        assert len(mine) == 1
        assert marker not in (mine[0].details or "")

    def test_hunt_name_is_the_sole_bounded_client_echo(
        self, client: TestClient, db_session: Session, analyst_token: str
    ):
        name = f"probe-hunt-{uuid.uuid4().hex[:8]}"
        before = _count(db_session, "threat_hunt.created")

        resp = client.post(
            "/api/threat-hunts",
            json={
                "name": name,
                "description": "audit probe",
                "hunt_type": "authentication_anomaly",
                "start_time": "2026-09-01T00:00:00Z",
                "end_time": "2026-09-22T00:00:00Z",
                "filters": [],
            },
            headers=auth_header(analyst_token),
        )
        assert resp.status_code == 201, resp.json()

        rows = db_session.execute(
            select(AuditLog).where(AuditLog.action == "threat_hunt.created").order_by(AuditLog.created_at.desc())
        ).scalars().all()
        assert len(rows) == before + 1
        mine = [r for r in rows if (r.details or "").startswith(f"Hunt '{name}'")]
        assert len(mine) == 1
        assert mine[0].user_id is not None

    def test_overlong_hunt_name_rejected_before_audit(
        self, client: TestClient, db_session: Session, analyst_token: str
    ):
        before = _count(db_session, "threat_hunt.created")
        resp = client.post(
            "/api/threat-hunts",
            json={
                "name": "x" * 121,
                "description": "audit probe",
                "hunt_type": "authentication_anomaly",
                "start_time": "2026-09-01T00:00:00Z",
                "end_time": "2026-09-22T00:00:00Z",
                "filters": [],
            },
            headers=auth_header(analyst_token),
        )
        assert resp.status_code == 422
        assert _count(db_session, "threat_hunt.created") == before


class TestAuditRoleGates:
    """H/L — read is admin-gated; SOP attempts that fail are themselves logged."""

    def test_non_admin_read_denied_and_audited(
        self,
        client: TestClient,
        db_session: Session,
        ciso_token: str,
        ciso_user: User,
    ):
        before = _count(db_session, "auth.authorization.denied")
        resp = client.get(AUDIT_LOGS_URL, headers=auth_header(ciso_token))
        assert resp.status_code == 403
        rows = db_session.execute(
            select(AuditLog).where(AuditLog.action == "auth.authorization.denied").order_by(AuditLog.created_at.desc())
        ).scalars().all()
        assert len(rows) == before + 1
        mine = [r for r in rows if r.user_id == ciso_user.id]
        assert len(mine) == 1
        assert mine[0].resource == "role_check"
        assert "admin" in (mine[0].details or "")

    def test_invalid_token_read_is_401(self, client: TestClient):
        resp = client.get(AUDIT_LOGS_URL, headers=auth_header("not-a-real-token"))
        assert resp.status_code == 401

    def test_viewer_soc_action_denied_and_audited(
        self,
        client: TestClient,
        db_session: Session,
        viewer_token: str,
        viewer_user: User,
    ):
        before = _count(db_session, "approval.unauthorized_attempt")
        resp = client.post(
            "/api/approvals", json=_create_payload(), headers=auth_header(viewer_token)
        )
        assert resp.status_code == 403
        rows = db_session.execute(
            select(AuditLog).where(AuditLog.action == "approval.unauthorized_attempt").order_by(AuditLog.created_at.desc())
        ).scalars().all()
        assert len(rows) == before + 1
        mine = [r for r in rows if r.user_id == viewer_user.id]
        assert len(mine) == 1
        assert mine[0].resource == "approval"
        assert mine[0].details == "insufficient role"
        assert mine[0].ip_address == "testclient"

    def test_invalid_token_soc_action_logged_without_actor(
        self, client: TestClient, db_session: Session
    ):
        started = datetime.now(timezone.utc)
        resp = client.post(
            "/api/approvals", json=_create_payload(), headers=auth_header("garbage")
        )
        assert resp.status_code == 401
        rows = db_session.execute(
            select(AuditLog).where(AuditLog.action == "approval.unauthorized_attempt").order_by(AuditLog.created_at.desc())
        ).scalars().all()
        mine = [
            r
            for r in rows
            if r.created_at >= started and r.details == "invalid or missing credentials"
        ]
        assert len(mine) == 1
        assert mine[0].user_id is None


class TestAuditDatabaseBoundary:
    """G — holder of application DB credentials can tamper rows: the true
    (documented, unfixed) boundary is database access control, not an
    in-DB chain."""

    def test_direct_db_access_can_modify_and_delete(
        self, db_session: Session
    ):
        entry = log_action(db=db_session, action="probe.boundary.original", details="v1")
        assert entry is not None

        with SessionLocal() as db:
            db.execute(
                update(AuditLog)
                .where(AuditLog.id == entry.id)
                .values(action="probe.boundary.tampered", details="v2")
            )
            db.commit()

        db_session.expire_all()
        entry = db_session.execute(
            select(AuditLog).where(AuditLog.id == entry.id)
        ).scalar_one()
        assert entry.action == "probe.boundary.tampered"
        assert entry.details == "v2"

        with SessionLocal() as db:
            db.execute(delete(AuditLog).where(AuditLog.id == entry.id))
            db.commit()

        assert db_session.execute(
            select(AuditLog).where(AuditLog.id == entry.id)
        ).scalar_one_or_none() is None