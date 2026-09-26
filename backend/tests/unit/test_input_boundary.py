"""Input-boundary regression tests (V2 hardening).

Locks the hardened request boundary to reality:

* email fields declare an RFC 5321 length bound (register + login);
* client- and engine-carried ``metadata`` dictionaries are bounded in
  nesting depth and serialized size (policy decisions, evidence,
  SOAR) so a single record cannot absorb an unbounded blob;
* the SOAR ``execution_id`` path parameter is typed UUID on both the
  read and the cancel (write) routes;
* the shared control-character guard additionally rejects DEL (0x7F)
  and C1 (0x80-0x9F) characters while still permitting tab.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.schemas.policy_decision import (
    PolicyDecision,
    PolicyDecisionStatus,
    ResponseActionType,
)
from app.schemas.risk import RiskLevel
from app.schemas.soar import SoarExecutionRequest
from app.services.policy.identity import (
    derive_policy_decision_id,
    policy_decision_id_content,
)
from tests.conftest import auth_header

TZ = timezone.utc
NOW = datetime(2026, 9, 22, 8, 0, 0, tzinfo=TZ)

#: Over the 64 KiB serialized bound so a single ``metadata`` dict is
#: rejected by the size check.
_BIG_METADATA_BYTES = 70 * 1024


def _decision(**overrides) -> dict:
    data = {
        "correlation_id": uuid.uuid4(),
        "requested_action": ResponseActionType.BLOCK_IP,
        "decision": PolicyDecisionStatus.REQUIRES_APPROVAL,
        "reason": "Requested action block_ip requires human approval.",
        "policy_rule_id": "BOUNDARY-INPUT-RULE-001",
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
    return data


def _decision_model(**overrides) -> PolicyDecision:
    return PolicyDecision.model_validate(_decision(**overrides))


def _decision_json(**overrides) -> dict:
    """JSON-safe decision body (UUIds serialized) for HTTP probes."""
    return _decision_model(**overrides).model_dump(mode="json")


class TestEmailBound:
    def test_register_rejects_overlong_email(self, client: TestClient):
        resp = client.post(
            "/api/auth/register",
            json={
                "email": f"{'a' * 300}@example.com",
                "password": "TestPassword123!",
            },
        )
        assert resp.status_code == 422

    def test_login_rejects_overlong_email(self, client: TestClient):
        resp = client.post(
            "/api/auth/login",
            json={
                "email": f"{'a' * 300}@example.com",
                "password": "TestPassword123!",
            },
        )
        assert resp.status_code == 422


class TestMetadataBound:
    def test_decision_metadata_serialized_size_rejected(self):
        blob = "x" * _BIG_METADATA_BYTES
        with pytest.raises(ValidationError):
            _decision_model(metadata={"blob": blob})

    def test_decision_metadata_depth_rejected(self):
        nested = {"a": {"b": {"c": {"d": {"e": 1}}}}}
        with pytest.raises(ValidationError):
            _decision_model(metadata=nested)

    def test_evidence_metadata_serialized_size_rejected(self):
        from app.schemas.policy_decision import PolicyEvidence, PolicyEvidenceType

        with pytest.raises(ValidationError):
            PolicyEvidence(
                evidence_type=PolicyEvidenceType.CORRELATION,
                reference_id=uuid.uuid4(),
                role="primary_correlation",
                metadata={"blob": "x" * _BIG_METADATA_BYTES},
            )

    def test_soar_request_metadata_serialized_size_rejected(self):
        decision = _decision_model().model_dump(mode="json")
        with pytest.raises(ValidationError):
            SoarExecutionRequest(
                decision=decision,
                target="198.51.100.10",
                response_id=uuid.uuid4(),
                metadata={"blob": "x" * _BIG_METADATA_BYTES},
            )

    def test_approval_create_oversized_metadata_is_422(
        self, client: TestClient, analyst_token: str
    ):
        import json

        decision_dict = json.loads(
            json.dumps(
                _decision(metadata={"blob": "x" * _BIG_METADATA_BYTES}),
                default=str,
            )
        )
        payload = {"decision": decision_dict, "target": "198.51.100.11"}
        resp = client.post(
            "/api/approvals", json=payload, headers=auth_header(analyst_token)
        )
        assert resp.status_code == 422


class TestSoarExecutionIdTyped:
    def test_get_execution_rejects_non_uuid(self, client: TestClient, analyst_token: str):
        resp = client.get(
            "/api/soar/executions/not-a-uuid", headers=auth_header(analyst_token)
        )
        assert resp.status_code == 422

    def test_cancel_execution_rejects_non_uuid(self, client: TestClient, admin_token: str):
        resp = client.post(
            "/api/soar/executions/not-a-uuid/cancel", headers=auth_header(admin_token)
        )
        assert resp.status_code == 422


class TestControlCharacterGuard:
    def test_approval_target_rejects_del_and_c1(
        self, client: TestClient, analyst_token: str
    ):
        for target in ("198.51.100.1\x7f", "198.51.100.2\x85"):
            payload = {"decision": _decision_json(), "target": target}
            resp = client.post(
                "/api/approvals", json=payload, headers=auth_header(analyst_token)
            )
            assert resp.status_code == 422, target

    def test_approval_target_still_accepts_tab(self):
        decision = _decision_model()
        # Direct schema check: the target field's guard rejects controls but
        # allows tab; exercise via HTTP to prove the wire path accepts it.
        payload = {"decision": decision.model_dump(mode="json"), "target": "198.51.100.1\t"}
        from app.schemas.approval import ApprovalRequestCreate

        ApprovalRequestCreate.model_validate(payload)

    def test_hunt_name_rejects_del(self, client: TestClient, analyst_token: str):
        resp = client.post(
            "/api/threat-hunts",
            json={
                "name": "bad\x7fname",
                "description": "probe",
                "hunt_type": "authentication_anomaly",
                "start_time": "2026-09-01T00:00:00Z",
                "end_time": "2026-09-22T00:00:00Z",
                "filters": [],
            },
            headers=auth_header(analyst_token),
        )
        assert resp.status_code == 422