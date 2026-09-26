"""Approval Workflow security tests (V2.16).

Covers the adversarial perimeter of the human-in-the-loop workflow:

* the Response executor's approval gate rejects forged / unknown /
  missing / pending / misattributed grants before any provider call;
* an approval stored for one decision can never be re-purposed for
  another decision or another action (defense-in-depth: even a corrupted
  approval row is rejected by the verifier);
* replay of an already-processed response is suppressed by the
  executor's idempotency store;
* an approved grant never triggers execution for non-approved statuses.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import create_access_token, hash_password
from app.models.approval_request import ApprovalRequestRow
from app.models.role import Role
from app.models.user import User
from app.schemas.approval import ApprovalDecisionInput, ApprovalRecord
from app.schemas.policy_decision import (
    PolicyDecision,
    PolicyDecisionStatus,
    ResponseActionType,
)
from app.schemas.response import ResponseExecutionStatus, ResponseRequest
from app.schemas.risk import RiskLevel
from app.services.approval.service import ApprovalGrantVerifier, ApprovalService
from app.services.policy.identity import (
    derive_policy_decision_id,
    policy_decision_id_content,
)
from app.services.response import validator as _v
from app.services.response.executor import ResponseExecutor
from app.services.response.providers import MockResponseProvider
from app.services.response.registry import ResponseProviderRegistry
from tests.conftest import auth_header as _auth_header

TZ = timezone.utc
NOW = datetime(2026, 9, 22, 8, 0, 0, tzinfo=TZ)


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


def _clock():
    return NOW


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


def _request(
    decision: PolicyDecision,
    *,
    approval_id: uuid.UUID | None,
    action: ResponseActionType | None = None,
    target: str | None = None,
) -> ResponseRequest:
    action = action or decision.requested_action
    target = target or "198.51.100.7"
    return ResponseRequest(
        response_id=_v.derive_response_id(
            policy_decision_id=decision.policy_decision_id,
            action=action,
            target=target,
        ),
        policy_decision_id=decision.policy_decision_id,
        correlation_id=decision.correlation_id,
        action_type=action,
        target=target,
        approval_id=approval_id,
    )


class _CountingProvider(MockResponseProvider):
    def __init__(self) -> None:
        self.calls = 0

    def execute(self, request: ResponseRequest, *, clock=None):
        self.calls += 1
        return super().execute(request, clock=clock)


def _executor(
    db: Session, provider: _CountingProvider | None = None
) -> ResponseExecutor:
    return ResponseExecutor(
        registry=(
            ResponseProviderRegistry([provider]) if provider is not None else None
        ),
        clock=_clock,
        approval_verifier=ApprovalGrantVerifier(db, clock=_clock),
    )


def _approve_one(
    db: Session,
    *,
    requester_user_id: uuid.UUID,
    resolver_user_id: uuid.UUID,
) -> tuple[ApprovalRecord, PolicyDecision]:
    """Create + approve one grant through the service; returns the
    approved record and the underlying decision.

    Dual-control (H2.F-04): the approval is requested by one SOC user and
    resolved by a *different* SOC user.
    """
    service = ApprovalService()
    decision = _decision()
    created = service.create_request(
        db,
        DecisionStub(decision, "198.51.100.7"),
        actor_user_id=requester_user_id,
        actor_role="analyst",
        clock=_clock,
    )
    approved = service.approve(
        db,
        created.approval_id,
        ApprovalDecisionInput(comment="authorized by human"),
        actor_user_id=resolver_user_id,
        actor_role="ciso",
        clock=_clock,
    )
    return approved, decision


# Minimal 3-field carrier for ApprovalRequestCreate (the service reads only
# .decision/.target/.request_note in this test path).
class DecisionStub:
    def __init__(self, decision: PolicyDecision, target: str) -> None:
        self.decision = decision
        self.target = target
        self.request_note = None


class TestExecutorApprovalGate:
    def test_forged_approval_id_rejected_without_provider_call(
        self, db_session: Session
    ) -> None:
        decision = _decision()
        provider = _CountingProvider()
        result = _executor(db_session, provider).execute(
            _request(decision, approval_id=uuid.uuid4()), decision
        )
        assert result.execution_status is ResponseExecutionStatus.REJECTED
        assert result.error_code == "APPROVAL_UNKNOWN"
        assert provider.calls == 0

    def test_missing_approval_id_rejected(self, db_session: Session) -> None:
        decision = _decision()
        result = _executor(db_session).execute(
            _request(decision, approval_id=None), decision
        )
        assert result.execution_status is ResponseExecutionStatus.REJECTED
        assert result.error_code == "APPROVAL_NOT_GIVEN"

    def test_no_verifier_preserves_historic_behaviour(
        self, db_session: Session
    ) -> None:
        decision = _decision()
        provider = _CountingProvider()
        executor = ResponseExecutor(registry=ResponseProviderRegistry([provider]))
        result = executor.execute(
            _request(decision, approval_id=uuid.uuid4()), decision
        )
        assert result.execution_status is ResponseExecutionStatus.REJECTED
        assert result.error_code == "POLICY_REQUIRES_APPROVAL"
        assert provider.calls == 0

    def test_request_action_mismatch_rejected_before_grant(
        self, db_session: Session
    ) -> None:
        decision = _decision()
        provider = _CountingProvider()
        smuggled = _request(
            decision,
            approval_id=uuid.uuid4(),
            action=ResponseActionType.BLOCK_DOMAIN,
            target="evil.example.com",
        )
        result = _executor(db_session, provider).execute(smuggled, decision)
        assert result.execution_status is ResponseExecutionStatus.REJECTED
        assert result.error_code == "ACTION_MISMATCH"
        assert provider.calls == 0


class TestGrantCannotBeRepurposed:
    def test_grant_for_one_decision_rejects_another(
        self, db_session: Session, analyst_user, ciso_user
    ) -> None:
        approved, _ = _approve_one(
            db_session,
            requester_user_id=analyst_user.id,
            resolver_user_id=ciso_user.id,
        )
        other = _decision()
        result = _executor(db_session).execute(
            _request(other, approval_id=approved.approval_id), other
        )
        assert result.execution_status is ResponseExecutionStatus.REJECTED
        assert result.error_code == "APPROVAL_MISMATCH"

    def test_corrupted_stored_action_rejected(
        self, db_session: Session, analyst_user, ciso_user
    ) -> None:
        approved, decision = _approve_one(
            db_session,
            requester_user_id=analyst_user.id,
            resolver_user_id=ciso_user.id,
        )
        row = db_session.scalar(
            select(ApprovalRequestRow).where(
                ApprovalRequestRow.approval_id == approved.approval_id
            )
        )
        row.action_type = ResponseActionType.BLOCK_DOMAIN.value
        db_session.commit()
        result = _executor(db_session).execute(
            _request(decision, approval_id=approved.approval_id, target="198.51.100.7"),
            decision,
        )
        assert result.execution_status is ResponseExecutionStatus.REJECTED
        assert result.error_code == "APPROVAL_MISMATCH"

    def test_pending_grant_not_approved(
        self, db_session: Session, analyst_user
    ) -> None:
        service = ApprovalService()
        created = service.create_request(
            db_session,
            DecisionStub(_decision(), "198.51.100.7"),
            actor_user_id=analyst_user.id,
            actor_role="analyst",
            clock=_clock,
        )
        row = db_session.scalar(
            select(ApprovalRequestRow).where(
                ApprovalRequestRow.approval_id == created.approval_id
            )
        )
        decision = PolicyDecision.model_validate(row.decision)
        result = _executor(db_session).execute(
            _request(decision, approval_id=created.approval_id), decision
        )
        assert result.execution_status is ResponseExecutionStatus.REJECTED
        assert result.error_code == "APPROVAL_NOT_APPROVED"


class TestReplaySuppression:
    def test_replayed_response_executes_once(
        self, db_session: Session, analyst_user, ciso_user
    ) -> None:
        approved, decision = _approve_one(
            db_session,
            requester_user_id=analyst_user.id,
            resolver_user_id=ciso_user.id,
        )
        provider = _CountingProvider()
        executor = _executor(db_session, provider)
        request = _request(decision, approval_id=approved.approval_id)
        first = executor.execute(request, decision)
        second = executor.execute(request, decision)
        assert first.execution_status is ResponseExecutionStatus.EXECUTED
        assert second.execution_status is ResponseExecutionStatus.EXECUTED
        assert provider.calls == 1


class TestUnauthorizedAudit:
    def test_outsider_attempt_rejected(
        self, client: TestClient, outsider_token: str
    ) -> None:
        response = client.post(
            "/api/approvals",
            json={
                "decision": _decision().model_dump(mode="json"),
                "target": "198.51.100.7",
            },
            headers=_auth_header(outsider_token),
        )
        assert response.status_code == 403

    def test_resolution_actor_is_recorded(
        self, db_session: Session, analyst_user, ciso_user
    ) -> None:
        service = ApprovalService()
        created = service.create_request(
            db_session,
            DecisionStub(_decision(), "198.51.100.7"),
            actor_user_id=analyst_user.id,
            actor_role="analyst",
            clock=_clock,
        )
        cancelled = service.cancel(
            db_session,
            created.approval_id,
            ApprovalDecisionInput(comment="withdrawn"),
            actor_user_id=ciso_user.id,
            actor_role="ciso",
            clock=_clock,
        )
        row = db_session.scalar(
            select(ApprovalRequestRow).where(
                ApprovalRequestRow.approval_id == created.approval_id
            )
        )
        assert cancelled.status.value == "cancelled"
        assert cancelled.requested_by == analyst_user.id
        assert cancelled.resolved_by == ciso_user.id
        assert row.resolved_by == ciso_user.id