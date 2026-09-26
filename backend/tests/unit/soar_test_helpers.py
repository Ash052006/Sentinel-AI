"""Shared builders/stubs for the V2.18 SOAR test suite."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy.dialects.sqlite.base import SQLiteTypeCompiler

if not hasattr(SQLiteTypeCompiler, "visit_JSONB"):
    SQLiteTypeCompiler.visit_JSONB = lambda self, type_, **kw: "JSON"  # noqa: E731
# Pin native PG ``UUID(as_uuid=True)`` columns to fixed-size text on the
# test SQLite engines.  Overriding ``visit_uuid`` alone is **not enough**:
# when ``supports_native_uuid`` is False the generic ``visit_uuid`` falls
# through to the **inherited** ``GenericTypeCompiler.visit_UUID`` (whose
# ``SQLiteTypeCompiler``-scoped shadow is itself a lie while the generic
# base method still dispatch-matches by the PG ``UUID.__visit_name__``),
# leaving a bare ``UUID`` SQLite column with **NUMERIC** affinity — and
# pysqlite then silently coerces bound ``uuid.UUID`` hex strings into
# floats (corrupting ids on read-back and on ``Session.refresh``).  Both
# visitors are pinned to ``CHAR(32)`` (TEXT affinity).
SQLiteTypeCompiler.visit_UUID = lambda self, type_, **kw: "CHAR(32)"  # noqa: E731
SQLiteTypeCompiler.visit_uuid = lambda self, type_, **kw: "CHAR(32)"  # noqa: E731

from app.schemas.policy_decision import (
    POLICY_DECISION_NAMESPACE,
    PolicyDecision,
    PolicyDecisionStatus,
    ResponseActionType,
)
from app.schemas.risk import RiskLevel
from app.services.response.approval_gate import ApprovalGateResult

TZ = timezone.utc
NOW = datetime(2026, 9, 24, 8, 0, 0, tzinfo=TZ)


def a_decision(
    *,
    action: ResponseActionType = ResponseActionType.BLOCK_IP,
    status: PolicyDecisionStatus = PolicyDecisionStatus.ALLOWED,
    policy_rule_id: str = "TEST-SOAR-RULE-001",
    correlation_id: uuid.UUID | None = None,
    **overrides: object,
) -> PolicyDecision:
    """A deterministic, schema-valid :class:`PolicyDecision`.

    ``requires_approval`` is derived from ``status`` so the record is
    always internally consistent unless overridden.
    """
    data: dict[str, object] = {
        "policy_decision_id": uuid.uuid5(
            POLICY_DECISION_NAMESPACE,
            f"{policy_rule_id}:{action.value}:{status.value}",
        ),
        "correlation_id": correlation_id or uuid.uuid4(),
        "requested_action": action,
        "decision": status,
        "reason": f"Deterministic {status.value} decision for SOAR tests.",
        "policy_rule_id": policy_rule_id,
        "risk_level": RiskLevel.HIGH,
        "risk_score": 0.7,
        "confidence": 0.9,
        "requires_approval": status is PolicyDecisionStatus.REQUIRES_APPROVAL,
        "evidence": [],
        "metadata": {"source": "soar-test"},
        "timestamp": NOW,
    }
    data.update(overrides)
    return PolicyDecision.model_validate(data)


def a_request(
    *,
    playbook_id: str = "block_ip",
    target: str = "203.0.113.7",
    action: ResponseActionType = ResponseActionType.BLOCK_IP,
    status: PolicyDecisionStatus = PolicyDecisionStatus.ALLOWED,
    approval_id: uuid.UUID | None = None,
    response_id: uuid.UUID | None = None,
    decision: PolicyDecision | None = None,
    **decision_overrides: object,
) -> dict:
    """A full governed submission in the wire (JSON) shape."""
    decided = decision or a_decision(
        action=action, status=status, **decision_overrides
    )
    return {
        "decision": decided.model_dump(mode="json"),
        "target": target,
        "approval_id": str(approval_id) if approval_id is not None else None,
        "response_id": str(response_id or uuid.uuid4()),
        "playbook_id": playbook_id,
        "metadata": {"source": "soar-test"},
    }


class StubApprovalVerifier:
    """Scriptable :class:`ApprovalVerifier` stub (no DB needed)."""

    def __init__(
        self,
        *,
        ok: bool,
        error_code: str | None = None,
        calls: list[object] | None = None,
    ) -> None:
        self._ok = ok
        self._error_code = error_code
        self.calls = calls if calls is not None else []

    def verify_grant(
        self,
        *,
        approval_id: uuid.UUID | None,
        policy_decision_id: uuid.UUID,
        action_type: ResponseActionType,
        now: datetime,
    ) -> ApprovalGateResult:
        self.calls.append(
            {
                "approval_id": approval_id,
                "policy_decision_id": policy_decision_id,
                "action_type": action_type,
                "now": now,
            }
        )
        return ApprovalGateResult(ok=self._ok, error_code=self._error_code)