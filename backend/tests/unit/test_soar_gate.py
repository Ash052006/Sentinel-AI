"""SOAR policy gate tests (V2.18).

The gate is the engine's independent check: it never trusts the caller.
These tests pin the refusal matrix — DENIED / invalid / unverifiable
grants all stop before any provider could run, and an approval grant only
ever passes through the V2.16 verifier seam.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.schemas.policy_decision import (
    PolicyDecision,
    PolicyDecisionStatus,
    ResponseActionType,
)
from app.schemas.security_event import Provenance
from app.schemas.soar import SoarExecutionStatus
from app.services.response.approval_gate import APPROVAL_EXPIRED
from app.services.soar import (
    DEFAULT_SOAR_PLAYBOOK_REGISTRY,
    SoarPolicyGate,
)
from app.services.soar.gate import (
    APPROVAL_NOT_GIVEN,
    CODE_ACTION_MISMATCH,
    CODE_POLICY_DENIED,
    CODE_POLICY_INVALID,
    CODE_POLICY_REQUIRES_APPROVAL,
)
from tests.unit.soar_test_helpers import StubApprovalVerifier, a_decision

TZ = timezone.utc
NOW = datetime(2026, 9, 24, 8, 0, 0, tzinfo=TZ)

block_ip = DEFAULT_SOAR_PLAYBOOK_REGISTRY.require("block_ip")


def _non_policy_provenance_decision() -> PolicyDecision:
    """A no-validate decision carrying OBSERVED provenance.

    The schema pins provenance to POLICY_DECIDED, so this fabricated
    record is built via ``model_construct`` purely to exercise the gate's
    own provenance check.
    """
    base = a_decision(action=ResponseActionType.BLOCK_IP)
    fields = {field: getattr(base, field) for field in base.model_fields}
    fields["provenance"] = Provenance.OBSERVED
    return PolicyDecision.model_construct(**fields)


def test_allowed_with_anchored_action_passes() -> None:
    gate = SoarPolicyGate()
    decision = a_decision(action=ResponseActionType.BLOCK_IP)
    result = gate.evaluate(decision=decision, playbook=block_ip, approval_id=None, now=NOW)
    assert result.allowed is True
    assert result.error_code is None


def test_allowed_with_mismatched_playbook_rejected() -> None:
    gate = SoarPolicyGate()
    decision = a_decision(action=ResponseActionType.BLOCK_DOMAIN)
    result = gate.evaluate(decision=decision, playbook=block_ip, approval_id=None, now=NOW)
    assert result.allowed is False
    assert result.status is SoarExecutionStatus.REJECTED
    assert result.error_code == CODE_ACTION_MISMATCH


def test_denied_never_passes() -> None:
    gate = SoarPolicyGate()
    decision = a_decision(
        action=ResponseActionType.BLOCK_IP,
        status=PolicyDecisionStatus.DENIED,
    )
    result = gate.evaluate(decision=decision, playbook=block_ip, approval_id=None, now=NOW)
    assert result.allowed is False
    assert result.error_code == CODE_POLICY_DENIED


def test_non_policy_provenance_invalid() -> None:
    gate = SoarPolicyGate()
    result = gate.evaluate(
        decision=_non_policy_provenance_decision(),
        playbook=block_ip,
        approval_id=None,
        now=NOW,
    )
    assert result.allowed is False
    assert result.error_code == CODE_POLICY_INVALID


def test_requires_approval_without_grant_records_pending() -> None:
    gate = SoarPolicyGate()
    decision = a_decision(
        action=ResponseActionType.BLOCK_IP,
        status=PolicyDecisionStatus.REQUIRES_APPROVAL,
    )
    result = gate.evaluate(decision=decision, playbook=block_ip, approval_id=None, now=NOW)
    assert result.allowed is False
    assert result.status is SoarExecutionStatus.PENDING
    assert result.error_code == APPROVAL_NOT_GIVEN


def test_requires_approval_with_grant_but_no_verifier_fails_closed() -> None:
    gate = SoarPolicyGate()
    decision = a_decision(
        action=ResponseActionType.BLOCK_IP,
        status=PolicyDecisionStatus.REQUIRES_APPROVAL,
    )
    result = gate.evaluate(
        decision=decision,
        playbook=block_ip,
        approval_id=uuid.uuid4(),
        now=NOW,
    )
    assert result.allowed is False
    assert result.error_code == CODE_POLICY_REQUIRES_APPROVAL


def test_requires_approval_with_valid_grant_passes() -> None:
    verifier = StubApprovalVerifier(ok=True)
    gate = SoarPolicyGate(approval_verifier=verifier)
    decision = a_decision(
        action=ResponseActionType.BLOCK_IP,
        status=PolicyDecisionStatus.REQUIRES_APPROVAL,
    )
    approval_id = uuid.uuid4()
    result = gate.evaluate(
        decision=decision,
        playbook=block_ip,
        approval_id=approval_id,
        now=NOW,
    )
    assert result.allowed is True
    assert result.error_code is None
    assert verifier.calls
    assert verifier.calls[0]["approval_id"] == approval_id


def test_requires_approval_with_invalid_grant_rejected() -> None:
    verifier = StubApprovalVerifier(ok=False, error_code=APPROVAL_EXPIRED)
    gate = SoarPolicyGate(approval_verifier=verifier)
    decision = a_decision(
        action=ResponseActionType.BLOCK_IP,
        status=PolicyDecisionStatus.REQUIRES_APPROVAL,
    )
    result = gate.evaluate(
        decision=decision,
        playbook=block_ip,
        approval_id=uuid.uuid4(),
        now=NOW,
    )
    assert result.allowed is False
    assert result.status is SoarExecutionStatus.REJECTED
    assert result.error_code == APPROVAL_EXPIRED


def test_requires_approval_mismatched_action_rejected_before_grant() -> None:
    verifier = StubApprovalVerifier(ok=True)
    gate = SoarPolicyGate(approval_verifier=verifier)
    decision = a_decision(
        action=ResponseActionType.BLOCK_DOMAIN,
        status=PolicyDecisionStatus.REQUIRES_APPROVAL,
    )
    result = gate.evaluate(
        decision=decision,
        playbook=block_ip,
        approval_id=uuid.uuid4(),
        now=NOW,
    )
    assert result.allowed is False
    assert result.error_code == CODE_ACTION_MISMATCH
    assert verifier.calls == []  # grant never consulted on a mismatch