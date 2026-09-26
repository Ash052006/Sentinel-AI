"""Approval Workflow domain contract tests (V2.16).

Covers ``app/schemas/approval.py``: the closed approval-state vocabulary
(``pending``/``approved``/``rejected``/``expired``/``cancelled``), the
deterministic identity constants, structured request validation
(secret-safe targets and notes, inherited action), the human decision
input (required, secret-free comment), the provenance-pinned approval
read record (an approval is a human governance action and is never any
prior provenance value), and the pagination envelope.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from app.schemas.approval import (
    APPROVAL_MAX_COMMENT_LENGTH,
    APPROVAL_MAX_TARGET_LENGTH,
    APPROVAL_NAMESPACE,
    APPROVAL_PENDING_TTL,
    APPROVAL_TERMINAL_STATUSES,
    ApprovalDecisionInput,
    ApprovalPage,
    ApprovalRecord,
    ApprovalRequestCreate,
    ApprovalStatus,
)
from app.schemas.policy_decision import (
    PolicyDecision,
    PolicyDecisionStatus,
    ResponseActionType,
)
from app.schemas.risk import RiskLevel
from app.schemas.security_event import Provenance
from app.services.policy.identity import (
    derive_policy_decision_id,
    policy_decision_id_content,
)

TZ = timezone.utc
NOW = datetime(2025, 7, 17, 8, 0, 0, tzinfo=TZ)


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
    # content (H2.F-01) — keep every fixture decision self-consistent.
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


def _record(**overrides) -> ApprovalRecord:
    data = {
        "id": uuid.uuid4(),
        "approval_id": uuid.uuid5(APPROVAL_NAMESPACE, "deterministic-test"),
        "policy_decision_id": uuid.uuid4(),
        "correlation_id": uuid.uuid4(),
        "action_type": ResponseActionType.BLOCK_IP,
        "target": "198.51.100.7",
        "status": ApprovalStatus.PENDING,
        "reason": "Requested action block_ip requires human approval.",
        "policy_rule_id": "TEST-RULE-APPROVAL-001",
        "risk_level": RiskLevel.HIGH,
        "risk_score": 0.8,
        "confidence": 0.95,
        "evidence": [],
        "request_note": None,
        "requested_by": uuid.uuid4(),
        "requested_by_role": "analyst",
        "requested_at": NOW,
        "expires_at": NOW + APPROVAL_PENDING_TTL,
        "resolved_at": None,
        "resolved_by": None,
        "resolution_reason": None,
        "response_status": None,
        "response_provider": None,
        "response_error_code": None,
        "metadata": {},
        "created_at": NOW,
        "updated_at": NOW,
    }
    data.update(overrides)
    return ApprovalRecord.model_validate(data)


# ---------------------------------------------------------------------------
# 1. Constants
# ---------------------------------------------------------------------------


class TestConstants:
    def test_pending_ttl_is_fixed_and_documented(self):
        assert APPROVAL_PENDING_TTL == timedelta(hours=24)

    def test_approval_namespace_is_fixed_and_deterministic(self):
        assert APPROVAL_NAMESPACE == uuid.UUID("3d4e5f6a-7b8c-4d9e-8f0a-1b2c3d4e5f60")

    def test_max_bounds_are_positive(self):
        assert APPROVAL_MAX_COMMENT_LENGTH == 500
        assert APPROVAL_MAX_TARGET_LENGTH == 512


# ---------------------------------------------------------------------------
# 2. Approval status vocabulary
# ---------------------------------------------------------------------------


class TestApprovalStatus:
    def test_closed_vocabulary(self):
        assert [s.value for s in ApprovalStatus] == [
            "pending",
            "approved",
            "rejected",
            "expired",
            "cancelled",
        ]

    def test_terminal_statuses_closed(self):
        assert set(ApprovalStatus) == set(ApprovalStatus)  # closed enum (sanity)
        assert ApprovalStatus.APPROVED in APPROVAL_TERMINAL_STATUSES
        assert ApprovalStatus.REJECTED in APPROVAL_TERMINAL_STATUSES
        assert ApprovalStatus.EXPIRED in APPROVAL_TERMINAL_STATUSES
        assert ApprovalStatus.CANCELLED in APPROVAL_TERMINAL_STATUSES
        assert ApprovalStatus.PENDING not in APPROVAL_TERMINAL_STATUSES

    def test_decision_statuses_only_human_decisions(self):
        from app.schemas.approval import APPROVAL_DECISION_STATUSES

        assert APPROVAL_DECISION_STATUSES == frozenset(
            {ApprovalStatus.APPROVED, ApprovalStatus.REJECTED}
        )


# ---------------------------------------------------------------------------
# 3. ApprovalRequestCreate
# ---------------------------------------------------------------------------


class TestApprovalRequestCreate:
    def test_valid_create(self):
        create = ApprovalRequestCreate(
            decision=_decision(),
            target="198.51.100.7",
            request_note="Review before blocking.",
        )
        assert create.target == "198.51.100.7"
        assert create.request_note == "Review before blocking."
        assert create.decision.decision is PolicyDecisionStatus.REQUIRES_APPROVAL

    def test_action_is_inherited_not_supplied(self):
        decision = _decision(requested_action=ResponseActionType.BLOCK_DOMAIN)
        create = ApprovalRequestCreate(decision=decision, target="evil.example.com")
        assert create.decision.requested_action is ResponseActionType.BLOCK_DOMAIN

    def test_extra_fields_rejected(self):
        with pytest.raises(ValidationError):
            ApprovalRequestCreate.model_validate(
                {
                    "decision": _decision().model_dump(mode="json"),
                    "target": "198.51.100.7",
                    "action_type": "block_ip",
                }
            )

    def test_blank_target_rejected(self):
        with pytest.raises(ValidationError):
            ApprovalRequestCreate(decision=_decision(), target="   ")

    def test_oversized_target_rejected(self):
        with pytest.raises(ValidationError):
            ApprovalRequestCreate(
                decision=_decision(), target="a" * (APPROVAL_MAX_TARGET_LENGTH + 1)
            )

    def test_control_characters_rejected_in_target(self):
        with pytest.raises(ValidationError):
            ApprovalRequestCreate(decision=_decision(), target="198.51.100.7\x00")

    def test_secret_shaped_target_rejected(self):
        for secret in ("Bearer abcdef123", "api_key=super-secret", "secret-token"):
            with pytest.raises(ValidationError):
                ApprovalRequestCreate(decision=_decision(), target=secret)

    def test_blank_note_rejected(self):
        with pytest.raises(ValidationError):
            ApprovalRequestCreate(
                decision=_decision(), target="198.51.100.7", request_note="  "
            )

    def test_oversized_note_rejected(self):
        with pytest.raises(ValidationError):
            ApprovalRequestCreate(
                decision=_decision(),
                target="198.51.100.7",
                request_note="n" * (APPROVAL_MAX_COMMENT_LENGTH + 1),
            )

    def test_secret_shaped_note_rejected(self):
        with pytest.raises(ValidationError):
            ApprovalRequestCreate(
                decision=_decision(),
                target="198.51.100.7",
                request_note="please use my api_key to proceed",
            )


# ---------------------------------------------------------------------------
# 4. ApprovalDecisionInput
# ---------------------------------------------------------------------------


class TestApprovalDecisionInput:
    def test_comment_required(self):
        with pytest.raises(ValidationError):
            ApprovalDecisionInput.model_validate({})

    def test_blank_comment_rejected(self):
        with pytest.raises(ValidationError):
            ApprovalDecisionInput(comment="   ")

    def test_oversized_comment_rejected(self):
        with pytest.raises(ValidationError):
            ApprovalDecisionInput(comment="c" * (APPROVAL_MAX_COMMENT_LENGTH + 1))

    def test_secret_shaped_comment_rejected(self):
        with pytest.raises(ValidationError):
            ApprovalDecisionInput(comment="authorization Bearer deadbeef")

    def test_extra_fields_rejected(self):
        with pytest.raises(ValidationError):
            ApprovalDecisionInput.model_validate(
                {"comment": "Approved - low risk.", "expires_in": 5}
            )


# ---------------------------------------------------------------------------
# 5. ApprovalRecord — provenance pinning and read-model shape
# ---------------------------------------------------------------------------


class TestApprovalRecordProvenance:
    def test_default_provenance_is_approval_reviewed(self):
        record = _record()
        assert record.provenance is Provenance.APPROVAL_REVIEWED

    def test_explicit_approval_reviewed_accepted(self):
        record = _record(provenance=Provenance.APPROVAL_REVIEWED)
        assert record.provenance.value == "approval_reviewed"

    def test_prior_provenance_values_rejected(self):
        for prior in (
            Provenance.OBSERVED,
            Provenance.DETECTED,
            Provenance.CORRELATED,
            Provenance.RISK_ASSESSED,
            Provenance.POLICY_DECIDED,
            Provenance.RESPONSE_EXECUTED,
        ):
            with pytest.raises(ValidationError):
                _record(provenance=prior)

    def test_approval_reviewed_is_additive_tail_of_provenance(self):
        assert Provenance.APPROVAL_REVIEWED.name == "APPROVAL_REVIEWED"
        assert Provenance.APPROVAL_REVIEWED.value == "approval_reviewed"
        members = list(Provenance)
        assert members[-1] is Provenance.APPROVAL_REVIEWED


class TestApprovalRecordShape:
    def test_response_status_distinct_from_status(self):
        record = _record(
            status=ApprovalStatus.APPROVED,
            response_status="executed",
            response_provider="mock",
        )
        assert record.status is ApprovalStatus.APPROVED
        assert record.response_status == "executed"
        assert record.response_provider == "mock"
        assert record.status.value != record.response_status

    def test_resolved_fields_null_for_pending(self):
        record = _record()
        assert record.resolved_at is None
        assert record.resolved_by is None
        assert record.resolution_reason is None

    def test_naive_timestamps_rejected(self):
        for field in ("requested_at", "expires_at", "created_at", "updated_at"):
            with pytest.raises(ValidationError):
                _record(**{field: datetime(2025, 1, 1)})

    def test_naive_resolved_at_rejected(self):
        with pytest.raises(ValidationError):
            _record(resolved_at=datetime(2025, 1, 1))

    def test_metadata_is_cloned_not_aliased(self):
        original = {"source": "approval"}
        record = _record(metadata=original)
        record.metadata["tampered"] = True
        assert "tampered" not in original

    def test_secret_shaped_metadata_rejected(self):
        with pytest.raises(ValidationError):
            _record(metadata={"authorization": "Bearer deadbeef"})

    def test_reason_preserved_verbatim_from_decision_even_when_it_mentions_secrets(
        self,
    ):
        reason = (
            "elevated-risk escalation requires human authorization and "
            "rotating the API secret is out of scope for automation"
        )
        record = _record(reason=reason)
        assert record.reason == reason

    def test_resolution_reason_still_secret_scanned(self):
        with pytest.raises(ValidationError):
            _record(resolution_reason="authorization Bearer deadbeef")

    def test_blank_or_control_char_reason_still_rejected(self):
        with pytest.raises(ValidationError):
            _record(reason="   ")
        with pytest.raises(ValidationError):
            _record(reason="elevated risk\x00")

    def test_control_characters_rejected_in_target(self):
        with pytest.raises(ValidationError):
            _record(target="198.51.100.7\x00")

    def test_read_model_exposes_no_command_or_instruction_channel(self):
        allowed = {name for name in ApprovalRecord.model_fields}
        for forbidden in ("command", "instructions", "prompt", "llm_prompt", "agent"):
            assert forbidden not in allowed


# ---------------------------------------------------------------------------
# 6. Pagination envelope
# ---------------------------------------------------------------------------


class TestApprovalPage:
    def test_page_model(self):
        page = ApprovalPage(items=[_record()], total=1, page=1, page_size=50)
        assert page.total == 1
        assert page.page == 1
        assert page.page_size == 50

    def test_page_bounds_enforced(self):
        with pytest.raises(ValidationError):
            ApprovalPage(items=[], total=-1, page=1, page_size=50)
        with pytest.raises(ValidationError):
            ApprovalPage(items=[], total=0, page=0, page_size=50)
        with pytest.raises(ValidationError):
            ApprovalPage(items=[], total=0, page=1, page_size=0)