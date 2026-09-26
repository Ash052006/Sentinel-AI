"""Approval orchestration service tests (V2.16).

Drives ``ApprovalService`` directly against the real (development)
database: creation doctrine (only REQUIRES_APPROVAL decisions, inherited
action, deterministic identity, one lifecycle per decision), the
conditional-resolution concurrency guard, idempotent grants, the
state machine (pending -> approved/rejected/cancelled/expired; terminal
states never transition), the fixed-TTL lazy expiry, and the approved ->
Response layer hand-off with its separately recorded ``response_status``.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.approval_request import ApprovalRequestRow
from app.repositories.approval import ApprovalRepository
from app.schemas.approval import (
    APPROVAL_PENDING_TTL,
    ApprovalDecisionInput,
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
from app.services.approval.errors import (
    ApprovalConflictError,
    ApprovalNotFoundError,
    ApprovalValidationError,
)
from app.services.approval.service import MAX_PAGE_SIZE, MAX_RECENT_LIMIT, ApprovalService
from app.services.policy.identity import (
    derive_policy_decision_id,
    policy_decision_id_content,
)

TZ = timezone.utc
NOW = datetime(2026, 9, 20, 12, 0, 0, tzinfo=TZ)


def _clock():
    return NOW


def _now_clock():
    return datetime.now(timezone.utc)


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
    # content — the workflow recomputes it and rejects any mismatch
    # (H2.F-01), so every test decision must be self-consistent.  An
    # explicit override lets tests build an intentionally incoherent id.
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


def _payload(**overrides) -> ApprovalRequestCreate:
    data = {
        "decision": _decision(),
        "target": "198.51.100.7",
        "request_note": None,
    }
    data.update(overrides)
    return ApprovalRequestCreate.model_validate(data)


def _comment(text: str = "Reviewed and authorized by a human.") -> ApprovalDecisionInput:
    return ApprovalDecisionInput(comment=text)


def _row_count(db: Session, policy_decision_id: uuid.UUID) -> int:
    return len(
        db.execute(
            select(ApprovalRequestRow).where(
                ApprovalRequestRow.policy_decision_id == policy_decision_id
            )
        ).scalars().all()
    )


class TestCreation:
    def test_create_pending_record(self, db_session: Session, analyst_user) -> None:
        service = ApprovalService()
        record = service.create_request(
            db_session,
            _payload(),
            actor_user_id=analyst_user.id,
            actor_role="analyst",
            clock=_clock,
        )
        assert record.status is ApprovalStatus.PENDING
        assert record.provenance is Provenance.APPROVAL_REVIEWED
        assert record.expires_at == record.requested_at + APPROVAL_PENDING_TTL
        assert record.action_type is ResponseActionType.BLOCK_IP
        assert record.requested_by == analyst_user.id
        assert record.requested_by_role == "analyst"
        assert record.resolved_at is None

    def test_action_inherited_from_decision(
        self, db_session: Session, analyst_user
    ) -> None:
        service = ApprovalService()
        record = service.create_request(
            db_session,
            _payload(
                decision=_decision(
                    requested_action=ResponseActionType.ISOLATE_ENDPOINT
                ),
                target="edge-01",
            ),
            actor_user_id=analyst_user.id,
            actor_role="analyst",
            clock=_clock,
        )
        assert record.action_type is ResponseActionType.ISOLATE_ENDPOINT
        assert record.target == "edge-01"

    def test_request_note_persisted(self, db_session: Session, analyst_user) -> None:
        service = ApprovalService()
        record = service.create_request(
            db_session,
            _payload(request_note="Please review before blocking this host."),
            actor_user_id=analyst_user.id,
            actor_role="analyst",
            clock=_clock,
        )
        assert record.request_note == "Please review before blocking this host."

    def test_non_requires_approval_decisions_rejected(
        self, db_session: Session, analyst_user
    ) -> None:
        service = ApprovalService()
        for decision in (
            _decision(decision=PolicyDecisionStatus.ALLOWED),
            _decision(
                decision=PolicyDecisionStatus.DENIED, requires_approval=False
            ),
        ):
            with pytest.raises(ApprovalValidationError):
                service.create_request(
                    db_session,
                    _payload(decision=decision),
                    actor_user_id=analyst_user.id,
                    actor_role="analyst",
                    clock=_clock,
                )

    def test_requires_approval_flag_enforced(
        self, db_session: Session, analyst_user
    ) -> None:
        service = ApprovalService()
        with pytest.raises(ApprovalValidationError):
            service.create_request(
                db_session,
                _payload(decision=_decision(requires_approval=False)),
                actor_user_id=analyst_user.id,
                actor_role="analyst",
                clock=_clock,
            )

    def test_malformed_target_for_action_rejected(
        self, db_session: Session, analyst_user
    ) -> None:
        service = ApprovalService()
        with pytest.raises(ApprovalValidationError):
            service.create_request(
                db_session,
                _payload(decision=_decision(), target="this-is-not-an-ip"),
                actor_user_id=analyst_user.id,
                actor_role="analyst",
                clock=_clock,
            )


class TestOneLifecyclePerDecision:
    def test_recreate_while_pending_is_idempotent(
        self, db_session: Session, analyst_user
    ) -> None:
        service = ApprovalService()
        payload = _payload()
        first = service.create_request(
            db_session,
            payload,
            actor_user_id=analyst_user.id,
            actor_role="analyst",
            clock=_clock,
        )
        second = service.create_request(
            db_session,
            payload,
            actor_user_id=analyst_user.id,
            actor_role="analyst",
            clock=_clock,
        )
        assert second.approval_id == first.approval_id
        assert second.status is ApprovalStatus.PENDING
        assert _row_count(db_session, payload.decision.policy_decision_id) == 1

    def test_recreate_while_approved_returns_stored_record(
        self, db_session: Session, analyst_user, ciso_user
    ) -> None:
        service = ApprovalService()
        payload = _payload()
        created = service.create_request(
            db_session,
            payload,
            actor_user_id=analyst_user.id,
            actor_role="analyst",
            clock=_clock,
        )
        approved = service.approve(
            db_session,
            created.approval_id,
            _comment(),
            actor_user_id=ciso_user.id,
            actor_role="ciso",
            clock=_clock,
        )
        again = service.create_request(
            db_session,
            payload,
            actor_user_id=analyst_user.id,
            actor_role="analyst",
            clock=_clock,
        )
        assert again.approval_id == approved.approval_id
        assert again.status is ApprovalStatus.APPROVED
        assert _row_count(db_session, payload.decision.policy_decision_id) == 1

    def test_recreate_after_resolution_conflicts(
        self, db_session: Session, analyst_user, ciso_user
    ) -> None:
        service = ApprovalService()
        payload = _payload()
        created = service.create_request(
            db_session,
            payload,
            actor_user_id=analyst_user.id,
            actor_role="analyst",
            clock=_clock,
        )
        service.reject(
            db_session,
            created.approval_id,
            _comment(),
            actor_user_id=ciso_user.id,
            actor_role="ciso",
            clock=_clock,
        )
        with pytest.raises(ApprovalConflictError):
            service.create_request(
                db_session,
                payload,
                actor_user_id=analyst_user.id,
                actor_role="analyst",
                clock=_clock,
            )


class TestResolution:
    def test_approve_hand_off_to_response_layer(
        self, db_session: Session, analyst_user, ciso_user
    ) -> None:
        service = ApprovalService()
        created = service.create_request(
            db_session,
            _payload(),
            actor_user_id=analyst_user.id,
            actor_role="analyst",
            clock=_clock,
        )
        approved = service.approve(
            db_session,
            created.approval_id,
            _comment(),
            actor_user_id=ciso_user.id,
            actor_role="ciso",
            clock=_clock,
        )
        # Approval is authorization: the Response layer executed it via
        # the deterministic mock provider — but "approved" and "executed"
        # stay distinct fields.
        assert approved.status is ApprovalStatus.APPROVED
        assert approved.resolved_by == ciso_user.id
        assert approved.response_status == "executed"
        assert approved.response_provider == "mock"
        assert approved.response_error_code is None

    def test_approve_is_idempotent_and_never_reexecutes(
        self, db_session: Session, analyst_user, ciso_user
    ) -> None:
        service = ApprovalService()
        created = service.create_request(
            db_session,
            _payload(),
            actor_user_id=analyst_user.id,
            actor_role="analyst",
            clock=_clock,
        )
        first = service.approve(
            db_session,
            created.approval_id,
            _comment(),
            actor_user_id=ciso_user.id,
            actor_role="ciso",
            clock=_clock,
        )
        second = service.approve(
            db_session,
            created.approval_id,
            _comment("Second grant attempt."),
            actor_user_id=ciso_user.id,
            actor_role="ciso",
            clock=_clock,
        )
        assert second.approval_id == first.approval_id
        assert second.status is ApprovalStatus.APPROVED
        assert second.response_status == "executed"
        assert second.resolution_reason == first.resolution_reason

    def test_reject_never_executes(
        self, db_session: Session, analyst_user, ciso_user
    ) -> None:
        service = ApprovalService()
        created = service.create_request(
            db_session,
            _payload(),
            actor_user_id=analyst_user.id,
            actor_role="analyst",
            clock=_clock,
        )
        rejected = service.reject(
            db_session,
            created.approval_id,
            _comment("Refused: insufficient evidence."),
            actor_user_id=ciso_user.id,
            actor_role="ciso",
            clock=_clock,
        )
        assert rejected.status is ApprovalStatus.REJECTED
        assert rejected.resolution_reason == "Refused: insufficient evidence."
        assert rejected.response_status is None
        assert rejected.response_provider is None

    def test_cancel_withdraws_before_resolution(
        self, db_session: Session, analyst_user, ciso_user
    ) -> None:
        service = ApprovalService()
        created = service.create_request(
            db_session,
            _payload(),
            actor_user_id=analyst_user.id,
            actor_role="analyst",
            clock=_clock,
        )
        cancelled = service.cancel(
            db_session,
            created.approval_id,
            _comment("Withdrawn by operator."),
            actor_user_id=ciso_user.id,
            actor_role="ciso",
            clock=_clock,
        )
        assert cancelled.status is ApprovalStatus.CANCELLED
        assert cancelled.resolved_by == ciso_user.id
        assert cancelled.response_status is None

    def test_terminal_states_never_transition(
        self, db_session: Session, analyst_user, ciso_user
    ) -> None:
        service = ApprovalService()
        created = service.create_request(
            db_session,
            _payload(),
            actor_user_id=analyst_user.id,
            actor_role="analyst",
            clock=_clock,
        )
        service.reject(
            db_session,
            created.approval_id,
            _comment(),
            actor_user_id=ciso_user.id,
            actor_role="ciso",
            clock=_clock,
        )
        with pytest.raises(ApprovalConflictError):
            service.approve(
                db_session,
                created.approval_id,
                _comment(),
                actor_user_id=ciso_user.id,
                actor_role="ciso",
                clock=_clock,
            )
        with pytest.raises(ApprovalConflictError):
            service.cancel(
                db_session,
                created.approval_id,
                _comment(),
                actor_user_id=ciso_user.id,
                actor_role="ciso",
                clock=_clock,
            )

    def test_unknown_approval_id_not_found(
        self, db_session: Session, analyst_user
    ) -> None:
        service = ApprovalService()
        with pytest.raises(ApprovalNotFoundError):
            service.approve(
                db_session,
                uuid.uuid4(),
                _comment(),
                actor_user_id=analyst_user.id,
                actor_role="analyst",
                clock=_clock,
            )

    def test_get_request_returns_none_for_unknown(
        self, db_session: Session
    ) -> None:
        service = ApprovalService()
        assert service.get_request(db_session, uuid.uuid4(), clock=_clock) is None


class TestDualControl:
    """H2.F-04: the requester can never resolve their own request."""

    def test_requester_cannot_approve_own_request(
        self, db_session: Session, analyst_user
    ) -> None:
        service = ApprovalService()
        created = service.create_request(
            db_session,
            _payload(),
            actor_user_id=analyst_user.id,
            actor_role="analyst",
            clock=_clock,
        )
        with pytest.raises(ApprovalValidationError):
            service.approve(
                db_session,
                created.approval_id,
                _comment(),
                actor_user_id=analyst_user.id,
                actor_role="analyst",
                clock=_clock,
            )
        row = db_session.scalar(
            select(ApprovalRequestRow).where(
                ApprovalRequestRow.approval_id == created.approval_id
            )
        )
        assert row.status == ApprovalStatus.PENDING.value

    def test_requester_cannot_reject_or_cancel_own_request(
        self, db_session: Session, analyst_user
    ) -> None:
        service = ApprovalService()
        created = service.create_request(
            db_session,
            _payload(),
            actor_user_id=analyst_user.id,
            actor_role="analyst",
            clock=_clock,
        )
        for operate in (service.reject, service.cancel):
            with pytest.raises(ApprovalValidationError):
                operate(
                    db_session,
                    created.approval_id,
                    _comment(),
                    actor_user_id=analyst_user.id,
                    actor_role="analyst",
                    clock=_clock,
                )


class TestDecisionSelfConsistency:
    """H2.F-01: only coherent engine-issued decisions are routable."""

    def test_tampered_decision_id_rejected_before_persist(
        self, db_session: Session, analyst_user
    ) -> None:
        service = ApprovalService()
        incoherent = _decision(policy_decision_id=uuid.uuid4())
        with pytest.raises(ApprovalValidationError) as exc:
            service.create_request(
                db_session,
                _payload(decision=incoherent),
                actor_user_id=analyst_user.id,
                actor_role="analyst",
                clock=_clock,
            )
        assert "does not match" in str(exc.value)

    def test_engine_minted_decision_round_trips_through_workflow(
        self, db_session: Session, analyst_user, ciso_user
    ) -> None:
        """A genuine engine decision passes the self-consistency guard and
        flows through create -> approve exactly as a real SOC workflow."""
        from app.services.policy.engine import PolicyDecisionEngine

        engine = PolicyDecisionEngine()
        decision = engine.decide(
            {
                "correlation_id": uuid.uuid4(),
                "requested_action": "block_ip",
                "risk_level": "critical",
                "risk_score": 0.95,
                "confidence": 0.99,
                "evidence_available": True,
                "investigation_available": False,
                "attribution_status": None,
                "metadata": {"test": "H2.F-01"},
                "evidence_references": [],
            },
            clock=_clock,
        )
        service = ApprovalService()
        created = service.create_request(
            db_session,
            _payload(decision=decision, target="198.51.100.7"),
            actor_user_id=analyst_user.id,
            actor_role="analyst",
            clock=_clock,
        )
        approved = service.approve(
            db_session,
            created.approval_id,
            _comment(),
            actor_user_id=ciso_user.id,
            actor_role="ciso",
            clock=_clock,
        )
        assert approved.status is ApprovalStatus.APPROVED
        assert approved.response_status == "executed"


class TestConditionalGuard:
    def test_conditional_resolution_wins_exactly_once(
        self, db_session: Session, analyst_user
    ) -> None:
        created = ApprovalService().create_request(
            db_session,
            _payload(),
            actor_user_id=analyst_user.id,
            actor_role="analyst",
            clock=_clock,
        )
        repo = ApprovalRepository(db_session)
        first_claim = repo.resolve_pending(
            created.approval_id,
            now=NOW,
            target_status="approved",
            resolved_by=analyst_user.id,
            resolution_reason="first human",
        )
        assert first_claim is not None
        assert first_claim.status == "approved"
        second_claim = repo.resolve_pending(
            created.approval_id,
            now=NOW,
            target_status="rejected",
            resolved_by=analyst_user.id,
            resolution_reason="second human (loses)",
        )
        assert second_claim is None

    def test_expired_pending_cannot_be_claimed(
        self, db_session: Session, analyst_user
    ) -> None:
        created = ApprovalService().create_request(
            db_session,
            _payload(),
            actor_user_id=analyst_user.id,
            actor_role="analyst",
            clock=_clock,
        )
        repo = ApprovalRepository(db_session)
        claim = repo.resolve_pending(
            created.approval_id,
            now=NOW + APPROVAL_PENDING_TTL + timedelta(seconds=1),
            target_status="approved",
            resolved_by=analyst_user.id,
            resolution_reason="too late",
        )
        assert claim is None


class TestExpiry:
    def test_lazy_expiry_marks_past_requests(
        self, db_session: Session, analyst_user
    ) -> None:
        service = ApprovalService()
        created = service.create_request(
            db_session,
            _payload(),
            actor_user_id=analyst_user.id,
            actor_role="analyst",
            clock=_clock,
        )
        later = NOW + APPROVAL_PENDING_TTL + timedelta(hours=1)
        expired = service.expire_pending(db_session, clock=lambda: later)
        assert expired >= 1
        fetched = service.get_request(
            db_session, created.approval_id, clock=lambda: later
        )
        assert fetched is not None
        assert fetched.status is ApprovalStatus.EXPIRED
        assert fetched.resolution_reason is not None
        assert fetched.resolved_by is None

    def test_approving_an_expired_request_conflicts(
        self, db_session: Session, analyst_user, ciso_user
    ) -> None:
        service = ApprovalService()
        created = service.create_request(
            db_session,
            _payload(),
            actor_user_id=analyst_user.id,
            actor_role="analyst",
            clock=_clock,
        )
        later = NOW + APPROVAL_PENDING_TTL + timedelta(hours=1)
        with pytest.raises(ApprovalConflictError):
            service.approve(
                db_session,
                created.approval_id,
                _comment(),
                actor_user_id=ciso_user.id,
                actor_role="ciso",
                clock=NOW_later_lambda(later),
            )


def NOW_later_lambda(later: datetime):
    return lambda: later


class TestReads:
    def test_get_request_round_trip_shape(
        self, db_session: Session, analyst_user
    ) -> None:
        service = ApprovalService()
        created = service.create_request(
            db_session,
            _payload(),
            actor_user_id=analyst_user.id,
            actor_role="analyst",
            clock=_clock,
        )
        fetched = service.get_request(
            db_session, created.approval_id, clock=_clock
        )
        assert fetched is not None
        assert fetched.provenance is Provenance.APPROVAL_REVIEWED
        assert fetched.requested_at == created.requested_at
        assert fetched.expires_at == created.expires_at

    def test_list_and_extract_created(self, db_session: Session, analyst_user) -> None:
        service = ApprovalService()
        created = service.create_request(
            db_session,
            _payload(),
            actor_user_id=analyst_user.id,
            actor_role="analyst",
            clock=_clock,
        )
        # The shared dev DB accumulates rows, so page forward until the
        # created record is found instead of assuming it lands on page 1.
        found = False
        total = None
        page_num = 1
        while page_num <= 20:
            page = service.list_requests(
                db_session,
                page=page_num,
                page_size=MAX_PAGE_SIZE,
                clock=_clock,
            )
            total = page.total
            if any(item.approval_id == created.approval_id for item in page.items):
                found = True
                break
            if page_num * len(page.items) >= total:
                break
            page_num += 1
        assert found
        pending_page = service.list_requests(
            db_session,
            page=1,
            page_size=MAX_PAGE_SIZE,
            status=ApprovalStatus.PENDING,
            clock=_clock,
        )
        assert any(
            item.approval_id == created.approval_id
            for item in pending_page.items
        )

    def test_recent_feed_and_status_filter(
        self, db_session: Session, analyst_user
    ) -> None:
        service = ApprovalService()
        created = service.create_request(
            db_session,
            _payload(),
            actor_user_id=analyst_user.id,
            actor_role="analyst",
            clock=_now_clock,
        )
        recent = service.list_recent_requests(
            db_session, limit=MAX_RECENT_LIMIT, clock=_now_clock
        )
        assert any(item.approval_id == created.approval_id for item in recent)
        recent_pending = service.list_recent_requests(
            db_session,
            limit=MAX_RECENT_LIMIT,
            status=ApprovalStatus.PENDING,
            clock=_now_clock,
        )
        assert any(
            item.approval_id == created.approval_id for item in recent_pending
        )

    def test_page_bounds_validated(self, db_session: Session) -> None:
        service = ApprovalService()
        for bad in ({"page": 0}, {"page_size": 0}, {"page_size": 201}):
            with pytest.raises(ApprovalValidationError):
                service.list_requests(db_session, clock=_clock, **bad)
        with pytest.raises(ApprovalValidationError):
            service.list_recent_requests(db_session, limit=0, clock=_clock)
        with pytest.raises(ApprovalValidationError):
            service.list_recent_requests(db_session, limit=201, clock=_clock)