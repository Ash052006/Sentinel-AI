"""Response executor — policy gate & execution semantics tests (Step 25).

The doctrine claims, and these tests pin down:

* an ``ALLOWED`` matching decision executes (provider called); anything
  else is ``REJECTED`` and the provider is provably **never** called;
* request/decision (decision id, correlation id, action type, response
  id) mismatches reject without invoking any provider;
* targets are validated per action (valid -> executed; invalid ->
  ``TARGET_INVALID``, no provider);
* idempotency: identical content executes once, deterministically; a
  retry returns the stored result; distinct content has distinct keys;
* provider failure maps to ``FAILED`` (never silently to success) and is
  itself idempotency-suppressed;
* unsupported action/provider resolves to a ``REJECTED`` record;
* determinism (fixed clock) and immutability (caller inputs untouched;
  returned records independent of internal state).

No shell, no OS mutation, no network, no filesystem: every provider here
is a pure in-memory simulation or a controlled test double.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from app.schemas.policy_decision import (
    PolicyDecision,
    PolicyDecisionStatus,
    ResponseActionType,
)
from app.schemas.response import (
    ResponseExecutionStatus,
    ResponseRequest,
    ResponseResult,
)
from app.schemas.security_event import Provenance
from app.services.response.errors import (
    ResponseInternalError,
    ResponseProviderError,
    ResponseValidationError,
)
from app.services.response.executor import ResponseExecutor
from app.services.response.providers import MOCK_PROVIDER, ResponseProvider
from app.services.response.registry import ResponseProviderRegistry
from app.services.response.validator import derive_response_id

TZ = timezone.utc
FIXED = datetime(2025, 8, 1, 11, 0, 0, tzinfo=TZ)


def _decision(
    *,
    decision_id: uuid.UUID,
    correlation_id: uuid.UUID,
    action: ResponseActionType = ResponseActionType.BLOCK_IP,
    status: PolicyDecisionStatus = PolicyDecisionStatus.ALLOWED,
) -> PolicyDecision:
    return PolicyDecision(
        policy_decision_id=decision_id,
        correlation_id=correlation_id,
        requested_action=action,
        decision=status,
        reason="allowed by rule" if status is PolicyDecisionStatus.ALLOWED else "denied by rule",
        policy_rule_id="POLICY-BLOCK-IP-001",
        risk_level="high",
        requires_approval=status is PolicyDecisionStatus.REQUIRES_APPROVAL,
        timestamp=FIXED,
    )


def _request(
    *,
    decision: PolicyDecision,
    action: ResponseActionType | None = None,
    target: str = "10.0.0.5",
    decision_id: uuid.UUID | None = None,
    correlation_id: uuid.UUID | None = None,
    response_id: uuid.UUID | None = None,
) -> ResponseRequest:
    effective_action = action if action is not None else decision.requested_action
    rid = response_id or derive_response_id(
        policy_decision_id=decision.policy_decision_id,
        action=effective_action,
        target=target,
    )
    return ResponseRequest(
        response_id=rid,
        policy_decision_id=(
            decision_id if decision_id is not None else decision.policy_decision_id
        ),
        correlation_id=(
            correlation_id if correlation_id is not None else decision.correlation_id
        ),
        action_type=effective_action,
        target=target,
        requested_at=FIXED,
    )


class CallCounting(ResponseProvider):
    """Registry-able provider that runs a controllable body."""

    name = "counting"

    def __init__(self, actions=frozenset(ResponseActionType)):
        self.supported_actions = actions
        self.call_count = 0
        self.last_target = None
        self.raise_error: Exception | None = None

    def execute(self, request: ResponseRequest, *, clock=None) -> ResponseResult:
        self.call_count += 1
        self.last_target = request.target
        if self.raise_error is not None:
            raise self.raise_error
        now = (clock() if clock is not None else datetime.now(timezone.utc))
        return ResponseResult(
            response_id=request.response_id,
            policy_decision_id=request.policy_decision_id,
            correlation_id=request.correlation_id,
            action_type=request.action_type,
            execution_status=ResponseExecutionStatus.EXECUTED,
            target=request.target,
            provider=self.name,
            started_at=now,
            completed_at=now,
            message="Simulated execution",
            error_code=None,
            metadata={},
            timestamp=now,
        )


@pytest.fixture
def counting() -> CallCounting:
    return CallCounting()


@pytest.fixture
def executor(counting: CallCounting) -> ResponseExecutor:
    return ResponseExecutor(
        registry=ResponseProviderRegistry((counting,)),
        clock=lambda: FIXED,
    )


# ---------------------------------------------------------------------------
# The policy gate (the heart of Step 25)
# ---------------------------------------------------------------------------


class TestPolicyGate:
    def test_allowed_executes(self, executor, counting: CallCounting) -> None:
        d = _decision(decision_id=uuid.uuid4(), correlation_id=uuid.uuid4())
        result = executor.execute(_request(decision=d), d)
        assert result.execution_status is ResponseExecutionStatus.EXECUTED
        assert result.error_code is None
        assert result.provider == "counting"
        assert counting.call_count == 1
        assert result.provenance is Provenance.RESPONSE_EXECUTED

    def test_allowed_records_canonical_target(self, executor) -> None:
        d = _decision(decision_id=uuid.uuid4(), correlation_id=uuid.uuid4())
        result = executor.execute(_request(decision=d, target=" 10.0.0.5 "), d)
        assert result.target == "10.0.0.5"

    @pytest.mark.parametrize(
        ("status", "expected_code"),
        [
            (PolicyDecisionStatus.DENIED, "POLICY_DENIED"),
            (PolicyDecisionStatus.REQUIRES_APPROVAL, "POLICY_REQUIRES_APPROVAL"),
        ],
    )
    def test_non_allowed_rejects_and_never_calls_provider(
        self, executor, counting: CallCounting, status, expected_code: str
    ) -> None:
        d = _decision(
            decision_id=uuid.uuid4(),
            correlation_id=uuid.uuid4(),
            status=status,
        )
        result = executor.execute(_request(decision=d), d)
        assert result.execution_status is ResponseExecutionStatus.REJECTED
        assert result.error_code == expected_code
        assert result.provider is None
        assert result.started_at is None and result.completed_at is None
        assert counting.call_count == 0  # provably never called

    def test_malformed_decision_fails_closed(
        self, executor, counting: CallCounting
    ) -> None:
        d = _decision(decision_id=uuid.uuid4(), correlation_id=uuid.uuid4())
        req = _request(decision=d)
        # A decision that claims to be something it is not (dict form,
        # bypassing the schema's own provenance pin) must fail closed.
        tampered = d.model_dump(mode="json")
        tampered["provenance"] = "detected"
        result = executor.execute(req, tampered)
        assert result.execution_status is ResponseExecutionStatus.REJECTED
        assert result.error_code == "POLICY_INVALID"
        assert counting.call_count == 0

    def test_unverifiable_decision_dict_fails_closed(self, executor, counting: CallCounting) -> None:
        req = _request(decision=_decision(decision_id=uuid.uuid4(), correlation_id=uuid.uuid4()))
        broken = {"policy_decision_id": uuid.uuid4(), "decision": "allowed"}  # missing fields
        result = executor.execute(req, broken)
        assert result.execution_status is ResponseExecutionStatus.REJECTED
        assert result.error_code == "POLICY_INVALID"
        assert counting.call_count == 0

    def test_unknown_decision_state_fails_closed(self, executor, counting: CallCounting) -> None:
        d = _decision(decision_id=uuid.uuid4(), correlation_id=uuid.uuid4())
        req = _request(decision=d)
        result = executor.execute(req, {"policy_decision_id": "", "decision": "maybe"})
        assert result.execution_status is ResponseExecutionStatus.REJECTED
        assert result.error_code == "POLICY_INVALID"
        assert counting.call_count == 0


# ---------------------------------------------------------------------------
# Request/decision integrity
# ---------------------------------------------------------------------------


class TestIntegrityMismatch:
    def test_policy_decision_id_mismatch_rejects(self, executor, counting: CallCounting) -> None:
        d = _decision(decision_id=uuid.uuid4(), correlation_id=uuid.uuid4())
        result = executor.execute(
            _request(decision=d, decision_id=uuid.uuid4()), d
        )
        assert result.execution_status is ResponseExecutionStatus.REJECTED
        assert result.error_code == "POLICY_DECISION_MISMATCH"
        assert counting.call_count == 0

    def test_correlation_id_mismatch_rejects(self, executor, counting: CallCounting) -> None:
        d = _decision(decision_id=uuid.uuid4(), correlation_id=uuid.uuid4())
        result = executor.execute(
            _request(decision=d, correlation_id=uuid.uuid4()), d
        )
        assert result.execution_status is ResponseExecutionStatus.REJECTED
        assert result.error_code == "CORRELATION_MISMATCH"
        assert counting.call_count == 0

    def test_action_type_mismatch_rejects(self, executor, counting: CallCounting) -> None:
        d = _decision(decision_id=uuid.uuid4(), correlation_id=uuid.uuid4())
        wrong = _request(
            decision=d,
            action=ResponseActionType.TERMINATE_SESSION,
            target="sess-001",
        )
        # response_id in `wrong` was derived from the WRONG action, so gate
        # must reject at ACTION_MISMATCH before identity is even checked.
        result = executor.execute(wrong, d)
        assert result.execution_status is ResponseExecutionStatus.REJECTED
        assert result.error_code == "ACTION_MISMATCH"
        assert counting.call_count == 0

    def test_spoofed_response_id_rejects(self, executor, counting: CallCounting) -> None:
        d = _decision(decision_id=uuid.uuid4(), correlation_id=uuid.uuid4())
        req = _request(decision=d, response_id=uuid.uuid4())
        result = executor.execute(req, d)
        assert result.execution_status is ResponseExecutionStatus.REJECTED
        assert result.error_code == "RESPONSE_ID_MISMATCH"
        assert counting.call_count == 0


# ---------------------------------------------------------------------------
# Per-action target validation
# ---------------------------------------------------------------------------


class TestTargetValidation:
    @pytest.mark.parametrize(
        ("action", "target"),
        [
            (ResponseActionType.BLOCK_IP, "10.0.0.1"),
            (ResponseActionType.BLOCK_IP, "2001:db8::1"),
            (ResponseActionType.BLOCK_DOMAIN, "evil.example.com"),
            (ResponseActionType.QUARANTINE_FILE, "tmp/eicar.txt"),
            (ResponseActionType.DISABLE_ACCOUNT, "alice@corp"),
            (ResponseActionType.TERMINATE_SESSION, "sess-001"),
            (ResponseActionType.ISOLATE_ENDPOINT, "endpoint-42"),
        ],
    )
    def test_valid_targets_execute(self, executor, action, target: str) -> None:
        d = _decision(
            decision_id=uuid.uuid4(),
            correlation_id=uuid.uuid4(),
            action=action,
        )
        result = executor.execute(_request(decision=d, action=action, target=target), d)
        assert result.execution_status is ResponseExecutionStatus.EXECUTED
        assert result.error_code is None

    @pytest.mark.parametrize(
        ("action", "target"),
        [
            (ResponseActionType.BLOCK_IP, "999.1.1.1"),  # invalid octet
            (ResponseActionType.BLOCK_IP, "10.0.0.1/24"),  # no CIDR for a single IP
            (ResponseActionType.BLOCK_IP, "http://10.0.0.1"),  # no scheme
            (ResponseActionType.BLOCK_DOMAIN, "http://evil.example.com"),
            (ResponseActionType.BLOCK_DOMAIN, "evil"),  # not a domain
            (ResponseActionType.QUARANTINE_FILE, "../../etc/passwd"),
            (ResponseActionType.QUARANTINE_FILE, "/etc/passwd"),
            (ResponseActionType.DISABLE_ACCOUNT, "alice smith"),
            (ResponseActionType.TERMINATE_SESSION, "a" * 200),
            (ResponseActionType.ISOLATE_ENDPOINT, "endpoint_42"),  # no underscore
        ],
    )
    def test_invalid_targets_reject_without_provider(
        self, executor, counting: CallCounting, action, target: str
    ) -> None:
        d = _decision(
            decision_id=uuid.uuid4(),
            correlation_id=uuid.uuid4(),
            action=action,
        )
        req = _request(decision=d, action=action, target=target)
        result = executor.execute(req, d)
        assert result.execution_status is ResponseExecutionStatus.REJECTED
        assert result.error_code == "TARGET_INVALID"
        assert counting.call_count == 0


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


class TestIdempotency:
    def test_identical_request_executes_once(self, executor, counting: CallCounting) -> None:
        d = _decision(decision_id=uuid.uuid4(), correlation_id=uuid.uuid4())
        req = _request(decision=d)
        first = executor.execute(req, d)
        second = executor.execute(req, d)
        assert first == second
        assert first.response_id == second.response_id
        assert counting.call_count == 1  # not double-executed
        assert executor.processed_count == 1
        assert second.execution_status is ResponseExecutionStatus.EXECUTED

    def test_identity_is_content_derived_across_new_requests(self, executor, counting) -> None:
        d = _decision(decision_id=uuid.uuid4(), correlation_id=uuid.uuid4())
        req_a = _request(decision=d)
        req_b = _request(decision=d)  # identical content, fresh object
        a = executor.execute(req_a, d)
        b = executor.execute(req_b, d)
        assert a.response_id == b.response_id
        assert a == b
        assert counting.call_count == 1

    def test_different_target_different_key(self, executor, counting) -> None:
        d = _decision(decision_id=uuid.uuid4(), correlation_id=uuid.uuid4())
        executor.execute(_request(decision=d, target="10.0.0.5"), d)
        executor.execute(_request(decision=d, target="10.0.0.6"), d)
        assert counting.call_count == 2
        assert executor.processed_count == 2

    def test_different_decision_different_key(self, executor, counting) -> None:
        d1 = _decision(decision_id=uuid.uuid4(), correlation_id=uuid.uuid4())
        d2 = _decision(decision_id=uuid.uuid4(), correlation_id=uuid.uuid4())
        executor.execute(_request(decision=d1), d1)
        executor.execute(_request(decision=d2), d2)
        assert counting.call_count == 2

    def test_failed_provider_is_idempotent(self) -> None:
        counting = CallCounting()
        failing = CallCounting()
        failing.raise_error = ResponseValidationError("provider exploded")
        executor = ResponseExecutor(
            registry=ResponseProviderRegistry((failing,)),
            clock=lambda: FIXED,
        )
        d = _decision(decision_id=uuid.uuid4(), correlation_id=uuid.uuid4())
        req = _request(decision=d)
        first = executor.execute(req, d)
        second = executor.execute(req, d)
        assert first.execution_status is ResponseExecutionStatus.FAILED
        assert first == second
        assert failing.call_count == 1
        assert executor.processed_count == 1

    def test_duplicate_returns_copy_not_shared_reference(self, executor, counting) -> None:
        d = _decision(decision_id=uuid.uuid4(), correlation_id=uuid.uuid4())
        req = _request(decision=d)
        first = executor.execute(req, d)
        second = executor.execute(req, d)
        assert first is not second
        first.metadata["tampered"] = True
        third = executor.execute(req, d)
        assert "tampered" not in third.metadata

    def test_capacity_exhaustion_fails_closed(self, monkeypatch) -> None:
        import app.services.response.executor as executor_module

        monkeypatch.setattr(
            executor_module, "RESPONSE_MAX_PROCESSED_KEYS", 1
        )
        counting = CallCounting()
        exec_ = ResponseExecutor(
            registry=ResponseProviderRegistry((counting,)),
            clock=lambda: FIXED,
        )
        d1 = _decision(decision_id=uuid.uuid4(), correlation_id=uuid.uuid4())
        exec_.execute(_request(decision=d1), d1)
        d2 = _decision(decision_id=uuid.uuid4(), correlation_id=uuid.uuid4())
        with pytest.raises(ResponseInternalError):
            exec_.execute(_request(decision=d2), d2)


# ---------------------------------------------------------------------------
# Failure semantics & unsupported actions
# ---------------------------------------------------------------------------


class TestFailureSemantics:
    def test_provider_response_provider_error_is_failed(self) -> None:
        counting = CallCounting()
        counting.raise_error = ResponseProviderError("down")
        executor = ResponseExecutor(
            registry=ResponseProviderRegistry((counting,)),
            clock=lambda: FIXED,
        )
        d = _decision(decision_id=uuid.uuid4(), correlation_id=uuid.uuid4())
        result = executor.execute(_request(decision=d), d)
        assert result.execution_status is ResponseExecutionStatus.FAILED
        assert result.error_code == "PROVIDER_ERROR"
        assert result.provider == "counting"
        assert "Simulated" not in result.message  # never fakes success

    def test_unexpected_provider_exception_is_failed_not_leaked(self) -> None:
        counting = CallCounting()
        counting.raise_error = RuntimeError("boom")
        executor = ResponseExecutor(
            registry=ResponseProviderRegistry((counting,)),
            clock=lambda: FIXED,
        )
        d = _decision(decision_id=uuid.uuid4(), correlation_id=uuid.uuid4())
        result = executor.execute(_request(decision=d), d)
        assert result.execution_status is ResponseExecutionStatus.FAILED
        assert result.error_code == "PROVIDER_FAILURE"
        assert "boom" not in result.message  # sanitized

    def test_unsupported_action_is_rejected(self) -> None:
        only_ip = CallCounting(actions=frozenset({ResponseActionType.BLOCK_IP}))
        executor = ResponseExecutor(
            registry=ResponseProviderRegistry((only_ip,)),
            clock=lambda: FIXED,
        )
        d = _decision(
            decision_id=uuid.uuid4(),
            correlation_id=uuid.uuid4(),
            action=ResponseActionType.ISOLATE_ENDPOINT,
        )
        result = executor.execute(
            _request(
                decision=d, action=ResponseActionType.ISOLATE_ENDPOINT, target="ep-1"
            ),
            d,
        )
        assert result.execution_status is ResponseExecutionStatus.REJECTED
        assert result.error_code == "PROVIDER_UNSUPPORTED"
        assert only_ip.call_count == 0

    def test_malformed_request_raises_validation_error(self, executor) -> None:
        d = _decision(decision_id=uuid.uuid4(), correlation_id=uuid.uuid4())
        with pytest.raises(ResponseValidationError):
            executor.execute({"response_id": uuid.uuid4()}, d)  # missing fields


# ---------------------------------------------------------------------------
# Determinism & immutability
# ---------------------------------------------------------------------------


class TestDeterminismAndImmutability:
    def test_same_request_same_clock_same_result(self) -> None:
        d = _decision(decision_id=uuid.uuid4(), correlation_id=uuid.uuid4())
        e1 = ResponseExecutor(
            registry=ResponseProviderRegistry((MOCK_PROVIDER,)),
            clock=lambda: FIXED,
        )
        e2 = ResponseExecutor(
            registry=ResponseProviderRegistry((MOCK_PROVIDER,)),
            clock=lambda: FIXED,
        )
        assert e1.execute(_request(decision=d), d) == e2.execute(_request(decision=d), d)

    def test_caller_request_and_decision_untouched(self, executor) -> None:
        d = _decision(decision_id=uuid.uuid4(), correlation_id=uuid.uuid4())
        req = _request(decision=d)
        meta = {"tags": ["alpha"]}
        req = req.model_copy(update={"metadata": meta})
        decision_before = d.model_dump()
        req_before = req.model_dump()
        executor.execute(req, d)
        assert d.model_dump() == decision_before
        assert req.model_dump() == req_before
        # Mutating the caller's metadata after the fact never leaks in.
        req.metadata["tags"].append("beta")
        assert d.model_dump() == decision_before

    def test_result_is_alias_free(self, executor, counting) -> None:
        d = _decision(decision_id=uuid.uuid4(), correlation_id=uuid.uuid4())
        req = _request(decision=d)
        result = executor.execute(req, d)
        assert result is not req
        result.metadata["mutated"] = True
        assert "mutated" not in req.metadata

    def test_rejected_result_is_provenance_pinned(self, executor) -> None:
        d = _decision(
            decision_id=uuid.uuid4(),
            correlation_id=uuid.uuid4(),
            status=PolicyDecisionStatus.DENIED,
        )
        result = executor.execute(_request(decision=d), d)
        assert result.provenance is Provenance.RESPONSE_EXECUTED
        assert result.execution_status is ResponseExecutionStatus.REJECTED