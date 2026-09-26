"""Response provider & registry tests (Step 25).

* the provider abstraction returns structured, deterministic results and
  never touches host/shell/network/filesystem;
* ``MockResponseProvider`` covers all six actions and simulates instantly;
* the registry is an immutable, deterministic action->provider map that
  rejects duplicate/conflicting registrations and unknown provider names;
* default registry covers every closed action exactly once.

Everything here is off-host: no subprocess, no OS mutation, no network.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from app.schemas.policy_decision import ResponseActionType
from app.schemas.response import (
    ResponseExecutionStatus,
    ResponseRequest,
    ResponseResult,
)
from app.schemas.security_event import Provenance
from app.services.response.errors import ResponseValidationError
from app.services.response.providers import MOCK_PROVIDER, MockResponseProvider, ResponseProvider
from app.services.response.registry import (
    DEFAULT_RESPONSE_REGISTRY,
    ResponseProviderRegistry,
)
from app.services.response.validator import derive_response_id

TZ = timezone.utc
FIXED = datetime(2025, 8, 1, 10, 30, 0, tzinfo=TZ)
DECISION_ID = uuid.uuid4()
CORR_ID = uuid.uuid4()


def _request(action: ResponseActionType, target: str) -> ResponseRequest:
    return ResponseRequest(
        response_id=derive_response_id(
            policy_decision_id=DECISION_ID, action=action, target=target
        ),
        policy_decision_id=DECISION_ID,
        correlation_id=CORR_ID,
        action_type=action,
        target=target,
        requested_at=FIXED,
    )


class CallCountingProvider(ResponseProvider):
    """Deterministic provider that records how many times execute ran."""

    name = "counting"
    supported_actions = frozenset(ResponseActionType)

    def __init__(self) -> None:
        self.call_count = 0

    def execute(self, request: ResponseRequest, *, clock=None) -> ResponseResult:
        self.call_count += 1
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


# ---------------------------------------------------------------------------
# Provider contract
# ---------------------------------------------------------------------------


class TestResponseProviderContract:
    def test_provider_is_abstract(self) -> None:
        with pytest.raises(TypeError):
            ResponseProvider()  # type: ignore[abstract]

    def test_mock_is_a_provider(self) -> None:
        assert isinstance(MOCK_PROVIDER, ResponseProvider)
        assert MOCK_PROVIDER.name == "mock"

    def test_mock_simulates_all_six_actions(self) -> None:
        assert MOCK_PROVIDER.supported_actions == frozenset(ResponseActionType)
        assert len(MOCK_PROVIDER.supported_actions) == 6

    @pytest.mark.parametrize(
        ("action", "target"),
        [
            (ResponseActionType.BLOCK_IP, "10.0.0.1"),
            (ResponseActionType.BLOCK_DOMAIN, "evil.example.com"),
            (ResponseActionType.QUARANTINE_FILE, "tmp/eicar.txt"),
            (ResponseActionType.DISABLE_ACCOUNT, "alice@corp"),
            (ResponseActionType.TERMINATE_SESSION, "sess-001"),
            (ResponseActionType.ISOLATE_ENDPOINT, "endpoint-42"),
        ],
    )
    def test_mock_returns_executed_result(
        self, action: ResponseActionType, target: str
    ) -> None:
        req = _request(action, target)
        result = MOCK_PROVIDER.execute(req, clock=lambda: FIXED)
        assert isinstance(result, ResponseResult)
        assert result.execution_status is ResponseExecutionStatus.EXECUTED
        assert result.provenance is Provenance.RESPONSE_EXECUTED
        assert result.provider == "mock"
        assert result.response_id == req.response_id
        assert result.target == target
        assert result.started_at == FIXED
        assert result.completed_at == FIXED
        assert result.error_code is None
        assert "Simulated" in result.message

    def test_mock_provider_is_deterministic(self) -> None:
        req = _request(ResponseActionType.BLOCK_IP, "10.0.0.1")
        a = MOCK_PROVIDER.execute(req, clock=lambda: FIXED)
        b = MOCK_PROVIDER.execute(req, clock=lambda: FIXED)
        assert a == b

    def test_mock_provider_is_stateless(self) -> None:
        req = _request(ResponseActionType.BLOCK_IP, "10.0.0.1")
        before = MOCK_PROVIDER.execute(req, clock=lambda: FIXED)
        for _ in range(3):
            MOCK_PROVIDER.execute(req, clock=lambda: FIXED)
        after = MOCK_PROVIDER.execute(req, clock=lambda: FIXED)
        assert before == after

    def test_mock_provider_rejects_naive_clock(self) -> None:
        from app.services.response.errors import ResponseProviderError

        req = _request(ResponseActionType.BLOCK_IP, "10.0.0.1")
        with pytest.raises(ResponseProviderError):
            MOCK_PROVIDER.execute(req, clock=lambda: datetime.now())  # naive


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class TestResponseRegistry:
    def test_default_covers_all_six_actions_once(self) -> None:
        assert set(DEFAULT_RESPONSE_REGISTRY.actions) == set(ResponseActionType)
        assert len(DEFAULT_RESPONSE_REGISTRY.actions) == 6
        assert len(DEFAULT_RESPONSE_REGISTRY.providers) == 1

    def test_default_lookup_is_mock_for_every_action(self) -> None:
        for action in ResponseActionType:
            assert DEFAULT_RESPONSE_REGISTRY.provider_for(action) is MOCK_PROVIDER

    def test_actions_are_sorted_deterministically(self) -> None:
        values = [a.value for a in DEFAULT_RESPONSE_REGISTRY.actions]
        assert values == sorted(values)

    def test_get_by_name(self) -> None:
        assert DEFAULT_RESPONSE_REGISTRY.get("mock") is MOCK_PROVIDER
        assert DEFAULT_RESPONSE_REGISTRY.get("nope") is None

    def test_duplicate_registration_rejected(self) -> None:
        with pytest.raises(ResponseValidationError):
            ResponseProviderRegistry((MOCK_PROVIDER, MOCK_PROVIDER))

    def test_conflicting_providers_for_same_action_rejected(self) -> None:
        class Other(ResponseProvider):
            name = "other"
            supported_actions = frozenset({ResponseActionType.BLOCK_IP})

            def execute(self, request, *, clock=None):
                raise AssertionError("unreachable")

        with pytest.raises(ResponseValidationError):
            ResponseProviderRegistry(
                (MOCK_PROVIDER, Other()),
            )

    def test_duplicate_provider_name_rejected(self) -> None:
        class Twin(MockResponseProvider):
            pass

        with pytest.raises(ResponseValidationError):
            ResponseProviderRegistry((MOCK_PROVIDER, Twin()))

    def test_blank_name_rejected(self) -> None:
        class Blank(ResponseProvider):
            name = ""
            supported_actions = frozenset({ResponseActionType.BLOCK_IP})

            def execute(self, request, *, clock=None):
                raise AssertionError("unreachable")

        with pytest.raises(ResponseValidationError):
            ResponseProviderRegistry((Blank(),))

    def test_non_provider_rejected(self) -> None:
        with pytest.raises(ResponseValidationError):
            ResponseProviderRegistry((object(),))  # type: ignore[arg-type]

    def test_provider_for_unsupported_action_rejected(self) -> None:
        class OnlyIp(ResponseProvider):
            name = "only_ip"
            supported_actions = frozenset({ResponseActionType.BLOCK_IP})

            def execute(self, request, *, clock=None):
                raise AssertionError("unreachable")

        registry = ResponseProviderRegistry((OnlyIp(),))
        assert registry.provider_for(ResponseActionType.BLOCK_IP).name == "only_ip"
        with pytest.raises(ResponseValidationError):
            registry.provider_for(ResponseActionType.ISOLATE_ENDPOINT)

    def test_registry_is_read_only_view(self) -> None:
        view = DEFAULT_RESPONSE_REGISTRY.providers
        assert isinstance(view, tuple)
        assert view[0] is MOCK_PROVIDER
        assert DEFAULT_RESPONSE_REGISTRY.get("mock") is MOCK_PROVIDER
        assert DEFAULT_RESPONSE_REGISTRY.provider_for(
            ResponseActionType.BLOCK_DOMAIN
        ) is MOCK_PROVIDER

    def test_isolated_registry_does_not_share_state(self) -> None:
        counting = CallCountingProvider()
        registry = ResponseProviderRegistry((counting,))
        provider = registry.provider_for(ResponseActionType.BLOCK_IP)
        req = _request(ResponseActionType.BLOCK_IP, "10.0.0.1")
        provider.execute(req, clock=lambda: FIXED)
        assert counting.call_count == 1
        # Default registry unaffected and still covers everything.
        assert DEFAULT_RESPONSE_REGISTRY.provider_for(ResponseActionType.BLOCK_IP) is MOCK_PROVIDER