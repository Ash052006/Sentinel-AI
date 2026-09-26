"""SOAR provider adapter tests (V2.18) — sandbox/mock only.

The providers are deterministic in-memory simulations.  These tests pin:
* the closed operation surface of each registered adapter;
* the observability ledger (prove a step ran, or provably never ran);
* dry-run purity (identical result, zero ledger mutation);
* fail-closed on unsupported operations.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.schemas.policy_decision import ResponseActionType
from app.schemas.soar import SoarFailureCategory, SoarProviderType
from app.services.soar import (
    DEFAULT_SOAR_PROVIDER_REGISTRY,
    MockEDRProvider,
    MockFirewallProvider,
    MockIdentityProvider,
    SoarProviderError,
    SoarProviderResult,
    SoarValidationError,
)

TZ = timezone.utc
NOW = datetime(2026, 9, 24, 8, 0, 0, tzinfo=TZ)

CLOCK = lambda: NOW  # noqa: E731


class TestClosedVocabulary:
    def test_default_registry_resolves_all_sandbox_adapters(self) -> None:
        registry = DEFAULT_SOAR_PROVIDER_REGISTRY
        assert registry.ids() == ("edr", "firewall", "identity")
        assert isinstance(registry.provider_for("firewall"), MockFirewallProvider)
        assert isinstance(registry.provider_for("edr"), MockEDRProvider)
        assert isinstance(registry.provider_for("identity"), MockIdentityProvider)

    def test_unknown_provider_fails_closed(self) -> None:
        with pytest.raises(SoarValidationError, match="no registered provider"):
            DEFAULT_SOAR_PROVIDER_REGISTRY.provider_for("powershell_bridge")

    def test_operation_to_provider_mapping(self) -> None:
        registry = DEFAULT_SOAR_PROVIDER_REGISTRY
        firewall = registry.provider_for("firewall")
        edr = registry.provider_for("edr")
        identity = registry.provider_for("identity")
        assert firewall.provider_type is SoarProviderType.FIREWALL
        assert {ResponseActionType.BLOCK_IP, ResponseActionType.BLOCK_DOMAIN} == set(
            firewall.supported_operations
        )
        assert {
            ResponseActionType.QUARANTINE_FILE,
            ResponseActionType.TERMINATE_SESSION,
            ResponseActionType.ISOLATE_ENDPOINT,
        } == set(edr.supported_operations)
        assert {ResponseActionType.DISABLE_ACCOUNT} == set(
            identity.supported_operations
        )


class TestFirewall:
    def test_block_ip_executes_and_is_observable(self) -> None:
        firewall = MockFirewallProvider()
        result = firewall.execute(
            operation=ResponseActionType.BLOCK_IP,
            target="203.0.113.9",
            params={},
            step_label="Block source IP",
            clock=CLOCK,
        )
        assert isinstance(result, SoarProviderResult)
        assert result.ok
        assert result.message and "203.0.113.9" in result.message
        assert result.metadata.get("sandbox") is True
        assert "203.0.113.9" in firewall.blocked_ips
        assert firewall.attempt_count == 1

    def test_dry_run_never_mutates_the_ledger(self) -> None:
        firewall = MockFirewallProvider()
        result = firewall.execute(
            operation=ResponseActionType.BLOCK_DOMAIN,
            target="evil.example.com",
            params={},
            step_label="Block domain",
            clock=CLOCK,
            dry_run=True,
        )
        assert result.ok
        assert firewall.blocked_domains == set()
        assert firewall.attempt_count == 0


class TestEdrAndIdentity:
    def test_isolate_endpoint(self) -> None:
        edr = MockEDRProvider()
        result = edr.execute(
            operation=ResponseActionType.ISOLATE_ENDPOINT,
            target="host-7f3a",
            params={},
            step_label="Isolate endpoint",
            clock=CLOCK,
        )
        assert result.ok
        assert "host-7f3a" in edr.isolated_endpoints

    def test_disable_account(self) -> None:
        identity = MockIdentityProvider()
        result = identity.execute(
            operation=ResponseActionType.DISABLE_ACCOUNT,
            target="alice@sentinel.local",
            params={},
            step_label="Disable account",
            clock=CLOCK,
        )
        assert result.ok
        assert "alice@sentinel.local" in identity.disabled_accounts


class TestFailClosed:
    def test_unsupported_operation_rejected(self) -> None:
        firewall = MockFirewallProvider()
        with pytest.raises(SoarProviderError) as excinfo:
            firewall.execute(
                operation=ResponseActionType.ISOLATE_ENDPOINT,
                target="host-x",
                params={},
                step_label="bad",
                clock=CLOCK,
            )
        assert excinfo.value.category is SoarFailureCategory.INVALID_INPUT

    def test_unsupported_operation_mutates_nothing(self) -> None:
        firewall = MockFirewallProvider()
        with pytest.raises(SoarProviderError):
            firewall.execute(
                operation=ResponseActionType.DISABLE_ACCOUNT,
                target="alice@corp",
                params={},
                step_label="bad",
                clock=CLOCK,
            )
        assert firewall.blocked_ips == set()
        assert firewall.blocked_domains == set()
        assert firewall.attempt_count == 0