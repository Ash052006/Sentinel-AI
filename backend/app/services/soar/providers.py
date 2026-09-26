"""SOAR provider adapters (V2.18) — sandbox/mock only.

The adapter contract and the three registered sandbox providers:

* :class:`MockFirewallProvider`  — ``block_ip`` / ``block_domain``.
* :class:`MockEDRProvider`       — ``quarantine_file`` / ``terminate_session``
  / ``isolate_endpoint``.
* :class:`MockIdentityProvider`  — ``disable_account``.

Boundary (documented in ``docs/development/soar_v218.md``):

    V2.18 providers are **sandbox adapters**.  Nothing here touches a real
    firewall, EDR, identity store, host, network, filesystem or cloud.  A
    provider never accepts or interprets a command, script, path, URL,
    module or executable — it only coerces a closed operation + canonical
    target into a deterministic, recorded in-memory simulation.

Determinism & observability:

* Providers keep an in-memory ledger of simulated actions so tests and the
  E2E suite can prove "this step ran" vs "this step provably never ran"
  (e.g. a DENIED execution must leave the ledger empty).
* ``dry_run=True`` returns the *identical* deterministic result and NEVER
  mutates the ledger — a dry-run has zero side effects, even in memory.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.schemas.policy_decision import ResponseActionType
from app.schemas.soar import (
    SOAR_MAX_MESSAGE_LENGTH,
    SoarFailureCategory,
    SoarProviderType,
)


class SoarProviderError(Exception):
    """Raised by a provider for a categorized failure.

    ``category`` selects whether the engine may retry (only
    :data:`~app.schemas.soar.SOAR_RETRYABLE_CATEGORIES`) and is recorded on
    the step as a sanitized error code.
    """

    def __init__(
        self,
        message: str,
        *,
        category: SoarFailureCategory = SoarFailureCategory.PROVIDER_ERROR,
    ) -> None:
        super().__init__(message)
        self.message = message[:SOAR_MAX_MESSAGE_LENGTH]
        self.category = category


@dataclass(frozen=True)
class SoarProviderResult:
    """Deterministic outcome of one provider invocation."""

    ok: bool = True
    message: str | None = None
    error_code: str | None = None
    failure_category: SoarFailureCategory | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def with_metadata(self, **extra: Any) -> "SoarProviderResult":
        """A dependently-typed copy carrying provider observability."""
        return SoarProviderResult(
            ok=self.ok,
            message=self.message,
            error_code=self.error_code,
            failure_category=self.failure_category,
            metadata={**self.metadata, **extra},
        )


class SoarProvider(ABC):
    """Sandbox provider adapter contract.

    Subclasses declare a stable ``provider_id``, a closed
    ``provider_type`` and the closed operations they support, and implement
    :meth:`execute`.  Execution is deterministic, secret-free and
    side-effect-free under ``dry_run``.
    """

    provider_id: str
    provider_type: SoarProviderType
    supported_operations: frozenset[ResponseActionType]

    @abstractmethod
    def execute(
        self,
        *,
        operation: ResponseActionType,
        target: str,
        params: dict[str, Any],
        step_label: str,
        clock: Callable[[], datetime],
        dry_run: bool = False,
    ) -> SoarProviderResult:
        """Perform (or, under ``dry_run``, project) the closed operation
        against *target* with bounded *params*.

        Raises:
            SoarProviderError: categorized failure (only retryable
                categories may ever be retried by the engine).
        """

    def _guard_operation(
        self,
        operation: ResponseActionType,
    ) -> None:
        """Fail closed when the adapter does not support *operation* (never
        a dynamic dispatch, never a user-chosen callable)."""
        if operation not in self.supported_operations:
            raise SoarProviderError(
                f"provider '{self.provider_id}' does not support "
                f"operation '{operation.value}'",
                category=SoarFailureCategory.INVALID_INPUT,
            )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{type(self).__name__} {self.provider_id}>"


class MockFirewallProvider(SoarProvider):
    """Sandbox firewall adapter: simulated block_ip / block_domain."""

    provider_id = "firewall"
    provider_type = SoarProviderType.FIREWALL
    supported_operations = frozenset(
        {
            ResponseActionType.BLOCK_IP,
            ResponseActionType.BLOCK_DOMAIN,
        }
    )

    def __init__(self) -> None:
        self._blocked_ips: set[str] = set()
        self._blocked_domains: set[str] = set()
        self._attempts: dict[tuple[str, str], int] = {}

    @property
    def blocked_ips(self) -> set[str]:
        return set(self._blocked_ips)

    @property
    def blocked_domains(self) -> set[str]:
        return set(self._blocked_domains)

    @property
    def attempt_count(self) -> int:
        return sum(self._attempts.values())

    def execute(
        self,
        *,
        operation: ResponseActionType,
        target: str,
        params: dict[str, Any],
        step_label: str,
        clock: Callable[[], datetime],
        dry_run: bool = False,
    ) -> SoarProviderResult:
        del clock, step_label
        self._guard_operation(operation)
        if operation is ResponseActionType.BLOCK_IP:
            if not dry_run:
                self._blocked_ips.add(target)
                self._attempts[("block_ip", target)] = (
                    self._attempts.get(("block_ip", target), 0) + 1
                )
            return SoarProviderResult(
                message=f"simulated block_ip for {target} via firewall (sandbox)",
                metadata={"sandbox": True, "simulated": True, "kind": "ip_rule"},
            ).with_metadata(attempts=sum(self._attempts.values()) if not dry_run else 0)
        if not dry_run:
            self._blocked_domains.add(target)
            self._attempts[("block_domain", target)] = (
                self._attempts.get(("block_domain", target), 0) + 1
            )
        return SoarProviderResult(
            message=f"simulated block_domain for {target} via firewall (sandbox)",
            metadata={"sandbox": True, "simulated": True, "kind": "domain_rule"},
        ).with_metadata(attempts=sum(self._attempts.values()) if not dry_run else 0)


class MockEDRProvider(SoarProvider):
    """Sandbox EDR adapter: simulated quarantine / session / isolation."""

    provider_id = "edr"
    provider_type = SoarProviderType.EDR
    supported_operations = frozenset(
        {
            ResponseActionType.QUARANTINE_FILE,
            ResponseActionType.TERMINATE_SESSION,
            ResponseActionType.ISOLATE_ENDPOINT,
        }
    )

    def __init__(self) -> None:
        self._quarantined_files: set[str] = set()
        self._terminated_sessions: set[str] = set()
        self._isolated_endpoints: set[str] = set()
        self._attempt_count = 0

    @property
    def attempt_count(self) -> int:
        return self._attempt_count

    @property
    def quarantined_files(self) -> set[str]:
        return set(self._quarantined_files)

    @property
    def terminated_sessions(self) -> set[str]:
        return set(self._terminated_sessions)

    @property
    def isolated_endpoints(self) -> set[str]:
        return set(self._isolated_endpoints)

    def execute(
        self,
        *,
        operation: ResponseActionType,
        target: str,
        params: dict[str, Any],
        step_label: str,
        clock: Callable[[], datetime],
        dry_run: bool = False,
    ) -> SoarProviderResult:
        del clock, step_label, params
        self._guard_operation(operation)
        if operation is ResponseActionType.QUARANTINE_FILE:
            if not dry_run:
                self._quarantined_files.add(target)
                self._attempt_count += 1
            return SoarProviderResult(
                message=f"simulated quarantine_file for {target} via EDR (sandbox)",
                metadata={"sandbox": True, "simulated": True, "kind": "quarantine"},
            )
        if operation is ResponseActionType.TERMINATE_SESSION:
            if not dry_run:
                self._terminated_sessions.add(target)
                self._attempt_count += 1
            return SoarProviderResult(
                message=f"simulated terminate_session for {target} via EDR (sandbox)",
                metadata={"sandbox": True, "simulated": True, "kind": "session"},
            )
        # ISOLATE_ENDPOINT
        if not dry_run:
            self._isolated_endpoints.add(target)
            self._attempt_count += 1
        return SoarProviderResult(
            message=f"simulated isolate_endpoint for {target} via EDR (sandbox)",
            metadata={"sandbox": True, "simulated": True, "kind": "endpoint"},
        )


class MockIdentityProvider(SoarProvider):
    """Sandbox identity adapter: simulated disable_account."""

    provider_id = "identity"
    provider_type = SoarProviderType.IDENTITY
    supported_operations = frozenset(
        {
            ResponseActionType.DISABLE_ACCOUNT,
        }
    )

    def __init__(self) -> None:
        self._disabled_accounts: set[str] = set()
        self._attempt_count = 0

    @property
    def attempt_count(self) -> int:
        return self._attempt_count

    @property
    def disabled_accounts(self) -> set[str]:
        return set(self._disabled_accounts)

    def execute(
        self,
        *,
        operation: ResponseActionType,
        target: str,
        params: dict[str, Any],
        step_label: str,
        clock: Callable[[], datetime],
        dry_run: bool = False,
    ) -> SoarProviderResult:
        del clock, step_label, params
        self._guard_operation(operation)
        if not dry_run:
            self._disabled_accounts.add(target)
            self._attempt_count += 1
        return SoarProviderResult(
            message=f"simulated disable_account for {target} via identity (sandbox)",
            metadata={"sandbox": True, "simulated": True, "kind": "account"},
        )


#: Convenience factory of the three registered sandbox providers.
def default_providers() -> list[SoarProvider]:
    return [
        MockFirewallProvider(),
        MockEDRProvider(),
        MockIdentityProvider(),
    ]


__all__ = [
    "MockEDRProvider",
    "MockFirewallProvider",
    "MockIdentityProvider",
    "SoarProvider",
    "SoarProviderError",
    "SoarProviderResult",
    "default_providers",
]