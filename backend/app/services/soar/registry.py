"""SOAR provider registry (V2.18).

A closed, immutable-at-runtime registry of the registered sandbox
provider adapters.  Registration rejects duplicate ids and unsupported
adapter types; lookups are by fixed identifier and never dynamic.

The registry is the **only** source of provider resolution for the engine
— there is no user-controlled provider name, import, URL or callable path
anywhere in the execution path.
"""

from __future__ import annotations

from app.schemas.policy_decision import ResponseActionType
from app.schemas.soar import SoarProviderType
from app.services.soar.errors import SoarValidationError
from app.services.soar.providers import (
    MockEDRProvider,
    MockFirewallProvider,
    MockIdentityProvider,
    SoarProvider,
    default_providers,
)


class SoarProviderRegistry:
    """Closed registry of registered provider adapters."""

    def __init__(self, providers: list[SoarProvider] | None = None) -> None:
        self._providers: dict[str, SoarProvider] = {}
        self._register_many(providers if providers is not None else default_providers())

    def _register_many(self, providers: list[SoarProvider]) -> None:
        for provider in providers:
            self._register(provider)

    def _register(self, provider: SoarProvider) -> None:
        provider_id = provider.provider_id
        if not provider_id or provider_id in self._providers:
            raise SoarValidationError(
                f"provider id {provider_id!r} is missing or already registered"
            )
        try:
            provider_type = SoarProviderType(provider.provider_type)
        except (ValueError, TypeError) as exc:
            raise SoarValidationError(
                "provider type is not part of the closed SOAR vocabulary"
            ) from exc
        if not isinstance(provider.supported_operations, frozenset) or not provider.supported_operations:
            raise SoarValidationError(
                "a provider must declare a non-empty closed operation set"
            )
        for operation in provider.supported_operations:
            if not isinstance(operation, ResponseActionType):
                raise SoarValidationError(
                    "provider operations must be ResponseActionType values"
                )
        self._providers[provider_id] = provider

    def provider_for(self, provider_id: str) -> SoarProvider:
        """Resolve a registered provider by id.

        Raises:
            SoarValidationError: unknown provider id (fail closed — no
                dynamic resolution, no fallback provider).
        """
        provider = self._providers.get(provider_id)
        if provider is None:
            raise SoarValidationError(
                f"no registered provider for id '{provider_id}'"
            )
        return provider

    def providers_for_operation(self, operation: ResponseActionType) -> list[SoarProvider]:
        """Registered providers supporting *operation*, in registration order."""
        return [
            provider
            for provider in self._providers.values()
            if operation in provider.supported_operations
        ]

    def ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._providers))

    def __contains__(self, provider_id: str) -> bool:
        return provider_id in self._providers


def default_provider_registry() -> SoarProviderRegistry:
    """The canonical registry (firewall, edr, identity sandbox adapters)."""
    return SoarProviderRegistry(
        [
            MockFirewallProvider(),
            MockEDRProvider(),
            MockIdentityProvider(),
        ]
    )


DEFAULT_SOAR_PROVIDER_REGISTRY = default_provider_registry()

__all__ = [
    "DEFAULT_SOAR_PROVIDER_REGISTRY",
    "SoarProviderRegistry",
    "default_provider_registry",
]