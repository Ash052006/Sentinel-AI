"""ProviderRegistry — registry of threat-intelligence providers.

The registry manages a set of :class:`ThreatIntelProvider` instances
using dependency injection (providers are passed into the registry
explicitly) rather than global hidden state.  This keeps the registry
independently testable and free of network side-effects.

Responsibilities:
    * Register providers.
    * Retrieve a provider by name.
    * List all registered providers.
    * Find providers that support a given indicator type.
"""

from __future__ import annotations

from typing import Iterable

from app.services.threat_intelligence.base import ThreatIntelProvider
from app.services.threat_intelligence.exceptions import (
    DuplicateProviderError,
    ProviderNotFoundError,
)
from app.services.threat_intelligence.types import IndicatorType


class ProviderRegistry:
    """Stores and retrieves threat-intelligence providers by name.

    Providers are injected at construction time (or via ``register``)
    and live only for the lifetime of this registry instance.  No global
    state is used.
    """

    def __init__(
        self,
        providers: Iterable[ThreatIntelProvider] | None = None,
    ) -> None:
        self._providers: dict[str, ThreatIntelProvider] = {}
        if providers is not None:
            for provider in providers:
                self.register(provider)

    def register(self, provider: ThreatIntelProvider) -> None:
        """Register a provider, keyed by its ``provider_name``.

        Raises:
            DuplicateProviderError: If a provider with the same name is
                already registered.
        """
        if not isinstance(provider, ThreatIntelProvider):
            raise TypeError(
                "Expected ThreatIntelProvider, "
                f"got {type(provider).__name__}"
            )
        name = provider.provider_name
        if name in self._providers:
            raise DuplicateProviderError(name)
        self._providers[name] = provider

    def get(self, provider_name: str) -> ThreatIntelProvider:
        """Return the provider registered under *provider_name*.

        Raises:
            ProviderNotFoundError: If no provider with that name is
                registered.
        """
        try:
            return self._providers[provider_name]
        except KeyError:
            raise ProviderNotFoundError(provider_name) from None

    def get_or_none(self, provider_name: str) -> ThreatIntelProvider | None:
        """Return the provider or ``None`` if not registered.

        This is an alternative to :meth:`get` for callers that prefer
        ``None`` over an exception for unknown providers.
        """
        return self._providers.get(provider_name)

    def list_providers(self) -> list[ThreatIntelProvider]:
        """Return all registered providers (in registration order).

        The insertion order is preserved to give deterministic,
        reproducible enumeration.
        """
        return list(self._providers.values())

    def provider_names(self) -> list[str]:
        """Return the sorted names of all registered providers."""
        return sorted(self._providers.keys())

    def has_provider(self, provider_name: str) -> bool:
        """Return True if a provider with *provider_name* is registered."""
        return provider_name in self._providers

    def find_providers_for(
        self, indicator_type: IndicatorType,
    ) -> list[ThreatIntelProvider]:
        """Return all providers that support *indicator_type*.

        This is used by the future Threat Intelligence Agent to decide
        which providers can handle a given indicator.
        """
        return [
            p for p in self._providers.values()
            if p.supports(indicator_type)
        ]

    def count(self) -> int:
        """Return the number of registered providers."""
        return len(self._providers)
