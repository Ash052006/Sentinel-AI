"""Deterministic response provider registry (Step 25).

Maps the closed :class:`ResponseActionType` vocabulary to the providers
that realize each action.  Properties:

* **Explicit action → provider mapping** — each provider declares its
  ``supported_actions``; the registry builds one account per action.
* **Duplicate registration rejected** — two providers claiming the same
  action is a configuration error.
* **Deterministic lookup** — plain dict keyed by the enum member; no
  string-derived dispatch, no ``getattr``, no dynamic imports.
* **Unsupported action rejected** at construction or lookup with a
  sanitized error.
* **Immutable snapshot** — the registry only exposes read surfaces after
  construction (providers are stateless and reusable).
"""

from __future__ import annotations

from collections.abc import Iterable

from app.schemas.policy_decision import ResponseActionType
from app.services.response.errors import ResponseValidationError
from app.services.response.providers import MOCK_PROVIDER, ResponseProvider


class ResponseProviderRegistry:
    """Immutable, deterministic action → provider mapping."""

    def __init__(self, providers: Iterable[ResponseProvider] = ()) -> None:
        snapshot = tuple(providers)
        seen_actions: dict[ResponseActionType, str] = {}
        provider_names: set[str] = set()
        for provider in snapshot:
            if not isinstance(provider, ResponseProvider):
                raise ResponseValidationError(
                    "response providers must be ResponseProvider instances"
                )
            if not provider.name or not provider.name.strip():
                raise ResponseValidationError(
                    "response providers must declare a stable name"
                )
            if provider.name in provider_names:
                raise ResponseValidationError(
                    f"duplicate response provider name {provider.name!r} "
                    "(conflicting provider configuration)"
                )
            provider_names.add(provider.name)
            for action in provider.supported_actions:
                if not isinstance(action, ResponseActionType):
                    raise ResponseValidationError(
                        "provider supported_actions must be ResponseActionType "
                        "members"
                    )
                if action in seen_actions:
                    raise ResponseValidationError(
                        f"duplicate registration of {action.value!r} by "
                        f"{provider.name!r} and {seen_actions[action]!r} "
                        "(conflicting provider configuration)"
                    )
                seen_actions[action] = provider.name

        self._providers: tuple[ResponseProvider, ...] = snapshot
        #: Deterministic enumeration order for auditability.
        self._actions: tuple[ResponseActionType, ...] = tuple(
            sorted(seen_actions, key=lambda a: a.value)
        )
        self._by_action: dict[ResponseActionType, ResponseProvider] = {
            action: next(
                p for p in snapshot if action in p.supported_actions
            )
            for action in self._actions
        }
        self._by_name: dict[str, ResponseProvider] = {
            provider.name: provider for provider in snapshot
        }

    @property
    def providers(self) -> tuple[ResponseProvider, ...]:
        """Read-only view of the registered providers."""
        return self._providers

    @property
    def actions(self) -> tuple[ResponseActionType, ...]:
        """All covered actions in deterministic order."""
        return self._actions

    def get(self, name: str) -> ResponseProvider | None:
        """Return the provider registered under *name* (stable id), or None."""
        return self._by_name.get(name)

    def provider_for(self, action: ResponseActionType) -> ResponseProvider:
        """Deterministic lookup for *action*.

        Raises:
            ResponseValidationError: unsupported action (sanitized).
        """
        provider = self._by_action.get(action)
        if provider is None:
            raise ResponseValidationError(
                "no response provider is registered for the requested action"
            )
        return provider

    def __len__(self) -> int:
        return len(self._providers)


def _default_registry() -> ResponseProviderRegistry:
    return ResponseProviderRegistry((MOCK_PROVIDER,))


#: Canonical default registry: MockResponseProvider for all six actions.
DEFAULT_RESPONSE_REGISTRY: ResponseProviderRegistry = _default_registry()


__all__ = [
    "DEFAULT_RESPONSE_REGISTRY",
    "ResponseProviderRegistry",
]