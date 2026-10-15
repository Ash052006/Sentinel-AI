"""Configured-provider resolution for the Step 12C Investigation Agent.

The Investigation Agent (12C) reasons only through the
:class:`~app.agents.investigation.llm_client.InvestigationLLMClient` seam.  By
default it constructs a :class:`~app.agents.investigation.gemini.GeminiClient`,
but the platform already supports a second, configurable reasoning provider
(Groq) selected once through ``Settings.llm_provider`` and used across the
reasoning subsystems.

This module is the **single place** an investigation provider is chosen,
mirroring :func:`app.agents.debate.runtime.build_debate_runtime`.  It reuses the
existing concrete clients verbatim — no second provider abstraction, no new
transport, no duplicated credential handling — so an operator who configures
``LLM_PROVIDER=groq`` gets Groq-backed investigations without any code change.

Design notes:

* **No hard-coded provider** — Gemini is the documented default only because
  ``Settings.llm_provider`` defaults to ``"gemini"``.  The factory never pins a
  provider of its own.
* **Closed mapping** — an unknown provider cannot degrade into a default; it
  raises.  Exactly one client is returned.
* **No fallback** — a configured provider's failure is surfaced as that
  provider's failure, never silently completed by a different backend.  The
  explanation service turns such a failure into a graceful, honest
  ``ai_unavailable`` degradation instead of a fabricated narrative.
* **Lazy credentials** — the client is built on demand, so importing this
  module (and wiring the service) never requires an API key.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from app.agents.investigation.agent import InvestigationAgent
from app.agents.investigation.gemini import GeminiClient
from app.agents.investigation.groq import GroqClient
from app.agents.investigation.llm_client import InvestigationLLMClient
from app.core.config import settings

#: Provider label -> concrete ``InvestigationLLMClient``.  A closed mapping:
#: an unknown provider is rejected rather than silently resolved.
_PROVIDER_CLIENTS: dict[str, type[InvestigationLLMClient]] = {
    "gemini": GeminiClient,
    "groq": GroqClient,
}


class InvestigationProviderConfigurationError(Exception):
    """Raised when the configured investigation provider cannot be resolved."""


def build_investigation_llm_client(
    provider: str | None = None,
) -> InvestigationLLMClient:
    """Return the single ``InvestigationLLMClient`` for *provider*.

    Args:
        provider: Explicit provider label; ``None`` reads
            ``Settings.llm_provider`` (the configured provider).

    Raises:
        InvestigationProviderConfigurationError: the provider is unknown.
        InvestigationConfigurationError: the selected provider is not
            configured (missing API key) — surfaced by the concrete client.
    """
    resolved = provider if provider is not None else settings.llm_provider
    normalized = (
        resolved.strip().lower() if isinstance(resolved, str) else resolved
    )
    try:
        client_class = _PROVIDER_CLIENTS[normalized]
    except (KeyError, TypeError) as exc:
        raise InvestigationProviderConfigurationError(
            f"unknown reasoning provider {resolved!r}; expected one of "
            f"{sorted(_PROVIDER_CLIENTS)}"
        ) from exc
    return client_class()


def build_investigation_agent(
    provider: str | None = None,
    **agent_kwargs: Any,
) -> InvestigationAgent:
    """Build an :class:`InvestigationAgent` bound to the configured provider.

    ``agent_kwargs`` (e.g. ``investigation_id_factory`` /
    ``result_timestamp_factory``) are forwarded to the agent so callers can
    keep builds deterministic.  An explicit ``llm_client`` in ``agent_kwargs``
    always wins (tests inject a scripted client).
    """
    if agent_kwargs.get("llm_client") is None:
        agent_kwargs["llm_client"] = build_investigation_llm_client(provider)
    return InvestigationAgent(**agent_kwargs)


#: Signature of the injectable agent factory used by the explanation service.
InvestigationAgentFactory = Callable[[], InvestigationAgent]


__all__ = [
    "InvestigationProviderConfigurationError",
    "build_investigation_llm_client",
    "build_investigation_agent",
    "InvestigationAgentFactory",
]
