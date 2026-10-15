"""Provider seam for the V3.23 debate agents.

The debate engine depends on :class:`DebateRuntime`, a one-method boundary that
returns the provider's **raw response text**.  Everything security-relevant
(secret scanning, strict parsing, output-contract validation, evidence
resolution) happens in the engine, so no provider quirk can bypass a
safeguard.

Two runtimes implement that one boundary — :class:`GeminiDebateRuntime` and
:class:`GroqDebateRuntime` — and neither owns transport, retry policy, timeout
handling, or credential handling.  Each merely wraps the repository's existing
provider client and tells it which structured-output schema to request for a
given round.  There is exactly one HTTP path per provider.

The engine cannot tell them apart: it depends only on the boundary.  Adding a
provider is therefore additive — no engine, prompt, evidence, persistence, or
API change.

Dependency injection is the point: tests supply a scripted runtime, so the
entire backend suite runs with no outbound network access and no provider key.

:func:`build_debate_runtime` is the single place a provider is chosen.  It
selects **exactly one** runtime from ``Settings.llm_provider`` and raises on an
unknown value.  It has no fallback branch by design: silently completing a
debate with a different model than the one recorded in its metadata would make
the result unreproducible and would attribute reasoning to a backend that never
contributed to it.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

from app.agents.debate.exceptions import (
    DebateConfigurationError,
    DebateProviderError,
)
from app.agents.debate.prompt import DebatePrompt
from app.agents.investigation.gemini import GeminiClient
from app.agents.investigation.groq import GroqClient
from app.agents.investigation.llm_client import InvestigationLLMClient
from app.core.config import settings

logger = logging.getLogger(__name__)


class DebateRuntime(ABC):
    """Abstract reasoning-provider boundary for debate agents."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Stable, non-secret provider identifier (e.g. ``"gemini"``)."""

    @property
    def model_name(self) -> str | None:
        """Configured model name when the provider exposes one (safe to log)."""
        return None

    @abstractmethod
    def complete(self, prompt: DebatePrompt, response_schema: dict[str, Any]) -> str:
        """Return the provider's raw response text for *prompt*.

        The caller strictly validates the returned text.  Implementations must
        not sanitize, repair, or interpret it.

        Raises:
            DebateProviderError: transport, timeout, or provider failure.
        """


class _SchemaBoundDebateRuntime(DebateRuntime):
    """Shared plumbing for runtimes that wrap an ``InvestigationLLMClient``.

    Both cloud providers expose the same ``generate(prompt) -> str`` contract
    and differ only in which client they construct, so the per-round schema
    rebinding, prompt-type guard, and error normalization live here once.  A
    subclass supplies the client class, the provider label, and the
    configuration error text.

    The client is created **lazily**, so constructing a runtime never requires
    an API key — which keeps module import and dependency wiring free of
    credentials.  The configured model name is still reported eagerly, because
    it is public metadata and is part of the debate's identity.
    """

    #: Concrete ``InvestigationLLMClient`` subclass to build per round.
    client_class: type
    #: Non-secret provider label reported to the engine.
    provider: str
    #: Settings attribute holding the configured model name.
    model_setting: str
    #: Operator-facing hint used when the provider is not configured.
    configuration_hint: str

    def __init__(self, llm_client: InvestigationLLMClient | None = None) -> None:
        self._client = llm_client
        if self._client is not None and not isinstance(
            self._client, InvestigationLLMClient
        ):
            raise DebateConfigurationError(
                "llm_client must implement InvestigationLLMClient; received "
                f"{type(self._client).__name__}"
            )
        self._configured_model: str | None = getattr(
            settings, self.model_setting, None
        ) or None

    @property
    def provider_name(self) -> str:
        return self.provider

    @property
    def model_name(self) -> str | None:
        """The model this debate will actually use.

        A lazily-created client has no resolved model yet, so the configured
        default is reported instead of ``None``.  That matters: the engine
        records this value in the debate metadata *and* folds it into the
        configuration digest, so reporting ``None`` would both hide the real
        backend from an auditor and let two differently-configured deployments
        resolve to one debate id.
        """
        if self._client is not None:
            return self._client.model_name
        return self._configured_model

    def _resolve_client(self, response_schema: dict[str, Any]) -> InvestigationLLMClient:
        """Return a client bound to *response_schema*.

        A caller-supplied client is used as-is (a test double owns its own
        schema handling).  The lazily-created default client is rebuilt per
        schema because the provider clients take the response schema at
        construction time.
        """
        if self._client is not None:
            return self._client
        try:
            return self.client_class(response_schema=response_schema)
        except Exception as exc:
            # The client raises InvestigationConfigurationError when no key is
            # configured (and, for Groq, when a response schema cannot be
            # translated faithfully).  Surfaced as a debate configuration
            # failure so the API reports an honest "provider not configured"
            # rather than a 500 or, worse, a fabricated debate.
            raise DebateConfigurationError(
                self.configuration_hint
            ) from exc

    def complete(self, prompt: DebatePrompt, response_schema: dict[str, Any]) -> str:
        if not isinstance(prompt, DebatePrompt):
            raise DebateConfigurationError(
                "DebateRuntime.complete requires a DebatePrompt; received "
                f"{type(prompt).__name__}"
            )
        client = self._resolve_client(response_schema)
        try:
            return client.generate(prompt)
        except DebateProviderError:
            raise
        except Exception as exc:
            # The client raises Investigation* errors, which are already
            # sanitized.  They are mapped onto the debate hierarchy so the
            # engine and API can classify them without importing the
            # investigation exception module into every layer.
            raise _map_provider_exception(exc) from exc


class GeminiDebateRuntime(_SchemaBoundDebateRuntime):
    """Runs the debate against the existing Gemini provider.

    Behaviour is unchanged from the original Gemini-only runtime; the shared
    base class exists so the Groq runtime behaves identically rather than
    reimplementing the seam.
    """

    client_class = GeminiClient
    provider = "gemini"
    model_setting = "gemini_model"
    configuration_hint = (
        "the Gemini debate runtime is not configured; set GEMINI_API_KEY or "
        "inject a runtime explicitly"
    )


class GroqDebateRuntime(_SchemaBoundDebateRuntime):
    """Runs the debate against Groq.

    Identical semantics to :class:`GeminiDebateRuntime`; only the underlying
    client differs.  In particular it does **not** fall back to Gemini: a Groq
    failure propagates as a governed debate failure.
    """

    client_class = GroqClient
    provider = "groq"
    model_setting = "groq_model"
    configuration_hint = (
        "the Groq debate runtime is not configured; set GROQ_API_KEY or "
        "inject a runtime explicitly"
    )


#: Provider label -> runtime.  A closed mapping, so an unknown provider cannot
#: be resolved by accident and cannot degrade into a default.
_DEBATE_RUNTIMES: dict[str, type[_SchemaBoundDebateRuntime]] = {
    GeminiDebateRuntime.provider: GeminiDebateRuntime,
    GroqDebateRuntime.provider: GroqDebateRuntime,
}


def build_debate_runtime(provider: str | None = None) -> DebateRuntime:
    """Return the single runtime for *provider* (default: configured one).

    This is the only place a debate's provider is chosen.  Exactly one provider
    is returned and it serves every model-backed round of that debate; there is
    no fallback path, here or anywhere else.

    Args:
        provider: Explicit provider label.  Only used by tests and callers that
            already resolved the setting; ``None`` reads
            ``Settings.llm_provider``.

    Raises:
        DebateConfigurationError: the provider is not in the closed set.
            ``Settings`` validates ``llm_provider`` too, but this keeps the
            runtime factory safe to call directly.
    """
    resolved = provider if provider is not None else settings.llm_provider
    normalized = resolved.strip().lower() if isinstance(resolved, str) else resolved
    try:
        runtime_class = _DEBATE_RUNTIMES[normalized]
    except (KeyError, TypeError) as exc:
        raise DebateConfigurationError(
            f"unknown reasoning provider {resolved!r}; expected one of "
            f"{sorted(_DEBATE_RUNTIMES)}"
        ) from exc
    logger.debug(
        "debate runtime selected: provider=%s", runtime_class.provider
    )
    return runtime_class()


def _map_provider_exception(exc: BaseException) -> DebateProviderError:
    """Map an existing investigation-provider error onto a debate error.

    Only the exception *type* is inspected — the message is never copied into
    the debate error, because the original may embed provider detail that the
    investigation layer already decided to sanitize.
    """
    name = type(exc).__name__
    if name == "InvestigationProviderTimeoutError":
        from app.agents.debate.exceptions import DebateProviderTimeoutError

        return DebateProviderTimeoutError(
            "the reasoning provider did not respond within the timeout"
        )
    if name in {
        "InvestigationProviderUnavailableError",
        "InvestigationConfigurationError",
    }:
        from app.agents.debate.exceptions import DebateProviderUnavailableError

        return DebateProviderUnavailableError(
            "the reasoning provider is unavailable or not configured"
        )
    if name.startswith("Investigation"):
        return DebateProviderError("the reasoning provider failed")
    return DebateProviderError("the reasoning provider failed")


__all__ = [
    "DebateRuntime",
    "GeminiDebateRuntime",
    "GroqDebateRuntime",
    "build_debate_runtime",
]