"""LLM provider boundary for the Step 12C Investigation Agent.

``InvestigationLLMClient`` is the small provider-agnostic seam that makes
:class:`~app.agents.investigation.agent.InvestigationAgent` testable without
real Gemini calls: the agent depends on this abstraction and never on a
concrete provider implementation.  A future provider (e.g. Ollama) can be
added later by implementing the same interface without rewriting the agent.

The boundary returns the **raw response text** only.  Strict validation of
that text (JSON parsing, output-contract validation, evidence-reference
resolution, provenance, secret scanning) is the agent's responsibility, so
no provider-specific quirk can bypass agent-level safeguards.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from app.agents.investigation.prompt import InvestigationPrompt


class InvestigationLLMClient(ABC):
    """Abstract provider interface for investigation LLM calls."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Stable, non-secret provider identifier (e.g. ``"gemini"``)."""

    @property
    def model_name(self) -> str | None:
        """Configured model name, when the provider exposes one (safe to log)."""
        return None

    @abstractmethod
    def generate(self, prompt: InvestigationPrompt) -> str:
        """Send *prompt* to the provider and return its raw response text.

        Raises:
            InvestigationConfigurationError: provider not configured.
            InvestigationProviderError / investigation subclasses:
                transport, timeout, unavailable, or authentication failures
                (sanitized messages, causes chained).
            InvestigationModelOutputError: the provider reported that the
                completion did not end with a clean ``STOP`` (truncation,
                blocked content).
        """