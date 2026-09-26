"""Gemini provider for the V2.20 AI Incident Report Generator.

A concrete subclass of the Step 12C :class:`GeminiClient` that reuses the
existing transport unchanged (headers, endpoint, bounded retry, finish-reason
rejection, sanitized errors) and only changes two things:

* the structured-output ``responseSchema`` is the incident-report model
  schema (``INCIDENT_REPORT_MODEL_JSON_SCHEMA``) instead of the investigation
  schema;
* ``generate`` accepts an :class:`IncidentReportPrompt` and unwraps the shared
  :class:`InvestigationPrompt` the base transport understands.

A successful provider response is **never** assumed valid: the provider only
extracts raw text; strict contract validation and evidence-citation
resolution happen in the generator (``generator.py``).  The API key is sent
only as the ``x-goog-api-key`` header and never appears in logs, payloads or
exceptions.
"""

from __future__ import annotations

from typing import Any

import httpx

from app.agents.investigation.exceptions import (
    InvestigationConfigurationError,
)
from app.agents.investigation.gemini import GeminiClient
from app.agents.investigation.prompt import InvestigationPrompt
from app.services.reporting.model_output import INCIDENT_REPORT_MODEL_JSON_SCHEMA
from app.services.reporting.prompt import IncidentReportPrompt


class IncidentReportGeminiClient(GeminiClient):
    """Gemini ``generateContent`` structured-output provider for incident reports.

    Construction, endpoint addressing, headers, retry policy and response
    handling are inherited from :class:`GeminiClient`.  Only the output schema
    and the prompt type differ.

    Parameters mirror :class:`GeminiClient` exactly (see its docstring); the
    report generator resolves defaults from :mod:`app.core.config.settings`.
    """

    # -- Payload composition ------------------------------------------------

    def _build_payload(self, prompt: InvestigationPrompt) -> dict[str, Any]:
        """Compose the generateContent payload for the incident-report schema."""
        parts: list[dict[str, str]] = [{"text": prompt.content}]
        if prompt.historical_memory_content:
            # Historical incident memory stays a separate, clearly-labelled
            # part (reference-only section), mirroring the investigation agent.
            parts.append({"text": prompt.historical_memory_content})
        if prompt.knowledge_content:
            parts.append({"text": prompt.knowledge_content})
        return {
            "systemInstruction": {
                "parts": [{"text": prompt.system_instruction}]
            },
            "contents": [{"role": "user", "parts": parts}],
            "generationConfig": {
                "temperature": self._temperature,
                "maxOutputTokens": self._max_output_tokens,
                "responseMimeType": "application/json",
                "responseSchema": INCIDENT_REPORT_MODEL_JSON_SCHEMA,
            },
        }

    # -- Public interface ----------------------------------------------------

    def generate(self, prompt: IncidentReportPrompt) -> str:
        """Send the report prompt and return the raw structured output text.

        Unwraps :attr:`IncidentReportPrompt.prompt` so the inherited
        ``InvestigationPrompt`` transport and retry/error handling are reused.
        """
        if not isinstance(prompt, IncidentReportPrompt):
            raise TypeError(
                "IncidentReportGeminiClient.generate requires an "
                f"IncidentReportPrompt; received {type(prompt).__name__}"
            )
        return super().generate(prompt.prompt)


def default_report_llm(**kwargs: Any) -> IncidentReportGeminiClient:
    """Build the default configured report LLM client.

    Accepts the same keyword overrides as :class:`GeminiClient` (e.g. an
    injectable ``httpx.Client`` or ``sleep`` for tests).  Configuration
    failures (missing API key / model) raise
    :class:`InvestigationConfigurationError`, exactly like the investigation
    agent.
    """
    return IncidentReportGeminiClient(**kwargs)


__all__ = ["IncidentReportGeminiClient", "default_report_llm"]