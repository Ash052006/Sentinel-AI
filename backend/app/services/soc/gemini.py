"""Gemini adapter for the Natural Language SOC intent parser — Step 23.

A concrete :class:`~app.services.soc.parser.SOCIntentParser` that talks to
the Google Gemini ``generateContent`` REST API over the repository's
existing ``httpx`` dependency, mirroring the Step 12C investigation
provider's conventions: injectable ``httpx.Client`` for tests, bounded
timeout, bounded retry for transient failures only, sanitized exceptions,
and the API key carried in the ``x-goog-api-key`` header (never in the URL,
logs, exceptions, or messages).

Structured output is requested via ``responseMimeType: application/json``
plus the SOC candidate-intent ``responseSchema``.  A successful HTTP
response is **never** assumed valid: the adapter only extracts the raw text
and returns it inside a :class:`~app.services.soc.parser.SOCParseResult`;
the deterministic strict parse + Pydantic contract validation always happen
outside the model, in :func:`~app.services.soc.parser.build_candidate`.

Security properties:

* The provider never accesses databases, tools, or the filesystem.
* The prompt is built from the fixed SOC system instruction plus the user
  query inside a clearly delimited ``<user_data>`` region.
* Logs contain only provider/model identifiers, retry counts, and
  sanitized failure classes — never raw prompts, raw user queries, or raw
  provider responses.
* Exceptions carry sanitized messages; causes are chained internally.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable

import httpx

from app.core.config import settings
from app.schemas.soc_query import (
    SOC_INTENT_MODEL_JSON_SCHEMA,
    SOC_MAX_QUERY_LENGTH,
)
from app.services.soc.errors import (
    SOCConfigurationError,
    SOCInputValidationError,
    SOCProviderError,
    SOCProviderTimeoutError,
    SOCProviderUnavailableError,
)
from app.services.soc.parser import SOCIntentParser, SOCParseResult
from app.services.soc.prompt import SOCPrompt, SOCPromptBuilder

logger = logging.getLogger(__name__)

#: Backoff base for transient retries (seconds), multiplicative per attempt.
_RETRY_BASE_DELAY = 1.0

#: Default generation token cap for the tiny SOC intent JSON.  This is a
#: *lower* bound than the investigation agent's cap — the SOC output is a
#: small structured intent and never needs the full model budget.
DEFAULT_SOC_MAX_OUTPUT_TOKENS = 1024

#: Default temperature for deterministic parsing.
DEFAULT_SOC_TEMPERATURE = 0.0


class _TransientProviderError(SOCProviderError):
    """Internal marker for retryable server-side failures (5xx)."""

    def __init__(self, status: int, provider: str) -> None:
        super().__init__(f"server error (HTTP {status})", provider=provider)
        self.status = status


class GeminiSOCIntentParser(SOCIntentParser):
    """Gemini ``generateContent`` structured-output SOC intent parser.

    Parameters:
        api_key: Gemini API key.  Must be provided explicitly or resolved
            from ``Settings.gemini_api_key``.
        model: Model identifier.  Must be provided explicitly or resolved
            from ``Settings.gemini_model``.
        timeout_seconds: Per-request timeout (default from
            ``Settings.gemini_timeout_seconds``).
        max_retries: Bounded retry count for transient failures (default
            from ``Settings.gemini_max_retries``).
        max_output_tokens: ``maxOutputTokens`` generation bound (default
            ``DEFAULT_SOC_MAX_OUTPUT_TOKENS``).
        endpoint_base: API base URL (default from
            ``Settings.gemini_endpoint_base``).
        http_client: Optional pre-configured ``httpx.Client`` (tests inject
            a ``MockTransport`` client; no network is touched).
        sleep: Overridable sleeper used for retry backoff.
        prompt_builder: Optional :class:`SOCPromptBuilder` override.
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str | None = None,
        timeout_seconds: float | None = None,
        max_retries: int | None = None,
        max_output_tokens: int | None = None,
        endpoint_base: str | None = None,
        http_client: httpx.Client | None = None,
        sleep: Callable[[float], None] | None = None,
        prompt_builder: SOCPromptBuilder | None = None,
    ) -> None:
        resolved_key = api_key or settings.gemini_api_key
        if not resolved_key:
            raise SOCConfigurationError(
                "Gemini API key is required for Natural Language SOC.  Set "
                "GEMINI_API_KEY or pass api_key explicitly."
            )
        resolved_model = model or settings.gemini_model
        if not resolved_model or not resolved_model.strip():
            raise SOCConfigurationError(
                "Gemini model name is required for Natural Language SOC.  "
                "Set GEMINI_MODEL or pass model explicitly."
            )

        self._api_key: str = resolved_key
        self._model: str = resolved_model

        self._timeout_seconds: float = (
            timeout_seconds
            if timeout_seconds is not None
            else settings.gemini_timeout_seconds
        )
        if self._timeout_seconds <= 0:
            raise SOCConfigurationError(
                "Gemini timeout must be a positive number of seconds"
            )

        self._max_retries: int = (
            max_retries if max_retries is not None else settings.gemini_max_retries
        )
        if self._max_retries < 0:
            raise SOCConfigurationError(
                "Gemini retry count must be zero or a positive integer"
            )

        self._max_output_tokens: int = (
            max_output_tokens
            if max_output_tokens is not None
            else DEFAULT_SOC_MAX_OUTPUT_TOKENS
        )
        if self._max_output_tokens <= 0:
            raise SOCConfigurationError(
                "Gemini max output tokens must be a positive integer"
            )

        self._endpoint_base: str = (endpoint_base or settings.gemini_endpoint_base).rstrip("/")
        self._sleep: Callable[[float], None] = sleep or time.sleep
        self._prompt_builder: SOCPromptBuilder = prompt_builder or SOCPromptBuilder()

        self._owns_client = http_client is None
        self._client: httpx.Client = (
            http_client
            if http_client is not None
            else httpx.Client(timeout=self._timeout_seconds)
        )

    @property
    def provider_name(self) -> str:
        return "gemini"

    @property
    def model_name(self) -> str | None:
        return self._model

    # -- Endpoint helpers ----------------------------------------------------

    def _endpoint_url(self) -> str:
        return (
            f"{self._endpoint_base}/v1beta/models/"
            f"{self._model}:generateContent"
        )

    def _request_headers(self) -> dict[str, str]:
        return {
            "x-goog-api-key": self._api_key,
            "Accept": "application/json",
        }

    def _build_payload(self, prompt: SOCPrompt) -> dict[str, Any]:
        return {
            "systemInstruction": {
                "parts": [{"text": prompt.system_instruction}],
            },
            "contents": [{"role": "user", "parts": [{"text": prompt.content}]}],
            "generationConfig": {
                "temperature": DEFAULT_SOC_TEMPERATURE,
                "maxOutputTokens": self._max_output_tokens,
                "responseMimeType": "application/json",
                "responseSchema": SOC_INTENT_MODEL_JSON_SCHEMA,
            },
        }

    # -- Public interface ----------------------------------------------------

    def parse(self, user_query: str) -> SOCParseResult:
        if not isinstance(user_query, str):
            raise SOCInputValidationError(
                "the SOC query must be a non-empty string"
            )
        if not user_query.strip():
            raise SOCInputValidationError(
                "the SOC query must not be blank"
            )
        if len(user_query) > SOC_MAX_QUERY_LENGTH:
            raise SOCInputValidationError(
                f"the SOC query must not exceed {SOC_MAX_QUERY_LENGTH} characters"
            )

        prompt = self._prompt_builder.build(user_query)
        endpoint = self._endpoint_url()
        headers = self._request_headers()
        payload = self._build_payload(prompt)

        response = self._request_with_retry(endpoint, headers, payload)
        raw_text = self._extract_response_text(response)
        return SOCParseResult(
            raw_text=raw_text,
            provider=self.provider_name,
            model=self.model_name,
        )

    # -- HTTP request with bounded retry for transient errors ----------------

    def _request_with_retry(
        self,
        endpoint: str,
        headers: dict[str, str],
        payload: dict[str, Any],
    ) -> Any:
        """POST *payload* with bounded retry on transient failures only.

        Retries 5xx server errors, transport-level failures, and timeouts.
        Never retries 4xx client errors (including rate limits) or
        authentication failures.
        """
        last_exc: Exception | None = None

        for attempt in range(1, self._max_retries + 2):
            try:
                response = self._client.post(
                    endpoint, headers=headers, json=payload
                )
                return self._handle_response(response)
            except _TransientProviderError as exc:
                last_exc = exc
                logger.warning(
                    "soc gemini server error (attempt %d/%d): HTTP %d",
                    attempt,
                    self._max_retries + 1,
                    exc.status,
                )
                if attempt <= self._max_retries:
                    self._sleep(_RETRY_BASE_DELAY * attempt)
                    continue
                raise SOCProviderUnavailableError(
                    f"server error (HTTP {exc.status})",
                    provider=self.provider_name,
                ) from exc
            except SOCProviderError:
                raise
            except httpx.TimeoutException as exc:
                last_exc = exc
                logger.warning(
                    "soc gemini request timed out (attempt %d/%d)",
                    attempt,
                    self._max_retries + 1,
                )
                if attempt <= self._max_retries:
                    self._sleep(_RETRY_BASE_DELAY * attempt)
                    continue
                raise SOCProviderTimeoutError(
                    "request timed out", provider=self.provider_name
                ) from exc
            except httpx.HTTPError as exc:
                last_exc = exc
                logger.warning(
                    "soc gemini transport error (attempt %d/%d): %s",
                    attempt,
                    self._max_retries + 1,
                    type(exc).__name__,
                )
                if attempt <= self._max_retries:
                    self._sleep(_RETRY_BASE_DELAY * attempt)
                    continue
                raise SOCProviderUnavailableError(
                    f"transport error: {type(exc).__name__}",
                    provider=self.provider_name,
                ) from exc

        raise SOCProviderUnavailableError(
            "request failed after retries", provider=self.provider_name
        ) from last_exc

    # -- Response handling ---------------------------------------------------

    def _handle_response(self, response: httpx.Response) -> Any:
        status = response.status_code

        if status == 401:
            raise SOCProviderError(
                "authentication failed — check the API key configuration",
                provider=self.provider_name,
            )
        if status == 403:
            raise SOCProviderError(
                "forbidden — the API key lacks permission for this model",
                provider=self.provider_name,
            )
        if status == 429:
            raise SOCProviderUnavailableError(
                "rate limit exceeded", provider=self.provider_name
            )
        if status == 400:
            raise SOCProviderError(
                "bad request — malformed generation request",
                provider=self.provider_name,
            )
        if status >= 500:
            raise _TransientProviderError(status, self.provider_name)
        if status != 200:
            raise SOCProviderError(
                f"unexpected HTTP status {status}",
                provider=self.provider_name,
            )

        try:
            payload = response.json()
        except Exception as exc:
            raise SOCProviderError(
                "malformed provider response", provider=self.provider_name
            ) from exc

        if not isinstance(payload, dict):
            raise SOCProviderError(
                "unexpected provider response — expected a JSON object",
                provider=self.provider_name,
            )
        return payload

    @staticmethod
    def _extract_response_text(payload: dict[str, Any]) -> str:
        candidates = payload.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            raise SOCProviderError(
                "empty provider response", provider="gemini"
            )
        candidate = candidates[0]
        if not isinstance(candidate, dict):
            raise SOCProviderError(
                "unexpected provider response — malformed candidate",
                provider="gemini",
            )

        finish_reason = candidate.get("finishReason")
        if finish_reason is not None and finish_reason != "STOP":
            raise SOCProviderError(
                "Gemini completion did not end in a clean STOP "
                f"(finishReason={finish_reason}); the output is rejected "
                "rather than partially accepted",
                provider="gemini",
            )

        content = candidate.get("content")
        parts = content.get("parts") if isinstance(content, dict) else None
        if not isinstance(parts, list):
            raise SOCProviderError(
                "empty provider response", provider="gemini"
            )

        text_parts = [
            part.get("text", "")
            for part in parts
            if isinstance(part, dict) and isinstance(part.get("text"), str)
        ]
        if not text_parts:
            raise SOCProviderError(
                "empty provider response", provider="gemini"
            )
        return "".join(text_parts)


__all__ = [
    "GeminiSOCIntentParser",
    "DEFAULT_SOC_MAX_OUTPUT_TOKENS",
    "DEFAULT_SOC_TEMPERATURE",
]