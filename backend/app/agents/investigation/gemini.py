"""Gemini provider for the Step 12C Investigation Agent.

A concrete :class:`InvestigationLLMClient` that talks to the Google Gemini
``generateContent`` REST API over the repository's existing ``httpx``
dependency (the same HTTP convention used by the threat-intelligence
providers: injectable ``httpx.Client`` for tests, bounded timeout, bounded
retry for transient failures only).

Structured output is requested via ``responseMimeType: application/json``
plus the ``responseSchema`` derived from the model-output contract.  A
successful HTTP response is **never** assumed valid: the provider only
extracts the raw text; the agent strictly validates the returned payload
itself.

Security properties:

* The API key is sent as the ``x-goog-api-key`` header (never in the URL,
  never logged, never in exceptions, never in logs).
* Logs contain only provider/model identifiers and retry counts.
* Exceptions carry sanitized messages; causes are chained internally.
* Retries are conservative and bounded (``gemini_max_retries``), occur
  only for transient failures (5xx / transport / timeout), and are never
  used for client (4xx) errors, rate limits, or malformed output.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable

import httpx

from app.agents.investigation._transport import (
    RETRY_BASE_DELAY as _RETRY_BASE_DELAY,
)
from app.agents.investigation._transport import (
    TransientProviderError as _TransientProviderError,
)
from app.agents.investigation._transport import (
    backoff_delay,
)
from app.agents.investigation._transport import (
    retry_after_seconds as _retry_after_seconds,
)
from app.agents.investigation.exceptions import (
    InvestigationConfigurationError,
    InvestigationModelOutputError,
    InvestigationProviderError,
    InvestigationProviderTimeoutError,
    InvestigationProviderUnavailableError,
)
from app.agents.investigation.llm_client import InvestigationLLMClient
from app.agents.investigation.model_output import (
    INVESTIGATION_MODEL_JSON_SCHEMA,
)
from app.agents.investigation.prompt import InvestigationPrompt
from app.core.config import settings

logger = logging.getLogger(__name__)

# Retry backoff constants and the transient-failure marker now live in
# app.agents.investigation._transport so the Groq provider shares one
# implementation of the bounded-retry policy instead of forking it.  They are
# imported above under their original private names so the behaviour of this
# client is unchanged.


class GeminiClient(InvestigationLLMClient):
    """Gemini ``generateContent`` structured-output provider.

    Parameters:
        api_key: Gemini API key.  Must be provided explicitly or resolved
            from ``Settings.gemini_api_key``.
        model: Model identifier.  Must be provided explicitly or resolved
            from ``Settings.gemini_model`` (never hard-coded in the agent).
        timeout_seconds: Per-request timeout in seconds (default from
            ``Settings.gemini_timeout_seconds``).
        max_retries: Bounded retry count for transient failures (default
            from ``Settings.gemini_max_retries``).
        max_output_tokens: ``maxOutputTokens`` generation bound (default
            from ``Settings.gemini_max_output_tokens``).
temperature: Generation temperature (default from
            ``Settings.gemini_temperature``); 0.0 favours determinism.
        endpoint_base: API base URL (default from
            ``Settings.gemini_endpoint_base``).
        http_client: Optional pre-configured ``httpx.Client`` (tests inject a
            ``MockTransport`` client; no network is touched).  When
            ``None`` a client is created internally with the timeout.
        sleep: Overridable sleeper used for retry backoff (tests inject a
            non-blocking recorder).
        response_schema: Optional structured-output schema.  Defaults to the
            investigation schema.  Added so other V3 reasoning agents (e.g.
            the V3.23 debate agents) reuse *this* provider with their own
            output contract instead of introducing a second Gemini
            abstraction.  Only the schema travels on the wire; the caller
            remains responsible for strictly validating the returned payload.
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str | None = None,
        timeout_seconds: float | None = None,
        max_retries: int | None = None,
        max_output_tokens: int | None = None,
        temperature: float | None = None,
        endpoint_base: str | None = None,
        http_client: httpx.Client | None = None,
        sleep: Callable[[float], None] | None = None,
        response_schema: dict[str, Any] | None = None,
    ) -> None:
        resolved_key = api_key or settings.gemini_api_key
        if not resolved_key:
            raise InvestigationConfigurationError(
                "Gemini API key is required.  Set GEMINI_API_KEY in your "
                "environment or pass api_key explicitly."
            )
        resolved_model = model or settings.gemini_model
        if not resolved_model or not resolved_model.strip():
            raise InvestigationConfigurationError(
                "Gemini model name is required.  Set GEMINI_MODEL in your "
                "environment or pass model explicitly."
            )

        self._api_key: str = resolved_key
        self._model: str = resolved_model

        self._timeout_seconds: float = (
            timeout_seconds
            if timeout_seconds is not None
            else settings.gemini_timeout_seconds
        )
        if self._timeout_seconds <= 0:
            raise InvestigationConfigurationError(
                "Gemini timeout must be a positive number of seconds"
            )

        self._max_retries: int = (
            max_retries if max_retries is not None else settings.gemini_max_retries
        )
        if self._max_retries < 0:
            raise InvestigationConfigurationError(
                "Gemini retry count must be zero or a positive integer"
            )

        self._max_output_tokens: int = (
            max_output_tokens
            if max_output_tokens is not None
            else settings.gemini_max_output_tokens
        )
        self._temperature: float = (
            temperature if temperature is not None else settings.gemini_temperature
        )
        self._endpoint_base: str = (
            endpoint_base or settings.gemini_endpoint_base
        ).rstrip("/")
        self._sleep: Callable[[float], None] = sleep or time.sleep

        self._owns_client = http_client is None
        self._client: httpx.Client = (
            http_client
            if http_client is not None
            else httpx.Client(timeout=self._timeout_seconds)
        )

        # A caller-supplied schema lets another reasoning agent reuse this
        # provider without forking it.  It is copied so a caller mutating its
        # dict afterwards cannot change what is sent.
        self._response_schema: dict[str, Any] = (
            dict(response_schema)
            if response_schema is not None
            else INVESTIGATION_MODEL_JSON_SCHEMA
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

    def _build_payload(self, prompt: InvestigationPrompt) -> dict[str, Any]:
        parts: list[dict[str, str]] = [{"text": prompt.content}]
        if getattr(prompt, "historical_memory_content", ""):
            # Historical incident memory stays a separate, clearly-labelled
            # part so the reference / instruction boundary survives the wire
            # format (Step 21).
            parts.append({"text": prompt.historical_memory_content})
        if getattr(prompt, "knowledge_content", ""):
            # Retrieved knowledge stays a separate, clearly-labelled part so
            # the reference / instruction boundary survives the wire format.
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
                "responseSchema": self._response_schema,
            },
        }

    # -- Public interface ----------------------------------------------------

    def generate(self, prompt: InvestigationPrompt) -> str:
        # Structural check rather than an isinstance check on one concrete
        # prompt dataclass, so other V3 reasoning agents can supply their own
        # prompt object (same four string fields) without a second provider.
        # A string, dict, or any object missing the fields is still rejected.
        if not (
            hasattr(prompt, "system_instruction")
            and hasattr(prompt, "content")
            and isinstance(getattr(prompt, "system_instruction", None), str)
            and isinstance(getattr(prompt, "content", None), str)
        ):
            raise TypeError(
                "GeminiClient.generate requires a prompt object exposing "
                "string 'system_instruction' and 'content' attributes; "
                f"received {type(prompt).__name__}"
            )

        endpoint = self._endpoint_url()
        headers = self._request_headers()
        payload = self._build_payload(prompt)

        response = self._request_with_retry(endpoint, headers, payload)
        return self._extract_response_text(response)

    # -- HTTP request with bounded retry for transient errors ----------------

    def _request_with_retry(
        self,
        endpoint: str,
        headers: dict[str, str],
        payload: dict[str, Any],
    ) -> Any:
        """POST *payload* with bounded retry on transient failures only.

        Retries 5xx server errors, HTTP 429 rate limits, transport-level
        failures, and timeouts.  Never retries other 4xx client errors or
        authentication failures, which cannot succeed on repetition.

        A 429 is retried because it is by definition a *transient* refusal:
        the provider is asking for back-pressure, not rejecting the request.
        When the provider supplies a usable ``Retry-After`` the client honours
        it (bounded by :data:`_MAX_RETRY_SLEEP_SECONDS`) instead of guessing.
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
                    "gemini transient provider error (attempt %d/%d): HTTP %d",
                    attempt,
                    self._max_retries + 1,
                    exc.status,
                )
                if attempt <= self._max_retries:
                    self._sleep(self._backoff(attempt, exc.retry_after))
                    continue
                raise InvestigationProviderUnavailableError(
                    str(exc),
                    provider=self.provider_name,
                    retry_after=exc.retry_after_header,
                ) from exc
            except InvestigationProviderError:
                raise
            except httpx.TimeoutException as exc:
                last_exc = exc
                logger.warning(
                    "gemini request timed out (attempt %d/%d)",
                    attempt,
                    self._max_retries + 1,
                )
                if attempt <= self._max_retries:
                    self._sleep(_RETRY_BASE_DELAY * attempt)
                    continue
                raise InvestigationProviderTimeoutError(
                    "request timed out", provider=self.provider_name
                ) from exc
            except httpx.HTTPError as exc:
                last_exc = exc
                logger.warning(
                    "gemini transport error (attempt %d/%d): %s",
                    attempt,
                    self._max_retries + 1,
                    type(exc).__name__,
                )
                if attempt <= self._max_retries:
                    self._sleep(_RETRY_BASE_DELAY * attempt)
                    continue
                raise InvestigationProviderUnavailableError(
                    f"transport error: {type(exc).__name__}",
                    provider=self.provider_name,
                ) from exc

        raise InvestigationProviderUnavailableError(
            "request failed after retries", provider=self.provider_name
        ) from last_exc

    # -- Response handling ---------------------------------------------------

    @staticmethod
    def _backoff(attempt: int, retry_after: float | None) -> float:
        """Return the sleep before retry *attempt* (shared transport policy)."""
        return backoff_delay(attempt, retry_after)

    def _handle_response(self, response: httpx.Response) -> Any:
        status = response.status_code

        if status == 401:
            raise InvestigationProviderError(
                "authentication failed — check the API key configuration",
                provider=self.provider_name,
            )
        if status == 403:
            raise InvestigationProviderError(
                "forbidden — the API key lacks permission for this model",
                provider=self.provider_name,
            )
        if status == 429:
            # Retryable: the provider is applying back-pressure, not
            # rejecting the request.  A ``Retry-After`` the client already
            # honoured above is still reported on the terminal failure so the
            # caller can see how long the provider asked us to wait.
            retry_after = _retry_after_seconds(response)
            raise _TransientProviderError(
                429,
                self.provider_name,
                retry_after=retry_after,
                retry_after_header=retry_after,
                message="rate limit exceeded",
            )
        if status == 400:
            raise InvestigationProviderError(
                "bad request — malformed generation request",
                provider=self.provider_name,
            )
        if status >= 500:
            raise _TransientProviderError(status, self.provider_name)
        if status != 200:
            raise InvestigationProviderError(
                f"unexpected HTTP status {status}",
                provider=self.provider_name,
            )

        try:
            payload = response.json()
        except Exception as exc:
            raise InvestigationProviderError(
                "malformed provider response", provider=self.provider_name
            ) from exc

        if not isinstance(payload, dict):
            raise InvestigationProviderError(
                "unexpected provider response — expected a JSON object",
                provider=self.provider_name,
            )
        return payload

    @staticmethod
    def _extract_response_text(payload: dict[str, Any]) -> str:
        candidates = payload.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            raise InvestigationProviderError(
                "empty provider response", provider="gemini"
            )
        candidate = candidates[0]
        if not isinstance(candidate, dict):
            raise InvestigationProviderError(
                "unexpected provider response — malformed candidate",
                provider="gemini",
            )

        finish_reason = candidate.get("finishReason")
        if finish_reason is not None and finish_reason != "STOP":
            raise InvestigationModelOutputError(
                "Gemini completion did not end in a clean STOP "
                f"(finishReason={finish_reason}); the output is rejected "
                "rather than partially accepted"
            )

        content = candidate.get("content")
        parts = content.get("parts") if isinstance(content, dict) else None
        if not isinstance(parts, list):
            raise InvestigationProviderError(
                "empty provider response", provider="gemini"
            )

        text_parts = [
            part.get("text", "")
            for part in parts
            if isinstance(part, dict) and isinstance(part.get("text"), str)
        ]
        if not text_parts:
            raise InvestigationProviderError(
                "empty provider response", provider="gemini"
            )
        return "".join(text_parts)