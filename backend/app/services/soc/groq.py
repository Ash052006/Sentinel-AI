"""Groq adapter for the Natural Language SOC intent parser — Step 23.

A concrete :class:`~app.services.soc.parser.SOCIntentParser` that talks to
Groq's OpenAI-compatible ``/openai/v1/chat/completions`` endpoint over the
repository's existing ``httpx`` dependency, mirroring the Gemini SOC adapter
in :mod:`app.services.soc.gemini`: injectable ``httpx.Client`` for tests,
bounded timeout, bounded retry for transient failures only, sanitized
exceptions, and the API key carried in the ``Authorization: Bearer`` header
(never in the URL, logs, exceptions, or messages).

Structured output is requested through Groq's JSON-object mode
(``response_format: {"type": "json_object"}``), the analogue of Gemini's
``responseMimeType: application/json``.  A successful HTTP response is
**never** assumed valid: the adapter only extracts the raw text and returns
it inside a :class:`~app.services.soc.parser.SOCParseResult`; the
deterministic strict parse + Pydantic contract validation always happen
outside the model, in :func:`~app.services.soc.parser.build_candidate`.

Security properties:

* The provider never accesses databases, tools, or the filesystem.
* The prompt is built from the fixed SOC system instruction plus the user
  query inside a clearly delimited ``<user_data>`` region.
* Provider error bodies are never copied into an exception; failures are
  described by HTTP status so a provider that echoes the submitted payload
  (or a key) cannot leak it into logs or API responses.
* Logs contain only provider/model identifiers, retry counts, and
  sanitized failure classes — never raw prompts, raw user queries, raw
  provider responses, or the API key.
* Exceptions carry sanitized messages; causes are chained internally.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable

import httpx

from app.core.config import settings
from app.schemas.soc_query import SOC_MAX_QUERY_LENGTH
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

#: Upper bound on any single retry sleep (seconds), so a hostile or
#: nonsensical ``Retry-After`` header can never stall a request indefinitely.
_MAX_RETRY_SLEEP_SECONDS = 30.0

#: Default generation token cap for the tiny SOC intent JSON.  Groq's
#: ``gpt-oss`` models are reasoning models and their reasoning tokens are
#: billed/timed as completion tokens, so this cap is deliberately larger than
#: the deterministic SOC output bound (:data:`SOC_MAX_MODEL_OUTPUT_BYTES`)
#: while still keeping a parse request small.
DEFAULT_SOC_MAX_OUTPUT_TOKENS = 2048

#: Default temperature for deterministic parsing.
DEFAULT_SOC_TEMPERATURE = 0.0

#: Closed vocabulary of Groq reasoning-effort values.
_REASONING_EFFORTS = frozenset({"low", "medium", "high"})


class _TransientProviderError(SOCProviderError):
    """Internal marker for retryable provider failures (5xx, 429, 498).

    Carries an optional provider-supplied ``retry_after`` so the caller can
    honour the server's own pacing hint instead of guessing.  Never escapes
    the parser: consumers observe a regular
    :class:`SOCProviderUnavailableError` once retries are exhausted.
    """

    def __init__(
        self,
        status: int,
        provider: str,
        *,
        retry_after: float | None = None,
        message: str | None = None,
    ) -> None:
        super().__init__(
            message or f"server error (HTTP {status})", provider=provider
        )
        self.status = status
        self.retry_after = retry_after


def _retry_after_seconds(response: Any) -> float | None:
    """Return a usable ``Retry-After`` delay from *response*, or ``None``.

    Only the delta-seconds form is honoured, and only when it is a finite,
    non-negative number.  The HTTP-date form and anything unparsable fall
    through to ``None`` so the caller uses its own bounded backoff instead of
    trusting an unverified value.
    """
    header = response.headers.get("Retry-After")
    if not header:
        return None
    try:
        value = float(header)
    except (TypeError, ValueError):
        return None
    if value < 0 or value != value or value in (float("inf"), float("-inf")):
        return None
    return value


class GroqSOCIntentParser(SOCIntentParser):
    """Groq chat-completions JSON-mode SOC intent parser.

    Parameters:
        api_key: Groq API key.  Must be provided explicitly or resolved
            from ``Settings.groq_api_key``.
        model: Model identifier.  Must be provided explicitly or resolved
            from ``Settings.groq_model``.  Groq ids are namespace-qualified,
            e.g. ``openai/gpt-oss-120b``.
        timeout_seconds: Per-request timeout (default from
            ``Settings.groq_timeout_seconds``).
        max_retries: Bounded retry count for transient failures (default
            from ``Settings.groq_max_retries``).
        max_output_tokens: ``max_completion_tokens`` generation bound
            (default ``DEFAULT_SOC_MAX_OUTPUT_TOKENS``).
        temperature: Generation temperature (default
            ``DEFAULT_SOC_TEMPERATURE``); 0.0 favours determinism.
        reasoning_effort: Reasoning budget for reasoning models such as
            gpt-oss (default from ``Settings.groq_reasoning_effort``).
        endpoint_base: API base URL (default from
            ``Settings.groq_endpoint_base``).
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
        temperature: float | None = None,
        reasoning_effort: str | None = None,
        endpoint_base: str | None = None,
        http_client: httpx.Client | None = None,
        sleep: Callable[[float], None] | None = None,
        prompt_builder: SOCPromptBuilder | None = None,
    ) -> None:
        resolved_key = api_key or settings.groq_api_key
        if not resolved_key:
            raise SOCConfigurationError(
                "Groq API key is required for Natural Language SOC.  Set "
                "GROQ_API_KEY or pass api_key explicitly."
            )
        resolved_model = model or settings.groq_model
        if not resolved_model or not resolved_model.strip():
            raise SOCConfigurationError(
                "Groq model name is required for Natural Language SOC.  "
                "Set GROQ_MODEL or pass model explicitly."
            )

        self._api_key: str = resolved_key
        self._model: str = resolved_model

        self._timeout_seconds: float = (
            timeout_seconds
            if timeout_seconds is not None
            else settings.groq_timeout_seconds
        )
        if self._timeout_seconds <= 0:
            raise SOCConfigurationError(
                "Groq timeout must be a positive number of seconds"
            )

        self._max_retries: int = (
            max_retries if max_retries is not None else settings.groq_max_retries
        )
        if self._max_retries < 0:
            raise SOCConfigurationError(
                "Groq retry count must be zero or a positive integer"
            )

        self._max_output_tokens: int = (
            max_output_tokens
            if max_output_tokens is not None
            else DEFAULT_SOC_MAX_OUTPUT_TOKENS
        )
        if self._max_output_tokens <= 0:
            raise SOCConfigurationError(
                "Groq max output tokens must be a positive integer"
            )

        self._temperature: float = (
            temperature if temperature is not None else DEFAULT_SOC_TEMPERATURE
        )

        resolved_effort = (
            reasoning_effort
            if reasoning_effort is not None
            else settings.groq_reasoning_effort
        )
        if resolved_effort not in _REASONING_EFFORTS:
            raise SOCConfigurationError(
                "Groq reasoning effort must be one of "
                f"{sorted(_REASONING_EFFORTS)}; received {resolved_effort!r}"
            )
        self._reasoning_effort: str = resolved_effort

        self._endpoint_base: str = (
            endpoint_base or settings.groq_endpoint_base
        ).rstrip("/")
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
        return "groq"

    @property
    def model_name(self) -> str | None:
        return self._model

    # -- Endpoint helpers ----------------------------------------------------

    def _endpoint_url(self) -> str:
        return f"{self._endpoint_base}/openai/v1/chat/completions"

    def _request_headers(self) -> dict[str, str]:
        # Bearer token in a header: never a query parameter, so the key cannot
        # end up in a URL that gets logged, cached, or echoed by a proxy.
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _build_payload(self, prompt: SOCPrompt) -> dict[str, Any]:
        # The trusted grammar/security instruction travels in the system role;
        # the untrusted query travels in the user role inside the delimited
        # <user_data> region, exactly as with Gemini.
        return {
            "model": self._model,
            "messages": [
                {"role": "system", "content": prompt.system_instruction},
                {"role": "user", "content": prompt.content},
            ],
            "temperature": self._temperature,
            "max_completion_tokens": self._max_output_tokens,
            "reasoning_effort": self._reasoning_effort,
            # JSON-object mode guarantees the model returns a single JSON
            # object, mirroring Gemini's ``application/json`` mime type.  The
            # authoritative contract check remains the deterministic strict
            # parse + Pydantic validation outside the model.
            "response_format": {"type": "json_object"},
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

        Retries 5xx server errors, HTTP 429 rate limits, Groq's HTTP 498
        flex-tier-capacity signal, transport-level failures, and timeouts.
        Never retries other 4xx client errors or authentication failures,
        which cannot succeed on repetition.

        A 429 is retried because it is by definition a *transient* refusal:
        the provider is asking for back-pressure, not rejecting the request.
        When the provider supplies a usable ``Retry-After`` the parser honours
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
                    "soc groq transient provider error (attempt %d/%d): HTTP %d",
                    attempt,
                    self._max_retries + 1,
                    exc.status,
                )
                if attempt <= self._max_retries:
                    self._sleep(self._backoff(attempt, exc.retry_after))
                    continue
                raise SOCProviderUnavailableError(
                    str(exc), provider=self.provider_name
                ) from exc
            except SOCProviderError:
                raise
            except httpx.TimeoutException as exc:
                last_exc = exc
                logger.warning(
                    "soc groq request timed out (attempt %d/%d)",
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
                    "soc groq transport error (attempt %d/%d): %s",
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

    @staticmethod
    def _backoff(attempt: int, retry_after: float | None) -> float:
        """Return the sleep before retry *attempt*.

        A provider-supplied ``retry_after`` wins, because the provider knows
        when its own rate limit clears.  It is still clamped to
        :data:`_MAX_RETRY_SLEEP_SECONDS` so a pathological header cannot turn
        a bounded retry into an unbounded stall.  With no usable hint the
        original bounded linear backoff is used unchanged.
        """
        if retry_after is not None:
            return min(retry_after, _MAX_RETRY_SLEEP_SECONDS)
        return _RETRY_BASE_DELAY * attempt

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
        if status == 404:
            # Groq returns 404 for an unknown model or endpoint.  Not
            # retryable: repeating a bad identifier cannot succeed.
            raise SOCProviderError(
                "not found — the configured model may be unknown or not "
                "permitted for this key",
                provider=self.provider_name,
            )
        if status == 429:
            # Retryable: the provider is applying back-pressure, not rejecting
            # the request.  Honour its own Retry-After hint when it sends one.
            raise _TransientProviderError(
                429,
                self.provider_name,
                retry_after=_retry_after_seconds(response),
                message="rate limit exceeded",
            )
        if status == 498:
            # Groq's documented "Flex Tier Capacity Exceeded".  Back-pressure
            # rather than rejection, so it is transient — named explicitly
            # because it is a 4xx that must not be treated as permanent.
            raise _TransientProviderError(
                498,
                self.provider_name,
                message="provider capacity exceeded",
            )
        if status in (400, 413, 422):
            # 400 also carries Groq's "invalid model id" case, a
            # misconfiguration rather than a transient fault.
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
        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            raise SOCProviderError(
                "empty provider response", provider="groq"
            )
        choice = choices[0]
        if not isinstance(choice, dict):
            raise SOCProviderError(
                "unexpected provider response — malformed choice",
                provider="groq",
            )

        finish_reason = choice.get("finish_reason")
        if finish_reason is not None and finish_reason != "stop":
            # "length" means the generation was cut off mid-object.  Accepting
            # it would feed a truncated, schema-invalid document to the
            # deterministic validator as if it were complete, so it is
            # rejected outright — the same fail-closed treatment Gemini gives
            # a non-STOP finish reason.
            raise SOCProviderError(
                "Groq completion did not end in a clean stop "
                f"(finish_reason={finish_reason}); the output is rejected "
                "rather than partially accepted",
                provider="groq",
            )

        message = choice.get("message")
        if not isinstance(message, dict):
            raise SOCProviderError(
                "unexpected provider response — malformed message",
                provider="groq",
            )

        refusal = message.get("refusal")
        if isinstance(refusal, str) and refusal.strip():
            raise SOCProviderError(
                "the model refused to produce a structured answer; the output "
                "is rejected rather than partially accepted",
                provider="groq",
            )

        content = message.get("content")
        if not isinstance(content, str) or not content.strip():
            raise SOCProviderError(
                "empty provider response", provider="groq"
            )
        return content


__all__ = [
    "GroqSOCIntentParser",
    "DEFAULT_SOC_MAX_OUTPUT_TOKENS",
    "DEFAULT_SOC_TEMPERATURE",
]
