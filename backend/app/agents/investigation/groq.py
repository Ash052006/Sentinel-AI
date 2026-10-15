"""Groq provider — the second cloud reasoning backend.

A concrete :class:`InvestigationLLMClient` that talks to Groq's OpenAI-compatible
``/openai/v1/chat/completions`` endpoint over the repository's existing ``httpx``
dependency.  This is the *same* HTTP convention as
:class:`~app.agents.investigation.gemini.GeminiClient` — injectable client for
tests, bounded timeout, bounded retry for transient failures only — so adding a
second provider required no new dependency and no second transport abstraction.

Structured output is requested through Groq's Structured Outputs feature in
**strict** mode (``response_format.type = "json_schema"`` with
``json_schema.strict = true``), which uses constrained decoding to guarantee the
response matches the supplied schema.  Strict mode imposes real requirements on
the schema (``additionalProperties: false`` on every object, and *every*
property listed in ``required``), so the Gemini/OpenAPI-style response schema
the V3.23 agents already use is translated by
:func:`to_groq_strict_json_schema` first.

That translation **fails closed**.  Anything it cannot translate with certainty
raises rather than being silently dropped, because quietly discarding a
constraint is indistinguishable from honouring it — and a schema that silently
lost ``required`` would let the model omit a field the engine then treats as
absent.

A successful HTTP response is **never** assumed valid: this provider only
extracts the raw text.  Strict parsing, output-contract validation, evidence
citation resolution, provenance, and bounds enforcement remain the caller's
job, so no provider-specific behaviour can bypass a safeguard.

Security properties:

* The API key is sent as an ``Authorization: Bearer`` header — never in the URL,
  never in a query string, never logged, never in an exception message.
* Provider error bodies are **never** copied into an exception.  Failures are
  described by HTTP status alone, so a provider that echoes the submitted
  payload (or a key) back in its error body cannot leak it into logs, audit
  records, or API responses.
* Logs contain only provider/model identifiers and retry counts.
* Retries are bounded (``groq_max_retries``), occur only for transient failures
  (5xx / 429 / 498 / transport / timeout), and are never used for authentication
  failures or other client errors that cannot succeed on repetition.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any, Callable

import httpx

from app.agents.investigation._transport import (
    RETRY_BASE_DELAY,
    TransientProviderError,
    backoff_delay,
    retry_after_seconds,
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

#: Gemini/OpenAPI schema type token -> JSON Schema type.  Gemini spells its
#: types in upper case; OpenAI-compatible strict schemas use the lower-case
#: JSON Schema spelling.
_JSON_TYPE_MAP: dict[str, str] = {
    "OBJECT": "object",
    "ARRAY": "array",
    "STRING": "string",
    "NUMBER": "number",
    "INTEGER": "integer",
    "BOOLEAN": "boolean",
}

#: Keywords this translator refuses to guess at.  ``$ref``/``$defs``/
#: ``anyOf``/``oneOf``/``allOf`` are either unsupported under strict mode or
#: change the shape of the contract in ways that cannot be verified here.  A
#: schema using one of them is a hard configuration error, never a silent
#: downgrade.
_UNSUPPORTED_KEYWORDS: frozenset[str] = frozenset(
    {
        "$ref",
        "$defs",
        "$schema",
        "anyOf",
        "oneOf",
        "allOf",
        "not",
        "additionalItems",
        "patternProperties",
        "dependencies",
        "contains",
    }
)

#: Per-node keys this translator understands.  Anything else is refused rather
#: than dropped, so an unfamiliar constraint can never disappear unnoticed.
#: ``nullable`` is deliberately absent: translating it faithfully (a union with
#: ``null``, which strict mode still requires to be listed in ``required``) is
#: not implemented, so accepting and ignoring it would be exactly the silent
#: downgrade this function exists to prevent.
_KNOWN_NODE_KEYS: frozenset[str] = frozenset(
    {"type", "description", "enum", "properties", "required", "items"}
)

#: Keys each node type may legitimately carry.  A key that is valid elsewhere in
#: JSON Schema but meaningless for this node type is refused rather than
#: ignored — otherwise a malformed node would translate to something subtly
#: different from what it says.
_KEYS_BY_TYPE: dict[str, frozenset[str]] = {
    "object": frozenset({"type", "description", "enum", "properties", "required"}),
    "array": frozenset({"type", "description", "enum", "items"}),
    "string": frozenset({"type", "description", "enum"}),
    "number": frozenset({"type", "description", "enum"}),
    "integer": frozenset({"type", "description", "enum"}),
    "boolean": frozenset({"type", "description", "enum"}),
}


def to_groq_strict_json_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Translate a Gemini/OpenAPI response schema into a Groq strict schema.

    Groq's Structured Outputs strict mode guarantees the response matches the
    supplied schema, but only when the schema obeys its subset: ``type`` values
    in lower-case JSON Schema spelling, ``additionalProperties: false`` on every
    object, and *every* property named in ``required``.

    The V3.23 agent schemas already satisfy the last point — each object lists
    all of its properties as required — so the translation is faithful rather
    than a reinterpretation.  Where a schema does not satisfy it, this function
    raises instead of repairing, because repairing would change the contract the
    engine expects:

    * an object missing ``additionalProperties`` gets ``false`` added (that is
      the documented, required form — not a weakening);
    * an object with a property absent from ``required`` is **refused**, since
      strict mode has no way to express an optional field and silently
      promoting it to required would invent an obligation the model never had;
    * an unrecognised type token or keyword is **refused**.

    Raises:
        InvestigationConfigurationError: the schema cannot be translated
            faithfully.  Raised at construction, before any request is sent, so
            a bad contract fails closed rather than degrading silently.
    """
    if not isinstance(schema, dict):
        raise InvestigationConfigurationError(
            "response schema must be a JSON object; received "
            f"{type(schema).__name__}"
        )
    return _translate_node(schema, path="$")


def _translate_node(node: Any, *, path: str) -> dict[str, Any]:
    if not isinstance(node, dict):
        raise InvestigationConfigurationError(
            f"response schema node at {path} must be a JSON object; received "
            f"{type(node).__name__}"
        )

    unsupported = sorted(_UNSUPPORTED_KEYWORDS & set(node))
    if unsupported:
        raise InvestigationConfigurationError(
            f"response schema node at {path} uses keyword(s) "
            f"{unsupported}, which this translator cannot verify against "
            "Groq strict structured outputs; refusing to send a schema that "
            "might mean something weaker than intended"
        )

    unknown = sorted(set(node) - _KNOWN_NODE_KEYS)
    if unknown:
        raise InvestigationConfigurationError(
            f"response schema node at {path} uses unrecognised key(s) "
            f"{unknown}; refusing to drop a constraint that may be load-bearing"
        )

    raw_type = node.get("type")
    if not isinstance(raw_type, str):
        raise InvestigationConfigurationError(
            f"response schema node at {path} is missing a string 'type'"
        )
    json_type = _JSON_TYPE_MAP.get(raw_type.strip().upper())
    if json_type is None:
        raise InvestigationConfigurationError(
            f"response schema node at {path} has unsupported type "
            f"{raw_type!r}; expected one of {sorted(_JSON_TYPE_MAP)}"
        )

    irrelevant = sorted(set(node) - _KEYS_BY_TYPE[json_type])
    if irrelevant:
        raise InvestigationConfigurationError(
            f"response schema node at {path} is a {json_type} but carries "
            f"key(s) {irrelevant}, which mean nothing for that type; refusing "
            "to ignore them in case they were meant as a constraint"
        )

    translated: dict[str, Any] = {"type": json_type}

    description = node.get("description")
    if description is not None:
        if not isinstance(description, str):
            raise InvestigationConfigurationError(
                f"response schema node at {path} has a non-string 'description'"
            )
        translated["description"] = description

    enum = node.get("enum")
    if enum is not None:
        if not isinstance(enum, list) or not enum:
            raise InvestigationConfigurationError(
                f"response schema node at {path} has an 'enum' that is not a "
                "non-empty list"
            )
        translated["enum"] = list(enum)

    if json_type == "object":
        translated.update(_translate_object(node, path=path))
    elif json_type == "array":
        items = node.get("items")
        if items is None:
            raise InvestigationConfigurationError(
                f"response schema node at {path} is an array with no 'items'"
            )
        translated["items"] = _translate_node(items, path=f"{path}.items")

    return translated


def _translate_object(node: dict[str, Any], *, path: str) -> dict[str, Any]:
    properties = node.get("properties")
    if properties is None:
        raise InvestigationConfigurationError(
            f"response schema node at {path} is an object with no 'properties'"
        )
    if not isinstance(properties, dict):
        raise InvestigationConfigurationError(
            f"response schema node at {path} has non-object 'properties'"
        )

    required = node.get("required", [])
    if not isinstance(required, list) or not all(
        isinstance(name, str) for name in required
    ):
        raise InvestigationConfigurationError(
            f"response schema node at {path} has a malformed 'required' list"
        )
    required_names = set(required)

    missing = sorted(set(properties) - required_names)
    if missing:
        raise InvestigationConfigurationError(
            f"response schema node at {path} declares propert(ies) {missing} "
            "that are not in 'required'. Groq strict structured outputs cannot "
            "express an optional field, and promoting it to required would "
            "invent an obligation the model never had; refusing rather than "
            "silently changing the output contract"
        )

    unknown_required = sorted(required_names - set(properties))
    if unknown_required:
        raise InvestigationConfigurationError(
            f"response schema node at {path} marks propert(ies) "
            f"{unknown_required} as required but does not define them"
        )

    return {
        "properties": {
            name: _translate_node(
                sub_schema, path=f"{path}.properties.{name}"
            )
            for name, sub_schema in properties.items()
        },
        # Strict mode requires this on every object; it is the documented form
        # and prevents the model from inventing undeclared fields.
        "additionalProperties": False,
        # Ordered to match `properties` so the wire payload is deterministic.
        "required": [
            name for name in properties if name in required_names
        ],
    }


def _schema_name(schema: dict[str, Any]) -> str:
    """Derive a stable, valid JSON-schema name from the schema itself.

    Groq requires a ``name`` for the response schema.  Hashing the canonical
    form keeps it deterministic (so an identical contract always produces an
    identical request) and means callers never have to invent a name that could
    drift from the schema it describes.
    """
    encoded = json.dumps(schema, sort_keys=True, separators=(",", ":"))
    return "sentinelai_" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:16]


class GroqClient(InvestigationLLMClient):
    """Groq chat-completions structured-output provider.

    Parameters:
        api_key: Groq API key.  Must be provided explicitly or resolved from
            ``Settings.groq_api_key``.
        model: Model identifier.  Must be provided explicitly or resolved from
            ``Settings.groq_model``.  Groq ids are namespace-qualified, e.g.
            ``openai/gpt-oss-120b``.
        timeout_seconds: Per-request timeout (default from
            ``Settings.groq_timeout_seconds``).
        max_retries: Bounded retry count for transient failures (default from
            ``Settings.groq_max_retries``).
        max_output_tokens: ``max_completion_tokens`` generation bound (default
            from ``Settings.groq_max_output_tokens``).
        temperature: Generation temperature (default from
            ``Settings.groq_temperature``); 0.0 favours determinism.
        reasoning_effort: Reasoning budget for reasoning models such as
            gpt-oss (default from ``Settings.groq_reasoning_effort``).
        endpoint_base: API base URL (default from
            ``Settings.groq_endpoint_base``).
        http_client: Optional pre-configured ``httpx.Client`` (tests inject a
            ``MockTransport`` client; no network is touched).  When ``None`` a
            client is created internally with the timeout.
        sleep: Overridable sleeper used for retry backoff.
        response_schema: Optional structured-output schema.  Defaults to the
            investigation schema.  Present so other V3 reasoning agents (e.g.
            the V3.23 debate agents) reuse *this* provider with their own
            output contract, exactly as they reuse the Gemini provider.
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
        response_schema: dict[str, Any] | None = None,
    ) -> None:
        resolved_key = api_key or settings.groq_api_key
        if not resolved_key:
            raise InvestigationConfigurationError(
                "Groq API key is required.  Set GROQ_API_KEY in your "
                "environment or pass api_key explicitly."
            )
        resolved_model = model or settings.groq_model
        if not resolved_model or not resolved_model.strip():
            raise InvestigationConfigurationError(
                "Groq model name is required.  Set GROQ_MODEL in your "
                "environment or pass model explicitly."
            )

        self._api_key: str = resolved_key
        self._model: str = resolved_model

        self._timeout_seconds: float = (
            timeout_seconds
            if timeout_seconds is not None
            else settings.groq_timeout_seconds
        )
        if self._timeout_seconds <= 0:
            raise InvestigationConfigurationError(
                "Groq timeout must be a positive number of seconds"
            )

        self._max_retries: int = (
            max_retries if max_retries is not None else settings.groq_max_retries
        )
        if self._max_retries < 0:
            raise InvestigationConfigurationError(
                "Groq retry count must be zero or a positive integer"
            )

        self._max_output_tokens: int = (
            max_output_tokens
            if max_output_tokens is not None
            else settings.groq_max_output_tokens
        )
        if self._max_output_tokens <= 0:
            raise InvestigationConfigurationError(
                "Groq max output tokens must be a positive integer"
            )

        self._temperature: float = (
            temperature if temperature is not None else settings.groq_temperature
        )
        resolved_effort = (
            reasoning_effort
            if reasoning_effort is not None
            else settings.groq_reasoning_effort
        )
        if resolved_effort not in {"low", "medium", "high"}:
            raise InvestigationConfigurationError(
                "Groq reasoning effort must be one of "
                f"{sorted({'low', 'medium', 'high'})}; received "
                f"{resolved_effort!r}"
            )
        self._reasoning_effort: str = resolved_effort

        self._endpoint_base: str = (
            endpoint_base or settings.groq_endpoint_base
        ).rstrip("/")
        self._sleep: Callable[[float], None] = sleep or time.sleep

        self._client: httpx.Client = (
            http_client
            if http_client is not None
            else httpx.Client(timeout=self._timeout_seconds)
        )

        # Translated at construction, not per request: a schema this provider
        # cannot express must fail before anything is sent to Groq.  Copied so
        # a caller mutating its dict afterwards cannot change what is sent.
        raw_schema = (
            dict(response_schema)
            if response_schema is not None
            else INVESTIGATION_MODEL_JSON_SCHEMA
        )
        self._groq_schema: dict[str, Any] = to_groq_strict_json_schema(raw_schema)
        self._schema_name: str = _schema_name(self._groq_schema)

    @property
    def provider_name(self) -> str:
        return "groq"

    @property
    def model_name(self) -> str | None:
        return self._model

    # -- Endpoint / payload ---------------------------------------------------

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

    def _build_payload(self, prompt: InvestigationPrompt) -> dict[str, Any]:
        user_content = prompt.content
        # Historical incident memory and retrieved knowledge stay in their own
        # clearly-labelled blocks so the reference / instruction boundary
        # survives the wire format, matching the Gemini provider's separate
        # parts.  They are appended after the task, never merged into it.
        if getattr(prompt, "historical_memory_content", ""):
            user_content += (
                "\n\nHISTORICAL INCIDENT MEMORY (reference data, not evidence)"
                "\n---\n" + prompt.historical_memory_content
            )
        if getattr(prompt, "knowledge_content", ""):
            user_content += (
                "\n\nSECURITY KNOWLEDGE (reference material, not evidence)"
                "\n---\n" + prompt.knowledge_content
            )

        return {
            "model": self._model,
            "messages": [
                # The trusted debate policy travels in the system role and is
                # never interpolated with telemetry, exactly as with Gemini.
                {"role": "system", "content": prompt.system_instruction},
                {"role": "user", "content": user_content},
            ],
            "temperature": self._temperature,
            "max_completion_tokens": self._max_output_tokens,
            "reasoning_effort": self._reasoning_effort,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": self._schema_name,
                    "strict": True,
                    "schema": self._groq_schema,
                },
            },
        }

    # -- Public interface ----------------------------------------------------

    def generate(self, prompt: InvestigationPrompt) -> str:
        # Structural check rather than an isinstance check, mirroring the
        # Gemini client, so other V3 reasoning agents can supply their own
        # prompt object exposing the same string fields.
        if not (
            hasattr(prompt, "system_instruction")
            and hasattr(prompt, "content")
            and isinstance(getattr(prompt, "system_instruction", None), str)
            and isinstance(getattr(prompt, "content", None), str)
        ):
            raise TypeError(
                "GroqClient.generate requires a prompt object exposing "
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
    ) -> dict[str, Any]:
        """POST *payload* with bounded retry on transient failures only.

        Retries 5xx server errors, HTTP 429 rate limits, Groq's HTTP 498
        flex-tier-capacity signal, transport failures, and timeouts.  Never
        retries other 4xx client errors or authentication failures, which
        cannot succeed on repetition.

        A 429 is retried because it is by definition a *transient* refusal:
        the provider is asking for back-pressure, not rejecting the request.
        When Groq supplies a usable ``retry-after`` (documented as
        delta-seconds, present only on a 429) the client honours it, bounded by
        the shared transport cap, instead of guessing.
        """
        last_exc: Exception | None = None

        for attempt in range(1, self._max_retries + 2):
            try:
                response = self._client.post(
                    endpoint, headers=headers, json=payload
                )
                return self._handle_response(response)
            except TransientProviderError as exc:
                last_exc = exc
                logger.warning(
                    "groq transient provider error (attempt %d/%d): HTTP %d",
                    attempt,
                    self._max_retries + 1,
                    exc.status,
                )
                if attempt <= self._max_retries:
                    self._sleep(backoff_delay(attempt, exc.retry_after))
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
                    "groq request timed out (attempt %d/%d)",
                    attempt,
                    self._max_retries + 1,
                )
                if attempt <= self._max_retries:
                    self._sleep(RETRY_BASE_DELAY * attempt)
                    continue
                raise InvestigationProviderTimeoutError(
                    "request timed out", provider=self.provider_name
                ) from exc
            except httpx.HTTPError as exc:
                last_exc = exc
                logger.warning(
                    "groq transport error (attempt %d/%d): %s",
                    attempt,
                    self._max_retries + 1,
                    type(exc).__name__,
                )
                if attempt <= self._max_retries:
                    self._sleep(RETRY_BASE_DELAY * attempt)
                    continue
                raise InvestigationProviderUnavailableError(
                    f"transport error: {type(exc).__name__}",
                    provider=self.provider_name,
                ) from exc

        raise InvestigationProviderUnavailableError(
            "request failed after retries", provider=self.provider_name
        ) from last_exc

    # -- Response handling ---------------------------------------------------

    def _handle_response(self, response: httpx.Response) -> dict[str, Any]:
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
        if status == 404:
            # Groq returns 404 for an unknown model or endpoint.  Not
            # retryable: repeating a bad identifier cannot succeed, and
            # retrying it would only turn a clear misconfiguration into a
            # slow one.
            raise InvestigationProviderError(
                "not found — the configured model may be unknown or not "
                "permitted for this key",
                provider=self.provider_name,
            )
        if status == 429:
            # Retryable back-pressure.  The honoured `retry-after` is still
            # reported on the terminal failure so the caller can see how long
            # the provider asked us to wait.
            retry_after = retry_after_seconds(response)
            raise TransientProviderError(
                429,
                self.provider_name,
                retry_after=retry_after,
                retry_after_header=retry_after,
                message="rate limit exceeded",
            )
        if status == 498:
            # Groq's documented "Flex Tier Capacity Exceeded".  Also
            # back-pressure rather than rejection, so it is transient — and it
            # must be named explicitly, because a naive "5xx means transient"
            # rule would misclassify this 4xx as permanent.
            raise TransientProviderError(
                498,
                self.provider_name,
                message="provider capacity exceeded",
            )
        if status in (400, 413, 422):
            # 400 also carries Groq's "invalid model id" case, which is a
            # misconfiguration rather than a transient fault.
            raise InvestigationProviderError(
                "bad request — malformed generation request",
                provider=self.provider_name,
            )
        if status >= 500:
            raise TransientProviderError(status, self.provider_name)
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
        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            raise InvestigationProviderError(
                "empty provider response", provider="groq"
            )
        choice = choices[0]
        if not isinstance(choice, dict):
            raise InvestigationProviderError(
                "unexpected provider response — malformed choice",
                provider="groq",
            )

        finish_reason = choice.get("finish_reason")
        if finish_reason is not None and finish_reason != "stop":
            # "length" means the generation was cut off mid-object.  Accepting
            # it would feed a truncated, schema-invalid document to the caller
            # as if it were complete, so it is rejected outright — the same
            # fail-closed treatment Gemini gives a non-STOP finish reason.
            raise InvestigationModelOutputError(
                "Groq completion did not end in a clean stop "
                f"(finish_reason={finish_reason}); the output is rejected "
                "rather than partially accepted"
            )

        message = choice.get("message")
        if not isinstance(message, dict):
            raise InvestigationProviderError(
                "unexpected provider response — malformed message",
                provider="groq",
            )

        refusal = message.get("refusal")
        if isinstance(refusal, str) and refusal.strip():
            raise InvestigationModelOutputError(
                "the model refused to produce a structured answer; the output "
                "is rejected rather than partially accepted"
            )

        content = message.get("content")
        if not isinstance(content, str) or not content.strip():
            raise InvestigationProviderError(
                "empty provider response", provider="groq"
            )
        return content


__all__ = ["GroqClient", "to_groq_strict_json_schema"]