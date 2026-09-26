"""Step 12C — Gemini provider tests.

``GeminiClient`` is exercised exclusively through an injected
``httpx.MockTransport`` (no real network): request shape, headers, payload
schema, bounded retry policy (transient only), error mapping, exception
sanitization, and output extraction.  A single ``gemini_integration``
marked smoke test is skipped unless ``GEMINI_API_KEY`` is set.
"""

from __future__ import annotations

import json
import os

import httpx
import pytest

from app.agents.investigation.exceptions import (
    InvestigationAgentError,
    InvestigationConfigurationError,
    InvestigationModelOutputError,
    InvestigationProviderError,
    InvestigationProviderTimeoutError,
    InvestigationProviderUnavailableError,
)
from app.agents.investigation.gemini import GeminiClient
from app.agents.investigation.model_output import INVESTIGATION_MODEL_JSON_SCHEMA
from app.agents.investigation.prompt import InvestigationPrompt

_API_KEY = "test-gemini-api-key"
_MODEL = "gemini-2.0-flash"
_BASE = "https://generativelanguage.googleapis.com"


def _prompt(text: str = "reason about context") -> InvestigationPrompt:
    return InvestigationPrompt(
        system_instruction="you are the investigator",
        content=text,
    )


def _transport(
    responses: list[httpx.Response] | httpx.Response | object,
    recorder: list[httpx.Request] | None = None,
) -> httpx.MockTransport:
    """Wrap *responses* in a MockTransport handler.

    A plain callable is invoked once per request (for error-handler stubs
    that raise on every attempt).  A single Response or a list of Responses
    is served once, popping each on request.
    """
    if callable(responses):
        persistent = responses

        def handler(request: httpx.Request) -> httpx.Response:
            if recorder is not None:
                recorder.append(request)
            return persistent(request)

        return httpx.MockTransport(handler)

    if not isinstance(responses, list):
        responses = [responses]
    queue = list(responses)

    def handler(request: httpx.Request) -> httpx.Response:
        if recorder is not None:
            recorder.append(request)
        return queue.pop(0)

    return httpx.MockTransport(handler)


def _client(
    responses,
    *,
    recorder: list[httpx.Request] | None = None,
    sleeps: list[float] | None = None,
    max_retries: int = 2,
) -> GeminiClient:
    transport = _transport(responses, recorder=recorder)
    return GeminiClient(
        api_key=_API_KEY,
        model=_MODEL,
        temperature=0.0,
        max_retries=max_retries,
        endpoint_base=_BASE,
        http_client=httpx.Client(transport=transport),
        sleep=sleeps.append if sleeps is not None else None,
    )


def _ok_response(text: str, finish_reason: str = "STOP") -> httpx.Response:
    payload = {
        "candidates": [
            {
                "content": {"parts": [{"text": text}]},
                "finishReason": finish_reason,
            }
        ]
    }
    return httpx.Response(200, json=payload)


# ---------------------------------------------------------------------------
# A. Success path
# ---------------------------------------------------------------------------


def test_generate_returns_extracted_text():
    text = json.dumps({"findings": [], "observations": []})
    client = _client(_ok_response(text))
    assert client.generate(_prompt()) == text


def test_request_shape_and_headers():
    recorded: list[httpx.Request] = []
    text = json.dumps({"findings": [], "observations": []})
    client = _client(_ok_response(text), recorder=recorded)
    client.generate(_prompt("investigate"))

    assert len(recorded) == 1
    request = recorded[0]
    assert request.method == "POST"
    expected_url = f"{_BASE}/v1beta/models/{_MODEL}:generateContent"
    assert str(request.url) == expected_url
    assert request.headers["x-goog-api-key"] == _API_KEY
    assert request.headers["Accept"] == "application/json"
    assert _API_KEY not in str(request.url)

    body = json.loads(request.content)
    assert body["contents"] == [
        {"role": "user", "parts": [{"text": "investigate"}]}
    ]
    assert body["systemInstruction"]["parts"][0]["text"] == (
        "you are the investigator"
    )
    generation = body["generationConfig"]
    assert generation["responseMimeType"] == "application/json"
    assert generation["responseSchema"] == INVESTIGATION_MODEL_JSON_SCHEMA
    assert generation["temperature"] == 0.0


def test_multiple_text_parts_joined():
    payload = {
        "candidates": [
            {
                "content": {
                    "parts": [{"text": "a"}, {"text": "b"}, {"text": "c"}]
                },
                "finishReason": "STOP",
            }
        ]
    }
    client = _client(httpx.Response(200, json=payload))
    assert client.generate(_prompt()) == "abc"


# ---------------------------------------------------------------------------
# B. Retry policy (transient only)
# ---------------------------------------------------------------------------


def test_5xx_then_success_retries():
    recorded: list[httpx.Request] = []
    sleeps: list[float] = []
    text = json.dumps({"findings": [], "observations": []})
    client = _client(
        [
            httpx.Response(500, json={}),
            httpx.Response(502, json={}),
            _ok_response(text),
        ],
        recorder=recorded,
        sleeps=sleeps,
    )
    assert client.generate(_prompt()) == text
    assert len(recorded) == 3
    assert sleeps == [1.0, 2.0]


def test_5xx_exhaustion_raises_unavailable():
    sleeps: list[float] = []
    client = _client(
        [httpx.Response(503, json={}), httpx.Response(503, json={})],
        sleeps=sleeps,
        max_retries=1,
    )
    with pytest.raises(InvestigationProviderUnavailableError):
        client.generate(_prompt())
    assert sleeps == [1.0]


def test_timeout_retries_then_raises_timeout():
    sleeps: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("connection timed out")

    client = GeminiClient(
        api_key=_API_KEY,
        model=_MODEL,
        max_retries=1,
        http_client=httpx.Client(transport=_transport(handler, recorder=None)),
        sleep=sleeps.append,
    )
    with pytest.raises(InvestigationProviderTimeoutError):
        client.generate(_prompt())
    assert sleeps == [1.0]


def test_transport_error_raises_unavailable_no_retry_on_final():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    sleeps: list[float] = []
    client = GeminiClient(
        api_key=_API_KEY,
        model=_MODEL,
        max_retries=0,
        http_client=httpx.Client(transport=_transport(handler)),
        sleep=sleeps.append,
    )
    with pytest.raises(InvestigationProviderUnavailableError):
        client.generate(_prompt())
    assert sleeps == []


# ---------------------------------------------------------------------------
# C. Client / auth errors — never retried
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "status,error_class",
    [
        (400, InvestigationProviderError),
        (401, InvestigationProviderError),
        (403, InvestigationProviderError),
        (404, InvestigationProviderError),
    ],
)
def test_client_errors_not_retried(status, error_class):
    recorded: list[httpx.Request] = []
    client = _client(httpx.Response(status, json={}), recorder=recorded)
    with pytest.raises(error_class):
        client.generate(_prompt())
    assert len(recorded) == 1


def test_rate_limit_parses_retry_after():
    response = httpx.Response(
        429, json={}, headers={"Retry-After": "17"}
    )
    client = _client(response)
    with pytest.raises(InvestigationProviderUnavailableError) as excinfo:
        client.generate(_prompt())
    assert excinfo.value.retry_after == 17.0


def test_rate_limit_without_retry_after():
    client = _client(httpx.Response(429, json={}))
    with pytest.raises(InvestigationProviderUnavailableError) as excinfo:
        client.generate(_prompt())
    assert excinfo.value.retry_after is None


# ---------------------------------------------------------------------------
# D. Malformed responses
# ---------------------------------------------------------------------------


def test_non_json_body_rejected():
    client = _client(httpx.Response(200, content=b"not-json"))
    with pytest.raises(InvestigationProviderError):
        client.generate(_prompt())


def test_json_non_object_rejected():
    client = _client(httpx.Response(200, json=[1, 2, 3]))
    with pytest.raises(InvestigationProviderError):
        client.generate(_prompt())


def test_missing_candidates_rejected():
    client = _client(httpx.Response(200, json={}))
    with pytest.raises(InvestigationProviderError):
        client.generate(_prompt())


def test_empty_candidates_rejected():
    client = _client(httpx.Response(200, json={"candidates": []}))
    with pytest.raises(InvestigationProviderError):
        client.generate(_prompt())


def test_non_clean_finish_rejected():
    client = _client(
        httpx.Response(
            200,
            json={
                "candidates": [
                    {
                        "content": {"parts": [{"text": "partial"}]},
                        "finishReason": "MAX_TOKENS",
                    }
                ]
            },
        )
    )
    with pytest.raises(InvestigationModelOutputError):
        client.generate(_prompt())


def test_missing_text_parts_rejected():
    client = _client(
        httpx.Response(
            200,
            json={
                "candidates": [
                    {"content": {"parts": [{"functionCall": {}}]}, "finishReason": "STOP"}
                ]
            },
        )
    )
    with pytest.raises(InvestigationProviderError):
        client.generate(_prompt())


# ---------------------------------------------------------------------------
# E. Configuration
# ---------------------------------------------------------------------------


def test_missing_api_key_fails_fast(monkeypatch):
    monkeypatch.setattr("app.core.config.settings.gemini_api_key", "")
    with pytest.raises(InvestigationConfigurationError):
        GeminiClient(api_key="", model=_MODEL)


def test_blank_model_fails_fast(monkeypatch):
    monkeypatch.setattr("app.core.config.settings.gemini_api_key", _API_KEY)
    with pytest.raises(InvestigationConfigurationError):
        GeminiClient(api_key=_API_KEY, model="  ")


def test_nonpositive_timeout_fails_fast():
    with pytest.raises(InvestigationConfigurationError):
        GeminiClient(api_key=_API_KEY, model=_MODEL, timeout_seconds=0)


def test_negative_retries_fail_fast():
    with pytest.raises(InvestigationConfigurationError):
        GeminiClient(api_key=_API_KEY, model=_MODEL, max_retries=-1)


# ---------------------------------------------------------------------------
# F. Sanitization
# ---------------------------------------------------------------------------


def test_exceptions_never_contain_api_key():
    client = _client(httpx.Response(401, json={}))
    with pytest.raises(InvestigationProviderError) as excinfo:
        client.generate(_prompt())
    assert _API_KEY not in str(excinfo.value)
    assert _API_KEY not in repr(excinfo.value)
    assert isinstance(excinfo.value, InvestigationAgentError)


def test_api_key_not_in_transport_error_message():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    client = GeminiClient(
        api_key=_API_KEY,
        model=_MODEL,
        max_retries=0,
        http_client=httpx.Client(transport=_transport(handler)),
    )
    with pytest.raises(InvestigationProviderUnavailableError) as excinfo:
        client.generate(_prompt())
    assert _API_KEY not in str(excinfo.value)


def test_model_output_error_sanitized():
    client = _client(
        httpx.Response(
            200,
            json={
                "candidates": [
                    {
                        "content": {"parts": [{"text": "x"}]},
                        "finishReason": "SAFETY",
                    }
                ]
            },
        )
    )
    with pytest.raises(InvestigationModelOutputError) as excinfo:
        client.generate(_prompt())
    assert _API_KEY not in str(excinfo.value)


# ---------------------------------------------------------------------------
# G. Input guard
# ---------------------------------------------------------------------------


def test_generate_requires_an_investigation_prompt():
    client = _client(_ok_response("{}"))
    with pytest.raises(TypeError):
        client.generate("just a string")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# H. Live smoke test (opt-in, no network in the normal suite)
# ---------------------------------------------------------------------------


@pytest.mark.gemini_integration
@pytest.mark.skipif(
    os.environ.get("GEMINI_API_KEY") is None,
    reason="GEMINI_API_KEY not set",
)
def test_live_gemini_generate():
    """End-to-end smoke test against the real Gemini API.

    Intentionally excluded from the default suite; requires the API key.
    """
    from app.agents.investigation.gemini import GeminiClient as LiveClient

    client = LiveClient()
    text = client.generate(
        _prompt(
            'Return this exact JSON: {"findings": [], "observations": []}'
        )
    )
    parsed = json.loads(text)
    assert parsed == {"findings": [], "observations": []}