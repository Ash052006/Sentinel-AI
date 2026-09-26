"""Gemini SOC intent-parser provider tests (Step 23).

Exercised exclusively through an injected ``httpx.MockTransport`` (no real
network): configuration validation, request shape (headers, payload,
schema, temperature), bounded retry policy (transient only), error
mapping, and raw-output extraction.  A single ``gemini_integration``
skipped smoke test runs only when ``GEMINI_API_KEY`` is set.
"""

from __future__ import annotations

import json

import httpx
import pytest

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
from app.services.soc.gemini import (
    DEFAULT_SOC_MAX_OUTPUT_TOKENS,
    DEFAULT_SOC_TEMPERATURE,
    GeminiSOCIntentParser,
)

_TEST_KEY = "test-soc-gemini-api-key"
_SOC_MODEL = "gemini-2.0-flash"
_BASE = "https://generativelanguage.googleapis.com"

_OK_PAYLOAD = {
    "candidates": [
        {
            "content": {
                "role": "model",
                "parts": [
                    {
                        "text": json.dumps(
                            {"resource": "detections", "operation": "recent"}
                        )
                    }
                ],
            },
            "finishReason": "STOP",
        }
    ]
}


def _transport(responses, recorder=None):
    """Wrap *responses* in a MockTransport, popping each served response."""
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


def _parser(
    responses,
    *,
    recorder=None,
    max_retries: int = 2,
    sleeps: list[float] | None = None,
    **kwargs,
) -> GeminiSOCIntentParser:
    if sleeps is not None:

        def noop_sleep(seconds: float) -> None:
            sleeps.append(seconds)

        kwargs.setdefault("sleep", noop_sleep)
    client = httpx.Client(
        transport=_transport(responses, recorder), timeout=30
    )
    return GeminiSOCIntentParser(
        api_key=_TEST_KEY,
        model=_SOC_MODEL,
        timeout_seconds=30,
        max_retries=max_retries,
        endpoint_base=_BASE,
        http_client=client,
        **kwargs,
    )


def _json_response(payload: dict, status: int = 200) -> httpx.Response:
    return httpx.Response(
        status, json=payload, request=httpx.Request("POST", _BASE)
    )


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class TestConfiguration:
    def test_missing_api_key_rejected(self, monkeypatch) -> None:
        from app.core.config import settings

        monkeypatch.setattr(settings, "gemini_api_key", "")
        with pytest.raises(SOCConfigurationError):
            GeminiSOCIntentParser(
                api_key=None,
                model=_SOC_MODEL,
            )

    def test_missing_model_rejected(self, monkeypatch) -> None:
        from app.core.config import settings

        # Fallback settings exist, so force the resolved model to be absent.
        monkeypatch.setattr(settings, "gemini_model", "")
        with pytest.raises(SOCConfigurationError):
            GeminiSOCIntentParser(
                api_key=_TEST_KEY,
                model=None,
            )

    def test_blank_model_rejected(self) -> None:
        with pytest.raises(SOCConfigurationError):
            GeminiSOCIntentParser(api_key=_TEST_KEY, model="  ")

    def test_nonpositive_timeout_rejected(self) -> None:
        with pytest.raises(SOCConfigurationError):
            GeminiSOCIntentParser(
                api_key=_TEST_KEY, model=_SOC_MODEL, timeout_seconds=0
            )

    def test_negative_retries_rejected(self) -> None:
        with pytest.raises(SOCConfigurationError):
            GeminiSOCIntentParser(
                api_key=_TEST_KEY, model=_SOC_MODEL, max_retries=-1
            )

    def test_nonpositive_output_tokens_rejected(self) -> None:
        with pytest.raises(SOCConfigurationError):
            GeminiSOCIntentParser(
                api_key=_TEST_KEY, model=_SOC_MODEL, max_output_tokens=0
            )


# ---------------------------------------------------------------------------
# Request shape
# ---------------------------------------------------------------------------


class TestRequestShape:
    def test_payload_shape(self) -> None:
        recorded = []
        parser = _parser(
            lambda request: httpx.Response(
                200,
                json=_OK_PAYLOAD,
                request=request,
            ),
            recorder=recorded,
        )
        result = parser.parse("show recent detections")
        assert result.raw_text == json.dumps(
            {"resource": "detections", "operation": "recent"}
        )

        request = recorded[0]
        assert request.method == "POST"
        assert request.url.path.endswith(
            f"/v1beta/models/{_SOC_MODEL}:generateContent"
        )
        assert request.headers["x-goog-api-key"] == _TEST_KEY
        assert "test-soc-gemini-api-key" not in str(request.url)

        payload = json.loads(request.read().decode("utf-8"))
        system = payload["systemInstruction"]["parts"][0]["text"]
        assert system
        # System instruction is fixed grammar; user text is isolated in a
        # delimited region and never echoed into the system instruction.
        assert "detections" in system or "resources" in system
        assert "show recent detections" not in system
        contents = payload["contents"][0]
        assert "show recent detections" in contents["parts"][0]["text"]
        assert contents["parts"][0]["text"].startswith("<user_data>")
        config = payload["generationConfig"]
        assert config["temperature"] == DEFAULT_SOC_TEMPERATURE
        assert config["maxOutputTokens"] == DEFAULT_SOC_MAX_OUTPUT_TOKENS
        assert config["responseMimeType"] == "application/json"
        assert config["responseSchema"] == SOC_INTENT_MODEL_JSON_SCHEMA

    def test_provider_and_model_identifiers(self) -> None:
        parser = _parser(
            lambda request: httpx.Response(200, json=_OK_PAYLOAD, request=request)
        )
        assert parser.provider_name == "gemini"
        assert parser.model_name == _SOC_MODEL


# ---------------------------------------------------------------------------
# Raw extraction + provider errors
# ---------------------------------------------------------------------------


class TestExtractionAndErrors:
    def test_extracts_raw_text_unvalidated(self) -> None:
        parser = _parser(
            lambda request: httpx.Response(200, json=_OK_PAYLOAD, request=request)
        )
        result = parser.parse("any question")
        # Provider output is returned RAW — contract validation is deferred
        # to the deterministic build_candidate step.
        assert "operation" in result.raw_text

    def test_non_stop_finish_raises(self) -> None:
        payload = {"candidates": [{"finishReason": "MAX_TOKENS", "content": {"parts": [{"text": "{}"}]}}]}
        parser = _parser(lambda r: httpx.Response(200, json=payload, request=r))
        with pytest.raises(SOCProviderError):
            parser.parse("question")

    def test_empty_candidates_rejected(self) -> None:
        parser = _parser(lambda r: httpx.Response(200, json={"candidates": []}, request=r))
        with pytest.raises(SOCProviderError):
            parser.parse("question")

    def test_missing_text_parts_rejected(self) -> None:
        payload = {"candidates": [{"finishReason": "STOP", "content": {"parts": []}}]}
        parser = _parser(lambda r: httpx.Response(200, json=payload, request=r))
        with pytest.raises(SOCProviderError):
            parser.parse("question")

    def test_non_json_provider_payload_rejected(self) -> None:
        parser = _parser(lambda r: httpx.Response(200, text="not json", request=r))
        with pytest.raises(SOCProviderError):
            parser.parse("question")

    def test_empty_provider_payload_rejected(self) -> None:
        parser = _parser(lambda r: httpx.Response(200, json=None, request=r))
        with pytest.raises(SOCProviderError):
            parser.parse("question")


class TestHttpErrorMapping:
    def test_401_authentication(self) -> None:
        parser = _parser(lambda r: httpx.Response(401, json={}, request=r))
        with pytest.raises(SOCProviderError):
            parser.parse("question")

    def test_403_forbidden(self) -> None:
        parser = _parser(lambda r: httpx.Response(403, json={}, request=r))
        with pytest.raises(SOCProviderError):
            parser.parse("question")

    def test_400_bad_request(self) -> None:
        parser = _parser(lambda r: httpx.Response(400, json={}, request=r))
        with pytest.raises(SOCProviderError):
            parser.parse("question")

    def test_429_rate_limit_terminal(self) -> None:
        parser = _parser(lambda r: httpx.Response(429, json={}, request=r), max_retries=2)
        with pytest.raises(SOCProviderUnavailableError):
            parser.parse("question")

    def test_5xx_retried_then_unavailable(self) -> None:
        sleeps: list[float] = []
        parser = _parser(lambda r: httpx.Response(503, json={}, request=r), sleeps=sleeps, max_retries=1)
        with pytest.raises(SOCProviderUnavailableError):
            parser.parse("question")
        assert sleeps == [1.0]

    def test_5xx_recovers_on_retry(self) -> None:
        attempts = {"n": 0}
        sleeps: list[float] = []

        def handler(request: httpx.Request) -> httpx.Response:
            attempts["n"] += 1
            if attempts["n"] == 1:
                return httpx.Response(502, json={}, request=request)
            return httpx.Response(200, json=_OK_PAYLOAD, request=request)

        parser = _parser(handler, sleeps=sleeps, max_retries=2)
        result = parser.parse("question")
        assert attempts["n"] == 2
        assert "operation" in result.raw_text

    def test_timeout_terminal(self) -> None:
        sleeps: list[float] = []

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("boom")

        parser = _parser(handler, sleeps=sleeps, max_retries=1)
        with pytest.raises(SOCProviderTimeoutError):
            parser.parse("question")
        assert sleeps == [1.0]


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


class TestInputValidation:
    def test_blank_query_rejected(self) -> None:
        parser = _parser(lambda r: httpx.Response(200, json=_OK_PAYLOAD, request=r))
        with pytest.raises(SOCInputValidationError):
            parser.parse("   ")

    def test_oversized_query_rejected(self) -> None:
        parser = _parser(lambda r: httpx.Response(200, json=_OK_PAYLOAD, request=r))
        with pytest.raises(SOCInputValidationError):
            parser.parse("a" * (SOC_MAX_QUERY_LENGTH + 1))

    def test_non_string_rejected(self) -> None:
        parser = _parser(lambda r: httpx.Response(200, json=_OK_PAYLOAD, request=r))
        with pytest.raises(SOCInputValidationError):
            parser.parse(None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Integration smoke test (skipped unless GEMINI_API_KEY set)
# ---------------------------------------------------------------------------


@pytest.mark.gemini_integration
@pytest.mark.skipif(
    not __import__("os").environ.get("GEMINI_API_KEY"),
    reason="GEMINI_API_KEY not set; integration test skipped",
)
def test_live_gemini_parse() -> None:
    parser = GeminiSOCIntentParser()
    result = parser.parse("show me the most recent detections")
    assert result.raw_text
    assert result.provider == "gemini"