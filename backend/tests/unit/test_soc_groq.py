"""Groq SOC intent-parser provider tests (Step 23 → Groq migration).

Exercised exclusively through an injected ``httpx.MockTransport`` (no real
network): configuration validation, request shape (endpoint, headers,
payload, model, JSON-object mode, reasoning effort), bounded retry policy
(transient only), error mapping, raw-output extraction, secret hygiene, and
the engine-level guarantee that Ask SOC selects Groq — never silently Gemini
— and reads its key/model from configuration.
"""

from __future__ import annotations

import json

import httpx
import pytest

from app.core.config import settings
from app.schemas.soc_query import SOC_MAX_QUERY_LENGTH
from app.services.soc import engine as engine_mod
from app.services.soc.errors import (
    SOCConfigurationError,
    SOCInputValidationError,
    SOCProviderError,
    SOCProviderTimeoutError,
    SOCProviderUnavailableError,
)
from app.services.soc.executor import SOCQueryExecutor
from app.services.soc.groq import (
    DEFAULT_SOC_MAX_OUTPUT_TOKENS,
    DEFAULT_SOC_TEMPERATURE,
    GroqSOCIntentParser,
)
from app.services.soc.prompt import SYSTEM_INSTRUCTION
from app.services.soc.registry import QueryHandler
from app.schemas.soc_query import SOCExecutionMode, SOCOperation, SOCResource

from soc_test_helpers import FakeRecord, NOW

_TEST_KEY = "gsk_test_soc_groq_key_not_real"
_SOC_MODEL = "openai/gpt-oss-120b"
_BASE = "https://api.groq.com"

_OK_PAYLOAD = {
    "choices": [
        {
            "message": {
                "role": "assistant",
                "content": json.dumps(
                    {"resource": "detections", "operation": "recent"}
                ),
            },
            "finish_reason": "stop",
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
) -> GroqSOCIntentParser:
    if sleeps is not None:

        def noop_sleep(seconds: float) -> None:
            sleeps.append(seconds)

        kwargs.setdefault("sleep", noop_sleep)
    client = httpx.Client(
        transport=_transport(responses, recorder), timeout=30
    )
    return GroqSOCIntentParser(
        api_key=_TEST_KEY,
        model=_SOC_MODEL,
        timeout_seconds=30,
        max_retries=max_retries,
        endpoint_base=_BASE,
        http_client=client,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class TestConfiguration:
    def test_missing_api_key_rejected(self, monkeypatch) -> None:
        monkeypatch.setattr(settings, "groq_api_key", "")
        with pytest.raises(SOCConfigurationError):
            GroqSOCIntentParser(api_key=None, model=_SOC_MODEL)

    def test_missing_model_rejected(self, monkeypatch) -> None:
        monkeypatch.setattr(settings, "groq_model", "")
        with pytest.raises(SOCConfigurationError):
            GroqSOCIntentParser(api_key=_TEST_KEY, model=None)

    def test_blank_model_rejected(self) -> None:
        with pytest.raises(SOCConfigurationError):
            GroqSOCIntentParser(api_key=_TEST_KEY, model="  ")

    def test_nonpositive_timeout_rejected(self) -> None:
        with pytest.raises(SOCConfigurationError):
            GroqSOCIntentParser(
                api_key=_TEST_KEY, model=_SOC_MODEL, timeout_seconds=0
            )

    def test_negative_retries_rejected(self) -> None:
        with pytest.raises(SOCConfigurationError):
            GroqSOCIntentParser(
                api_key=_TEST_KEY, model=_SOC_MODEL, max_retries=-1
            )

    def test_nonpositive_output_tokens_rejected(self) -> None:
        with pytest.raises(SOCConfigurationError):
            GroqSOCIntentParser(
                api_key=_TEST_KEY, model=_SOC_MODEL, max_output_tokens=0
            )

    def test_invalid_reasoning_effort_rejected(self) -> None:
        with pytest.raises(SOCConfigurationError):
            GroqSOCIntentParser(
                api_key=_TEST_KEY, model=_SOC_MODEL, reasoning_effort="turbo"
            )

    def test_api_key_read_from_configuration(self, monkeypatch) -> None:
        monkeypatch.setattr(settings, "groq_api_key", _TEST_KEY)
        parser = GroqSOCIntentParser(model=_SOC_MODEL)
        assert parser._api_key == _TEST_KEY

    def test_model_read_from_configuration(self, monkeypatch) -> None:
        monkeypatch.setattr(settings, "groq_model", _SOC_MODEL)
        parser = GroqSOCIntentParser(api_key=_TEST_KEY, model=None)
        assert parser.model_name == _SOC_MODEL


# ---------------------------------------------------------------------------
# Request shape
# ---------------------------------------------------------------------------


class TestRequestShape:
    def test_payload_shape(self) -> None:
        recorded = []
        parser = _parser(
            lambda request: httpx.Response(
                200, json=_OK_PAYLOAD, request=request
            ),
            recorder=recorded,
        )
        result = parser.parse("show recent detections")
        assert result.raw_text == json.dumps(
            {"resource": "detections", "operation": "recent"}
        )

        request = recorded[0]
        assert request.method == "POST"
        assert str(request.url).startswith(_BASE)
        assert request.url.path.endswith("/openai/v1/chat/completions")
        assert request.headers["Authorization"] == f"Bearer {_TEST_KEY}"
        # The key never travels in the URL or the request body.
        assert _TEST_KEY not in str(request.url)
        assert _TEST_KEY not in request.content.decode()

        payload = json.loads(request.read().decode("utf-8"))
        assert payload["model"] == _SOC_MODEL
        messages = payload["messages"]
        assert messages[0]["role"] == "system"
        assert messages[0]["content"] == SYSTEM_INSTRUCTION
        assert "show recent detections" not in messages[0]["content"]
        user_content = messages[1]["content"]
        assert user_content.startswith("<user_data>")
        assert "show recent detections" in user_content
        assert payload["temperature"] == DEFAULT_SOC_TEMPERATURE
        assert payload["max_completion_tokens"] == DEFAULT_SOC_MAX_OUTPUT_TOKENS
        assert payload["response_format"] == {"type": "json_object"}
        assert payload["reasoning_effort"] == settings.groq_reasoning_effort

    def test_configured_model_is_sent(self, monkeypatch) -> None:
        recorded = []
        monkeypatch.setattr(settings, "groq_model", _SOC_MODEL)
        client = httpx.Client(
            transport=_transport(
                lambda request: httpx.Response(
                    200, json=_OK_PAYLOAD, request=request
                ),
                recorded,
            ),
            timeout=30,
        )
        parser = GroqSOCIntentParser(
            api_key=_TEST_KEY,
            model=None,
            endpoint_base=_BASE,
            http_client=client,
        )
        parser.parse("show recent detections")
        payload = json.loads(recorded[0].read().decode("utf-8"))
        assert payload["model"] == _SOC_MODEL

    def test_provider_and_model_identifiers(self) -> None:
        parser = _parser(
            lambda request: httpx.Response(200, json=_OK_PAYLOAD, request=request)
        )
        assert parser.provider_name == "groq"
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
        assert "operation" in result.raw_text

    def test_non_stop_finish_raises(self) -> None:
        payload = {
            "choices": [
                {
                    "finish_reason": "length",
                    "message": {"content": "{}"},
                }
            ]
        }
        parser = _parser(lambda r: httpx.Response(200, json=payload, request=r))
        with pytest.raises(SOCProviderError):
            parser.parse("question")

    def test_refusal_raises(self) -> None:
        payload = {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"content": "", "refusal": "cannot help"},
                }
            ]
        }
        parser = _parser(lambda r: httpx.Response(200, json=payload, request=r))
        with pytest.raises(SOCProviderError):
            parser.parse("question")

    def test_empty_choices_rejected(self) -> None:
        parser = _parser(
            lambda r: httpx.Response(200, json={"choices": []}, request=r)
        )
        with pytest.raises(SOCProviderError):
            parser.parse("question")

    def test_malformed_message_rejected(self) -> None:
        payload = {"choices": [{"finish_reason": "stop", "message": "nope"}]}
        parser = _parser(lambda r: httpx.Response(200, json=payload, request=r))
        with pytest.raises(SOCProviderError):
            parser.parse("question")

    def test_empty_content_rejected(self) -> None:
        payload = {
            "choices": [{"finish_reason": "stop", "message": {"content": "  "}}]
        }
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

    def test_404_unknown_model_not_retried(self) -> None:
        attempts = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            attempts["n"] += 1
            return httpx.Response(404, json={}, request=request)

        parser = _parser(handler, max_retries=3)
        with pytest.raises(SOCProviderError):
            parser.parse("question")
        assert attempts["n"] == 1

    def test_400_bad_request(self) -> None:
        parser = _parser(lambda r: httpx.Response(400, json={}, request=r))
        with pytest.raises(SOCProviderError):
            parser.parse("question")

    def test_429_retried_then_unavailable(self) -> None:
        attempts = {"n": 0}
        sleeps: list[float] = []

        def handler(request: httpx.Request) -> httpx.Response:
            attempts["n"] += 1
            return httpx.Response(
                429, json={}, headers={"Retry-After": "3"}, request=request
            )

        parser = _parser(handler, sleeps=sleeps, max_retries=2)
        with pytest.raises(SOCProviderUnavailableError):
            parser.parse("question")
        assert attempts["n"] == 3
        assert sleeps == [3.0, 3.0]

    def test_429_recovers_on_retry(self) -> None:
        attempts = {"n": 0}
        sleeps: list[float] = []

        def handler(request: httpx.Request) -> httpx.Response:
            attempts["n"] += 1
            if attempts["n"] == 1:
                return httpx.Response(429, json={}, request=request)
            return httpx.Response(200, json=_OK_PAYLOAD, request=request)

        parser = _parser(handler, sleeps=sleeps, max_retries=2)
        result = parser.parse("question")
        assert attempts["n"] == 2
        assert "operation" in result.raw_text
        assert sleeps == [1.0]

    def test_429_absurd_retry_after_is_clamped(self) -> None:
        sleeps: list[float] = []

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                429,
                json={},
                headers={"Retry-After": "999999"},
                request=request,
            )

        parser = _parser(handler, sleeps=sleeps, max_retries=1)
        with pytest.raises(SOCProviderUnavailableError):
            parser.parse("question")
        assert sleeps == [30.0]

    def test_498_flex_capacity_is_transient(self) -> None:
        attempts = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            attempts["n"] += 1
            return httpx.Response(498, json={}, request=request)

        parser = _parser(handler, max_retries=1)
        with pytest.raises(SOCProviderUnavailableError):
            parser.parse("question")
        assert attempts["n"] == 2

    def test_5xx_retried_then_unavailable(self) -> None:
        sleeps: list[float] = []
        parser = _parser(
            lambda r: httpx.Response(503, json={}, request=r),
            sleeps=sleeps,
            max_retries=1,
        )
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
# Secret hygiene
# ---------------------------------------------------------------------------


class TestSecretHygiene:
    def test_api_key_never_in_exception_message(self) -> None:
        parser = _parser(
            lambda r: httpx.Response(500, json={"error": _TEST_KEY}, request=r),
            max_retries=0,
        )
        with pytest.raises(SOCProviderUnavailableError) as excinfo:
            parser.parse("question")
        assert _TEST_KEY not in str(excinfo.value)

    def test_api_key_never_in_auth_error_message(self) -> None:
        parser = _parser(lambda r: httpx.Response(401, json={}, request=r))
        with pytest.raises(SOCProviderError) as excinfo:
            parser.parse("question")
        assert _TEST_KEY not in str(excinfo.value)


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
# Engine integration — Ask SOC selects Groq, never silently Gemini
# ---------------------------------------------------------------------------


def _handlers_recent_detections() -> dict:
    def recent(db, *, limit=50):
        return [FakeRecord(id=f"r{i}") for i in range(min(limit, 2))]

    return {
        (SOCResource.DETECTIONS, SOCOperation.RECENT): QueryHandler(
            resource=SOCResource.DETECTIONS,
            operation=SOCOperation.RECENT,
            mode=SOCExecutionMode.RECENT_FEED,
            id_field=None,
            allowed_filters=frozenset(),
            call=recent,
            collect=lambda records: records,
        )
    }


class TestEngineSelectsGroq:
    def test_default_parser_is_groq(self, monkeypatch) -> None:
        monkeypatch.setattr(settings, "groq_api_key", "test-key")
        svc = engine_mod.SOCQueryService()
        parser = svc._resolve_parser()
        assert isinstance(parser, GroqSOCIntentParser)
        assert parser.provider_name == "groq"
        assert parser.model_name == settings.groq_model

    def test_engine_module_never_references_gemini(self) -> None:
        import inspect

        source = inspect.getsource(engine_mod)
        assert "gemini" not in source.lower()

    def test_groq_failure_never_falls_back_to_gemini(
        self, monkeypatch
    ) -> None:
        import app.services.soc.gemini as gemini_mod

        def _forbidden(*args, **kwargs):
            raise AssertionError("Ask SOC must not construct Gemini")

        monkeypatch.setattr(
            gemini_mod, "GeminiSOCIntentParser", _forbidden
        )
        # A Groq parser whose provider fails hard must surface a controlled
        # SOC error and never invoke Gemini.
        client = httpx.Client(
            transport=_transport(lambda r: httpx.Response(503, json={}, request=r)),
            timeout=30,
        )
        svc = engine_mod.SOCQueryService(
            parser=GroqSOCIntentParser(
                api_key=_TEST_KEY,
                model=_SOC_MODEL,
                max_retries=0,
                endpoint_base=_BASE,
                http_client=client,
            ),
            executor=SOCQueryExecutor(handlers=_handlers_recent_detections()),
            clock=lambda: NOW,
        )
        with pytest.raises(SOCProviderUnavailableError):
            svc.query(object(), "recent detections")

    def test_metadata_records_groq_provider(self) -> None:
        client = httpx.Client(
            transport=_transport(
                lambda r: httpx.Response(200, json=_OK_PAYLOAD, request=r)
            ),
            timeout=30,
        )
        svc = engine_mod.SOCQueryService(
            parser=GroqSOCIntentParser(
                api_key=_TEST_KEY,
                model=_SOC_MODEL,
                endpoint_base=_BASE,
                http_client=client,
            ),
            executor=SOCQueryExecutor(handlers=_handlers_recent_detections()),
            clock=lambda: NOW,
        )
        resp = svc.query(object(), "show recent detections")
        assert resp.metadata.parser_provider == "groq"
        assert resp.metadata.parser_model == _SOC_MODEL
        assert resp.read_only is True
        assert resp.count == 2


# ---------------------------------------------------------------------------
# Integration smoke test (skipped unless GROQ_API_KEY set)
# ---------------------------------------------------------------------------


@pytest.mark.groq_integration
@pytest.mark.skipif(
    not __import__("os").environ.get("GROQ_API_KEY"),
    reason="GROQ_API_KEY not set; integration test skipped",
)
def test_live_groq_parse() -> None:
    parser = GroqSOCIntentParser()
    result = parser.parse("show me the most recent detections")
    assert result.raw_text
    assert result.provider == "groq"
