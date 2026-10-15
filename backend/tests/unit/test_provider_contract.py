"""Common LLM-provider contract tests — Gemini and Groq.

The V3.23 debate engine depends on one abstraction, so the properties it relies
on must hold for *every* provider that implements it.  Rather than duplicating a
provider's whole test suite, this module states the contract once and runs it
against both providers.

The contract is deliberately narrow — only what the debate engine actually
needs:

* a non-secret provider/model identity;
* raw response text returned untouched (validation is the caller's job);
* identical exception *types* for the same class of failure, so the engine and
  the API can classify a failure without knowing which provider produced it;
* bounded retries that are spent on transient failures and never on ones a
  repeat cannot fix;
* an explicit output bound;
* no credential in metadata, payload, or exception text.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable

import httpx
import pytest

from app.agents.investigation.exceptions import (
    InvestigationModelOutputError,
    InvestigationProviderError,
    InvestigationProviderTimeoutError,
    InvestigationProviderUnavailableError,
)
from app.agents.investigation.gemini import GeminiClient
from app.agents.investigation.groq import GroqClient
from app.agents.investigation.llm_client import InvestigationLLMClient
from app.agents.investigation.prompt import InvestigationPrompt
from app.core.config import settings

_GEMINI_KEY = "test-gemini-key-not-real"
_GROQ_KEY = "gsk_test_not_a_real"
_RAW = '{"findings": [], "observations": []}'


def _prompt(text: str = "reason about context") -> InvestigationPrompt:
    return InvestigationPrompt(
        system_instruction="you are the investigator", content=text
    )


def _persistent(
    response: Callable[[httpx.Request], httpx.Response]
    | httpx.Response,
    recorder: list[httpx.Request] | None = None,
) -> httpx.MockTransport:
    if not callable(response):
        fixed = response

        def response(request: httpx.Request) -> httpx.Response:  # type: ignore[misc]
            return fixed

    def handler(request: httpx.Request) -> httpx.Response:
        if recorder is not None:
            recorder.append(request)
        return response(request)

    return httpx.MockTransport(handler)


def _once(
    responses: list[httpx.Response], recorder: list[httpx.Request] | None = None
) -> httpx.MockTransport:
    queue = list(responses)

    def handler(request: httpx.Request) -> httpx.Response:
        if recorder is not None:
            recorder.append(request)
        return queue.pop(0)

    return httpx.MockTransport(handler)


@dataclass(frozen=True)
class ProviderUnderTest:
    """Wire-format adapter so one contract can span two different APIs."""

    label: str
    api_key: str
    default_model: str
    client_class: type
    #: Build a well-formed success response carrying *content*.
    success: Callable[[str], httpx.Response]
    #: Build a response that is valid HTTP but not a usable completion.
    unusable: Callable[[], httpx.Response]
    #: Build a response whose generation was cut off / not cleanly finished.
    truncated: Callable[[], httpx.Response]
    #: Build an HTTP *n* response.
    status: Callable[[int], httpx.Response]
    #: Read the generation-bound field out of a captured request payload.
    output_bound: Callable[[dict], int]


def _gemini_success(content: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "candidates": [
                {
                    "finishReason": "STOP",
                    "content": {"parts": [{"text": content}]},
                }
            ]
        },
    )


def _gemini_unusable() -> httpx.Response:
    return httpx.Response(200, json={"candidates": []})


def _gemini_truncated() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "candidates": [
                {
                    "finishReason": "MAX_TOKENS",
                    "content": {"parts": [{"text": '{"findings": ['}]},
                }
            ]
        },
    )


def _gemini_status(status_code: int) -> httpx.Response:
    return httpx.Response(status_code, json={"error": {"message": "denied"}})


def _gemini_bound(payload: dict) -> int:
    return payload["generationConfig"]["maxOutputTokens"]


def _groq_success(content: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }
            ]
        },
    )


def _groq_unusable() -> httpx.Response:
    return httpx.Response(200, json={"choices": []})


def _groq_truncated() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "choices": [
                {
                    "message": {"content": '{"findings": ['},
                    "finish_reason": "length",
                }
            ]
        },
    )


def _groq_status(status_code: int) -> httpx.Response:
    return httpx.Response(status_code, json={"error": {"message": "denied"}})


def _groq_bound(payload: dict) -> int:
    return payload["max_completion_tokens"]


PROVIDERS = [
    ProviderUnderTest(
        label="gemini",
        api_key=_GEMINI_KEY,
        default_model="gemini-3.8-flash",
        client_class=GeminiClient,
        success=_gemini_success,
        unusable=_gemini_unusable,
        truncated=_gemini_truncated,
        status=_gemini_status,
        output_bound=_gemini_bound,
    ),
    ProviderUnderTest(
        label="groq",
        api_key=_GROQ_KEY,
        default_model="openai/gpt-oss-120b",
        client_class=GroqClient,
        success=_groq_success,
        unusable=_groq_unusable,
        truncated=_groq_truncated,
        status=_groq_status,
        output_bound=_groq_bound,
    ),
]

_IDS = [p.label for p in PROVIDERS]


def _client(
    provider: ProviderUnderTest,
    transport: httpx.MockTransport,
    *,
    max_retries: int = 2,
    sleeps: list[float] | None = None,
    model: str | None = None,
    **kwargs,
) -> InvestigationLLMClient:
    return provider.client_class(
        api_key=provider.api_key,
        model=model or provider.default_model,
        max_retries=max_retries,
        http_client=httpx.Client(transport=transport),
        sleep=(sleeps.append if sleeps is not None else (lambda _s: None)),
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Contract: identity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("provider", PROVIDERS, ids=_IDS)
def test_satisfies_the_abstract_client_contract(provider):
    assert isinstance(_client(provider, _once([provider.success(_RAW)])), InvestigationLLMClient)


@pytest.mark.parametrize("provider", PROVIDERS, ids=_IDS)
def test_reports_its_own_non_secret_identity(provider):
    client = _client(provider, _once([provider.success(_RAW)]))
    assert client.provider_name == provider.label
    assert client.model_name == provider.default_model
    # Neither identity field may contain the credential.
    assert provider.api_key not in str(client.provider_name)
    assert provider.api_key not in str(client.model_name)


@pytest.mark.parametrize("provider", PROVIDERS, ids=_IDS)
def test_model_name_comes_from_configuration_when_not_given(provider):
    client = provider.client_class(api_key=provider.api_key)
    expected = (
        settings.gemini_model if provider.label == "gemini" else settings.groq_model
    )
    assert client.model_name == expected


@pytest.mark.parametrize("provider", PROVIDERS, ids=_IDS)
def test_missing_api_key_fails_the_same_way_for_every_provider(provider, monkeypatch):
    # Both clients resolve a blank explicit key from settings, so the settings
    # value has to be cleared to exercise the genuinely-unconfigured path.
    monkeypatch.setattr(settings, "gemini_api_key", "", raising=False)
    monkeypatch.setattr(settings, "groq_api_key", "", raising=False)
    with pytest.raises(Exception) as excinfo:
        provider.client_class(api_key="", model=provider.default_model)
    # Same exception type across providers, so callers classify uniformly.
    assert type(excinfo.value).__name__ == "InvestigationConfigurationError"


# ---------------------------------------------------------------------------
# Contract: raw text out, validation left to the caller
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("provider", PROVIDERS, ids=_IDS)
def test_returns_raw_response_text_verbatim(provider):
    """The provider must not parse, repair, or sanitize the model's text."""
    client = _client(provider, _once([provider.success(_RAW)]))
    assert client.generate(_prompt()) == _RAW


@pytest.mark.parametrize("provider", PROVIDERS, ids=_IDS)
def test_does_not_validate_the_payload_on_the_callers_behalf(provider):
    """Structurally invalid JSON is returned as-is, not rejected here.

    A provider that "helpfully" validated output would move a security-relevant
    decision out of the engine, where evidence citation resolution happens.
    """
    nonsense = "this is not json at all"
    client = _client(provider, _once([provider.success(nonsense)]))
    assert client.generate(_prompt()) == nonsense


@pytest.mark.parametrize("provider", PROVIDERS, ids=_IDS)
def test_unusable_success_response_is_a_provider_error(provider):
    client = _client(provider, _once([provider.unusable()]))
    with pytest.raises(InvestigationProviderError):
        client.generate(_prompt())


@pytest.mark.parametrize("provider", PROVIDERS, ids=_IDS)
def test_truncated_generation_is_rejected_not_partially_accepted(provider):
    """Both providers must refuse a cut-off generation."""
    client = _client(provider, _once([provider.truncated()]))
    with pytest.raises(InvestigationModelOutputError):
        client.generate(_prompt())


@pytest.mark.parametrize("provider", PROVIDERS, ids=_IDS)
def test_rejects_a_non_prompt(provider):
    with pytest.raises(TypeError):
        _client(provider, _once([provider.success(_RAW)])).generate(  # type: ignore[arg-type]
            "just a string"
        )


# ---------------------------------------------------------------------------
# Contract: identical error normalization
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("provider", PROVIDERS, ids=_IDS)
def test_authentication_failure_is_not_retried(provider):
    recorder: list[httpx.Request] = []
    sleeps: list[float] = []
    client = _client(
        provider, _persistent(provider.status(401), recorder), sleeps=sleeps
    )
    with pytest.raises(InvestigationProviderError):
        client.generate(_prompt())
    assert len(recorder) == 1
    assert sleeps == []


@pytest.mark.parametrize("provider", PROVIDERS, ids=_IDS)
def test_timeout_maps_to_the_timeout_error(provider):
    def timeout(_request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("read timed out")

    client = _client(provider, _persistent(timeout), max_retries=1)
    with pytest.raises(InvestigationProviderTimeoutError):
        client.generate(_prompt())


@pytest.mark.parametrize("provider", PROVIDERS, ids=_IDS)
def test_transport_failure_maps_to_unavailable(provider):
    def broken(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    client = _client(provider, _persistent(broken), max_retries=1)
    with pytest.raises(InvestigationProviderUnavailableError):
        client.generate(_prompt())


@pytest.mark.parametrize("provider", PROVIDERS, ids=_IDS)
def test_rate_limit_exhaustion_is_bounded_and_never_fake_success(provider):
    recorder: list[httpx.Request] = []
    client = _client(
        provider,
        _persistent(provider.status(429), recorder),
        max_retries=2,
    )
    with pytest.raises(InvestigationProviderUnavailableError):
        client.generate(_prompt())
    assert len(recorder) == 3  # initial attempt + exactly two retries


@pytest.mark.parametrize("provider", PROVIDERS, ids=_IDS)
def test_server_error_is_retried_then_unavailable(provider):
    recorder: list[httpx.Request] = []
    client = _client(
        provider, _persistent(provider.status(503), recorder), max_retries=1
    )
    with pytest.raises(InvestigationProviderUnavailableError):
        client.generate(_prompt())
    assert len(recorder) == 2


@pytest.mark.parametrize("provider", PROVIDERS, ids=_IDS)
def test_transient_failure_recovers_inside_the_budget(provider):
    client = _client(
        provider, _once([provider.status(503), provider.success(_RAW)]), max_retries=1
    )
    assert client.generate(_prompt()) == _RAW


@pytest.mark.parametrize("provider", PROVIDERS, ids=_IDS)
def test_no_exception_text_ever_contains_the_credential(provider):
    """A provider that reflects the key back must not get it into our logs."""
    leaky = httpx.Response(
        401,
        json={
            "error": {
                "message": f"bad key {provider.api_key}",
                "type": "invalid_request_error",
            }
        },
    )
    for status_code in (401, 400, 429, 500):
        client = _client(
            provider, _persistent(lambda _r, s=status_code: httpx.Response(s, json=leaky.json())), max_retries=0
        )
        with pytest.raises(InvestigationProviderError) as excinfo:
            client.generate(_prompt())
        rendered = f"{excinfo.value}"
        assert provider.api_key not in rendered
        assert "Bearer" not in rendered


# ---------------------------------------------------------------------------
# Contract: bounded output
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("provider", PROVIDERS, ids=_IDS)
def test_request_declares_a_positive_output_bound(provider):
    recorder: list[httpx.Request] = []
    client = _client(provider, _once([provider.success(_RAW)], recorder))
    client.generate(_prompt())
    payload = json.loads(recorder[0].content)
    bound = provider.output_bound(payload)
    assert isinstance(bound, int)
    assert bound > 0


@pytest.mark.parametrize("provider", PROVIDERS, ids=_IDS)
def test_configured_output_bound_is_honoured(provider):
    recorder: list[httpx.Request] = []
    client = _client(
        provider,
        _once([provider.success(_RAW)], recorder),
        max_output_tokens=4096,
    )
    client.generate(_prompt())
    assert provider.output_bound(json.loads(recorder[0].content)) == 4096


# ---------------------------------------------------------------------------
# Contract: the two providers are interchangeable
# ---------------------------------------------------------------------------


def test_both_providers_implement_the_same_interface():
    """A caller holding only the interface can use either provider."""
    clients = [
        p.client_class(api_key=p.api_key, model=p.default_model) for p in PROVIDERS
    ]
    for client in clients:
        assert isinstance(client, InvestigationLLMClient)
        assert client.provider_name in {"gemini", "groq"}
        assert isinstance(client.model_name, str) and client.model_name


def test_provider_labels_are_distinct_so_identity_stays_unambiguous():
    labels = [p.client_class(api_key=p.api_key, model=p.default_model).provider_name
              for p in PROVIDERS]
    assert len(set(labels)) == len(PROVIDERS)