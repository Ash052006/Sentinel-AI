"""Groq provider tests — the second cloud reasoning backend.

``GroqClient`` is exercised exclusively through an injected
``httpx.MockTransport`` (no real network, no Groq key required): request shape,
bearer-token auth, structured-output request shape, bounded retry policy
(transient only), error normalization, secret-safe errors, and output
extraction.

Two areas get particular attention because they are where a second provider
could quietly weaken the system:

* :func:`to_groq_strict_json_schema` — the Gemini/OpenAPI -> Groq strict schema
  translation, which must **fail closed** rather than drop a constraint it
  cannot verify.
* failure classification — an authentication or not-found failure must never be
  retried, while genuine back-pressure must be.

A single ``groq_integration`` marked smoke test is skipped unless
``GROQ_API_KEY`` is set.
"""

from __future__ import annotations

import json
import os

import httpx
import pytest

from app.agents.debate.model_output import (
    DEBATE_ARGUMENTS_JSON_SCHEMA,
    DEBATE_ASSESSMENT_JSON_SCHEMA,
    DEBATE_COUNTERARGUMENTS_JSON_SCHEMA,
)
from app.agents.investigation.exceptions import (
    InvestigationConfigurationError,
    InvestigationModelOutputError,
    InvestigationProviderError,
    InvestigationProviderTimeoutError,
    InvestigationProviderUnavailableError,
)
from app.agents.investigation.groq import (
    GroqClient,
    to_groq_strict_json_schema,
)
from app.agents.investigation.model_output import INVESTIGATION_MODEL_JSON_SCHEMA
from app.agents.investigation.prompt import InvestigationPrompt

_API_KEY = "gsk_test_not_a_real_key"
_MODEL = "openai/gpt-oss-120b"
_BASE = "https://api.groq.com"

#: A provider error body that (hostilely) echoes the credential back.  No
#: exception this client raises may contain any of it.
_LEAKY_BODY = {
    "error": {
        "message": (
            f"invalid api key {_API_KEY} for Authorization: Bearer {_API_KEY}"
        ),
        "type": "invalid_request_error",
    }
}


def _prompt(
    text: str = "reason about context",
    *,
    knowledge: str = "",
    memory: str = "",
) -> InvestigationPrompt:
    return InvestigationPrompt(
        system_instruction="you are the investigator",
        content=text,
        knowledge_content=knowledge,
        historical_memory_content=memory,
    )


def _ok(content: str = '{"findings": [], "observations": []}', **extra) -> httpx.Response:
    """A minimal, well-formed Groq chat-completion success response."""
    choice: dict = {
        "index": 0,
        "message": {"role": "assistant", "content": content},
        "finish_reason": "stop",
    }
    choice.update(extra)
    return httpx.Response(200, json={"choices": [choice], "model": _MODEL})


def _transport(
    responses: list[httpx.Response] | httpx.Response | object,
    recorder: list[httpx.Request] | None = None,
) -> httpx.MockTransport:
    """Wrap *responses* in a MockTransport handler.

    A callable is invoked once per request (for stubs that raise on every
    attempt).  A single Response or a list of Responses is served once, popping
    each on request.
    """
    if callable(responses):

        def handler(request: httpx.Request) -> httpx.Response:
            if recorder is not None:
                recorder.append(request)
            return responses(request)

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
    **kwargs,
) -> GroqClient:
    kwargs.setdefault("api_key", _API_KEY)
    kwargs.setdefault("model", _MODEL)
    return GroqClient(
        max_retries=max_retries,
        http_client=httpx.Client(transport=_transport(responses, recorder)),
        sleep=(sleeps.append if sleeps is not None else (lambda _s: None)),
        **kwargs,
    )


# ---------------------------------------------------------------------------
# A. Initialization and configuration
# ---------------------------------------------------------------------------


def test_missing_api_key_is_a_configuration_error(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "groq_api_key", "", raising=False)
    with pytest.raises(InvestigationConfigurationError) as excinfo:
        GroqClient(api_key="", model=_MODEL)
    assert "GROQ_API_KEY" in str(excinfo.value)


def test_api_key_is_read_from_settings_when_absent(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "groq_api_key", _API_KEY, raising=False)
    client = GroqClient(model=_MODEL)
    assert client.provider_name == "groq"


def test_blank_model_is_rejected():
    with pytest.raises(InvestigationConfigurationError):
        GroqClient(api_key=_API_KEY, model="   ")


def test_default_model_comes_from_settings():
    from app.core.config import settings

    client = GroqClient(api_key=_API_KEY)
    assert client.model_name == settings.groq_model
    # Groq model ids are namespace-qualified; an unprefixed id is not valid.
    assert client.model_name.startswith("openai/")


def test_provider_and_model_metadata():
    client = _client(_ok())
    assert client.provider_name == "groq"
    assert client.model_name == _MODEL


@pytest.mark.parametrize(
    "kwargs",
    [
        {"timeout_seconds": 0},
        {"timeout_seconds": -1},
        {"max_retries": -1},
        {"max_output_tokens": 0},
        {"reasoning_effort": "xhigh"},
        {"reasoning_effort": "none"},
    ],
)
def test_invalid_tunables_are_rejected(kwargs):
    with pytest.raises(InvestigationConfigurationError):
        _client(_ok(), **kwargs)


def test_zero_retries_is_allowed():
    client = _client(_ok(), max_retries=0)
    assert client.generate(_prompt()) is not None


# ---------------------------------------------------------------------------
# B. Request shape and authentication
# ---------------------------------------------------------------------------


def test_request_targets_the_chat_completions_endpoint():
    recorder: list[httpx.Request] = []
    _client(_ok(), recorder=recorder).generate(_prompt())
    request = recorder[0]
    assert request.method == "POST"
    assert str(request.url) == f"{_BASE}/openai/v1/chat/completions"


def test_api_key_travels_as_a_bearer_header_and_never_in_the_url():
    recorder: list[httpx.Request] = []
    _client(_ok(), recorder=recorder).generate(_prompt())
    request = recorder[0]
    assert request.headers["Authorization"] == f"Bearer {_API_KEY}"
    assert request.headers["Content-Type"] == "application/json"
    # The credential must not be recoverable from the URL.
    assert _API_KEY not in str(request.url)


def test_payload_requests_strict_structured_output():
    recorder: list[httpx.Request] = []
    _client(_ok(), recorder=recorder).generate(_prompt())
    payload = json.loads(recorder[0].content)

    assert payload["model"] == _MODEL
    assert payload["temperature"] == 0.0
    assert payload["max_completion_tokens"] == 8192
    assert payload["reasoning_effort"] == "low"

    response_format = payload["response_format"]
    assert response_format["type"] == "json_schema"
    assert response_format["json_schema"]["strict"] is True
    assert response_format["json_schema"]["name"].startswith("sentinelai_")
    # The schema actually sent must be the translated, strict-safe one.
    assert response_format["json_schema"]["schema"]["additionalProperties"] is False


def test_payload_separates_the_trusted_system_instruction():
    recorder: list[httpx.Request] = []
    _client(_ok(), recorder=recorder).generate(
        _prompt("TASK BODY", knowledge="KNOWLEDGE BODY")
    )
    payload = json.loads(recorder[0].content)
    messages = payload["messages"]

    assert messages[0]["role"] == "system"
    assert messages[0]["content"] == "you are the investigator"
    assert messages[1]["role"] == "user"
    # Untrusted/reference content stays in the user message, clearly labelled,
    # so it can never be mistaken for instruction.
    assert "TASK BODY" in messages[1]["content"]
    assert "KNOWLEDGE BODY" in messages[1]["content"]
    assert "not evidence" in messages[1]["content"]
    assert "KNOWLEDGE BODY" not in messages[0]["content"]


def test_historical_memory_is_labelled_separately():
    recorder: list[httpx.Request] = []
    _client(_ok(), recorder=recorder).generate(
        _prompt("TASK", memory="MEMORY BODY")
    )
    user_message = json.loads(recorder[0].content)["messages"][1]["content"]
    assert "HISTORICAL INCIDENT MEMORY" in user_message
    assert "MEMORY BODY" in user_message


def test_response_schema_is_copied_so_later_mutation_cannot_change_it():
    schema = dict(INVESTIGATION_MODEL_JSON_SCHEMA)
    recorder: list[httpx.Request] = []
    client = _client(_ok(), recorder=recorder, response_schema=schema)
    schema["type"] = "MUTATED"
    client.generate(_prompt())
    sent = json.loads(recorder[0].content)["response_format"]["json_schema"][
        "schema"
    ]
    assert sent["type"] == "object"


def test_generate_rejects_a_non_prompt():
    with pytest.raises(TypeError):
        _client(_ok()).generate("just a string")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# C. Successful response handling
# ---------------------------------------------------------------------------


def test_returns_raw_response_text_untouched():
    raw = '{"findings": [], "observations": []}'
    assert _client(_ok(raw)).generate(_prompt()) == raw


def test_missing_finish_reason_is_accepted():
    response = httpx.Response(
        200, json={"choices": [{"message": {"content": "{}"}}]}
    )
    assert _client(response).generate(_prompt()) == "{}"


@pytest.mark.parametrize(
    "finish_reason",
    ["length", "content_filter", "tool_calls", "STOP"],
)
def test_non_stop_finish_reason_is_rejected(finish_reason):
    """A truncated generation must not be accepted as if it were complete."""
    response = _ok(finish_reason=finish_reason)
    with pytest.raises(InvestigationModelOutputError):
        _client(response).generate(_prompt())


def test_model_refusal_is_rejected():
    response = httpx.Response(
        200,
        json={
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "refusal": "I cannot help with that.",
                    },
                    "finish_reason": "stop",
                }
            ]
        },
    )
    with pytest.raises(InvestigationModelOutputError):
        _client(response).generate(_prompt())


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"choices": []},
        {"choices": "not-a-list"},
        {"choices": ["not-an-object"]},
        {"choices": [{"no_message": True}]},
        {"choices": [{"message": "not-an-object"}]},
        {"choices": [{"message": {"content": ""}}]},
        {"choices": [{"message": {"content": "   "}}]},
        {"choices": [{"message": {"content": None}}]},
        {"choices": [{"message": {}}]},
    ],
)
def test_malformed_success_payloads_are_rejected(payload):
    with pytest.raises(InvestigationProviderError):
        _client(httpx.Response(200, json=payload)).generate(_prompt())


def test_non_json_body_is_rejected():
    with pytest.raises(InvestigationProviderError):
        _client(httpx.Response(200, text="<html>gateway error</html>")).generate(
            _prompt()
        )


def test_non_object_json_body_is_rejected():
    with pytest.raises(InvestigationProviderError):
        _client(httpx.Response(200, json=[1, 2, 3])).generate(_prompt())


# ---------------------------------------------------------------------------
# D. Error normalization and bounded retries
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "expected_fragment"),
    [
        (401, "authentication failed"),
        (403, "forbidden"),
        (404, "not found"),
        (400, "bad request"),
        (413, "bad request"),
        (422, "bad request"),
        (418, "unexpected HTTP status 418"),
    ],
)
def test_client_errors_are_not_retried_and_map_to_sanitized_messages(
    status, expected_fragment
):
    recorder: list[httpx.Request] = []
    sleeps: list[float] = []
    client = _client(
        httpx.Response(status, json=_LEAKY_BODY), recorder=recorder, sleeps=sleeps
    )
    with pytest.raises(InvestigationProviderError) as excinfo:
        client.generate(_prompt())

    message = str(excinfo.value)
    assert expected_fragment in message
    # Exactly one attempt: nothing a repeat could fix is retried.
    assert len(recorder) == 1
    assert sleeps == []
    # The provider's body is never echoed, so a provider that reflects the
    # credential cannot leak it through an exception message.
    assert _API_KEY not in message


def test_429_is_retried_then_reported_as_unavailable():
    recorder: list[httpx.Request] = []
    sleeps: list[float] = []
    client = _client(
        lambda _r: httpx.Response(
            429, json=_LEAKY_BODY, headers={"retry-after": "2"}
        ),
        recorder=recorder,
        sleeps=sleeps,
        max_retries=2,
    )
    with pytest.raises(InvestigationProviderUnavailableError) as excinfo:
        client.generate(_prompt())

    assert len(recorder) == 3  # initial attempt + 2 bounded retries
    assert _API_KEY not in str(excinfo.value)


def test_429_honours_retry_after_within_bounds():
    sleeps: list[float] = []
    client = _client(
        lambda _r: httpx.Response(
            429,
            json={"error": {"message": "slow down"}},
            headers={"retry-after": "2"},
        ),
        recorder=[],
        sleeps=sleeps,
        max_retries=3,
    )
    with pytest.raises(InvestigationProviderUnavailableError):
        client.generate(_prompt())
    # Groq documents retry-after as delta-seconds, present only on a 429, so
    # the provider's own pacing hint wins over our linear backoff.
    assert sleeps == [2.0, 2.0, 2.0]


def test_hostile_retry_after_cannot_stall_the_request():
    sleeps: list[float] = []
    client = _client(
        lambda _r: httpx.Response(429, json={}, headers={"retry-after": "99999"}),
        recorder=[],
        sleeps=sleeps,
        max_retries=1,
    )
    with pytest.raises(InvestigationProviderUnavailableError):
        client.generate(_prompt())
    assert sleeps == [30.0]  # clamped


def test_unparsable_retry_after_falls_back_to_bounded_backoff():
    sleeps: list[float] = []
    client = _client(
        lambda _r: httpx.Response(
            429, json={}, headers={"retry-after": "Wed, 21 Oct 2099 07:28:00 GMT"}
        ),
        recorder=[],
        sleeps=sleeps,
        max_retries=2,
    )
    with pytest.raises(InvestigationProviderUnavailableError):
        client.generate(_prompt())
    assert sleeps == [1.0, 2.0]


def test_429_recovers_within_the_retry_budget():
    client = _client([httpx.Response(429, json={}), _ok("{}")], max_retries=2)
    assert client.generate(_prompt()) == "{}"


def test_flex_tier_capacity_498_is_treated_as_transient():
    """498 is a 4xx that means back-pressure, not rejection."""
    recorder: list[httpx.Request] = []
    sleeps: list[float] = []
    client = _client(
        lambda _r: httpx.Response(498, json={"error": {"message": "capacity"}}),
        recorder=recorder,
        sleeps=sleeps,
        max_retries=1,
    )
    with pytest.raises(InvestigationProviderUnavailableError):
        client.generate(_prompt())
    assert len(recorder) == 2
    assert sleeps  # backed off, i.e. treated as retryable


@pytest.mark.parametrize("status", [500, 502, 503, 529])
def test_server_errors_are_retried_then_reported_unavailable(status):
    recorder: list[httpx.Request] = []
    client = _client(
        lambda _r: httpx.Response(status, json=_LEAKY_BODY),
        recorder=recorder,
        max_retries=2,
    )
    with pytest.raises(InvestigationProviderUnavailableError) as excinfo:
        client.generate(_prompt())
    assert len(recorder) == 3
    assert _API_KEY not in str(excinfo.value)


def test_server_error_recovers_within_the_retry_budget():
    client = _client([httpx.Response(503, json={}), _ok("{}")], max_retries=1)
    assert client.generate(_prompt()) == "{}"


def test_retries_are_bounded_not_infinite():
    """An always-429 provider must terminate, not spin forever."""
    recorder: list[httpx.Request] = []

    def always_429(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={})

    client = _client(always_429, recorder=recorder, max_retries=3)
    with pytest.raises(InvestigationProviderUnavailableError):
        client.generate(_prompt())
    assert len(recorder) == 4  # 1 + 3, and no more


def test_timeout_is_retried_then_reported_as_timeout():
    recorder: list[httpx.Request] = []

    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("connection timed out")

    client = _client(timeout, recorder=recorder, max_retries=2)
    with pytest.raises(InvestigationProviderTimeoutError):
        client.generate(_prompt())
    assert len(recorder) == 3


def test_transport_error_is_retried_then_reported_unavailable():
    recorder: list[httpx.Request] = []

    def broken(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    client = _client(broken, recorder=recorder, max_retries=1)
    with pytest.raises(InvestigationProviderUnavailableError) as excinfo:
        client.generate(_prompt())
    assert len(recorder) == 2
    assert "ConnectError" in str(excinfo.value)


def test_transport_error_message_does_not_echo_the_url():
    def broken(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"failed talking to {request.url}")

    client = _client(broken, max_retries=0)
    with pytest.raises(InvestigationProviderUnavailableError) as excinfo:
        client.generate(_prompt())
    assert _API_KEY not in str(excinfo.value)


def test_a_rate_limit_never_becomes_a_fake_success():
    """Exhausting the budget must surface as a failure, never as output."""
    client = _client(lambda r: httpx.Response(429, json={}), max_retries=0)
    with pytest.raises(InvestigationProviderUnavailableError):
        client.generate(_prompt())


# ---------------------------------------------------------------------------
# E. Schema translation — the fail-closed guarantee
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "schema",
    [
        DEBATE_ASSESSMENT_JSON_SCHEMA,
        DEBATE_ARGUMENTS_JSON_SCHEMA,
        DEBATE_COUNTERARGUMENTS_JSON_SCHEMA,
        INVESTIGATION_MODEL_JSON_SCHEMA,
    ],
)
def test_every_agent_schema_translates_to_a_strict_schema(schema):
    translated = to_groq_strict_json_schema(schema)

    def assert_strict(node: dict) -> None:
        assert node["type"] in {"object", "array", "string", "number", "integer", "boolean"}
        if node["type"] == "object":
            # Both strict-mode requirements.
            assert node["additionalProperties"] is False
            assert sorted(node["required"]) == sorted(node["properties"])
            for sub in node["properties"].values():
                assert_strict(sub)
        elif node["type"] == "array":
            assert_strict(node["items"])

    assert_strict(translated)


def test_type_tokens_are_lowercased_for_openai_compatibility():
    translated = to_groq_strict_json_schema(
        {"type": "OBJECT", "properties": {"a": {"type": "STRING"}}, "required": ["a"]}
    )
    assert translated == {
        "type": "object",
        "properties": {"a": {"type": "string"}},
        "additionalProperties": False,
        "required": ["a"],
    }


def test_enum_and_description_survive_translation():
    translated = to_groq_strict_json_schema(
        {
            "type": "OBJECT",
            "properties": {
                "stance": {"type": "STRING", "enum": ["supports", "opposes"]}
            },
            "required": ["stance"],
        }
    )
    assert translated["properties"]["stance"]["enum"] == ["supports", "opposes"]


def test_nested_arrays_of_objects_translate():
    translated = to_groq_strict_json_schema(
        {
            "type": "OBJECT",
            "properties": {
                "items": {
                    "type": "ARRAY",
                    "items": {
                        "type": "OBJECT",
                        "properties": {"x": {"type": "NUMBER"}},
                        "required": ["x"],
                    },
                }
            },
            "required": ["items"],
        }
    )
    item = translated["properties"]["items"]["items"]
    assert item["additionalProperties"] is False
    assert item["required"] == ["x"]


def test_optional_property_is_refused_rather_than_silently_promoted():
    """Strict mode cannot express optional fields; inventing one is worse."""
    with pytest.raises(InvestigationConfigurationError) as excinfo:
        to_groq_strict_json_schema(
            {
                "type": "OBJECT",
                "properties": {"a": {"type": "STRING"}, "b": {"type": "STRING"}},
                "required": ["a"],
            }
        )
    assert "'b'" in str(excinfo.value)


@pytest.mark.parametrize(
    "schema",
    [
        {"type": "OBJECT", "properties": {"a": {"type": "STRING"}}},  # missing required
        {"type": "OBJECT"},  # no properties
        {"type": "ARRAY"},  # no items
        {"type": "WIDGET"},  # unknown type
        {"type": "OBJECT", "properties": {"a": {"type": "STRING"}}, "required": ["a", "z"]},
        {"type": ["string", "null"]},  # union spelling
        {"type": "STRING", "$ref": "#/defs/x"},
        {"type": "STRING", "anyOf": [{"type": "STRING"}]},
        {"type": "STRING", "oneOf": [{"type": "STRING"}]},
        {"type": "OBJECT", "properties": {"a": {"type": "STRING", "maxLength": 5}}, "required": ["a"]},
        {"type": "STRING", "pattern": "^a"},
        {"type": "OBJECT", "properties": "nope", "required": []},
        {"type": "STRING", "required": "not-a-list"},
        {"type": "STRING", "enum": []},
        "not-a-dict",
        {"no_type": "STRING"},
    ],
)
def test_untranslatable_schemas_fail_closed(schema):
    with pytest.raises(InvestigationConfigurationError):
        to_groq_strict_json_schema(schema)


def test_a_bad_schema_is_rejected_before_any_request_is_sent():
    """Fail closed at construction, not after contacting the provider."""
    recorder: list[httpx.Request] = []
    with pytest.raises(InvestigationConfigurationError):
        _client(_ok(), recorder=recorder, response_schema={"type": "OBJECT"})
    assert recorder == []


@pytest.mark.parametrize(
    "schema",
    [
        {"type": "STRING", "required": "not-a-list"},
        {"type": "STRING", "properties": {"a": {"type": "STRING"}}},
        {"type": "NUMBER", "items": {"type": "STRING"}},
        {"type": "ARRAY", "properties": {"a": {"type": "STRING"}}},
        # `nullable` is recognised by Gemini but not translated here, so it
        # must be refused rather than silently dropped.
        {"type": "STRING", "nullable": True},
        {"type": "OBJECT", "properties": {"a": {"type": "STRING", "nullable": True}}, "required": ["a"]},
    ],
)
def test_keys_meaningless_for_their_node_type_are_refused(schema):
    """Ignoring a stray key could translate a malformed node into a valid one."""
    with pytest.raises(InvestigationConfigurationError):
        to_groq_strict_json_schema(schema)


def test_translation_is_deterministic():
    schema = DEBATE_ARGUMENTS_JSON_SCHEMA
    assert to_groq_strict_json_schema(schema) == to_groq_strict_json_schema(
        dict(schema)
    )


# ---------------------------------------------------------------------------
# F. Live smoke test (opt-in, no network in the normal suite)
# ---------------------------------------------------------------------------


@pytest.mark.groq_integration
@pytest.mark.skipif(
    os.environ.get("GROQ_API_KEY") is None,
    reason="GROQ_API_KEY not set",
)
def test_live_groq_structured_generation():
    """Minimal connectivity check against the real Groq API.

    Deliberately not a full five-agent debate: establish that Groq works and
    that its output normalizes into the same contract before spending 15 model
    calls on a real debate.
    """
    from app.agents.investigation.groq import GroqClient as LiveClient

    client = LiveClient(
        response_schema={
            "type": "OBJECT",
            "properties": {
                "findings": {"type": "ARRAY", "items": {"type": "STRING"}},
                "observations": {"type": "ARRAY", "items": {"type": "STRING"}},
            },
            "required": ["findings", "observations"],
        }
    )
    text = client.generate(
        InvestigationPrompt(
            system_instruction=(
                "You return JSON matching the supplied schema and nothing else."
            ),
            content=(
                'Return this exact JSON: {"findings": [], "observations": []}'
            ),
        )
    )
    # Provider metadata must be the configured model, not a secret.
    assert client.provider_name == "groq"
    assert client.model_name == os.environ.get("GROQ_MODEL", client.model_name)
    assert json.loads(text) == {"findings": [], "observations": []}
    # The credential must not survive into the returned text.
    assert os.environ["GROQ_API_KEY"] not in text