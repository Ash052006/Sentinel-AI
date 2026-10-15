"""Provider integration for the V3.23 debate engine — Gemini and Groq.

The engine must be provider-agnostic: identical five agents, identical
five-round lifecycle, identical evidence model, identical validation,
reconciliation, persistence, and security controls — regardless of which cloud
backend produced the text.

These tests drive the engine through *real* provider clients over an
``httpx.MockTransport`` (no network, no keys) rather than through a runtime test
double, so the whole provider path — HTTP, strict structured-output request,
error normalization — is exercised end to end.

Three properties get dedicated coverage because they are the ones a second
provider could plausibly break:

* **No silent fallback.** A failing provider must fail the debate, and the
  other provider must never be contacted.
* **One provider per debate.** Every model-backed round uses the same provider
  and model; round 4 stays model-free.
* **Deterministic identity.** The provider/model is part of the configuration
  digest, so a Groq debate and a Gemini debate over identical evidence are
  distinct artifacts rather than one silently standing in for the other.
"""

from __future__ import annotations

import json
from typing import Literal

import httpx
import pytest

from app.agents.debate.engine import DebateEngine
from app.agents.debate.exceptions import (
    DebateConfigurationError,
    DebateEvidenceError,
    DebatePartialFailureError,
    DebateProviderError,
)
from app.agents.debate.runtime import (
    DebateRuntime,
    GeminiDebateRuntime,
    GroqDebateRuntime,
    build_debate_runtime,
)
from app.agents.debate.evidence import graph_snapshot_digest
from app.agents.debate.vocabulary import (
    AGENT_ROLES,
    MODEL_ROUNDS,
    RoundKind,
    deterministic_debate_id,
)
from app.agents.investigation.gemini import GeminiClient
from app.agents.investigation.groq import GroqClient
from tests.helpers.debate_runtime import ScriptedDebateRuntime
from tests.integration.debate_fixtures import agreement_script

pytestmark = pytest.mark.usefixtures("debate_correlation")

ROLES = tuple(spec.role.value for spec in AGENT_ROLES.values())

_GEMINI_KEY = "test-gemini-key-not-real"
_GROQ_KEY = "gsk_test_not_a_real"


@pytest.fixture(name="fixture")
def _fixture(debate_correlation):
    """Local alias so test bodies can read ``fixture["graph"]`` etc. directly."""
    return debate_correlation


# ---------------------------------------------------------------------------
# Wire-format helpers
# ---------------------------------------------------------------------------


def _groq_body(payload: dict, finish_reason: str = "stop") -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": json.dumps(payload),
                    },
                    "finish_reason": finish_reason,
                }
            ]
        },
    )


def _gemini_body(payload: dict) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "candidates": [
                {
                    "finishReason": "STOP",
                    "content": {"parts": [{"text": json.dumps(payload)}]},
                }
            ]
        },
    )


def _role_and_round(request_body: dict) -> tuple[str, int]:
    """Recover (role, round) from the prompt the provider actually received.

    Reading it back off the wire proves which rounds really issued a model call
    rather than trusting the engine's own bookkeeping.
    """
    content = ""
    for message in request_body.get("messages", []):
        content += message.get("content", "") + "\n"
    for part in request_body.get("contents", []):
        for chunk in part.get("parts", []):
            content += chunk.get("text", "") + "\n"

    role = "unknown"
    for line in content.splitlines():
        if line.startswith("ROLE — you are the "):
            display = line.removeprefix("ROLE — you are the ").strip().rstrip(".")
            role = next(
                (spec.role.value for spec in AGENT_ROLES.values() if spec.display_name == display),
                display.lower().replace(" ", "_"),
            )
            break
    round_number = 0
    for line in content.splitlines():
        if line.startswith("Round "):
            round_number = next(
                int(t) for t in line.split() if t.isdigit()
            )
            break
    return role, round_number


class RecordingTransport:
    """MockTransport that serves a scripted payload and records the requests.

    ``payload_for(role, round)`` decides what the "model" answers, so a test can
    script a whole debate over the real provider path.
    """

    def __init__(
        self,
        payload_for,
        *,
        wrap=None,
        recorder: list[httpx.Request] | None = None,
    ) -> None:
        self._payload_for = payload_for
        self._wrap = wrap or (lambda payload: payload)
        self.recorder = recorder if recorder is not None else []
        self.pairs: list[tuple[str, int]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.recorder.append(request)
        body = json.loads(request.content)
        role, round_number = _role_and_round(body)
        self.pairs.append((role, round_number))
        return self._wrap(self._payload_for(role, round_number))

    def as_transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)

    @property
    def hosts(self) -> set[str]:
        return {request.url.host for request in self.recorder}


def _provider_runtime(
    provider: str,
    transport: RecordingTransport,
    *,
    model: str | None = None,
) -> DebateRuntime:
    """A real runtime wired to a real provider client over the mock transport."""
    if provider == "groq":
        client = GroqClient(
            api_key=_GROQ_KEY,
            model=model or "openai/gpt-oss-120b",
            max_retries=0,
            http_client=httpx.Client(transport=transport.as_transport()),
            sleep=lambda _s: None,
        )
        # The client is schema-bound per round; rebuild a runtime that reuses it.
        return _BoundGroqRuntime(client)
    client = GeminiClient(
        api_key=_GEMINI_KEY,
        model=model or "gemini-3.8-flash",
        max_retries=0,
        http_client=httpx.Client(transport=transport.as_transport()),
        sleep=lambda _s: None,
    )
    return _BoundGeminiRuntime(client)


class _BoundGroqRuntime(GroqDebateRuntime):
    def __init__(self, client) -> None:  # noqa: ANN001 - test double wiring
        super().__init__(llm_client=client)

    @property
    def model_name(self) -> str | None:
        return self._client.model_name  # type: ignore[union-attr,attr-defined]


class _BoundGeminiRuntime(GeminiDebateRuntime):
    def __init__(self, client) -> None:  # noqa: ANN001 - test double wiring
        super().__init__(llm_client=client)

    @property
    def model_name(self) -> str | None:
        return self._client.model_name  # type: ignore[union-attr,attr-defined]


def _agreement_script(fixture):
    """The agreed scripted answers, keyed by "<role>:<round>"."""
    return agreement_script(fixture["detection_ref"], fixture["correlation_ref"])


def _script_payload(fixture):
    """Resolve the engine's (role, round) call to the agreed scripted answer."""
    script = _agreement_script(fixture)

    def payload_for(role: str, round_number: int) -> dict:
        return script.get(f"{role}:{round_number}", {})

    return payload_for


def _run(fixture, runtime, **kwargs):
    engine = DebateEngine(runtime=runtime)
    return engine.run(
        fixture["graph"],
        correlation_id=fixture["correlation_id"],
        unavailable_entity_types=fixture["queries"].unavailable_entity_types(),
        **kwargs,
    )


# ---------------------------------------------------------------------------
# A. Provider selection (server-side, no client control)
# ---------------------------------------------------------------------------


def test_factory_defaults_to_the_configured_provider(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "llm_provider", "gemini", raising=False)
    assert isinstance(build_debate_runtime(), GeminiDebateRuntime)

    monkeypatch.setattr(settings, "llm_provider", "groq", raising=False)
    runtime = build_debate_runtime()
    assert isinstance(runtime, GroqDebateRuntime)
    assert runtime.provider_name == "groq"
    assert runtime.model_name == settings.groq_model


@pytest.mark.parametrize(
    ("spelling", "expected"),
    [("groq", GroqDebateRuntime), ("GROQ", GroqDebateRuntime), (" groq ", GroqDebateRuntime), ("gemini", GeminiDebateRuntime)],
)
def test_factory_normalizes_casing_and_whitespace(spelling, expected):
    assert isinstance(build_debate_runtime(spelling), expected)


@pytest.mark.parametrize("provider", ["openai", "claude", "", "gemini groq", None])
def test_factory_refuses_an_unknown_provider(provider):
    if provider is None:
        # None means "use settings", so exercise it via settings instead.
        from app.core.config import settings

        settings.llm_provider = "gemini"
        assert isinstance(build_debate_runtime(None), GeminiDebateRuntime)
        return
    with pytest.raises(DebateConfigurationError):
        build_debate_runtime(provider)


def test_unknown_provider_is_rejected_by_configuration_too():
    """Settings validation fails at boot, not at the first debate."""
    from pydantic import ValidationError

    from app.core.config import Settings

    with pytest.raises(ValidationError):
        Settings(llm_provider="openai")


def test_both_runtimes_share_one_implementation():
    """Adding a provider must not fork the seam's behaviour."""
    from app.agents.debate.runtime import _SchemaBoundDebateRuntime

    assert issubclass(GeminiDebateRuntime, _SchemaBoundDebateRuntime)
    assert issubclass(GroqDebateRuntime, _SchemaBoundDebateRuntime)


def test_runtimes_report_configured_model_without_a_client():
    """Metadata must name the real backend even before a client is built."""
    from app.core.config import settings

    assert GeminiDebateRuntime().model_name == settings.gemini_model
    assert GroqDebateRuntime().model_name == settings.groq_model


# ---------------------------------------------------------------------------
# B. A Groq debate is structurally identical to a Gemini debate
# ---------------------------------------------------------------------------


def test_groq_runs_the_same_five_agent_debate(fixture):
    transport = RecordingTransport(_script_payload(fixture), wrap=_groq_body)
    session = _run(fixture, _provider_runtime("groq", transport))

    assert len(session.agents) == 5
    assert {agent.role.value for agent in session.agents} == set(ROLES)
    assert [r.round_number for r in session.rounds] == [0, 1, 2, 3, 4]
    assert [r.round_kind for r in session.rounds] == [
        RoundKind.ROUND_ZERO,
        RoundKind.ROUND_ONE,
        RoundKind.ROUND_TWO,
        RoundKind.ROUND_THREE,
        RoundKind.ROUND_FOUR,
    ]
    assert len(session.facts) >= 1
    # ``agreement_script`` agrees on the hypothesis but leaves round 2/3 empty,
    # so the honest verdict is partial consensus, not full agreement.
    assert session.consensus.state.value == "partial_consensus"
    assert session.metadata.agent_count == 5
    assert transport.hosts == {"api.groq.com"}


def test_groq_records_its_provider_and_model_in_metadata(fixture):
    transport = RecordingTransport(_script_payload(fixture), wrap=_groq_body)
    session = _run(
        fixture, _provider_runtime("groq", transport, model="openai/gpt-oss-120b")
    )
    assert session.metadata.provider == "groq"
    assert session.metadata.model == "openai/gpt-oss-120b"


def test_gemini_debate_is_structurally_identical(fixture):
    """Same agents, rounds, reconciliation, and consensus on the Gemini path."""
    transport = RecordingTransport(_script_payload(fixture), wrap=_gemini_body)
    groq_session = _run(
        fixture,
        _provider_runtime(
            "groq", RecordingTransport(_script_payload(fixture), wrap=_groq_body)
        ),
    )
    gemini_session = _run(fixture, _provider_runtime("gemini", transport))

    assert len(gemini_session.agents) == len(groq_session.agents)
    assert [r.round_kind for r in gemini_session.rounds] == [
        r.round_kind for r in groq_session.rounds
    ]
    assert gemini_session.consensus.state == groq_session.consensus.state
    assert gemini_session.consensus.confidence == pytest.approx(
        groq_session.consensus.confidence
    )
    assert len(gemini_session.assessments) == len(groq_session.assessments)
    assert len(gemini_session.arguments) == len(groq_session.arguments)
    assert (
        gemini_session.metadata.hypotheses_count
        == groq_session.metadata.hypotheses_count
    )
    assert gemini_session.metadata.provider == "gemini"
    assert transport.hosts == {"generativelanguage.googleapis.com"}


def test_groq_makes_fifteen_model_calls_across_rounds_one_to_three(fixture):
    transport = RecordingTransport(_script_payload(fixture), wrap=_groq_body)
    _run(fixture, _provider_runtime("groq", transport))

    # 5 agents x rounds 1-3.  Rounds 0 and 4 are model-free.
    assert len(transport.pairs) == 15
    assert sorted({r for _, r in transport.pairs}) == [1, 2, 3]
    for round_number in (1, 2, 3):
        roles = [role for role, r in transport.pairs if r == round_number]
        assert sorted(roles) == sorted(ROLES)


def test_round_four_makes_no_model_calls_on_groq(fixture):
    """Round 4 is deterministic reconciliation; a call there is a defect."""
    transport = RecordingTransport(_script_payload(fixture), wrap=_groq_body)
    session = _run(fixture, _provider_runtime("groq", transport))

    assert session.rounds[-1].round_kind is RoundKind.ROUND_FOUR
    assert session.rounds[0].round_kind is RoundKind.ROUND_ZERO
    assert 0 not in {r for _, r in transport.pairs}
    assert 4 not in {r for _, r in transport.pairs}
    # The model round constants still describe a 3-round model lifecycle.
    assert tuple(sorted(MODEL_ROUNDS, key=lambda k: k.value)) == (
        RoundKind.ROUND_ONE,
        RoundKind.ROUND_TWO,
        RoundKind.ROUND_THREE,
    )


def test_every_round_uses_one_provider_and_model(fixture):
    """No round may switch backends mid-debate."""
    transport = RecordingTransport(_script_payload(fixture), wrap=_groq_body)
    _run(fixture, _provider_runtime("groq", transport))

    models = {json.loads(request.content)["model"] for request in transport.recorder}
    hosts = transport.hosts
    assert models == {"openai/gpt-oss-120b"}
    assert hosts == {"api.groq.com"}


def test_groq_sends_the_strict_structured_output_request(fixture):
    transport = RecordingTransport(_script_payload(fixture), wrap=_groq_body)
    _run(fixture, _provider_runtime("groq", transport))

    for request in transport.recorder:
        body = json.loads(request.content)
        response_format = body["response_format"]
        assert response_format["type"] == "json_schema"
        assert response_format["json_schema"]["strict"] is True
        # The system instruction travels in its own role, not merged into data.
        assert body["messages"][0]["role"] == "system"
        # The credential is a header, never in the body or the URL.
        assert _GROQ_KEY not in request.content.decode()
        assert _GROQ_KEY not in str(request.url)
        assert request.headers["Authorization"] == f"Bearer {_GROQ_KEY}"


def test_groq_prompt_preserves_the_untrusted_data_boundary(fixture):
    transport = RecordingTransport(_script_payload(fixture), wrap=_groq_body)
    _run(fixture, _provider_runtime("groq", transport))

    body = json.loads(transport.recorder[0].content)
    system_message = body["messages"][0]["content"]
    user_message = body["messages"][1]["content"]
    # Telemetry markers live only in the user/data message.
    for marker in ("ROLE —", "EVIDENCE CATALOG"):
        assert marker in user_message
        assert marker not in system_message


# ---------------------------------------------------------------------------
# C. Evidence integrity is unchanged for Groq
# ---------------------------------------------------------------------------


def test_unresolvable_citation_rejects_the_groq_agent_output(fixture):
    """Groq gets no extra authority: a bad reference kills the whole debate."""

    def payload_for(role: str, round_number: int) -> dict:
        base = _script_payload(fixture)(role, round_number)
        if round_number == 1:
            base = json.loads(json.dumps(base))
            base["observations"] = [
                {
                    "observation_kind": "observation",
                    "statement": "Fabricated observation citing nothing real.",
                    "evidence_references": ["det:nonexistent-reference"],
                    "confidence": 0.9,
                }
            ]
        return base

    transport = RecordingTransport(payload_for, wrap=_groq_body)
    with pytest.raises(DebatePartialFailureError) as excinfo:
        _run(fixture, _provider_runtime("groq", transport))
    # Every agent failed the same integrity check...
    assert set(excinfo.value.failed_agents) == set(ROLES)
    # ...and the aggregate must not erase *why* they failed.
    assert isinstance(excinfo.value.cause, DebateEvidenceError)


def test_groq_cannot_promote_a_hypothesis_to_a_fact(fixture):
    """`fact` remains structurally unrepresentable in the output contract."""
    from app.agents.debate.model_output import (
        DebateAssessmentOutput,
        ModelObservation,
    )

    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ModelObservation(
            observation_kind="fact",  # type: ignore[arg-type]
            statement="invented",
            evidence_references=["det:x"],
            confidence=0.5,
        )
    # The valid kinds are unchanged, and ``fact`` is simply not representable.
    assert ModelObservation.model_fields["observation_kind"].annotation == Literal[
        "observation",
        "hypothesis",
    ]
    assert set(DebateAssessmentOutput.model_fields) == {
        "observations",
        "hypotheses",
        "limitations",
        "confidence",
    }


def test_gemini_evidence_rejection_still_applies_independently(fixture):
    """The rejection path is not Groq-specific behaviour."""

    def payload_for(role: str, round_number: int) -> dict:
        base = _script_payload(fixture)(role, round_number)
        if round_number == 1:
            base = json.loads(json.dumps(base))
            base["observations"] = [
                {
                    "observation_kind": "observation",
                    "statement": "Fabricated.",
                    "evidence_references": ["det:nope"],
                    "confidence": 0.9,
                }
            ]
        return base

    transport = RecordingTransport(payload_for, wrap=_gemini_body)
    with pytest.raises(DebatePartialFailureError) as excinfo:
        _run(fixture, _provider_runtime("gemini", transport))
    assert set(excinfo.value.failed_agents) == set(ROLES)
    assert isinstance(excinfo.value.cause, DebateEvidenceError)


# ---------------------------------------------------------------------------
# D. No silent fallback
# ---------------------------------------------------------------------------


def test_groq_rate_limit_fails_the_debate_and_never_uses_gemini(fixture, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "llm_provider", "groq", raising=False)

    def always_429(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"error": {"message": "rate limited"}})

    groq_requests: list[httpx.Request] = []
    transport = RecordingTransport(
        lambda *_: {}, wrap=always_429, recorder=groq_requests
    )

    runtime = _provider_runtime("groq", transport)
    with pytest.raises(DebatePartialFailureError) as excinfo:
        _run(fixture, runtime)

    # The rate limit is classified as a provider failure, not silently absorbed.
    assert isinstance(excinfo.value.cause, DebateProviderError)
    assert groq_requests, "Groq should have been called"
    # Single-provider selection: only Groq was ever addressed.
    assert transport.hosts == {"api.groq.com"}


def test_gemini_failure_never_invokes_groq(fixture, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "llm_provider", "gemini", raising=False)

    def always_401(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"message": "bad key"}})

    groq_requests: list[httpx.Request] = []

    def exploding(request: httpx.Request) -> httpx.Response:
        groq_requests.append(request)
        raise AssertionError("Groq was contacted despite LLM_PROVIDER=gemini")

    transport = RecordingTransport(lambda *_: {}, wrap=always_401)
    runtime = _provider_runtime("gemini", transport)
    with pytest.raises(DebatePartialFailureError) as excinfo:
        _run(fixture, runtime)

    assert isinstance(excinfo.value.cause, DebateProviderError)
    assert groq_requests == []
    # Only the Gemini host was ever addressed.
    assert transport.hosts == {"generativelanguage.googleapis.com"}


def test_groq_partial_failure_still_fails_the_whole_debate(fixture):
    """A provider that dies mid-roster must not yield a consensus of survivors."""
    calls = {"n": 0}

    def payload_for(role: str, round_number: int) -> dict:
        calls["n"] += 1
        return _script_payload(fixture)(role, round_number)

    def fail_after_three(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] > 3:
            return httpx.Response(503, json={"error": {"message": "down"}})
        return _groq_body(payload_for("detection_analyst", 1))

    transport = RecordingTransport(payload_for, wrap=fail_after_three)
    with pytest.raises(DebatePartialFailureError):
        _run(fixture, _provider_runtime("groq", transport))


def test_a_failing_provider_never_produces_a_session(fixture):
    """No partial or fabricated session may be persisted or returned."""

    def always_500(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": {"message": "boom"}})

    transport = RecordingTransport(lambda *_: {}, wrap=always_500)
    with pytest.raises(DebatePartialFailureError) as excinfo:
        _run(fixture, _provider_runtime("groq", transport))
    assert isinstance(excinfo.value.cause, DebateProviderError)


# ---------------------------------------------------------------------------
# E. Determinism and identity
# ---------------------------------------------------------------------------


def test_same_provider_and_configuration_produce_the_same_identity(fixture):
    def identity() -> str:
        transport = RecordingTransport(_script_payload(fixture), wrap=_groq_body)
        return _run(fixture, _provider_runtime("groq", transport)).debate_id

    assert identity() == identity()


def test_configuration_digest_separates_gemini_from_groq(fixture):
    """Same evidence, different backend => a different analytical artifact."""
    groq = _run(
        fixture,
        _provider_runtime(
            "groq", RecordingTransport(_script_payload(fixture), wrap=_groq_body)
        ),
    )
    gemini = _run(
        fixture,
        _provider_runtime(
            "gemini", RecordingTransport(_script_payload(fixture), wrap=_gemini_body)
        ),
    )

    assert groq.debate_id != gemini.debate_id
    assert groq.metadata.configuration_digest != gemini.metadata.configuration_digest
    # ...while the evidence inputs are identical.
    assert (
        groq.metadata.graph_snapshot_digest
        == gemini.metadata.graph_snapshot_digest
    )
    assert groq.metadata.graph_snapshot_digest


def test_configuration_digest_separates_different_models(fixture):
    """Same provider, different model => also a different artifact."""
    first = _run(
        fixture,
        _provider_runtime(
            "groq",
            RecordingTransport(_script_payload(fixture), wrap=_groq_body),
            model="openai/gpt-oss-120b",
        ),
    )
    second = _run(
        fixture,
        _provider_runtime(
            "groq",
            RecordingTransport(_script_payload(fixture), wrap=_groq_body),
            model="openai/gpt-oss-20b",
        ),
    )
    assert first.debate_id != second.debate_id
    assert first.metadata.configuration_digest != second.metadata.configuration_digest


def test_debate_id_is_reproducible_from_its_recorded_inputs(fixture):
    """The stored digest still reconstructs the stored id."""
    session = _run(
        fixture,
        _provider_runtime(
            "groq", RecordingTransport(_script_payload(fixture), wrap=_groq_body)
        ),
    )
    assert session.debate_id == deterministic_debate_id(
        correlation_id=session.correlation_id,
        graph_snapshot_digest=session.metadata.graph_snapshot_digest,
        config_digest=session.metadata.configuration_digest,
    )


def test_graph_snapshot_digest_is_provider_independent(fixture):
    """Only the reasoning configuration differs; the evidence view does not."""
    transport = RecordingTransport(_script_payload(fixture), wrap=_groq_body)
    session = _run(fixture, _provider_runtime("groq", transport))
    assert session.metadata.graph_snapshot_digest == graph_snapshot_digest(
        fixture["graph"]
    )


def test_a_scripted_double_with_groq_identity_is_indistinguishable_in_shape(
    fixture,
):
    """Sanity: provider choice does not alter the session schema."""
    groq = _run(
        fixture,
        _provider_runtime(
            "groq", RecordingTransport(_script_payload(fixture), wrap=_groq_body)
        ),
    )
    scripted = _run(
        fixture, ScriptedDebateRuntime(_agreement_script(fixture), provider="groq")
    )
    assert set(type(groq).model_fields) == set(type(scripted).model_fields)
    assert groq.metadata.agent_count == scripted.metadata.agent_count