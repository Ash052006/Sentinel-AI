"""Deterministic fake runtimes for debate tests — V3.23.

These are test doubles implementing :class:`~app.agents.debate.runtime.DebateRuntime`.
They let the entire backend suite exercise the full debate lifecycle with no
outbound network access and no Gemini key.

``ScriptedDebateRuntime`` returns canned JSON per (role, round), which is how
consensus states, dissent, and evidence-fabrication rejection are tested
deterministically.  ``FailingDebateRuntime`` and ``FlakyDebateRuntime`` model
the governed-failure and partial-failure paths.

Nothing here is imported by application code.
"""

from __future__ import annotations

import json
from typing import Any

from app.agents.debate.exceptions import (
    DebateProviderError,
    DebateProviderTimeoutError,
    DebateProviderUnavailableError,
)
from app.agents.debate.prompt import DebatePrompt
from app.agents.debate.runtime import DebateRuntime


class ScriptedDebateRuntime(DebateRuntime):
    """Returns a scripted JSON payload for each (role, round) pair.

    ``responses`` maps ``"<role>:<round_number>"`` to either a ``dict`` (JSON
    payload) or a ``str`` (raw text, so malformed-output paths can be tested).
    Any pair with no entry returns an empty-but-valid payload, so a test only
    scripts the rounds it cares about.
    """

    def __init__(
        self,
        responses: dict[str, Any] | None = None,
        *,
        provider: str = "scripted",
        model: str | None = "scripted-model",
    ) -> None:
        self._responses = dict(responses or {})
        self._provider = provider
        self._model = model
        self.calls: list[tuple[str, int]] = []

    @property
    def provider_name(self) -> str:
        return self._provider

    @property
    def model_name(self) -> str | None:
        return self._model

    def complete(self, prompt: DebatePrompt, response_schema: dict[str, Any]) -> str:
        role, round_number = _extract_role_and_round(prompt)
        self.calls.append((role, round_number))
        payload = self._responses.get(f"{role}:{round_number}")
        if payload is None:
            return json.dumps(_EMPTY_BY_ROUND[round_number])
        if isinstance(payload, str):
            return payload
        return json.dumps(payload)


class FailingDebateRuntime(DebateRuntime):
    """Always fails with the configured governed provider error."""

    def __init__(
        self,
        error: Exception | None = None,
        *,
        provider: str = "unavailable",
    ) -> None:
        self._error = error or DebateProviderUnavailableError(
            "provider is unavailable"
        )
        self._provider = provider
        self.call_count = 0

    @property
    def provider_name(self) -> str:
        return self._provider

    def complete(self, prompt: DebatePrompt, response_schema: dict[str, Any]) -> str:
        self.call_count += 1
        raise self._error


class FlakyDebateRuntime(DebateRuntime):
    """Fails for a chosen subset of (role, round) pairs."""

    def __init__(
        self,
        fail_roles: set[str] | None = None,
        *,
        error: Exception | None = None,
        responses: dict[str, Any] | None = None,
    ) -> None:
        self._fail_roles = set(fail_roles or {"skeptic"})
        self._error = error or DebateProviderTimeoutError("provider timed out")
        self._responses = dict(responses or {})

    @property
    def provider_name(self) -> str:
        return "flaky"

    def complete(self, prompt: DebatePrompt, response_schema: dict[str, Any]) -> str:
        role, round_number = _extract_role_and_round(prompt)
        if role in self._fail_roles:
            raise self._error
        payload = self._responses.get(f"{role}:{round_number}")
        return json.dumps(payload if payload is not None else _EMPTY_BY_ROUND[round_number])


_EMPTY_BY_ROUND: dict[int, dict[str, Any]] = {
    1: {
        "observations": [],
        "hypotheses": [],
        "limitations": {"limitations": ["no further assessment recorded"]},
        "confidence": 0.5,
    },
    2: {"arguments": [], "unresolved_questions": []},
    3: {"counterarguments": []},
}


def _extract_role_and_round(prompt: DebatePrompt) -> tuple[str, int]:
    """Recover the role and round number from the built prompt.

    The engine embeds ``ROLE — you are the <display name>`` and
    ``Round N — ...`` in the content, so a test double can key off the real
    prompt rather than requiring the engine to hand it a side-channel.
    """
    content = prompt.content
    role = "unknown"
    for line in content.splitlines():
        if line.startswith("ROLE — you are the "):
            display = line.removeprefix("ROLE — you are the ").strip().rstrip(".")
            role = _ROLE_BY_DISPLAY.get(display, display.lower().replace(" ", "_"))
            break
    round_number = 0
    for line in content.splitlines():
        if line.startswith("Round "):
            for token in line.split():
                if token.isdigit():
                    round_number = int(token)
                    break
            break
    return role, round_number


from app.agents.debate.vocabulary import AGENT_ROLES  # noqa: E402

_ROLE_BY_DISPLAY: dict[str, str] = {
    spec.display_name: spec.role.value for spec in AGENT_ROLES.values()
}


__all__ = [
    "FailingDebateRuntime",
    "FlakyDebateRuntime",
    "ScriptedDebateRuntime",
    "DebateProviderError",
]