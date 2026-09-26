"""SOC intent parser abstraction and strict-output orchestration — Step 23.

Natural Language SOC uses an LLM **only** for language understanding,
constrained to produce the structured SOC candidate intent.  The parser

* never executes queries,
* never accesses databases or tools,
* never generates SQL,
* never chooses arbitrary functions,
* never modifies state.

This module defines the :class:`SOCIntentParser` abstraction (the parser
returns a parse result whose payload is RAW structured output — the raw
text is left unvalidated for the caller) and the deterministic
orchestration helpers shared by every concrete parser:

:func:`parse_strict` — strict JSON parse (no fences, no prose, no multiple
objects, no oversized output; malformed output is rejected, never
"repaired", following the Step 12C philosophy);

:func:`validate_candidate` — Pydantic contract validation of the parsed
candidate against :class:`~app.schemas.soc_query.SOCModelIntent`
(unknown/forbidden fields, invalid enums, malformed UUIDs, and bounds all
fail closed);

:func:`assert_candidate_secret_free` — fail-closed credential-shaped
content scan over the serialized candidate.

The concrete :class:`~app.services.soc.gemini.GeminiSOCIntentParser`
adapts the existing Gemini provider for SOC through this abstraction.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

from pydantic import ValidationError

from app.schemas.soc_query import (
    SOC_MAX_MODEL_OUTPUT_BYTES,
    SOCModelIntent,
)
from app.services.soc.errors import (
    SOCModelOutputError,
    SOCModelValidationError,
    SOCSafetyError,
)

#: Credential-shaped substrings the SOC trust boundary refuses.  Kept in
#: lock-step with the project's shared safety vocabulary (api_key /
#: authorization / bearer / secret / password / cookie / session_token / jwt).
SECRET_PATTERNS = (
    "api_key",
    "authorization",
    "bearer",
    "secret",
    "password",
    "cookie",
    "session_token",
    "jwt",
)


class SOCParseResult:
    """One parser outcome.

    ``raw_text`` holds the RAW structured output the parser received
    (provider text, unvalidated).  The payload is deliberately left as raw
    text so that deterministic validation always happens *outside* the
    model, in :func:`parse_strict` / :func:`validate_candidate`.
    """

    __slots__ = ("raw_text", "provider", "model")

    def __init__(
        self,
        *,
        raw_text: str,
        provider: str | None = None,
        model: str | None = None,
    ) -> None:
        self.raw_text = raw_text
        self.provider = provider
        self.model = model


class SOCIntentParser(ABC):
    """Parses user language into a raw structured-output candidate.

    Implementations must raise :class:`~app.services.soc.errors.SOCParserError`
    subclasses for provider/output failures; they must never return partially
    accepted or "repaired" output.
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Provider identifier (e.g. 'gemini'); safe, non-secret."""

    @property
    @abstractmethod
    def model_name(self) -> str | None:
        """Model identifier when known; safe, non-secret."""

    @abstractmethod
    def parse(self, user_query: str) -> SOCParseResult:
        """Return the raw structured output for *user_query*."""


def build_candidate(result: SOCParseResult) -> SOCModelIntent:
    """Turn a raw :class:`SOCParseResult` into a validated candidate intent.

    Orchestrates the strict, deterministic validation chain: raw text ->
    strict JSON -> :class:`SOCModelIntent` contract -> secret scan.  This is
    the layer the LLM output must pass through and nothing is auto-fixed.
    """
    parsed = parse_strict(result.raw_text)
    candidate = validate_candidate(parsed)
    assert_candidate_secret_free(candidate)
    return candidate


def parse_strict(raw_text: str) -> dict[str, Any]:
    """Strict JSON parse: no fences, no prose, no multiple objects.

    Malformed output is rejected, never repaired.
    """
    if not isinstance(raw_text, str):
        raise SOCModelOutputError("model output must be a string")
    text = raw_text.strip()
    if not text:
        raise SOCModelOutputError(
            "model output is empty; the output is rejected rather than accepted"
        )
    if len(text.encode("utf-8")) > SOC_MAX_MODEL_OUTPUT_BYTES:
        raise SOCModelOutputError(
            f"model output exceeds SOC_MAX_MODEL_OUTPUT_BYTES="
            f"{SOC_MAX_MODEL_OUTPUT_BYTES}; the output is rejected rather "
            "than truncated"
        )
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SOCModelOutputError(
            "model output is not strict JSON (fenced, prose-wrapped, or "
            "malformed output is never accepted)"
        ) from exc
    if not isinstance(parsed, dict):
        raise SOCModelOutputError(
            "model output must be a single JSON object; "
            f"received {type(parsed).__name__}"
        )
    return parsed


def validate_candidate(parsed: dict[str, Any]) -> SOCModelIntent:
    """Validate a parsed JSON object against the candidate-intent contract."""
    try:
        return SOCModelIntent.model_validate(parsed)
    except ValidationError as exc:
        raise SOCModelValidationError(
            f"model output failed the intent contract "
            f"({len(exc.errors())} issue(s)); the output is rejected rather "
            "than truncated"
        ) from exc


def assert_candidate_secret_free(candidate: SOCModelIntent) -> None:
    """Fail closed when the serialized candidate contains credential-shaped
    content.  The message never echoes the offending value."""
    serialized = candidate.model_dump_json().lower()
    for pattern in SECRET_PATTERNS:
        if pattern in serialized:
            raise SOCSafetyError(
                "refusing to accept a model intent that contains "
                "credential-shaped content"
            )


__all__ = [
    "SOCIntentParser",
    "SOCParseResult",
    "build_candidate",
    "parse_strict",
    "validate_candidate",
    "assert_candidate_secret_free",
    "SECRET_PATTERNS",
]