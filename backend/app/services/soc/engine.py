"""Natural Language SOC query engine — Step 23 orchestration.

:class:`SOCQueryService` composes the controlled pipeline::

    natural-language query
        -> SOC intent parser (Gemini adapter, raw structured output only)
        -> strict JSON / candidate-intent validation (fail closed)
        -> deterministc allowlist-intent validation
        -> read-only query executor (existing query services)
        -> structured SOC query response

The LLM is only responsible for parsing language into a candidate
structured intent; validation and execution are deterministic and the
engine never lets the LLM execute queries, choose functions, or affect
anything beyond the candidate.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

from app.schemas.soc_query import (
    SOC_MAX_QUERY_LENGTH,
    SOCModelIntent,
    SOCQueryResponse,
)
from app.services.soc.errors import SOCInputValidationError, SOCInternalError
from app.services.soc.executor import SOCQueryExecutor
from app.services.soc.gemini import GeminiSOCIntentParser
from app.services.soc.parser import (
    SOCIntentParser,
    SOCParseResult,
    build_candidate,
)
from app.services.soc.prompt import SOCPromptBuilder
from app.services.soc.validator import validate_model_intent


def _default_now() -> datetime:
    return datetime.now(timezone.utc)


class SOCQueryService:
    """Orchestrates parse -> validate -> execute for one natural-language query.

    Args:
        parser: Optional :class:`SOCIntentParser`.  Defaults to a lazily
            constructed :class:`GeminiSOCIntentParser` (never built at
            import time, so an unset ``GEMINI_API_KEY`` cannot break app
            import; configuration failures surface as sanitized errors on
            the first query).
        executor: Optional :class:`SOCQueryExecutor`.  Defaults to the
            canonical executor over the allowlist registry.
        clock: Overridable UTC clock for deterministic timestamps.
        prompt_builder: Optional prompt builder passed to the lazily built
            Gemini parser.
    """

    def __init__(
        self,
        *,
        parser: SOCIntentParser | None = None,
        executor: SOCQueryExecutor | None = None,
        clock: Callable[[], datetime] | None = None,
        prompt_builder: SOCPromptBuilder | None = None,
    ) -> None:
        self._parser: SOCIntentParser | None = parser
        self._executor: SOCQueryExecutor = (
            executor if executor is not None else SOCQueryExecutor()
        )
        self._clock: Callable[[], datetime] = clock or _default_now
        self._prompt_builder: SOCPromptBuilder | None = prompt_builder

    @property
    def executor(self) -> SOCQueryExecutor:
        return self._executor

    def _resolve_parser(self) -> SOCIntentParser:
        if self._parser is None:
            self._parser = GeminiSOCIntentParser(
                prompt_builder=self._prompt_builder
            )
        return self._parser

    # -- Public entry point ---------------------------------------------------

    def query(
        self,
        db: Any,
        user_query: str,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> SOCQueryResponse:
        """Run one natural-language SOC query end to end (read-only).

        Args:
            db: The caller-owned read session (passed through to existing
                query services; never written to).
            user_query: Bounded natural-language request.
            clock: Overridable UTC clock (defaults to the engine's).

        Raises:
            SOCInputValidationError: the query input is blank/oversized.
            SOCParserError family: provider / parsing / contract failures
                from the untrusted LLM output (fail-closed).
            SOCSafetyError: credential-shaped model output was rejected.
            SOCIntentValidationError: the candidate violated the grammar.
            SOCExecutionError: a downstream read-only query service failed.
            SOCConfigurationError: the parser provider is not configured.
        """
        self._validate_query(user_query)

        parser = self._resolve_parser()
        raw: SOCParseResult = parser.parse(user_query)
        if not isinstance(raw, SOCParseResult):
            raise SOCInternalError(
                "the SOC parser returned an unexpected response"
            )

        candidate: SOCModelIntent = build_candidate(raw)
        intent = validate_model_intent(candidate)

        return self._executor.execute(
            db,
            intent,
            parser_provider=parser.provider_name,
            parser_model=parser.model_name,
            clock=clock or self._clock,
        )

    @staticmethod
    def _validate_query(user_query: Any) -> None:
        if not isinstance(user_query, str):
            raise SOCInputValidationError(
                "the SOC query must be a non-empty string"
            )
        if not user_query.strip():
            raise SOCInputValidationError("the SOC query must not be blank")
        if len(user_query) > SOC_MAX_QUERY_LENGTH:
            raise SOCInputValidationError(
                f"the SOC query must not exceed {SOC_MAX_QUERY_LENGTH} "
                "characters"
            )


__all__ = ["SOCQueryService"]