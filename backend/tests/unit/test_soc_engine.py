"""Natural Language SOC engine tests (Step 23).

Covers the end-to-end orchestration in
:class:`~app.services.soc.engine.SOCQueryService`: input bounds, the
parse -> strict-build -> validate -> execute chain, lazy default parser
construction (missing configuration surfaces as a sanitized error, never a
crash at import), and the structured response contract.
"""

from __future__ import annotations

import json

import pytest

from app.schemas.soc_query import (
    SOC_MAX_QUERY_LENGTH,
    SOCExecutionMode,
    SOCOperation,
    SOCQueryTarget,
    SOCResource,
)
from app.services.soc import engine as engine_mod
from app.services.soc.errors import (
    SOCConfigurationError,
    SOCExecutionError,
    SOCInputValidationError,
    SOCIntentValidationError,
    SOCInternalError,
    SOCModelOutputError,
)
from app.services.soc.executor import SOCQueryExecutor
from app.services.soc.gemini import GeminiSOCIntentParser
from app.services.soc.parser import SOCIntentParser, SOCParseResult
from app.services.soc.registry import QueryHandler

from soc_test_helpers import FakeRecord, NOW


class _FixedParser(SOCIntentParser):
    """Test parser returning a fixed raw structured-output payload."""

    def __init__(self, raw: dict, *, provider="gemini", model="m") -> None:
        self._raw = raw
        self._provider = provider
        self._model = model

    @property
    def provider_name(self) -> str:
        return self._provider

    @property
    def model_name(self) -> str | None:
        return self._model

    def parse(self, user_query: str) -> SOCParseResult:
        return SOCParseResult(
            raw_text=json.dumps(self._raw),
            provider=self._provider,
            model=self._model,
        )


class _BadParser(SOCIntentParser):
    """Parser returning an unexpected (non-raw-result) object."""

    @property
    def provider_name(self) -> str:
        return "broken"

    @property
    def model_name(self) -> str | None:
        return "broken"

    def parse(self, user_query: str):  # type: ignore[override]
        return {"unexpected": True}


def _handlers_recent_detections() -> dict:
    def recent(db, *, limit=50):
        return [FakeRecord(id=f"r{i}") for i in range(min(limit, 3))]

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


def _service(raw: dict, handlers: dict) -> engine_mod.SOCQueryService:
    return engine_mod.SOCQueryService(
        parser=_FixedParser(raw),
        executor=SOCQueryExecutor(handlers=handlers),
        clock=lambda: NOW,
    )


# ---------------------------------------------------------------------------
# Input bounds
# ---------------------------------------------------------------------------


class TestInputBounds:
    def test_blank_query_rejected(self) -> None:
        svc = _service({}, _handlers_recent_detections())
        with pytest.raises(SOCInputValidationError):
            svc.query(object(), "   ")

    def test_oversized_query_rejected_never_truncated(self) -> None:
        svc = _service({}, _handlers_recent_detections())
        with pytest.raises(SOCInputValidationError):
            svc.query(object(), "a" * (SOC_MAX_QUERY_LENGTH + 1))

    def test_non_string_rejected(self) -> None:
        svc = _service({}, _handlers_recent_detections())
        with pytest.raises(SOCInputValidationError):
            svc.query(object(), None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Full pipeline
# ---------------------------------------------------------------------------


class TestPipeline:
    def test_happy_path_recent_detections(self) -> None:
        raw = {"resource": "detections", "operation": "recent", "limit": 3}
        svc = _service(raw, _handlers_recent_detections())
        resp = svc.query(object(), "show recent detections")
        assert resp.read_only is True
        assert resp.found is True
        assert resp.count == 3
        assert resp.intent.mode is SOCExecutionMode.RECENT_FEED
        assert resp.intent.pagination.limit == 3
        assert resp.metadata.parser_provider == "gemini"
        assert resp.metadata.recorded_at == NOW
        assert resp.semantics == ["detection_results"]
        assert resp.note == "Returned 3 recent detections."

    def test_malformed_model_output_rejected(self) -> None:
        class MalformedParser(SOCIntentParser):
            @property
            def provider_name(self) -> str:
                return "gemini"

            @property
            def model_name(self) -> str | None:
                return "m"

            def parse(self, user_query: str) -> SOCParseResult:
                return SOCParseResult(raw_text="not json")

        svc = engine_mod.SOCQueryService(
            parser=MalformedParser(),
            executor=SOCQueryExecutor(handlers=_handlers_recent_detections()),
        )
        with pytest.raises(SOCModelOutputError):
            svc.query(object(), "recent detections")

    def test_unsupported_intent_rejected_before_execution(self) -> None:
        raw = {"resource": "detections", "operation": "list"}
        svc = _service(raw, _handlers_recent_detections())
        with pytest.raises(SOCIntentValidationError):
            svc.query(object(), "list detections")

    def test_unregistered_dispatch_rejected(self) -> None:
        # Grammar-valid but not wired in the executor's dispatch table.
        raw = {"resource": "correlations", "operation": "recent", "limit": 5}
        svc = _service(raw, _handlers_recent_detections())
        with pytest.raises(SOCExecutionError):
            svc.query(object(), "recent correlations")

    def test_unexpected_parser_result_rejected(self) -> None:
        svc = engine_mod.SOCQueryService(
            parser=_BadParser(),
            executor=SOCQueryExecutor(handlers=_handlers_recent_detections()),
        )
        with pytest.raises(SOCInternalError):
            svc.query(object(), "anything")


# ---------------------------------------------------------------------------
# Lazy default parser construction
# ---------------------------------------------------------------------------


class TestLazyDefaultParser:
    def test_unconfigured_gemini_yields_sanitized_config_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.core.config import settings

        monkeypatch.setattr(settings, "gemini_api_key", "")
        svc = engine_mod.SOCQueryService(
            executor=SOCQueryExecutor(handlers=_handlers_recent_detections())
        )
        with pytest.raises(SOCConfigurationError):
            svc.query(object(), "show recent detections")

    def test_configured_gemini_builds_real_parser(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.core.config import settings

        monkeypatch.setattr(settings, "gemini_api_key", "test-key")
        svc = engine_mod.SOCQueryService()
        parser = svc._resolve_parser()
        assert isinstance(parser, GeminiSOCIntentParser)
        assert parser.provider_name == "gemini"
        # Cached — a second resolution returns the same instance.
        assert svc._resolve_parser() is parser

    def test_injected_parser_is_used(self) -> None:
        svc = engine_mod.SOCQueryService(
            parser=_FixedParser({"resource": "detections", "operation": "recent"}),
            executor=SOCQueryExecutor(handlers=_handlers_recent_detections()),
            clock=lambda: NOW,
        )
        assert isinstance(svc._resolve_parser(), _FixedParser)


# ---------------------------------------------------------------------------
# Response contract
# ---------------------------------------------------------------------------


class TestResponseContract:
    def test_items_are_json_safe_dicts(self) -> None:
        raw = {"resource": "detections", "operation": "recent", "limit": 2}
        svc = _service(raw, _handlers_recent_detections())
        resp = svc.query(object(), "recent detections")
        assert all(isinstance(i, dict) for i in resp.items)
        json.dumps(resp.items)

    def test_no_target_identifier_on_feed_intent(self) -> None:
        raw = {"resource": "detections", "operation": "recent"}
        svc = _service(raw, _handlers_recent_detections())
        resp = svc.query(object(), "recent detections")
        assert resp.intent.target == SOCQueryTarget()
        assert resp.intent.pagination.page is None