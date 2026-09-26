"""SOC read-only executor tests (Step 23).

The executor dispatches a validated intent through the allowlist to
existing read query services.  Tests inject stub handler maps to prove:
deterministic dict dispatch, exact-lookup semantics, recent-feed and
paged pass-through, the deterministic risk_level in-process post-filter,
memory_type pass-through, sanitized failures, and the full response
envelope (read_only pinned, injectable clock, JSON-safe items).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from app.schemas.incident_memory import MemoryType
from app.schemas.risk import RiskLevel
from app.schemas.soc_query import (
    SOCExecutionMode,
    SOCFilters,
    SOCPagination,
    SOCQueryTarget,
    SOCOperation,
    SOCResource,
)
from app.services.soc.errors import SOCExecutionError
from app.services.soc.executor import SOCQueryExecutor
from app.services.soc.formatter import SOCOutcome
from app.services.soc.registry import QueryHandler

from soc_test_helpers import FakePage, FakeRecord, NOW, make_intent

#: Sentinel "db" stand-in — the executor never touches it beyond forwarding.
DB = object()


def _identity(records):
    return records


def _items(page):
    return list(page.items)


def _handler(
    resource: SOCResource,
    operation: SOCOperation,
    mode: SOCExecutionMode,
    *,
    calls=None,
    id_field: str | None = None,
    collect=_identity,
    allowed_filters: frozenset = frozenset(),
) -> QueryHandler:
    return QueryHandler(
        resource=resource,
        operation=operation,
        mode=mode,
        id_field=id_field,
        allowed_filters=allowed_filters,
        call=calls,
        collect=collect,
    )


class _Recorder:
    """Captures the kwargs a stub received per call."""

    def __init__(self, result) -> None:
        self._result = result
        self.calls = []
        self.kwargs = []

    def __call__(self, db, **kwargs):
        self.calls.append((db, kwargs))
        self.kwargs.append(kwargs)
        return self._result


class TestExactLookup:
    def test_found_returns_record(self) -> None:
        rec = _Recorder(FakeRecord(id="r1"))
        handlers = {
            (SOCResource.DETECTIONS, SOCOperation.GET): _handler(
                SOCResource.DETECTIONS,
                SOCOperation.GET,
                SOCExecutionMode.EXACT_LOOKUP,
                calls=rec,
                id_field="detection_id",
            )
        }
        cid = uuid.uuid4()
        intent = make_intent(
            SOCResource.DETECTIONS,
            "get",
            mode=SOCExecutionMode.EXACT_LOOKUP,
            target=SOCQueryTarget(detection_id=cid),
        )
        resp = SOCQueryExecutor(handlers=handlers).execute(
            DB, intent, clock=lambda: NOW
        )
        assert resp.found is True
        assert resp.count == 1
        assert resp.total is None
        assert resp.items == [{"id": "r1", "level": None, "memory_type": None}]
        assert rec.kwargs == [{"detection_id": cid}]

    def test_miss_returns_found_false(self) -> None:
        rec = _Recorder(None)
        handlers = {
            (SOCResource.DETECTIONS, SOCOperation.GET): _handler(
                SOCResource.DETECTIONS,
                SOCOperation.GET,
                SOCExecutionMode.EXACT_LOOKUP,
                calls=rec,
                id_field="detection_id",
            )
        }
        intent = make_intent(
            SOCResource.DETECTIONS,
            "get",
            mode=SOCExecutionMode.EXACT_LOOKUP,
            target=SOCQueryTarget(detection_id=uuid.uuid4()),
        )
        resp = SOCQueryExecutor(handlers=handlers).execute(DB, intent)
        assert resp.found is False
        assert resp.count == 0
        assert resp.items == []

    def test_only_target_id_passed(self) -> None:
        rec = _Recorder(None)
        handlers = {
            (SOCResource.RISK_ASSESSMENTS, SOCOperation.GET): _handler(
                SOCResource.RISK_ASSESSMENTS,
                SOCOperation.GET,
                SOCExecutionMode.EXACT_LOOKUP,
                calls=rec,
                id_field="risk_assessment_id",
            )
        }
        rid = uuid.uuid4()
        intent = make_intent(
            SOCResource.RISK_ASSESSMENTS,
            "get",
            mode=SOCExecutionMode.EXACT_LOOKUP,
            target=SOCQueryTarget(risk_assessment_id=rid),
        )
        SOCQueryExecutor(handlers=handlers).execute(DB, intent)
        assert rec.kwargs == [{"risk_assessment_id": rid}]


class TestRecentFeed:
    def test_limit_forwarded_and_found(self) -> None:
        rec = _Recorder([FakeRecord(id="a"), FakeRecord(id="b")])
        handlers = {
            (SOCResource.DETECTIONS, SOCOperation.RECENT): _handler(
                SOCResource.DETECTIONS,
                SOCOperation.RECENT,
                SOCExecutionMode.RECENT_FEED,
                calls=rec,
            )
        }
        intent = make_intent(
            SOCResource.DETECTIONS,
            "recent",
            mode=SOCExecutionMode.RECENT_FEED,
            pagination=SOCPagination(limit=25),
        )
        resp = SOCQueryExecutor(handlers=handlers).execute(
            DB, intent, clock=lambda: NOW
        )
        assert rec.kwargs == [{"limit": 25}]
        assert resp.count == 2
        assert resp.found is True
        assert resp.total is None
        assert resp.metadata.limit == 25
        assert resp.items[0]["id"] == "a"

    def test_empty_feed_found_false(self) -> None:
        rec = _Recorder([])
        handlers = {
            (SOCResource.CORRELATIONS, SOCOperation.RECENT): _handler(
                SOCResource.CORRELATIONS,
                SOCOperation.RECENT,
                SOCExecutionMode.RECENT_FEED,
                calls=rec,
            )
        }
        intent = make_intent(
            SOCResource.CORRELATIONS,
            "recent",
            mode=SOCExecutionMode.RECENT_FEED,
            pagination=SOCPagination(limit=10),
        )
        resp = SOCQueryExecutor(handlers=handlers).execute(DB, intent)
        assert resp.found is False
        assert resp.count == 0
        assert resp.semantics == ["correlation_results"]
        assert "No correlations matched." in resp.note


class TestRiskLevelPostFilter:
    def _handlers(self, rec) -> dict:
        return {
            (SOCResource.RISK_ASSESSMENTS, SOCOperation.RECENT): _handler(
                SOCResource.RISK_ASSESSMENTS,
                SOCOperation.RECENT,
                SOCExecutionMode.RECENT_FEED,
                calls=rec,
                allowed_filters=frozenset({"risk_level"}),
            )
        }

    def test_filter_applied_over_bounded_feed(self) -> None:
        rec = _Recorder(
            [
                FakeRecord(id="low", level=RiskLevel.LOW),
                FakeRecord(id="high", level=RiskLevel.HIGH),
                FakeRecord(id="critical", level=RiskLevel.CRITICAL),
            ]
        )
        handlers = {
            (
                SOCResource.RISK_ASSESSMENTS,
                SOCOperation.RECENT,
            ): _handler(
                SOCResource.RISK_ASSESSMENTS,
                SOCOperation.RECENT,
                SOCExecutionMode.RECENT_FEED,
                calls=rec,
                allowed_filters=frozenset({"risk_level"}),
            )
        }
        intent = make_intent(
            SOCResource.RISK_ASSESSMENTS,
            "recent",
            mode=SOCExecutionMode.RECENT_FEED,
            pagination=SOCPagination(limit=50),
            filters=SOCFilters(risk_level=RiskLevel.HIGH),
        )
        resp = SOCQueryExecutor(handlers=handlers).execute(DB, intent)
        assert [i["id"] for i in resp.items] == ["high"]
        assert resp.metadata.applied_filters == ["risk_level=high"]
        assert resp.count == 1
        assert "filtered by risk level high" in resp.note

    def test_no_filter_no_applied_filters(self) -> None:
        rec = _Recorder([FakeRecord(id="a", level=RiskLevel.LOW)])
        resp = SOCQueryExecutor(handlers=self._handlers(rec)).execute(
            DB,
            make_intent(
                SOCResource.RISK_ASSESSMENTS,
                "recent",
                mode=SOCExecutionMode.RECENT_FEED,
                pagination=SOCPagination(limit=50),
            ),
        )
        assert resp.metadata.applied_filters == []
        assert resp.count == 1


class TestPaged:
    def test_page_and_page_size_forwarded_with_total(self) -> None:
        rec = _Recorder(
            FakePage(
                items=[FakeRecord(id="x"), FakeRecord(id="y")],
                total=42,
                page=2,
                page_size=10,
            )
        )
        handlers = {
            (
                SOCResource.INCIDENT_MEMORIES,
                SOCOperation.BY_CORRELATION,
            ): QueryHandler(
                resource=SOCResource.INCIDENT_MEMORIES,
                operation=SOCOperation.BY_CORRELATION,
                mode=SOCExecutionMode.PAGED_QUERY,
                id_field="correlation_id",
                allowed_filters=frozenset(),
                call=rec,
                collect=_items,
            )
        }
        cid = uuid.uuid4()
        intent = make_intent(
            SOCResource.INCIDENT_MEMORIES,
            "by_correlation",
            mode=SOCExecutionMode.PAGED_QUERY,
            target=SOCQueryTarget(correlation_id=cid),
            pagination=SOCPagination(page=2, page_size=10),
        )
        resp = SOCQueryExecutor(handlers=handlers).execute(DB, intent)
        assert rec.kwargs == [
            {"correlation_id": cid, "page": 2, "page_size": 10}
        ]
        assert resp.total == 42
        assert resp.count == 2
        assert resp.metadata.page == 2
        assert resp.metadata.page_size == 10
        assert resp.items[1]["id"] == "y"

    def test_empty_page_found_false(self) -> None:
        rec = _Recorder(FakePage(items=[], total=0))
        handlers = {
            (
                SOCResource.INCIDENT_MEMORIES,
                SOCOperation.LIST,
            ): QueryHandler(
                resource=SOCResource.INCIDENT_MEMORIES,
                operation=SOCOperation.LIST,
                mode=SOCExecutionMode.PAGED_QUERY,
                id_field=None,
                allowed_filters=frozenset({"memory_type"}),
                call=rec,
                collect=_items,
            )
        }
        intent = make_intent(
            SOCResource.INCIDENT_MEMORIES,
            "list",
            mode=SOCExecutionMode.PAGED_QUERY,
            pagination=SOCPagination(page=1, page_size=50),
        )
        resp = SOCQueryExecutor(handlers=handlers).execute(DB, intent)
        assert resp.found is False
        assert resp.total == 0

    def test_memory_type_forwarded_only_when_present(self) -> None:
        rec = _Recorder(FakePage(items=[], total=0))
        handlers = {
            (
                SOCResource.INCIDENT_MEMORIES,
                SOCOperation.LIST,
            ): QueryHandler(
                resource=SOCResource.INCIDENT_MEMORIES,
                operation=SOCOperation.LIST,
                mode=SOCExecutionMode.PAGED_QUERY,
                id_field=None,
                allowed_filters=frozenset({"memory_type"}),
                call=rec,
                collect=_items,
            )
        }
        intent = make_intent(
            SOCResource.INCIDENT_MEMORIES,
            "list",
            mode=SOCExecutionMode.PAGED_QUERY,
            pagination=SOCPagination(page=1, page_size=50),
            filters=SOCFilters(memory_type=MemoryType.ATTACK_PATTERN),
        )
        SOCQueryExecutor(handlers=handlers).execute(DB, intent)
        assert rec.kwargs == [
            {
                "page": 1,
                "page_size": 50,
                "memory_type": MemoryType.ATTACK_PATTERN,
            }
        ]


class TestDispatchAndSafety:
    def test_unregistered_pair_rejected(self) -> None:
        handlers = {
            (SOCResource.DETECTIONS, SOCOperation.RECENT): _handler(
                SOCResource.DETECTIONS,
                SOCOperation.RECENT,
                SOCExecutionMode.RECENT_FEED,
                calls=_Recorder([]),
            )
        }
        intent = make_intent(
            SOCResource.DETECTIONS,
            "get",  # not in the injected dispatch table
            mode=SOCExecutionMode.EXACT_LOOKUP,
            target=SOCQueryTarget(detection_id=uuid.uuid4()),
        )
        with pytest.raises(SOCExecutionError):
            SOCQueryExecutor(handlers=handlers).execute(DB, intent)

    def test_non_intent_rejected(self) -> None:
        with pytest.raises(SOCExecutionError):
            SOCQueryExecutor().execute(DB, "nope")  # type: ignore[arg-type]

    def test_downstream_failure_sanitized(self) -> None:
        def _boom(db, **kwargs):
            raise RuntimeError("secret connection string leaked: postgres://...")

        handlers = {
            (SOCResource.DETECTIONS, SOCOperation.RECENT): _handler(
                SOCResource.DETECTIONS,
                SOCOperation.RECENT,
                SOCExecutionMode.RECENT_FEED,
                calls=_boom,
            )
        }
        intent = make_intent(
            SOCResource.DETECTIONS,
            "recent",
            mode=SOCExecutionMode.RECENT_FEED,
            pagination=SOCPagination(limit=10),
        )
        with pytest.raises(SOCExecutionError) as excinfo:
            SOCQueryExecutor(handlers=handlers).execute(DB, intent)
        assert "postgres://" not in str(excinfo.value)
        assert "SOC data is unavailable" in str(excinfo.value)

    def test_read_only_pinned_and_metadata(self) -> None:
        rec = _Recorder([FakeRecord(id="a")])
        handlers = {
            (SOCResource.CORRELATIONS, SOCOperation.RECENT): _handler(
                SOCResource.CORRELATIONS,
                SOCOperation.RECENT,
                SOCExecutionMode.RECENT_FEED,
                calls=rec,
            )
        }
        fixed = datetime(2026, 9, 2, 0, 0, 0, tzinfo=timezone.utc)
        intent = make_intent(
            SOCResource.CORRELATIONS,
            "recent",
            mode=SOCExecutionMode.RECENT_FEED,
            pagination=SOCPagination(limit=10),
        )
        resp = SOCQueryExecutor(handlers=handlers).execute(
            DB,
            intent,
            parser_provider="gemini",
            parser_model="gemini-2.0-flash",
            clock=lambda: fixed,
        )
        assert resp.read_only is True
        assert resp.metadata.parser_provider == "gemini"
        assert resp.metadata.parser_model == "gemini-2.0-flash"
        assert resp.metadata.recorded_at == fixed
        assert resp.metadata.resource is SOCResource.CORRELATIONS
        assert resp.metadata.operation is SOCOperation.RECENT

    def test_outcome_is_plain_json_safe_dicts(self) -> None:
        # Serialized dicts, not pydantic models — safe for JSON response.
        rec = _Recorder([FakeRecord(id="a")])
        handlers = {
            (SOCResource.DETECTIONS, SOCOperation.RECENT): _handler(
                SOCResource.DETECTIONS,
                SOCOperation.RECENT,
                SOCExecutionMode.RECENT_FEED,
                calls=rec,
            )
        }
        intent = make_intent(
            SOCResource.DETECTIONS,
            "recent",
            mode=SOCExecutionMode.RECENT_FEED,
            pagination=SOCPagination(limit=10),
        )
        resp = SOCQueryExecutor(handlers=handlers).execute(DB, intent)
        assert isinstance(resp.items[0], dict)
        import json

        json.dumps(resp.items)