"""Natural Language SOC intent-contract tests (Step 23).

Covers the structured grammar contracts in
:mod:`app.schemas.soc_query`: the candidate model intent (untrusted LLM
output), the validated query intent, bounds (reject, never truncate), the
response envelope, and the Gemini structured-output companion schema.
"""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from app.schemas.incident_memory import MemoryType
from app.schemas.risk import RiskLevel
from app.schemas.soc_query import (
    SOC_DEFAULT_PAGE_SIZE,
    SOC_DEFAULT_RECENT_LIMIT,
    SOC_INTENT_MODEL_JSON_SCHEMA,
    SOC_MAX_MODEL_OUTPUT_BYTES,
    SOC_MAX_PAGE_SIZE,
    SOC_MAX_QUERY_LENGTH,
    SOC_MAX_RECENT_LIMIT,
    SOCExecutionMode,
    SOCFilters,
    SOCModelIntent,
    SOCOperation,
    SOCPagination,
    SOCQueryIntent,
    SOCQueryRequest,
    SOCQueryResponse,
    SOCQueryTarget,
    SOCResource,
)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class TestEnums:
    def test_resource_values(self) -> None:
        assert SOCResource.DETECTIONS == "detections"
        assert SOCResource.CORRELATIONS == "correlations"
        assert SOCResource.RISK_ASSESSMENTS == "risk_assessments"
        assert SOCResource.INCIDENT_MEMORIES == "incident_memories"

    def test_operation_values(self) -> None:
        assert {
            SOCOperation.GET,
            SOCOperation.LIST,
            SOCOperation.RECENT,
            SOCOperation.BY_EVENT,
            SOCOperation.BY_CORRELATION,
            SOCOperation.BY_DETECTION,
            SOCOperation.BY_RULE,
        } == {
            SOCOperation("get"),
            SOCOperation("list"),
            SOCOperation("recent"),
            SOCOperation("by_event"),
            SOCOperation("by_correlation"),
            SOCOperation("by_detection"),
            SOCOperation("by_rule"),
        }

    def test_operation_declared_order_deterministic(self) -> None:
        # The registry spec order relies on enum declaration order; keep it
        # stable so validator + executor + tests always agree.
        assert list(SOCOperation) == [
            SOCOperation.GET,
            SOCOperation.LIST,
            SOCOperation.RECENT,
            SOCOperation.BY_EVENT,
            SOCOperation.BY_CORRELATION,
            SOCOperation.BY_DETECTION,
            SOCOperation.BY_RULE,
        ]

    def test_mode_values(self) -> None:
        assert SOCExecutionMode.EXACT_LOOKUP == "exact_lookup"
        assert SOCExecutionMode.PAGED_QUERY == "paged_query"
        assert SOCExecutionMode.RECENT_FEED == "recent_feed"


# ---------------------------------------------------------------------------
# Bounds — reject, never truncate
# ---------------------------------------------------------------------------


class TestBounds:
    def test_constants_are_fixed_contract(self) -> None:
        assert SOC_MAX_QUERY_LENGTH == 2048
        assert SOC_MAX_MODEL_OUTPUT_BYTES == 4096
        assert SOC_MAX_PAGE_SIZE == 200
        assert SOC_MAX_RECENT_LIMIT == 200
        assert SOC_DEFAULT_PAGE_SIZE == 50
        assert SOC_DEFAULT_RECENT_LIMIT == 50

    def test_page_cap_never_exceeds_recent_cap(self) -> None:
        # Both bounds feed existing query services; page size must never be
        # larger than the recent-feed cap (they share the service caps).
        assert SOC_MAX_PAGE_SIZE <= SOC_MAX_RECENT_LIMIT


# ---------------------------------------------------------------------------
# SOCQueryRequest
# ---------------------------------------------------------------------------


class TestQueryRequest:
    def test_valid_query(self) -> None:
        req = SOCQueryRequest(query="Show me recent high risk detections")
        assert req.query == "Show me recent high risk detections"

    def test_blank_query_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SOCQueryRequest(query="   ")

    def test_oversized_query_rejected_not_truncated(self) -> None:
        with pytest.raises(ValidationError):
            SOCQueryRequest(query="a" * (SOC_MAX_QUERY_LENGTH + 1))

    def test_extra_fields_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SOCQueryRequest(query="show recent", trailing="x")


# ---------------------------------------------------------------------------
# SOCModelIntent — the untrusted candidate the LLM may produce
# ---------------------------------------------------------------------------


class TestModelIntent:
    def test_minimal_valid_candidate(self) -> None:
        intent = SOCModelIntent(
            resource="detections",
            operation="recent",
        )
        assert intent.resource is SOCResource.DETECTIONS
        assert intent.operation is SOCOperation.RECENT
        assert intent.filters == SOCFilters()
        assert intent.limit is None

    def test_valid_candidate_full(self) -> None:
        cid = uuid.uuid4()
        intent = SOCModelIntent(
            resource="incident_memories",
            operation="list",
            page=2,
            page_size=10,
            filters={"memory_type": "attack_pattern"},
        )
        assert intent.page == 2
        assert intent.page_size == 10
        assert intent.filters.memory_type is MemoryType.ATTACK_PATTERN
        assert cid is not None

    def test_list_vocabulary_operations_are_members(self) -> None:
        # The LLM's operation vocabulary is closed: e.g. "detections.list"
        # must be a valid *enum* member but is later rejected at the grammar
        # layer (list is intentionally not registered for most resources).
        assert SOCOperation("list") is SOCOperation.LIST
        assert SOCOperation("recent") is SOCOperation.RECENT

    def test_unknown_resource_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SOCModelIntent(resource="queries", operation="recent")

    def test_unknown_operation_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SOCModelIntent(resource="detections", operation="drop")

    def test_extra_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SOCModelIntent(
                resource="detections",
                operation="recent",
                execute_sql=True,
            )

    def test_oversized_limit_rejected_not_truncated(self) -> None:
        with pytest.raises(ValidationError):
            SOCModelIntent(
                resource="detections",
                operation="recent",
                limit=SOC_MAX_RECENT_LIMIT + 1,
            )

    def test_oversized_page_size_rejected_not_truncated(self) -> None:
        with pytest.raises(ValidationError):
            SOCModelIntent(
                resource="detections",
                operation="by_event",
                event_id=uuid.uuid4(),
                page=1,
                page_size=SOC_MAX_PAGE_SIZE + 1,
            )

    def test_multiple_target_identifiers_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SOCModelIntent(
                resource="detections",
                operation="get",
                detection_id=uuid.uuid4(),
                correlation_id=uuid.uuid4(),
            )

    def test_limit_and_pagination_mutually_exclusive(self) -> None:
        with pytest.raises(ValidationError):
            SOCModelIntent(
                resource="detections",
                operation="recent",
                limit=10,
                page=1,
            )

    def test_page_size_requires_page(self) -> None:
        with pytest.raises(ValidationError):
            SOCModelIntent(
                resource="detections",
                operation="by_event",
                event_id=uuid.uuid4(),
                page_size=50,
            )

    def test_bad_uuid_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SOCModelIntent(
                resource="detections",
                operation="get",
                detection_id="not-a-uuid",
            )

    def test_rule_id_bounded(self) -> None:
        with pytest.raises(ValidationError):
            SOCModelIntent(
                resource="detections",
                operation="by_rule",
                rule_id="r" * 256,
            )

    def test_rule_id_must_be_nonempty(self) -> None:
        with pytest.raises(ValidationError):
            SOCModelIntent(
                resource="detections",
                operation="by_rule",
                rule_id="",
            )


# ---------------------------------------------------------------------------
# SOCQueryTarget / SOCPagination / SOCQueryIntent — validated shapes
# ---------------------------------------------------------------------------


class TestQueryTarget:
    def test_empty_target(self) -> None:
        target = SOCQueryTarget()
        assert target.model_dump(exclude_none=True) == {}

    def test_single_identifier(self) -> None:
        cid = uuid.uuid4()
        target = SOCQueryTarget(correlation_id=cid)
        assert target.model_dump(exclude_none=True) == {"correlation_id": cid}

    def test_two_identifiers_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SOCQueryTarget(event_id=uuid.uuid4(), memory_id=uuid.uuid4())

    def test_rule_id_bound_reapplied(self) -> None:
        with pytest.raises(ValidationError):
            SOCQueryTarget(rule_id="r" * 256)


class TestPagination:
    def test_exact_lookup_shape(self) -> None:
        assert SOCPagination().model_dump() == {
            "page": None,
            "page_size": None,
            "limit": None,
        }

    def test_recent_shape(self) -> None:
        p = SOCPagination(limit=10)
        assert p.limit == 10

    def test_paged_shape(self) -> None:
        p = SOCPagination(page=2, page_size=10)
        assert p.page == 2
        assert p.page_size == 10

    def test_limit_and_pages_mutually_exclusive(self) -> None:
        with pytest.raises(ValidationError):
            SOCPagination(limit=10, page=1)

    def test_page_size_requires_page(self) -> None:
        with pytest.raises(ValidationError):
            SOCPagination(page_size=10)


class TestQueryIntent:
    def test_happy_path(self) -> None:
        intent = SOCQueryIntent(
            resource=SOCResource.DETECTIONS,
            operation=SOCOperation.RECENT,
            mode=SOCExecutionMode.RECENT_FEED,
            pagination=SOCPagination(limit=50),
        )
        assert intent.mode is SOCExecutionMode.RECENT_FEED
        assert intent.target.model_dump(exclude_none=True) == {}

    def test_extra_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SOCQueryIntent(
                resource=SOCResource.DETECTIONS,
                operation=SOCOperation.RECENT,
                mode=SOCExecutionMode.RECENT_FEED,
                arbitrary=True,
            )


# ---------------------------------------------------------------------------
# SOCQueryResponse envelope
# ---------------------------------------------------------------------------


class TestQueryResponse:
    def test_read_only_is_literal_true(self) -> None:
        resp = SOCQueryResponse(
            intent=SOCQueryIntent(
                resource=SOCResource.DETECTIONS,
                operation=SOCOperation.RECENT,
                mode=SOCExecutionMode.RECENT_FEED,
            ),
            metadata={
                "resource": "detections",
                "operation": "recent",
                "mode": "recent_feed",
                "recorded_at": "2026-09-01T12:00:00Z",
            },
            found=True,
            count=1,
            items=[{"detection_id": "x"}],
            semantics=["detection_results"],
            note="Returned 1 recent detections.",
        )
        assert resp.read_only is True

    def test_read_only_cannot_be_false(self) -> None:
        intent = SOCQueryIntent(
            resource=SOCResource.DETECTIONS,
            operation=SOCOperation.RECENT,
            mode=SOCExecutionMode.RECENT_FEED,
        )
        with pytest.raises(ValidationError):
            SOCQueryResponse(
                intent=intent,
                metadata={
                    "resource": "detections",
                    "operation": "recent",
                    "mode": "recent_feed",
                    "recorded_at": "2026-09-01T12:00:00Z",
                },
                read_only=False,
                found=True,
                count=1,
                items=[],
                semantics=[],
                note="x",
            )

    def test_count_cannot_exceed_bounds(self) -> None:
        intent = SOCQueryIntent(
            resource=SOCResource.DETECTIONS,
            operation=SOCOperation.RECENT,
            mode=SOCExecutionMode.RECENT_FEED,
        )
        with pytest.raises(ValidationError):
            SOCQueryResponse(
                intent=intent,
                metadata={
                    "resource": "detections",
                    "operation": "recent",
                    "mode": "recent_feed",
                    "recorded_at": "2026-09-01T12:00:00Z",
                },
                found=True,
                count=SOC_MAX_PAGE_SIZE + 1,
                items=[],
                semantics=[],
                note="x",
            )


# ---------------------------------------------------------------------------
# Gemini structured-output companion schema mirrors the candidate intent
# ---------------------------------------------------------------------------


class TestGeminiCompanionSchema:
    def test_schema_top_level_keys_match_model_intent(self) -> None:
        schema = SOC_INTENT_MODEL_JSON_SCHEMA
        assert schema["type"] == "OBJECT"
        assert set(schema["properties"]) == {
            "resource",
            "operation",
            "correlation_id",
            "event_id",
            "detection_id",
            "risk_assessment_id",
            "memory_id",
            "rule_id",
            "filters",
            "limit",
            "page",
            "page_size",
        }
        assert sorted(schema["required"]) == ["operation", "resource"]

    def test_schema_filter_keys_match_filters(self) -> None:
        filters = SOC_INTENT_MODEL_JSON_SCHEMA["properties"]["filters"]
        assert set(filters["properties"]) == {"memory_type", "risk_level"}

    def test_enum_and_filter_contract_roundtrip(self) -> None:
        # Every filter value must be expressible in the gemini schema types.
        assert SOCFilters().model_dump() == {
            "memory_type": None,
            "risk_level": None,
        }
        assert RiskLevel("high") == "high"