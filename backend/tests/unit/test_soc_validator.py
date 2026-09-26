"""SOC allowlist-intent validator tests (Step 23).

The validator re-checks every LLM candidate against the single-source
allowlist grammar BEFORE any database access.  These tests pin the full
grammar: every supported (resource, operation) combination, the exact
target identifier rules, the legal filters, and the pagination shapes.
"""

from __future__ import annotations

import uuid

import pytest

from app.schemas.incident_memory import MemoryType
from app.schemas.risk import RiskLevel
from app.schemas.soc_query import (
    SOC_DEFAULT_PAGE_SIZE,
    SOC_DEFAULT_RECENT_LIMIT,
    SOCExecutionMode,
    SOCModelIntent,
    SOCOperation,
    SOCResource,
)
from app.services.soc import registry
from app.services.soc.errors import SOCIntentValidationError
from app.services.soc.validator import validate_model_intent


def _candidate(resource, operation, **kwargs) -> SOCModelIntent:
    return SOCModelIntent(resource=resource, operation=operation, **kwargs)


# ---------------------------------------------------------------------------
# Every supported (resource, operation) validates
# ---------------------------------------------------------------------------


class TestGrammarAccepts:
    def test_exact_lookups(self) -> None:
        cid = uuid.uuid4()
        assert validate_model_intent(
            _candidate("detections", "get", detection_id=cid)
        ).mode is SOCExecutionMode.EXACT_LOOKUP
        assert validate_model_intent(
            _candidate("correlations", "get", correlation_id=cid)
        ).mode is SOCExecutionMode.EXACT_LOOKUP
        assert validate_model_intent(
            _candidate("risk_assessments", "get", risk_assessment_id=cid)
        ).mode is SOCExecutionMode.EXACT_LOOKUP
        assert validate_model_intent(
            _candidate("incident_memories", "get", memory_id=cid)
        ).mode is SOCExecutionMode.EXACT_LOOKUP

    def test_recent_feeds_with_default_limit(self) -> None:
        for resource in registry.specs():
            if resource.mode is SOCExecutionMode.RECENT_FEED:
                intent = validate_model_intent(
                    _candidate(resource.resource, resource.operation)
                )
                assert intent.pagination.limit == SOC_DEFAULT_RECENT_LIMIT

    def test_recent_feed_with_explicit_limit(self) -> None:
        intent = validate_model_intent(
            _candidate("detections", "recent", limit=7)
        )
        assert intent.pagination.limit == 7
        assert intent.pagination.page is None

    def test_paged_defaults(self) -> None:
        # Every paginated combination defaults to page 1 / default page size.
        for spec in registry.specs():
            if spec.mode is not SOCExecutionMode.PAGED_QUERY:
                continue
            kwargs = (
                {spec.id_field: uuid.uuid4()}
                if spec.id_field and spec.id_field != "rule_id"
                else ({spec.id_field: "sigma-rule-1"} if spec.id_field else {})
            )
            intent = validate_model_intent(
                _candidate(spec.resource, spec.operation, **kwargs)
            )
            assert intent.pagination.page == 1
            assert intent.pagination.page_size == SOC_DEFAULT_PAGE_SIZE

    def test_paged_with_explicit_page(self) -> None:
        cid = uuid.uuid4()
        intent = validate_model_intent(
            _candidate(
                "correlations",
                "by_event",
                event_id=cid,
                page=2,
                page_size=25,
            )
        )
        assert intent.pagination.page == 2
        assert intent.pagination.page_size == 25
        assert intent.target.event_id == cid

    def test_rule_target(self) -> None:
        intent = validate_model_intent(
            _candidate(
                "detections",
                "by_rule",
                rule_id="sigma-eicar",
                page=1,
                page_size=10,
            )
        )
        assert intent.target.rule_id == "sigma-eicar"

    def test_risk_level_filter_only_on_risk_recent(self) -> None:
        intent = validate_model_intent(
            _candidate(
                "risk_assessments",
                "recent",
                limit=100,
                filters={"risk_level": "high"},
            )
        )
        assert intent.filters.risk_level is RiskLevel.HIGH

    def test_memory_type_filter_only_on_memory_list(self) -> None:
        intent = validate_model_intent(
            _candidate(
                "incident_memories",
                "list",
                page=1,
                page_size=10,
                filters={"memory_type": "attack_pattern"},
            )
        )
        assert intent.filters.memory_type is MemoryType.ATTACK_PATTERN

    def test_registry_specs_cover_all_declared_combos(self) -> None:
        # The validator and the executor share the single registry table, so
        # the exact set of supported pairs is the registry's spec set.
        by_key = {(s.resource, s.operation) for s in registry.specs()}
        assert len(by_key) == len(list(registry.specs()))
        assert by_key == set(registry.HANDLERS)

    def test_specs_are_deterministically_ordered(self) -> None:
        expected = [
            (SOCResource.DETECTIONS, SOCOperation.GET),
            (SOCResource.DETECTIONS, SOCOperation.RECENT),
            (SOCResource.DETECTIONS, SOCOperation.BY_EVENT),
            (SOCResource.DETECTIONS, SOCOperation.BY_RULE),
            (SOCResource.CORRELATIONS, SOCOperation.GET),
            (SOCResource.CORRELATIONS, SOCOperation.RECENT),
            (SOCResource.CORRELATIONS, SOCOperation.BY_EVENT),
            (SOCResource.CORRELATIONS, SOCOperation.BY_DETECTION),
            (SOCResource.RISK_ASSESSMENTS, SOCOperation.GET),
            (SOCResource.RISK_ASSESSMENTS, SOCOperation.RECENT),
            (SOCResource.RISK_ASSESSMENTS, SOCOperation.BY_CORRELATION),
            (SOCResource.INCIDENT_MEMORIES, SOCOperation.GET),
            (SOCResource.INCIDENT_MEMORIES, SOCOperation.LIST),
            (SOCResource.INCIDENT_MEMORIES, SOCOperation.RECENT),
            (SOCResource.INCIDENT_MEMORIES, SOCOperation.BY_CORRELATION),
        ]
        assert [(s.resource, s.operation) for s in registry.specs()] == expected


# ---------------------------------------------------------------------------
# Unsupported combinations and operations are rejected
# ---------------------------------------------------------------------------


class TestGrammarRejects:
    def test_list_not_supported_for_most_resources(self) -> None:
        for resource in (
            "detections",
            "correlations",
            "risk_assessments",
        ):
            with pytest.raises(SOCIntentValidationError):
                validate_model_intent(_candidate(resource, "list"))

    def test_by_rule_only_for_detections(self) -> None:
        with pytest.raises(SOCIntentValidationError):
            validate_model_intent(_candidate("correlations", "by_rule", rule_id="r"))

    def test_by_detection_only_for_correlations(self) -> None:
        with pytest.raises(SOCIntentValidationError):
            validate_model_intent(
                _candidate("risk_assessments", "by_detection", detection_id=uuid.uuid4())
            )

    def test_wrong_identifier_type_rejected(self) -> None:
        # detections.get expects detection_id; a correlation_id is the wrong
        # target for that operation.
        with pytest.raises(SOCIntentValidationError):
            validate_model_intent(
                _candidate("detections", "get", correlation_id=uuid.uuid4())
            )

    def test_missing_required_identifier_rejected(self) -> None:
        with pytest.raises(SOCIntentValidationError):
            validate_model_intent(_candidate("detections", "get"))

    def test_identifier_on_feed_operation_rejected(self) -> None:
        with pytest.raises(SOCIntentValidationError):
            validate_model_intent(
                _candidate("detections", "recent", detection_id=uuid.uuid4())
            )

    def test_identifier_on_list_operation_rejected(self) -> None:
        with pytest.raises(SOCIntentValidationError):
            validate_model_intent(
                _candidate(
                    "incident_memories",
                    "list",
                    memory_id=uuid.uuid4(),
                    page=1,
                    page_size=10,
                )
            )


# ---------------------------------------------------------------------------
# Filter grammar
# ---------------------------------------------------------------------------


class TestFilterGrammar:
    def test_risk_level_not_valid_on_detections(self) -> None:
        with pytest.raises(SOCIntentValidationError):
            validate_model_intent(
                _candidate(
                    "detections",
                    "recent",
                    limit=10,
                    filters={"risk_level": "high"},
                )
            )

    def test_risk_level_not_valid_on_risk_by_correlation(self) -> None:
        with pytest.raises(SOCIntentValidationError):
            validate_model_intent(
                _candidate(
                    "risk_assessments",
                    "by_correlation",
                    correlation_id=uuid.uuid4(),
                    filters={"risk_level": "high"},
                )
            )

    def test_memory_type_not_valid_on_memory_recent(self) -> None:
        with pytest.raises(SOCIntentValidationError):
            validate_model_intent(
                _candidate(
                    "incident_memories",
                    "recent",
                    limit=10,
                    filters={"memory_type": "incident_summary"},
                )
            )

    def test_validated_intent_carries_only_legal_filters(self) -> None:
        intent = validate_model_intent(
            _candidate("risk_assessments", "recent", filters={"risk_level": "low"})
        )
        assert intent.filters.risk_level is RiskLevel.LOW
        assert intent.filters.memory_type is None


# ---------------------------------------------------------------------------
# Pagination grammar
# ---------------------------------------------------------------------------


class TestPaginationGrammar:
    def test_limit_invalid_on_paged_operation(self) -> None:
        cid = uuid.uuid4()
        with pytest.raises(SOCIntentValidationError):
            validate_model_intent(
                _candidate(
                    "correlations",
                    "by_event",
                    event_id=cid,
                    limit=10,
                )
            )

    def test_page_invalid_on_feed_operation(self) -> None:
        with pytest.raises(SOCIntentValidationError):
            validate_model_intent(
                _candidate("detections", "recent", page=2)
            )

    def test_page_invalid_on_exact_lookup(self) -> None:
        with pytest.raises(SOCIntentValidationError):
            validate_model_intent(
                _candidate("detections", "get", detection_id=uuid.uuid4(), page=1)
            )

    def test_limit_invalid_on_exact_lookup(self) -> None:
        with pytest.raises(SOCIntentValidationError):
            validate_model_intent(
                _candidate("incident_memories", "get", memory_id=uuid.uuid4(), limit=5)
            )


# ---------------------------------------------------------------------------
# Validator input contract
# ---------------------------------------------------------------------------


class TestValidatorInput:
    def test_non_candidate_rejected(self) -> None:
        with pytest.raises(SOCIntentValidationError):
            validate_model_intent("not an intent")  # type: ignore[arg-type]

    def test_unknown_operation_combination_has_no_handler(self) -> None:
        assert registry.lookup("detections", "list") is None
        assert registry.supports("detections", "list") is False