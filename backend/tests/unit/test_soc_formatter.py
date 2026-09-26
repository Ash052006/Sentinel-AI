"""SOC deterministic formatter tests (Step 23).

The response note and semantics labels are pure functions of the validated
intent + executed outcome.  They are never LLM-generated.  These tests pin
the exact deterministic wording and the historical-memory semantics guard.
"""

from __future__ import annotations

from app.schemas.incident_memory import MemoryType
from app.schemas.risk import RiskLevel
from app.schemas.soc_query import (
    SOCExecutionMode,
    SOCFilters,
    SOCPagination,
    SOCQueryTarget,
    SOCResource,
)
from app.services.soc.formatter import (
    SOCOutcome,
    build_note,
    build_semantics,
    format_response,
)

from soc_test_helpers import make_intent


class TestExactLookupNotes:
    def test_found(self) -> None:
        intent = make_intent(
            SOCResource.RISK_ASSESSMENTS,
            "get",
            mode=SOCExecutionMode.EXACT_LOOKUP,
            target=SOCQueryTarget(risk_assessment_id="00000000-0000-0000-0000-000000000000"),  # noqa: E501
        )
        outcome = SOCOutcome(found=True, count=1, items=[{"id": "x"}])
        assert build_note(intent, outcome) == (
            "Found the requested risk assessment (1 result)."
        )

    def test_not_found_never_claims_presence(self) -> None:
        intent = make_intent(
            SOCResource.INCIDENT_MEMORIES,
            "get",
            mode=SOCExecutionMode.EXACT_LOOKUP,
            target=SOCQueryTarget(memory_id="00000000-0000-0000-0000-000000000000"),  # noqa: E501
        )
        outcome = SOCOutcome(found=False, count=0, items=[])
        assert build_note(intent, outcome) == (
            "No incident memories found for the requested identifier."
        )


class TestRecentNotes:
    def test_found(self) -> None:
        intent = make_intent(
            SOCResource.DETECTIONS,
            "recent",
            mode=SOCExecutionMode.RECENT_FEED,
            pagination=SOCPagination(limit=50),
        )
        outcome = SOCOutcome(found=True, count=3, items=[{}, {}, {}])
        assert build_note(intent, outcome) == "Returned 3 recent detections."

    def test_not_found(self) -> None:
        intent = make_intent(
            SOCResource.CORRELATIONS,
            "recent",
            mode=SOCExecutionMode.RECENT_FEED,
            pagination=SOCPagination(limit=50),
        )
        assert build_note(intent, SOCOutcome(found=False, count=0)) == (
            "No correlations matched."
        )

    def test_risk_level_filter_noted(self) -> None:
        intent = make_intent(
            SOCResource.RISK_ASSESSMENTS,
            "recent",
            mode=SOCExecutionMode.RECENT_FEED,
            pagination=SOCPagination(limit=50),
            filters=SOCFilters(risk_level=RiskLevel.HIGH),
        )
        outcome = SOCOutcome(
            found=True,
            count=2,
            items=[{}, {}],
            applied_filters=["risk_level=high"],
        )
        assert build_note(intent, outcome) == (
            "Returned 2 recent risk assessments. filtered by risk level high"
        )


class TestPagedNotes:
    def test_found_with_total(self) -> None:
        intent = make_intent(
            SOCResource.INCIDENT_MEMORIES,
            "list",
            mode=SOCExecutionMode.PAGED_QUERY,
            pagination=SOCPagination(page=2, page_size=10),
        )
        outcome = SOCOutcome(
            found=True,
            count=10,
            total=55,
            items=[{}] * 10,
        )
        assert build_note(intent, outcome) == (
            "Returned 10 of 55 incident memories on page 2."
        )

    def test_not_found(self) -> None:
        intent = make_intent(
            SOCResource.DETECTIONS,
            "by_rule",
            mode=SOCExecutionMode.PAGED_QUERY,
            target=SOCQueryTarget(rule_id="r"),
            pagination=SOCPagination(page=1, page_size=50),
        )
        outcome = SOCOutcome(found=False, count=0, total=0)
        assert build_note(intent, outcome) == (
            "No detections matched on page 1."
        )

    def test_total_falls_back_to_count(self) -> None:
        intent = make_intent(
            SOCResource.CORRELATIONS,
            "by_event",
            mode=SOCExecutionMode.PAGED_QUERY,
            target=SOCQueryTarget(event_id="00000000-0000-0000-0000-000000000000"),  # noqa: E501
            pagination=SOCPagination(page=1, page_size=50),
        )
        outcome = SOCOutcome(found=True, count=4, items=[{}] * 4)
        assert "Returned 4 of 4 correlations" in build_note(intent, outcome)


class TestSemantics:
    def test_memory_semantics_mark_historical(self) -> None:
        intent = make_intent(
            SOCResource.INCIDENT_MEMORIES,
            "list",
            mode=SOCExecutionMode.PAGED_QUERY,
            pagination=SOCPagination(page=1, page_size=50),
            filters=SOCFilters(memory_type=MemoryType.ATTACK_PATTERN),
        )
        outcome = SOCOutcome(found=True, count=1, items=[{}])
        assert build_semantics(intent, outcome) == [
            "incident_memories",
            "historical_incident_memory_not_current_observation",
        ]

    def test_detection_semantics(self) -> None:
        intent = make_intent(
            SOCResource.DETECTIONS,
            "recent",
            mode=SOCExecutionMode.RECENT_FEED,
            pagination=SOCPagination(limit=50),
        )
        assert build_semantics(intent, SOCOutcome(found=False, count=0)) == [
            "detection_results"
        ]

    def test_risk_semantics(self) -> None:
        intent = make_intent(
            SOCResource.RISK_ASSESSMENTS,
            "recent",
            mode=SOCExecutionMode.RECENT_FEED,
            pagination=SOCPagination(limit=50),
        )
        assert build_semantics(intent, SOCOutcome(found=True, count=1)) == [
            "risk_assessment_results"
        ]

    def test_format_response_tuple(self) -> None:
        intent = make_intent(
            SOCResource.CORRELATIONS,
            "recent",
            mode=SOCExecutionMode.RECENT_FEED,
            pagination=SOCPagination(limit=50),
        )
        note, semantics = format_response(
            intent, SOCOutcome(found=True, count=1, items=[{}])
        )
        assert note == "Returned 1 recent correlations."
        assert semantics == ["correlation_results"]


class TestDeterminism:
    def test_same_inputs_same_outputs(self) -> None:
        intent = make_intent(
            SOCResource.DETECTIONS,
            "recent",
            mode=SOCExecutionMode.RECENT_FEED,
            pagination=SOCPagination(limit=50),
        )
        outcome = SOCOutcome(found=True, count=2, items=[{}, {}])
        first = format_response(intent, outcome)
        second = format_response(intent, outcome)
        assert first == second

    def test_formatter_never_fabricates_totals(self) -> None:
        intent = make_intent(
            SOCResource.DETECTIONS,
            "recent",
            mode=SOCExecutionMode.RECENT_FEED,
            pagination=SOCPagination(limit=50),
        )
        # A found outcome of 1 is reported exactly; nothing is extrapolated.
        assert "of " not in build_note(
            intent, SOCOutcome(found=True, count=1, items=[{}])
        )