"""Explicit allowlisted SOC query dispatch registry — Step 23.

This module is the **single source of truth** for which ``(resource,
operation)`` combinations the Natural Language SOC grammar supports.  Every
supported combination is paired with an explicitly bound method of an
*existing* read-only query service (Detection / Correlation / Risk /
Incident Memory).  The registry:

* never accepts a method/callable name from the LLM or from an intent —
  dispatch is a deterministic ``dict`` lookup of pre-bound handlers;
* never uses ``getattr`` or dynamic member resolution;
* only composes established query services — Natural Language SOC sits
  *above* them and never creates new query implementations;
* is shared by the deterministic validator (which re-checks candidates
  against this table) and the read-only executor (which dispatches through
  it), so validation and dispatch can never disagree.

The query-service methods are stateless read-only views (the same instances
the read APIs use), so module-level instances are safe and deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from app.schemas.soc_query import SOCExecutionMode, SOCOperation, SOCResource
from app.services.correlation_query import CorrelationQueryService
from app.services.detection_query import DetectionQueryService
from app.services.incident_memory_query import IncidentMemoryQueryService
from app.services.risk_query import RiskQueryService


@dataclass(frozen=True)
class QueryHandler:
    """One allowlisted (resource, operation) dispatch entry.

    Attributes:
        resource: Allowlisted read resource.
        operation: Operation on the resource.
        mode: Dispatch class — determines the pagination shape and the
            service call signature.
        id_field: Name of the single target-identifier field required for
            this operation, or ``None`` for operations with no identifier.
        allowed_filters: Filter names the grammar permits for this pair.
        call: The explicitly bound existing query-service method, invoked as
            ``call(db, **kwargs)``; the method is fixed at import time and
            can never be influenced by the LLM.
        collect: The handler's deserialization result view used by the
            executor (read-only inspection of the returned read model).
    """

    resource: SOCResource
    operation: SOCOperation
    mode: SOCExecutionMode
    id_field: str | None
    allowed_filters: frozenset[str]
    call: Callable[..., Any]
    collect: Callable[[Any], list[Any]] = field(compare=False, repr=False)


#: Rule IDs live in the detection layer; its read record carries
#: ``severity`` but the grammar keeps filters minimal (only declared,
#: explicitly bounded filters).
_NO_FILTERS = frozenset()

#: Filters valid only for incident_memories.list (native, database-side).
_MEMORY_TYPE_FILTERS = frozenset({"memory_type"})

#: Filters valid only for risk_assessments.recent (deterministic in-process
#: post-filter over the bounded feed against persisted ``level``).
_RISK_LEVEL_FILTERS = frozenset({"risk_level"})


def _identity(records: list[Any]) -> list[Any]:
    return records


def _items(page: Any) -> list[Any]:
    return list(page.items)


_det = DetectionQueryService()
_cor = CorrelationQueryService()
_rsk = RiskQueryService()
_mem = IncidentMemoryQueryService()

#: The complete allowlist, in explicit (resource, operation) order.
HANDLERS: dict[tuple[SOCResource, SOCOperation], QueryHandler] = {
    # -- detections ---------------------------------------------------------
    (
        SOCResource.DETECTIONS,
        SOCOperation.GET,
    ): QueryHandler(
        resource=SOCResource.DETECTIONS,
        operation=SOCOperation.GET,
        mode=SOCExecutionMode.EXACT_LOOKUP,
        id_field="detection_id",
        allowed_filters=_NO_FILTERS,
        call=_det.get_result,
        collect=_identity,
    ),
    (
        SOCResource.DETECTIONS,
        SOCOperation.RECENT,
    ): QueryHandler(
        resource=SOCResource.DETECTIONS,
        operation=SOCOperation.RECENT,
        mode=SOCExecutionMode.RECENT_FEED,
        id_field=None,
        allowed_filters=_NO_FILTERS,
        call=_det.list_recent_results,
        collect=_identity,
    ),
    (
        SOCResource.DETECTIONS,
        SOCOperation.BY_EVENT,
    ): QueryHandler(
        resource=SOCResource.DETECTIONS,
        operation=SOCOperation.BY_EVENT,
        mode=SOCExecutionMode.PAGED_QUERY,
        id_field="event_id",
        allowed_filters=_NO_FILTERS,
        call=_det.list_results_for_event,
        collect=_items,
    ),
    (
        SOCResource.DETECTIONS,
        SOCOperation.BY_RULE,
    ): QueryHandler(
        resource=SOCResource.DETECTIONS,
        operation=SOCOperation.BY_RULE,
        mode=SOCExecutionMode.PAGED_QUERY,
        id_field="rule_id",
        allowed_filters=_NO_FILTERS,
        call=_det.list_results_for_rule,
        collect=_items,
    ),
    # -- correlations --------------------------------------------------------
    (
        SOCResource.CORRELATIONS,
        SOCOperation.GET,
    ): QueryHandler(
        resource=SOCResource.CORRELATIONS,
        operation=SOCOperation.GET,
        mode=SOCExecutionMode.EXACT_LOOKUP,
        id_field="correlation_id",
        allowed_filters=_NO_FILTERS,
        call=_cor.get_correlation,
        collect=_identity,
    ),
    (
        SOCResource.CORRELATIONS,
        SOCOperation.RECENT,
    ): QueryHandler(
        resource=SOCResource.CORRELATIONS,
        operation=SOCOperation.RECENT,
        mode=SOCExecutionMode.RECENT_FEED,
        id_field=None,
        allowed_filters=_NO_FILTERS,
        call=_cor.list_recent_correlations,
        collect=_identity,
    ),
    (
        SOCResource.CORRELATIONS,
        SOCOperation.BY_EVENT,
    ): QueryHandler(
        resource=SOCResource.CORRELATIONS,
        operation=SOCOperation.BY_EVENT,
        mode=SOCExecutionMode.PAGED_QUERY,
        id_field="event_id",
        allowed_filters=_NO_FILTERS,
        call=_cor.list_correlations_for_event,
        collect=_items,
    ),
    (
        SOCResource.CORRELATIONS,
        SOCOperation.BY_DETECTION,
    ): QueryHandler(
        resource=SOCResource.CORRELATIONS,
        operation=SOCOperation.BY_DETECTION,
        mode=SOCExecutionMode.PAGED_QUERY,
        id_field="detection_id",
        allowed_filters=_NO_FILTERS,
        call=_cor.list_correlations_for_detection,
        collect=_items,
    ),
    # -- risk assessments ----------------------------------------------------
    (
        SOCResource.RISK_ASSESSMENTS,
        SOCOperation.GET,
    ): QueryHandler(
        resource=SOCResource.RISK_ASSESSMENTS,
        operation=SOCOperation.GET,
        mode=SOCExecutionMode.EXACT_LOOKUP,
        id_field="risk_assessment_id",
        allowed_filters=_NO_FILTERS,
        call=_rsk.get_assessment,
        collect=_identity,
    ),
    (
        SOCResource.RISK_ASSESSMENTS,
        SOCOperation.RECENT,
    ): QueryHandler(
        resource=SOCResource.RISK_ASSESSMENTS,
        operation=SOCOperation.RECENT,
        mode=SOCExecutionMode.RECENT_FEED,
        id_field=None,
        allowed_filters=_RISK_LEVEL_FILTERS,
        call=_rsk.list_recent_assessments,
        collect=_identity,
    ),
    (
        SOCResource.RISK_ASSESSMENTS,
        SOCOperation.BY_CORRELATION,
    ): QueryHandler(
        resource=SOCResource.RISK_ASSESSMENTS,
        operation=SOCOperation.BY_CORRELATION,
        mode=SOCExecutionMode.PAGED_QUERY,
        id_field="correlation_id",
        allowed_filters=_NO_FILTERS,
        call=_rsk.list_assessments_for_correlation,
        collect=_items,
    ),
    # -- incident memories ---------------------------------------------------
    (
        SOCResource.INCIDENT_MEMORIES,
        SOCOperation.GET,
    ): QueryHandler(
        resource=SOCResource.INCIDENT_MEMORIES,
        operation=SOCOperation.GET,
        mode=SOCExecutionMode.EXACT_LOOKUP,
        id_field="memory_id",
        allowed_filters=_NO_FILTERS,
        call=_mem.get_memory,
        collect=_identity,
    ),
    (
        SOCResource.INCIDENT_MEMORIES,
        SOCOperation.RECENT,
    ): QueryHandler(
        resource=SOCResource.INCIDENT_MEMORIES,
        operation=SOCOperation.RECENT,
        mode=SOCExecutionMode.RECENT_FEED,
        id_field=None,
        allowed_filters=_NO_FILTERS,
        call=_mem.list_recent_memories,
        collect=_identity,
    ),
    (
        SOCResource.INCIDENT_MEMORIES,
        SOCOperation.BY_CORRELATION,
    ): QueryHandler(
        resource=SOCResource.INCIDENT_MEMORIES,
        operation=SOCOperation.BY_CORRELATION,
        mode=SOCExecutionMode.PAGED_QUERY,
        id_field="correlation_id",
        allowed_filters=_NO_FILTERS,
        call=_mem.list_memories_for_correlation,
        collect=_items,
    ),
    (
        SOCResource.INCIDENT_MEMORIES,
        SOCOperation.LIST,
    ): QueryHandler(
        resource=SOCResource.INCIDENT_MEMORIES,
        operation=SOCOperation.LIST,
        mode=SOCExecutionMode.PAGED_QUERY,
        id_field=None,
        allowed_filters=_MEMORY_TYPE_FILTERS,
        call=_mem.list_memories,
        collect=_items,
    ),
}


def lookup(
    resource: SOCResource,
    operation: SOCOperation,
) -> QueryHandler | None:
    """Return the allowlisted handler for *resource*/*operation*, or None."""
    if not isinstance(resource, SOCResource) or not isinstance(operation, SOCOperation):
        return None
    return HANDLERS.get((resource, operation))


def supports(resource: SOCResource, operation: SOCOperation) -> bool:
    """True when the grammar permits *resource* + *operation*."""
    return lookup(resource, operation) is not None


def specs() -> tuple[QueryHandler, ...]:
    """All handlers in deterministic resource-enum, then operation-enum order."""
    ordered = []
    for resource in SOCResource:
        for operation in SOCOperation:
            handler = HANDLERS.get((resource, operation))
            if handler is not None:
                ordered.append(handler)
    return tuple(ordered)


__all__ = ["QueryHandler", "HANDLERS", "lookup", "supports", "specs"]