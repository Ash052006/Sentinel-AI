"""Deterministic intent validation for Natural Language SOC — Step 23.

This layer re-checks every :class:`~app.schemas.soc_query.SOCModelIntent`
candidate against the allowlist grammar *before* any database access.  It
verifies:

* the resource and operation belong to the allowlist (via the shared
  registry — the same table the executor dispatches on);
* the operation is valid for the resource;
* the target identifier has the correct type, is present exactly where the
  grammar requires it, and is absent everywhere else;
* filters are grammar-legal for the ``(resource, operation)`` pair;
* pagination matches the operation's mode (recent feed limit, or page/
  page_size, or nothing) and in-bounds defaults are filled in.

Validation is deterministic and independent of the LLM: model randomness
only ever influences the *candidate*; from the candidate onward every step
is fully determined.  Failures raise
:class:`~app.services.soc.errors.SOCIntentValidationError` with sanitized
messages that never echo raw user text or model output.
"""

from __future__ import annotations

from app.schemas.soc_query import (
    SOC_DEFAULT_PAGE_SIZE,
    SOC_DEFAULT_RECENT_LIMIT,
    SOCExecutionMode,
    SOCFilters,
    SOCModelIntent,
    SOCPagination,
    SOCQueryIntent,
    SOCQueryTarget,
)
from app.services.soc import registry
from app.services.soc.errors import SOCIntentValidationError


def _present_target_field(candidate: SOCModelIntent) -> str | None:
    for name in (
        "event_id",
        "correlation_id",
        "detection_id",
        "risk_assessment_id",
        "memory_id",
        "rule_id",
    ):
        if getattr(candidate, name) is not None:
            return name
    return None


def _pagination_for(
    handler: registry.QueryHandler,
    candidate: SOCModelIntent,
) -> SOCPagination:
    """Return the exact legal pagination shape for the handler's mode."""
    has_page_field = candidate.page is not None or candidate.page_size is not None

    if handler.mode is SOCExecutionMode.EXACT_LOOKUP:
        if candidate.limit is not None or has_page_field:
            raise SOCIntentValidationError(
                f"pagination is not valid for "
                f"{candidate.resource}.{candidate.operation}"
            )
        return SOCPagination()

    if handler.mode is SOCExecutionMode.RECENT_FEED:
        if has_page_field:
            raise SOCIntentValidationError(
                f"page/page_size are not valid for "
                f"{candidate.resource}.{candidate.operation}; use a recent "
                "feed limit"
            )
        return SOCPagination(
            limit=candidate.limit or SOC_DEFAULT_RECENT_LIMIT,
        )

    # PAGED_QUERY
    if candidate.limit is not None:
        raise SOCIntentValidationError(
            f"a feed limit is not valid for "
            f"{candidate.resource}.{candidate.operation}; use page/page_size"
        )
    return SOCPagination(
        page=candidate.page or 1,
        page_size=candidate.page_size or SOC_DEFAULT_PAGE_SIZE,
    )


def _filters_for(
    handler: registry.QueryHandler,
    candidate: SOCModelIntent,
) -> SOCFilters:
    """Return the candidate's filters, validating each against the grammar."""
    if candidate.filters.risk_level is not None and (
        "risk_level" not in handler.allowed_filters
    ):
        raise SOCIntentValidationError(
            f"filter 'risk_level' is not valid for "
            f"{candidate.resource}.{candidate.operation}"
        )
    if candidate.filters.memory_type is not None and (
        "memory_type" not in handler.allowed_filters
    ):
        raise SOCIntentValidationError(
            f"filter 'memory_type' is not valid for "
            f"{candidate.resource}.{candidate.operation}"
        )
    return candidate.filters


def validate_model_intent(candidate: SOCModelIntent) -> SOCQueryIntent:
    """Validate *candidate* against the allowlist grammar.

    Raises:
        SOCIntentValidationError: the candidate violates the grammar.
    """
    if not isinstance(candidate, SOCModelIntent):
        raise SOCIntentValidationError(
            "a validated SOC model intent is required"
        )

    handler = registry.lookup(candidate.resource, candidate.operation)
    if handler is None:
        raise SOCIntentValidationError(
            f"{candidate.operation.value} is not a supported operation for "
            f"resource {candidate.resource.value}"
        )

    present = _present_target_field(candidate)

    if handler.id_field is None:
        if present is not None:
            raise SOCIntentValidationError(
                f"identifier '{present}' is not valid for "
                f"{candidate.resource.value}.{candidate.operation.value}"
            )
    else:
        if present is None:
            raise SOCIntentValidationError(
                f"{candidate.resource.value}.{candidate.operation.value} "
                f"requires target identifier '{handler.id_field}'"
            )
        if present != handler.id_field:
            raise SOCIntentValidationError(
                f"identifier '{present}' is not valid for "
                f"{candidate.resource.value}.{candidate.operation.value}; "
                f"expected '{handler.id_field}'"
            )

    filters = _filters_for(handler, candidate)
    pagination = _pagination_for(handler, candidate)

    if handler.id_field is None:
        target = SOCQueryTarget()
    else:
        target = SOCQueryTarget(**{handler.id_field: getattr(candidate, handler.id_field)})

    return SOCQueryIntent(
        resource=candidate.resource,
        operation=candidate.operation,
        mode=handler.mode,
        target=target,
        filters=filters,
        pagination=pagination,
    )


__all__ = ["validate_model_intent"]