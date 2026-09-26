"""Deterministic read-only SOC query executor — Step 23.

The executor turns a validated :class:`~app.schemas.soc_query.SOCQueryIntent`
into a structured :class:`~app.schemas.soc_query.SOCQueryResponse` by
dispatching through the explicit allowlist registry to the *existing*
read-only query services.

Guarantees:

* **No arbitrary dispatch.**  There is no ``getattr`` and no callable
  name ever comes from the LLM.  The caller-provided ``handlers`` dict (or
  the canonical registry) is keyed by ``(SOCResource, SOCOperation)`` and
  holds explicitly bound existing query-service methods fixed at import
  time.
* **Only allowed parameters pass through.**  Pagination, the single target
  identifier, and the grammar-legal filters are the only values ever
  forwarded to a query service.
* **Read-only by construction.**  The executor only calls ``list/get``
  query methods; it never writes, flushes, commits, or mutates the session.
* **Sanitized failures.**  Downstream query failures surface as a generic
  :class:`~app.services.soc.errors.SOCExecutionError`; causes are chained
  for diagnosis and the raw failure text is never propagated.
* **Structured results.**  Results are the serialized (JSON-safe) existing
  query-layer read models — never SQLAlchemy objects, never raw rows, never
  database internals.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Callable

from app.schemas.soc_query import (
    SOCExecutionMetadata,
    SOCExecutionMode,
    SOCQueryIntent,
    SOCQueryResponse,
)
from app.services.soc import formatter, registry
from app.services.soc.errors import SOCExecutionError

logger = logging.getLogger(__name__)


def _default_now() -> datetime:
    return datetime.now(timezone.utc)


class SOCQueryExecutor:
    """Deterministically executes validated SOC intents via the allowlist.

    Args:
        handlers: Optional explicit dispatch map keyed by ``(SOCResource,
            SOCOperation)``.  Defaults to the canonical allowlist registry.
            Tests inject maps of stub handlers to prove dispatch and
            parameter pass-through without a database.
    """

    def __init__(
        self,
        handlers: dict | None = None,
    ) -> None:
        self._handlers: dict = handlers if handlers is not None else registry.HANDLERS

    def execute(
        self,
        db: Any,
        intent: SOCQueryIntent,
        *,
        parser_provider: str | None = None,
        parser_model: str | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> SOCQueryResponse:
        """Execute a validated intent and assemble the structured response.

        Args:
            db: The caller-owned read session, passed through verbatim to
                the allowlisted query service.  Never used for writes.
            intent: A validated :class:`SOCQueryIntent`.
            parser_provider / parser_model: Safe parser identifiers attached
                to the execution metadata.
            clock: Overridable UTC clock for deterministic ``recorded_at``.

        Raises:
            SOCExecutionError: dispatch did not resolve or a downstream
                query service failed (sanitized).
        """
        if not isinstance(intent, SOCQueryIntent):
            raise SOCExecutionError(
                "a validated SOC query intent is required for execution"
            )
        handler = self._handlers.get((intent.resource, intent.operation))
        if handler is None:
            raise SOCExecutionError(
                f"unsupported SOC query: "
                f"{intent.resource.value}.{intent.operation.value}"
            )

        recorded_at = (clock or _default_now)()

        try:
            outcome = self._run(db, handler, intent)
        except SOCExecutionError:
            raise
        except Exception as exc:
            logger.warning(
                "SOC data query failed (resource=%s operation=%s): %s",
                intent.resource.value,
                intent.operation.value,
                type(exc).__name__,
            )
            raise SOCExecutionError(
                "SOC data is unavailable"
            ) from exc

        note, semantics = formatter.format_response(intent, outcome)
        metadata = SOCExecutionMetadata(
            resource=intent.resource,
            operation=intent.operation,
            mode=intent.mode,
            page=intent.pagination.page if intent.mode is SOCExecutionMode.PAGED_QUERY else None,
            page_size=(
                intent.pagination.page_size
                if intent.mode is SOCExecutionMode.PAGED_QUERY
                else None
            ),
            limit=intent.pagination.limit if intent.mode is SOCExecutionMode.RECENT_FEED else None,
            applied_filters=list(outcome.applied_filters),
            parser_provider=parser_provider,
            parser_model=parser_model,
            recorded_at=recorded_at,
        )
        return SOCQueryResponse(
            intent=intent,
            metadata=metadata,
            read_only=True,
            found=outcome.found,
            count=outcome.count,
            total=outcome.total,
            items=outcome.items,
            semantics=semantics,
            note=note,
        )

    # -- Internals -----------------------------------------------------------

    @staticmethod
    def _target_params(intent: SOCQueryIntent) -> dict[str, Any]:
        """The intent's single target identifier as a kwargs dict."""
        return intent.target.model_dump(exclude_none=True)

    def _run(
        self,
        db: Any,
        handler: registry.QueryHandler,
        intent: SOCQueryIntent,
    ) -> formatter.SOCOutcome:
        applied: list[str] = []
        mode = intent.mode

        if mode is SOCExecutionMode.EXACT_LOOKUP:
            record = handler.call(db, **self._target_params(intent))
            records = [record] if record is not None else []
            total: int | None = None
        elif mode is SOCExecutionMode.PAGED_QUERY:
            params = self._target_params(intent)
            params["page"] = intent.pagination.page
            params["page_size"] = intent.pagination.page_size
            if (
                "memory_type" in handler.allowed_filters
                and intent.filters.memory_type is not None
            ):
                params["memory_type"] = intent.filters.memory_type
                applied.append(f"memory_type={intent.filters.memory_type.value}")
            result = handler.call(db, **params)
            records = handler.collect(result)
            total = result.total
        else:  # RECENT_FEED
            result = handler.call(db, limit=intent.pagination.limit)
            records = handler.collect(result)
            total = None
            if (
                "risk_level" in handler.allowed_filters
                and intent.filters.risk_level is not None
            ):
                level = intent.filters.risk_level
                records = [r for r in records if r.level == level]
                applied.append(f"risk_level={level.value}")

        items = [r.model_dump(mode="json") for r in records]
        return formatter.SOCOutcome(
            found=len(records) > 0,
            count=len(items),
            total=total,
            items=items,
            applied_filters=applied,
        )


__all__ = ["SOCQueryExecutor"]