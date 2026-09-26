"""Correlation Agent — Step 10B.

Orchestrates a configured :class:`CorrelationStrategy` against a Step 9I
:class:`~app.schemas.detection_correlation.DetectionCorrelationBatch`
and produces Step 10A
:class:`~app.schemas.correlation.CorrelationResult` objects.

Detection answers *"what individual detection rules matched this
event?"*.  Correlation answers *"which detections/events are related?"*
— this agent establishes those relationships deterministically.  It does
**not** decide whether the activity is malicious, assign risk, create
incidents, map MITRE ATT&CK, or perform response; those belong to later
SentinelAI layers.

Design principles:

* **Orchestrator only** — the agent holds no correlation rules; all
  grouping decisions live in the injected strategy.
* **Stateless** — the agent retains nothing between invocations; every
  analysis operates only on the supplied batch.
* **Non-mutating** — the batch and its detection records are never
  modified, and results reference detections by id
  (``CorrelationMember``) rather than copying them.
* **Deterministic** — group ordering follows first-seen input order and
  member ordering follows batch order; with an injected ``clock`` the
  generated ``timestamp`` is fixed.  ``correlation_id`` remains the
  Step 10A-generated identity (per that contract).
* **Failure-safe** — invalid input raises a controlled
  :class:`CorrelationInputError`; unexpected strategy failures raise a
  :class:`CorrelationStrategyError` with the original cause preserved.
  No partially constructed results are ever returned.
* **Secret-safe** — evidence is constructed from the group's signal and
  event id only; detection payloads are never copied into evidence and
  never logged.
* **Purely in-memory by default** — the agent never commits, rolls back,
  or depends on a database.  Persistence, if any, is an injected
  side-effect sink (Step 10C-C) invoked only *after* the complete result
  list is built; with no sink supplied the agent performs zero
  persistence.

Relationship to the pipeline::

    DetectionCorrelationBatch
        -> CorrelationAgent.analyze()
            -> CorrelationStrategy.correlate()
                -> CorrelationResult[]   (Step 10A)
                    -> [optional persistence sink (Step 10C-C)]
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Protocol

from app.schemas.correlation import CorrelationResult, to_correlation_members
from app.schemas.detection_correlation import DetectionCorrelationBatch
from app.services.correlation.exceptions import (
    CorrelationInputError,
    CorrelationStrategyError,
)
from app.services.correlation.strategy import (
    CorrelationGroup,
    CorrelationStrategy,
    DeterministicCorrelationStrategy,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pluggable persistence boundary (Step 10C-C)
# ---------------------------------------------------------------------------
#
# The agent stays a *pure* orchestration layer: it always builds and returns
# its complete result list with no side effects.  Persisting those results
# is an orthogonal concern, injected as an optional callback so the agent
# never knows about the database.  This keeps the agent stateless and
# deterministic while allowing the pipeline (or tests) to supply whatever
# persistence they need.


class CorrelationsPersistence(Protocol):
    """Protocol satisfied by a correlation persistence sink.

    A conforming callable takes the completed list of Step 10A
    :class:`~app.schemas.correlation.CorrelationResult` objects and
    persists them, returning an opaque summary.  The persistence (service)
    owns its own transaction boundary — the agent never commits or rolls
    back.
    """

    def __call__(self, results: list[CorrelationResult]) -> object: ...


#: Type alias for the injected persistence callback accepted by ``analyze()``.
PersistenceCallback = Callable[[list[CorrelationResult]], object]


# ---------------------------------------------------------------------------
# Step 10A result conversion (strategy output -> contract)
# ---------------------------------------------------------------------------


def _correlation_evidence(group: CorrelationGroup) -> dict[str, Any]:
    """Deterministic, non-sensitive evidence explaining a group.

    The evidence names the exact reason the members were grouped and the
    defining event.  It never copies detection payloads, evidence,
    metadata, confidence, or severity values, so it is secret-safe by
    construction and JSON-compatible.
    """
    return {
        "reason": group.signal,
        "event_id": str(group.event_id),
        "member_count": len(group.members),
    }


def _groups_to_results(
    groups: list[CorrelationGroup],
    now: datetime,
) -> list[CorrelationResult]:
    """Convert strategy output into the Step 10A contract.

    The complete result list is built before anything is returned; a
    malformed group aborts the whole conversion so no partially
    constructed ``CorrelationResult`` can escape.

    Raises:
        CorrelationStrategyError: when a group is not a
            ``CorrelationGroup``, is empty, or carries a non-UUID event.
    """
    results: list[CorrelationResult] = []
    for group in groups:
        if not isinstance(group, CorrelationGroup):
            raise CorrelationStrategyError(
                "the correlation strategy returned a"
                " non-CorrelationGroup item"
            )
        if not group.members:
            raise CorrelationStrategyError(
                "the correlation strategy returned an empty"
                " correlation group"
            )
        if not isinstance(group.event_id, uuid.UUID):
            raise CorrelationStrategyError(
                "the correlation strategy returned a group"
                " without a valid event id"
            )
        results.append(
            CorrelationResult(
                members=to_correlation_members(group.members),
                evidence=_correlation_evidence(group),
                metadata={},
                timestamp=now,
            )
        )
    return results


class CorrelationAgent:
    """Consumes a detection batch and produces correlation results.

    The agent is an orchestrator: it validates the batch, delegates all
    grouping to the configured strategy, converts the strategy's output
    into the Step 10A contract, and returns a complete list of
    ``CorrelationResult`` objects in deterministic order.

    Args:
        strategy: The correlation strategy to delegate to.  When
            ``None``, :class:`DeterministicCorrelationStrategy`
            (same-event correlation) is used.

    Example::

        agent = CorrelationAgent()
        results = agent.analyze(batch, clock=FIXED_TS)
    """

    def __init__(
        self,
        *,
        strategy: CorrelationStrategy | None = None,
    ) -> None:
        self._strategy = strategy or DeterministicCorrelationStrategy()

    def analyze(
        self,
        batch: DetectionCorrelationBatch,
        *,
        clock: datetime | None = None,
        persistence: PersistenceCallback | None = None,
    ) -> list[CorrelationResult]:
        """Correlate the detections transported by *batch*.

        The batch is never mutated; its detection records are never
        mutated, copied, or deduplicated (duplicate detection records are
        transported as-is into the members of their correlations).

        When *persistence* is supplied, the complete result list is handed
        to it before being returned.  Persistence is purely a side-effect
        sink: the results are fully built first, the agent never
        commits/rolls back, and a persistence failure is logged and
        re-raised as-is so the caller can decide how to handle it.  With
        ``persistence=None`` (the default) the agent performs no
        persistence and its behavior is exactly the Step 10B behavior.  An
        empty batch produces no results and the sink is not invoked.

        Args:
            batch: Step 9I batch envelope to analyze.  An empty batch
                produces no results.
            clock: Optional fixed timestamp for deterministic testing.
                When ``None``, the current UTC time is used.
            persistence: Optional callable invoked with the completed list
                of :class:`CorrelationResult` objects to persist them.
                Defaults to ``None`` (no persistence).

        Returns:
            All correlations deterministically grouped from the batch,
            in first-seen input order.  An empty batch returns ``[]``.

        Raises:
            CorrelationInputError: when *batch* is not a
                ``DetectionCorrelationBatch``.
            CorrelationStrategyError: when the configured strategy fails
                unexpectedly (original cause preserved); no partial
                results are produced.
        """
        if not isinstance(batch, DetectionCorrelationBatch):
            raise CorrelationInputError(
                "correlation analysis requires a"
                " DetectionCorrelationBatch; received"
                f" {type(batch).__module__}"
                f".{type(batch).__qualname__}"
            )

        if not batch.detections:
            logger.info(
                "correlation created no results: strategy=%s"
                " inputs=0 correlations=0",
                self._strategy.name,
            )
            return []

        try:
            groups = self._strategy.correlate(batch.detections)
        except CorrelationInputError:
            raise
        except Exception as exc:
            logger.warning(
                "correlation strategy %s raised an unexpected"
                " exception: %s",
                self._strategy.name,
                type(exc).__name__,
            )
            raise CorrelationStrategyError(
                "the configured correlation strategy failed"
                " unexpectedly"
            ) from exc

        now = clock or datetime.now(timezone.utc)
        try:
            results = _groups_to_results(groups, now)
        except CorrelationStrategyError:
            raise
        except Exception as exc:
            raise CorrelationStrategyError(
                "the correlation strategy produced invalid results"
            ) from exc

        logger.info(
            "correlation complete: strategy=%s inputs=%d"
            " correlations=%d",
            self._strategy.name,
            len(batch.detections),
            len(results),
        )

        # 10C-C persistence boundary: delegate to the injected sink (if any).
        # The results are fully built — the agent has already done all of its
        # deterministic work.  The sink owns its own transaction; we only
        # surface a failure (which the sink has already sanitized) so the
        # caller can react.  The agent itself stays stateless and in-memory.
        if persistence is not None:
            try:
                persistence(results)
            except Exception as exc:  # noqa: BLE001 - surface sanitized error
                logger.warning(
                    "correlation persistence failed for strategy=%s"
                    " correlations=%d (%s)",
                    self._strategy.name,
                    len(results),
                    type(exc).__name__,
                )
                raise

        return results


def persist_correlations_bound(
    db,
    *,
    service: CorrelationPersistenceService | None = None,
) -> PersistenceCallback:
    """Bind a persistence *service* to *db* for injection into ``analyze()``.

    Returns a :class:`PersistenceCallback` that persists a completed list
    of Step 10A :class:`~app.schemas.correlation.CorrelationResult`
    objects through
    :meth:`CorrelationPersistenceService.persist_correlations`.

    This is the concrete wiring between the Step 10B agent and the Step
    10C persistence service::

        callback = persist_correlations_bound(session)
        results = agent.analyze(batch, persistence=callback)

    The service (not the agent) owns the transaction: it commits the whole
    result list atomically and rolls back on any failure.  The returned
    callback simply forwards the list and returns the service's summary.

    Args:
        db: The database session owned by the caller.
        service: Optional persistence service; defaults to a fresh
            :class:`CorrelationPersistenceService`.

    Returns:
        A callable accepting a ``list[CorrelationResult]``.
    """
    from app.services.correlation_persistence import CorrelationPersistenceService

    sink = service or CorrelationPersistenceService()

    def _persist(results: list[CorrelationResult]) -> object:
        return sink.persist_correlations(db, results)

    return _persist