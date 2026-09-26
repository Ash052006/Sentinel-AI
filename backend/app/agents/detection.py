"""Detection Agent — Step 9E.

Orchestrates the existing Sigma and YARA detection engines against a
single :class:`~app.schemas.normalized_event.NormalizedSecurityEvent`
and produces a unified :class:`DetectionAnalysis`.

This agent is an **orchestrator only**:

* It does **not** implement Sigma detection logic.
* It does **not** compile or evaluate YARA rules.
* It does **not** calculate risk scores, verdicts, or severity
  aggregations.
* It does **not** correlate events across time.
* It does **not** map MITRE ATT&CK techniques.
* It does **not** persist results to a database on its own; persistence, if
  any, is an injected side-effect sink (Step 9F-C) invoked only *after* the
  analysis is built — the agent itself never commits, rolls back, or depends
  on a database.
* It does **not** call external services (HTTP, LLM, message queues).

Design principles:

* **Dependency injection** — engines and registry are injected via the
  constructor; the agent is easy to unit-test with fakes/mocks.
* **Failure isolation** — an unexpected exception in one engine does
  not prevent the other engine from executing.
* **Immutability** — the input ``NormalizedSecurityEvent`` and all
  ``DetectionRule`` objects are treated as read-only.
* **Deterministic ordering** — results and failures are ordered:
  Sigma first, then YARA; within each engine, by ``rule_id``.
* **No fabrication** — the agent never creates detections from
  failures, and never silently converts ``INVALID_TARGET`` into
  ``NO_MATCH``.

Relationship to the pipeline::

    NormalizedSecurityEvent
        -> DetectionAgent.evaluate()
            -> SigmaDetectionEngine.evaluate()
            -> YaraDetectionEngine.evaluate()
            -> DetectionAnalysis
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Callable, Protocol

from sqlalchemy.orm import Session

from app.schemas.detection_agent import (
    DetectionAnalysis,
    DetectionAnalysisMetadata,
    DetectionFailure,
)
from app.schemas.normalized_event import NormalizedSecurityEvent
from app.schemas.security_event import Provenance
from app.services.detection.registry import DetectionRuleRegistry
from app.services.detection.sigma.engine import (
    SigmaDetectionEngine,
    SigmaDetectionReport,
    SigmaRuleFailure,
)
from app.services.detection.yara.engine import (
    YaraDetectionEngine,
    YaraDetectionReport,
    YaraRuleFailure,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pluggable persistence boundary (Step 9F-C)
# ---------------------------------------------------------------------------
#
# The agent stays a *pure* orchestration layer: it always builds and returns
# a :class:`DetectionAnalysis` with no side effects.  Persisting that
# analysis is an orthogonal concern, injected as an optional callback so the
# agent never knows about the database.  This keeps the agent stateless and
# deterministic while allowing the pipeline (or tests) to supply whatever
# persistence they need.


class AnalysisPersistence(Protocol):
    """Protocol satisfied by a detection persistence sink.

    A conforming callable takes a completed
    :class:`~app.schemas.detection_agent.DetectionAnalysis` and persists it,
    returning an opaque summary.  The persistence (service) owns its own
    transaction boundary — the agent never commits or rolls back.
    """

    def __call__(self, analysis: DetectionAnalysis) -> object: ...


#: Type alias for the injected persistence callback accepted by ``evaluate()``.
PersistenceCallback = Callable[[DetectionAnalysis], object]


def _sigma_failure_to_unified(failure: SigmaRuleFailure) -> DetectionFailure:
    """Convert a :class:`SigmaRuleFailure` to a :class:`DetectionFailure`."""
    return DetectionFailure(
        engine="sigma",
        rule_id=failure.rule_id,
        error_type=failure.error_type,
        message=failure.message,
    )


def _yara_failure_to_unified(failure: YaraRuleFailure) -> DetectionFailure:
    """Convert a :class:`YaraRuleFailure` to a :class:`DetectionFailure`."""
    return DetectionFailure(
        engine="yara",
        rule_id=failure.rule_id,
        error_type=failure.error_type,
        message=failure.message,
    )


class DetectionAgent:
    """Orchestrates Sigma and YARA detection engines.

    The agent accepts a :class:`DetectionRuleRegistry` and optional
    engine instances via constructor injection.  When engines are not
    provided, default instances are created.

    The :meth:`evaluate` method executes both engines against a single
    event and returns a unified :class:`DetectionAnalysis`.

    Example::

        registry = DetectionRuleRegistry(rules=[...])
        agent = DetectionAgent(registry=registry)
        analysis = agent.evaluate(event)
    """

    def __init__(
        self,
        registry: DetectionRuleRegistry | None = None,
        *,
        sigma_engine: SigmaDetectionEngine | None = None,
        yara_engine: YaraDetectionEngine | None = None,
    ) -> None:
        self._registry = registry
        self._sigma_engine = sigma_engine or SigmaDetectionEngine(
            registry=registry,
        )
        self._yara_engine = yara_engine or YaraDetectionEngine()

    def evaluate(
        self,
        event: NormalizedSecurityEvent,
        *,
        clock: datetime | None = None,
        persistence: PersistenceCallback | None = None,
    ) -> DetectionAnalysis:
        """Evaluate *event* using all available detection engines.

        Executes both Sigma and YARA engines in deterministic order
        (Sigma first, then YARA).  Failures in one engine are
        isolated — the other engine still runs.

        When *persistence* is supplied, the completed analysis is handed to
        it before being returned.  Persistence is purely a side-effect sink:
        the analysis is fully built first, the agent never commits/rolls
        back, and a persistence failure is logged and re-raised as-is so the
        caller can decide how to handle it.  With ``persistence=None`` (the
        default) the agent performs no persistence and its behavior is
        exactly the Step 9E behavior.

        The input *event* is never mutated.

        Args:
            event: The normalised security event to evaluate.
            clock: Optional fixed timestamp for deterministic testing.
                When ``None``, the current UTC time is used.
            persistence: Optional callable invoked with the completed
                :class:`DetectionAnalysis` to persist it.  Defaults to
                ``None`` (no persistence).

        Returns:
            A :class:`DetectionAnalysis` containing all results and
            failures from both engines.
        """
        now = clock or datetime.now(timezone.utc)
        start_time = time.monotonic()

        # -- Execute engines with failure isolation --------------------------

        sigma_report: SigmaDetectionReport | None = None
        sigma_error: Exception | None = None

        yara_report: YaraDetectionReport | None = None
        yara_error: Exception | None = None

        try:
            sigma_report = self._sigma_engine.evaluate(event)
        except Exception as exc:
            sigma_error = exc
            logger.warning(
                "Sigma engine raised an unexpected exception: %s",
                exc,
                exc_info=True,
            )

        try:
            yara_report = self._yara_engine.evaluate(
                event,
                self._get_yara_rules(),
            )
        except Exception as exc:
            yara_error = exc
            logger.warning(
                "YARA engine raised an unexpected exception: %s",
                exc,
                exc_info=True,
            )

        # -- Collect results -------------------------------------------------

        results: list = []
        sigma_result_count = 0
        yara_result_count = 0

        if sigma_report is not None:
            results.extend(sigma_report.results)
            sigma_result_count = len(sigma_report.results)

        if yara_report is not None:
            results.extend(yara_report.results)
            yara_result_count = len(yara_report.results)

        # -- Collect failures ------------------------------------------------

        failures: list[DetectionFailure] = []
        sigma_failure_count = 0
        yara_failure_count = 0

        if sigma_report is not None:
            for f in sigma_report.failures:
                failures.append(_sigma_failure_to_unified(f))
            sigma_failure_count = len(sigma_report.failures)

        if sigma_error is not None:
            failures.append(
                DetectionFailure(
                    engine="sigma",
                    rule_id="<engine>",
                    error_type="engine_error",
                    message=f"Sigma engine error: {type(sigma_error).__name__}",
                )
            )
            sigma_failure_count += 1

        if yara_report is not None:
            for f in yara_report.failures:
                failures.append(_yara_failure_to_unified(f))
            yara_failure_count = len(yara_report.failures)

        if yara_error is not None:
            failures.append(
                DetectionFailure(
                    engine="yara",
                    rule_id="<engine>",
                    error_type="engine_error",
                    message=f"YARA engine error: {type(yara_error).__name__}",
                )
            )
            yara_failure_count += 1

        # -- Aggregate metadata ----------------------------------------------

        elapsed_ms = (time.monotonic() - start_time) * 1000.0

        sigma_evaluated = (
            sigma_report.rules_evaluated if sigma_report is not None else 0
        )
        sigma_ignored = (
            sigma_report.rules_ignored if sigma_report is not None else 0
        )
        yara_evaluated = (
            yara_report.rules_evaluated if yara_report is not None else 0
        )
        yara_ignored = (
            yara_report.rules_ignored if yara_report is not None else 0
        )

        engines_executed = 0
        if sigma_report is not None:
            engines_executed += 1
        if yara_report is not None:
            engines_executed += 1

        metadata = DetectionAnalysisMetadata(
            engines_executed=engines_executed,
            sigma_rules_evaluated=sigma_evaluated,
            sigma_rules_ignored=sigma_ignored,
            yara_rules_evaluated=yara_evaluated,
            yara_rules_ignored=yara_ignored,
            total_results=len(results),
            sigma_results=sigma_result_count,
            yara_results=yara_result_count,
            total_failures=len(failures),
            sigma_failures=sigma_failure_count,
            yara_failures=yara_failure_count,
            execution_time_ms=round(elapsed_ms, 3),
        )

        analysis = DetectionAnalysis(
            event_id=event.event_id,
            results=results,
            failures=failures,
            metadata=metadata,
            timestamp=now,
            provenance=Provenance.DETECTED,
        )

        # 9F-C persistence boundary: delegate to the injected sink (if any).
        # The analysis is fully built — the agent has already done all of its
        # deterministic work.  The sink owns its own transaction; we only
        # surface a failure (which the sink has already sanitized) so the
        # caller can react.  The agent itself stays stateless.
        if persistence is not None:
            try:
                persistence(analysis)
            except Exception as exc:  # noqa: BLE001 - surface sanitized error
                logger.warning(
                    "Detection analysis persistence failed for event=%s (%s)",
                    event.event_id,
                    type(exc).__name__,
                )
                raise

        return analysis

    def _get_yara_rules(self) -> list:
        """Return enabled YARA rules from the registry.

        The YARA engine requires explicit rules (no registry support).
        If no registry is available, an empty list is returned.
        """
        if self._registry is not None:
            from app.schemas.detection import RuleType

            return self._registry.find_enabled_by_type(RuleType.YARA)
        return []


def persist_analysis_bound(
    db: Session,
    *,
    service: DetectionPersistenceService | None = None,
) -> PersistenceCallback:
    """Bind a persistence *service* to *db* for injection into ``evaluate()``.

    Returns a :class:`PersistenceCallback` that persists a completed
    :class:`DetectionAnalysis` through
    :meth:`DetectionPersistenceService.persist_analysis`.

    This is the concrete wiring between the Step 9E agent and the existing
    Step 9F persistence service::

        callback = persist_analysis_bound(session)
        analysis = agent.evaluate(event, persistence=callback)

    The service (not the agent) owns the transaction: it commits the whole
    analysis atomically and rolls back on any failure.  The returned callback
    simply forwards the analysis and returns the service's summary.

    Args:
        db: The SQLAlchemy session owned by the caller.
        service: Optional persistence service; defaults to a fresh
            :class:`DetectionPersistenceService`.

    Returns:
        A callable accepting a ``DetectionAnalysis``.
    """
    from app.services.detection_persistence import DetectionPersistenceService

    sink = service or DetectionPersistenceService()

    def _persist(analysis: DetectionAnalysis) -> object:
        return sink.persist_analysis(db, analysis)

    return _persist