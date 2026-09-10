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
* It does **not** persist results to a database.
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
    ) -> DetectionAnalysis:
        """Evaluate *event* using all available detection engines.

        Executes both Sigma and YARA engines in deterministic order
        (Sigma first, then YARA).  Failures in one engine are
        isolated — the other engine still runs.

        The input *event* is never mutated.

        Args:
            event: The normalised security event to evaluate.
            clock: Optional fixed timestamp for deterministic testing.
                When ``None``, the current UTC time is used.

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

        return DetectionAnalysis(
            event_id=event.event_id,
            results=results,
            failures=failures,
            metadata=metadata,
            timestamp=now,
            provenance=Provenance.DETECTED,
        )

    def _get_yara_rules(self) -> list:
        """Return enabled YARA rules from the registry.

        The YARA engine requires explicit rules (no registry support).
        If no registry is available, an empty list is returned.
        """
        if self._registry is not None:
            from app.schemas.detection import RuleType

            return self._registry.find_enabled_by_type(RuleType.YARA)
        return []