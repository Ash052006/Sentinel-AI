"""Risk Scoring Agent — Step 11B.

Orchestrates a configured :class:`RiskScoringStrategy` against a Step 10A
:class:`~app.schemas.correlation.CorrelationResult` and produces a single
Step 11A :class:`~app.schemas.risk.RiskAssessment`.

Detection answers *"what individual detection rules matched this
event?"*.  Correlation answers *"which detections/events are related?"*.
Risk scoring answers *"how dangerous does the correlated situation
appear?"* — this agent deterministically evaluates one correlation and
records a ``RiskAssessment``.  It does **not** persist the assessment,
expose an API, create incidents, map MITRE ATT&CK, or perform response;
those belong to later SentinelAI layers.

Design principles:

* **Orchestrator only** — the agent holds no scoring rules; all scoring
  decisions live in the injected strategy (the deterministic engine).
* **Stateless** — the agent retains nothing between invocations; every
  evaluation operates only on the supplied correlation.
* **Non-mutating** — the correlation (and its members) are never
  modified; the assessment references the correlation by
  ``correlation_id`` rather than copying it.
* **Deterministic** — with an injected ``clock`` the generated
  ``timestamp`` is fixed; the score/level/confidence/factors/evidence are
  computed deterministically by the strategy.  ``risk_assessment_id``
  remains the Step 11A-generated identity (per that contract) and never
  influences scoring.
* **Failure-safe** — invalid input raises a controlled
  :class:`RiskScoringInputError`; unexpected strategy failures raise a
  :class:`RiskScoringStrategyError` with the original cause preserved.
  A malformed strategy result is never passed through.
* **Secret-safe** — the engine builds evidence from member references and
  documented counts only; correlation payloads are never copied into the
  assessment.
* **Purely in-memory by default** — the agent never commits, rolls back, or
  depends on a database, message bus, or external service.  Persistence, if
  any, is an injected side-effect sink (Step 11C-B) invoked only *after* the
  complete assessment is built; with no sink supplied the agent performs
  zero persistence.

Relationship to the pipeline::

    CorrelationResult (Step 10A)
        -> RiskScoringAgent.analyze()
            -> RiskScoringStrategy.score()
                -> RiskAssessment (Step 11A)
                    -> [optional persistence sink (Step 11C-B)]
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Callable, Protocol

from app.schemas.correlation import CorrelationResult
from app.schemas.risk import RiskAssessment
from app.services.risk.engine import (
    DeterministicRiskScoringEngine,
    RiskScoringStrategy,
)
from app.services.risk.exceptions import (
    RiskScoringInputError,
    RiskScoringStrategyError,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pluggable persistence boundary (Step 11C-B)
# ---------------------------------------------------------------------------
#
# The agent stays a *pure* orchestration layer: it always builds and returns
# its complete assessment with no side effects.  Persisting that assessment
# is an orthogonal concern, injected as an optional callback so the agent
# never knows about the database.  This keeps the agent stateless and
# deterministic while allowing the pipeline (or tests) to supply whatever
# persistence they need.


class RiskAssessmentPersistence(Protocol):
    """Protocol satisfied by a risk-assessment persistence sink.

    A conforming callable takes a completed Step 11A
    :class:`~app.schemas.risk.RiskAssessment` and persists it, returning an
    opaque summary.  The persistence (service) owns its own transaction
    boundary — the agent never commits or rolls back.
    """

    def __call__(self, assessment: RiskAssessment) -> object: ...


#: Type alias for the injected persistence callback accepted by ``analyze()``.
PersistenceCallback = Callable[[RiskAssessment], object]


class RiskScoringAgent:
    """Consumes a correlation result and produces one risk assessment.

    The agent is an orchestrator: it validates the correlation, delegates
    all scoring to the configured strategy, validates the strategy's
    output, and returns a single Step 11A ``RiskAssessment``.

    Args:
        engine: The risk scoring strategy to delegate to.  When ``None``,
            :class:`DeterministicRiskScoringEngine` (deterministic
            cardinality scoring) is used.

    Example::

        agent = RiskScoringAgent()
        assessment = agent.analyze(correlation, clock=FIXED_TS)
    """

    def __init__(
        self,
        *,
        engine: RiskScoringStrategy | None = None,
    ) -> None:
        self._engine = engine or DeterministicRiskScoringEngine()

    @property
    def engine_name(self) -> str:
        """Name of the configured scoring strategy."""
        return self._engine.name

    def analyze(
        self,
        correlation: CorrelationResult,
        *,
        clock: datetime | None = None,
        persistence: PersistenceCallback | None = None,
    ) -> RiskAssessment:
        """Score the Step 10A *correlation*.

        The correlation is never mutated; the assessment references it by
        ``correlation_id`` and records deterministic evidence derived only
        from that correlation.

        When *persistence* is supplied, the completed assessment is handed
        to it before being returned.  Persistence is purely a side-effect
        sink: the assessment is fully built first, the agent never
        commits/rolls back, and a persistence failure is logged and re-raised
        as-is so the caller can decide how to handle it.  With
        ``persistence=None`` (the default) the agent performs no persistence
        and its behavior is exactly the Step 11B behavior.

        Args:
            correlation: Step 10A ``CorrelationResult`` to evaluate.
            clock: Optional fixed timestamp for deterministic testing.
                When ``None``, the current UTC time is used.  The
                timestamp is descriptive bookkeeping and never influences
                scoring.
            persistence: Optional callable invoked with the completed
                :class:`RiskAssessment` to persist it.  Defaults to ``None``
                (no persistence).

        Returns:
            A Step 11A ``RiskAssessment`` describing the correlated
            situation.

        Raises:
            RiskScoringInputError: when *correlation* is not a
                ``CorrelationResult``.
            RiskScoringStrategyError: when the configured strategy fails
                unexpectedly or returns a malformed result (original cause
                preserved); no partial assessment is produced.
        """
        if not isinstance(correlation, CorrelationResult):
            raise RiskScoringInputError(
                "risk scoring requires a CorrelationResult; received"
                f" {type(correlation).__module__}"
                f".{type(correlation).__qualname__}"
            )

        now = clock or datetime.now(timezone.utc)
        try:
            assessment = self._engine.score(correlation, timestamp=now)
        except RiskScoringInputError:
            raise
        except Exception as exc:
            logger.warning(
                "risk scoring strategy %s raised an unexpected"
                " exception: %s",
                self._engine.name,
                type(exc).__name__,
            )
            raise RiskScoringStrategyError(
                "the configured risk scoring strategy failed"
                " unexpectedly"
            ) from exc

        if not isinstance(assessment, RiskAssessment):
            raise RiskScoringStrategyError(
                "the configured risk scoring strategy returned a"
                " non-RiskAssessment result"
            )

        logger.info(
            "risk assessment complete: engine=%s correlation=%s"
            " score=%s level=%s",
            self._engine.name,
            correlation.correlation_id,
            assessment.score,
            assessment.level.value,
        )

        # 11C-B persistence boundary: delegate to the injected sink (if any).
        # The assessment is fully built — the agent has already done all of
        # its deterministic work.  The sink owns its own transaction; we only
        # surface a failure (which the sink has already sanitized) so the
        # caller can react.  The agent itself stays stateless and in-memory.
        if persistence is not None:
            try:
                persistence(assessment)
            except Exception as exc:  # noqa: BLE001 - surface sanitized error
                logger.warning(
                    "risk persistence failed for engine=%s correlation=%s (%s)",
                    self._engine.name,
                    correlation.correlation_id,
                    type(exc).__name__,
                )
                raise

        return assessment


def persist_risk_assessment_bound(
    db,
    *,
    service: RiskPersistenceService | None = None,
) -> PersistenceCallback:
    """Bind a persistence *service* to *db* for injection into ``analyze()``.

    Returns a :class:`PersistenceCallback` that persists a completed Step 11A
    :class:`~app.schemas.risk.RiskAssessment` through
    :meth:`RiskPersistenceService.persist_assessment`.

    This is the concrete wiring between the Step 11B agent and the Step 11C
    persistence service::

        callback = persist_risk_assessment_bound(session)
        assessment = agent.analyze(correlation, persistence=callback)

    The service (not the agent) owns the transaction: it commits the whole
    assessment atomically and rolls back on any failure.  The returned
    callback simply forwards the assessment and returns the service's
    summary.

    Args:
        db: The database session owned by the caller.
        service: Optional persistence service; defaults to a fresh
            :class:`RiskPersistenceService`.

    Returns:
        A callable accepting a ``RiskAssessment``.
    """
    from app.services.risk_persistence import RiskPersistenceService

    sink = service or RiskPersistenceService()

    def _persist(assessment: RiskAssessment) -> object:
        return sink.persist_assessment(db, assessment)

    return _persist