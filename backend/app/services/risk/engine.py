"""Deterministic risk scoring engine — Step 11B.

Implements the risk scoring strategy abstraction consumed by the Risk
Scoring Agent (see :mod:`app.agents.risk_scoring`).  Step 11A defined the
``RiskAssessment`` domain contract; Step 11B implements the first
**deterministic, rule-based, evidence-driven risk scoring engine** that
consumes a Step 10A ``CorrelationResult`` and produces Step 11A
``RiskAssessment`` objects.

Detection answers *"what individual detection rules matched this
event?"*.  Correlation answers *"which detections/events are related?"*.
Risk scoring answers *"how dangerous does this correlated situation
appear, and how confident is SentinelAI in that assessment?"* — for Step
11B that answer is deliberately minimal, deterministic, and explainable.

Design principles:

* **Pure & stateless** — the engine is a deterministic pure function of
  its ``CorrelationResult`` input.  It reads only the correlation it is
  given, retains nothing between calls, never mutates its input, and
  performs no I/O.
* **No invented semantics** — every signal is derived from facts that
  genuinely exist in the Step 10A contract:
  ``member_count`` (how many detections are linked), ``event_breadth``
  (how many distinct source events), and ``detection_diversity`` (how
  many distinct detections).  Severity, per-detection confidence, rule
  ids/versions/types, member timestamps, threat intelligence, and
  correlation evidence/metadata content are *not* present in a
  ``CorrelationResult`` and are **never** used as scoring inputs.
* **No timestamps as scoring inputs** — the assessment ``timestamp`` is
  descriptive bookkeeping supplied at scoring time; it never influences
  the score, level, confidence, factors, or evidence.
* **Risk vs confidence independent** — ``score``/``level`` are computed
  solely from member cardinalities; ``confidence`` is sourced solely from
  the correlation's own optional ``confidence`` field (a documented ``0.0``
  baseline when the correlation asserts none).  The two quantities share
  no formula.
* **Bounded & documented** — the score is a clamped, weighted,
  baseline-subtracted combination of the three normalized signals, so a
  minimal single-detection correlation scores ``0.0`` and a maximal one
  scores ``1.0``.  Normalization, weights, references, and level
  thresholds are module-level constants (single source of truth).
* **Explainable** — every factor names its signal and carries
  deterministic evidence referencing the exact detections/events that
  supplied it.  ``metadata`` is JSON-compatible and secret-free.
* **Failure-safe** — an input that is not a ``CorrelationResult`` raises
  :class:`RiskScoringInputError`; the agent converts unexpected engine
  failures into :class:`RiskScoringStrategyError`.
* **In-memory only** — no database, repository, API, message bus,
  external service, graph store, or external AI.

Relationship to the pipeline::

    CorrelationResult (Step 10A)
        -> DeterministicRiskScoringEngine (this module)
            -> RiskAssessment (Step 11A)
                -> [RiskScoringAgent wraps this — Step 11B]
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Protocol

from app.schemas.correlation import CorrelationResult
from app.schemas.risk import RiskAssessment, RiskEvidence, RiskFactor, RiskLevel
from app.services.risk.exceptions import RiskScoringInputError

# ---------------------------------------------------------------------------
# Scoring policy — single source of truth (documented + tested)
# ---------------------------------------------------------------------------

#: Risk score result precision: every published score/contribution uses the
#: same rounding so the engine is bit-for-bit reproducible.
ROUND_DECIMALS = 6

#: Reference counts at which a signal reaches its full (normalized = 1.0)
#: contribution.  These are *references*, not hard caps: values above the
#: reference are clamped to the full contribution.
VOLUME_REFERENCE = 8     # members (linked detections)
BREADTH_REFERENCE = 4    # distinct source events
DIVERSITY_REFERENCE = 4  # distinct detections

#: Contribution weights (each in [0, 1], summing to exactly 1.0).
WEIGHT_VOLUME = 0.5
WEIGHT_BREADTH = 0.3
WEIGHT_DIVERSITY = 0.2

#: Assessment confidence baseline when the correlation asserts no numeric
#: confidence.  Documented under "Confidence policy" below.
CONFIDENCE_ABSENT_BASELINE = 0.0

#: Risk level thresholds (score -> level), lower-inclusive.
LEVEL_LOW_MAX = 0.30       # score < 0.30                -> LOW
LEVEL_MEDIUM_MAX = 0.55    # 0.30 <= score < 0.55        -> MEDIUM
LEVEL_HIGH_MAX = 0.75      # 0.55 <= score < 0.75        -> HIGH
LEVEL_CRITICAL_MIN = 0.75  # 0.75 <= score               -> CRITICAL

#: Policy label recorded in every assessment's metadata.
POLICY_NAME = "deterministic_cardinality_risk_v1"


# ---------------------------------------------------------------------------
# Pure scoring helpers (each unit is tested directly)
# ---------------------------------------------------------------------------


def clamp01(value: float) -> float:
    """Clamp *value* into the closed interval ``[0.0, 1.0]``.

    The clamping guarantee makes the score bounded even against exotic
    floating-point accumulation.  Deterministic and side-effect free.
    """
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return value


def normalize_excess(count: int, reference: int) -> float:
    """Normalize *count* to ``[0, 1]`` relative to a baseline.

    Subtracts the single-element baseline (``count == 1`` yields exactly
    ``0.0``) and saturates at *reference* elements (``count >= reference``
    yields exactly ``1.0``).  This baseline subtraction is what lets the
    score reach its lower boundary (``0.0``) for a minimal single-detection
    correlation and its upper boundary (``1.0``) for a maximal one.

    Raises:
        ValueError: if *reference* is less than 2 or *count* is less than 1
            (programmer error — the contract guarantees ``count >= 1``).
    """
    if reference < 2:
        raise ValueError(f"reference must be >= 2; received {reference}")
    if count < 1:
        raise ValueError(f"count must be >= 1; received {count}")
    return clamp01((count - 1) / (reference - 1))


def risk_level_for_score(score: float) -> RiskLevel:
    """Map a numeric :class:`RiskLevel` using the documented thresholds.

    Thresholds are lower-inclusive: ``0.30`` is MEDIUM, ``0.55`` is HIGH,
    ``0.75`` is CRITICAL.  This pure mapping is tested at every boundary
    value exactly and independently of the pipeline.
    """
    if score < LEVEL_LOW_MAX:
        return RiskLevel.LOW
    if score < LEVEL_MEDIUM_MAX:
        return RiskLevel.MEDIUM
    if score < LEVEL_HIGH_MAX:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def confidence_for_correlation(
    correlation: CorrelationResult,
) -> float:
    """Project the correlation's confidence onto the assessment.

    Confidence is **independent** from the risk score: it is sourced only
    from the Step 10A ``correlation.confidence`` field and never from the
    scoring signals or the computed score/level.

    * When the correlation asserts a numeric confidence (``[0, 1]`` by the
      Step 10A contract), it is copied through unchanged.
    * When the correlation asserts none (``None`` — the Step 10B agent's
      behaviour), the assessment records a documented baseline of
      ``CONFIDENCE_ABSENT_BASELINE`` (``0.0``): the engine never invents a
      confidence number.  This is deterministic and testable.
    """
    if correlation.confidence is None:
        return CONFIDENCE_ABSENT_BASELINE
    return correlation.confidence


def _distinct_in_order(values):
    """Return distinct values in first-seen order.

    Deterministic: relies on insertion order (guaranteed by CPython dicts)
    rather than set iteration, so the same input always yields the same
    sequence.  The source order is the correlation's own member order,
    which the Step 10A contract already keeps stable.
    """
    return tuple(dict.fromkeys(values))


def _evidence_for_member(member) -> RiskEvidence:
    """Build the member observation evidence for one correlation member."""
    return RiskEvidence(
        observation_type="correlation_member",
        detection_id=member.detection_id,
        event_id=member.event_id,
        metadata={},
    )


def _evidence_for_event(event_id: uuid.UUID, seen_count: int) -> RiskEvidence:
    """Build a distinct-event breadth observation."""
    return RiskEvidence(
        observation_type="distinct_event",
        event_id=event_id,
        metadata={"distinct_event_count": seen_count},
    )


def _evidence_for_detection(
    detection_id: uuid.UUID, seen_count: int
) -> RiskEvidence:
    """Build a distinct-detection diversity observation."""
    return RiskEvidence(
        observation_type="distinct_detection",
        detection_id=detection_id,
        metadata={"distinct_detection_count": seen_count},
    )


def _assessment_metadata(
    member_count: int,
    distinct_event_count: int,
    distinct_detection_count: int,
    volume_n: float,
    breadth_n: float,
    diversity_n: float,
) -> dict[str, object]:
    """Deterministic, JSON-compatible, secret-free assessment metadata.

    Contains only counts, normalized values, the policy label, and the
    documented constants — never timestamps, identities, or content copied
    from the correlation.
    """
    return {
        "policy": POLICY_NAME,
        "member_count": member_count,
        "distinct_event_count": distinct_event_count,
        "distinct_detection_count": distinct_detection_count,
        "volume_normalized": round(volume_n, ROUND_DECIMALS),
        "breadth_normalized": round(breadth_n, ROUND_DECIMALS),
        "diversity_normalized": round(diversity_n, ROUND_DECIMALS),
        "weights": {
            "volume": WEIGHT_VOLUME,
            "breadth": WEIGHT_BREADTH,
            "diversity": WEIGHT_DIVERSITY,
        },
        "references": {
            "volume": VOLUME_REFERENCE,
            "breadth": BREADTH_REFERENCE,
            "diversity": DIVERSITY_REFERENCE,
        },
        "level_thresholds": {
            "low_max": LEVEL_LOW_MAX,
            "medium_max": LEVEL_MEDIUM_MAX,
            "high_max": LEVEL_HIGH_MAX,
            "critical_min": LEVEL_CRITICAL_MIN,
        },
    }


# ---------------------------------------------------------------------------
# Strategy contract
# ---------------------------------------------------------------------------


class RiskScoringStrategy(Protocol):
    """Strategy contract consumed by the Risk Scoring Agent.

    A strategy deterministically scores a single Step 10A
    :class:`~app.schemas.correlation.CorrelationResult` into a Step 11A
    :class:`~app.schemas.risk.RiskAssessment`.  It must:

    * be deterministic (the same correlation always produces the same
      score, level, confidence, factors, and evidence);
    * be stateless (operate only on the supplied correlation plus the
      supplied scoring ``timestamp``);
    * never mutate its input;
    * raise :class:`RiskScoringInputError` for a correlation that is not a
      ``CorrelationResult``;
    * raise any other exception only for genuine strategy failures (the
      agent converts those into :class:`RiskScoringStrategyError`).
    """

    name: str

    def score(
        self,
        correlation: CorrelationResult,
        *,
        timestamp: datetime,
    ) -> RiskAssessment:
        """Score *correlation* as of *timestamp* into a RiskAssessment."""
        ...


# ---------------------------------------------------------------------------
# Baseline deterministic engine
# ---------------------------------------------------------------------------


class DeterministicRiskScoringEngine:
    """Baseline deterministic, rule-based, evidence-driven risk engine.

    Scores a Step 10A ``CorrelationResult`` from exactly three objective
    signals that genuinely exist in that contract:

    1. ``member_count`` (volume) — how many detections are linked into the
       correlation (reference: ``VOLUME_REFERENCE``).
    2. ``event_breadth`` — how many distinct source ``event_id`` values its
       members reference (reference: ``BREADTH_REFERENCE``).
    3. ``detection_diversity`` — how many distinct ``detection_id`` values
       its members reference (reference: ``DIVERSITY_REFERENCE``).

    Each signal is normalized with :func:`normalize_excess` (baseline
    subtraction + saturation) and combined with fixed, documented weights
    that sum to ``1.0``::

        score = clamp01(
            0.5 * volume_n + 0.3 * breadth_n + 0.2 * diversity_n
        ), rounded to 6 decimal places

    A minimal correlation (one member / one event / one distinct
    detection, i.e. a standalone detection) scores exactly ``0.0`` (LOW);
    a maximal correlation (at or above every reference) scores exactly
    ``1.0`` (CRITICAL).  Every level threshold (``0.30`` / ``0.55`` /
    ``0.75``) is tested exactly via :func:`risk_level_for_score`.

    **Confidence policy** — independent of the score.  The assessment
    ``confidence`` mirrors ``CorrelationResult.confidence`` when the
    correlation asserts one, and otherwise records the documented baseline
    ``CONFIDENCE_ABSENT_BASELINE`` (``0.0``).  It is never derived from the
    scoring signals, the score, or the level, and it never influences them.

    **Deliberately not used as scoring signals** (documented in the module
    docstring and the Phase 2 report):

    * severity, rule id/version/type, per-detection confidence — these
      fields exist in ``DetectionCorrelationInput`` / ``DetectionResult``
      but are **not** present in the Step 10A ``CorrelationResult`` this
      engine consumes; scoring them would require fabricating data;
    * member timestamps / correlation timestamp — timestamps are never
      scoring inputs;
    * correlation ``status`` — lifecycle bookkeeping, not risk evidence;
    * correlation ``evidence`` / ``metadata`` content — opaque engine
      artefacts, never parsed or scored.
    """

    name = "deterministic_cardinality_risk_v1"

    def score(
        self,
        correlation: CorrelationResult,
        *,
        timestamp: datetime,
    ) -> RiskAssessment:
        """Score *correlation* as of *timestamp*.

        Args:
            correlation: Step 10A ``CorrelationResult`` to evaluate.  A
                valid correlation references at least one member by
                contract; a standalone detection is a valid (minimal)
                input and scores ``0.0``.
            timestamp: Timezone-aware instant at which the assessment is
                produced.  Descriptive bookkeeping only — it never
                influences the score, level, confidence, factors, or
                evidence.

        Returns:
            A new Step 11A ``RiskAssessment`` referencing
            ``correlation.correlation_id``.

        Raises:
            RiskScoringInputError: if *correlation* is not a
                ``CorrelationResult``.
        """
        if not isinstance(correlation, CorrelationResult):
            raise RiskScoringInputError(
                "risk scoring requires a CorrelationResult; received"
                f" {type(correlation).__module__}"
                f".{type(correlation).__qualname__}"
            )

        members = correlation.members
        distinct_event_ids = _distinct_in_order(
            member.event_id for member in members
        )
        distinct_detection_ids = _distinct_in_order(
            member.detection_id for member in members
        )
        member_count = len(members)
        distinct_event_count = len(distinct_event_ids)
        distinct_detection_count = len(distinct_detection_ids)

        volume_n = normalize_excess(member_count, VOLUME_REFERENCE)
        breadth_n = normalize_excess(distinct_event_count, BREADTH_REFERENCE)
        diversity_n = normalize_excess(
            distinct_detection_count, DIVERSITY_REFERENCE
        )

        score = round(
            clamp01(
                WEIGHT_VOLUME * volume_n
                + WEIGHT_BREADTH * breadth_n
                + WEIGHT_DIVERSITY * diversity_n
            ),
            ROUND_DECIMALS,
        )

        evidence = [_evidence_for_member(member) for member in members]

        member_evidence = [
            _evidence_for_member(member) for member in members
        ]

        factors = [
            RiskFactor(
                factor_type="member_volume",
                contribution=round(volume_n, ROUND_DECIMALS),
                evidence=member_evidence,
                metadata={"member_count": member_count},
            ),
            RiskFactor(
                factor_type="event_breadth",
                contribution=round(breadth_n, ROUND_DECIMALS),
                evidence=[
                    _evidence_for_event(event_id, idx)
                    for idx, event_id in enumerate(distinct_event_ids, start=1)
                ],
                metadata={"distinct_event_count": distinct_event_count},
            ),
            RiskFactor(
                factor_type="detection_diversity",
                contribution=round(diversity_n, ROUND_DECIMALS),
                evidence=[
                    _evidence_for_detection(detection_id, idx)
                    for idx, detection_id in enumerate(
                        distinct_detection_ids, start=1
                    )
                ],
                metadata={"distinct_detection_count": distinct_detection_count},
            ),
        ]

        return RiskAssessment(
            correlation_id=correlation.correlation_id,
            score=score,
            level=risk_level_for_score(score),
            confidence=confidence_for_correlation(correlation),
            factors=factors,
            evidence=evidence,
            metadata=_assessment_metadata(
                member_count=member_count,
                distinct_event_count=distinct_event_count,
                distinct_detection_count=distinct_detection_count,
                volume_n=volume_n,
                breadth_n=breadth_n,
                diversity_n=diversity_n,
            ),
            timestamp=timestamp,
        )