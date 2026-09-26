"""Risk scoring engine — Step 11B.

Implements the deterministic risk scoring strategy abstraction consumed by
the Risk Scoring Agent (see :mod:`app.agents.risk_scoring`).

Step 11A defined the ``RiskAssessment`` domain contract; Step 11B
implements the first **deterministic baseline risk scoring engine**
(evidence-driven cardinality scoring of a Step 10A ``CorrelationResult``)
together with the agent that consumes a Step 10A ``CorrelationResult`` and
produces Step 11A ``RiskAssessment`` objects.

No persistence, no API, no incidents, no MITRE ATT&CK, no response, and
no storage/network/AI dependencies exist in this step — the engine works
entirely in memory and deterministically.
"""

from app.services.risk.exceptions import (
    RiskScoringError,
    RiskScoringInputError,
    RiskScoringStrategyError,
)
from app.services.risk.engine import (
    BREADTH_REFERENCE,
    CONFIDENCE_ABSENT_BASELINE,
    DIVERSITY_REFERENCE,
    LEVEL_CRITICAL_MIN,
    LEVEL_HIGH_MAX,
    LEVEL_LOW_MAX,
    LEVEL_MEDIUM_MAX,
    POLICY_NAME,
    ROUND_DECIMALS,
    VOLUME_REFERENCE,
    WEIGHT_BREADTH,
    WEIGHT_DIVERSITY,
    WEIGHT_VOLUME,
    DeterministicRiskScoringEngine,
    RiskScoringStrategy,
    clamp01,
    confidence_for_correlation,
    normalize_excess,
    risk_level_for_score,
)

__all__ = [
    "RiskScoringError",
    "RiskScoringInputError",
    "RiskScoringStrategyError",
    "RiskScoringStrategy",
    "DeterministicRiskScoringEngine",
    "clamp01",
    "normalize_excess",
    "risk_level_for_score",
    "confidence_for_correlation",
    "ROUND_DECIMALS",
    "VOLUME_REFERENCE",
    "BREADTH_REFERENCE",
    "DIVERSITY_REFERENCE",
    "WEIGHT_VOLUME",
    "WEIGHT_BREADTH",
    "WEIGHT_DIVERSITY",
    "CONFIDENCE_ABSENT_BASELINE",
    "LEVEL_LOW_MAX",
    "LEVEL_MEDIUM_MAX",
    "LEVEL_HIGH_MAX",
    "LEVEL_CRITICAL_MIN",
    "POLICY_NAME",
]