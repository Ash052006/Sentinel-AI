"""Threat Attribution Engine — deterministic, evidence-grounded attribution.

Step 15 of the SentinelAI build-out.  Public surface:

* :class:`~app.services.threat_attribution.engine.ThreatAttributionEngine` —
  the deterministic orchestrator.
* :class:`~app.services.threat_attribution.input.ThreatAttributionInput`,
  :class:`~app.services.threat_attribution.input.AttributionClaim`,
  :class:`~app.services.threat_attribution.input.AttributionContext` —
  explicit structured attribution signals the engine is allowed to use.
* :class:`~app.services.threat_attribution.policy.DeterministicAttributionStrategy`
  and the ``attribution_confidence`` / ``assess_status`` policy helpers.
* The attribution exception taxonomy from
  :class:`~app.services.threat_attribution.exceptions`.

The engine consumes the Step 14 attribution contract
(:mod:`app.schemas.threat_attribution`) and produces validated
:class:`~app.schemas.threat_attribution.AttributionAssessment` objects.
See ``docs/development/threat_attribution_engine.md`` for the full policy.
"""

from app.services.threat_attribution.engine import ThreatAttributionEngine
from app.services.threat_attribution.exceptions import (
    AttributionError,
    AttributionEvidenceReferenceError,
    AttributionOutputValidationError,
    AttributionSafetyError,
    AttributionStrategyError,
    InvalidAttributionInputError,
    UnsupportedAttributionSignalError,
)
from app.services.threat_attribution.input import (
    MAX_ATTRIBUTION_CLAIMS,
    AttributionClaim,
    AttributionContext,
    AttributionRelation,
    ThreatAttributionInput,
)
from app.services.threat_attribution.policy import (
    ATTRIBUTED_MIN_SUPPORTING_SIGNALS,
    CONFIDENCE_DECIMALS,
    CONFIDENCE_SATURATION,
    MIN_SUPPORTING_SIGNALS,
    POLICY_NAME,
    AttributionStrategy,
    DeterministicAttributionStrategy,
    assess_status,
    attribution_confidence,
)

__all__ = [
    "ATTRIBUTED_MIN_SUPPORTING_SIGNALS",
    "CONFIDENCE_DECIMALS",
    "CONFIDENCE_SATURATION",
    "MAX_ATTRIBUTION_CLAIMS",
    "MIN_SUPPORTING_SIGNALS",
    "POLICY_NAME",
    "AttributionClaim",
    "AttributionContext",
    "AttributionError",
    "AttributionEvidenceReferenceError",
    "AttributionOutputValidationError",
    "AttributionRelation",
    "AttributionSafetyError",
    "AttributionStrategy",
    "AttributionStrategyError",
    "DeterministicAttributionStrategy",
    "InvalidAttributionInputError",
    "ThreatAttributionEngine",
    "ThreatAttributionInput",
    "UnsupportedAttributionSignalError",
    "assess_status",
    "attribution_confidence",
]