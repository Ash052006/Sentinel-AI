"""Sigma detection engine exception hierarchy.

All exceptions derive from the existing :class:`DetectionError` base
so that callers can catch detection-layer errors uniformly.

Exception messages never expose rule content, event payloads, or
secrets.  Messages reference rule IDs only.
"""

from __future__ import annotations

from app.services.detection.exceptions import DetectionError


class SigmaDetectionError(DetectionError):
    """Base exception for all Sigma engine evaluation errors."""


class MalformedSigmaRuleError(SigmaDetectionError):
    """Raised when a Sigma rule cannot be parsed or is structurally invalid.

    This covers missing required fields, invalid YAML/dict structure,
    pySigma parse failures, and any other structural validation error
    that prevents the rule from being compiled into an evaluatable form.
    """

    def __init__(self, rule_id: str, *, reason: str = "parse failure") -> None:
        super().__init__(
            f"Sigma rule '{rule_id}' is malformed ({reason})"
        )
        self.rule_id = rule_id
        self.reason = reason


class UnsupportedSigmaFeatureError(SigmaDetectionError):
    """Raised when a Sigma rule uses a construct the engine does not support.

    The engine implements a **documented supported subset** of Sigma.
    Features outside that subset — regex modifiers, numeric comparisons,
    aggregation, correlation rules, unsupported logsource fields — are
    rejected explicitly rather than silently misinterpreted.
    """

    def __init__(self, rule_id: str, *, feature: str) -> None:
        super().__init__(
            f"Sigma rule '{rule_id}' uses unsupported feature: {feature}"
        )
        self.rule_id = rule_id
        self.feature = feature


class InvalidEventDataError(SigmaDetectionError):
    """Raised when the event provided for evaluation is invalid.

    This covers ``None`` events, wrong types, and any structural
    validation failure in the event data itself.
    """

    def __init__(self, message: str = "invalid event data") -> None:
        super().__init__(message)
