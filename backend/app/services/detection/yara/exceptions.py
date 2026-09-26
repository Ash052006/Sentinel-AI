"""YARA detection engine exception hierarchy.

All exceptions derive from the existing :class:`DetectionError` base
so that callers can catch detection-layer errors uniformly.

Exception messages never expose rule content, event payloads, or
secrets.  Messages reference rule IDs only.
"""

from __future__ import annotations

from app.services.detection.exceptions import DetectionError


class YaraDetectionError(DetectionError):
    """Base exception for all YARA engine evaluation errors."""


class MalformedYaraRuleError(YaraDetectionError):
    """Raised when a YARA rule cannot be compiled or is structurally invalid.

    This covers missing required fields, invalid YARA source syntax,
    compilation failures, and any other structural validation error
    that prevents the rule from being compiled into an evaluatable form.
    """

    def __init__(self, rule_id: str, *, reason: str = "compilation failure") -> None:
        super().__init__(
            f"YARA rule '{rule_id}' is malformed ({reason})"
        )
        self.rule_id = rule_id
        self.reason = reason


class UnsupportedYaraFeatureError(YaraDetectionError):
    """Raised when a YARA rule uses a construct the engine does not support.

    The engine implements a **documented supported subset** of YARA
    functionality.  Features outside that subset are rejected explicitly
    rather than silently misinterpreted.
    """

    def __init__(self, rule_id: str, *, feature: str) -> None:
        super().__init__(
            f"YARA rule '{rule_id}' uses unsupported feature: {feature}"
        )
        self.rule_id = rule_id
        self.feature = feature


class InvalidYaraTargetError(YaraDetectionError):
    """Raised when the target provided for YARA evaluation is invalid.

    This covers ``None`` targets, wrong types, missing file content,
    and any structural validation failure in the target data itself.
    """

    def __init__(self, message: str = "invalid YARA target") -> None:
        super().__init__(message)
