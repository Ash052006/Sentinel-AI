"""Detection registry exception hierarchy.

The rule registry uses these exceptions to communicate rule-management
failures in a structured, distinguishable way.  Exception messages must
never expose secrets, API keys, credentials, or rule content.
"""


class DetectionError(Exception):
    """Base exception for all detection rule-management errors."""


class DuplicateDetectionRuleError(DetectionError):
    """Raised when attempting to register a rule_id that already exists."""

    def __init__(self, rule_id: str, version: str | None = None) -> None:
        msg = f"Detection rule '{rule_id}' is already registered"
        if version is not None:
            msg += f" (version {version})"
        super().__init__(msg)
        self.rule_id = rule_id
        self.version = version


class DetectionRuleNotFoundError(DetectionError):
    """Raised when a rule_id is not found in the registry."""

    def __init__(self, rule_id: str) -> None:
        super().__init__(f"Detection rule '{rule_id}' is not registered")
        self.rule_id = rule_id
