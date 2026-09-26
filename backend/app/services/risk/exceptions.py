"""Risk scoring subsystem exception hierarchy — Step 11B.

The Risk Scoring Agent and its scoring strategy communicate failures
through this structured, distinguishable hierarchy.  Exception messages
must never expose secrets, credentials, detection payloads, or raw
evidence: they describe *what* failed, never the security content that
failed.  The hierarchy mirrors the Step 10B correlation exception
conventions (``CorrelationError`` / ``CorrelationInputError`` /
``CorrelationStrategyError``).
"""


class RiskScoringError(Exception):
    """Base exception for all risk scoring subsystem errors."""


class RiskScoringInputError(RiskScoringError):
    """The risk scoring input violates the Step 10A / Step 11A contracts.

    Raised when the agent receives something other than a Step 10A
    ``CorrelationResult``.
    """


class RiskScoringStrategyError(RiskScoringError):
    """The configured risk scoring strategy failed unexpectedly.

    The original cause is preserved through the ``__cause__`` chain
    (raised via ``raise ... from``); the message is deliberately generic
    and never repeats the underlying exception's content.
    """