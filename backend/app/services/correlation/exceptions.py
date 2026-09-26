"""Correlation subsystem exception hierarchy — Step 10B.

The Correlation Agent and its strategies communicate failures through
this structured, distinguishable hierarchy.  Exception messages must
never expose secrets, credentials, detection payloads, or raw evidence:
they describe *what* failed, never the security content that failed.
"""


class CorrelationError(Exception):
    """Base exception for all correlation subsystem errors."""


class CorrelationInputError(CorrelationError):
    """The correlation input violates the Step 9I / Step 10A contracts.

    Raised when the agent receives something other than a Step 9I
    ``DetectionCorrelationBatch``, or when a strategy receives a record
    that is not a ``DetectionCorrelationInput``.
    """


class CorrelationStrategyError(CorrelationError):
    """The configured correlation strategy failed unexpectedly.

    The original cause is preserved through the ``__cause__`` chain
    (raised via ``raise ... from``); the message is deliberately generic
    and never repeats the underlying exception's content.
    """