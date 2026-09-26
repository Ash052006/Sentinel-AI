"""Sigma Detection Engine — Step 9C.

Evaluates Sigma rules against SentinelAI normalized security events and
produces deterministic, auditable :class:`DetectionResult` objects.

This module implements a **documented supported subset** of Sigma
functionality.  Unsupported constructs are rejected explicitly — the
engine never silently ignores or misinterprets unsupported Sigma features.

Supported constructs
--------------------
* Detection conditions: ``and``, ``or``, ``not``, selection-based.
* Condition qualifiers: ``1 of them``, ``all of them``,
  ``1 of <prefix>*``, ``all of <prefix>*``.
* Value matching: exact, wildcard (``*`` / ``?``), lists (OR).
* Modifiers: ``|contains``, ``|startswith``, ``|endswith``,
  ``|cased`` (case-sensitive).
* Logsource: ``category`` and ``product`` (documented mapping subset).
* Field-less detection items (keyword search across all string values).

Unsupported constructs
---------------------
* Regex modifier (``|re``), base64, UTF-16, windash, numeric comparison
  modifiers, cidr, expand, timestamp modifiers.
* ``near`` aggregation, ``count()`` / ``| count`` qualifiers.
* ``ruletype`` (correlation rules).
* ``service`` and ``definition`` logsource fields.
* ``SigmaNull`` / ``NoneType`` value comparisons.

Relationship to the pipeline::

    NormalizedSecurityEvent
        → SigmaDetectionEngine.evaluate()
            → SigmaDetectionReport
                → DetectionResult (matches only)
"""

from app.services.detection.sigma.engine import (
    SigmaDetectionEngine,
    SigmaDetectionReport,
    SigmaRuleFailure,
)
from app.services.detection.sigma.exceptions import (
    InvalidEventDataError,
    MalformedSigmaRuleError,
    SigmaDetectionError,
    UnsupportedSigmaFeatureError,
)

__all__ = [
    "SigmaDetectionEngine",
    "SigmaDetectionReport",
    "SigmaRuleFailure",
    "SigmaDetectionError",
    "MalformedSigmaRuleError",
    "UnsupportedSigmaFeatureError",
    "InvalidEventDataError",
]
