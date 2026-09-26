"""Exception hierarchy for the Policy Decision Engine (Step 24).

Distinguishes, conceptually:

1. input validation failure (caller provided invalid/structurally
   malformed policy input — a catch-all for the engine boundary, since
   the contract itself validates with Pydantic)
2. rule configuration failure (duplicate rule ids, malformed rule set)
3. internal failure (unexpected engine defect, sanitized)

Messages are sanitized by construction: they never contain raw caller
values, secrets, identifiers, prompts, or internals.  Underlying causes
are preserved via ``raise ... from`` chains for internal diagnosis
without leaking sensitive data in the message.  The engine never emits
any log or exception that echoes evaluation context.
"""

from __future__ import annotations


class PolicyError(Exception):
    """Base exception for all Policy Decision Engine errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        #: Safe, consumer-facing message.  Never contains raw caller
        #: values, secrets, identifiers, or internals.
        self.message = message


class PolicyInputValidationError(PolicyError):
    """The policy input is structurally invalid or uses an unsupported
    action.  Raised at the engine boundary; the Pydantic contract itself
    raises ``ValidationError`` on direct construction."""


class PolicyRuleConfigurationError(PolicyError):
    """The rule registry is inconsistent (duplicate/malformed rule set).
    Raised before any evaluation; the engine fails closed."""


class PolicyEvaluationError(PolicyError):
    """An evaluation could not be completed safely.  Fail-closed: no
    decision is fabricated here."""


class PolicyInternalError(PolicyError):
    """Unexpected internal failure that could not be attributed to a
    documented failure mode.  The cause is chained; the message stays
    safe."""


__all__ = [
    "PolicyError",
    "PolicyInputValidationError",
    "PolicyRuleConfigurationError",
    "PolicyEvaluationError",
    "PolicyInternalError",
]