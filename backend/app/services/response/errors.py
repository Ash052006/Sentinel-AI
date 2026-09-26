"""Exception hierarchy for the Response & Mitigation layer (Step 25).

Distinguishes, conceptually:

1. input validation failure (structurally invalid request / unsupported
   action / malformed target — caller error)
2. policy-gate rejection (the decision is not ALLOWED, or the request
   does not match the decision) — the *executor* converts these into
   auditable ``REJECTED`` results; the exceptions exist for the lower
   layers to signal them cleanly
3. provider failure (a provider raised or was unavailable)
4. internal failure (engine defect / provisioning exhaustion,
   sanitized)

Messages are sanitized by construction: they never contain raw caller
values, secrets, identifiers, targets, prompts, or internals.
Underlying causes are preserved via ``raise ... from`` chains for
internal diagnosis without leaking sensitive data.  Nothing here ever
logs or echoes a target, token, or payload.
"""

from __future__ import annotations


class ResponseError(Exception):
    """Base exception for all Response & Mitigation errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        #: Safe, consumer-facing message, never echoing caller content.
        self.message = message


class ResponseValidationError(ResponseError):
    """The request/decision is structurally invalid, the action is
    unsupported, or the target is malformed."""


class ResponsePolicyGateError(ResponseError):
    """The authorization gate rejected the request (decision not
    ALLOWED, decision malformed, or request does not match decision).
    Raised by the gate helpers; the executor converts it to an auditable
    ``REJECTED`` result."""


class ResponseProviderError(ResponseError):
    """A provider failed or was unavailable.  Always converted to a
    ``FAILED`` result — never silently to success."""


class ResponseInternalError(ResponseError):
    """Unexpected internal failure (provisioning exhaustion, invariant
    violation).  The cause is chained; the message stays safe."""


__all__ = [
    "ResponseError",
    "ResponseValidationError",
    "ResponsePolicyGateError",
    "ResponseProviderError",
    "ResponseInternalError",
]