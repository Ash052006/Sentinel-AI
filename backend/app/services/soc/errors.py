"""Exception hierarchy for the Natural Language SOC system (Step 23).

Distinguishes, conceptually:

1. configuration failure (missing/unusable Gemini credentials/settings)
2. invalid user input (bound/type violations; defense-in-depth)
3. secret-safety rejection (credential-shaped content anywhere fail-closed)
4. parser failure — malformed model output (not strict JSON / fences /
   prose / empty / oversized)
5. model-output validation failure (valid JSON but violates the candidate
   intent contract — unknown fields, bad enums, bad UUIDs, bounds)
6. provider / transport failure (timeouts, 4xx/5xx, unavailable)
7. allowlist-intent validation failure (unsupported resource/operation,
   invalid filter, missing/extra/malformed identifier, illegal pagination)
8. execution failure (downstream read-only query service failure)
9. unexpected internal failure

Messages are sanitized by construction: they never contain API keys,
authorization headers, request bodies, full prompts, raw user queries, or
raw provider responses.  Underlying causes are preserved via ``raise ...
from`` chains for internal diagnosis without leaking sensitive data in the
message.  The raw user query and the raw Gemini prompt are never logged and
never embedded in any exception message.
"""

from __future__ import annotations


class SOCError(Exception):
    """Base exception for all Natural Language SOC errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        #: Safe, consumer-facing message.  Never contains raw user text,
        #: model output, API keys, or database internals.
        self.message = message


class SOCConfigurationError(SOCError):
    """The SOC parser/provider is not configured correctly (missing API key,
    missing/unusable model name, invalid numeric settings)."""


class SOCInputValidationError(SOCError):
    """The user query input is invalid (blank, wrong type, or oversized)."""


class SOCSafetyError(SOCError):
    """Credential-shaped content was detected in the LLM's output candidate.

    Fail-closed: nothing unsafe is accepted, nothing is redacted or
    silently substituted, and nothing unsafe is echoed in any message.
    """


class SOCParserError(SOCError):
    """Base class for the LLM-output parsing and provider failure family."""


class SOCModelOutputError(SOCParserError):
    """LLM output is malformed as structured output: not strict JSON,
    fenced/prose-wrapped, empty, oversized, or multiple objects.

    Malformed output is rejected, never "repaired".
    """


class SOCModelValidationError(SOCParserError):
    """LLM returned valid JSON that violates the candidate-intent contract
    (unknown/forbidden fields, invalid enums, malformed UUIDs, out-of-bounds
    values, multiple target identifiers, inconsistent pagination)."""


class SOCProviderError(SOCParserError):
    """Gemini provider / transport failure (HTTP client errors, malformed
    provider payloads, unexpected HTTP statuses)."""

    def __init__(self, message: str, *, provider: str) -> None:
        super().__init__(message)
        self.provider = provider

    def __str__(self) -> str:  # pragma: no cover - cosmetic only
        return f"{self.provider} provider error: {self.message}"


class SOCProviderTimeoutError(SOCProviderError):
    """The provider request timed out (after bounded retries)."""


class SOCProviderUnavailableError(SOCProviderError):
    """The provider was unavailable or rate-limited (transport/5xx/429).

    A retry was already attempted for transient failures; this is the
    terminal outcome.
    """


class SOCIntentValidationError(SOCError):
    """A candidate intent violated the allowlist grammar (unsupported
    resource/operation, invalid filter, wrong/extra/missing identifier,
    illegal pagination).  Raised before any database access."""


class SOCExecutionError(SOCError):
    """A downstream read-only query service failed, or dispatch did not
    resolve.  The message is sanitized and never leaks database/query
    internals."""


class SOCInternalError(SOCError):
    """Unexpected internal failure that could not be attributed to a
    documented failure mode.  The cause is chained; the message stays safe."""