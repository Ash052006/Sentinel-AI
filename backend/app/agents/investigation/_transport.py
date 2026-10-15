"""Shared cloud-LLM transport primitives.

Both reasoning providers — Gemini and Groq — are HTTP transports with the same
non-negotiable properties: an explicit bounded timeout, a *bounded* retry
budget spent only on genuinely transient failures, no retry on anything a
repeat cannot fix, and exception messages that never echo provider payloads.

Those properties live here so the two providers cannot drift apart.  The
Gemini client imported these definitions directly before Groq existed; it now
imports them from here, with no behavioural change and no duplication.  This
module is private to :mod:`app.agents.investigation`.
"""

from __future__ import annotations

from typing import Any

from app.agents.investigation.exceptions import InvestigationProviderError

#: Backoff base for transient retries (seconds), multiplicative per attempt.
RETRY_BASE_DELAY = 1.0

#: Upper bound on any single retry sleep (seconds), so a hostile or
#: nonsensical ``Retry-After`` header can never stall a request indefinitely.
MAX_RETRY_SLEEP_SECONDS = 30.0


class TransientProviderError(InvestigationProviderError):
    """Internal marker for retryable provider failures.

    Covers server errors and documented back-pressure responses (HTTP 429, and
    Groq's HTTP 498 flex-tier capacity signal).  Carries an optional
    provider-supplied ``retry_after`` so the caller can honour the server's own
    pacing hint instead of guessing.

    Never escapes a provider: consumers observe a regular
    :class:`~app.agents.investigation.exceptions.InvestigationProviderUnavailableError`
    once the retry budget is exhausted, so a transient failure is never
    reported as a permanent one.
    """

    def __init__(
        self,
        status: int,
        provider: str,
        *,
        retry_after: float | None = None,
        message: str | None = None,
        retry_after_header: float | None = None,
    ) -> None:
        super().__init__(
            message or f"server error (HTTP {status})", provider=provider
        )
        self.status = status
        self.retry_after = retry_after
        # Preserved for the provider-unavailable surface, which reports the
        # server's own pacing hint alongside the failure.
        self.retry_after_header = retry_after_header


def retry_after_seconds(response: Any) -> float | None:
    """Return a usable ``Retry-After`` delay from *response*, or ``None``.

    Only the delta-seconds form is honoured, and only when it is a finite,
    non-negative number.  The HTTP-date form and anything unparsable fall
    through to ``None`` so the caller uses its own bounded backoff instead of
    trusting an unverified value.

    Both providers document ``retry-after`` as delta-seconds (Groq: "In
    seconds", present only on a 429), so this is safe for either host.
    """
    header = response.headers.get("Retry-After")
    if not header:
        return None
    try:
        value = float(header)
    except (TypeError, ValueError):
        return None
    if value < 0 or value != value or value in (float("inf"), float("-inf")):
        return None
    return value


def backoff_delay(attempt: int, retry_after: float | None) -> float:
    """Return the sleep before retry *attempt*.

    A provider-supplied ``retry_after`` wins, because the provider knows when
    its own rate limit clears.  It is still clamped to
    :data:`MAX_RETRY_SLEEP_SECONDS` so a pathological header cannot turn a
    bounded retry into an unbounded stall.  With no usable hint the original
    bounded linear backoff is used unchanged.
    """
    if retry_after is not None:
        return min(retry_after, MAX_RETRY_SLEEP_SECONDS)
    return RETRY_BASE_DELAY * attempt


__all__ = [
    "MAX_RETRY_SLEEP_SECONDS",
    "RETRY_BASE_DELAY",
    "TransientProviderError",
    "backoff_delay",
    "retry_after_seconds",
]