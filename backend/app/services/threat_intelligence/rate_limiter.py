"""Rate limiter for manual threat-intelligence lookups.

Provides a thread-safe, in-process sliding-window rate limiter per identity
(e.g., user ID or client IP) to protect manual lookup endpoints from abuse
and prevent external provider socket and quota exhaustion.

NOTE on deployment architecture:
This is an in-process, memory-bounded sliding window limiter. In multi-worker
deployments (e.g., Uvicorn with multiple worker processes or multi-instance
clusters), rate limits are enforced per-worker rather than globally across all
processes. Distributed rate limiting would require an external state store
such as Redis; this design deliberately avoids adding an external infrastructure
dependency while providing strict per-process protection.
"""

from __future__ import annotations

import collections
import threading
import time
from typing import NamedTuple


class RateLimitStatus(NamedTuple):
    allowed: bool
    limit: int
    remaining: int
    reset_after: float


class InMemoryRateLimiter:
    """Thread-safe sliding-window rate limiter."""

    def __init__(self, requests_per_minute: int = 30) -> None:
        self._lock = threading.Lock()
        self._requests_per_minute = requests_per_minute
        self._window_seconds = 60.0
        self._history: dict[str, collections.deque[float]] = collections.defaultdict(collections.deque)
        self._enabled = True

    @property
    def requests_per_minute(self) -> int:
        return self._requests_per_minute

    @requests_per_minute.setter
    def requests_per_minute(self, value: int) -> None:
        with self._lock:
            self._requests_per_minute = max(1, value)

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        with self._lock:
            self._enabled = value

    def reset(self) -> None:
        """Clear all rate limit history (useful in tests)."""
        with self._lock:
            self._history.clear()

    def check(self, identity: str) -> RateLimitStatus:
        """Record an attempt and return whether it is allowed under the rate limit."""
        if not self._enabled:
            return RateLimitStatus(
                allowed=True,
                limit=self._requests_per_minute,
                remaining=self._requests_per_minute,
                reset_after=0.0,
            )

        now = time.monotonic()
        cutoff = now - self._window_seconds

        with self._lock:
            timestamps = self._history[identity]
            while timestamps and timestamps[0] <= cutoff:
                timestamps.popleft()

            count = len(timestamps)
            if count >= self._requests_per_minute:
                oldest = timestamps[0]
                reset_after = max(0.0, (oldest + self._window_seconds) - now)
                return RateLimitStatus(
                    allowed=False,
                    limit=self._requests_per_minute,
                    remaining=0,
                    reset_after=round(reset_after, 2),
                )

            timestamps.append(now)
            remaining = self._requests_per_minute - len(timestamps)
            return RateLimitStatus(
                allowed=True,
                limit=self._requests_per_minute,
                remaining=remaining,
                reset_after=self._window_seconds,
            )
