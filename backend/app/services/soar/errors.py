"""SOAR service error hierarchy (V2.18).

Every error carries only safe, sanitized identifiers (execution/playbook
UUIDS and ids) and bounded reasons — never raw payloads, secrets, or
database text.  The route layer maps them to HTTP semantics:

* :class:`SoarValidationError` -> 422 (malformed / unknown playbook / bad
  decision shape)
* :class:`SoarNotFoundError`   -> 404 (unknown execution or playbook)
* :class:`SoarConflictError`   -> 409 (lifecycle conflicts / disabled
  playbook)
* :class:`SoarServiceError`    -> 503 (sanitized infrastructure failure)
"""

from __future__ import annotations

import uuid
from typing import Any


class SoarError(Exception):
    """Base class for all SOAR service failures."""

    def __init__(self, message: str = "SOAR service error") -> None:
        super().__init__(message)
        self.message = message


class SoarValidationError(SoarError):
    """Raised for structurally or semantically invalid SOAR input.

    Examples: an unknown playbook id, a disabled playbook, a playbook
    whose primary action does not match the decision, or a malformed
    execution request.
    """


class SoarNotFoundError(SoarError):
    """Raised when an execution_id or playbook id does not identify a
    record."""

    def __init__(self, identifier: uuid.UUID | Any) -> None:
        message = f"SOAR record not found for {identifier}"
        super().__init__(message)
        self.identifier = identifier


class SoarConflictError(SoarError):
    """Raised for lifecycle conflicts (HTTP 409 semantics)."""


class SoarServiceError(SoarError):
    """Raised for sanitized infrastructure/database failures.

    The underlying exception is preserved as ``__cause__`` for server-side
    logging; the message never carries raw driver/SQL text.
    """

    def __init__(self, message: str = "SOAR service unavailable") -> None:
        super().__init__(message)


class SoarInternalError(SoarError):
    """Unexpected internal failure (idempotency-store exhaustion or engine
    invariant violation).  The cause is chained; the message stays safe."""


__all__ = [
    "SoarConflictError",
    "SoarError",
    "SoarInternalError",
    "SoarNotFoundError",
    "SoarServiceError",
    "SoarValidationError",
]