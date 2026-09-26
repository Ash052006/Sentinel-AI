"""Approval service error hierarchy (V2.16).

Every error carries only safe, sanitized identifiers (approval/decision
UUIDs) and bounded reasons — never raw payloads, secrets, or database
text.  The route layer maps them to HTTP semantics:

* :class:`ApprovalValidationError` -> 422 (malformed / non-approval input)
* :class:`ApprovalNotFoundError`   -> 404 (unknown approval_id)
* :class:`ApprovalConflictError`   -> 409 (already resolved / invalid
  transition / duplicate lifecycle on a consumed decision)
* :class:`ApprovalServiceError`    -> 503 (sanitized infrastructure failure)
"""

from __future__ import annotations

import uuid
from typing import Any


class ApprovalError(Exception):
    """Base class for all approval-service failures."""

    def __init__(self, message: str = "Approval workflow error") -> None:
        super().__init__(message)
        self.message = message


class ApprovalValidationError(ApprovalError):
    """Raised for structurally or semantically invalid approval input.

    Examples: a decision that is not ``REQUIRES_APPROVAL``, a malformed
    target for its action, or a blank/oversized resolution comment.
    """


class ApprovalNotFoundError(ApprovalError):
    """Raised when an approval_id does not identify a request."""

    def __init__(self, approval_id: uuid.UUID | Any) -> None:
        message = f"Approval request not found for {approval_id}"
        super().__init__(message)
        self.approval_id = approval_id


class ApprovalConflictError(ApprovalError):
    """Raised for lifecycle conflicts (HTTP 409 semantics).

    Examples: approving an already-rejected (or expired/cancelled) request,
    or re-creating a request whose decision already resolved.
    """


class ApprovalServiceError(ApprovalError):
    """Raised for sanitized infrastructure/database failures.

    The underlying exception is preserved as ``__cause__`` for server-side
    logging; the message never carries raw driver/SQL text.
    """

    def __init__(self, message: str = "Approval service unavailable") -> None:
        super().__init__(message)


__all__ = [
    "ApprovalConflictError",
    "ApprovalError",
    "ApprovalNotFoundError",
    "ApprovalServiceError",
    "ApprovalValidationError",
]