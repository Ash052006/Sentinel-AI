"""Threat Hunting error model — V2.19.

A closed hierarchy of domain errors that a hunt may terminate with.  Each
error maps 1:1 onto a sanitized ``error_code`` / ``error_message`` pair
persisted on the hunt row and surfaced to the analyst API.
"""

from __future__ import annotations


class ThreatHuntError(Exception):
    """Base class for all hunt domain errors."""

    code: str = "hunt.error"
    message: str = "Threat hunt error"

    def __init__(self, message: str | None = None) -> None:
        self.message = message or self.message
        super().__init__(self.message)


def sanitize(message: str) -> str:
    """Trim/bound a message for persistence (never raw payloads)."""
    return " ".join(message.split())[:500]


class HuntNotFoundError(ThreatHuntError):
    code = "HUNT_NOT_FOUND"
    message = "Hunt not found"


class HuntValidationError(ThreatHuntError):
    code = "HUNT_INVALID"
    message = "Hunt is not valid"

    def __init__(self, reason: str) -> None:
        super().__init__(reason or "Hunt is not valid")


class HuntStateError(ThreatHuntError):
    code = "HUNT_STATE_CONFLICT"
    message = "Hunt is not in a state that allows the requested operation"


class HuntAlreadyCompletedError(ThreatHuntError):
    code = "HUNT_ALREADY_COMPLETED"
    message = "Hunt has already run and completed"


class HuntAlreadyRunningError(ThreatHuntError):
    code = "HUNT_ALREADY_RUNNING"
    message = "Hunt is already running"


class HuntAlreadyFailedError(ThreatHuntError):
    code = "HUNT_ALREADY_FAILED"
    message = "Hunt has already failed"


class HuntAlreadyCancelledError(ThreatHuntError):
    code = "HUNT_ALREADY_CANCELLED"
    message = "Hunt has already been cancelled"


class HuntLimitError(ThreatHuntError):
    """A run hit a hard bound and was stopped (never partial/hidden data)."""

    code = "HUNT_LIMIT_EXCEEDED"
    message = "Hunt exceeded a configured bound and was stopped"


class HuntExecutionError(ThreatHuntError):
    code = "HUNT_EXECUTION_FAILED"
    message = "Hunt execution failed"


class HuntUnexpectedError(ThreatHuntError):
    code = "HUNT_INTERNAL"
    message = "Hunt failed with an unexpected internal error"


__all__ = [
    "ThreatHuntError",
    "sanitize",
    "HuntNotFoundError",
    "HuntValidationError",
    "HuntStateError",
    "HuntAlreadyCompletedError",
    "HuntAlreadyRunningError",
    "HuntAlreadyFailedError",
    "HuntAlreadyCancelledError",
    "HuntLimitError",
    "HuntExecutionError",
    "HuntUnexpectedError",
]