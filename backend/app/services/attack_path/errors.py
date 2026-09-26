"""Attack Path Visualization error hierarchy — V2.21.

Read-only projection errors.  ``AttackPathCorrelationNotFoundError`` maps to
HTTP 404 (the only expected runtime condition); source failures map to 503;
validation and unexpected defects stay internal to the service so the
transport can translate them consistently with the rest of the API.
"""

from __future__ import annotations


class AttackPathError(Exception):
    """Base class for attack-path projection errors."""


class AttackPathCorrelationNotFoundError(AttackPathError):
    """No persisted correlation exists for the requested correlation id."""


class AttackPathSourceError(AttackPathError):
    """A read of persisted source data failed; the projection is unavailable."""


class AttackPathValidationError(AttackPathError):
    """The projection request or assembled graph violated a contract."""


class AttackPathUnexpectedError(AttackPathError):
    """An internal defect prevented the projection from being built."""


__all__ = [
    "AttackPathError",
    "AttackPathCorrelationNotFoundError",
    "AttackPathSourceError",
    "AttackPathValidationError",
    "AttackPathUnexpectedError",
]