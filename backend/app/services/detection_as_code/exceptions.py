"""Detection-as-Code domain exceptions (V2.17).

Every reviewable failure in the lifecycle has a typed error the API layer
maps to its HTTP semantics (mirrors ``app/services/approval/errors.py``).
All messages are sanitized, deterministic and never echo rule content or
credentials.
"""

from __future__ import annotations


class DetectionAsCodeError(Exception):
    """Base class for all Detection-as-Code domain errors."""


class ManifestValidationError(DetectionAsCodeError):
    """The controlled manifest / rule set is inconsistent or malformed."""


class SourceIntegrityError(DetectionAsCodeError):
    """A source file fails an integrity/security gate (hash, path, type)."""


class DetectionRuleNotFoundError(DetectionAsCodeError):
    """No governed rule/persistence rows exist for the requested identity."""


class VersionConflictError(DetectionAsCodeError):
    """A version identity conflicts with an existing immutable version."""


class ValidationConflictError(DetectionAsCodeError):
    """Validation cannot run in the requested way for this rule."""


class ReleaseConflictError(DetectionAsCodeError):
    """A release transition is invalid for the current release state."""


class DeploymentConflictError(DetectionAsCodeError):
    """A deployment/rollback transition is invalid for the current state."""


class UnauthorizedLifecycleAction(DetectionAsCodeError):
    """A lifecycle action requires a higher role (mapped to 403 upstream)."""


__all__ = [
    "DetectionAsCodeError",
    "ManifestValidationError",
    "SourceIntegrityError",
    "DetectionRuleNotFoundError",
    "VersionConflictError",
    "ValidationConflictError",
    "ReleaseConflictError",
    "DeploymentConflictError",
    "UnauthorizedLifecycleAction",
]