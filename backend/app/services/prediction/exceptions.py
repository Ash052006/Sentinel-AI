"""Governed failures for the attack prediction engine — V3.24.

Mirrors the V3.23 failure model: every failure is an explicit, typed signal
that reaches the client as a governed status code.  The invariant is that a
failure never degrades into a fabricated prediction — an unavailable input
produces ``INSUFFICIENT_EVIDENCE`` or a governed error, never a plausible
narrative.
"""

from __future__ import annotations


class PredictionError(Exception):
    """Base class for every V3.24 failure."""

    failure_code: str = "prediction_error"


class PredictionConfigurationError(PredictionError):
    """Prediction configuration is invalid or unusable."""

    failure_code = "prediction_configuration_error"


class PredictionContextError(PredictionError):
    """Required inputs could not be assembled."""

    failure_code = "prediction_context_error"


class PredictionBoundsError(PredictionError):
    """An architectural bound was exceeded.

    Raised instead of silently truncating.  Bounds are checked before anything
    is persisted, so an oversized request fails without leaving partial state.
    """

    failure_code = "prediction_bounds_error"


class PredictionEvidenceError(PredictionError):
    """An evidence reference failed to resolve, or grounding was violated."""

    failure_code = "prediction_evidence_error"


class PredictionValidationError(PredictionError):
    """A produced prediction violated its own contract."""

    failure_code = "prediction_validation_error"


class PredictionPersistenceError(PredictionError):
    """Persistence failed."""

    failure_code = "prediction_persistence_error"


class PredictionNotFoundError(PredictionError):
    """The requested prediction session or prediction does not exist."""

    failure_code = "prediction_not_found"


#: Failure code -> the closed vocabulary of codes this module can emit.
FAILURE_CODES: dict[str, str] = {
    "prediction_configuration_error": PredictionConfigurationError.failure_code,
    "prediction_context_error": PredictionContextError.failure_code,
    "prediction_bounds_error": PredictionBoundsError.failure_code,
    "prediction_evidence_error": PredictionEvidenceError.failure_code,
    "prediction_validation_error": PredictionValidationError.failure_code,
    "prediction_persistence_error": PredictionPersistenceError.failure_code,
    "prediction_not_found": PredictionNotFoundError.failure_code,
    "prediction_error": PredictionError.failure_code,
}


def failure_code(error: BaseException) -> str:
    """Return the closed failure code for ``error``."""
    code = getattr(error, "failure_code", None)
    if isinstance(code, str) and code in FAILURE_CODES:
        return code
    return "prediction_error"


__all__ = [
    "FAILURE_CODES",
    "PredictionBoundsError",
    "PredictionConfigurationError",
    "PredictionContextError",
    "PredictionError",
    "PredictionEvidenceError",
    "PredictionNotFoundError",
    "PredictionPersistenceError",
    "PredictionValidationError",
    "failure_code",
]