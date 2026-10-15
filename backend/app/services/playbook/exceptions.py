"""Governed failures for the playbook generation engine — V3.25.

Mirrors the V3.23/V3.24 failure model: every failure is an explicit, typed
signal that reaches the client as a governed status code carrying a
``failure_code`` and a ``detail``.

The invariant is that a failure never degrades into a fabricated playbook.  When
inputs are insufficient the engine reports ``INSUFFICIENT_EVIDENCE`` — a
successful, empty answer — rather than inventing a response plan.  A failure is
reserved for the cases where the engine genuinely cannot produce a trustworthy
answer: unresolvable inputs, exceeded bounds, or violated contracts.
"""

from __future__ import annotations


class PlaybookError(Exception):
    """Base class for every V3.25 failure."""

    failure_code: str = "playbook_error"


class PlaybookConfigurationError(PlaybookError):
    """Playbook configuration is invalid or unusable."""

    failure_code = "playbook_configuration_error"


class PlaybookContextError(PlaybookError):
    """Required inputs could not be assembled."""

    failure_code = "playbook_context_error"


class PlaybookBoundsError(PlaybookError):
    """An architectural bound was exceeded.

    Raised instead of silently truncating.  Bounds are checked before anything is
    persisted, so an oversized run fails without leaving partial state.
    """

    failure_code = "playbook_bounds_error"


class PlaybookEvidenceError(PlaybookError):
    """An evidence reference failed to resolve, or grounding was violated."""

    failure_code = "playbook_evidence_error"


class PlaybookSafetyError(PlaybookError):
    """A proposed action violated the safety model.

    Covers arbitrary action injection, broad or ambiguous targets, invented
    rollback, lifecycle escalation, and any attempt to ground a destructive
    action in a prediction alone.
    """

    failure_code = "playbook_safety_error"


class PlaybookDependencyError(PlaybookError):
    """The proposed dependency graph is invalid or cyclic."""

    failure_code = "playbook_dependency_error"


class PlaybookValidationError(PlaybookError):
    """A produced playbook violated its own contract."""

    failure_code = "playbook_validation_error"


class PlaybookPersistenceError(PlaybookError):
    """Persistence failed."""

    failure_code = "playbook_persistence_error"


class PlaybookNotFoundError(PlaybookError):
    """The requested playbook does not exist."""

    failure_code = "playbook_not_found"


class PlaybookProviderError(PlaybookError):
    """The optional model-candidate provider failed.

    Distinct from :class:`PlaybookGenerationProviderError` only in ownership: this
    is the transport-level signal from the reused V3.23 provider client.  Its
    message is never propagated to a client verbatim — provider failures are
    sanitized before they leave the process.
    """

    failure_code = "playbook_generation_provider_error"


class PlaybookGenerationProviderError(PlaybookProviderError):
    """Provider raised an error that could not be normalized.

    Carries no credential, header or payload: the reused client already
    sanitizes its own messages, and this layer refuses to add anything to them.
    """

    failure_code = "playbook_generation_provider_error"


class PlaybookModelOutputError(PlaybookError):
    """Model output could not be parsed into the candidate contract."""

    failure_code = "playbook_model_output_error"


class PlaybookModelCandidateError(PlaybookError):
    """A model-proposed candidate failed validation and was rejected.

    Raised only in the strict mode where a single rejected candidate invalidates
    the run.  In the default advisory mode the candidate is dropped and recorded
    as a limitation instead.
    """

    failure_code = "playbook_model_candidate_error"


#: Failure code -> the closed vocabulary of codes this module can emit.
FAILURE_CODES: dict[str, str] = {
    "playbook_configuration_error": PlaybookConfigurationError.failure_code,
    "playbook_context_error": PlaybookContextError.failure_code,
    "playbook_bounds_error": PlaybookBoundsError.failure_code,
    "playbook_evidence_error": PlaybookEvidenceError.failure_code,
    "playbook_safety_error": PlaybookSafetyError.failure_code,
    "playbook_dependency_error": PlaybookDependencyError.failure_code,
    "playbook_validation_error": PlaybookValidationError.failure_code,
    "playbook_persistence_error": PlaybookPersistenceError.failure_code,
    "playbook_not_found": PlaybookNotFoundError.failure_code,
    "playbook_generation_provider_error": PlaybookProviderError.failure_code,
    "playbook_model_output_error": PlaybookModelOutputError.failure_code,
    "playbook_model_candidate_error": PlaybookModelCandidateError.failure_code,
    "playbook_error": PlaybookError.failure_code,
}


def failure_code(error: BaseException) -> str:
    """Return the closed failure code for ``error``.

    Unknown exception types collapse to ``playbook_error`` rather than leaking
    their class name, which keeps internal structure out of API responses.
    """
    code = getattr(error, "failure_code", None)
    if isinstance(code, str) and code in FAILURE_CODES:
        return code
    return "playbook_error"


__all__ = [
    "FAILURE_CODES",
    "PlaybookBoundsError",
    "PlaybookConfigurationError",
    "PlaybookContextError",
    "PlaybookDependencyError",
    "PlaybookError",
    "PlaybookEvidenceError",
    "PlaybookGenerationProviderError",
    "PlaybookModelCandidateError",
    "PlaybookModelOutputError",
    "PlaybookNotFoundError",
    "PlaybookPersistenceError",
    "PlaybookProviderError",
    "PlaybookSafetyError",
    "PlaybookValidationError",
    "failure_code",
]