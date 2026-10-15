"""Governed failures for the V3.23 multi-agent debate engine.

Every failure mode is a distinct, *named* exception so a caller can tell the
difference between "the provider was unreachable" and "the model returned a
fabricated evidence reference".  Collapsing those into one generic error would
make an unavailable model indistinguishable from a successful debate with weak
conclusions — exactly the dishonesty V3.23 exists to prevent.

The governing rule: **a debate failure never becomes a successful debate.**
There is no silent deterministic fallback that manufactures consensus when the
provider is unavailable.  A caller either receives a validated debate or an
explicit, classifiable failure.
"""

from __future__ import annotations


class DebateError(Exception):
    """Base class for every debate failure."""


class DebateConfigurationError(DebateError):
    """The engine or a runtime was configured incorrectly."""


class DebateContextError(DebateError):
    """The supplied evidence context is missing, malformed, or unbounded."""


class DebateEvidenceError(DebateError):
    """An evidence reference did not resolve to real persisted evidence.

    This covers fabricated identifiers, references to entities outside the
    supplied graph, and references to unavailable entity kinds.  It is the most
    security-relevant failure in the engine: the model proposed citing something
    that does not exist.
    """


class DebateModelOutputError(DebateError):
    """The provider returned output that was not strict JSON."""


class DebateModelValidationError(DebateError):
    """The provider returned valid JSON that failed the output contract.

    Raised when a payload contains an unknown field, an out-of-vocabulary
    claim kind, a blank statement, an out-of-range confidence, or more objects
    than the configured bounds allow.  Output is rejected, never repaired and
    never truncated.
    """


class DebateSecretSafetyError(DebateError):
    """Credential-shaped content was detected at the AI trust boundary.

    Raised for unsafe input *and* for unsafe model output.  Nothing is
    redacted and substituted: detection fails closed.
    """


class DebateBoundsError(DebateError):
    """A bound was exceeded, or a bound was invalid at construction."""


class DebatePersistenceError(DebateError):
    """A debate could not be persisted or loaded."""


class DebateProviderError(DebateError):
    """The reasoning provider failed (transport, timeout, or unavailable)."""


class DebateProviderTimeoutError(DebateProviderError):
    """The reasoning provider did not respond within the timeout."""


class DebateProviderUnavailableError(DebateProviderError):
    """The reasoning provider is unreachable or refused the request."""


class DebatePartialFailureError(DebateError):
    """One or more agents failed, so no consensus could be reached.

    Distinct from a provider error on a single agent: the debate as a whole is
    incomplete and is reported as such rather than being scored over the
    agents that happened to succeed.
    """

    def __init__(
        self,
        message: str,
        *,
        failed_agents: tuple[str, ...] = (),
        failure_code: str | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message)
        self.failed_agents = failed_agents
        # The aggregate failure must not erase *why* the agents failed. Without
        # this a provider outage and a fabricated citation would both surface as
        # an opaque "partial failure", and the API could not map one to a 503
        # and the other to a 422. The code is taken from the first underlying
        # failure in deterministic (sorted role) order.
        self.failure_code = failure_code or "debate_partial_failure"
        self.cause = cause


#: Stable, non-secret failure codes exposed by the API so a client can react
#: programmatically without string-matching a human-readable message.
FAILURE_CODES: dict[type[DebateError], str] = {
    DebateConfigurationError: "debate_configuration_error",
    DebateContextError: "debate_context_error",
    DebateEvidenceError: "debate_evidence_error",
    DebateModelOutputError: "debate_model_output_error",
    DebateModelValidationError: "debate_model_validation_error",
    DebateSecretSafetyError: "debate_secret_safety_error",
    DebateBoundsError: "debate_bounds_error",
    DebatePersistenceError: "debate_persistence_error",
    DebateProviderTimeoutError: "debate_provider_timeout",
    DebateProviderUnavailableError: "debate_provider_unavailable",
    DebateProviderError: "debate_provider_error",
    DebatePartialFailureError: "debate_partial_failure",
}


def failure_code(error: BaseException) -> str:
    """Return the stable failure code for *error*.

    Unknown exception types map to a generic code so a new failure mode can
    never accidentally surface as a successful debate or leak its type name.
    """
    for error_type, code in FAILURE_CODES.items():
        if isinstance(error, error_type):
            return code
    return "debate_internal_error"


__all__ = [
    "FAILURE_CODES",
    "DebateBoundsError",
    "DebateConfigurationError",
    "DebateContextError",
    "DebateError",
    "DebateEvidenceError",
    "DebateModelOutputError",
    "DebateModelValidationError",
    "DebatePartialFailureError",
    "DebatePersistenceError",
    "DebateProviderError",
    "DebateProviderTimeoutError",
    "DebateProviderUnavailableError",
    "DebateSecretSafetyError",
    "failure_code",
]