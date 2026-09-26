"""Exception hierarchy for the Step 12C AI Investigation Agent.

Distinguishes, conceptually:

1. configuration failure
2. provider/transport failure
3. provider timeout
4. provider unavailable / rate-limited failure
5. malformed model output (not strict JSON / fences / prose / empty)
6. model-output validation failure (valid JSON but violates the contract)
7. invalid evidence reference (dangling / fabricated)
8. secret-safety rejection
9. invalid InvestigationContext input
10. unexpected internal agent failure

Messages are sanitized by construction: they never contain API keys,
authorization headers, request bodies, full prompts, full contexts, or raw
provider responses.  Underlying causes are preserved via ``raise ... from``
chains for internal diagnosis without leaking sensitive data in the message.
"""


class InvestigationAgentError(Exception):
    """Base exception for all Step 12C investigation-agent errors."""


class InvestigationConfigurationError(InvestigationAgentError):
    """The agent/provider is not configured correctly (missing API key,
    missing/unusable model name, invalid numeric settings).

    The message is sanitized and never reveals the secret value.
    """


class InvestigationProviderError(InvestigationAgentError):
    """Gemini provider / transport failure (HTTP client errors, malformed
    provider payloads, unexpected HTTP statuses).  Provider model name is a
    safe non-secret identifier and may be attached.
    """

    def __init__(self, message: str, *, provider: str) -> None:
        super().__init__(f"{provider} provider error: {message}")
        self.provider = provider


class InvestigationProviderTimeoutError(InvestigationProviderError):
    """The provider request timed out (after bounded retries)."""


class InvestigationProviderUnavailableError(InvestigationProviderError):
    """The provider was unavailable or rate-limited (transport/5xx/429).

    A retry was already attempted for transient failures; this is the
    terminal outcome.  ``retry_after`` carries an optional server-provided
    backoff hint that is not a secret.
    """

    def __init__(
        self,
        message: str,
        *,
        provider: str,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message, provider=provider)
        self.retry_after = retry_after


class InvestigationModelOutputError(InvestigationAgentError):
    """Gemini output is malformed as structured output: not strict JSON,
    surrounded by prose/Markdown fences, an empty output, multiple JSON
    objects, or otherwise unparseable.  Malformed output is never repaired.
    """


class InvestigationModelValidationError(
    InvestigationModelOutputError
):
    """Gemini returned valid JSON that violates the model-output contract
    (missing fields, wrong types, unknown/forbidden fields, bounds
    violations, out-of-range confidence, oversized output, malformed
    evidence ids).  The output is rejected, never truncated.
    """


class InvestigationEvidenceError(InvestigationAgentError):
    """A finding references an evidence id that is not present in the
    supplied InvestigationContext (dangling or fabricated reference).  The
    entire model output is rejected; nothing is silently removed or fixed.
    """


class InvestigationSecretSafetyError(InvestigationAgentError):
    """Credential-shaped content was detected in the prompt or model output.
    Fail-closed: nothing is sent to or accepted from the provider.
    """


class InvestigationContextError(InvestigationAgentError):
    """The input to ``investigate``/``build`` is not a valid
    :class:`~app.schemas.investigation_context.InvestigationContext`.
    """


class InvestigationInternalError(InvestigationAgentError):
    """Unexpected internal agent failure that could not be attributed to a
    documented failure mode.  The cause is chained; the message stays safe.
    """