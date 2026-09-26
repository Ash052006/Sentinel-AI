"""Provider-layer exception hierarchy for threat intelligence.

Future providers and the registry use these exceptions to communicate
failures in a structured, distinguishable way.  Exception messages must
never expose secrets, API keys, or credentials.
"""


class ThreatIntelError(Exception):
    """Base exception for all threat-intelligence errors."""


class UnsupportedIndicatorTypeError(ThreatIntelError):
    """Raised when a provider does not support the requested indicator type."""

    def __init__(self, indicator_type: str, provider_name: str) -> None:
        super().__init__(
            f"Provider '{provider_name}' does not support "
            f"indicator type '{indicator_type}'"
        )
        self.indicator_type = indicator_type
        self.provider_name = provider_name


class ProviderNotFoundError(ThreatIntelError):
    """Raised when a provider name is not found in the registry."""

    def __init__(self, provider_name: str) -> None:
        super().__init__(f"Provider '{provider_name}' is not registered")
        self.provider_name = provider_name


class DuplicateProviderError(ThreatIntelError):
    """Raised when attempting to register a provider name that already exists."""

    def __init__(self, provider_name: str) -> None:
        super().__init__(f"Provider '{provider_name}' is already registered")
        self.provider_name = provider_name


class ProviderLookupError(ThreatIntelError):
    """Raised when a provider lookup fails at runtime."""

    def __init__(self, provider_name: str, reason: str) -> None:
        super().__init__(
            f"Provider '{provider_name}' lookup failed: {reason}"
        )
        self.provider_name = provider_name
        self.reason = reason


class InvalidIndicatorError(ThreatIntelError):
    """Raised when an indicator value is invalid or malformed."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"Invalid indicator: {reason}")
        self.reason = reason


class RateLimitError(ThreatIntelError):
    """Raised when the provider's API rate limit has been exceeded."""

    def __init__(
        self,
        provider_name: str,
        retry_after: float | None = None,
    ) -> None:
        msg = f"Rate limit exceeded for provider '{provider_name}'"
        if retry_after is not None:
            msg += f" (retry after {retry_after:.1f}s)"
        super().__init__(msg)
        self.provider_name = provider_name
        self.retry_after = retry_after
