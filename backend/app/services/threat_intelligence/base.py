"""Abstract provider interface and result contract for threat intelligence.

Every future threat-intelligence provider (VirusTotal, AbuseIPDB,
AlienVault OTX, etc.) implements :class:`ThreatIntelProvider` and
returns :class:`ThreatIntelResult` instances.

The result contract is intentionally provider-neutral so that
downstream consumers (the future Threat Intelligence Agent) can
process results uniformly regardless of which provider produced them.

Architecture::

    ThreatIntelProvider
         |
         |  lookup(ThreatIndicator) -> ThreatIntelResult
         |
         v
    ThreatIntelResult
         |
         |  (mapped by the future Threat Intelligence Agent)
         v
    EnrichmentResult
         |
         v
    EnrichedSecurityEvent
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.services.threat_intelligence.exceptions import (
    UnsupportedIndicatorTypeError,
)
from app.services.threat_intelligence.types import (
    IndicatorType,
    ThreatIndicator,
)


# ---------------------------------------------------------------------------
# ThreatIntelResult
# ---------------------------------------------------------------------------

class ThreatIntelResult(BaseModel):
    """Provider-neutral result of a threat-intelligence lookup.

    Every provider produces this same structure regardless of its
    internal API format.  The ``data`` field is intentionally
    untyped (JSON-compatible dict) so that provider-specific
    payloads do not require schema changes in SentinelAI.

    Attributes:
        indicator: The indicator that was looked up.
        provider: Name of the provider that produced this result.
        found: Whether the provider had any information about the indicator.
        data: Provider-specific payload (must be JSON-serializable).
        confidence: Optional numeric confidence in [0.0, 1.0].
        timestamp: When the lookup was performed (timezone-aware UTC).
        metadata: Optional provider-specific metadata.
    """

    indicator: ThreatIndicator = Field(
        ...,
        description="The indicator that was looked up.",
    )

    provider: str = Field(
        ...,
        min_length=1,
        description="Name of the provider that produced this result.",
    )

    found: bool = Field(
        ...,
        description=(
            "Whether the provider had any information about the indicator."
        ),
    )

    data: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Provider-specific payload.  Must be JSON-serializable."
        ),
    )

    confidence: float | None = Field(
        default=None,
        description="Optional numeric confidence score in [0.0, 1.0].",
    )

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description=(
            "When the lookup was performed (timezone-aware UTC)."
        ),
    )

    metadata: dict[str, Any] | None = Field(
        default=None,
        description="Optional provider-specific metadata.",
    )

    # -- Validators --------------------------------------------------------

    @field_validator("timestamp")
    @classmethod
    def _ensure_timezone_aware(cls, v: datetime) -> datetime:
        """Reject naive (timezone-unaware) timestamps."""
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError(
                "timestamp must be timezone-aware; "
                "naive (UTC-less) timestamps are not accepted"
            )
        return v

    @field_validator("confidence")
    @classmethod
    def _validate_confidence(cls, v: float | None) -> float | None:
        """Constrain confidence to [0.0, 1.0] when provided."""
        if v is None:
            return v
        if not (0.0 <= v <= 1.0):
            raise ValueError(
                f"confidence must be between 0.0 and 1.0, got {v}"
            )
        return v

    @field_validator("data")
    @classmethod
    def _ensure_data_json_compatible(
        cls, v: dict[str, Any]
    ) -> dict[str, Any]:
        """Ensure data is strictly JSON-serializable."""
        try:
            json.dumps(v)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"data must be JSON-compatible: {exc}"
            ) from exc
        return v

    @field_validator("metadata")
    @classmethod
    def _ensure_metadata_json_compatible(
        cls, v: dict[str, Any] | None
    ) -> dict[str, Any] | None:
        """Ensure metadata is strictly JSON-serializable when provided."""
        if v is None:
            return v
        try:
            json.dumps(v)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"metadata must be JSON-compatible: {exc}"
            ) from exc
        return v



# ---------------------------------------------------------------------------
# ThreatIntelProvider  (abstract)
# ---------------------------------------------------------------------------

class ThreatIntelProvider(ABC):
    """Abstract interface that every threat-intelligence provider must implement.

    The interface defines three key elements:

    * ``provider_name`` — a unique human-readable name.
    * ``supported_indicator_types`` — which IoC types this provider can handle.
    * ``lookup(indicator)`` — perform the lookup and return a result.

    Future implementations::

        class VirusTotalProvider(ThreatIntelProvider):
            provider_name = "VirusTotal"
            ...

        class AbuseIPDBProvider(ThreatIntelProvider):
            provider_name = "AbuseIPDB"
            ...

        class AlienVaultOTXProvider(ThreatIntelProvider):
            provider_name = "AlienVault OTX"
            ...

    The ``lookup`` method must return a :class:`ThreatIntelResult`.
    It must NOT make any network calls, database queries, or
    side-effects in the base contract.  Actual network access will be
    added when concrete providers are implemented.
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Unique human-readable name for this provider (e.g. 'VirusTotal')."""
        ...

    @property
    @abstractmethod
    def supported_indicator_types(self) -> frozenset[IndicatorType]:
        """Set of indicator types this provider can look up."""
        ...

    @abstractmethod
    def lookup(self, indicator: ThreatIndicator) -> ThreatIntelResult:
        """Perform a threat-intelligence lookup for *indicator*.

        Returns:
            A :class:`ThreatIntelResult` containing the provider's
            response for the given indicator.

        Raises:
            UnsupportedIndicatorTypeError: If the indicator type is not
                supported by this provider.
        """
        ...

    def supports(self, indicator_type: IndicatorType) -> bool:
        """Return True if this provider supports *indicator_type*.

        This is a convenience method for the future Threat Intelligence
        Agent to determine provider suitability without querying
        ``supported_indicator_types`` directly.
        """
        return indicator_type in self.supported_indicator_types

    def assert_supports(self, indicator: ThreatIndicator) -> None:
        """Raise :class:`UnsupportedIndicatorTypeError` if not supported.

        This is a guard that future provider implementations can call
        at the top of their ``lookup`` method.
        """
        if not self.supports(indicator.indicator_type):
            raise UnsupportedIndicatorTypeError(
                indicator.indicator_type.value, self.provider_name,
            )

