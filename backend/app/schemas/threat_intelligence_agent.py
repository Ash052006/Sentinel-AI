"""Threat Intelligence Agent contract — Step 8A.

This module defines the **contract** for the Threat Intelligence Agent
without implementing its orchestration.  It is a pure data-contract
layer that coordinates the structured representation of:

* indicators extracted from a NormalizedSecurityEvent,
* deterministic deduplication of those indicators,
* provider association and results,
* provider failure isolation, and
* the eventual conversion of provider results into EnrichmentResults.

Architecture principles
-----------------------

* **Contract only** — no network calls, no provider querying, no
  orchestration loop.  Providers and the registry are never invoked
  here.
* **Provider-agnostic** — nothing here hardcodes VirusTotal, AbuseIPDB,
  or AlienVault OTX.  Provider selection flows through the existing
  :class:`~app.services.threat_intelligence.registry.ProviderRegistry`.
* **No verdicts** — this contract never assigns a malicious/benign
  verdict, never creates a final risk score, and never aggregates
  confidence.  Such decisions are explicitly out of scope.
* **No mutation** — the original NormalizedSecurityEvent is never
  modified.  All analysis data is additive.
* **Traceable** — every provider result stays associated with the
  indicator and indicator type it concerns, preserving the
  ``event → indicator → provider → result`` chain required for future
  explainability.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from pydantic import BaseModel, Field, field_validator

from app.schemas.enriched_event import EnrichmentResult
from app.services.threat_intelligence.base import ThreatIntelResult
from app.services.threat_intelligence.types import IndicatorType


# ---------------------------------------------------------------------------
# ExtractedIndicator
# ---------------------------------------------------------------------------

class ExtractedIndicator(BaseModel):
    """A single indicator extracted from an event's structured fields.

    Unlike :class:`~app.services.threat_intelligence.types.ThreatIndicator`,
    an extracted indicator keeps track of *where* in the event the value
    was found so that provenance and traceability are preserved.

    Attributes:
        indicator: The raw indicator value (e.g. ``"8.8.8.8"``).
        indicator_type: The category of indicator (ip, domain, url, hash).
        source_field: Dotted path to the field the value came from,
            e.g. ``"source_endpoint.ip"`` or ``"file.hash"``.
        source_context: Coarse context describing where the value came
            from, e.g. ``"source_endpoint"`` or ``"file"``.
    """

    indicator: str = Field(
        ...,
        min_length=1,
        description="The indicator value (e.g. IP, domain, URL, or hash).",
    )
    indicator_type: IndicatorType = Field(
        ...,
        description="Classification of the indicator.",
    )
    source_field: str = Field(
        ...,
        min_length=1,
        description=(
            "Dotted path to the event field the indicator came from, "
            "e.g. 'source_endpoint.ip'."
        ),
    )
    source_context: str = Field(
        ...,
        min_length=1,
        description=(
            "Coarse context of origin, e.g. 'source_endpoint', "
            "'destination_endpoint', 'file'."
        ),
    )

    @field_validator("indicator")
    @classmethod
    def _indicator_not_blank(cls, v: str) -> str:
        """Reject purely whitespace indicator values."""
        if not v.strip():
            raise ValueError("indicator must not be blank/whitespace")
        return v

    @field_validator("source_field")
    @classmethod
    def _source_field_not_blank(cls, v: str) -> str:
        """Reject purely whitespace source fields."""
        if not v.strip():
            raise ValueError("source_field must not be blank/whitespace")
        return v

    @field_validator("source_context")
    @classmethod
    def _source_context_not_blank(cls, v: str) -> str:
        """Reject purely whitespace source contexts."""
        if not v.strip():
            raise ValueError("source_context must not be blank/whitespace")
        return v

    @property
    def canonical_key(self) -> str:
        """Deterministic deduplication key for this indicator.

        The key is ``"{type}:{normalized_value}"``.  Normalization is
        intentionally conservative so it never changes indicator meaning:

        * Domains are lower-cased.
        * Hashes are lower-cased.
        * IPs and URLs are kept exactly as extracted (URL normalization
          is only performed when explicitly requested elsewhere).

        Returns:
            A stable string suitable for deterministic deduplication.
        """
        normalized = self.indicator
        if self.indicator_type in (IndicatorType.DOMAIN, IndicatorType.HASH):
            normalized = self.indicator.lower()
        return f"{self.indicator_type.value}:{normalized}"


# ---------------------------------------------------------------------------
# ProviderAssociation
# ---------------------------------------------------------------------------

class ProviderAssociation(BaseModel):
    """Links an extracted indicator to a provider and its result.

    This is the unit of **traceability** in the contract.  It preserves
    the ``event → indicator → provider → result`` chain so that future
    explainability can walk from a finding back to its origin.

    Attributes:
        indicator: The extracted indicator this association concerns.
        provider: The provider name involved.
        result: The resulting ThreatIntelResult, or None when the lookup
            was not performed / had no result.
    """

    indicator: ExtractedIndicator = Field(
        ...,
        description="The extracted indicator this association concerns.",
    )
    provider: str = Field(
        ...,
        min_length=1,
        description="Name of the provider associated with this lookup.",
    )
    result: ThreatIntelResult | None = Field(
        default=None,
        description=(
            "The provider result, or None when no result was produced."
        ),
    )

    @field_validator("provider")
    @classmethod
    def _provider_not_blank(cls, v: str) -> str:
        """Reject purely whitespace provider names."""
        if not v.strip():
            raise ValueError("provider must not be blank/whitespace")
        return v


# ---------------------------------------------------------------------------
# ProviderFailure
# ---------------------------------------------------------------------------

class ProviderFailure(BaseModel):
    """A structured, secret-safe representation of a provider failure.

    Failures are isolated so that one provider's failure never fails the
    whole agent.  This model deliberately contains **no** API keys,
    authorization headers, or raw HTTP responses.

    Attributes:
        provider: Name of the provider that failed.
        indicator: The indicator that was being looked up.
        indicator_type: The type of the indicator.
        error_type: A short machine-readable failure category, e.g.
            ``"timeout"``, ``"rate_limit"``, ``"http_error"``.
        message: Human-readable error message (must not contain secrets).
        retryable: Whether the failure is likely transient/retryable.
    """

    provider: str = Field(
        ...,
        min_length=1,
        description="Name of the provider that failed.",
    )
    indicator: str = Field(
        ...,
        min_length=1,
        description="The indicator value that was being looked up.",
    )
    indicator_type: IndicatorType = Field(
        ...,
        description="The type of the indicator being looked up.",
    )
    error_type: str = Field(
        ...,
        min_length=1,
        description=(
            "Short failure category, e.g. 'timeout', 'rate_limit', "
            "'http_error'."
        ),
    )
    message: str = Field(
        ...,
        description="Human-readable error message (secret-safe).",
    )
    retryable: bool = Field(
        ...,
        description="Whether the failure is likely transient and retryable.",
    )

    @field_validator("provider")
    @classmethod
    def _provider_not_blank(cls, v: str) -> str:
        """Reject purely whitespace provider names."""
        if not v.strip():
            raise ValueError("provider must not be blank/whitespace")
        return v

    @field_validator("error_type")
    @classmethod
    def _error_type_not_blank(cls, v: str) -> str:
        """Reject purely whitespace error types."""
        if not v.strip():
            raise ValueError("error_type must not be blank/whitespace")
        return v


# ---------------------------------------------------------------------------
# Execution metadata
# ---------------------------------------------------------------------------

class ThreatIntelMetadata(BaseModel):
    """Safe observability metadata for a threat-intelligence run.

    Contains counters that can later support monitoring and logging.
    It deliberately contains **no** secrets and **no** raw HTTP
    responses.

    Attributes:
        providers_attempted: Number of providers selected for lookups.
        providers_succeeded: Number of providers that returned results.
        providers_failed: Number of providers that failed.
        indicators_extracted: Number of unique indicators extracted.
        lookups_attempted: Number of provider lookups attempted.
        lookups_succeeded: Number of lookups that succeeded.
        lookups_failed: Number of lookups that failed.
    """

    providers_attempted: int = Field(
        default=0, ge=0, description="Providers selected for lookups.",
    )
    providers_succeeded: int = Field(
        default=0, ge=0, description="Providers that returned results.",
    )
    providers_failed: int = Field(
        default=0, ge=0, description="Providers that failed.",
    )
    indicators_extracted: int = Field(
        default=0, ge=0, description="Number of unique indicators extracted.",
    )
    lookups_attempted: int = Field(
        default=0, ge=0, description="Provider lookups attempted.",
    )
    lookups_succeeded: int = Field(
        default=0, ge=0, description="Provider lookups that succeeded.",
    )
    lookups_failed: int = Field(
        default=0, ge=0, description="Provider lookups that failed.",
    )


# ---------------------------------------------------------------------------
# ThreatIntelligenceAnalysis
# ---------------------------------------------------------------------------

class ThreatIntelligenceAnalysis(BaseModel):
    """Top-level, contract-only result of a (future) agent run.

    This is a pure data holder.  It carries the original event identity,
    the extracted indicators, provider results, isolated failures,
    generated enrichment results, and execution metadata.

    It deliberately defines **no** final risk score, **no**
    malicious/benign verdict, and **no** aggregated confidence.

    Attributes:
        event_id: Identity of the security event analyzed (preserved).
        indicators: Deduplicated list of extracted indicators.
        results: List of provider associations (traceability).
        failures: List of isolated provider failures.
        enrichments: List of generated enrichment results.
        metadata: Execution metadata.
    """

    event_id: uuid.UUID = Field(
        ...,
        description=(
            "Identity of the security event.  Preserved from the "
            "NormalizedSecurityEvent — never regenerated."
        ),
    )

    indicators: list[ExtractedIndicator] = Field(
        default_factory=list,
        description="Deduplicated extracted indicators.",
    )

    results: list[ProviderAssociation] = Field(
        default_factory=list,
        description="Provider associations with their results.",
    )

    failures: list[ProviderFailure] = Field(
        default_factory=list,
        description="Isolated provider failures.",
    )

    enrichments: list[EnrichmentResult] = Field(
        default_factory=list,
        description="Generated enrichment results.",
    )

    metadata: ThreatIntelMetadata = Field(
        default_factory=ThreatIntelMetadata,
        description="Execution metadata.",
    )

    # -- Convenience ---------------------------------------------------------

    @property
    def providers_failed(self) -> int:
        """Number of recorded provider failures."""
        return len(self.failures)

    @property
    def has_failures(self) -> bool:
        """Return True if any provider failure was recorded."""
        return len(self.failures) > 0

    @property
    def has_results(self) -> bool:
        """Return True if at least one provider result is present."""
        return len(self.results) > 0


# ---------------------------------------------------------------------------
# Pure enrichment conversion (contract definition of the relationship)
# ---------------------------------------------------------------------------

#: Enrichment type used for threat-intelligence-derived enrichments.
THREAT_INTELLIGENCE_ENRICHMENT_TYPE = "threat_intelligence"


def threat_intel_result_to_enrichment(
    result: ThreatIntelResult,
    *,
    as_of: datetime | None = None,
) -> EnrichmentResult:
    """Map a single provider result to an :class:`EnrichmentResult`.

    This is a **pure transformation** — it performs no network calls,
    holds no state, and never mutates the input result.  It defines how
    the future agent will convert external intelligence into the
    existing enrichment contract.

    The enrichment ``value`` carries structured, non-destructive provider
    evidence.  It never includes the API key or a raw HTTP response.

    Args:
        result: The provider result to convert.
        as_of: Optional timestamp to stamp on the enrichment; defaults to
            the current UTC time.  All enrichments are timezone-aware.

    Returns:
        An :class:`EnrichmentResult` with ``enrichment_type`` set to
        ``"threat_intelligence"`` and ``source`` set to the provider
        name.  The event-level provenance for the resulting content is
        ``ENRICHED`` — external intelligence is never labelled
        ``observed`` or ``reconstructed``.
    """
    stamp = as_of or datetime.now(timezone.utc)
    value = {
        "indicator_type": result.indicator.indicator_type.value,
        "indicator": result.indicator.value,
        "provider": result.provider,
        "found": result.found,
        **result.data,
    }
    return EnrichmentResult(
        enrichment_type=THREAT_INTELLIGENCE_ENRICHMENT_TYPE,
        source=result.provider,
        value=value,
        confidence=result.confidence,
        timestamp=stamp,
    )
