"""Threat Intelligence read models (Step 8A read surface).

Transport-agnostic response schemas for the read-only Threat Intelligence
API.  They exist so a caller -- notably the Threat Intelligence console --
can read what the Step 8A pipeline **actually persisted** without inventing
an enrichment verdict.

Provenance of these models
--------------------------
Every field below maps to a column that already exists on
:class:`~app.models.threat_intel_indicator.ThreatIntelIndicator` or
:class:`~app.models.threat_intel_lookup.ThreatIntelLookup`.  No column,
table, or enum is introduced here, and no field is derived from provider
documentation rather than from a stored value.

What these models deliberately do **not** contain
------------------------------------------------
There is no ``verdict``, ``malicious``, ``severity``, ``risk``,
``threat_level``, or ``score`` field anywhere in this module.

That omission is a contract, not an oversight.  Nothing in Step 8A
persists a verdict, so a read surface that returned one would be
fabricating an analytic conclusion the system never made.  The three
signals that *are* persisted are surfaced instead, each with its exact
meaning:

* ``found`` -- whether the provider held any record for the indicator.
  ``found=False`` means "the provider was queried and had nothing", which
  is **not** the same as "provider failed" and **not** a verdict.
* ``confidence`` -- the provider's own optional numeric confidence, only
  present when the provider actually supplied one.  All three bundled
  providers deliberately omit it.
* ``status`` -- the lookup outcome: :class:`LookupStatus.SUCCESS` or
  :class:`LookupStatus.ERROR`, plus the human-facing status rollup derived
  from it in :mod:`app.services.threat_intelligence_query`.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.security_event import Provenance
from app.services.threat_intelligence.types import IndicatorType

__all__ = [
    "ThreatIntelLookupRecord",
    "ThreatIntelIndicatorRecord",
    "ThreatIntelIndicatorPage",
    "ThreatIntelIndicatorDetail",
    "ThreatIntelIndicatorEvents",
    "ThreatIntelReadOnlyNotice",
]


# ---------------------------------------------------------------------------
# Shared read-only notice
# ---------------------------------------------------------------------------


class ThreatIntelReadOnlyNotice(BaseModel):
    """Attaches the honest capability statement to every TI response.

    Mirrors the ``read_only``/``semantics`` pattern already used by the
    Natural Language SOC and incident-report read surfaces so a client can
    assert the read-only guarantee instead of inferring it.
    """

    model_config = ConfigDict(extra="forbid")

    read_only: bool = Field(
        default=True,
        description=(
            "Always true.  No Threat Intelligence route performs a write; "
            "indicators and lookups are created solely by the Threat "
            "Intelligence Agent and its persistence service."
        ),
    )
    verdict_available: bool = Field(
        default=False,
        description=(
            "Always false.  Step 8A persists no malicious/benign verdict, "
            "severity, or risk, so none is returned or implied."
        ),
    )


# ---------------------------------------------------------------------------
# Lookup read model
# ---------------------------------------------------------------------------


class ThreatIntelLookupRecord(BaseModel):
    """One persisted provider lookup for one indicator.

    Mirrors :class:`ThreatIntelLookup` column for column, plus two derived
    presentation fields (``status_label`` and ``provider_result_available``)
    that are computed from persisted values only.
    """

    model_config = ConfigDict(extra="forbid")

    lookup_id: uuid.UUID = Field(
        ...,
        description="Identity of the persisted lookup row.",
    )
    indicator_id: uuid.UUID = Field(
        ...,
        description="The indicator this lookup was performed for.",
    )
    event_id: uuid.UUID = Field(
        ...,
        description=(
            "The security event the indicator was extracted from.  "
            "SentinelAI has no security-event store, so this is a "
            "correlation key, not a resolvable event."
        ),
    )
    provider: str = Field(
        ...,
        min_length=1,
        description=(
            "Provider name exactly as persisted, i.e. provider.provider_name: "
            "'VirusTotal', 'abuseipdb', or 'AlienVault OTX'."
        ),
    )
    status: str = Field(
        ...,
        min_length=1,
        description="Persisted LookupStatus: 'success' or 'error'.",
    )
    status_label: str = Field(
        ...,
        min_length=1,
        description=(
            "Human-facing rollup of the persisted status and its stored "
            "error_type: ENRICHED, NO DATA, FAILED, RATE LIMITED, TIMED OUT, "
            "REJECTED, or UNAVAILABLE.  Derived only from stored values; a "
            "failure is never reported as a malicious verdict."
        ),
    )
    found: bool | None = Field(
        default=None,
        description=(
            "Whether the provider held a record for the indicator.  Null on "
            "a failed lookup.  False means 'queried, nothing found' -- it is "
            "NOT a benign verdict."
        ),
    )
    provider_result_available: bool = Field(
        default=False,
        description=(
            "True only when the lookup succeeded and stored provider data.  "
            "This is the 'provider returned data' signal, distinct from "
            "'provider queried' and from 'provider failed'."
        ),
    )
    confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "Provider-supplied confidence, only when actually persisted.  "
            "All three bundled providers omit it, so null is normal."
        ),
    )
    performed_at: datetime = Field(
        ...,
        description="When the lookup was performed (UTC-normalized).",
    )
    result_timestamp: datetime | None = Field(
        default=None,
        description=(
            "Provider-reported result instant, when persisted (UTC-normalized). "
            "This is when the provider's data is from, which is not the same "
            "as performed_at."
        ),
    )
    error_type: str | None = Field(
        default=None,
        description=(
            "Persisted failure category on an error lookup: rate_limit, "
            "timeout, provider_error, invalid_indicator, or unexpected."
        ),
    )
    error_message: str | None = Field(
        default=None,
        description=(
            "Persisted failure detail, already secret-sanitized on write and "
            "re-sanitized on read.  Never a raw provider response body."
        ),
    )
    retryable: bool | None = Field(
        default=None,
        description="Whether the persisted failure was classified retryable.",
    )
    evidence: dict | None = Field(
        default=None,
        description=(
            "Persisted provider evidence, recursively sanitized and bounded "
            "for display.  Null when the provider returned nothing or failed."
        ),
    )
    result_metadata: dict | None = Field(
        default=None,
        description="Persisted safe provider metadata, recursively sanitized.",
    )
    provenance: Provenance = Field(
        default=Provenance.ENRICHED,
        description=(
            "Always 'enriched' -- the lookup table enforces it with a CHECK "
            "constraint, so no indicator value is ever presented as observed."
        ),
    )
    created_at: datetime = Field(...)
    updated_at: datetime = Field(...)


# ---------------------------------------------------------------------------
# Indicator read models
# ---------------------------------------------------------------------------


class ThreatIntelIndicatorRecord(BaseModel):
    """One persisted indicator with a rollup of its provider lookups."""

    model_config = ConfigDict(extra="forbid")

    indicator_id: uuid.UUID = Field(
        ...,
        description="Identity of the persisted indicator row.",
    )
    indicator_type: IndicatorType = Field(
        ...,
        description="Persisted indicator type: ip, domain, url, or hash.",
    )
    value: str = Field(
        ...,
        min_length=1,
        description=(
            "Indicator value exactly as extracted.  URLs are deliberately "
            "not canonicalized by Step 8A, so this may differ from canonical_key."
        ),
    )
    canonical_key: str = Field(
        ...,
        min_length=1,
        description=(
            "The Step 8A dedup key, '{type}:{normalized_value}'.  Lowercased "
            "for domain and hash only; ip and url are byte-exact."
        ),
    )
    first_seen: datetime = Field(
        ...,
        description=(
            "First time this indicator was extracted.  Immutable after "
            "creation, even as later events re-observe it."
        ),
    )
    last_seen: datetime = Field(
        ...,
        description="Most recent time this indicator was extracted.",
    )
    providers: list[str] = Field(
        default_factory=list,
        description=(
            "Distinct provider names with a persisted lookup for this "
            "indicator, sorted.  Empty means no lookup was ever recorded."
        ),
    )
    lookup_count: int = Field(
        default=0,
        ge=0,
        description="Total persisted lookups across all providers and events.",
    )
    success_count: int = Field(
        default=0,
        ge=0,
        description="Persisted lookups with status 'success'.",
    )
    error_count: int = Field(
        default=0,
        ge=0,
        description="Persisted lookups with status 'error'.",
    )
    latest_lookup_at: datetime | None = Field(
        default=None,
        description="Most recent lookup instant for this indicator, if any.",
    )
    status: str = Field(
        default="no_lookup",
        min_length=1,
        description=(
            "Rollup over persisted lookups only: 'no_lookup' (none exists), "
            "'enriched' (at least one returned provider data), 'partial' "
            "(some lookups failed), or 'failed' (every lookup failed).  None "
            "of these is a malicious or benign verdict."
        ),
    )
    provenance: Provenance = Field(
        default=Provenance.OBSERVED,
        description=(
            "Provenance of the indicator's existence.  Extraction from a "
            "normalized event is an observation; the provider enrichment is "
            "recorded separately on each lookup."
        ),
    )
    created_at: datetime = Field(...)
    updated_at: datetime = Field(...)


class ThreatIntelIndicatorPage(BaseModel):
    """One bounded, deterministically ordered page of indicators."""

    model_config = ConfigDict(extra="forbid")

    items: list[ThreatIntelIndicatorRecord] = Field(
        default_factory=list,
        description=(
            "Indicators for this page.  Ordered by last_seen descending, id "
            "ascending as the tie-break, so paging is deterministic."
        ),
    )
    total: int = Field(
        default=0,
        ge=0,
        description=(
            "Total indicators matching the filters across all pages, "
            "independent of this page's size."
        ),
    )
    page: int = Field(..., ge=1, description="One-based page number.")
    page_size: int = Field(..., ge=1, description="Rows per page requested.")
    read_only: bool = True
    verdict_available: bool = False


class ThreatIntelIndicatorDetail(BaseModel):
    """One indicator plus its bounded lookup history."""

    model_config = ConfigDict(extra="forbid")

    indicator: ThreatIntelIndicatorRecord = Field(...)
    lookups: list[ThreatIntelLookupRecord] = Field(
        default_factory=list,
        description=(
            "Lookups for this indicator, newest first (performed_at "
            "descending, id ascending).  Bounded by the service; "
            "lookups_truncated reports whether more exist."
        ),
    )
    lookups_truncated: bool = Field(
        default=False,
        description="True when more lookups exist than were returned.",
    )
    events: list[uuid.UUID] = Field(
        default_factory=list,
        description=(
            "Distinct security-event ids this indicator was extracted from, "
            "newest first, bounded.  Correlation keys only -- SentinelAI "
            "persists no security-event table to resolve them against."
        ),
    )
    events_truncated: bool = Field(
        default=False,
        description="True when more distinct event ids exist than returned.",
    )
    read_only: bool = True
    verdict_available: bool = False


class ThreatIntelIndicatorEvents(BaseModel):
    """Bounded event-correlation view for a single indicator."""

    model_config = ConfigDict(extra="forbid")

    indicator_id: uuid.UUID = Field(...)
    events: list[uuid.UUID] = Field(
        default_factory=list,
        description=(
            "Distinct event ids from this indicator's persisted lookups, "
            "ordered by most recent lookup descending, event id ascending."
        ),
    )
    total: int = Field(default=0, ge=0, description="Total distinct event ids.")
    truncated: bool = Field(
        default=False,
        description="True when more distinct event ids exist than returned.",
    )
    read_only: bool = True
    note: str = Field(
        default=(
            "Event ids are correlation keys recorded on lookups; "
            "SentinelAI persists no security-event table to resolve them."
        ),
        description="Explains why these ids cannot be dereferenced.",
    )
