"""Enrichment Contract for SentinelAI.

Defines the validated internal schema for **enriched** security events
in SentinelAI.  Enrichment adds derived, external, or contextual
information to a normalized SecurityEvent without mutating it.

Design principles:

* **Non-destructive** — the original NormalizedSecurityEvent is stored
  in full and never modified.  Enrichments are additive only.
* **Typed results** — every enrichment is represented as an
  EnrichmentResult with a clear type, source, value, and confidence.
* **Provenance-aware** — enrichment results carry their own provenance
  context (ENRICHED).  The original event's provenance is preserved.
* **No fabrication** — this module defines how enrichment data is
  represented, not how it is obtained.  Provider integrations,
  threat-intelligence lookups, DNS, WHOIS, geolocation, and
  synthetic reconstruction are all separate future steps.
* **Extensible** — new enrichment types and sources can be added by
  producing new EnrichmentResult instances without changing the schema.

This module is a **data contract only** — it introduces no enrichment
logic, no provider integrations, no database tables, and no API
endpoints.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.schemas.normalized_event import NormalizedSecurityEvent
from app.schemas.security_event import Provenance


# ---------------------------------------------------------------------------
# EnrichmentResult
# ---------------------------------------------------------------------------

class EnrichmentResult(BaseModel):
    """A single enrichment applied to a normalized security event.

    Each result represents one piece of additional context obtained from
    an enrichment source (e.g. threat-intelligence provider, asset
    inventory, identity store).  Multiple EnrichmentResult instances can
    be attached to a single EnrichedSecurityEvent.

    The ``value`` field holds the enrichment payload as structured,
    JSON-compatible data.  Its schema is defined by the
    ``enrichment_type`` and is intentionally not rigidly typed here so
    that different enrichment categories can carry different structures.
    """

    enrichment_id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        description=(
            "Unique identifier for this enrichment result.  "
            "Auto-generated when not supplied."
        ),
    )

    enrichment_type: str = Field(
        ...,
        min_length=1,
        description=(
            "Category of enrichment, e.g. 'ip_reputation', "
            "'geolocation', 'domain_reputation', 'hash_reputation', "
            "'user_context', 'asset_context'."
        ),
    )

    source: str = Field(
        ...,
        min_length=1,
        description=(
            "Origin of the enrichment data, e.g. 'VirusTotal', "
            "'AbuseIPDB', 'AlienVault OTX', 'internal_asset_inventory'."
        ),
    )

    value: dict[str, Any] = Field(
        ...,
        description=(
            "Structured enrichment payload.  The schema depends on the "
            "enrichment_type.  Must be JSON-serializable."
        ),
    )

    confidence: float | None = Field(
        default=None,
        description=(
            "Optional numeric confidence score for this enrichment, "
            "constrained to [0.0, 1.0].  None when confidence is "
            "not applicable or not provided."
        ),
    )

    timestamp: datetime = Field(
        ...,
        description=(
            "Timezone-aware timestamp of when the enrichment was "
            "produced or recorded."
        ),
    )

    metadata: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Optional JSON-compatible metadata.  May contain provider-"
            "specific fields, lookup identifiers, TTL, response "
            "metadata, or enrichment context.  Must not contain "
            "secrets or API keys."
        ),
    )

    # -- Validators ----------------------------------------------------------

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
        """Confidence must be in [0.0, 1.0] when provided."""
        if v is None:
            return v
        if not 0.0 <= v <= 1.0:
            raise ValueError(
                f"confidence must be between 0.0 and 1.0 inclusive, "
                f"got {v}"
            )
        return v

    @field_validator("value")
    @classmethod
    def _ensure_value_json_compatible(
        cls, v: dict[str, Any]
    ) -> dict[str, Any]:
        """Ensure value is strictly JSON-serializable."""
        try:
            json.dumps(v)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"enrichment value must be JSON-compatible: {exc}"
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
# EnrichedSecurityEvent
# ---------------------------------------------------------------------------

class EnrichedSecurityEvent(BaseModel):
    """Enriched security event wrapping the original normalized event.

    The ``normalized_event`` is stored in full and **must never be
    mutated** by enrichment.  All enrichment results are additive and
    live in the ``enrichments`` list.

    The ``event_id`` and ``timestamp`` are carried forward from the
    normalized event to maintain a single traceable identity across the
    pipeline::

        SecurityEvent
            → NormalizedSecurityEvent
                → EnrichedSecurityEvent  (this model)

    Each EnrichmentResult in the ``enrichments`` list has its own
    ``enrichment_id`` that is distinct from ``event_id``.
    """

    event_id: uuid.UUID = Field(
        ...,
        description=(
            "Identity of the security event.  Preserved from the "
            "NormalizedSecurityEvent — never regenerated."
        ),
    )

    timestamp: datetime = Field(
        ...,
        description=(
            "Timezone-aware timestamp of when the event occurred.  "
            "Preserved from the NormalizedSecurityEvent."
        ),
    )

    normalized_event: NormalizedSecurityEvent = Field(
        ...,
        description=(
            "The full NormalizedSecurityEvent that was enriched.  "
            "Stored as-is and never modified."
        ),
    )

    enrichments: list[EnrichmentResult] = Field(
        default_factory=list,
        description=(
            "Ordered list of enrichment results applied to this event.  "
            "May be empty when no enrichments have been performed yet."
        ),
    )

    provenance: Provenance = Field(
        default=Provenance.ENRICHED,
        description=(
            "Event-level provenance marker for the enriched event.  "
            "Defaults to ENRICHED.  The original normalized event's "
            "provenance is preserved inside ``normalized_event``."
        ),
    )

    # -- Validators ----------------------------------------------------------

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

    # -- Convenience ---------------------------------------------------------

    @property
    def has_enrichments(self) -> bool:
        """Return True if at least one enrichment result is present."""
        return len(self.enrichments) > 0
