"""Security Event contract.

Defines the validated internal schema for security events flowing through
SentinelAI.  Future collectors, normalization, enrichment, and detection
agents will all operate on this contract.

No database table, API endpoint, or message-bus integration is introduced
here — this module is purely the data contract.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Provenance(str, Enum):
    """Where the information in an event (or field) originated.

    Semantic meaning:

    * ``observed``  — directly present in the original collected event.
    * ``enriched``  — added by an external or internal enrichment source.
    * ``reconstructed`` — inferred because the original was incomplete.
    * ``detected``  — derived analytical result produced by a detection
      evaluation (e.g. Sigma or YARA rule match).  A detected result is
      **not** an observation of the event itself; it is an analytical
      conclusion derived from evaluating a rule against event data.

    A **reconstructed** value must never silently appear as if it were an
    observed fact.  A **detected** value must never be confused with
    direct observation.  The schema enforces this distinction so
    downstream agents can make appropriate trust decisions.
    """

    OBSERVED = "observed"
    ENRICHED = "enriched"
    RECONSTRUCTED = "reconstructed"
    DETECTED = "detected"


class SourceType(str, Enum):
    """High-level category for the origin of a security event.

    The set of values is intentionally broad to accommodate future
    collectors.  New values can be added in later versions without
    breaking the contract.
    """

    OPERATING_SYSTEM = "operating_system"
    NETWORK = "network"
    APPLICATION = "application"
    CLOUD = "cloud"
    IDENTITY = "identity"
    SECURITY_DEVICE = "security_device"
    OTHER = "other"


# ---------------------------------------------------------------------------
# Security Event
# ---------------------------------------------------------------------------

class SecurityEvent(BaseModel):
    """Validated, internally canonical representation of a security event.

    The schema is designed around clear separation of concerns so that
    future processing stages (normalisation → enrichment → synthetic
    reconstruction → detection → correlation → investigation) can add
    information without overwriting original event data::

        raw_data            ← immutable, forensic-grade
        normalised_data     ← (future) normalised representation
        enriched_data       ← (future) added by enrichment
        provenance          ← event-level trust/provenance marker

    Field-level provenance can be added later via an optional mapping
    without redesigning this schema.
    """

    event_id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        description="Unique identifier for this event. Auto-generated when not supplied.",
    )

    timestamp: datetime = Field(
        ...,
        description="Timezone-aware timestamp of when the event occurred.",
    )

    source: str = Field(
        ...,
        min_length=1,
        description=(
            "Specific origin of the event, e.g. 'windows', 'linux', "
            "'firewall', 'application'."
        ),
    )

    source_type: SourceType = Field(
        ...,
        description="High-level category of the event source.",
    )

    event_type: str = Field(
        ...,
        min_length=1,
        description=(
            "What kind of event occurred, e.g. 'authentication', "
            "'process_creation', 'network_connection', 'file_activity'."
        ),
    )

    raw_data: dict[str, Any] = Field(
        ...,
        description=(
            "Original collected event data.  Preserved as-is for forensic "
            "integrity; must not be silently transformed downstream."
        ),
    )

    metadata: dict[str, Any] | None = Field(
        default=None,
        description="Optional structured information associated with collection.",
    )

    provenance: Provenance = Field(
        ...,
        description=(
            "Whether this event's information was directly observed, "
            "enriched, or reconstructed."
        ),
    )

    # ------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------

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
