"""Normalized Security Event contract.

Defines the validated internal schema for **normalized** security events
in SentinelAI.  Normalization transforms source-specific raw events into
a common internal representation suitable for downstream enrichment,
detection, correlation, and investigation.

Design principles:

* **raw_data stays on the original
  :class:`~app.schemas.security_event.SecurityEvent`** -- it is never
  duplicated or mutated here.
* The ``event_id`` is preserved from the original event so that every
  stage in the pipeline (raw -> normalized -> enriched -> reconstructed)
  remains traceable to a single underlying security event.
* ``normalized_data`` holds structured information derived from
  normalization that does not yet fit into the strongly-typed common
  fields.  It must not be used as a mirror of ``raw_data``.
* All nested entities (actor, endpoints, process, file) are optional
  because not every source provides every field.

This module is a **data contract only** -- it introduces no normalization
logic, no database tables, and no API endpoints.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.schemas.security_event import Provenance, SourceType


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class EventCategory(str, Enum):
    """High-level classification of a security event.

    The set of values covers the primary categories observed across
    operating systems, network devices, applications, and cloud services.
    New values can be added in later versions without breaking the contract.
    """

    AUTHENTICATION = "authentication"
    PROCESS = "process"
    NETWORK = "network"
    FILE = "file"
    SYSTEM = "system"
    APPLICATION = "application"
    OTHER = "other"


class EventOutcome(str, Enum):
    """Whether the event represents a successful or failed action.

    ``unknown`` is the default when the outcome cannot be determined from
    the source event.
    """

    SUCCESS = "success"
    FAILURE = "failure"
    ALLOWED = "allowed"
    DENIED = "denied"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Nested structured models
# ---------------------------------------------------------------------------

class Actor(BaseModel):
    """Identity of the entity that performed (or was the subject of) an action.

    All fields are optional -- if the source event does not provide actor
    information the fields are left absent rather than fabricated.
    """

    user_id: str | None = Field(
        default=None,
        description="Source-specific user identifier (e.g. SID, UID).",
    )
    username: str | None = Field(
        default=None,
        description="Username or account name.",
    )
    domain: str | None = Field(
        default=None,
        description="Domain or realm (e.g. Active Directory domain).",
    )


class Endpoint(BaseModel):
    """Network endpoint representation used for both source and destination.

    All fields are optional.  Only the information present in the original
    event should be populated -- enrichment and geolocation are future
    responsibilities.
    """

    ip: str | None = Field(
        default=None,
        description="IP address (v4 or v6).",
    )
    hostname: str | None = Field(
        default=None,
        description="Hostname or FQDN.",
    )
    port: int | None = Field(
        default=None,
        description="Transport-layer port number.",
    )
    protocol: str | None = Field(
        default=None,
        description="Protocol name or number (e.g. 'tcp', '6').",
    )


class ProcessInfo(BaseModel):
    """Structured process representation.

    Fields are populated only when the source event provides process-level
    telemetry.  No process-tree analysis or behavioural detection is
    performed at this stage.
    """

    name: str | None = Field(
        default=None,
        description="Process or image name.",
    )
    pid: int | None = Field(
        default=None,
        description="Process identifier.",
    )
    command_line: str | None = Field(
        default=None,
        description="Full command-line string used to launch the process.",
    )
    executable: str | None = Field(
        default=None,
        description="Path to the executable on disk.",
    )
    parent_process: str | None = Field(
        default=None,
        description=(
            "Name or identifier of the parent process.  A richer parent "
            "process structure may be added in a future version."
        ),
    )


class FileInfo(BaseModel):
    """Structured file representation.

    Fields are populated only when the source event includes file-level
    information.  Hash computation and malware analysis are not performed
    during normalization.
    """

    name: str | None = Field(
        default=None,
        description="File name (without path).",
    )
    path: str | None = Field(
        default=None,
        description="Full file-system path.",
    )
    extension: str | None = Field(
        default=None,
        description="File extension (e.g. '.dll', '.exe').",
    )
    hash: str | None = Field(
        default=None,
        description=(
            "File hash as reported by the source.  The format and algorithm "
            "are source-dependent (e.g. SHA-256, MD5)."
        ),
    )


# ---------------------------------------------------------------------------
# Normalized Security Event
# ---------------------------------------------------------------------------

class NormalizedSecurityEvent(BaseModel):
    """Validated, internally canonical representation of a **normalized**
    security event.

    Normalization transforms a source-specific
    :class:`~app.schemas.security_event.SecurityEvent` into this common
    representation so that downstream agents (enrichment, detection,
    correlation) operate on a uniform interface.

    Key relationship to the raw event::

        SecurityEvent.event_id  ==  NormalizedSecurityEvent.event_id

    ``raw_data`` intentionally lives **only** on
    :class:`~app.schemas.security_event.SecurityEvent`.  It must never
    be duplicated into this schema.  ``normalized_data`` holds the
    flexible derived representation instead.

    Provenance semantics:

    * ``observed``  -- the normalized field values were directly mapped
      from the raw event without external information.
    * ``enriched``  -- additional context was obtained from an external
      source (applied by future enrichment agents).
    * ``reconstructed`` -- information was inferred to fill gaps (applied
      by future synthetic-reconstruction agents).

    A newly normalized event **must not** be labelled ``enriched`` or
    ``reconstructed`` unless those pipeline stages have actually run.
    Field-level provenance can be layered on top via a future extension
    without redesigning this schema.
    """

    # -- Core fields --------------------------------------------------------

    event_id: uuid.UUID = Field(
        ...,
        description=(
            "Preserved from the original SecurityEvent.  Must not be "
            "regenerated during normalization so that raw -> normalized -> "
            "enriched events remain traceable."
        ),
    )

    timestamp: datetime = Field(
        ...,
        description=(
            "Original event timestamp.  Preserved as-is from the source "
            "event; never replaced with the normalization timestamp."
        ),
    )

    event_category: EventCategory = Field(
        ...,
        description="High-level classification of the event.",
    )

    action: str | None = Field(
        default=None,
        description=(
            "Specific action taken or observed (e.g. 'login', 'logout', "
            "'process_start', 'connection', 'file_access').  Free-form "
            "to accommodate source-specific vocabulary."
        ),
    )

    outcome: EventOutcome = Field(
        default=EventOutcome.UNKNOWN,
        description="Outcome of the event (success, failure, etc.).",
    )

    source: str = Field(
        ...,
        min_length=1,
        description=(
            "Specific origin of the event, carried forward from the "
            "original SecurityEvent."
        ),
    )

    source_type: SourceType = Field(
        ...,
        description="High-level category of the event source.",
    )

    # -- Optional structured entities ---------------------------------------

    actor: Actor | None = Field(
        default=None,
        description="Identity of the entity that performed the action.",
    )

    source_endpoint: Endpoint | None = Field(
        default=None,
        description="Network endpoint from which the event originated.",
    )

    destination_endpoint: Endpoint | None = Field(
        default=None,
        description="Network endpoint targeted by the event.",
    )

    process: ProcessInfo | None = Field(
        default=None,
        description="Process-level information associated with the event.",
    )

    file: FileInfo | None = Field(
        default=None,
        description="File-level information associated with the event.",
    )

    # -- Flexible derived data ----------------------------------------------

    normalized_data: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Structured JSON-compatible data derived from normalization "
            "that does not yet fit into the strongly-typed common fields.  "
            "Must not mirror or duplicate raw_data."
        ),
    )

    # -- Provenance ---------------------------------------------------------

    provenance: Provenance = Field(
        default=Provenance.OBSERVED,
        description=(
            "Event-level provenance marker.  A newly normalized event "
            "should be OBSERVED.  ENRICHED and RECONSTRUCTED are applied "
            "by their respective pipeline stages."
        ),
    )

    # -----------------------------------------------------------------------
    # Validators
    # -----------------------------------------------------------------------

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

    @field_validator("normalized_data")
    @classmethod
    def _ensure_json_compatible(cls, v: dict[str, Any]) -> dict[str, Any]:
        """Ensure normalized_data is strictly JSON-serializable."""
        try:
            json.dumps(v)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"normalized_data must be JSON-compatible: {exc}"
            ) from exc
        return v
