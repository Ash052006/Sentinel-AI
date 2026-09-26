"""Abstract collector interface and collection result models.

Every log collector in SentinelAI implements :class:`BaseCollector` and
returns a :class:`CollectionResult`.  This ensures a consistent contract
regardless of whether the source is a local file, syslog, Windows Event
Log, or a future cloud provider API.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.security_event import SecurityEvent

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Collection error
# ---------------------------------------------------------------------------

class CollectionError(BaseModel):
    """A single record-level error encountered during collection.

    Identifies *where* the problem occurred and a safe reason, without
    exposing sensitive raw event content.
    """

    line_number: int = Field(
        ...,
        description="1-based line number in the source where the error occurred.",
    )
    reason: str = Field(
        ...,
        description="Human-readable description of why the record was rejected.",
    )


# ---------------------------------------------------------------------------
# Collection result
# ---------------------------------------------------------------------------

class CollectionResult(BaseModel):
    """Aggregate result of a collection run.

    Returned by :meth:`BaseCollector.collect` and provides both the
    successfully collected events and operational statistics.
    """

    events: list[SecurityEvent] = Field(
        default_factory=list,
        description="Successfully validated SecurityEvent objects.",
    )

    total_records: int = Field(
        ...,
        description="Total number of records/lines read from the source.",
    )

    successful_records: int = Field(
        ...,
        description="Number of records that produced a valid SecurityEvent.",
    )

    failed_records: int = Field(
        ...,
        description="Number of records that were rejected or malformed.",
    )

    errors: list[CollectionError] = Field(
        default_factory=list,
        description="Details of each failed record.",
    )


# ---------------------------------------------------------------------------
# Abstract base collector
# ---------------------------------------------------------------------------

class BaseCollector(ABC):
    """Abstract base class for all SentinelAI log collectors.

    Subclasses implement :meth:`collect` to read from a specific source
    and return a :class:`CollectionResult` containing validated
    :class:`SecurityEvent` objects.

    Future collectors (syslog, Windows Event Log, cloud APIs, Kafka
    consumers) will all follow this same interface.
    """

    @abstractmethod
    def collect(self) -> CollectionResult:
        """Read records from the source and return validated events.

        The implementation must:

        * Treat file/network contents strictly as data (no ``eval``).
        * Preserve original event data in ``raw_data``.
        * Mark every event with ``Provenance.OBSERVED``.
        * Handle individual record failures without aborting the run.
        * Return a :class:`CollectionResult` with statistics.
        """