"""SecurityEvent serialization for Kafka transport.

Provides deterministic JSON serialization and deserialization that
preserves full event fidelity.  Every field — including ``raw_data``,
``provenance``, and ``event_id`` — survives the round-trip unchanged.

The producer and consumer use these functions exclusively so there is
a single source of truth for the wire format.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from app.schemas.security_event import SecurityEvent

logger = logging.getLogger(__name__)


def serialize_event(event: SecurityEvent) -> bytes:
    """Serialize a :class:`SecurityEvent` to a UTF-8 JSON byte string.

    Uses Pydantic's ``model_dump_json`` for schema-aware serialisation.
    Enums are emitted as their string values
    (``Provenance.OBSERVED`` → ``"observed"``).

    The resulting bytes can be sent directly as a Kafka message value.
    """
    return event.model_dump_json().encode("utf-8")


def deserialize_event(data: bytes | str) -> SecurityEvent:
    """Deserialize JSON bytes into a validated :class:`SecurityEvent`.

    Raises ``pydantic.ValidationError`` if the data does not conform to
    the SecurityEvent schema.  The caller **must** handle this — it must
    never be silently swallowed.
    """
    if isinstance(data, bytes):
        data = data.decode("utf-8")

    parsed: dict[str, Any] = json.loads(data)
    return SecurityEvent.model_validate(parsed)


def event_to_dict(event: SecurityEvent) -> dict[str, Any]:
    """Serialize a :class:`SecurityEvent` to a plain dictionary.

    Useful when callers need a dict rather than raw bytes (e.g. logging,
    inspection).
    """
    return event.model_dump(mode="json")