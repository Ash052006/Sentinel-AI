"""Unit tests for SecurityEvent Kafka serialization.

These tests verify the serialize → deserialize round-trip in isolation
(no Kafka broker required).  Every field must survive unchanged.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.kafka.serialization import (
    deserialize_event,
    event_to_dict,
    serialize_event,
)
from app.schemas.security_event import Provenance, SecurityEvent, SourceType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(**overrides) -> SecurityEvent:
    """Create a valid SecurityEvent with sensible defaults."""
    defaults = {
        "timestamp": datetime(2025, 1, 15, 12, 30, 0, tzinfo=timezone.utc),
        "source": "test-host",
        "source_type": SourceType.OPERATING_SYSTEM,
        "event_type": "authentication",
        "raw_data": {"event": "login", "user": "alice", "success": True},
        "provenance": Provenance.OBSERVED,
        "metadata": {"collector": "file_collector", "line_number": 1},
    }
    defaults.update(overrides)
    return SecurityEvent(**defaults)


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

class TestSerializeEvent:
    """SecurityEvent serialization produces valid JSON bytes."""

    def test_returns_bytes(self):
        event = _make_event()
        result = serialize_event(event)
        assert isinstance(result, bytes)

    def test_valid_utf8_json(self):
        event = _make_event()
        raw = serialize_event(event)
        parsed = json.loads(raw.decode("utf-8"))
        assert isinstance(parsed, dict)

    def test_contains_all_required_fields(self):
        event = _make_event()
        raw = serialize_event(event)
        parsed = json.loads(raw.decode("utf-8"))
        for field in ("event_id", "timestamp", "source", "source_type",
                       "event_type", "raw_data", "provenance"):
            assert field in parsed


# ---------------------------------------------------------------------------
# Deserialization
# ---------------------------------------------------------------------------

class TestDeserializeEvent:
    """Deserialization produces a validated SecurityEvent."""

    def test_from_bytes(self):
        event = _make_event()
        raw = serialize_event(event)
        restored = deserialize_event(raw)
        assert isinstance(restored, SecurityEvent)

    def test_from_string(self):
        event = _make_event()
        raw = serialize_event(event).decode("utf-8")
        restored = deserialize_event(raw)
        assert isinstance(restored, SecurityEvent)

    def test_rejects_invalid_json(self):
        with pytest.raises(Exception):
            deserialize_event(b"not valid json {{{")

    def test_rejects_missing_required_fields(self):
        incomplete = json.dumps({"event_id": str(uuid.uuid4())})
        with pytest.raises(ValidationError):
            deserialize_event(incomplete)

    def test_rejects_naive_timestamp(self):
        event = _make_event()
        raw = serialize_event(event)
        parsed = json.loads(raw)
        parsed["timestamp"] = "2025-01-15T12:30:00"
        with pytest.raises(ValidationError):
            deserialize_event(json.dumps(parsed).encode("utf-8"))

    def test_rejects_invalid_source_type(self):
        event = _make_event()
        raw = serialize_event(event)
        parsed = json.loads(raw)
        parsed["source_type"] = "invalid_type"
        with pytest.raises(ValidationError):
            deserialize_event(json.dumps(parsed).encode("utf-8"))


# ---------------------------------------------------------------------------
# Round-trip fidelity
# ---------------------------------------------------------------------------

class TestRoundTripFidelity:
    """Serialize → deserialize must preserve every field exactly."""

    @pytest.fixture()
    def original(self) -> SecurityEvent:
        return _make_event()

    @pytest.fixture()
    def restored(self, original: SecurityEvent) -> SecurityEvent:
        return deserialize_event(serialize_event(original))

    def test_event_id_unchanged(self, original: SecurityEvent, restored: SecurityEvent):
        assert original.event_id == restored.event_id

    def test_timestamp_unchanged(self, original: SecurityEvent, restored: SecurityEvent):
        assert original.timestamp == restored.timestamp

    def test_source_unchanged(self, original: SecurityEvent, restored: SecurityEvent):
        assert original.source == restored.source

    def test_source_type_unchanged(self, original: SecurityEvent, restored: SecurityEvent):
        assert original.source_type == restored.source_type

    def test_event_type_unchanged(self, original: SecurityEvent, restored: SecurityEvent):
        assert original.event_type == restored.event_type

    def test_raw_data_unchanged(self, original: SecurityEvent, restored: SecurityEvent):
        assert original.raw_data == restored.raw_data

    def test_raw_data_exact_value(self, original: SecurityEvent, restored: SecurityEvent):
        assert json.dumps(original.raw_data) == json.dumps(restored.raw_data)

    def test_provenance_unchanged(self, original: SecurityEvent, restored: SecurityEvent):
        assert original.provenance == restored.provenance
        assert original.provenance == Provenance.OBSERVED

    def test_metadata_unchanged(self, original: SecurityEvent, restored: SecurityEvent):
        assert original.metadata == restored.metadata

    def test_provenance_is_observed(self, restored: SecurityEvent):
        """Kafka transport must not change provenance."""
        assert restored.provenance == Provenance.OBSERVED


# ---------------------------------------------------------------------------
# Multiple events
# ---------------------------------------------------------------------------

class TestMultipleEvents:
    """Multiple events retain their identities through serialization."""

    def test_different_events_different_ids(self):
        events = [_make_event() for _ in range(5)]
        serialized = [serialize_event(e) for e in events]
        restored = [deserialize_event(s) for s in serialized]
        ids = [e.event_id for e in restored]
        assert len(set(ids)) == 5, "All event IDs must remain unique"

    def test_specific_event_identity(self):
        event = _make_event(
            raw_data={"specific": True, "value": 42},
        )
        original_id = event.event_id
        restored = deserialize_event(serialize_event(event))
        assert restored.event_id == original_id
        assert restored.raw_data["specific"] is True
        assert restored.raw_data["value"] == 42


# ---------------------------------------------------------------------------
# event_to_dict
# ---------------------------------------------------------------------------

class TestEventToDict:
    """event_to_dict produces a plain dictionary."""

    def test_returns_dict(self):
        event = _make_event()
        result = event_to_dict(event)
        assert isinstance(result, dict)

    def test_contains_all_fields(self):
        event = _make_event()
        result = event_to_dict(event)
        for field in ("event_id", "timestamp", "source", "source_type",
                       "event_type", "raw_data", "provenance"):
            assert field in result

    def test_event_id_is_string_in_dict(self):
        event = _make_event()
        result = event_to_dict(event)
        assert isinstance(result["event_id"], str)

    def test_provenance_is_string_in_dict(self):
        event = _make_event()
        result = event_to_dict(event)
        assert result["provenance"] == "observed"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestSerializationEdgeCases:
    """Edge cases in serialization."""

    def test_complex_nested_raw_data(self):
        raw = {
            "network": {
                "src_ip": "10.0.0.1",
                "dst_ip": "192.168.1.100",
                "ports": [80, 443, 8080],
                "headers": {"User-Agent": "Mozilla/5.0"},
            }
        }
        event = _make_event(raw_data=raw)
        restored = deserialize_event(serialize_event(event))
        assert restored.raw_data == raw

    def test_unicode_in_raw_data(self):
        raw = {"message": "测试消息 — 日本語テスト — Ελληνικά"}
        event = _make_event(raw_data=raw)
        restored = deserialize_event(serialize_event(event))
        assert restored.raw_data == raw

    def test_empty_dict_raw_data(self):
        event = _make_event(raw_data={})
        restored = deserialize_event(serialize_event(event))
        assert restored.raw_data == {}

    def test_large_raw_data(self):
        raw = {"items": [f"item_{i}" for i in range(1000)]}
        event = _make_event(raw_data=raw)
        restored = deserialize_event(serialize_event(event))
        assert restored.raw_data == raw