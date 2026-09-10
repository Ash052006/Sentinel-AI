"""Tests for the SecurityEvent contract.

These are pure schema-level unit tests — no database connection is required.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.schemas.security_event import Provenance, SecurityEvent, SourceType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_event(**overrides) -> dict:
    """Return a minimal valid SecurityEvent payload, with optional overrides."""
    base = {
        "timestamp": datetime.now(timezone.utc),
        "source": "windows",
        "source_type": SourceType.OPERATING_SYSTEM,
        "event_type": "authentication",
        "raw_data": {"EventID": 4624, "SubjectUserName": "SYSTEM"},
        "provenance": Provenance.OBSERVED,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# 1. Valid event creation
# ---------------------------------------------------------------------------

class TestValidEventCreation:
    def test_creates_valid_event(self):
        event = SecurityEvent(**_minimal_event())
        assert event.event_id is not None
        assert event.source == "windows"
        assert event.source_type == SourceType.OPERATING_SYSTEM
        assert event.event_type == "authentication"
        assert event.raw_data == {"EventID": 4624, "SubjectUserName": "SYSTEM"}
        assert event.provenance == Provenance.OBSERVED


# ---------------------------------------------------------------------------
# 2. Automatic UUID generation
# ---------------------------------------------------------------------------

class TestAutomaticUUID:
    def test_event_id_auto_generated(self):
        event = SecurityEvent(**_minimal_event())
        assert isinstance(event.event_id, uuid.UUID)

    def test_explicit_event_id_accepted(self):
        explicit = uuid.uuid4()
        event = SecurityEvent(**_minimal_event(event_id=explicit))
        assert event.event_id == explicit


# ---------------------------------------------------------------------------
# 3. Valid timezone-aware timestamp
# ---------------------------------------------------------------------------

class TestTimezoneAwareTimestamp:
    def test_utc_timestamp_accepted(self):
        ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        event = SecurityEvent(**_minimal_event(timestamp=ts))
        assert event.timestamp == ts

    def test_offset_timestamp_accepted(self):
        tz_plus2 = timezone(timedelta(hours=2))
        ts = datetime(2025, 6, 15, 14, 0, 0, tzinfo=tz_plus2)
        event = SecurityEvent(**_minimal_event(timestamp=ts))
        assert event.timestamp.utcoffset() == timedelta(hours=2)


# ---------------------------------------------------------------------------
# 4. Invalid UUID rejected
# ---------------------------------------------------------------------------

class TestInvalidUUID:
    def test_non_uuid_rejected(self):
        with pytest.raises(Exception):
            SecurityEvent(**_minimal_event(event_id="not-a-uuid"))

    def test_int_rejected(self):
        with pytest.raises(Exception):
            SecurityEvent(**_minimal_event(event_id=12345))


# ---------------------------------------------------------------------------
# 5. Naive timestamp rejected
# ---------------------------------------------------------------------------

class TestNaiveTimestampRejected:
    def test_naive_datetime_rejected(self):
        naive = datetime(2025, 6, 15, 12, 0, 0)
        with pytest.raises(Exception, match="timezone-aware"):
            SecurityEvent(**_minimal_event(timestamp=naive))


# ---------------------------------------------------------------------------
# 6. Empty source rejected
# ---------------------------------------------------------------------------

class TestEmptySourceRejected:
    def test_empty_string_rejected(self):
        with pytest.raises(Exception):
            SecurityEvent(**_minimal_event(source=""))


# ---------------------------------------------------------------------------
# 7. Empty event_type rejected
# ---------------------------------------------------------------------------

class TestEmptyEventTypeRejected:
    def test_empty_event_type_rejected(self):
        with pytest.raises(Exception):
            SecurityEvent(**_minimal_event(event_type=""))


# ---------------------------------------------------------------------------
# 8. Invalid source_type rejected
# ---------------------------------------------------------------------------

class TestInvalidSourceTypeRejected:
    def test_invalid_source_type_rejected(self):
        with pytest.raises(Exception):
            SecurityEvent(**_minimal_event(source_type="invalid_category"))

    def test_all_source_types_accepted(self):
        for st in SourceType:
            event = SecurityEvent(**_minimal_event(source_type=st))
            assert event.source_type == st


# ---------------------------------------------------------------------------
# 9. Invalid provenance rejected
# ---------------------------------------------------------------------------

class TestInvalidProvenanceRejected:
    def test_invalid_provenance_rejected(self):
        with pytest.raises(Exception):
            SecurityEvent(**_minimal_event(provenance="unknown"))

    def test_all_provenance_values_accepted(self):
        for p in Provenance:
            event = SecurityEvent(**_minimal_event(provenance=p))
            assert event.provenance == p


# ---------------------------------------------------------------------------
# 10. Structured raw_data accepted
# ---------------------------------------------------------------------------

class TestStructuredRawData:
    def test_nested_dict_accepted(self):
        raw = {
            "event": {"id": 4624, "level": 4},
            "host": {"name": "dc01", "ip": "10.0.0.1"},
            "tags": ["logon", "interactive"],
        }
        event = SecurityEvent(**_minimal_event(raw_data=raw))
        assert event.raw_data["event"]["id"] == 4624
        assert event.raw_data["host"]["name"] == "dc01"
        assert "logon" in event.raw_data["tags"]

    def test_raw_data_preserved_as_is(self):
        """raw_data must not be silently transformed."""
        raw = {"key": "value", "number": 42, "nested": {"a": [1, 2, 3]}}
        event = SecurityEvent(**_minimal_event(raw_data=raw))
        assert event.raw_data == raw


# ---------------------------------------------------------------------------
# 11. Structured metadata accepted
# ---------------------------------------------------------------------------

class TestStructuredMetadata:
    def test_metadata_accepted(self):
        meta = {
            "collector": "winlogbeat-8.12",
            "pipeline": "windows-auth",
            "custom": {"region": "us-east-1"},
        }
        event = SecurityEvent(**_minimal_event(metadata=meta))
        assert event.metadata == meta

    def test_metadata_defaults_to_none(self):
        event = SecurityEvent(**_minimal_event())
        assert event.metadata is None


# ---------------------------------------------------------------------------
# 12. Provenance correctly represented
# ---------------------------------------------------------------------------

class TestProvenanceRepresentation:
    def test_provenance_enum_values(self):
        assert Provenance.OBSERVED.value == "observed"
        assert Provenance.ENRICHED.value == "enriched"
        assert Provenance.RECONSTRUCTED.value == "reconstructed"

    def test_provenance_serialises_as_string(self):
        event = SecurityEvent(**_minimal_event(provenance=Provenance.ENRICHED))
        dumped = event.model_dump()
        assert dumped["provenance"] == "enriched"

    def test_provenance_observed_accepted(self):
        event = SecurityEvent(**_minimal_event(provenance=Provenance.OBSERVED))
        assert event.provenance == Provenance.OBSERVED

    def test_provenance_enriched_accepted(self):
        event = SecurityEvent(**_minimal_event(provenance=Provenance.ENRICHED))
        assert event.provenance == Provenance.ENRICHED

    def test_provenance_reconstructed_accepted(self):
        event = SecurityEvent(**_minimal_event(provenance=Provenance.RECONSTRUCTED))
        assert event.provenance == Provenance.RECONSTRUCTED


# ---------------------------------------------------------------------------
# 13. Raw data remains separate from future derived data
# ---------------------------------------------------------------------------

class TestRawDataSeparation:
    def test_no_normalized_data_field(self):
        """The schema should not yet have normalised_data — it is a future
        addition.  This test ensures we don't accidentally add it too early."""
        fields = SecurityEvent.model_fields
        assert "normalised_data" not in fields
        assert "normalized_data" not in fields
        assert "enriched_data" not in fields

    def test_raw_data_not_mutated_by_serialisation(self):
        original_raw = {"EventID": 4624, "data": [1, 2, 3]}
        event = SecurityEvent(**_minimal_event(raw_data=original_raw))
        # Serialize and deserialise
        restored = SecurityEvent.model_validate(event.model_dump())
        assert restored.raw_data == original_raw
        assert original_raw == {"EventID": 4624, "data": [1, 2, 3]}


# ---------------------------------------------------------------------------
# 14. Multiple events receive different event IDs
# ---------------------------------------------------------------------------

class TestUniqueEventIDs:
    def test_different_events_different_ids(self):
        events = [
            SecurityEvent(**_minimal_event()) for _ in range(20)
        ]
        ids = {e.event_id for e in events}
        assert len(ids) == 20, (
            f"Expected 20 unique IDs, got {len(ids)} — "
            "UUID default_factory may not be generating unique values"
        )


# ---------------------------------------------------------------------------
# SourceType enum coverage
# ---------------------------------------------------------------------------

class TestSourceTypeEnum:
    def test_source_type_enum_values(self):
        expected = {
            "operating_system",
            "network",
            "application",
            "cloud",
            "identity",
            "security_device",
            "other",
        }
        actual = {st.value for st in SourceType}
        assert actual == expected

    def test_source_type_serialises_as_string(self):
        event = SecurityEvent(**_minimal_event(source_type=SourceType.CLOUD))
        dumped = event.model_dump()
        assert dumped["source_type"] == "cloud"
