"""Tests for the NormalizedSecurityEvent contract.

These are pure schema-level unit tests -- no database or Kafka connection
is required.  They verify the data contract for normalized security
events, ensuring validation, type safety, and design invariants.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.schemas.normalized_event import (
    Actor,
    Endpoint,
    EventCategory,
    EventOutcome,
    FileInfo,
    NormalizedSecurityEvent,
    ProcessInfo,
)
from app.schemas.security_event import Provenance, SourceType


# ---------------------------------------------------------------------------
# Helpers -- synthetic test data
# ---------------------------------------------------------------------------

def _minimal_normalized(**overrides) -> dict:
    """Return a minimal valid NormalizedSecurityEvent payload."""
    base = {
        "event_id": uuid.uuid4(),
        "timestamp": datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc),
        "event_category": EventCategory.AUTHENTICATION,
        "source": "windows-dc-01",
        "source_type": SourceType.OPERATING_SYSTEM,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# 1. Valid NormalizedSecurityEvent creation
# ---------------------------------------------------------------------------

class TestValidNormalizedEventCreation:
    def test_creates_valid_normalized_event(self):
        event = NormalizedSecurityEvent(**_minimal_normalized())
        assert isinstance(event.event_id, uuid.UUID)
        assert event.event_category == EventCategory.AUTHENTICATION
        assert event.source == "windows-dc-01"
        assert event.source_type == SourceType.OPERATING_SYSTEM
        assert event.outcome == EventOutcome.UNKNOWN
        assert event.action is None
        assert event.provenance == Provenance.OBSERVED
        assert event.normalized_data == {}
        assert event.actor is None
        assert event.source_endpoint is None
        assert event.destination_endpoint is None
        assert event.process is None
        assert event.file is None

    def test_all_core_fields_populated(self):
        event = NormalizedSecurityEvent(**_minimal_normalized(
            action="login",
            outcome=EventOutcome.SUCCESS,
        ))
        assert event.action == "login"
        assert event.outcome == EventOutcome.SUCCESS


# ---------------------------------------------------------------------------
# 2. event_id is preserved
# ---------------------------------------------------------------------------

class TestEventIdPreserved:
    def test_event_id_matches_supplied_value(self):
        fixed_id = uuid.uuid4()
        event = NormalizedSecurityEvent(**_minimal_normalized(event_id=fixed_id))
        assert event.event_id == fixed_id

    def test_event_id_not_regenerated(self):
        fixed_id = uuid.uuid4()
        event = NormalizedSecurityEvent(**_minimal_normalized(event_id=fixed_id))
        dumped = event.model_dump()
        restored = NormalizedSecurityEvent.model_validate(dumped)
        assert restored.event_id == fixed_id


# ---------------------------------------------------------------------------
# 3. timestamp is preserved and timezone-aware
# ---------------------------------------------------------------------------

class TestTimestampPreserved:
    def test_utc_timestamp_preserved(self):
        ts = datetime(2025, 3, 10, 8, 30, 0, tzinfo=timezone.utc)
        event = NormalizedSecurityEvent(**_minimal_normalized(timestamp=ts))
        assert event.timestamp == ts

    def test_non_utc_offset_preserved(self):
        tz_plus5 = timezone(timedelta(hours=5, minutes=30))
        ts = datetime(2025, 3, 10, 14, 0, 0, tzinfo=tz_plus5)
        event = NormalizedSecurityEvent(**_minimal_normalized(timestamp=ts))
        assert event.timestamp.utcoffset() == timedelta(hours=5, minutes=30)


# ---------------------------------------------------------------------------
# 4. Valid event_category accepted
# ---------------------------------------------------------------------------

class TestEventCategoryAccepted:
    @pytest.mark.parametrize("category", list(EventCategory))
    def test_each_category_accepted(self, category):
        event = NormalizedSecurityEvent(**_minimal_normalized(
            event_category=category,
        ))
        assert event.event_category == category

    def test_category_serialises_as_string(self):
        event = NormalizedSecurityEvent(**_minimal_normalized(
            event_category=EventCategory.NETWORK,
        ))
        dumped = event.model_dump()
        assert dumped["event_category"] == "network"


# ---------------------------------------------------------------------------
# 5. Valid action accepted
# ---------------------------------------------------------------------------

class TestActionAccepted:
    def test_known_action_string(self):
        event = NormalizedSecurityEvent(**_minimal_normalized(action="login"))
        assert event.action == "login"

    def test_custom_action_string(self):
        """Actions are free-form -- source-specific strings are accepted."""
        event = NormalizedSecurityEvent(**_minimal_normalized(
            action="custom_firewall_rule_match",
        ))
        assert event.action == "custom_firewall_rule_match"

    def test_action_none_by_default(self):
        event = NormalizedSecurityEvent(**_minimal_normalized())
        assert event.action is None


# ---------------------------------------------------------------------------
# 6. Valid outcome accepted
# ---------------------------------------------------------------------------

class TestOutcomeAccepted:
    @pytest.mark.parametrize("outcome", list(EventOutcome))
    def test_each_outcome_accepted(self, outcome):
        event = NormalizedSecurityEvent(**_minimal_normalized(outcome=outcome))
        assert event.outcome == outcome

    def test_outcome_defaults_to_unknown(self):
        event = NormalizedSecurityEvent(**_minimal_normalized())
        assert event.outcome == EventOutcome.UNKNOWN

    def test_outcome_serialises_as_string(self):
        event = NormalizedSecurityEvent(**_minimal_normalized(
            outcome=EventOutcome.DENIED,
        ))
        dumped = event.model_dump()
        assert dumped["outcome"] == "denied"


# ---------------------------------------------------------------------------
# 7. Optional actor works
# ---------------------------------------------------------------------------

class TestActorOptional:
    def test_actor_none_by_default(self):
        event = NormalizedSecurityEvent(**_minimal_normalized())
        assert event.actor is None

    def test_actor_with_all_fields(self):
        actor = Actor(user_id="S-1-5-21", username="jdoe", domain="CORP")
        event = NormalizedSecurityEvent(**_minimal_normalized(actor=actor))
        assert event.actor.username == "jdoe"
        assert event.actor.domain == "CORP"
        assert event.actor.user_id == "S-1-5-21"

    def test_actor_with_partial_fields(self):
        actor = Actor(username="root")
        event = NormalizedSecurityEvent(**_minimal_normalized(actor=actor))
        assert event.actor.username == "root"
        assert event.actor.user_id is None
        assert event.actor.domain is None


# ---------------------------------------------------------------------------
# 8. Optional source_endpoint works
# ---------------------------------------------------------------------------

class TestSourceEndpointOptional:
    def test_source_endpoint_none_by_default(self):
        event = NormalizedSecurityEvent(**_minimal_normalized())
        assert event.source_endpoint is None

    def test_source_endpoint_with_fields(self):
        ep = Endpoint(ip="10.0.0.5", hostname="web-01", port=443, protocol="tcp")
        event = NormalizedSecurityEvent(**_minimal_normalized(source_endpoint=ep))
        assert event.source_endpoint.ip == "10.0.0.5"
        assert event.source_endpoint.port == 443

    def test_source_endpoint_partial(self):
        ep = Endpoint(ip="192.168.1.1")
        event = NormalizedSecurityEvent(**_minimal_normalized(source_endpoint=ep))
        assert event.source_endpoint.ip == "192.168.1.1"
        assert event.source_endpoint.port is None


# ---------------------------------------------------------------------------
# 9. Optional destination_endpoint works
# ---------------------------------------------------------------------------

class TestDestinationEndpointOptional:
    def test_destination_endpoint_none_by_default(self):
        event = NormalizedSecurityEvent(**_minimal_normalized())
        assert event.destination_endpoint is None

    def test_destination_endpoint_with_fields(self):
        ep = Endpoint(ip="172.16.0.100", port=3389, protocol="tcp")
        event = NormalizedSecurityEvent(**_minimal_normalized(
            destination_endpoint=ep,
        ))
        assert event.destination_endpoint.ip == "172.16.0.100"
        assert event.destination_endpoint.port == 3389


# ---------------------------------------------------------------------------
# 10. Optional process works
# ---------------------------------------------------------------------------

class TestProcessOptional:
    def test_process_none_by_default(self):
        event = NormalizedSecurityEvent(**_minimal_normalized())
        assert event.process is None

    def test_process_with_fields(self):
        proc = ProcessInfo(
            name="svchost.exe",
            pid=1234,
            command_line="svchost.exe -k netsvcs",
            executable="C:\\Windows\\System32\\svchost.exe",
            parent_process="services.exe",
        )
        event = NormalizedSecurityEvent(**_minimal_normalized(process=proc))
        assert event.process.name == "svchost.exe"
        assert event.process.pid == 1234
        assert event.process.parent_process == "services.exe"

    def test_process_partial(self):
        proc = ProcessInfo(name="bash", pid=999)
        event = NormalizedSecurityEvent(**_minimal_normalized(process=proc))
        assert event.process.name == "bash"
        assert event.process.command_line is None


# ---------------------------------------------------------------------------
# 11. Optional file works
# ---------------------------------------------------------------------------

class TestFileOptional:
    def test_file_none_by_default(self):
        event = NormalizedSecurityEvent(**_minimal_normalized())
        assert event.file is None

    def test_file_with_fields(self):
        fi = FileInfo(
            name="malware.exe",
            path="C:\\Temp\\malware.exe",
            extension=".exe",
            hash="abc123def456",
        )
        event = NormalizedSecurityEvent(**_minimal_normalized(file=fi))
        assert event.file.name == "malware.exe"
        assert event.file.extension == ".exe"
        assert event.file.hash == "abc123def456"

    def test_file_partial(self):
        fi = FileInfo(name="config.yaml")
        event = NormalizedSecurityEvent(**_minimal_normalized(file=fi))
        assert event.file.name == "config.yaml"
        assert event.file.path is None


# ---------------------------------------------------------------------------
# 12. normalized_data accepts structured JSON-compatible data
# ---------------------------------------------------------------------------

class TestNormalizedData:
    def test_empty_dict_default(self):
        event = NormalizedSecurityEvent(**_minimal_normalized())
        assert event.normalized_data == {}

    def test_nested_structures(self):
        data = {
            "user": {"name": "admin", "roles": ["read", "write"]},
            "count": 42,
            "flag": True,
            "nothing": None,
        }
        event = NormalizedSecurityEvent(**_minimal_normalized(normalized_data=data))
        assert event.normalized_data == data

    def test_nested_dict_with_lists(self):
        data = {
            "tags": ["suspicious", "lateral-movement"],
            "scores": [0.8, 0.9, 0.7],
        }
        event = NormalizedSecurityEvent(**_minimal_normalized(normalized_data=data))
        assert event.normalized_data["tags"] == ["suspicious", "lateral-movement"]

    def test_non_json_object_rejected(self):
        """Objects that are not JSON-serializable must be rejected."""
        with pytest.raises(Exception):
            NormalizedSecurityEvent(**_minimal_normalized(
                normalized_data={"bad": object()},
            ))


# ---------------------------------------------------------------------------
# 13. Invalid event_id rejected
# ---------------------------------------------------------------------------

class TestInvalidEventId:
    def test_string_rejected(self):
        with pytest.raises(Exception):
            NormalizedSecurityEvent(**_minimal_normalized(
                event_id="not-a-uuid",
            ))

    def test_int_rejected(self):
        with pytest.raises(Exception):
            NormalizedSecurityEvent(**_minimal_normalized(event_id=12345))


# ---------------------------------------------------------------------------
# 14. Naive timestamp rejected
# ---------------------------------------------------------------------------

class TestNaiveTimestampRejected:
    def test_naive_utc_rejected(self):
        ts = datetime(2025, 6, 15, 12, 0, 0)  # no tzinfo
        with pytest.raises(Exception):
            NormalizedSecurityEvent(**_minimal_normalized(timestamp=ts))

    def test_aware_timestamp_accepted(self):
        ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        event = NormalizedSecurityEvent(**_minimal_normalized(timestamp=ts))
        assert event.timestamp.tzinfo is not None


# ---------------------------------------------------------------------------
# 15. Invalid provenance rejected
# ---------------------------------------------------------------------------

class TestInvalidProvenance:
    def test_invalid_provenance_rejected(self):
        with pytest.raises(Exception):
            NormalizedSecurityEvent(**_minimal_normalized(
                provenance="bogus",
            ))

    def test_all_valid_provenance_accepted(self):
        for p in Provenance:
            event = NormalizedSecurityEvent(**_minimal_normalized(provenance=p))
            assert event.provenance == p


# ---------------------------------------------------------------------------
# 16. Missing required fields rejected
# ---------------------------------------------------------------------------

class TestMissingRequiredFields:
    def test_missing_event_id_rejected(self):
        with pytest.raises(Exception):
            NormalizedSecurityEvent(**{
                "timestamp": datetime.now(timezone.utc),
                "event_category": EventCategory.NETWORK,
                "source": "firewall-01",
                "source_type": SourceType.NETWORK,
            })

    def test_missing_timestamp_rejected(self):
        with pytest.raises(Exception):
            NormalizedSecurityEvent(**{
                "event_id": uuid.uuid4(),
                "event_category": EventCategory.NETWORK,
                "source": "firewall-01",
                "source_type": SourceType.NETWORK,
            })

    def test_missing_event_category_rejected(self):
        with pytest.raises(Exception):
            NormalizedSecurityEvent(**{
                "event_id": uuid.uuid4(),
                "timestamp": datetime.now(timezone.utc),
                "source": "firewall-01",
                "source_type": SourceType.NETWORK,
            })

    def test_missing_source_rejected(self):
        with pytest.raises(Exception):
            NormalizedSecurityEvent(**{
                "event_id": uuid.uuid4(),
                "timestamp": datetime.now(timezone.utc),
                "event_category": EventCategory.NETWORK,
                "source_type": SourceType.NETWORK,
            })

    def test_missing_source_type_rejected(self):
        with pytest.raises(Exception):
            NormalizedSecurityEvent(**{
                "event_id": uuid.uuid4(),
                "timestamp": datetime.now(timezone.utc),
                "event_category": EventCategory.NETWORK,
                "source": "firewall-01",
            })

    def test_empty_source_rejected(self):
        with pytest.raises(Exception):
            NormalizedSecurityEvent(**_minimal_normalized(source=""))


# ---------------------------------------------------------------------------
# 17. Raw event is not part of normalized_data by accidental mutation
# ---------------------------------------------------------------------------

class TestRawEventNotInNormalized:
    def test_no_raw_data_field(self):
        """NormalizedSecurityEvent must not have a raw_data field."""
        fields = NormalizedSecurityEvent.model_fields
        assert "raw_data" not in fields

    def test_creating_normalized_does_not_mutate_original(self):
        """Creating a NormalizedSecurityEvent must not imply any
        mutation of an external raw event."""
        original_data = {"EventID": 4624, "SubjectUserName": "SYSTEM"}
        fixed_id = uuid.uuid4()
        normalized = NormalizedSecurityEvent(**_minimal_normalized(event_id=fixed_id))

        assert "raw_data" not in normalized.model_dump()
        assert original_data == {"EventID": 4624, "SubjectUserName": "SYSTEM"}

    def test_normalized_data_independent_between_events(self):
        """Two normalized events with the same event_id but different
        normalized_data must not interfere."""
        fixed_id = uuid.uuid4()
        event_a = NormalizedSecurityEvent(**_minimal_normalized(
            event_id=fixed_id,
            normalized_data={"flag": "A"},
        ))
        event_b = NormalizedSecurityEvent(**_minimal_normalized(
            event_id=fixed_id,
            normalized_data={"flag": "B"},
        ))
        assert event_a.normalized_data["flag"] == "A"
        assert event_b.normalized_data["flag"] == "B"


# ---------------------------------------------------------------------------
# 18. Multiple normalized events can coexist with distinct event IDs
# ---------------------------------------------------------------------------

class TestDistinctEventIds:
    def test_multiple_events_unique_ids(self):
        events = [
            NormalizedSecurityEvent(**_minimal_normalized())
            for _ in range(20)
        ]
        ids = {e.event_id for e in events}
        assert len(ids) == 20, (
            f"Expected 20 unique IDs, got {len(ids)}"
        )


# ---------------------------------------------------------------------------
# Nested model validation
# ---------------------------------------------------------------------------

class TestNestedModelValidation:
    def test_actor_extra_fields_ignored(self):
        """Pydantic v2 default: unknown fields in nested models are
        silently ignored rather than raising."""
        actor = Actor.model_validate(
            {"username": "admin", "bogus_field": "nope"}
        )
        assert actor.username == "admin"
        assert not hasattr(actor, "bogus_field")

    def test_endpoint_port_must_be_int(self):
        with pytest.raises(Exception):
            Endpoint.model_validate({"ip": "10.0.0.1", "port": "not-a-number"})

    def test_process_pid_must_be_int(self):
        with pytest.raises(Exception):
            ProcessInfo.model_validate({"name": "bash", "pid": "abc"})


# ---------------------------------------------------------------------------
# Enum coverage
# ---------------------------------------------------------------------------

class TestEventCategoryEnum:
    def test_all_expected_values(self):
        expected = {
            "authentication", "process", "network",
            "file", "system", "application", "other",
        }
        actual = {c.value for c in EventCategory}
        assert actual == expected


class TestEventOutcomeEnum:
    def test_all_expected_values(self):
        expected = {"success", "failure", "allowed", "denied", "unknown"}
        actual = {o.value for o in EventOutcome}
        assert actual == expected
