"""Tests for the NormalizationAgent.

Covers deterministic field mapping from SecurityEvent → NormalizedSecurityEvent
for all required source types, field aliases, and edge cases.

These are pure unit tests — no database, Kafka, or network connections required.
"""

import uuid
from datetime import datetime, timezone
from typing import Any

import pytest

from app.agents.normalization import (
    FIREWALL_MAPPING,
    LINUX_MAPPING,
    WINDOWS_MAPPING,
    FieldMapping,
    NormalizationAgent,
    SourceMapping,
)
from app.schemas.normalized_event import (
    EventCategory,
    EventOutcome,
    NormalizedSecurityEvent,
)
from app.schemas.security_event import Provenance, SecurityEvent, SourceType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

agent = NormalizationAgent()

_FIXED_TS = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)


def _make_event(
    *,
    source: str = "windows",
    source_type: SourceType = SourceType.OPERATING_SYSTEM,
    event_type: str = "authentication",
    raw_data: dict[str, Any] | None = None,
    provenance: Provenance = Provenance.OBSERVED,
) -> SecurityEvent:
    """Create a SecurityEvent for testing."""
    return SecurityEvent(
        timestamp=_FIXED_TS,
        source=source,
        source_type=source_type,
        event_type=event_type,
        raw_data=raw_data if raw_data is not None else {},
        provenance=provenance,
    )


# ===========================================================================
# 1. FieldMapping unit tests
# ===========================================================================

class TestFieldMapping:
    def test_extract_returns_first_match(self):
        fm = FieldMapping(candidates=("a", "b", "c"))
        assert fm.extract({"b": 42, "c": 99}) == 42

    def test_extract_returns_none_when_no_match(self):
        fm = FieldMapping(candidates=("a", "b"))
        assert fm.extract({"x": 1}) is None

    def test_extract_returns_none_for_empty_candidates(self):
        fm = FieldMapping()
        assert fm.extract({"a": 1}) is None

    def test_extract_skips_none_values(self):
        fm = FieldMapping(candidates=("a", "b"))
        assert fm.extract({"a": None, "b": "found"}) == "found"

    def test_extract_str_coerces_to_string(self):
        fm = FieldMapping(candidates=("port",))
        assert fm.extract_str({"port": 443}) == "443"

    def test_extract_str_returns_none_when_absent(self):
        fm = FieldMapping(candidates=("port",))
        assert fm.extract_str({}) is None

    def test_extract_int_coerces_to_int(self):
        fm = FieldMapping(candidates=("port",))
        assert fm.extract_int({"port": "443"}) == 443

    def test_extract_int_handles_int_value(self):
        fm = FieldMapping(candidates=("port",))
        assert fm.extract_int({"port": 443}) == 443

    def test_extract_int_returns_none_for_non_numeric(self):
        fm = FieldMapping(candidates=("port",))
        assert fm.extract_int({"port": "abc"}) is None

    def test_extract_int_returns_none_when_absent(self):
        fm = FieldMapping(candidates=("port",))
        assert fm.extract_int({}) is None

    def test_frozen(self):
        fm = FieldMapping(candidates=("x",))
        with pytest.raises(AttributeError):
            fm.candidates = ("y",)  # type: ignore[misc]


# ===========================================================================
# 2. SourceMapping defaults
# ===========================================================================

class TestSourceMappingDefaults:
    def test_default_mapping_has_empty_candidates(self):
        sm = SourceMapping()
        assert sm.actor_username.candidates == ()

    def test_custom_mapping_preserves_values(self):
        fm = FieldMapping(candidates=("a", "b"))
        sm = SourceMapping(actor_username=fm)
        assert sm.actor_username.candidates == ("a", "b")


# ===========================================================================
# 3. get_mapping
# ===========================================================================

class TestGetMapping:
    def test_exact_match_windows(self):
        m = NormalizationAgent.get_mapping("windows", SourceType.OPERATING_SYSTEM)
        assert m is WINDOWS_MAPPING

    def test_exact_match_linux(self):
        m = NormalizationAgent.get_mapping("linux", SourceType.OPERATING_SYSTEM)
        assert m is LINUX_MAPPING

    def test_exact_match_firewall(self):
        m = NormalizationAgent.get_mapping("firewall", SourceType.NETWORK)
        assert m is FIREWALL_MAPPING

    def test_prefix_match_windows(self):
        m = NormalizationAgent.get_mapping("windows-dc-01", SourceType.OPERATING_SYSTEM)
        assert m is WINDOWS_MAPPING

    def test_prefix_match_linux(self):
        m = NormalizationAgent.get_mapping("linux-webserver-01", SourceType.OPERATING_SYSTEM)
        assert m is LINUX_MAPPING

    def test_case_insensitive(self):
        m = NormalizationAgent.get_mapping("WINDOWS", SourceType.OPERATING_SYSTEM)
        assert m is WINDOWS_MAPPING

    def test_unsupported_returns_empty_mapping(self):
        m = NormalizationAgent.get_mapping("unknown_device", SourceType.OTHER)
        assert m.actor_username.candidates == ()
        assert m.src_ip.candidates == ()

    def test_empty_string_returns_empty_mapping(self):
        m = NormalizationAgent.get_mapping("", SourceType.OTHER)
        assert m.actor_username.candidates == ()


# ===========================================================================
# 4. Windows field aliases
# ===========================================================================

class TestWindowsFieldAliases:
    """Verify every Windows-specific raw_data key maps to the correct field."""

    def test_target_username_maps_to_actor_username(self):
        event = _make_event(source="windows", raw_data={"TargetUserName": "alice"})
        assert agent.normalize(event).actor.username == "alice"

    def test_subject_username_fallback(self):
        event = _make_event(source="windows", raw_data={"SubjectUserName": "admin"})
        assert agent.normalize(event).actor.username == "admin"

    def test_account_name_fallback(self):
        event = _make_event(source="windows", raw_data={"AccountName": "svc"})
        assert agent.normalize(event).actor.username == "svc"

    def test_target_domain_maps_to_actor_domain(self):
        event = _make_event(source="windows", raw_data={"TargetDomainName": "CORP"})
        assert agent.normalize(event).actor.domain == "CORP"

    def test_subject_domain_fallback(self):
        event = _make_event(source="windows", raw_data={"SubjectDomainName": "NT AUTHORITY"})
        assert agent.normalize(event).actor.domain == "NT AUTHORITY"

    def test_target_user_sid_maps_to_user_id(self):
        event = _make_event(source="windows", raw_data={"TargetUserSid": "S-1-5-21"})
        assert agent.normalize(event).actor.user_id == "S-1-5-21"

    def test_subject_user_sid_fallback(self):
        event = _make_event(source="windows", raw_data={"SubjectUserSid": "S-1-0-0"})
        assert agent.normalize(event).actor.user_id == "S-1-0-0"

    def test_ip_address_maps_to_source_endpoint_ip(self):
        event = _make_event(source="windows", raw_data={"IpAddress": "10.0.0.5"})
        assert agent.normalize(event).source_endpoint.ip == "10.0.0.5"

    def test_ip_port_maps_to_source_endpoint_port(self):
        event = _make_event(source="windows", raw_data={"IpPort": 49832})
        assert agent.normalize(event).source_endpoint.port == 49832

    def test_workstation_name_maps_to_hostname(self):
        event = _make_event(source="windows", raw_data={"WorkstationName": "WS-01"})
        assert agent.normalize(event).source_endpoint.hostname == "WS-01"

    def test_computer_name_fallback(self):
        event = _make_event(source="windows", raw_data={"ComputerName": "DC-01"})
        assert agent.normalize(event).source_endpoint.hostname == "DC-01"

    def test_new_process_name_maps_to_process_name(self):
        event = _make_event(
            source="windows",
            event_type="process_creation",
            raw_data={"NewProcessName": "C:\\Windows\\System32\\cmd.exe"},
        )
        assert agent.normalize(event).process.name == "C:\\Windows\\System32\\cmd.exe"

    def test_process_name_fallback(self):
        event = _make_event(
            source="windows",
            event_type="process_creation",
            raw_data={"ProcessName": "notepad.exe"},
        )
        assert agent.normalize(event).process.name == "notepad.exe"

    def test_new_process_id_maps_to_pid(self):
        event = _make_event(
            source="windows", event_type="process_creation",
            raw_data={"NewProcessId": 1234},
        )
        assert agent.normalize(event).process.pid == 1234

    def test_process_id_fallback(self):
        event = _make_event(
            source="windows", event_type="process_creation",
            raw_data={"ProcessId": 5678},
        )
        assert agent.normalize(event).process.pid == 5678

    def test_command_line_maps_to_process_command_line(self):
        event = _make_event(
            source="windows", event_type="process_creation",
            raw_data={"CommandLine": "cmd.exe /c whoami"},
        )
        assert agent.normalize(event).process.command_line == "cmd.exe /c whoami"

    def test_parent_process_name_maps_to_parent(self):
        event = _make_event(
            source="windows", event_type="process_creation",
            raw_data={"ParentProcessName": "explorer.exe"},
        )
        assert agent.normalize(event).process.parent_process == "explorer.exe"

    def test_file_name_maps_to_file_name(self):
        event = _make_event(
            source="windows", event_type="file_activity",
            raw_data={"FileName": "report.docx"},
        )
        assert agent.normalize(event).file.name == "report.docx"

    def test_object_name_fallback_for_file(self):
        event = _make_event(
            source="windows", event_type="file_activity",
            raw_data={"ObjectName": "data.csv"},
        )
        assert agent.normalize(event).file.name == "data.csv"

    def test_status_0x0_maps_to_success(self):
        event = _make_event(source="windows", raw_data={"Status": "0x0"})
        assert agent.normalize(event).outcome == EventOutcome.SUCCESS

    def test_status_0xc000006d_maps_to_failure(self):
        event = _make_event(source="windows", raw_data={"Status": "0xC000006D"})
        assert agent.normalize(event).outcome == EventOutcome.FAILURE

    def test_status_0xc000006a_maps_to_failure(self):
        event = _make_event(source="windows", raw_data={"Status": "0xC000006A"})
        assert agent.normalize(event).outcome == EventOutcome.FAILURE

    def test_event_id_in_normalized_data(self):
        event = _make_event(source="windows", raw_data={"EventID": 4624})
        result = agent.normalize(event)
        assert result.normalized_data["event_id_raw"] == 4624

    def test_logon_type_in_normalized_data(self):
        event = _make_event(source="windows", raw_data={"LogonType": 10})
        result = agent.normalize(event)
        assert result.normalized_data["logon_type"] == 10


# ===========================================================================
# 5. Linux field aliases
# ===========================================================================

class TestLinuxFieldAliases:
    """Verify Linux-specific raw_data keys map to the correct normalized fields."""

    # -- Actor ---------------------------------------------------------------
    def test_user_maps_to_actor_username(self):
        event = _make_event(source="linux", raw_data={"user": "bob"})
        assert agent.normalize(event).actor.username == "bob"

    def test_username_fallback(self):
        event = _make_event(source="linux", raw_data={"username": "admin"})
        assert agent.normalize(event).actor.username == "admin"

    def test_account_name_fallback(self):
        event = _make_event(source="linux", raw_data={"account_name": "syslog"})
        assert agent.normalize(event).actor.username == "syslog"

    def test_uid_maps_to_user_id(self):
        event = _make_event(source="linux", raw_data={"uid": 1001})
        assert agent.normalize(event).actor.user_id == "1001"

    def test_domain_maps_to_actor_domain(self):
        event = _make_event(source="linux", raw_data={"domain": "EXAMPLE"})
        assert agent.normalize(event).actor.domain == "EXAMPLE"

    # -- Source endpoint -----------------------------------------------------
    def test_src_ip_maps_to_endpoint_ip(self):
        event = _make_event(source="linux", raw_data={"src_ip": "192.168.1.1"})
        assert agent.normalize(event).source_endpoint.ip == "192.168.1.1"

    def test_source_ip_fallback(self):
        event = _make_event(source="linux", raw_data={"source_ip": "10.0.0.1"})
        assert agent.normalize(event).source_endpoint.ip == "10.0.0.1"

    def test_client_ip_fallback(self):
        event = _make_event(source="linux", raw_data={"client_ip": "172.16.0.1"})
        assert agent.normalize(event).source_endpoint.ip == "172.16.0.1"

    def test_src_port_maps_to_endpoint_port(self):
        event = _make_event(source="linux", raw_data={"src_port": 22})
        assert agent.normalize(event).source_endpoint.port == 22

    def test_source_port_fallback(self):
        event = _make_event(source="linux", raw_data={"source_port": 443})
        assert agent.normalize(event).source_endpoint.port == 443

    def test_hostname_maps_to_endpoint_hostname(self):
        event = _make_event(source="linux", raw_data={"hostname": "webserver-01"})
        assert agent.normalize(event).source_endpoint.hostname == "webserver-01"

    # -- Destination endpoint ------------------------------------------------
    def test_dst_ip_maps_to_destination_ip(self):
        event = _make_event(source="linux", raw_data={"dst_ip": "10.0.0.2"})
        assert agent.normalize(event).destination_endpoint.ip == "10.0.0.2"

    def test_dest_ip_fallback(self):
        event = _make_event(source="linux", raw_data={"dest_ip": "10.0.0.3"})
        assert agent.normalize(event).destination_endpoint.ip == "10.0.0.3"

    def test_dst_port_maps_to_destination_port(self):
        event = _make_event(source="linux", raw_data={"dst_port": 8080})
        assert agent.normalize(event).destination_endpoint.port == 8080

    # -- Process -------------------------------------------------------------
    def test_process_name_maps_to_process_name(self):
        event = _make_event(source="linux", raw_data={"process_name": "sshd"})
        assert agent.normalize(event).process.name == "sshd"

    def test_process_fallback(self):
        event = _make_event(source="linux", raw_data={"process": "nginx"})
        assert agent.normalize(event).process.name == "nginx"

    def test_comm_fallback(self):
        event = _make_event(source="linux", raw_data={"comm": "bash"})
        assert agent.normalize(event).process.name == "bash"

    def test_pid_maps_to_process_pid(self):
        event = _make_event(source="linux", raw_data={"pid": 5678})
        assert agent.normalize(event).process.pid == 5678

    def test_process_id_fallback(self):
        event = _make_event(source="linux", raw_data={"process_id": 9999})
        assert agent.normalize(event).process.pid == 9999

    def test_cmdline_maps_to_command_line(self):
        event = _make_event(source="linux", raw_data={"cmdline": "sshd -D"})
        assert agent.normalize(event).process.command_line == "sshd -D"

    def test_exe_maps_to_executable(self):
        event = _make_event(source="linux", raw_data={"exe": "/usr/sbin/sshd"})
        assert agent.normalize(event).process.executable == "/usr/sbin/sshd"

    def test_parent_process_maps_to_parent(self):
        event = _make_event(source="linux", raw_data={"parent_process": "systemd"})
        assert agent.normalize(event).process.parent_process == "systemd"

    def test_parent_comm_fallback(self):
        event = _make_event(source="linux", raw_data={"parent_comm": "init"})
        assert agent.normalize(event).process.parent_process == "init"

    # -- File ----------------------------------------------------------------
    def test_file_name_maps_to_file_name(self):
        event = _make_event(
            source="linux", event_type="file_activity",
            raw_data={"file_name": "shadow.bak"},
        )
        assert agent.normalize(event).file.name == "shadow.bak"

    def test_filename_fallback(self):
        event = _make_event(
            source="linux", event_type="file_activity",
            raw_data={"filename": "passwd"},
        )
        assert agent.normalize(event).file.name == "passwd"

    def test_file_path_maps_to_file_path(self):
        event = _make_event(
            source="linux", event_type="file_activity",
            raw_data={"file_path": "/etc/shadow"},
        )
        assert agent.normalize(event).file.path == "/etc/shadow"

    def test_path_fallback(self):
        event = _make_event(
            source="linux", event_type="file_activity",
            raw_data={"path": "/etc/passwd"},
        )
        assert agent.normalize(event).file.path == "/etc/passwd"

    def test_hash_maps_to_file_hash(self):
        event = _make_event(
            source="linux", event_type="file_activity",
            raw_data={"hash": "abc123"},
        )
        assert agent.normalize(event).file.hash == "abc123"

    def test_sha256_fallback(self):
        event = _make_event(
            source="linux", event_type="file_activity",
            raw_data={"sha256": "def456"},
        )
        assert agent.normalize(event).file.hash == "def456"

    # -- Action & outcome ----------------------------------------------------
    def test_action_maps_to_action(self):
        event = _make_event(source="linux", raw_data={"action": "login"})
        assert agent.normalize(event).action == "login"

    def test_result_maps_to_outcome_success(self):
        event = _make_event(source="linux", raw_data={"result": "success"})
        assert agent.normalize(event).outcome == EventOutcome.SUCCESS

    def test_result_maps_to_outcome_failure(self):
        event = _make_event(source="linux", raw_data={"result": "failed"})
        assert agent.normalize(event).outcome == EventOutcome.FAILURE

    def test_status_fallback(self):
        event = _make_event(source="linux", raw_data={"status": "denied"})
        assert agent.normalize(event).outcome == EventOutcome.DENIED


# ===========================================================================
# 6. Firewall field aliases
# ===========================================================================

class TestFirewallFieldAliases:
    """Verify firewall-specific raw_data keys map correctly."""

    def test_src_ip_maps_to_source_endpoint_ip(self):
        event = _make_event(
            source="firewall", source_type=SourceType.NETWORK,
            raw_data={"src_ip": "10.0.0.1"},
        )
        assert agent.normalize(event).source_endpoint.ip == "10.0.0.1"

    def test_source_ip_fallback(self):
        event = _make_event(
            source="firewall", source_type=SourceType.NETWORK,
            raw_data={"source_ip": "192.168.1.1"},
        )
        assert agent.normalize(event).source_endpoint.ip == "192.168.1.1"

    def test_dst_ip_maps_to_destination_ip(self):
        event = _make_event(
            source="firewall", source_type=SourceType.NETWORK,
            raw_data={"dst_ip": "10.0.0.2"},
        )
        assert agent.normalize(event).destination_endpoint.ip == "10.0.0.2"

    def test_dest_ip_fallback(self):
        event = _make_event(
            source="firewall", source_type=SourceType.NETWORK,
            raw_data={"dest_ip": "172.16.0.1"},
        )
        assert agent.normalize(event).destination_endpoint.ip == "172.16.0.1"

    def test_destination_ip_fallback(self):
        event = _make_event(
            source="firewall", source_type=SourceType.NETWORK,
            raw_data={"destination_ip": "8.8.8.8"},
        )
        assert agent.normalize(event).destination_endpoint.ip == "8.8.8.8"

    def test_protocol_maps_to_both_endpoints(self):
        event = _make_event(
            source="firewall", source_type=SourceType.NETWORK,
            raw_data={"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "protocol": "tcp"},
        )
        result = agent.normalize(event)
        assert result.source_endpoint.protocol == "tcp"
        assert result.destination_endpoint.protocol == "tcp"

    def test_action_allow_maps_to_outcome_allowed(self):
        event = _make_event(
            source="firewall", source_type=SourceType.NETWORK,
            raw_data={"action": "allow"},
        )
        result = agent.normalize(event)
        assert result.outcome == EventOutcome.ALLOWED
        assert result.action == "allowed"

    def test_action_deny_maps_to_outcome_denied(self):
        event = _make_event(
            source="firewall", source_type=SourceType.NETWORK,
            raw_data={"action": "deny"},
        )
        result = agent.normalize(event)
        assert result.outcome == EventOutcome.DENIED
        assert result.action == "denied"

    def test_action_block_maps_to_denied(self):
        event = _make_event(
            source="firewall", source_type=SourceType.NETWORK,
            raw_data={"action": "block"},
        )
        result = agent.normalize(event)
        assert result.outcome == EventOutcome.DENIED
        assert result.action == "denied"

    def test_extra_fields_in_normalized_data(self):
        event = _make_event(
            source="firewall", source_type=SourceType.NETWORK,
            raw_data={"rule": "block_torrent", "bytes_sent": 1024, "bytes_received": 512},
        )
        result = agent.normalize(event)
        assert result.normalized_data["rule_name"] == "block_torrent"
        assert result.normalized_data["bytes_sent"] == 1024
        assert result.normalized_data["bytes_received"] == 512


# ===========================================================================
# 7. Category classification
# ===========================================================================

class TestCategoryClassification:
    @pytest.mark.parametrize("event_type,expected", [
        ("authentication", EventCategory.AUTHENTICATION),
        ("logon", EventCategory.AUTHENTICATION),
        ("login", EventCategory.AUTHENTICATION),
        ("process_creation", EventCategory.PROCESS),
        ("process_start", EventCategory.PROCESS),
        ("network_connection", EventCategory.NETWORK),
        ("network", EventCategory.NETWORK),
        ("file_activity", EventCategory.FILE),
        ("file_create", EventCategory.FILE),
        ("file_access", EventCategory.FILE),
        ("system", EventCategory.SYSTEM),
        ("application", EventCategory.APPLICATION),
    ])
    def test_known_event_types(self, event_type, expected):
        event = _make_event(event_type=event_type, raw_data={})
        assert agent.normalize(event).event_category == expected

    def test_unknown_event_type_maps_to_other(self):
        event = _make_event(event_type="some_weird_event", raw_data={})
        assert agent.normalize(event).event_category == EventCategory.OTHER

    def test_case_insensitive_fallback(self):
        event = _make_event(event_type="Authentication", raw_data={})
        assert agent.normalize(event).event_category == EventCategory.AUTHENTICATION

    def test_firewall_source_hint_overrides_default(self):
        """Firewall mapping has category_hints for 'firewall' event_type."""
        event = _make_event(
            source="firewall", source_type=SourceType.NETWORK,
            event_type="firewall", raw_data={},
        )
        assert agent.normalize(event).event_category == EventCategory.NETWORK


# ===========================================================================
# 8. Outcome mapping
# ===========================================================================

class TestOutcomeMapping:
    @pytest.mark.parametrize("raw_outcome,expected", [
        ("success", EventOutcome.SUCCESS),
        ("successful", EventOutcome.SUCCESS),
        ("failure", EventOutcome.FAILURE),
        ("failed", EventOutcome.FAILURE),
        ("error", EventOutcome.FAILURE),
        ("allowed", EventOutcome.ALLOWED),
        ("permit", EventOutcome.ALLOWED),
        ("denied", EventOutcome.DENIED),
        ("deny", EventOutcome.DENIED),
        ("block", EventOutcome.DENIED),
        ("blocked", EventOutcome.DENIED),
    ])
    def test_known_outcome_synonyms(self, raw_outcome, expected):
        event = _make_event(source="linux", raw_data={"result": raw_outcome})
        assert agent.normalize(event).outcome == expected

    def test_no_outcome_field_returns_unknown(self):
        event = _make_event(source="linux", raw_data={"user": "alice"})
        assert agent.normalize(event).outcome == EventOutcome.UNKNOWN

    def test_unknown_outcome_value_returns_unknown(self):
        event = _make_event(source="linux", raw_data={"result": "bizarre_value"})
        assert agent.normalize(event).outcome == EventOutcome.UNKNOWN

    def test_outcome_is_case_insensitive(self):
        event = _make_event(source="linux", raw_data={"result": "SUCCESS"})
        assert agent.normalize(event).outcome == EventOutcome.SUCCESS

    def test_windows_status_override(self):
        event = _make_event(source="windows", raw_data={"Status": "0xC000006D"})
        assert agent.normalize(event).outcome == EventOutcome.FAILURE


# ===========================================================================
# 9. End-to-end: Windows authentication event
# ===========================================================================

class TestWindowsAuthenticationE2E:
    def test_full_windows_auth_event(self):
        event = _make_event(
            source="windows",
            source_type=SourceType.OPERATING_SYSTEM,
            event_type="authentication",
            raw_data={
                "TargetUserName": "alice",
                "TargetDomainName": "CORP",
                "IpAddress": "10.0.0.5",
                "IpPort": 49832,
                "Status": "0x0",
                "EventID": 4624,
                "LogonType": 10,
            },
        )
        result = agent.normalize(event)
        assert result.event_category == EventCategory.AUTHENTICATION
        assert result.actor.username == "alice"
        assert result.actor.domain == "CORP"
        assert result.source_endpoint.ip == "10.0.0.5"
        assert result.source_endpoint.port == 49832
        assert result.outcome == EventOutcome.SUCCESS
        assert result.normalized_data["event_id_raw"] == 4624
        assert result.normalized_data["logon_type"] == 10
        assert result.action is None
        assert result.process is None
        assert result.file is None


# ===========================================================================
# 10. End-to-end: Linux authentication event
# ===========================================================================

class TestLinuxAuthenticationE2E:
    def test_full_linux_auth_event(self):
        event = _make_event(
            source="linux",
            source_type=SourceType.OPERATING_SYSTEM,
            event_type="authentication",
            raw_data={
                "user": "bob",
                "uid": 1001,
                "src_ip": "192.168.1.100",
                "src_port": 22,
                "hostname": "webserver-01",
                "result": "success",
                "action": "login",
            },
        )
        result = agent.normalize(event)
        assert result.event_category == EventCategory.AUTHENTICATION
        assert result.actor.username == "bob"
        assert result.actor.user_id == "1001"
        assert result.source_endpoint.ip == "192.168.1.100"
        assert result.source_endpoint.port == 22
        assert result.source_endpoint.hostname == "webserver-01"
        assert result.outcome == EventOutcome.SUCCESS
        assert result.action == "login"


# ===========================================================================
# 11. End-to-end: Network event
# ===========================================================================

class TestNetworkEventE2E:
    def test_full_network_event(self):
        event = _make_event(
            source="firewall",
            source_type=SourceType.NETWORK,
            event_type="network_connection",
            raw_data={
                "src_ip": "10.0.0.1",
                "src_port": 54321,
                "dst_ip": "10.0.0.2",
                "dst_port": 443,
                "protocol": "tcp",
                "action": "allow",
                "rule": "allow_https",
            },
        )
        result = agent.normalize(event)
        assert result.event_category == EventCategory.NETWORK
        assert result.source_endpoint.ip == "10.0.0.1"
        assert result.source_endpoint.port == 54321
        assert result.source_endpoint.protocol == "tcp"
        assert result.destination_endpoint.ip == "10.0.0.2"
        assert result.destination_endpoint.port == 443
        assert result.outcome == EventOutcome.ALLOWED
        assert result.action == "allowed"
        assert result.normalized_data["rule_name"] == "allow_https"


# ===========================================================================
# 12. End-to-end: Process event
# ===========================================================================

class TestProcessEventE2E:
    def test_full_process_event(self):
        event = _make_event(
            source="linux",
            source_type=SourceType.OPERATING_SYSTEM,
            event_type="process_creation",
            raw_data={
                "process_name": "curl",
                "pid": 4567,
                "command_line": "curl http://example.com",
                "exe": "/usr/bin/curl",
                "parent_process": "bash",
            },
        )
        result = agent.normalize(event)
        assert result.event_category == EventCategory.PROCESS
        assert result.process.name == "curl"
        assert result.process.pid == 4567
        assert result.process.command_line == "curl http://example.com"
        assert result.process.executable == "/usr/bin/curl"
        assert result.process.parent_process == "bash"


# ===========================================================================
# 13. End-to-end: File event
# ===========================================================================

class TestFileEventE2E:
    def test_full_file_event(self):
        event = _make_event(
            source="linux",
            source_type=SourceType.OPERATING_SYSTEM,
            event_type="file_activity",
            raw_data={
                "file_name": "secret.txt",
                "file_path": "/home/alice/secret.txt",
                "extension": ".txt",
                "hash": "abc123def456",
            },
        )
        result = agent.normalize(event)
        assert result.event_category == EventCategory.FILE
        assert result.file.name == "secret.txt"
        assert result.file.path == "/home/alice/secret.txt"
        assert result.file.extension == ".txt"
        assert result.file.hash == "abc123def456"


# ===========================================================================
# 14. Missing optional fields
# ===========================================================================

class TestOptionalFieldsMissing:
    def test_minimal_event_normalizes(self):
        event = _make_event(source="linux", event_type="authentication", raw_data={"user": "alice"})
        result = agent.normalize(event)
        assert result.actor.username == "alice"
        assert result.source_endpoint is None
        assert result.destination_endpoint is None
        assert result.process is None
        assert result.file is None
        assert result.outcome == EventOutcome.UNKNOWN
        assert result.action is None
        assert result.normalized_data == {}

    def test_empty_raw_data(self):
        event = _make_event(source="linux", raw_data={})
        result = agent.normalize(event)
        assert result.actor is None
        assert result.source_endpoint is None
        assert result.destination_endpoint is None
        assert result.process is None
        assert result.file is None
        assert result.outcome == EventOutcome.UNKNOWN
        assert result.action is None


# ===========================================================================
# 15. Unknown category → other
# ===========================================================================

class TestUnknownCategory:
    def test_unrecognized_event_type_maps_to_other(self):
        event = _make_event(event_type="some_weird_event", raw_data={})
        result = agent.normalize(event)
        assert result.event_category == EventCategory.OTHER

    def test_single_char_unknown_event_type_maps_to_other(self):
        event = _make_event(event_type="x", raw_data={})
        result = agent.normalize(event)
        assert result.event_category == EventCategory.OTHER


# ===========================================================================
# 16. Unknown outcome → unknown
# ===========================================================================

class TestUnknownOutcome:
    def test_no_outcome_field_results_in_unknown(self):
        event = _make_event(source="linux", raw_data={"user": "alice"})
        assert agent.normalize(event).outcome == EventOutcome.UNKNOWN


# ===========================================================================
# 17. Unsupported source handled safely
# ===========================================================================

class TestUnsupportedSource:
    def test_unknown_source_does_not_crash(self):
        event = _make_event(
            source="some_unknown_device", event_type="authentication",
            raw_data={"user": "alice"},
        )
        result = agent.normalize(event)
        assert result.source == "some_unknown_device"
        assert result.event_category == EventCategory.AUTHENTICATION

    def test_unsupported_source_actor_is_none(self):
        event = _make_event(source="some_unknown_device", raw_data={"user": "alice"})
        assert agent.normalize(event).actor is None

    def test_unsupported_source_endpoint_is_none(self):
        event = _make_event(source="some_unknown_device", raw_data={"src_ip": "10.0.0.1"})
        assert agent.normalize(event).source_endpoint is None


# ===========================================================================
# 18. Missing IP is NOT reconstructed
# ===========================================================================

class TestMissingIpNotReconstructed:
    def test_no_ip_field_leaves_endpoint_none(self):
        event = _make_event(source="linux", raw_data={"user": "alice"})
        assert agent.normalize(event).source_endpoint is None

    def test_only_port_without_ip_returns_endpoint_with_port_only(self):
        """Port is present but IP is None — we do NOT fabricate an IP."""
        event = _make_event(source="linux", raw_data={"src_port": 22})
        result = agent.normalize(event)
        assert result.source_endpoint is not None
        assert result.source_endpoint.port == 22
        assert result.source_endpoint.ip is None


# ===========================================================================
# 19. Missing username is NOT invented
# ===========================================================================

class TestMissingUsernameNotInvented:
    def test_no_user_field_leaves_actor_none(self):
        event = _make_event(source="linux", raw_data={})
        assert agent.normalize(event).actor is None

    def test_empty_user_value_left_as_none(self):
        event = _make_event(source="linux", raw_data={"user": None})
        assert agent.normalize(event).actor is None


# ===========================================================================
# 20. Event ID preserved
# ===========================================================================

class TestEventIdPreserved:
    def test_event_id_matches_original(self):
        event = _make_event(raw_data={})
        result = agent.normalize(event)
        assert result.event_id == event.event_id

    def test_explicit_event_id_preserved(self):
        explicit_id = uuid.uuid4()
        event = _make_event(raw_data={})
        event.event_id = explicit_id
        result = agent.normalize(event)
        assert result.event_id == explicit_id


# ===========================================================================
# 21. Timestamp preserved
# ===========================================================================

class TestTimestampPreserved:
    def test_timestamp_matches_original(self):
        event = _make_event(raw_data={})
        result = agent.normalize(event)
        assert result.timestamp == event.timestamp

    def test_not_replaced_by_current_time(self):
        event = _make_event(raw_data={})
        result = agent.normalize(event)
        assert result.timestamp == _FIXED_TS


# ===========================================================================
# 22. Source and source_type preserved
# ===========================================================================

class TestSourcePreserved:
    def test_source_matches_original(self):
        event = _make_event(source="windows", raw_data={})
        assert agent.normalize(event).source == "windows"

    def test_source_type_matches_original(self):
        event = _make_event(source_type=SourceType.NETWORK, raw_data={})
        assert agent.normalize(event).source_type == SourceType.NETWORK


# ===========================================================================
# 23. Provenance remains OBSERVED
# ===========================================================================

class TestProvenancePreserved:
    def test_observed_stays_observed(self):
        event = _make_event(provenance=Provenance.OBSERVED, raw_data={})
        assert agent.normalize(event).provenance == Provenance.OBSERVED

    def test_enriched_stays_enriched(self):
        event = _make_event(provenance=Provenance.ENRICHED, raw_data={})
        assert agent.normalize(event).provenance == Provenance.ENRICHED

    def test_reconstructed_stays_reconstructed(self):
        event = _make_event(provenance=Provenance.RECONSTRUCTED, raw_data={})
        assert agent.normalize(event).provenance == Provenance.RECONSTRUCTED


# ===========================================================================
# 24. Raw data remains unchanged
# ===========================================================================

class TestRawDataUnchanged:
    def test_original_event_not_mutated(self):
        raw = {"user": "alice", "src_ip": "10.0.0.1", "event_id": 4624}
        event = _make_event(raw_data=raw)
        _ = agent.normalize(event)
        assert event.raw_data == raw

    def test_raw_data_identity_preserved(self):
        raw = {"user": "bob"}
        event = _make_event(raw_data=raw)
        original_id = id(event.raw_data)
        _ = agent.normalize(event)
        assert id(event.raw_data) == original_id


# ===========================================================================
# 25. Normalized data contains only intended information
# ===========================================================================

class TestNormalizedDataContent:
    def test_windows_only_mapped_extras_present(self):
        event = _make_event(
            source="windows",
            raw_data={
                "EventID": 4624, "LogonType": 10,
                "random_field": "should_not_appear",
                "AnotherIrrelevant": True,
            },
        )
        result = agent.normalize(event)
        assert "event_id_raw" in result.normalized_data
        assert "logon_type" in result.normalized_data
        assert "random_field" not in result.normalized_data
        assert "AnotherIrrelevant" not in result.normalized_data
        assert "EventID" not in result.normalized_data

    def test_linux_no_extras_by_default(self):
        event = _make_event(source="linux", raw_data={"user": "alice"})
        assert agent.normalize(event).normalized_data == {}

    def test_empty_raw_data_produces_empty_normalized_data(self):
        event = _make_event(source="windows", raw_data={})
        assert agent.normalize(event).normalized_data == {}


# ===========================================================================
# 26. Multiple events normalize independently
# ===========================================================================

class TestIndependentNormalization:
    def test_different_sources_dont_interfere(self):
        event_a = _make_event(source="windows", raw_data={"TargetUserName": "alice"})
        event_b = _make_event(source="linux", raw_data={"user": "bob"})
        result_a = agent.normalize(event_a)
        result_b = agent.normalize(event_b)

        assert result_a.actor.username == "alice"
        assert result_b.actor.username == "bob"
        assert result_a.source_endpoint is None
        assert result_b.source_endpoint is None

    def test_consecutive_normalizations_are_independent(self):
        event1 = _make_event(source="linux", raw_data={"user": "first"})
        result1 = agent.normalize(event1)
        event2 = _make_event(source="linux", raw_data={"user": "second"})
        result2 = agent.normalize(event2)

        assert result1.actor.username == "first"
        assert result2.actor.username == "second"


