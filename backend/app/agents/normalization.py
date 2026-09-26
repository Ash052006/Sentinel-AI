"""Deterministic NormalizationAgent for SentinelAI.

Converts a validated :class:`SecurityEvent` into a
:class:`NormalizedSecurityEvent` using explicit, deterministic
field mapping rules.

This module is purely a **transformation** step.  It is NOT:

* enrichment
* synthetic reconstruction
* threat intelligence
* detection
* AI / LLM processing

Design principles:

* **Mapping-driven** — each source type declares which ``raw_data``
  keys map to which normalized fields via :class:`SourceMapping`.
* **No fabrication** — missing data is left as ``None`` / absent.
* **No mutation** — the input ``SecurityEvent`` is never modified.
* **Testable** — each mapping can be verified independently.
* **Extensible** — new source types are added by registering a new
  :class:`SourceMapping` without changing the agent logic.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from app.schemas.normalized_event import (
    Actor,
    Endpoint,
    EventCategory,
    EventOutcome,
    FileInfo,
    NormalizedSecurityEvent,
    ProcessInfo,
)
from app.schemas.security_event import Provenance, SecurityEvent, SourceType

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Default category classification
# ---------------------------------------------------------------------------

_DEFAULT_CATEGORY_MAP: dict[str, EventCategory] = {
    "authentication": EventCategory.AUTHENTICATION,
    "logon": EventCategory.AUTHENTICATION,
    "login": EventCategory.AUTHENTICATION,
    "logoff": EventCategory.AUTHENTICATION,
    "logout": EventCategory.AUTHENTICATION,
    "process_creation": EventCategory.PROCESS,
    "process_start": EventCategory.PROCESS,
    "process_termination": EventCategory.PROCESS,
    "network_connection": EventCategory.NETWORK,
    "network": EventCategory.NETWORK,
    "firewall": EventCategory.NETWORK,
    "file_activity": EventCategory.FILE,
    "file_create": EventCategory.FILE,
    "file_delete": EventCategory.FILE,
    "file_modify": EventCategory.FILE,
    "file_access": EventCategory.FILE,
    "file": EventCategory.FILE,
    "system": EventCategory.SYSTEM,
    "system_startup": EventCategory.SYSTEM,
    "system_shutdown": EventCategory.SYSTEM,
    "application": EventCategory.APPLICATION,
}


# ---------------------------------------------------------------------------
# Default outcome resolution (common synonyms)
# ---------------------------------------------------------------------------

_DEFAULT_OUTCOME_MAP: dict[str, EventOutcome] = {
    "success": EventOutcome.SUCCESS,
    "successful": EventOutcome.SUCCESS,
    "0": EventOutcome.SUCCESS,
    "0x0": EventOutcome.SUCCESS,
    "failure": EventOutcome.FAILURE,
    "failed": EventOutcome.FAILURE,
    "error": EventOutcome.FAILURE,
    "1": EventOutcome.FAILURE,
    "allowed": EventOutcome.ALLOWED,
    "permit": EventOutcome.ALLOWED,
    "allow": EventOutcome.ALLOWED,
    "denied": EventOutcome.DENIED,
    "deny": EventOutcome.DENIED,
    "block": EventOutcome.DENIED,
    "blocked": EventOutcome.DENIED,
}


# ---------------------------------------------------------------------------
# Field mapping primitive
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FieldMapping:
    """Maps one or more raw_data candidate keys to a single normalized concept.

    Extracts the first non-``None`` value found among the candidate keys.
    If no candidates match, returns ``None``.
    """

    candidates: tuple[str, ...] = ()

    def extract(self, raw_data: dict[str, Any]) -> Any:
        """Return the first matching value from *raw_data*, or ``None``."""
        for key in self.candidates:
            value = raw_data.get(key)
            if value is not None:
                return value
        return None

    def extract_str(self, raw_data: dict[str, Any]) -> str | None:
        """Extract and coerce to ``str``.  Returns ``None`` if absent."""
        value = self.extract(raw_data)
        return str(value) if value is not None else None

    def extract_int(self, raw_data: dict[str, Any]) -> int | None:
        """Extract and coerce to ``int``.

        Returns ``None`` if absent or not convertible to ``int``.
        """
        value = self.extract(raw_data)
        if value is not None:
            try:
                return int(value)
            except (ValueError, TypeError):
                return None
        return None


# ---------------------------------------------------------------------------
# Source-specific mapping definitions
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SourceMapping:
    """Complete deterministic mapping rules for a log source.

    Each ``FieldMapping`` attribute defines which ``raw_data`` keys map to
    a specific normalized concept.  Only explicitly listed fields are mapped
    — unmapped ``raw_data`` fields are silently ignored.
    """

    # -- Actor ---------------------------------------------------------------
    actor_username: FieldMapping = FieldMapping()
    actor_user_id: FieldMapping = FieldMapping()
    actor_domain: FieldMapping = FieldMapping()

    # -- Source endpoint -----------------------------------------------------
    src_ip: FieldMapping = FieldMapping()
    src_port: FieldMapping = FieldMapping()
    src_hostname: FieldMapping = FieldMapping()
    src_protocol: FieldMapping = FieldMapping()

    # -- Destination endpoint ------------------------------------------------
    dst_ip: FieldMapping = FieldMapping()
    dst_port: FieldMapping = FieldMapping()
    dst_protocol: FieldMapping = FieldMapping()

    # -- Process -------------------------------------------------------------
    process_name: FieldMapping = FieldMapping()
    process_pid: FieldMapping = FieldMapping()
    process_command_line: FieldMapping = FieldMapping()
    process_executable: FieldMapping = FieldMapping()
    process_parent: FieldMapping = FieldMapping()

    # -- File ----------------------------------------------------------------
    file_name: FieldMapping = FieldMapping()
    file_path: FieldMapping = FieldMapping()
    file_extension: FieldMapping = FieldMapping()
    file_hash: FieldMapping = FieldMapping()

    # -- Category classification ---------------------------------------------
    category_hints: dict[str, EventCategory] = field(default_factory=dict)

    # -- Action ---------------------------------------------------------------
    action_fields: FieldMapping = FieldMapping()
    action_value_map: dict[str, str] = field(default_factory=dict)

    # -- Outcome --------------------------------------------------------------
    outcome_fields: FieldMapping = FieldMapping()
    outcome_value_map: dict[str, EventOutcome] = field(default_factory=dict)

    # -- Extra normalized_data fields -----------------------------------------
    extra_fields: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Predefined source mappings
# ---------------------------------------------------------------------------

WINDOWS_MAPPING = SourceMapping(
    actor_username=FieldMapping(candidates=(
        "TargetUserName", "SubjectUserName", "AccountName",
    )),
    actor_user_id=FieldMapping(candidates=(
        "TargetUserSid", "SubjectUserSid",
    )),
    actor_domain=FieldMapping(candidates=(
        "TargetDomainName", "SubjectDomainName",
    )),
    src_ip=FieldMapping(candidates=("IpAddress",)),
    src_port=FieldMapping(candidates=("IpPort",)),
    src_hostname=FieldMapping(candidates=(
        "WorkstationName", "ComputerName",
    )),
    src_protocol=FieldMapping(candidates=("Protocol",)),
    process_name=FieldMapping(candidates=(
        "NewProcessName", "ProcessName",
    )),
    process_pid=FieldMapping(candidates=(
        "NewProcessId", "ProcessId",
    )),
    process_command_line=FieldMapping(candidates=("CommandLine",)),
    process_executable=FieldMapping(candidates=(
        "NewProcessName", "ProcessName",
    )),
    process_parent=FieldMapping(candidates=("ParentProcessName",)),
    file_name=FieldMapping(candidates=("FileName", "ObjectName")),
    file_path=FieldMapping(candidates=("ObjectFileName",)),
    file_extension=FieldMapping(candidates=("ObjectType",)),
    file_hash=FieldMapping(candidates=("Hash",)),
    outcome_fields=FieldMapping(candidates=("Status", "Result")),
    outcome_value_map={
        "0x0": EventOutcome.SUCCESS,
        "0": EventOutcome.SUCCESS,
        "success": EventOutcome.SUCCESS,
        "0xc000006d": EventOutcome.FAILURE,
        "0xc000006a": EventOutcome.FAILURE,
    },
    extra_fields={
        "EventID": "event_id_raw",
        "LogonType": "logon_type",
    },
)

LINUX_MAPPING = SourceMapping(
    actor_username=FieldMapping(candidates=(
        "user", "username", "account_name",
    )),
    actor_user_id=FieldMapping(candidates=("uid",)),
    actor_domain=FieldMapping(candidates=("domain",)),
    src_ip=FieldMapping(candidates=(
        "src_ip", "source_ip", "client_ip",
    )),
    src_port=FieldMapping(candidates=("src_port", "source_port")),
    src_hostname=FieldMapping(candidates=("hostname",)),
    src_protocol=FieldMapping(candidates=("protocol",)),
    dst_ip=FieldMapping(candidates=(
        "dst_ip", "dest_ip", "destination_ip",
    )),
    dst_port=FieldMapping(candidates=("dst_port", "dest_port")),
    dst_protocol=FieldMapping(candidates=("protocol",)),
    process_name=FieldMapping(candidates=(
        "process_name", "process", "comm",
    )),
    process_pid=FieldMapping(candidates=("pid", "process_id")),
    process_command_line=FieldMapping(candidates=("cmdline", "command_line")),
    process_executable=FieldMapping(candidates=("exe", "executable")),
    process_parent=FieldMapping(candidates=(
        "parent_process", "parent_comm",
    )),
    file_name=FieldMapping(candidates=("file_name", "filename")),
    file_path=FieldMapping(candidates=("file_path", "path")),
    file_extension=FieldMapping(candidates=("extension",)),
    file_hash=FieldMapping(candidates=("hash", "file_hash", "sha256")),
    action_fields=FieldMapping(candidates=("action", "action_type")),
    outcome_fields=FieldMapping(candidates=("result", "status")),
    outcome_value_map={
        "success": EventOutcome.SUCCESS,
        "failed": EventOutcome.FAILURE,
        "failure": EventOutcome.FAILURE,
        "error": EventOutcome.FAILURE,
        "denied": EventOutcome.DENIED,
        "allowed": EventOutcome.ALLOWED,
    },
)

FIREWALL_MAPPING = SourceMapping(
    src_ip=FieldMapping(candidates=("src_ip", "source_ip")),
    src_port=FieldMapping(candidates=("src_port", "source_port")),
    src_protocol=FieldMapping(candidates=("protocol",)),
    dst_ip=FieldMapping(candidates=(
        "dst_ip", "dest_ip", "destination_ip",
    )),
    dst_port=FieldMapping(candidates=(
        "dst_port", "dest_port", "destination_port",
    )),
    dst_protocol=FieldMapping(candidates=("protocol",)),
    category_hints={
        "firewall": EventCategory.NETWORK,
        "network_connection": EventCategory.NETWORK,
    },
    action_fields=FieldMapping(candidates=("action", "disposition")),
    action_value_map={
        "allow": "allowed",
        "allowed": "allowed",
        "permit": "allowed",
        "deny": "denied",
        "denied": "denied",
        "block": "denied",
        "blocked": "denied",
    },
    outcome_fields=FieldMapping(candidates=("action", "disposition")),
    outcome_value_map={
        "allow": EventOutcome.ALLOWED,
        "allowed": EventOutcome.ALLOWED,
        "permit": EventOutcome.ALLOWED,
        "deny": EventOutcome.DENIED,
        "denied": EventOutcome.DENIED,
        "block": EventOutcome.DENIED,
        "blocked": EventOutcome.DENIED,
    },
    extra_fields={
        "rule": "rule_name",
        "bytes_sent": "bytes_sent",
        "bytes_received": "bytes_received",
    },
)


# ---------------------------------------------------------------------------
# Source mapping registry
# ---------------------------------------------------------------------------

_SOURCE_MAPPINGS: dict[str, SourceMapping] = {
    "windows": WINDOWS_MAPPING,
    "linux": LINUX_MAPPING,
    "firewall": FIREWALL_MAPPING,
}


# ---------------------------------------------------------------------------
# Normalization agent
# ---------------------------------------------------------------------------

class NormalizationAgent:
    """Converts a :class:`SecurityEvent` into a
    :class:`NormalizedSecurityEvent` using deterministic field-mapping rules.

    The agent is **stateless** and safe to use concurrently.  All
    source-specific mapping logic lives in :class:`SourceMapping`
    definitions registered in ``_SOURCE_MAPPINGS``.
    """

    @staticmethod
    def get_mapping(source: str, source_type: SourceType) -> SourceMapping:
        """Return the mapping rules for *source*.

        Lookup: exact match → longest-prefix match → empty mapping.
        """
        source_lower = source.lower()

        exact = _SOURCE_MAPPINGS.get(source_lower)
        if exact is not None:
            return exact

        for key in sorted(_SOURCE_MAPPINGS, key=len, reverse=True):
            if source_lower.startswith(key):
                return _SOURCE_MAPPINGS[key]

        logger.debug("No source-specific mapping for source=%s", source)
        return SourceMapping()

    def normalize(self, event: SecurityEvent) -> NormalizedSecurityEvent:
        """Transform a :class:`SecurityEvent` into a
        :class:`NormalizedSecurityEvent`.

        The original *event* is never mutated.
        """
        logger.info(
            "Normalization started: source=%s source_type=%s",
            event.source,
            event.source_type.value,
        )

        mapping = self.get_mapping(event.source, event.source_type)
        raw = event.raw_data

        actor = self._build_actor(raw, mapping)
        src_endpoint = self._build_source_endpoint(raw, mapping)
        dst_endpoint = self._build_destination_endpoint(raw, mapping)
        process_info = self._build_process(raw, mapping)
        file_info = self._build_file(raw, mapping)
        category = self._classify_category(event.event_type, mapping)
        action = self._map_action(raw, mapping)
        outcome = self._map_outcome(raw, mapping)
        normalized_data = self._build_normalized_data(raw, mapping)

        result = NormalizedSecurityEvent(
            event_id=event.event_id,
            timestamp=event.timestamp,
            event_category=category,
            action=action,
            outcome=outcome,
            source=event.source,
            source_type=event.source_type,
            actor=actor,
            source_endpoint=src_endpoint,
            destination_endpoint=dst_endpoint,
            process=process_info,
            file=file_info,
            normalized_data=normalized_data,
            provenance=event.provenance,
        )

        logger.info(
            "Normalization completed: source=%s category=%s outcome=%s",
            event.source,
            category.value,
            outcome.value,
        )

        return result

    # -- Private: entity builders --------------------------------------------

    def _build_actor(
        self, raw: dict[str, Any], mapping: SourceMapping,
    ) -> Actor | None:
        """Build an :class:`Actor` from *raw* data, or ``None`` if absent."""
        username = mapping.actor_username.extract_str(raw)
        user_id = mapping.actor_user_id.extract_str(raw)
        domain = mapping.actor_domain.extract_str(raw)

        if username is None and user_id is None and domain is None:
            return None

        return Actor(username=username, user_id=user_id, domain=domain)

    def _build_source_endpoint(
        self, raw: dict[str, Any], mapping: SourceMapping,
    ) -> Endpoint | None:
        """Build the source :class:`Endpoint` from *raw* data."""
        return self._build_endpoint(
            raw, mapping.src_ip, mapping.src_port,
            mapping.src_hostname, mapping.src_protocol,
        )

    def _build_destination_endpoint(
        self, raw: dict[str, Any], mapping: SourceMapping,
    ) -> Endpoint | None:
        """Build the destination :class:`Endpoint` from *raw* data."""
        return self._build_endpoint(
            raw, mapping.dst_ip, mapping.dst_port,
            FieldMapping(), mapping.dst_protocol,
        )

    @staticmethod
    def _build_endpoint(
        raw: dict[str, Any],
        ip_fm: FieldMapping,
        port_fm: FieldMapping,
        hostname_fm: FieldMapping,
        protocol_fm: FieldMapping,
    ) -> Endpoint | None:
        """Build an :class:`Endpoint`, returning ``None`` if all absent."""
        ip = ip_fm.extract_str(raw)
        port = port_fm.extract_int(raw)
        hostname = hostname_fm.extract_str(raw)
        protocol = protocol_fm.extract_str(raw)

        if ip is None and port is None and hostname is None and protocol is None:
            return None

        return Endpoint(ip=ip, port=port, hostname=hostname, protocol=protocol)

    def _build_process(
        self, raw: dict[str, Any], mapping: SourceMapping,
    ) -> ProcessInfo | None:
        """Build :class:`ProcessInfo`, or ``None`` if absent."""
        name = mapping.process_name.extract_str(raw)
        pid = mapping.process_pid.extract_int(raw)
        command_line = mapping.process_command_line.extract_str(raw)
        executable = mapping.process_executable.extract_str(raw)
        parent = mapping.process_parent.extract_str(raw)

        if all(v is None for v in (name, pid, command_line, executable, parent)):
            return None

        return ProcessInfo(
            name=name, pid=pid, command_line=command_line,
            executable=executable, parent_process=parent,
        )

    def _build_file(
        self, raw: dict[str, Any], mapping: SourceMapping,
    ) -> FileInfo | None:
        """Build :class:`FileInfo`, or ``None`` if absent."""
        name = mapping.file_name.extract_str(raw)
        path = mapping.file_path.extract_str(raw)
        extension = mapping.file_extension.extract_str(raw)
        file_hash = mapping.file_hash.extract_str(raw)

        if all(v is None for v in (name, path, extension, file_hash)):
            return None

        return FileInfo(name=name, path=path, extension=extension, hash=file_hash)

    # -- Private: scalar mappers ---------------------------------------------

    def _classify_category(
        self, event_type: str, mapping: SourceMapping,
    ) -> EventCategory:
        """Determine :class:`EventCategory` from *event_type*."""
        if event_type in mapping.category_hints:
            return mapping.category_hints[event_type]
        if event_type in _DEFAULT_CATEGORY_MAP:
            return _DEFAULT_CATEGORY_MAP[event_type]
        if event_type.lower() in _DEFAULT_CATEGORY_MAP:
            return _DEFAULT_CATEGORY_MAP[event_type.lower()]
        return EventCategory.OTHER

    def _map_action(
        self, raw: dict[str, Any], mapping: SourceMapping,
    ) -> str | None:
        """Extract and normalise the action from *raw* data."""
        raw_action = mapping.action_fields.extract_str(raw)
        if raw_action is None:
            return None
        if mapping.action_value_map:
            mapped = mapping.action_value_map.get(raw_action.lower())
            if mapped is not None:
                return mapped
        return raw_action

    def _map_outcome(
        self, raw: dict[str, Any], mapping: SourceMapping,
    ) -> EventOutcome:
        """Determine :class:`EventOutcome` from *raw* data."""
        raw_outcome = mapping.outcome_fields.extract_str(raw)
        if raw_outcome is None:
            return EventOutcome.UNKNOWN
        raw_lower = raw_outcome.lower().strip()
        if mapping.outcome_value_map:
            mapped = mapping.outcome_value_map.get(raw_lower)
            if mapped is not None:
                return mapped
        mapped = _DEFAULT_OUTCOME_MAP.get(raw_lower)
        if mapped is not None:
            return mapped
        return EventOutcome.UNKNOWN

    # -- Private: extra data -------------------------------------------------

    def _build_normalized_data(
        self, raw: dict[str, Any], mapping: SourceMapping,
    ) -> dict[str, Any]:
        """Collect explicitly mapped extra fields into ``normalized_data``."""
        result: dict[str, Any] = {}
        for raw_key, norm_key in mapping.extra_fields.items():
            value = raw.get(raw_key)
            if value is not None:
                result[norm_key] = value
        return result
