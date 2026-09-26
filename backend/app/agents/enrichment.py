"""Deterministic EnrichmentAgent for SentinelAI.

Examines fields already present in a NormalizedSecurityEvent and
produces locally-derived contextual enrichments packaged as
EnrichmentResult instances.

This module is purely a deterministic, stateless transformation step.
It is NOT:
  - External threat intelligence (VirusTotal, AbuseIPDB, AlienVault OTX)
  - Geolocation lookup, reputation scoring, synthetic reconstruction
  - AI / LLM processing, detection or correlation

Design principles:
  - Rule-driven: each category is an independently testable EnrichmentRule.
  - No fabrication: missing or unrecognised data is silently skipped.
  - No mutation: the input NormalizedSecurityEvent is never modified.
  - Deterministic: same input always produces the same output.
  - Extensible: new categories are added by registering a new rule.
"""

from __future__ import annotations

import ipaddress
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from app.schemas.enriched_event import (
    EnrichedSecurityEvent,
    EnrichmentResult,
)
from app.schemas.normalized_event import NormalizedSecurityEvent
from app.schemas.security_event import Provenance

logger = logging.getLogger(__name__)

DETERMINISTIC_SOURCE: str = "sentinelai_deterministic_rules"

_WELL_KNOWN_PORTS: dict[int, str] = {
    20: "ftp_data", 21: "ftp", 22: "ssh", 23: "telnet",
    25: "smtp", 53: "dns", 80: "http", 110: "pop3",
    111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1434: "mssql_browser", 1521: "oracle",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5672: "amqp",
    5900: "vnc", 6379: "redis", 8080: "http_alt", 8443: "https_alt",
    27017: "mongodb",
}

_FILE_EXTENSION_MAP: dict[str, str] = {
    ".exe": "executable", ".dll": "library", ".sys": "driver",
    ".com": "executable", ".scr": "screensaver",
    ".bat": "batch_script", ".cmd": "batch_script",
    ".ps1": "powershell_script", ".psm1": "powershell_module",
    ".psd1": "powershell_data",
    ".vbs": "vbscript", ".vbe": "vbscript_encoded",
    ".js": "javascript", ".jar": "java_archive",
    ".py": "python_script", ".pyw": "python_script",
    ".rb": "ruby_script", ".pl": "perl_script", ".php": "php_script",
    ".sh": "shell_script", ".bash": "shell_script",
    ".csh": "shell_script", ".ksh": "shell_script",
    ".zsh": "shell_script",
    ".msi": "installer", ".msp": "installer_patch",
    ".mst": "installer_transform",
    ".doc": "word_document", ".docx": "word_document",
    ".docm": "word_macro_document",
    ".xls": "excel_spreadsheet", ".xlsx": "excel_spreadsheet",
    ".xlsm": "excel_macro_spreadsheet",
    ".ppt": "powerpoint_presentation", ".pptx": "powerpoint_presentation",
    ".pdf": "pdf_document",
    ".txt": "text", ".log": "log_file", ".csv": "csv_data",
    ".xml": "xml_data", ".json": "json_data",
    ".html": "html", ".htm": "html",
    ".zip": "archive", ".rar": "archive", ".7z": "archive",
    ".tar": "archive", ".gz": "archive",
    ".bz2": "archive", ".xz": "archive",
    ".jpg": "image", ".jpeg": "image", ".png": "image",
    ".gif": "image", ".bmp": "image", ".svg": "image",
    ".mp3": "audio", ".wav": "audio",
    ".mp4": "video", ".avi": "video", ".mkv": "video", ".mov": "video",
    ".so": "shared_library", ".dylib": "shared_library",
    ".ko": "kernel_module",
}

_PROCESS_CONTEXT_MAP: dict[str, str] = {
    "powershell.exe": "scripting_interpreter",
    "pwsh.exe": "scripting_interpreter",
    "cmd.exe": "command_shell",
    "sh": "shell", "bash": "shell", "zsh": "shell",
    "csh": "shell", "ksh": "shell", "fish": "shell", "dash": "shell",
    "python": "interpreter", "python3": "interpreter",
    "python.exe": "interpreter", "python3.exe": "interpreter",
    "perl": "interpreter", "perl.exe": "interpreter",
    "ruby": "interpreter", "ruby.exe": "interpreter",
    "java": "interpreter", "java.exe": "interpreter",
    "node": "interpreter", "node.exe": "interpreter",
    "ssh": "remote_access", "ssh.exe": "remote_access",
    "telnet": "remote_access", "telnet.exe": "remote_access",
    "rdesktop": "remote_access", "mstsc.exe": "remote_access",
    "curl": "network_utility", "curl.exe": "network_utility",
    "wget": "network_utility", "wget.exe": "network_utility",
    "ping": "network_utility", "ping.exe": "network_utility",
    "nslookup": "network_utility", "nslookup.exe": "network_utility",
    "net.exe": "network_utility", "net1.exe": "network_utility",
    "ipconfig.exe": "network_utility",
    "whoami.exe": "system_utility", "tasklist.exe": "system_utility",
    "taskkill.exe": "system_utility", "schtasks.exe": "system_utility",
    "reg.exe": "system_utility", "sc.exe": "system_utility",
    "netstat.exe": "system_utility", "attrib.exe": "system_utility",
    "cacls.exe": "system_utility", "icacls.exe": "system_utility",
    "fltmc.exe": "system_utility",
}



class EnrichmentRule(ABC):
    """Base class for deterministic enrichment rules."""

    @abstractmethod
    def applies(self, event: NormalizedSecurityEvent) -> bool:
        """Return True if this rule can produce enrichment for *event*."""

    @abstractmethod
    def enrich(self, event: NormalizedSecurityEvent) -> list[EnrichmentResult]:
        """Produce enrichment results for *event*."""


def _classify_ip(ip_str: str) -> str | None:
    """Return a deterministic classification string for an IP address."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link_local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_unspecified:
        return "unspecified"
    if addr.is_private:
        return "private"
    if addr.is_reserved:
        return "reserved"
    if addr.is_global:
        return "public"
    return "other"


def _build_ip_enrichment(
    ip_str: str, target: str,
) -> EnrichmentResult | None:
    """Build an IP classification EnrichmentResult, or None."""
    classification = _classify_ip(ip_str)
    if classification is None:
        return None
    return EnrichmentResult(
        enrichment_type="ip_classification",
        source=DETERMINISTIC_SOURCE,
        value={"classification": classification, "address": ip_str},
        confidence=None,
        timestamp=datetime.now(timezone.utc),
        metadata={"target": target},
    )


def _build_service_enrichment(
    port: int, protocol: str | None, target: str,
) -> EnrichmentResult | None:
    """Build a service-context EnrichmentResult, or None."""
    if port < 0 or port > 65535:
        return None
    service_name = _WELL_KNOWN_PORTS.get(port)
    if service_name is None:
        return None
    value: dict[str, Any] = {
        "service_name": service_name, "port": port,
    }
    if protocol is not None:
        value["protocol"] = protocol
    return EnrichmentResult(
        enrichment_type="service_context",
        source=DETERMINISTIC_SOURCE,
        value=value,
        confidence=None,
        timestamp=datetime.now(timezone.utc),
        metadata={"target": target},
    )


def _build_file_type_enrichment(
    extension: str, target: str,
) -> EnrichmentResult | None:
    """Build a file-type EnrichmentResult, or None."""
    ext = extension.lower().strip()
    if not ext.startswith("."):
        ext = "." + ext
    file_type = _FILE_EXTENSION_MAP.get(ext)
    if file_type is None:
        return None
    return EnrichmentResult(
        enrichment_type="file_type_context",
        source=DETERMINISTIC_SOURCE,
        value={"file_type": file_type, "extension": ext},
        confidence=None,
        timestamp=datetime.now(timezone.utc),
        metadata={"target": target},
    )


def _build_process_context_enrichment(
    process_name: str, target: str,
) -> EnrichmentResult | None:
    """Build a process-context EnrichmentResult, or None."""
    lookup = process_name.strip().lower()
    context = _PROCESS_CONTEXT_MAP.get(lookup)
    if context is None:
        return None
    return EnrichmentResult(
        enrichment_type="process_context",
        source=DETERMINISTIC_SOURCE,
        value={"context": context, "process_name": process_name},
        confidence=None,
        timestamp=datetime.now(timezone.utc),
        metadata={"target": target},
    )





class IPClassificationRule(EnrichmentRule):
    """Classify source and destination IP addresses."""

    def applies(self, event: NormalizedSecurityEvent) -> bool:
        return (
            (event.source_endpoint is not None
             and event.source_endpoint.ip is not None)
            or (event.destination_endpoint is not None
                and event.destination_endpoint.ip is not None)
        )

    def enrich(
        self, event: NormalizedSecurityEvent,
    ) -> list[EnrichmentResult]:
        results: list[EnrichmentResult] = []
        if (event.source_endpoint is not None
                and event.source_endpoint.ip is not None):
            enr = _build_ip_enrichment(
                event.source_endpoint.ip,
                target="source_endpoint.ip",
            )
            if enr is not None:
                results.append(enr)
        if (event.destination_endpoint is not None
                and event.destination_endpoint.ip is not None):
            enr = _build_ip_enrichment(
                event.destination_endpoint.ip,
                target="destination_endpoint.ip",
            )
            if enr is not None:
                results.append(enr)
        return results


class ServiceContextRule(EnrichmentRule):
    """Map well-known port numbers to service names."""

    def applies(self, event: NormalizedSecurityEvent) -> bool:
        return (
            (event.source_endpoint is not None
             and event.source_endpoint.port is not None)
            or (event.destination_endpoint is not None
                and event.destination_endpoint.port is not None)
        )

    def enrich(
        self, event: NormalizedSecurityEvent,
    ) -> list[EnrichmentResult]:
        results: list[EnrichmentResult] = []
        if (event.source_endpoint is not None
                and event.source_endpoint.port is not None):
            enr = _build_service_enrichment(
                event.source_endpoint.port,
                protocol=event.source_endpoint.protocol,
                target="source_endpoint.port",
            )
            if enr is not None:
                results.append(enr)
        if (event.destination_endpoint is not None
                and event.destination_endpoint.port is not None):
            enr = _build_service_enrichment(
                event.destination_endpoint.port,
                protocol=event.destination_endpoint.protocol,
                target="destination_endpoint.port",
            )
            if enr is not None:
                results.append(enr)
        return results


class FileTypeContextRule(EnrichmentRule):
    """Provide deterministic file-type context from file extensions."""

    def applies(self, event: NormalizedSecurityEvent) -> bool:
        return (
            event.file is not None and event.file.extension is not None
        )

    def enrich(
        self, event: NormalizedSecurityEvent,
    ) -> list[EnrichmentResult]:
        if event.file is None or event.file.extension is None:
            return []
        enr = _build_file_type_enrichment(
            event.file.extension, target="file.extension",
        )
        return [enr] if enr is not None else []


class ProcessContextRule(EnrichmentRule):
    """Provide basic deterministic process context."""

    def applies(self, event: NormalizedSecurityEvent) -> bool:
        return (
            event.process is not None and event.process.name is not None
        )

    def enrich(
        self, event: NormalizedSecurityEvent,
    ) -> list[EnrichmentResult]:
        if event.process is None or event.process.name is None:
            return []
        enr = _build_process_context_enrichment(
            event.process.name, target="process.name",
        )
        return [enr] if enr is not None else []


class EnrichmentAgent:
    """Stateless, deterministic enrichment engine.

    Takes a NormalizedSecurityEvent and produces an EnrichedSecurityEvent
    by running a configurable set of EnrichmentRule instances.
    """

    def __init__(
        self, rules: list[EnrichmentRule] | None = None,
    ) -> None:
        if rules is not None:
            self._rules = list(rules)
        else:
            self._rules = [
                IPClassificationRule(),
                ServiceContextRule(),
                FileTypeContextRule(),
                ProcessContextRule(),
            ]

    def enrich(
        self, event: NormalizedSecurityEvent,
    ) -> EnrichedSecurityEvent:
        """Produce an EnrichedSecurityEvent from *event*."""
        if not isinstance(event, NormalizedSecurityEvent):
            raise TypeError(
                "Expected NormalizedSecurityEvent, "
                f"got {type(event).__name__}"
            )
        enrichments: list[EnrichmentResult] = []
        for rule in self._rules:
            try:
                if rule.applies(event):
                    results = rule.enrich(event)
                    enrichments.extend(results)
            except Exception:
                logger.warning(
                    "Enrichment rule %s failed; skipping",
                    type(rule).__name__,
                    exc_info=True,
                )
        return EnrichedSecurityEvent(
            event_id=event.event_id,
            timestamp=event.timestamp,
            normalized_event=event,
            enrichments=enrichments,
            provenance=Provenance.ENRICHED,
        )


