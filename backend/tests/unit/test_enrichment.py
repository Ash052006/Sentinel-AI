"""Tests for the Deterministic EnrichmentAgent.

Covers IP classification, service context, file type context,
process context, multiple enrichments, provenance, identity,
immutability, resilience, and determinism.

Pure unit tests -- no database, Kafka, or network connections.
"""

import uuid
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

import pytest

from app.agents.enrichment import (
    DETERMINISTIC_SOURCE,
    EnrichmentAgent,
    EnrichmentRule,
    FileTypeContextRule,
    IPClassificationRule,
    ProcessContextRule,
    ServiceContextRule,
    _classify_ip,
)
from app.agents.normalization import NormalizationAgent
from app.schemas.enriched_event import (
    EnrichedSecurityEvent,
    EnrichmentResult,
)
from app.schemas.normalized_event import (
    Endpoint,
    FileInfo,
    NormalizedSecurityEvent,
    ProcessInfo,
)
from app.schemas.security_event import (
    Provenance,
    SecurityEvent,
    SourceType,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FIXED_TS = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
_norm_agent = NormalizationAgent()


def _make_security_event(**overrides: Any) -> SecurityEvent:
    base: dict[str, Any] = {
        "timestamp": _FIXED_TS,
        "source": "windows",
        "source_type": SourceType.OPERATING_SYSTEM,
        "event_type": "authentication",
        "raw_data": {"TargetUserName": "admin", "Status": "0x0"},
        "provenance": Provenance.OBSERVED,
    }
    base.update(overrides)
    return SecurityEvent(**base)


def _make_normalized_event(
    source_endpoint: Endpoint | None = None,
    destination_endpoint: Endpoint | None = None,
    process: ProcessInfo | None = None,
    file: FileInfo | None = None,
    **overrides: Any,
) -> NormalizedSecurityEvent:
    se = _make_security_event()
    ne = _norm_agent.normalize(se)
    data = ne.model_dump()
    data["source_endpoint"] = (
        source_endpoint.model_dump() if source_endpoint else None
    )
    data["destination_endpoint"] = (
        destination_endpoint.model_dump() if destination_endpoint else None
    )
    data["process"] = process.model_dump() if process else None
    data["file"] = file.model_dump() if file else None
    for k, v in overrides.items():
        data[k] = v
    return NormalizedSecurityEvent.model_validate(data)


def _enrichment_type_keys(
    enriched: EnrichedSecurityEvent, etype: str,
) -> list[dict[str, Any]]:
    return [
        e.value for e in enriched.enrichments
        if e.enrichment_type == etype
    ]

# ===========================================================================
# A. Agent basics
# ===========================================================================


class TestAgentBasics:
    def test_valid_event_returns_enriched_event(self):
        ne = _make_normalized_event()
        result = EnrichmentAgent().enrich(ne)
        assert isinstance(result, EnrichedSecurityEvent)

    def test_empty_event_produces_no_enrichments(self):
        ne = _make_normalized_event()
        result = EnrichmentAgent().enrich(ne)
        assert result.enrichments == []

    def test_stateless_behavior(self):
        ne = _make_normalized_event(
            source_endpoint=Endpoint(ip="192.168.1.1", port=443),
        )
        r1 = EnrichmentAgent().enrich(ne)
        r2 = EnrichmentAgent().enrich(ne)
        assert len(r1.enrichments) == len(r2.enrichments)
        for e1, e2 in zip(r1.enrichments, r2.enrichments):
            assert e1.enrichment_type == e2.enrichment_type
            assert e1.value == e2.value

    def test_repeated_calls_consistent(self):
        ne = _make_normalized_event(
            source_endpoint=Endpoint(ip="10.0.0.1", port=22),
        )
        agent = EnrichmentAgent()
        r1 = agent.enrich(ne)
        r2 = agent.enrich(ne)
        for e1, e2 in zip(r1.enrichments, r2.enrichments):
            assert e1.value == e2.value

    def test_rejects_non_normalized_event(self):
        with pytest.raises(TypeError, match="Expected NormalizedSecurityEvent"):
            EnrichmentAgent().enrich("not an event")

    def test_custom_rules(self):
        ne = _make_normalized_event(
            source_endpoint=Endpoint(ip="192.168.1.1"),
        )
        agent = EnrichmentAgent(rules=[IPClassificationRule()])
        result = agent.enrich(ne)
        types = {e.enrichment_type for e in result.enrichments}
        assert types == {"ip_classification"}

    def test_empty_rules_no_enrichments(self):
        ne = _make_normalized_event(
            source_endpoint=Endpoint(ip="192.168.1.1"),
        )
        agent = EnrichmentAgent(rules=[])
        assert agent.enrich(ne).enrichments == []

    def test_agent_independent_instances(self):
        a1 = EnrichmentAgent()
        a2 = EnrichmentAgent()
        assert a1._rules is not a2._rules

# ===========================================================================
# B. IP classification
# ===========================================================================


class TestIPClassification:
    def test_private_ipv4(self):
        ne = _make_normalized_event(source_endpoint=Endpoint(ip="192.168.1.10"))
        result = EnrichmentAgent().enrich(ne)
        vals = _enrichment_type_keys(result, "ip_classification")
        assert len(vals) == 1
        assert vals[0]["classification"] == "private"

    def test_public_ipv4(self):
        ne = _make_normalized_event(source_endpoint=Endpoint(ip="8.8.8.8"))
        result = EnrichmentAgent().enrich(ne)
        vals = _enrichment_type_keys(result, "ip_classification")
        assert vals[0]["classification"] == "public"

    def test_loopback(self):
        ne = _make_normalized_event(source_endpoint=Endpoint(ip="127.0.0.1"))
        result = EnrichmentAgent().enrich(ne)
        vals = _enrichment_type_keys(result, "ip_classification")
        assert vals[0]["classification"] == "loopback"

    def test_loopback_ipv6(self):
        ne = _make_normalized_event(source_endpoint=Endpoint(ip="::1"))
        result = EnrichmentAgent().enrich(ne)
        vals = _enrichment_type_keys(result, "ip_classification")
        assert vals[0]["classification"] == "loopback"

    def test_link_local(self):
        ne = _make_normalized_event(source_endpoint=Endpoint(ip="169.254.1.1"))
        result = EnrichmentAgent().enrich(ne)
        vals = _enrichment_type_keys(result, "ip_classification")
        assert vals[0]["classification"] == "link_local"

    def test_multicast(self):
        ne = _make_normalized_event(source_endpoint=Endpoint(ip="224.0.0.1"))
        result = EnrichmentAgent().enrich(ne)
        vals = _enrichment_type_keys(result, "ip_classification")
        assert vals[0]["classification"] == "multicast"

    def test_unspecified(self):
        ne = _make_normalized_event(source_endpoint=Endpoint(ip="0.0.0.0"))
        result = EnrichmentAgent().enrich(ne)
        vals = _enrichment_type_keys(result, "ip_classification")
        assert vals[0]["classification"] == "unspecified"

    def test_private_10_network(self):
        ne = _make_normalized_event(source_endpoint=Endpoint(ip="10.0.0.1"))
        result = EnrichmentAgent().enrich(ne)
        vals = _enrichment_type_keys(result, "ip_classification")
        assert vals[0]["classification"] == "private"

    def test_ipv6_global(self):
        # Use a real public IPv6 address (Cloudflare DNS)
        ne = _make_normalized_event(source_endpoint=Endpoint(ip="2606:4700:4700::1111"))
        result = EnrichmentAgent().enrich(ne)
        vals = _enrichment_type_keys(result, "ip_classification")
        assert vals[0]["classification"] == "public"

    def test_invalid_ip_skipped(self):
        ne = _make_normalized_event(source_endpoint=Endpoint(ip="not-an-ip"))
        result = EnrichmentAgent().enrich(ne)
        assert _enrichment_type_keys(result, "ip_classification") == []

    def test_both_endpoints(self):
        ne = _make_normalized_event(
            source_endpoint=Endpoint(ip="192.168.1.1"),
            destination_endpoint=Endpoint(ip="8.8.8.8"),
        )
        result = EnrichmentAgent().enrich(ne)
        ip_enr = [
            e for e in result.enrichments
            if e.enrichment_type == "ip_classification"
        ]
        assert len(ip_enr) == 2

    def test_no_endpoint(self):
        ne = _make_normalized_event()
        result = EnrichmentAgent().enrich(ne)
        assert _enrichment_type_keys(result, "ip_classification") == []


class TestClassifyIPUnit:
    def test_private(self):
        assert _classify_ip("192.168.1.1") == "private"
    def test_public(self):
        assert _classify_ip("8.8.8.8") == "public"
    def test_loopback(self):
        assert _classify_ip("127.0.0.1") == "loopback"
    def test_loopback_v6(self):
        assert _classify_ip("::1") == "loopback"
    def test_link_local_v6(self):
        assert _classify_ip("fe80::1") == "link_local"
    def test_multicast(self):
        assert _classify_ip("224.0.0.1") == "multicast"
    def test_unspecified(self):
        assert _classify_ip("0.0.0.0") == "unspecified"
    def test_invalid(self):
        assert _classify_ip("not-an-ip") is None
    def test_empty(self):
        assert _classify_ip("") is None

# ===========================================================================
# C. Service context
# ===========================================================================


class TestServiceContext:
    def test_ssh(self):
        ne = _make_normalized_event(destination_endpoint=Endpoint(port=22))
        result = EnrichmentAgent().enrich(ne)
        svcs = _enrichment_type_keys(result, "service_context")
        assert len(svcs) == 1
        assert svcs[0]["service_name"] == "ssh"

    def test_http(self):
        ne = _make_normalized_event(destination_endpoint=Endpoint(port=80))
        result = EnrichmentAgent().enrich(ne)
        svcs = _enrichment_type_keys(result, "service_context")
        assert svcs[0]["service_name"] == "http"

    def test_https(self):
        ne = _make_normalized_event(destination_endpoint=Endpoint(port=443))
        result = EnrichmentAgent().enrich(ne)
        svcs = _enrichment_type_keys(result, "service_context")
        assert svcs[0]["service_name"] == "https"

    def test_dns(self):
        ne = _make_normalized_event(destination_endpoint=Endpoint(port=53))
        result = EnrichmentAgent().enrich(ne)
        svcs = _enrichment_type_keys(result, "service_context")
        assert svcs[0]["service_name"] == "dns"

    def test_rdp(self):
        ne = _make_normalized_event(destination_endpoint=Endpoint(port=3389))
        result = EnrichmentAgent().enrich(ne)
        svcs = _enrichment_type_keys(result, "service_context")
        assert svcs[0]["service_name"] == "rdp"

    def test_unknown_port_skipped(self):
        ne = _make_normalized_event(destination_endpoint=Endpoint(port=19876))
        result = EnrichmentAgent().enrich(ne)
        assert _enrichment_type_keys(result, "service_context") == []

    def test_invalid_port_negative(self):
        ne = _make_normalized_event(destination_endpoint=Endpoint(port=-1))
        result = EnrichmentAgent().enrich(ne)
        assert _enrichment_type_keys(result, "service_context") == []

    def test_protocol_included(self):
        ne = _make_normalized_event(
            destination_endpoint=Endpoint(port=443, protocol="tcp"),
        )
        result = EnrichmentAgent().enrich(ne)
        svcs = _enrichment_type_keys(result, "service_context")
        assert svcs[0]["protocol"] == "tcp"

    def test_source_port(self):
        ne = _make_normalized_event(source_endpoint=Endpoint(port=5432))
        result = EnrichmentAgent().enrich(ne)
        svcs = _enrichment_type_keys(result, "service_context")
        assert len(svcs) == 1
        assert svcs[0]["service_name"] == "postgresql"


# ===========================================================================
# D. File context
# ===========================================================================


class TestFileTypeContext:
    def test_exe(self):
        ne = _make_normalized_event(file=FileInfo(extension=".exe"))
        result = EnrichmentAgent().enrich(ne)
        ft = _enrichment_type_keys(result, "file_type_context")
        assert len(ft) == 1
        assert ft[0]["file_type"] == "executable"

    def test_dll(self):
        ne = _make_normalized_event(file=FileInfo(extension=".dll"))
        result = EnrichmentAgent().enrich(ne)
        ft = _enrichment_type_keys(result, "file_type_context")
        assert ft[0]["file_type"] == "library"

    def test_ps1(self):
        ne = _make_normalized_event(file=FileInfo(extension=".ps1"))
        result = EnrichmentAgent().enrich(ne)
        ft = _enrichment_type_keys(result, "file_type_context")
        assert ft[0]["file_type"] == "powershell_script"

    def test_sh(self):
        ne = _make_normalized_event(file=FileInfo(extension=".sh"))
        result = EnrichmentAgent().enrich(ne)
        ft = _enrichment_type_keys(result, "file_type_context")
        assert ft[0]["file_type"] == "shell_script"

    def test_py(self):
        ne = _make_normalized_event(file=FileInfo(extension=".py"))
        result = EnrichmentAgent().enrich(ne)
        ft = _enrichment_type_keys(result, "file_type_context")
        assert ft[0]["file_type"] == "python_script"

    def test_txt(self):
        ne = _make_normalized_event(file=FileInfo(extension=".txt"))
        result = EnrichmentAgent().enrich(ne)
        ft = _enrichment_type_keys(result, "file_type_context")
        assert ft[0]["file_type"] == "text"

    def test_log(self):
        ne = _make_normalized_event(file=FileInfo(extension=".log"))
        result = EnrichmentAgent().enrich(ne)
        ft = _enrichment_type_keys(result, "file_type_context")
        assert ft[0]["file_type"] == "log_file"

    def test_unknown_extension_skipped(self):
        ne = _make_normalized_event(file=FileInfo(extension=".xyzzy"))
        result = EnrichmentAgent().enrich(ne)
        assert _enrichment_type_keys(result, "file_type_context") == []

    def test_no_extension(self):
        ne = _make_normalized_event(file=FileInfo())
        result = EnrichmentAgent().enrich(ne)
        assert _enrichment_type_keys(result, "file_type_context") == []

    def test_extension_without_dot(self):
        ne = _make_normalized_event(file=FileInfo(extension="exe"))
        result = EnrichmentAgent().enrich(ne)
        ft = _enrichment_type_keys(result, "file_type_context")
        assert len(ft) == 1
        assert ft[0]["file_type"] == "executable"

# ===========================================================================
# E. Process context
# ===========================================================================


class TestProcessContext:
    def test_powershell(self):
        ne = _make_normalized_event(process=ProcessInfo(name="powershell.exe"))
        result = EnrichmentAgent().enrich(ne)
        pc = _enrichment_type_keys(result, "process_context")
        assert len(pc) == 1
        assert pc[0]["context"] == "scripting_interpreter"

    def test_cmd(self):
        ne = _make_normalized_event(process=ProcessInfo(name="cmd.exe"))
        result = EnrichmentAgent().enrich(ne)
        pc = _enrichment_type_keys(result, "process_context")
        assert pc[0]["context"] == "command_shell"

    def test_bash(self):
        ne = _make_normalized_event(process=ProcessInfo(name="bash"))
        result = EnrichmentAgent().enrich(ne)
        pc = _enrichment_type_keys(result, "process_context")
        assert pc[0]["context"] == "shell"

    def test_python(self):
        ne = _make_normalized_event(process=ProcessInfo(name="python"))
        result = EnrichmentAgent().enrich(ne)
        pc = _enrichment_type_keys(result, "process_context")
        assert pc[0]["context"] == "interpreter"

    def test_ssh(self):
        ne = _make_normalized_event(process=ProcessInfo(name="ssh"))
        result = EnrichmentAgent().enrich(ne)
        pc = _enrichment_type_keys(result, "process_context")
        assert pc[0]["context"] == "remote_access"

    def test_unknown_process_skipped(self):
        ne = _make_normalized_event(process=ProcessInfo(name="random_process"))
        result = EnrichmentAgent().enrich(ne)
        assert _enrichment_type_keys(result, "process_context") == []

    def test_no_process(self):
        ne = _make_normalized_event()
        result = EnrichmentAgent().enrich(ne)
        assert _enrichment_type_keys(result, "process_context") == []


# ===========================================================================
# F. Multiple enrichments
# ===========================================================================


class TestMultipleEnrichments:
    def test_several_enrichments(self):
        ne = _make_normalized_event(
            source_endpoint=Endpoint(ip="192.168.1.1", port=22),
            destination_endpoint=Endpoint(ip="8.8.8.8", port=443),
            process=ProcessInfo(name="ssh"),
            file=FileInfo(extension=".exe"),
        )
        result = EnrichmentAgent().enrich(ne)
        types = {e.enrichment_type for e in result.enrichments}
        assert "ip_classification" in types
        assert "service_context" in types
        assert "process_context" in types
        assert "file_type_context" in types

    def test_independent_ids(self):
        ne = _make_normalized_event(
            source_endpoint=Endpoint(ip="10.0.0.1", port=22),
            destination_endpoint=Endpoint(ip="192.168.1.1", port=443),
        )
        result = EnrichmentAgent().enrich(ne)
        ids = {e.enrichment_id for e in result.enrichments}
        assert len(ids) == len(result.enrichments)


# ===========================================================================
# G. Provenance
# ===========================================================================


class TestProvenance:
    def test_enriched_event_provenance(self):
        ne = _make_normalized_event(source_endpoint=Endpoint(ip="192.168.1.1"))
        result = EnrichmentAgent().enrich(ne)
        assert result.provenance == Provenance.ENRICHED

    def test_original_provenance_unchanged(self):
        ne = _make_normalized_event(source_endpoint=Endpoint(ip="192.168.1.1"))
        assert ne.provenance == Provenance.OBSERVED
        _ = EnrichmentAgent().enrich(ne)
        assert ne.provenance == Provenance.OBSERVED

    def test_source_is_deterministic(self):
        ne = _make_normalized_event(source_endpoint=Endpoint(ip="192.168.1.1"))
        result = EnrichmentAgent().enrich(ne)
        for e in result.enrichments:
            assert e.source == DETERMINISTIC_SOURCE

    def test_not_reconstructed(self):
        ne = _make_normalized_event(source_endpoint=Endpoint(ip="192.168.1.1"))
        result = EnrichmentAgent().enrich(ne)
        assert result.provenance != Provenance.RECONSTRUCTED


# ===========================================================================
# H. Identity
# ===========================================================================


class TestIdentity:
    def test_event_id_preserved(self):
        ne = _make_normalized_event(source_endpoint=Endpoint(ip="192.168.1.1"))
        result = EnrichmentAgent().enrich(ne)
        assert result.event_id == ne.event_id

    def test_timestamp_preserved(self):
        ne = _make_normalized_event(source_endpoint=Endpoint(ip="192.168.1.1"))
        result = EnrichmentAgent().enrich(ne)
        assert result.timestamp == ne.timestamp

    def test_enrichment_ids_unique(self):
        ne = _make_normalized_event(
            source_endpoint=Endpoint(ip="10.0.0.1", port=22),
            destination_endpoint=Endpoint(ip="192.168.1.1", port=443),
        )
        result = EnrichmentAgent().enrich(ne)
        ids = [e.enrichment_id for e in result.enrichments]
        assert len(ids) == len(set(ids))

# ===========================================================================
# I. Immutability
# ===========================================================================


class TestImmutability:
    def test_input_event_unchanged(self):
        ne = _make_normalized_event(
            source_endpoint=Endpoint(ip="192.168.1.1", port=443),
            process=ProcessInfo(name="bash"),
            file=FileInfo(extension=".exe"),
        )
        original_dict = ne.model_dump()
        _ = EnrichmentAgent().enrich(ne)
        assert ne.model_dump() == original_dict

    def test_endpoint_values_unchanged(self):
        ep = Endpoint(ip="192.168.1.10", port=22, hostname="test.local")
        ne = _make_normalized_event(source_endpoint=ep)
        _ = EnrichmentAgent().enrich(ne)
        assert ne.source_endpoint.ip == "192.168.1.10"
        assert ne.source_endpoint.port == 22
        assert ne.source_endpoint.hostname == "test.local"

    def test_process_values_unchanged(self):
        proc = ProcessInfo(name="powershell.exe", pid=1234)
        ne = _make_normalized_event(process=proc)
        _ = EnrichmentAgent().enrich(ne)
        assert ne.process.name == "powershell.exe"
        assert ne.process.pid == 1234

    def test_file_values_unchanged(self):
        fi = FileInfo(extension=".ps1", name="script.ps1")
        ne = _make_normalized_event(file=fi)
        _ = EnrichmentAgent().enrich(ne)
        assert ne.file.extension == ".ps1"
        assert ne.file.name == "script.ps1"

    def test_normalized_data_unchanged(self):
        ne = _make_normalized_event(normalized_data={"key": "val"})
        _ = EnrichmentAgent().enrich(ne)
        assert ne.normalized_data == {"key": "val"}


# ===========================================================================
# J. Resilience
# ===========================================================================


class TestResilience:
    def test_malformed_ip(self):
        ne = _make_normalized_event(source_endpoint=Endpoint(ip="not-an-ip"))
        result = EnrichmentAgent().enrich(ne)
        assert isinstance(result, EnrichedSecurityEvent)

    def test_malformed_port(self):
        ne = _make_normalized_event(destination_endpoint=Endpoint(port=-1))
        result = EnrichmentAgent().enrich(ne)
        assert isinstance(result, EnrichedSecurityEvent)

    def test_large_port(self):
        ne = _make_normalized_event(destination_endpoint=Endpoint(port=99999))
        result = EnrichmentAgent().enrich(ne)
        assert isinstance(result, EnrichedSecurityEvent)

    def test_none_optional_fields(self):
        ne = _make_normalized_event(
            source_endpoint=Endpoint(), destination_endpoint=Endpoint(),
        )
        result = EnrichmentAgent().enrich(ne)
        assert result.enrichments == []

    def test_unknown_extension_safe(self):
        ne = _make_normalized_event(file=FileInfo(extension=".xyzzy"))
        result = EnrichmentAgent().enrich(ne)
        assert isinstance(result, EnrichedSecurityEvent)

    def test_unknown_process_safe(self):
        ne = _make_normalized_event(process=ProcessInfo(name="unknown_bin"))
        result = EnrichmentAgent().enrich(ne)
        assert isinstance(result, EnrichedSecurityEvent)

# ===========================================================================
# K. Determinism
# ===========================================================================


class TestDeterminism:
    def test_same_input_same_output(self):
        ne = _make_normalized_event(
            source_endpoint=Endpoint(ip="192.168.1.1", port=443),
            destination_endpoint=Endpoint(ip="10.0.0.1", port=22),
            process=ProcessInfo(name="bash"),
            file=FileInfo(extension=".exe"),
        )
        agent = EnrichmentAgent()
        r1 = agent.enrich(ne)
        r2 = agent.enrich(ne)
        r3 = agent.enrich(ne)
        t1 = [e.enrichment_type for e in r1.enrichments]
        t2 = [e.enrichment_type for e in r2.enrichments]
        t3 = [e.enrichment_type for e in r3.enrichments]
        assert t1 == t2 == t3
        for e1, e2, e3 in zip(r1.enrichments, r2.enrichments, r3.enrichments):
            assert e1.value == e2.value == e3.value
            assert e1.source == e2.source == e3.source


# ===========================================================================
# L. Rule base class
# ===========================================================================


class TestEnrichmentRuleBase:
    def test_ip_rule_applies(self):
        rule = IPClassificationRule()
        ne = _make_normalized_event(source_endpoint=Endpoint(ip="10.0.0.1"))
        assert rule.applies(ne) is True

    def test_ip_rule_not_applies(self):
        ne = _make_normalized_event()
        assert IPClassificationRule().applies(ne) is False

    def test_service_rule_applies(self):
        ne = _make_normalized_event(destination_endpoint=Endpoint(port=443))
        assert ServiceContextRule().applies(ne) is True

    def test_service_rule_not_applies(self):
        ne = _make_normalized_event()
        assert ServiceContextRule().applies(ne) is False

    def test_file_rule_applies(self):
        ne = _make_normalized_event(file=FileInfo(extension=".exe"))
        assert FileTypeContextRule().applies(ne) is True

    def test_file_rule_not_applies(self):
        ne = _make_normalized_event()
        assert FileTypeContextRule().applies(ne) is False

    def test_process_rule_applies(self):
        ne = _make_normalized_event(process=ProcessInfo(name="bash"))
        assert ProcessContextRule().applies(ne) is True

    def test_process_rule_not_applies(self):
        ne = _make_normalized_event()
        assert ProcessContextRule().applies(ne) is False

    def test_rule_abstract(self):
        with pytest.raises(TypeError):
            EnrichmentRule()
