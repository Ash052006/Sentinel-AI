"""Tests for Threat Intelligence private/reserved indicator protection.

Verifies:
* Centralized IP classification using Python's ``ipaddress`` module.
* Protection against external provider dispatch for private, loopback,
  link-local, multicast, unspecified, reserved, and non-globally-routable IPs.
* Non-IP indicators (domains, URLs, file hashes) are not subject to IP rules.
* Public IPv4 and IPv6 continue through normal provider lookups.
* Mixed batches correctly skip only non-public IPs.
* All three provider integrations (VirusTotal, AbuseIPDB, AlienVault OTX)
  are protected without separate per-client filters.
* Persistence preserves indicators while maintaining skipped-status ("no_lookup")
  semantics without fabricating results or marking indicators as malicious/benign.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.sqlite.base import SQLiteTypeCompiler
from sqlalchemy.orm import Session, sessionmaker

# Enable PostgreSQL JSONB columns on SQLite for unit tests
if not hasattr(SQLiteTypeCompiler, 'visit_JSONB'):
    SQLiteTypeCompiler.visit_JSONB = lambda self, type_, **kw: 'JSON'  # noqa: E731


from app.agents.threat_intelligence import ThreatIntelligenceAgent
from app.database.postgres.base import Base
from app.models.threat_intel_indicator import ThreatIntelIndicator
from app.models.threat_intel_lookup import ThreatIntelLookup
from app.schemas.enriched_event import EnrichedSecurityEvent
from app.schemas.normalized_event import (
    Endpoint,
    EventCategory,
    EventOutcome,
    FileInfo,
    NormalizedSecurityEvent,
)
from app.schemas.security_event import Provenance, SourceType
from app.schemas.threat_intelligence_agent import (
    ExtractedIndicator,
    ProviderAssociation,
)
from app.services.threat_intelligence.abuseipdb import AbuseIPDBProvider
from app.services.threat_intelligence.alienvault_otx import AlienVaultOTXProvider
from app.services.threat_intelligence.base import (
    ThreatIntelProvider,
    ThreatIntelResult,
)
from app.services.threat_intelligence.registry import ProviderRegistry
from app.services.threat_intelligence.types import (
    IndicatorType,
    ThreatIndicator,
)
from app.services.threat_intelligence.validation import (
    classify_non_public_ip,
    is_non_public_ip,
    should_skip_external_lookup,
)
from app.services.threat_intelligence.virustotal import VirusTotalProvider
from app.services.threat_intelligence_persistence import (
    ThreatIntelligencePersistenceService,
)
from app.services.threat_intelligence_query import ThreatIntelQueryService

_TS = datetime(2026, 11, 7, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Test Helpers & Fakes
# ---------------------------------------------------------------------------

class CountingFakeProvider(ThreatIntelProvider):
    """Fake provider tracking lookup invocations."""

    def __init__(
        self,
        name: str = "FakeProvider",
        supported_types: frozenset[IndicatorType] | None = None,
    ) -> None:
        self._name = name
        self._types = supported_types or frozenset({
            IndicatorType.IP,
            IndicatorType.DOMAIN,
            IndicatorType.URL,
            IndicatorType.HASH,
        })
        self.lookup_calls: list[ThreatIndicator] = []

    @property
    def provider_name(self) -> str:
        return self._name

    @property
    def supported_indicator_types(self) -> frozenset[IndicatorType]:
        return self._types

    def lookup(self, indicator: ThreatIndicator) -> ThreatIntelResult:
        self.lookup_calls.append(indicator)
        return ThreatIntelResult(
            indicator=indicator,
            provider=self._name,
            found=True,
            data={"status": "ok", "indicator": indicator.value},
            confidence=0.9,
            timestamp=_TS,
        )


def _make_event(
    *,
    source_ip: str | None = None,
    dest_ip: str | None = None,
    domain: str | None = None,
    url: str | None = None,
    file_hash: str | None = None,
) -> EnrichedSecurityEvent:
    normalized_data = {}
    if domain:
        normalized_data["domain"] = domain
    if url:
        normalized_data["url"] = url

    normalized = NormalizedSecurityEvent(
        event_id=uuid.uuid4(),
        timestamp=_TS,
        event_category=EventCategory.NETWORK,
        action="connect",
        outcome=EventOutcome.SUCCESS,
        source="test-firewall",
        source_type=SourceType.NETWORK,
        source_endpoint=Endpoint(ip=source_ip) if source_ip else None,
        destination_endpoint=Endpoint(ip=dest_ip) if dest_ip else None,
        file=FileInfo(hash=file_hash) if file_hash else None,
        normalized_data=normalized_data,
        provenance=Provenance.OBSERVED,
    )
    return EnrichedSecurityEvent(
        event_id=normalized.event_id,
        timestamp=_TS,
        normalized_event=normalized,
        enrichments=[],
        provenance=Provenance.ENRICHED,
    )


# ---------------------------------------------------------------------------
# 1. IP Classification Unit Tests
# ---------------------------------------------------------------------------

class TestIpClassification:
    """Tests for centralized IP address classification."""

    @pytest.mark.parametrize(
        "ip,expected_substring",
        [
            # Private IPv4 (RFC 1918)
            ("10.20.30.40", "private IPv4"),
            ("10.0.0.1", "private IPv4"),
            ("172.16.0.1", "private IPv4"),
            ("172.31.255.254", "private IPv4"),
            ("192.168.1.1", "private IPv4"),
            ("192.168.254.254", "private IPv4"),
            # Private IPv6 (RFC 4193 ULA)
            ("fc00::1", "private IPv6"),
            ("fd12:3456:789a::1", "private IPv6"),
            # Loopback IPv4 and IPv6
            ("127.0.0.1", "loopback IPv4"),
            ("127.255.255.255", "loopback IPv4"),
            ("::1", "loopback IPv6"),
            # Link-local IPv4 and IPv6
            ("169.254.1.1", "link-local IPv4"),
            ("169.254.254.254", "link-local IPv4"),
            ("fe80::1", "link-local IPv6"),
            ("fe80::dead:beef", "link-local IPv6"),
            # Multicast IPv4 and IPv6
            ("224.0.0.1", "multicast IPv4"),
            ("239.255.255.250", "multicast IPv4"),
            ("ff02::1", "multicast IPv6"),
            ("ff05::1:3", "multicast IPv6"),
            # Unspecified IPv4 and IPv6
            ("0.0.0.0", "unspecified IPv4"),
            ("::", "unspecified IPv6"),
            # Reserved and non-globally-routable addresses
            ("240.0.0.1", "reserved IPv4"),
            ("255.255.255.255", "reserved IPv4"),
            ("100.64.0.1", "reserved IPv4"),
            ("100.127.255.254", "reserved IPv4"),
            ("198.18.0.1", "reserved IPv4"),
        ],
    )
    def test_non_public_ips_classified_correctly(
        self, ip: str, expected_substring: str
    ) -> None:
        reason = classify_non_public_ip(ip)
        assert reason is not None
        assert expected_substring in reason
        assert is_non_public_ip(ip) is True

        skip, skip_reason = should_skip_external_lookup(IndicatorType.IP, ip)
        assert skip is True
        assert skip_reason == reason

    @pytest.mark.parametrize(
        "ip",
        [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "185.10.10.10",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
        ],
    )
    def test_public_ips_not_classified_as_non_public(self, ip: str) -> None:
        assert classify_non_public_ip(ip) is None
        assert is_non_public_ip(ip) is False

        skip, reason = should_skip_external_lookup(IndicatorType.IP, ip)
        assert skip is False
        assert reason is None

    @pytest.mark.parametrize(
        "indicator_type,value",
        [
            (IndicatorType.DOMAIN, "10.20.30.40.nip.io"),
            (IndicatorType.DOMAIN, "example.com"),
            (IndicatorType.DOMAIN, "localhost"),
            (IndicatorType.URL, "http://10.20.30.40/payload.exe"),
            (IndicatorType.URL, "https://example.com/api"),
            (IndicatorType.HASH, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (IndicatorType.HASH, "d41d8cd98f00b204e9800998ecf8427e"),
        ],
    )
    def test_non_ip_indicators_never_skipped_by_ip_rules(
        self, indicator_type: IndicatorType, value: str
    ) -> None:
        skip, reason = should_skip_external_lookup(indicator_type, value)
        assert skip is False
        assert reason is None

    def test_malformed_ip_not_classified_as_non_public(self) -> None:
        assert classify_non_public_ip("not-an-ip") is None
        assert is_non_public_ip("not-an-ip") is False
        skip, _ = should_skip_external_lookup(IndicatorType.IP, "not-an-ip")
        assert skip is False


# ---------------------------------------------------------------------------
# 2. Centralized ThreatIntelligenceAgent Lookup Protection Tests
# ---------------------------------------------------------------------------

class TestThreatIntelligenceAgentLookupProtection:
    """Verifies that ThreatIntelligenceAgent blocks external provider lookups centrally."""

    def test_private_ipv4_lookup_skipped_before_dispatch(self) -> None:
        provider = CountingFakeProvider()
        agent = ThreatIntelligenceAgent(ProviderRegistry([provider]))

        event = _make_event(source_ip="10.20.30.40")
        analysis = agent.analyze(event)

        # Provider must NEVER be called
        assert len(provider.lookup_calls) == 0
        assert analysis.metadata.lookups_attempted == 0
        assert analysis.metadata.lookups_succeeded == 0
        assert analysis.metadata.lookups_failed == 0
        assert analysis.metadata.indicators_extracted == 1

        # Indicator is preserved in analysis
        assert len(analysis.indicators) == 1
        assert analysis.indicators[0].indicator == "10.20.30.40"

        # Skipped lookup is represented honestly as ProviderAssociation with result=None
        assert len(analysis.results) == 1
        assoc = analysis.results[0]
        assert assoc.provider == provider.provider_name
        assert assoc.indicator.indicator == "10.20.30.40"
        assert assoc.result is None

        # No fake failures or enrichments
        assert analysis.failures == []
        assert analysis.enrichments == []
        assert analysis.has_results is False
        assert analysis.has_failures is False

    @pytest.mark.parametrize(
        "ip",
        [
            "fc00::1",          # private IPv6
            "127.0.0.1",        # loopback IPv4
            "::1",              # loopback IPv6
            "169.254.1.1",      # link-local IPv4
            "fe80::1",          # link-local IPv6
            "224.0.0.1",        # multicast IPv4
            "ff02::1",          # multicast IPv6
            "0.0.0.0",          # unspecified IPv4
            "::",               # unspecified IPv6
            "240.0.0.1",        # reserved IPv4
            "100.64.0.1",       # CGNAT non-global
        ],
    )
    def test_all_non_public_ip_categories_skip_provider_invocation(
        self, ip: str
    ) -> None:
        provider = CountingFakeProvider()
        agent = ThreatIntelligenceAgent(ProviderRegistry([provider]))

        event = _make_event(source_ip=ip)
        analysis = agent.analyze(event)

        assert len(provider.lookup_calls) == 0
        assert analysis.metadata.lookups_attempted == 0
        assert len(analysis.results) == 1
        assert analysis.results[0].result is None
        assert analysis.enrichments == []

    def test_public_ips_continue_normal_lookup(self) -> None:
        provider = CountingFakeProvider()
        agent = ThreatIntelligenceAgent(ProviderRegistry([provider]))

        event = _make_event(source_ip="8.8.8.8", dest_ip="2606:4700:4700::1111")
        analysis = agent.analyze(event)

        assert len(provider.lookup_calls) == 2
        assert {call.value for call in provider.lookup_calls} == {
            "8.8.8.8",
            "2606:4700:4700::1111",
        }
        assert analysis.metadata.lookups_attempted == 2
        assert analysis.metadata.lookups_succeeded == 2
        assert len(analysis.results) == 2
        assert all(assoc.result is not None for assoc in analysis.results)
        assert len(analysis.enrichments) == 2
        assert analysis.has_results is True

    def test_mixed_batch_filters_only_non_public_ips(self) -> None:
        provider = CountingFakeProvider()
        agent = ThreatIntelligenceAgent(ProviderRegistry([provider]))

        event = _make_event(
            source_ip="10.20.30.40",         # Non-public (skip)
            dest_ip="8.8.8.8",               # Public (lookup)
            domain="malicious.example.com",  # Domain (lookup)
            file_hash="d41d8cd98f00b204e9800998ecf8427e",  # Hash (lookup)
        )
        analysis = agent.analyze(event)

        # Provider must only be called for the 3 routable/public indicators
        called_values = {call.value for call in provider.lookup_calls}
        assert called_values == {
            "8.8.8.8",
            "malicious.example.com",
            "d41d8cd98f00b204e9800998ecf8427e",
        }
        assert "10.20.30.40" not in called_values

        assert analysis.metadata.indicators_extracted == 4
        assert analysis.metadata.lookups_attempted == 3
        assert analysis.metadata.lookups_succeeded == 3
        assert analysis.metadata.lookups_failed == 0

        # All 4 indicators exist on the analysis
        ind_values = {ind.indicator for ind in analysis.indicators}
        assert ind_values == {
            "10.20.30.40",
            "8.8.8.8",
            "malicious.example.com",
            "d41d8cd98f00b204e9800998ecf8427e",
        }

        # 10.20.30.40 has result=None; others have valid results
        results_by_indicator = {
            assoc.indicator.indicator: assoc.result for assoc in analysis.results
        }
        assert results_by_indicator["10.20.30.40"] is None
        assert results_by_indicator["8.8.8.8"] is not None
        assert results_by_indicator["malicious.example.com"] is not None
        assert results_by_indicator["d41d8cd98f00b204e9800998ecf8427e"] is not None


# ---------------------------------------------------------------------------
# 3. All Three Provider Integrations Tested
# ---------------------------------------------------------------------------

class TestThreeProviderClientsCentralProtection:
    """Verifies that VirusTotal, AbuseIPDB, and AlienVault OTX clients receive no non-public IP traffic."""

    def test_all_three_providers_protected_from_private_ip(self) -> None:
        vt_requests: list[httpx.Request] = []
        abuse_requests: list[httpx.Request] = []
        otx_requests: list[httpx.Request] = []

        def vt_handler(request: httpx.Request) -> httpx.Response:
            vt_requests.append(request)
            return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {}}}})

        def abuse_handler(request: httpx.Request) -> httpx.Response:
            abuse_requests.append(request)
            return httpx.Response(200, json={"data": {"ipAddress": "8.8.8.8", "abuseConfidenceScore": 0}})

        def otx_handler(request: httpx.Request) -> httpx.Response:
            otx_requests.append(request)
            return httpx.Response(200, json={"pulse_info": {"count": 0, "pulses": []}})

        vt_client = httpx.Client(transport=httpx.MockTransport(vt_handler))
        abuse_client = httpx.Client(transport=httpx.MockTransport(abuse_handler))
        otx_client = httpx.Client(transport=httpx.MockTransport(otx_handler))

        vt_provider = VirusTotalProvider(api_key="test-key", http_client=vt_client)
        abuse_provider = AbuseIPDBProvider(api_key="test-key", http_client=abuse_client)
        otx_provider = AlienVaultOTXProvider(api_key="test-key", http_client=otx_client)

        registry = ProviderRegistry([vt_provider, abuse_provider, otx_provider])
        agent = ThreatIntelligenceAgent(registry)

        # 1. Private IP lookup
        event_private = _make_event(source_ip="10.20.30.40")
        analysis_private = agent.analyze(event_private)

        # ZERO HTTP requests must have been issued across all 3 providers
        assert len(vt_requests) == 0
        assert len(abuse_requests) == 0
        assert len(otx_requests) == 0
        assert len(analysis_private.failures) == 0
        assert len(analysis_private.results) == 3
        assert all(assoc.result is None for assoc in analysis_private.results)

        # 2. Public IP lookup (confirming public IPs still work across all three)
        event_public = _make_event(source_ip="8.8.8.8")
        analysis_public = agent.analyze(event_public)

        # Exactly 1 HTTP request per provider
        assert len(vt_requests) == 1
        assert len(abuse_requests) == 1
        assert len(otx_requests) == 1
        assert len(analysis_public.failures) == 0
        assert len(analysis_public.results) == 3
        assert all(assoc.result is not None for assoc in analysis_public.results)
        assert len(analysis_public.enrichments) == 3


# ---------------------------------------------------------------------------
# 4. Persistence and Status Semantics Tests
# ---------------------------------------------------------------------------

class TestPersistenceAndStatusSemantics:
    """Verifies that skipped lookups preserve the indicator while storing no lookups (status: no_lookup)."""

    @pytest.fixture
    def db_session(self) -> Session:
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        session_factory = sessionmaker(bind=engine)
        session = session_factory()
        yield session
        session.close()

    def test_skipped_indicator_persists_with_no_lookup_status(
        self, db_session: Session
    ) -> None:
        provider = CountingFakeProvider()
        agent = ThreatIntelligenceAgent(ProviderRegistry([provider]))

        event = _make_event(source_ip="10.20.30.40")
        analysis = agent.analyze(event)

        # Persist through the persistence service
        persistence_service = ThreatIntelligencePersistenceService()
        result = persistence_service.persist_analysis(db_session, analysis)

        assert result.indicators_created == 1
        assert result.lookups_created == 0

        # Query the database
        indicator_row = db_session.query(ThreatIntelIndicator).filter_by(
            value="10.20.30.40"
        ).first()
        assert indicator_row is not None
        assert indicator_row.value == "10.20.30.40"
        assert indicator_row.indicator_type == IndicatorType.IP

        # Verify zero lookups are recorded in threat_intel_lookups
        lookup_rows = db_session.query(ThreatIntelLookup).filter_by(
            indicator_id=indicator_row.id
        ).all()
        assert len(lookup_rows) == 0

        # Query through ThreatIntelQueryService
        query_service = ThreatIntelQueryService(db_session)
        detail = query_service.get_indicator(indicator_row.id)

        # Assert honest status representation
        assert detail.indicator.status == "no_lookup"
        assert detail.indicator.lookup_count == 0
        assert detail.indicator.success_count == 0
        assert detail.indicator.error_count == 0
        assert detail.lookups == []
        assert detail.verdict_available is False

    def test_mixed_batch_persistence_semantics(
        self, db_session: Session
    ) -> None:
        provider = CountingFakeProvider()
        agent = ThreatIntelligenceAgent(ProviderRegistry([provider]))

        event = _make_event(source_ip="10.20.30.40", dest_ip="8.8.8.8")
        analysis = agent.analyze(event)

        persistence_service = ThreatIntelligencePersistenceService()
        result = persistence_service.persist_analysis(db_session, analysis)

        assert result.indicators_created == 2
        # Only the public IP generated a lookup record
        assert result.lookups_created == 1

        query_service = ThreatIntelQueryService(db_session)

        # 10.20.30.40 is preserved but has no_lookup
        priv_ind = db_session.query(ThreatIntelIndicator).filter_by(
            value="10.20.30.40"
        ).first()
        priv_detail = query_service.get_indicator(priv_ind.id)
        assert priv_detail.indicator.status == "no_lookup"
        assert priv_detail.indicator.lookup_count == 0

        # 8.8.8.8 is enriched
        pub_ind = db_session.query(ThreatIntelIndicator).filter_by(
            value="8.8.8.8"
        ).first()
        pub_detail = query_service.get_indicator(pub_ind.id)
        assert pub_detail.indicator.status == "enriched"
        assert pub_detail.indicator.lookup_count == 1
        assert pub_detail.lookups[0].provider_result_available is True
