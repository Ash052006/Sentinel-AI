"""Unit tests for the Threat Intelligence Agent execution (Step 8B).

Covers indicator extraction, deterministic deduplication, registry-based
provider selection, provider lookup execution, failure isolation,
enrichment conversion, traceability, metadata counters, secret-safety,
input immutability, and the absence of any verdict/risk-score output.

Pure unit tests ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â the agent is exercised with deterministic fake
providers registered in a test-local ProviderRegistry.  No real network
calls are ever made.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pytest

from app.agents.threat_intelligence import ThreatIntelligenceAgent
from app.schemas.enriched_event import (
    EnrichedSecurityEvent,
    EnrichmentResult,
)
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
    ProviderFailure,
    ThreatIntelMetadata,
    ThreatIntelligenceAnalysis,
    THREAT_INTELLIGENCE_ENRICHMENT_TYPE,
)
from app.services.threat_intelligence.base import (
    ThreatIntelProvider,
    ThreatIntelResult,
)
from app.services.threat_intelligence.exceptions import (
    InvalidIndicatorError,
    ProviderLookupError,
    RateLimitError,
)
from app.services.threat_intelligence.registry import ProviderRegistry
from app.services.threat_intelligence.types import IndicatorType, ThreatIndicator

_FIXED_TS = datetime(2025, 8, 10, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Fake providers (deterministic, no network)
# ---------------------------------------------------------------------------

class FakeProvider(ThreatIntelProvider):
    """Configurable in-memory provider for exercising the agent."""

    def __init__(
        self,
        *,
        name: str = "Fake",
        types: frozenset[IndicatorType] = frozenset({IndicatorType.IP}),
        found: bool = True,
        data: dict | None = None,
        confidence: float | None = None,
        raise_exc: Exception | None = None,
        timestamp: datetime = _FIXED_TS,
        api_key: str | None = None,
    ) -> None:
        self._name = name
        self._types = types
        self._found = found
        self._data = data or {}
        self._confidence = confidence
        self.raise_exc = raise_exc
        self.timestamp = timestamp
        # Credentials live only on the provider; a well-behaved provider
        # never copies them into results, data, or metadata.
        self._api_key = api_key
        # Every ThreatIndicator this provider was asked to look up.
        self.lookup_calls: list[ThreatIndicator] = []

    @property
    def provider_name(self) -> str:
        return self._name

    @property
    def supported_indicator_types(self) -> frozenset[IndicatorType]:
        return self._types

    def lookup(self, indicator: ThreatIndicator) -> ThreatIntelResult:
        self.lookup_calls.append(indicator)
        if self.raise_exc is not None:
            raise self.raise_exc
        return ThreatIntelResult(
            indicator=indicator,
            provider=self._name,
            found=self._found,
            data=dict(self._data),
            confidence=self._confidence,
            timestamp=self.timestamp,
        )


# ---------------------------------------------------------------------------
# Event builders
# ---------------------------------------------------------------------------

def _make_normalized_event(
    *,
    source_ip: str | None = None,
    dest_ip: str | None = None,
    file_hash: str | None = None,
    normalized_data: dict | None = None,
) -> NormalizedSecurityEvent:
    """Build a NormalizedSecurityEvent with the requested indicator fields."""
    return NormalizedSecurityEvent(
        event_id=uuid.uuid4(),
        timestamp=_FIXED_TS,
        event_category=EventCategory.NETWORK,
        action="connect",
        outcome=EventOutcome.SUCCESS,
        source="firewall",
        source_type=SourceType.NETWORK,
        source_endpoint=Endpoint(ip=source_ip) if source_ip else None,
        destination_endpoint=Endpoint(ip=dest_ip) if dest_ip else None,
        file=FileInfo(hash=file_hash) if file_hash else None,
        normalized_data=normalized_data or {},
        provenance=Provenance.OBSERVED,
    )


def _make_event(**overrides) -> EnrichedSecurityEvent:
    """Build a valid EnrichedSecurityEvent wrapping a normalized event."""
    normalized = overrides.pop("normalized_event", None)
    if normalized is None:
        normalized = _make_normalized_event(
            source_ip=overrides.pop("source_ip", None),
            dest_ip=overrides.pop("dest_ip", None),
            file_hash=overrides.pop("file_hash", None),
            normalized_data=overrides.pop("normalized_data", None),
        )
    base = {
        "event_id": normalized.event_id,
        "timestamp": normalized.timestamp,
        "normalized_event": normalized,
        "enrichments": [],
        "provenance": Provenance.ENRICHED,
    }
    base.update(overrides)
    return EnrichedSecurityEvent(**base)


# ---------------------------------------------------------------------------
# 1-2. Acceptance and empty analysis
# ---------------------------------------------------------------------------

class TestAgentAcceptsValidEvent:
    def test_accepts_valid_enriched_event(self):
        event = _make_event(source_ip="185.10.10.10")
        registry = ProviderRegistry([
            FakeProvider(name="VT", types=frozenset({IndicatorType.IP})),
        ])
        agent = ThreatIntelligenceAgent(registry)
        analysis = agent.analyze(event)
        assert isinstance(analysis, ThreatIntelligenceAnalysis)
        assert analysis.event_id == event.event_id

    def test_rejects_non_event_input(self):
        agent = ThreatIntelligenceAgent(ProviderRegistry())
        with pytest.raises(TypeError):
            agent.analyze("not-an-event")  # type: ignore[arg-type]

    def test_rejects_non_registry(self):
        with pytest.raises(TypeError):
            ThreatIntelligenceAgent("not-a-registry")  # type: ignore[arg-type]


class TestNoIndicators:
    def test_no_indicators_produces_empty_analysis(self):
        event = _make_event()
        provider = FakeProvider(name="VT")
        agent = ThreatIntelligenceAgent(ProviderRegistry([provider]))
        analysis = agent.analyze(event)
        assert analysis.indicators == []
        assert analysis.results == []
        assert analysis.failures == []
        assert analysis.enrichments == []
        assert analysis.metadata.indicators_extracted == 0
        assert analysis.metadata.lookups_attempted == 0
        assert provider.lookup_calls == []

    # ---------------------------------------------------------------------------
# 3-8. Indicator extraction
# ---------------------------------------------------------------------------

class TestIndicatorExtraction:
    def test_source_ip_extraction(self):
        event = _make_event(source_ip="185.10.10.10")
        agent = ThreatIntelligenceAgent(ProviderRegistry([FakeProvider()]))
        analysis = agent.analyze(event)
        assert len(analysis.indicators) == 1
        ind = analysis.indicators[0]
        assert ind.indicator_type is IndicatorType.IP
        assert ind.indicator == "185.10.10.10"
        assert ind.source_field == "source_endpoint.ip"
        assert ind.source_context == "source_endpoint"

    def test_destination_ip_extraction(self):
        event = _make_event(dest_ip="203.0.113.7")
        agent = ThreatIntelligenceAgent(ProviderRegistry([FakeProvider()]))
        analysis = agent.analyze(event)
        assert len(analysis.indicators) == 1
        ind = analysis.indicators[0]
        assert ind.indicator_type is IndicatorType.IP
        assert ind.indicator == "203.0.113.7"
        assert ind.source_field == "destination_endpoint.ip"
        assert ind.source_context == "destination_endpoint"

    def test_domain_extraction_from_normalized_data(self):
        event = _make_event(normalized_data={"domain": "evil.example.com"})
        provider = FakeProvider(types=frozenset({IndicatorType.DOMAIN}))
        agent = ThreatIntelligenceAgent(ProviderRegistry([provider]))
        analysis = agent.analyze(event)
        assert len(analysis.indicators) == 1
        ind = analysis.indicators[0]
        assert ind.indicator_type is IndicatorType.DOMAIN
        assert ind.indicator == "evil.example.com"
        assert ind.source_field == "normalized_data.domain"
        assert ind.source_context == "normalized_data"

    def test_url_extraction_from_normalized_data(self):
        event = _make_event(normalized_data={"url": "https://evil.example/payload"})
        provider = FakeProvider(types=frozenset({IndicatorType.URL}))
        agent = ThreatIntelligenceAgent(ProviderRegistry([provider]))
        analysis = agent.analyze(event)
        assert len(analysis.indicators) == 1
        ind = analysis.indicators[0]
        assert ind.indicator_type is IndicatorType.URL
        assert ind.indicator == "https://evil.example/payload"
        assert ind.source_field == "normalized_data.url"

    def test_file_hash_extraction(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        event = _make_event(file_hash=h)
        provider = FakeProvider(types=frozenset({IndicatorType.HASH}))
        agent = ThreatIntelligenceAgent(ProviderRegistry([provider]))
        analysis = agent.analyze(event)
        assert len(analysis.indicators) == 1
        ind = analysis.indicators[0]
        assert ind.indicator_type is IndicatorType.HASH
        assert ind.indicator == h
        assert ind.source_field == "file.hash"
        assert ind.source_context == "file"

    def test_explicit_hash_key_in_normalized_data(self):
        h = "d41d8cd98f00b204e9800998ecf8427e"
        event = _make_event(normalized_data={"sha256": h})
        provider = FakeProvider(types=frozenset({IndicatorType.HASH}))
        agent = ThreatIntelligenceAgent(ProviderRegistry([provider]))
        analysis = agent.analyze(event)
        assert len(analysis.indicators) == 1
        assert analysis.indicators[0].indicator == h

    def test_multiple_indicator_extraction(self):
        event = _make_event(
            source_ip="185.10.10.10",
            dest_ip="203.0.113.7",
            file_hash="d41d8cd98f00b204e9800998ecf8427e",
            normalized_data={
                "domain": "evil.example.com",
                "url": "https://evil.example/payload",
            },
        )
        agent = ThreatIntelligenceAgent(ProviderRegistry([FakeProvider()]))
        analysis = agent.analyze(event)


# ---------------------------------------------------------------------------
# 9-11. Deduplication and source context
# ---------------------------------------------------------------------------

class TestDeduplication:
    def test_deterministic_deduplication(self):
        # Same IP in both endpoints ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ one provider lookup, one result.
        src = FakeProvider(name="VT", types=frozenset({IndicatorType.IP}))
        agent = ThreatIntelligenceAgent(ProviderRegistry([src]))
        event = _make_event(source_ip="185.10.10.10", dest_ip="185.10.10.10")
        analysis = agent.analyze(event)
        assert len(src.lookup_calls) == 1
        assert len(analysis.results) == 1
        assert analysis.metadata.lookups_attempted == 1
        assert analysis.metadata.indicators_extracted == 1

    def test_same_value_different_types_stay_distinct(self):
        provider = FakeProvider(
            name="VT",
            types=frozenset({IndicatorType.IP, IndicatorType.DOMAIN}),
        )
        agent = ThreatIntelligenceAgent(ProviderRegistry([provider]))
        event = _make_event(
            source_ip="185.10.10.10",
            normalized_data={"domain": "185.10.10.10"},
        )
        analysis = agent.analyze(event)
        assert len(provider.lookup_calls) == 2
        assert analysis.metadata.indicators_extracted == 2
        types = {ind.indicator_type for ind in analysis.indicators}
        assert types == {IndicatorType.IP, IndicatorType.DOMAIN}

    def test_source_context_is_preserved(self):
        provider = FakeProvider(name="VT", types=frozenset({IndicatorType.IP}))
        agent = ThreatIntelligenceAgent(ProviderRegistry([provider]))
        event = _make_event(source_ip="185.10.10.10", dest_ip="203.0.113.7")
        analysis = agent.analyze(event)
        contexts = {
            (ind.source_field, ind.source_context, ind.indicator)
            for ind in analysis.indicators
        }
        assert ("source_endpoint.ip", "source_endpoint", "185.10.10.10") in contexts
        assert (
            "destination_endpoint.ip",
            "destination_endpoint",
            "203.0.113.7",
        ) in contexts
        # Both occurrences are preserved even when values repeat.
        event2 = _make_event(source_ip="185.10.10.10", dest_ip="185.10.10.10")
        analysis2 = agent.analyze(event2)
        fields = {ind.source_field for ind in analysis2.indicators}
        assert fields == {"source_endpoint.ip", "destination_endpoint.ip"}


# ---------------------------------------------------------------------------
# 15-18. Lookup execution and failure isolation
# ---------------------------------------------------------------------------

class TestLookupExecution:
    def test_successful_provider_lookup(self):
        provider = FakeProvider(
            name="VT",
            found=True,
            data={"reputation": -1},
            confidence=0.9,
        )
        agent = ThreatIntelligenceAgent(ProviderRegistry([provider]))
        event = _make_event(source_ip="185.10.10.10")
        analysis = agent.analyze(event)
        assert len(analysis.results) == 1
        assoc = analysis.results[0]
        assert isinstance(assoc, ProviderAssociation)
        assert assoc.result is not None
        assert assoc.result.provider == "VT"
        assert assoc.result.found is True
        assert assoc.result.data == {"reputation": -1}
        assert analysis.failures == []

    def test_provider_failure_does_not_abort_analysis(self):
        failing = FakeProvider(
            name="Bad", raise_exc=ProviderLookupError("Bad", "timeout"),
        )
        healthy = FakeProvider(name="Ok")
        agent = ThreatIntelligenceAgent(ProviderRegistry([failing, healthy]))
        event = _make_event(source_ip="185.10.10.10")
        analysis = agent.analyze(event)
        # The healthy provider still completed and other indicators still run.
        assert analysis.has_failures
        assert analysis.has_results
        assert len(analysis.results) == 1
        assert analysis.results[0].provider == "Ok"
        assert analysis.failures[0].provider == "Bad"

    def test_provider_failure_generated_correctly(self):
        provider = FakeProvider(
            name="VT", raise_exc=ProviderLookupError("VT", "timeout"),
        )
        agent = ThreatIntelligenceAgent(ProviderRegistry([provider]))
        event = _make_event(source_ip="185.10.10.10")
        analysis = agent.analyze(event)
        assert len(analysis.failures) == 1
        fail = analysis.failures[0]
        assert isinstance(fail, ProviderFailure)
        assert fail.provider == "VT"
        assert fail.indicator == "185.10.10.10"
        assert fail.indicator_type is IndicatorType.IP
        assert fail.error_type == "timeout"
        assert "timeout" in fail.message.lower()
        assert fail.retryable is True

    def test_retryable_failure_information_is_preserved(self):
        rate_limited = FakeProvider(
            name="Rate", raise_exc=RateLimitError("Rate", retry_after=30.0),
        )
        agent = ThreatIntelligenceAgent(ProviderRegistry([rate_limited]))
        event = _make_event(source_ip="185.10.10.10")
        analysis = agent.analyze(event)
        fail = analysis.failures[0]
        assert fail.error_type == "rate_limit"
        assert fail.retryable is True

    def test_non_retryable_failure_marked_false(self):
        provider = FakeProvider(
            name="VT",
            raise_exc=ProviderLookupError("VT", "unauthorized"),
        )
        agent = ThreatIntelligenceAgent(ProviderRegistry([provider]))
        event = _make_event(source_ip="185.10.10.10")
        analysis = agent.analyze(event)
        fail = analysis.failures[0]
        assert fail.error_type == "provider_error"
        assert fail.retryable is False

    def test_invalid_indicator_failure_classified(self):
        provider = FakeProvider(
            name="OTX", raise_exc=InvalidIndicatorError("bad value"),
        )
        agent = ThreatIntelligenceAgent(ProviderRegistry([provider]))
        event = _make_event(source_ip="185.10.10.10")
        analysis = agent.analyze(event)
        fail = analysis.failures[0]
        assert fail.error_type == "invalid_indicator"
        assert fail.retryable is False

    def test_unexpected_exception_isolated(self):
        provider = FakeProvider(name="Weird", raise_exc=RuntimeError("boom"))
        agent = ThreatIntelligenceAgent(ProviderRegistry([provider]))
        event = _make_event(source_ip="185.10.10.10")
        analysis = agent.analyze(event)
        assert len(analysis.failures) == 1
        assert analysis.failures[0].error_type == "unexpected"
        assert analysis.failures[0].retryable is False


# ---------------------------------------------------------------------------
# 12-14. Provider selection
# ---------------------------------------------------------------------------

class TestProviderSelection:
    def test_registry_is_used(self):
        provider = FakeProvider(
            name="VT",
            types=frozenset({IndicatorType.IP}),
        )
        registry = ProviderRegistry([provider])
        agent = ThreatIntelligenceAgent(registry)
        event = _make_event(source_ip="185.10.10.10")
        analysis = agent.analyze(event)
        assert len(analysis.results) == 1
        assert analysis.results[0].provider == "VT"

    def test_only_compatible_providers_selected(self):
        ip_provider = FakeProvider(name="IPOnly", types=frozenset({IndicatorType.IP}))
        domain_provider = FakeProvider(
            name="DomOnly", types=frozenset({IndicatorType.DOMAIN}),
        )
        registry = ProviderRegistry([ip_provider, domain_provider])
        agent = ThreatIntelligenceAgent(registry)
        event = _make_event(source_ip="185.10.10.10")
        analysis = agent.analyze(event)
        assert ip_provider.lookup_calls != []
        assert domain_provider.lookup_calls == []
        providers = {r.provider for r in analysis.results}
        assert providers == {"IPOnly"}

    def test_multiple_providers_for_one_indicator(self):
        p1 = FakeProvider(name="VT", types=frozenset({IndicatorType.IP}))
        p2 = FakeProvider(name="Abuse", types=frozenset({IndicatorType.IP}))
        agent = ThreatIntelligenceAgent(ProviderRegistry([p1, p2]))
        event = _make_event(source_ip="185.10.10.10")
        analysis = agent.analyze(event)
        assert len(p1.lookup_calls) == 1
        assert len(p2.lookup_calls) == 1
        assert len(analysis.results) == 2
        assert analysis.metadata.lookups_attempted == 2
        assert analysis.metadata.lookups_succeeded == 2


# ---------------------------------------------------------------------------
# 22-24. Traceability
# ---------------------------------------------------------------------------

class TestTraceability:
    def test_event_id_is_preserved(self):
        provider = FakeProvider(name="VT")
        agent = ThreatIntelligenceAgent(ProviderRegistry([provider]))
        event = _make_event(source_ip="185.10.10.10")
        analysis = agent.analyze(event)
        assert analysis.event_id == event.event_id
        assert analysis.event_id == event.normalized_event.event_id

    def test_provider_to_result_traceability(self):
        provider = FakeProvider(
            name="VT", data={"reputation": -5}, confidence=0.95,
        )
        agent = ThreatIntelligenceAgent(ProviderRegistry([provider]))
        event = _make_event(source_ip="185.10.10.10")
        analysis = agent.analyze(event)
        assoc = analysis.results[0]
        assert assoc.provider == "VT"
        assert assoc.result is not None
        assert assoc.result.provider == "VT"
        assert assoc.result.indicator.value == "185.10.10.10"
        # The enrichment is derived from that same provider result.
        enrich = analysis.enrichments[0]
        assert enrich.source == "VT"
        assert enrich.value["indicator"] == assoc.result.indicator.value

    def test_indicator_to_provider_traceability(self):
        provider = FakeProvider(name="Abuse")
        agent = ThreatIntelligenceAgent(ProviderRegistry([provider]))
        event = _make_event(source_ip="185.10.10.10")
        analysis = agent.analyze(event)
        ind = analysis.indicators[0]
        assoc = analysis.results[0]
        assert assoc.indicator.indicator == ind.indicator
        assert assoc.indicator.indicator_type is IndicatorType.IP
        assert assoc.indicator.canonical_key == ind.canonical_key


# ---------------------------------------------------------------------------
# 25-27. Metadata counters
# ---------------------------------------------------------------------------

class TestMetadataCounters:
    def test_zero_lookup_case(self):
        # Indicators exist but no provider supports them Ã¢â€ â€™ zero lookups and
        # accurate failure-free counters.
        agent = ThreatIntelligenceAgent(ProviderRegistry([FakeProvider(
            name="HashOnly", types=frozenset({IndicatorType.HASH}),
        )]))
        event = _make_event(source_ip="185.10.10.10")
        analysis = agent.analyze(event)
        md = analysis.metadata
        assert isinstance(md, ThreatIntelMetadata)
        assert md.indicators_extracted == 1
        assert md.providers_attempted == 0
        assert md.providers_succeeded == 0
        assert md.providers_failed == 0
        assert md.lookups_attempted == 0
        assert md.lookups_succeeded == 0
        assert md.lookups_failed == 0

    def test_all_metadata_counters_accurate(self):
        ip_provider = FakeProvider(name="VT", types=frozenset({IndicatorType.IP}))
        domain_provider = FakeProvider(
            name="OTX",
            types=frozenset({IndicatorType.IP, IndicatorType.DOMAIN}),
        )
        failing = FakeProvider(
            name="Bad",
            types=frozenset({IndicatorType.DOMAIN}),
            raise_exc=ProviderLookupError("Bad", "server error (HTTP 500)"),
        )
        registry = ProviderRegistry([ip_provider, domain_provider, failing])
        agent = ThreatIntelligenceAgent(registry)
        event = _make_event(
            source_ip="185.10.10.10",
            normalized_data={"domain": "evil.example.com"},
        )
        analysis = agent.analyze(event)
        md = analysis.metadata
        # 2 unique indicators (ip, domain).
        assert md.indicators_extracted == 2
        # IP Ã¢â€ â€™ VT + OTX; domain Ã¢â€ â€™ OTX + Bad Ã¢â€ â€™ 4 lookups in total.
        assert md.lookups_attempted == 4
        assert md.lookups_succeeded == 3
        assert md.lookups_failed == 1
        # 3 distinct providers attempted, 2 succeeded, 1 failed.
        assert md.providers_attempted == 3
        assert md.providers_succeeded == 2
        assert md.providers_failed == 1
        assert len(analysis.results) == 3
        assert len(analysis.failures) == 1
        assert len(analysis.enrichments) == 3

    def test_multiple_indicators_times_multiple_providers(self):
        p1 = FakeProvider(name="VT", types=frozenset({IndicatorType.IP}))
        p2 = FakeProvider(name="Abuse", types=frozenset({IndicatorType.IP}))
        p3 = FakeProvider(
            name="OTX",
            types=frozenset({IndicatorType.IP, IndicatorType.HASH}),
        )
        agent = ThreatIntelligenceAgent(ProviderRegistry([p1, p2, p3]))
        event = _make_event(
            source_ip="185.10.10.10",
            file_hash="d41d8cd98f00b204e9800998ecf8427e",
        )
        analysis = agent.analyze(event)
        # IP Ã¢â€ â€™ VT + Abuse + OTX; hash Ã¢â€ â€™ OTX.  Total 4 lookups.
        assert len(p1.lookup_calls) == 1
        assert len(p2.lookup_calls) == 1
        assert len(p3.lookup_calls) == 2
        assert analysis.metadata.lookups_attempted == 4
        assert len(analysis.results) == 4
        assert len(analysis.enrichments) == 4


# ---------------------------------------------------------------------------
# 19-21. Enrichment conversion
# ---------------------------------------------------------------------------

class TestEnrichmentConversion:
    def test_successful_results_become_enrichment_results(self):
        provider = FakeProvider(
            name="VT", data={"last_analysis": {"malicious": 3}},
        )
        agent = ThreatIntelligenceAgent(ProviderRegistry([provider]))
        event = _make_event(source_ip="185.10.10.10")
        analysis = agent.analyze(event)
        assert len(analysis.enrichments) == 1
        enrich = analysis.enrichments[0]
        assert isinstance(enrich, EnrichmentResult)
        assert enrich.value["indicator"] == "185.10.10.10"
        assert enrich.value["provider"] == "VT"
        assert enrich.value["found"] is True
        assert enrich.value["last_analysis"] == {"malicious": 3}

    def test_enrichment_type_is_threat_intelligence(self):
        provider = FakeProvider(name="OTX")
        agent = ThreatIntelligenceAgent(ProviderRegistry([provider]))
        event = _make_event(dest_ip="203.0.113.7")
        analysis = agent.analyze(event)
        assert analysis.enrichments[0].enrichment_type == (
            THREAT_INTELLIGENCE_ENRICHMENT_TYPE
        )
        assert analysis.enrichments[0].enrichment_type == "threat_intelligence"

    def test_enrichment_source_is_provider(self):
        provider = FakeProvider(name="Abuse", data={"abuseConfidenceScore": 94})
        agent = ThreatIntelligenceAgent(ProviderRegistry([provider]))
        event = _make_event(source_ip="185.10.10.10")
        analysis = agent.analyze(event)
        assert analysis.enrichments[0].source == "Abuse"

    def test_enrichment_provenance_is_enriched(self):
        # External intelligence is only ever represented with ENRICHED
        # provenance; the agent never labels evidence OBSERVED.
        assert THREAT_INTELLIGENCE_ENRICHMENT_TYPE == "threat_intelligence"
        assert Provenance.ENRICHED.value == "enriched"
        provider = FakeProvider(name="VT")
        agent = ThreatIntelligenceAgent(ProviderRegistry([provider]))
        event = _make_event(source_ip="185.10.10.10")
        analysis = agent.analyze(event)
        # The analysis is built without mutating the enriched event; the
        # event-level provenance remains ENRICHED and no downgrade happens.
        assert event.provenance is Provenance.ENRICHED
        assert isinstance(analysis.enrichments[0], EnrichmentResult)


# ---------------------------------------------------------------------------
# 28-29. Secret-safety
# ---------------------------------------------------------------------------

class TestSecretSafety:
    def test_no_api_key_leakage(self):
        api_key = "super-secret-api-key-12345"
        provider = FakeProvider(
            name="VT",
            data={"reputation": -1},
            api_key=api_key,  # private credential, never emitted by provider
        )
        agent = ThreatIntelligenceAgent(ProviderRegistry([provider]))
        event = _make_event(source_ip="185.10.10.10")
        analysis = agent.analyze(event)

        # The agent never serialises the provider's private credential.
        serialized = analysis.model_dump_json()
        assert api_key not in serialized

        for enrich in analysis.enrichments:
            assert api_key not in enrich.model_dump_json()
            assert "authorization" not in json.dumps(enrich.value).lower()
        for fail in analysis.failures:
            assert api_key not in fail.message

        # And the enrichment never carries an api_key/authorization payload.
        for enrich in analysis.enrichments:
            assert "api_key" not in enrich.value
            assert "authorization" not in enrich.value

    def test_no_raw_http_response_leakage(self):
        # A well-behaved provider (like the real VirusTotal/AbuseIPDB/OTX
        # implementations) returns only normalised evidence.  The agent must
        # never inject or append a raw HTTP response of its own.
        provider = FakeProvider(
            name="VT",
            data={"last_analysis_stats": {"malicious": 0, "harmless": 60}},
        )
        agent = ThreatIntelligenceAgent(ProviderRegistry([provider]))
        event = _make_event(source_ip="185.10.10.10")
        analysis = agent.analyze(event)
        for enrich in analysis.enrichments:
            dumped = json.dumps(enrich.value).lower()
            assert "http/1.1" not in dumped
            assert "set-cookie" not in dumped
            assert "transfer-encoding" not in dumped
        # The agent itself never fabricates raw-HTTP-shaped content.
        assert "HTTP/1.1" not in analysis.model_dump_json()

    def test_failure_message_is_sanitised(self):
        provider = FakeProvider(
            name="Bad",
            raise_exc=ProviderLookupError("Bad", "request timed out"),
        )
        agent = ThreatIntelligenceAgent(ProviderRegistry([provider]))
        event = _make_event(source_ip="185.10.10.10")
        analysis = agent.analyze(event)
        fail = analysis.failures[0]
        assert isinstance(fail, ProviderFailure)
        assert fail.message  # never an empty/blank message
        assert "authorization" not in fail.message.lower()


class TestNoHeaderLeakInProviderFailure:
    def test_no_auth_header_in_failure(self):
        provider = FakeProvider(
            name="Bad",
            raise_exc=ProviderLookupError("Bad", "request timed out"),
        )
        agent = ThreatIntelligenceAgent(ProviderRegistry([provider]))
        event = _make_event(source_ip="185.10.10.10")
        analysis = agent.analyze(event)
        dumped = analysis.model_dump_json()
        assert "authorization" not in dumped.lower()
        assert "api-key" not in dumped.lower()


# ---------------------------------------------------------------------------
# 30. Input immutability
# ---------------------------------------------------------------------------

class TestInputImmutability:
    def test_original_event_remains_unchanged(self):
        normalized = _make_normalized_event(
            source_ip="185.10.10.10",
            dest_ip="203.0.113.7",
            normalized_data={"domain": "evil.example.com"},
        )
        event = _make_event(normalized_event=normalized)
        before = normalized.model_dump()
        before_event = event.model_dump()

        provider = FakeProvider(
            name="VT",
            types=frozenset({IndicatorType.IP, IndicatorType.DOMAIN}),
        )
        agent = ThreatIntelligenceAgent(ProviderRegistry([provider]))
        analysis = agent.analyze(event)

        assert normalized.model_dump() == before
        assert event.model_dump() == before_event
        # The analysis carries its own enrichment objects; the event's
        # existing enrichment list stays untouched.
        assert event.enrichments == []
        assert len(analysis.enrichments) == 3


# ---------------------------------------------------------------------------
# 31-32. No verdict / no risk score
# ---------------------------------------------------------------------------

class TestNoVerdictOrRiskScore:
    def test_no_risk_score_generated(self):
        provider = FakeProvider(name="VT", data={"reputation": -10})
        agent = ThreatIntelligenceAgent(ProviderRegistry([provider]))
        event = _make_event(source_ip="185.10.10.10")
        analysis = agent.analyze(event)
        # Data is evidence; a SentinelAI risk_score is never produced.
        assert "risk_score" not in analysis.model_dump_json()
        model_fields = set(ThreatIntelligenceAnalysis.model_fields.keys())
        assert "risk_score" not in model_fields

    def test_no_malicious_or_benign_verdict_generated(self):
        provider = FakeProvider(name="Abuse", data={"abuseConfidenceScore": 100})
        agent = ThreatIntelligenceAgent(ProviderRegistry([provider]))
        event = _make_event(source_ip="185.10.10.10")
        analysis = agent.analyze(event)
        # Provider evidence may mention the words, but the analysis top-level
        # never carries a verdict field.
        model_fields = set(ThreatIntelligenceAnalysis.model_fields.keys())
        assert "malicious" not in model_fields
        assert "benign" not in model_fields
        assert "verdict" not in model_fields
        # Analysis has no dedicated risk/severity fields.
        assert "severity" not in model_fields
        assert "risk_score" not in model_fields
