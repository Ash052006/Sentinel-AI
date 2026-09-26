"""Tests for the Threat Intelligence Agent contract (Step 8A).

Covers ExtractedIndicator validation, deterministic deduplication,
provider association and result traceability, ProviderFailure isolation,
enrichment representation, ENRICHED provenance, metadata validation,
input immutability expectations, serialization/deserialization, and
secret-safety.

These are pure unit tests of the **contract** — they use fakes/stubs and
perform **zero** real provider network calls.  No provider is queried
and no real HTTP request is ever made.
"""

import json
import uuid
from datetime import datetime, timezone

import pytest

from app.schemas.enriched_event import EnrichmentResult
from app.schemas.security_event import Provenance
from app.schemas.threat_intelligence_agent import (
    ExtractedIndicator,
    ProviderAssociation,
    ProviderFailure,
    ThreatIntelMetadata,
    ThreatIntelligenceAnalysis,
    THREAT_INTELLIGENCE_ENRICHMENT_TYPE,
    threat_intel_result_to_enrichment,
)
from app.services.threat_intelligence.base import ThreatIntelResult
from app.services.threat_intelligence.types import (
    IndicatorType,
    ThreatIndicator,
)

_FIXED_TS = datetime(2025, 8, 1, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Helpers (fakes only - no network)
# ---------------------------------------------------------------------------

def _indicator(
    itype: IndicatorType = IndicatorType.IP,
    value: str = "185.10.10.10",
    field: str = "source_endpoint.ip",
    context: str = "source_endpoint",
) -> ExtractedIndicator:
    return ExtractedIndicator(
        indicator=value,
        indicator_type=itype,
        source_field=field,
        source_context=context,
    )


def _result(
    *,
    itype: IndicatorType = IndicatorType.IP,
    value: str = "185.10.10.10",
    provider: str = "VirusTotal",
    found: bool = True,
    data: dict | None = None,
    confidence: float | None = None,
) -> ThreatIntelResult:
    return ThreatIntelResult(
        indicator=ThreatIndicator(indicator_type=itype, value=value),
        provider=provider,
        found=found,
        data=data or {},
        confidence=confidence,
        timestamp=_FIXED_TS,
    )


def _analysis(**overrides) -> ThreatIntelligenceAnalysis:
    """Create a minimal valid analysis for testing."""
    base: dict = {"event_id": uuid.uuid4()}
    base.update(overrides)
    return ThreatIntelligenceAnalysis(**base)


# ---------------------------------------------------------------------------
# ExtractedIndicator validation
# ---------------------------------------------------------------------------

class TestExtractedIndicatorValidation:
    """Tests 1-6: ExtractedIndicator validation."""

    def test_valid_ip_indicator(self):
        ind = _indicator()
        assert ind.indicator == "185.10.10.10"
        assert ind.indicator_type is IndicatorType.IP

    def test_valid_domain_indicator(self):
        ind = _indicator(IndicatorType.DOMAIN, "Example.COM")
        assert ind.indicator_type is IndicatorType.DOMAIN
        assert ind.indicator == "Example.COM"

    def test_valid_url_indicator(self):
        ind = _indicator(
            IndicatorType.URL,
            "https://evil.example/payload?id=1",
            field="normalized_data.url",
            context="url",
        )
        assert ind.indicator_type is IndicatorType.URL
        assert ind.indicator == "https://evil.example/payload?id=1"

    def test_valid_hash_indicator(self):
        ind = _indicator(
            IndicatorType.HASH,
            "AAF4C61DDCC5E8A2DABEDE0F3B482CD9AEA9434D",
            field="file.hash",
            context="file",
        )
        assert ind.indicator_type is IndicatorType.HASH

    def test_invalid_empty_indicator(self):
        with pytest.raises(ValueError):
            ExtractedIndicator(
                indicator="",
                indicator_type=IndicatorType.IP,
                source_field="source_endpoint.ip",
                source_context="source_endpoint",
            )

    def test_invalid_whitespace_indicator(self):
        with pytest.raises(ValueError):
            ExtractedIndicator(
                indicator="   ",
                indicator_type=IndicatorType.IP,
                source_field="source_endpoint.ip",
                source_context="source_endpoint",
            )


class TestSourceFieldPreservation:
    """Tests 7-8: source field and indicator type preservation."""

    def test_source_field_preservation(self):
        ind = _indicator(field="destination_endpoint.ip",
                         context="destination_endpoint")
        assert ind.source_field == "destination_endpoint.ip"
        assert ind.source_context == "destination_endpoint"

    def test_source_context_preserved(self):
        ind = _indicator(field="file.hash", context="file")
        assert ind.source_context == "file"

    def test_indicator_type_preserved(self):
        ind = _indicator(IndicatorType.HASH, "abc123def456")
        assert ind.indicator_type is IndicatorType.HASH
        assert ind.indicator_type.value == "hash"

    def test_blank_source_field_rejected(self):
        with pytest.raises(ValueError):
            ExtractedIndicator(
                indicator="8.8.8.8",
                indicator_type=IndicatorType.IP,
                source_field=" ",
                source_context="source_endpoint",
            )

    def test_blank_source_context_rejected(self):
        with pytest.raises(ValueError):
            ExtractedIndicator(
                indicator="8.8.8.8",
                indicator_type=IndicatorType.IP,
                source_field="source_endpoint.ip",
                source_context="",
            )


class TestDeduplication:
    """Tests 9-12: deterministic deduplication and normalization."""

    def test_deterministic_dedup_key(self):
        a = _indicator(IndicatorType.IP, "185.10.10.10")
        b = _indicator(IndicatorType.IP, "185.10.10.10")
        assert a.canonical_key == b.canonical_key == "ip:185.10.10.10"

    def test_same_indicator_from_multiple_fields_dedups(self):
        a = _indicator(
            IndicatorType.IP, "185.10.10.10", field="source_endpoint.ip",
        )
        b = _indicator(
            IndicatorType.IP, "185.10.10.10", field="destination_endpoint.ip",
        )
        assert a.canonical_key == b.canonical_key
        assert len({a.canonical_key, b.canonical_key}) == 1

    def test_domain_case_normalization(self):
        a = _indicator(IndicatorType.DOMAIN, "Example.COM")
        b = _indicator(IndicatorType.DOMAIN, "example.com")
        assert a.canonical_key == b.canonical_key == "domain:example.com"

    def test_hash_case_normalization(self):
        a = _indicator(IndicatorType.HASH, "ABC123")
        b = _indicator(IndicatorType.HASH, "abc123")
        assert a.canonical_key == b.canonical_key == "hash:abc123"

    def test_ip_kept_exact_no_destructive_norm(self):
        a = _indicator(IndicatorType.IP, "185.10.10.10")
        assert a.canonical_key == "ip:185.10.10.10"

    def test_url_not_modified_by_default(self):
        ind = _indicator(IndicatorType.URL, "https://Evil.Example/Path")
        # URL normalization is NOT performed here (only when explicitly
        # requested elsewhere); the canonical key keeps the exact value.
        assert ind.canonical_key == "url:https://Evil.Example/Path"

    def test_different_types_do_not_dedup(self):
        ip = _indicator(IndicatorType.IP, "185.10.10.10")
        dom = _indicator(IndicatorType.DOMAIN, "185.10.10.10")
        assert ip.canonical_key != dom.canonical_key


# ---------------------------------------------------------------------------
# ThreatIntelligenceAnalysis validation
# ---------------------------------------------------------------------------

class TestThreatIntelligenceAnalysis:
    """Tests 13-14: analysis model validation and event_id preservation."""

    def test_analysis_validation(self):
        eid = uuid.uuid4()
        analysis = _analysis(event_id=eid)
        assert analysis.event_id == eid
        assert analysis.indicators == []
        assert analysis.results == []
        assert analysis.failures == []
        assert analysis.enrichments == []

    def test_event_id_preserved(self):
        eid = uuid.uuid4()
        analysis = _analysis(event_id=eid)
        assert analysis.event_id == eid

    def test_analysis_requires_event_id(self):
        with pytest.raises(ValueError):
            ThreatIntelligenceAnalysis()

    def test_type_properties(self):
        analysis = _analysis()
        assert analysis.has_failures is False
        assert analysis.has_results is False

    def test_indicators_list_holding(self):
        analysis = _analysis(
            indicators=[
                _indicator(),
                _indicator(IndicatorType.DOMAIN, "x.com"),
            ]
        )
        assert len(analysis.indicators) == 2


class TestResultAssociation:
    """Test 15: result association (traceability)."""

    def test_result_association(self):
        ind = _indicator()
        result = _result()
        assoc = ProviderAssociation(
            indicator=ind, provider="VirusTotal", result=result,
        )
        assert assoc.indicator is ind
        assert assoc.provider == "VirusTotal"
        assert assoc.result is result

    def test_association_without_result(self):
        ind = _indicator()
        assoc = ProviderAssociation(indicator=ind, provider="VirusTotal")
        assert assoc.result is None

    def test_association_null_result_allowed(self):
        ind = _indicator()
        assoc = ProviderAssociation(
            indicator=ind, provider="OTX", result=None,
        )
        assert assoc.result is None


class TestProviderFailure:
    """Tests 16-17: ProviderFailure validation and isolation."""

    def test_provider_failure_validation(self):
        fail = ProviderFailure(
            provider="AbuseIPDB",
            indicator="185.10.10.10",
            indicator_type=IndicatorType.IP,
            error_type="timeout",
            message="request timed out",
            retryable=True,
        )
        assert fail.provider == "AbuseIPDB"
        assert fail.error_type == "timeout"
        assert fail.retryable is True

    def test_failure_isolation_representation(self):
        fail = ProviderFailure(
            provider="VirusTotal",
            indicator="8.8.8.8",
            indicator_type=IndicatorType.IP,
            error_type="http_error",
            message="HTTP 429",
            retryable=True,
        )
        assert fail.indicator == "8.8.8.8"
        assert fail.indicator_type is IndicatorType.IP

    def test_blank_provider_rejected(self):
        with pytest.raises(ValueError):
            ProviderFailure(
                provider=" ",
                indicator="8.8.8.8",
                indicator_type=IndicatorType.IP,
                error_type="timeout",
                message="x",
                retryable=False,
            )

    def test_blank_error_type_rejected(self):
        with pytest.raises(ValueError):
            ProviderFailure(
                provider="AbuseIPDB",
                indicator="8.8.8.8",
                indicator_type=IndicatorType.IP,
                error_type="",
                message="x",
                retryable=False,
            )


# ---------------------------------------------------------------------------
# Enrichment representation and provenance
# ---------------------------------------------------------------------------

class TestEnrichmentRepresentation:
    """Tests 18-19: enrichment representation and ENRICHED provenance."""

    def test_enrichment_representation(self):
        result = _result(
            provider="AlienVault OTX",
            data={"pulse_count": 4},
            confidence=0.80,
        )
        enrich = threat_intel_result_to_enrichment(result, as_of=_FIXED_TS)
        assert isinstance(enrich, EnrichmentResult)
        assert enrich.enrichment_type == THREAT_INTELLIGENCE_ENRICHMENT_TYPE
        assert enrich.source == "AlienVault OTX"
        assert enrich.value["indicator_type"] == "ip"
        assert enrich.value["indicator"] == "185.10.10.10"
        assert enrich.value["provider"] == "AlienVault OTX"
        assert enrich.value["found"] is True
        assert enrich.value["pulse_count"] == 4
        assert enrich.confidence == 0.80
        assert enrich.timestamp == _FIXED_TS

    def test_enriched_provenance_is_enriched(self):
        # External intelligence enrichment uses ENRICHED provenance and is
        # never labelled OBSERVED or RECONSTRUCTED.  The contract exposes
        # this via the constant and the conversion helper, which produces
        # EnrichmentResult objects meant to be attached with ENRICHED
        # event-level provenance.
        assert THREAT_INTELLIGENCE_ENRICHMENT_TYPE == "threat_intelligence"
        assert Provenance.ENRICHED.value == "enriched"
        assert Provenance.ENRICHED is not Provenance.OBSERVED
        assert Provenance.ENRICHED is not Provenance.RECONSTRUCTED

    def test_converted_enrichment_source_is_provider(self):
        result = _result(provider="VirusTotal", found=False, data={})
        enrich = threat_intel_result_to_enrichment(result, as_of=_FIXED_TS)
        assert enrich.source == "VirusTotal"
        assert enrich.value["found"] is False


class TestNoVerdictOrRiskScore:
    """Tests 20-21: the contract never fabricates verdicts or risk."""

    def test_no_final_verdict_field(self):
        analysis = _analysis()
        model_fields = set(ThreatIntelligenceAnalysis.model_fields.keys())
        assert "verdict" not in model_fields
        assert "malicious" not in model_fields
        assert "benign" not in model_fields
        dumped = analysis.model_dump()
        assert "verdict" not in dumped
        assert "risk_score" not in dumped

    def test_no_risk_score_field(self):
        model_fields = set(ThreatIntelligenceAnalysis.model_fields.keys())
        assert "risk_score" not in model_fields
        assert "score" not in model_fields

    def test_no_aggregated_confidence_field(self):
        model_fields = set(ThreatIntelligenceAnalysis.model_fields.keys())
        assert "confidence" not in model_fields


class TestMetadataValidation:
    """Test 22: metadata validation."""

    def test_metadata_fields(self):
        meta = ThreatIntelMetadata(
            providers_attempted=3,
            providers_succeeded=2,
            providers_failed=1,
            indicators_extracted=1,
            lookups_attempted=3,
            lookups_succeeded=2,
            lookups_failed=1,
        )
        assert meta.providers_attempted == 3
        assert meta.providers_failed == 1
        assert meta.lookups_attempted == 3

    def test_metadata_defaults_to_zero(self):
        meta = ThreatIntelMetadata()
        assert meta.providers_attempted == 0
        assert meta.lookups_succeeded == 0

    def test_metadata_rejects_negative(self):
        with pytest.raises(ValueError):
            ThreatIntelMetadata(lookups_attempted=-1)

    def test_metadata_default_in_analysis(self):
        analysis = _analysis()
        assert isinstance(analysis.metadata, ThreatIntelMetadata)
        assert analysis.metadata.providers_attempted == 0


# ---------------------------------------------------------------------------
# Immutability and serialization
# ---------------------------------------------------------------------------

class TestInputImmutability:
    """Test 23: input immutability expectations."""

    def test_conversion_does_not_mutate_source_result(self):
        result = _result(provider="VirusTotal", data={"detections": 8})
        original_data = dict(result.data)
        _ = threat_intel_result_to_enrichment(result)
        # The conversion must leave the source result untouched.
        assert result.data == original_data
        assert result.provider == "VirusTotal"

    def test_analysis_holds_not_rewrites_event_id(self):
        eid = uuid.uuid4()
        analysis = _analysis(event_id=eid)
        analysis2 = _analysis(event_id=eid)
        # Each analysis references the same event but never regenerates it.
        assert analysis.event_id == analysis2.event_id == eid


class TestSerialization:
    """Test 24: serialization/deserialization round trip."""

    def test_analysis_model_dump_and_validate(self):
        analysis = _analysis(
            indicators=[_indicator()],
            results=[
                ProviderAssociation(
                    indicator=_indicator(),
                    provider="VirusTotal",
                    result=_result(provider="VirusTotal"),
                )
            ],
            failures=[
                ProviderFailure(
                    provider="AbuseIPDB",
                    indicator="185.10.10.10",
                    indicator_type=IndicatorType.IP,
                    error_type="timeout",
                    message="timed out",
                    retryable=True,
                )
            ],
        )
        dumped = analysis.model_dump(mode="json")
        # JSON-serializable (via model_dump_json used by consumers).
        json.dumps(dumped)
        restored = ThreatIntelligenceAnalysis.model_validate(
            json.loads(json.dumps(dumped))
        )
        assert restored.event_id == analysis.event_id
        assert len(restored.indicators) == len(analysis.indicators)
        assert len(restored.results) == 1
        assert len(restored.failures) == 1
        assert restored.results[0].provider == "VirusTotal"

    def test_enrichment_serializes(self):
        result = _result(provider="OTX", data={"pulse_count": 2})
        enrich = threat_intel_result_to_enrichment(result, as_of=_FIXED_TS)
        dumped = enrich.model_dump_json()
        restored = EnrichmentResult.model_validate_json(dumped)
        assert restored.enrichment_type == THREAT_INTELLIGENCE_ENRICHMENT_TYPE
        assert restored.source == "OTX"


# ---------------------------------------------------------------------------
# Empty / failure-only / mixed representations
# ---------------------------------------------------------------------------

class TestEmptyRepresentation:
    """Tests 25-26: empty indicator list and empty results."""

    def test_empty_indicator_list(self):
        analysis = _analysis()
        assert analysis.indicators == []

    def test_empty_results(self):
        analysis = _analysis()
        assert analysis.results == []
        assert analysis.has_results is False

    def test_empty_failures(self):
        analysis = _analysis()
        assert analysis.failures == []
        assert analysis.has_failures is False

    def test_empty_enrichments(self):
        analysis = _analysis()
        assert analysis.enrichments == []


class TestFailureOnlyResult:
    """Test 27: provider failure-only result."""

    def test_failure_only_result(self):
        analysis = _analysis(
            failures=[
                ProviderFailure(
                    provider="VirusTotal",
                    indicator="8.8.8.8",
                    indicator_type=IndicatorType.IP,
                    error_type="timeout",
                    message="timed out",
                    retryable=True,
                )
            ]
        )
        assert analysis.has_failures is True
        assert analysis.has_results is False
        assert len(analysis.failures) == 1
        assert analysis.providers_failed == 1
        # The analysis itself does not fail despite provider failure.
        assert analysis.event_id is not None


class TestMixedSuccessFailure:
    """Test 28: mixed success/failure representation."""

    def test_mixed_success_and_failure(self):
        analysis = _analysis(
            indicators=[
                _indicator(),
                _indicator(IndicatorType.URL, "https://x.y"),
            ],
            results=[
                ProviderAssociation(
                    indicator=_indicator(),
                    provider="VirusTotal",
                    result=_result(provider="VirusTotal", found=True),
                ),
                ProviderAssociation(
                    indicator=_indicator(),
                    provider="OTX",
                    result=_result(provider="OTX", found=False),
                ),
            ],
            failures=[
                ProviderFailure(
                    provider="AbuseIPDB",
                    indicator="185.10.10.10",
                    indicator_type=IndicatorType.IP,
                    error_type="timeout",
                    message="timed out",
                    retryable=True,
                )
            ],
        )
        assert analysis.has_results is True
        assert analysis.has_failures is True
        assert len(analysis.results) == 2
        # Isolation: successes are kept alongside failures, none cascades.
        providers = {r.provider for r in analysis.results}
        assert "VirusTotal" in providers and "OTX" in providers
        assert len(analysis.failures) == 1


# ---------------------------------------------------------------------------
# Traceability
# ---------------------------------------------------------------------------

class TestTraceability:
    """Test 29: traceability across event -> indicator -> provider -> result."""

    def test_full_traceability_chain(self):
        eid = uuid.uuid4()
        ind = _indicator()
        result = _result(provider="VirusTotal", data={"detections": 5})
        assoc = ProviderAssociation(
            indicator=ind, provider="VirusTotal", result=result,
        )
        analysis = _analysis(event_id=eid, indicators=[ind], results=[assoc])

        # event -> indicator
        assert analysis.event_id == eid
        assert analysis.indicators[0].indicator == ind.indicator
        # indicator -> provider
        assert analysis.results[0].provider == "VirusTotal"
        # provider -> result, and result links back to the indicator value
        r = analysis.results[0].result
        assert r is not None
        assert r.indicator.value == ind.indicator
        assert r.indicator.indicator_type is ind.indicator_type
        assert r.provider == "VirusTotal"


# ---------------------------------------------------------------------------
# Secret-safety
# ---------------------------------------------------------------------------

class TestSecretSafety:
    """Test 30: secrets and API keys never appear in contract models."""

    def test_enrichment_value_has_no_api_key_secret(self):
        result = _result(
            provider="VirusTotal",
            data={"detections": 3},
            confidence=0.9,
        )
        enrich = threat_intel_result_to_enrichment(result, as_of=_FIXED_TS)
        serialized = json.dumps(enrich.value)
        assert "api_key" not in serialized.lower()
        assert "authorization" not in serialized.lower()
        assert "token" not in serialized.lower()
        assert "50673a0c4b5f" not in serialized

    def test_provider_failure_message_is_secret_safe(self):
        fail = ProviderFailure(
            provider="AbuseIPDB",
            indicator="8.8.8.8",
            indicator_type=IndicatorType.IP,
            error_type="http_error",
            message="HTTP 403",
            retryable=False,
        )
        ser = json.dumps(fail.model_dump())
        assert "api_key" not in ser.lower()
        assert "authorization" not in ser.lower()

    def test_metadata_and_failure_have_no_raw_response(self):
        meta = ThreatIntelMetadata(lookups_attempted=3)
        dumped = meta.model_dump()
        assert "api_key" not in json.dumps(dumped).lower()
        # raw HTTP response payloads are never stored in the contract model
        fields = self._field_keys()
        assert not any("raw" in _f for _f in fields)

    def test_provider_failure_has_no_authorization_field(self):
        model_fields = set(ProviderFailure.model_fields.keys())
        assert "api_key" not in model_fields
        assert "authorization" not in model_fields
        assert "headers" not in model_fields
        assert "token" not in model_fields

    @staticmethod
    def _field_keys():
        keys = set(ThreatIntelMetadata.model_fields.keys())
        keys |= set(ProviderFailure.model_fields.keys())
        keys |= set(ExtractedIndicator.model_fields.keys())
        keys |= set(ThreatIntelligenceAnalysis.model_fields.keys())
        keys |= set(ProviderAssociation.model_fields.keys())
        return keys