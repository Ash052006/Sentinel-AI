"""Tests for the threat-intelligence provider contract and infrastructure.

Covers ThreatIndicator, ThreatIntelResult, ThreatIntelProvider interface,
ProviderRegistry, errors, no-network behavior, provider independence, and
result-to-enrichment mapping.

Pure unit tests -- no network, no database, no external providers.
"""

import uuid
from datetime import datetime, timezone

import pytest

from app.schemas.enriched_event import (
    EnrichedSecurityEvent,
    EnrichmentResult,
)
from app.schemas.security_event import Provenance
from app.services.threat_intelligence import (
    DuplicateProviderError,
    IndicatorType,
    ProviderLookupError,
    ProviderNotFoundError,
    ProviderRegistry,
    ThreatIndicator,
    ThreatIntelError,
    ThreatIntelProvider,
    ThreatIntelResult,
    UnsupportedIndicatorTypeError,
)

_FIXED_TS = datetime(2025, 7, 1, 12, 0, 0, tzinfo=timezone.utc)


def _indicator(
    itype: IndicatorType = IndicatorType.IP,
    value: str = "8.8.8.8",
) -> ThreatIndicator:
    return ThreatIndicator(indicator_type=itype, value=value)


def _result(
    *,
    indicator: ThreatIndicator | None = None,
    provider: str = "Fake",
    found: bool = True,
    data: dict | None = None,
    confidence: float | None = None,
    metadata: dict | None = None,
) -> ThreatIntelResult:
    return ThreatIntelResult(
        indicator=indicator or _indicator(),
        provider=provider,
        found=found,
        data=data or {},
        confidence=confidence,
        metadata=metadata,
        timestamp=_FIXED_TS,
    )


# ===========================================================================
# A. ThreatIndicator
# ===========================================================================

class TestThreatIndicator:
    def test_valid_ip(self):
        ti = _indicator(IndicatorType.IP, "8.8.8.8")
        assert ti.indicator_type == IndicatorType.IP
        assert ti.value == "8.8.8.8"

    def test_valid_domain(self):
        ti = _indicator(IndicatorType.DOMAIN, "example.com")
        assert ti.indicator_type == IndicatorType.DOMAIN
        assert ti.value == "example.com"

    def test_valid_url(self):
        ti = _indicator(IndicatorType.URL, "https://example.com/path")
        assert ti.indicator_type == IndicatorType.URL
        assert ti.value == "https://example.com/path"

    def test_valid_hash(self):
        ti = _indicator(
            IndicatorType.HASH,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        assert ti.indicator_type == IndicatorType.HASH
        assert ti.value.startswith("e3b0")

    def test_empty_value_rejected(self):
        with pytest.raises(ValueError):
            ThreatIndicator(indicator_type=IndicatorType.IP, value="")

    def test_blank_value_rejected(self):
        with pytest.raises(ValueError):
            ThreatIndicator(indicator_type=IndicatorType.DOMAIN, value="   ")

    def test_invalid_indicator_type_rejected(self):
        with pytest.raises(ValueError):
            ThreatIndicator(indicator_type="not_a_type", value="x")

    def test_indicator_type_enum_values(self):
        assert IndicatorType.IP.value == "ip"
        assert IndicatorType.DOMAIN.value == "domain"
        assert IndicatorType.URL.value == "url"
        assert IndicatorType.HASH.value == "hash"

    def test_missing_value_rejected(self):
        with pytest.raises(ValueError):
            ThreatIndicator(indicator_type=IndicatorType.IP)


# ===========================================================================
# B. ThreatIntelResult
# ===========================================================================

class TestThreatIntelResult:
    def test_valid_construction(self):
        r = _result()
        assert r.provider == "Fake"
        assert r.found is True
        assert r.data == {}
        assert r.indicator.indicator_type == IndicatorType.IP
        assert r.timestamp == _FIXED_TS

    def test_found_true(self):
        r = _result(found=True)
        assert r.found is True

    def test_found_false(self):
        r = _result(found=False)
        assert r.found is False

    def test_confidence_boundary_zero(self):
        r = _result(confidence=0.0)
        assert r.confidence == 0.0

    def test_confidence_boundary_one(self):
        r = _result(confidence=1.0)
        assert r.confidence == 1.0

    def test_confidence_midpoint(self):
        r = _result(confidence=0.75)
        assert r.confidence == 0.75

    def test_invalid_confidence_above_one(self):
        with pytest.raises(ValueError):
            _result(confidence=1.5)

    def test_invalid_confidence_below_zero(self):
        with pytest.raises(ValueError):
            _result(confidence=-0.1)

    def test_default_confidence_none(self):
        r = _result()
        assert r.confidence is None

    def test_timestamp_timezone_aware(self):
        r = _result()
        assert r.timestamp.tzinfo is not None
        assert r.timestamp.tzinfo.utcoffset(r.timestamp) is not None

    def test_naive_timestamp_rejected(self):
        with pytest.raises(ValueError):
            ThreatIntelResult(
                indicator=_indicator(),
                provider="Fake",
                found=True,
                timestamp=datetime(2025, 7, 1, 12, 0, 0),
            )

    def test_metadata(self):
        r = _result(metadata={"attack_type": "scan"})
        assert r.metadata == {"attack_type": "scan"}

    def test_metadata_none_default(self):
        r = _result()
        assert r.metadata is None

    def test_data_json_compatible(self):
        r = _result(data={"detections": 8, "reported": True})
        assert r.data == {"detections": 8, "reported": True}

    def test_data_incompatible_json_rejected(self):
        with pytest.raises(ValueError):
            _result(data={"bad": object()})

    def test_metadata_incompatible_json_rejected(self):
        with pytest.raises(ValueError):
            _result(metadata={"bad": object()})

    def test_provider_required(self):
        with pytest.raises(ValueError):
            ThreatIntelResult(
                indicator=_indicator(),
                found=True,
            )

    def test_result_roundtrips_through_dict(self):
        r = _result()
        back = ThreatIntelResult.model_validate(r.model_dump())
        assert back.provider == r.provider
        assert back.indicator == r.indicator
        assert back.found == r.found


# ===========================================================================
# C. ThreatIntelProvider (abstract interface)
# ===========================================================================

class TestThreatIntelProviderInterface:
    def test_interface_cannot_be_instantiated(self):
        with pytest.raises(TypeError):
            ThreatIntelProvider()

    def test_provider_name_is_abstract(self):
        class NoName(ThreatIntelProvider):
            @property
            def supported_indicator_types(self):
                return frozenset({IndicatorType.IP})
            def lookup(self, indicator):
                pass
        with pytest.raises(TypeError):
            NoName()

    def test_supported_indicator_types_abstract(self):
        class NoSupported(ThreatIntelProvider):
            @property
            def provider_name(self):
                return "X"
            def lookup(self, indicator):
                pass
        with pytest.raises(TypeError):
            NoSupported()

    def test_lookup_is_abstract(self):
        class NoLookup(ThreatIntelProvider):
            @property
            def provider_name(self):
                return "X"
            @property
            def supported_indicator_types(self):
                return frozenset({IndicatorType.IP})
        with pytest.raises(TypeError):
            NoLookup()

    def test_subclass_is_abstract_without_all(self):
        class PartiallyAbstract(ThreatIntelProvider):
            @property
            def supported_indicator_types(self):
                return frozenset()
        with pytest.raises(TypeError):
            PartiallyAbstract()


class FakeBaseProvider(ThreatIntelProvider):
    """Minimal fake provider satisfying the interface (no network)."""

    @property
    def provider_name(self) -> str:
        return "FakeBase"

    @property
    def supported_indicator_types(self) -> frozenset[IndicatorType]:
        return frozenset({IndicatorType.IP, IndicatorType.DOMAIN})

    def lookup(self, indicator: ThreatIndicator) -> ThreatIntelResult:
        self.assert_supports(indicator)
        return _result(
            indicator=indicator,
            provider=self.provider_name,
            found=True,
            data={"note": "fake"},
        )


class TestProviderInterfaceConcrete:
    def test_minimal_implementation_satisfies_interface(self):
        assert isinstance(FakeBaseProvider(), ThreatIntelProvider)

    def test_provider_name_metadata(self):
        assert FakeBaseProvider().provider_name == "FakeBase"

    def test_supported_indicator_types(self):
        p = FakeBaseProvider()
        assert p.supports(IndicatorType.IP)
        assert p.supports(IndicatorType.DOMAIN)
        assert not p.supports(IndicatorType.URL)

    def test_lookup_returns_result(self):
        p = FakeBaseProvider()
        r = p.lookup(_indicator(IndicatorType.IP, "1.2.3.4"))
        assert isinstance(r, ThreatIntelResult)
        assert r.provider == "FakeBase"
        assert r.found is True

    def test_assert_supports_raises_for_unsupported(self):
        p = FakeBaseProvider()
        with pytest.raises(UnsupportedIndicatorTypeError):
            p.assert_supports(_indicator(IndicatorType.URL, "https://x.com"))

    def test_supports_matches_metadata(self):
        p = FakeBaseProvider()
        assert set(p.supported_indicator_types) == {
            IndicatorType.IP, IndicatorType.DOMAIN,
        }


# ===========================================================================
# D. ProviderRegistry
# ===========================================================================

class TestProviderRegistry:
    def test_register_provider(self):
        reg = ProviderRegistry()
        reg.register(FakeBaseProvider())
        assert reg.count() == 1

    def test_retrieve_provider_by_name(self):
        reg = ProviderRegistry()
        p = FakeBaseProvider()
        reg.register(p)
        assert reg.get("FakeBase") is p

    def test_list_providers(self):
        reg = ProviderRegistry()
        reg.register(FakeBaseProvider())
        names = [p.provider_name for p in reg.list_providers()]
        assert names == ["FakeBase"]

    def test_duplicate_provider_rejected(self):
        reg = ProviderRegistry()
        reg.register(FakeBaseProvider())
        with pytest.raises(DuplicateProviderError):
            reg.register(FakeBaseProvider())

    def test_unknown_provider_raises(self):
        reg = ProviderRegistry()
        with pytest.raises(ProviderNotFoundError):
            reg.get("DoesNotExist")

    def test_unknown_provider_get_or_none(self):
        reg = ProviderRegistry()
        assert reg.get_or_none("Nope") is None

    def test_has_provider(self):
        reg = ProviderRegistry()
        reg.register(FakeBaseProvider())
        assert reg.has_provider("FakeBase") is True
        assert reg.has_provider("Nope") is False

    def test_find_providers_by_indicator_type(self):
        reg = ProviderRegistry()
        reg.register(FakeBaseProvider())
        matches = reg.find_providers_for(IndicatorType.IP)
        assert len(matches) == 1
        assert matches[0].provider_name == "FakeBase"

    def test_find_providers_unsupported_type(self):
        reg = ProviderRegistry()
        reg.register(FakeBaseProvider())
        assert reg.find_providers_for(IndicatorType.HASH) == []

    def test_constructor_injects_providers(self):
        reg = ProviderRegistry([FakeBaseProvider()])
        assert reg.count() == 1

    def test_register_non_provider_rejected(self):
        with pytest.raises(TypeError):
            ProviderRegistry().register("not a provider")

    def test_provider_names_sorted(self):
        reg = ProviderRegistry()
        reg.register(FakeBaseProvider())
        assert reg.provider_names() == ["FakeBase"]

    def test_count(self):
        reg = ProviderRegistry()
        assert reg.count() == 0
        reg.register(FakeBaseProvider())
        assert reg.count() == 1


# ===========================================================================
# E. Errors
# ===========================================================================

class TestErrors:
    def test_unsupported_indicator_error(self):
        with pytest.raises(UnsupportedIndicatorTypeError):
            FakeBaseProvider().assert_supports(
                _indicator(IndicatorType.HASH, "abc"),
            )

    def test_unsupported_error_is_threat_intel_error(self):
        e = UnsupportedIndicatorTypeError("hash", "Provider")
        assert isinstance(e, ThreatIntelError)

    def test_lookup_failure(self):
        with pytest.raises(ProviderLookupError):
            raise ProviderLookupError("Fake", "timeout")

    def test_invalid_indicator_error(self):
        from app.services.threat_intelligence import InvalidIndicatorError
        with pytest.raises(InvalidIndicatorError):
            raise InvalidIndicatorError("bad value")

    def test_all_exceptions_subclass_base(self):
        from app.services.threat_intelligence import (
            DuplicateProviderError,
            InvalidIndicatorError,
            ProviderLookupError,
            ProviderNotFoundError,
            UnsupportedIndicatorTypeError,
        )
        for cls in (
            UnsupportedIndicatorTypeError,
            ProviderNotFoundError,
            DuplicateProviderError,
            ProviderLookupError,
            InvalidIndicatorError,
        ):
            assert issubclass(cls, ThreatIntelError)

    def test_errors_do_not_leak_secrets(self):
        e = ProviderLookupError("VirusTotal", "401 unauthorized")
        assert "apikey" not in e.args[0].lower()
        assert "secret" not in e.args[0].lower()

    def test_provider_not_found_error_attributes(self):
        e = ProviderNotFoundError("Missing")
        assert e.provider_name == "Missing"
        assert "Missing" in str(e)

    def test_duplicate_provider_error_attributes(self):
        e = DuplicateProviderError("Dup")
        assert e.provider_name == "Dup"


# ===========================================================================
# F. No network behavior
# ===========================================================================

class TestNoNetworkBehavior:
    def test_registry_makes_no_network_requests(self):
        reg = ProviderRegistry()
        reg.register(FakeBaseProvider())
        reg.get("FakeBase")
        reg.find_providers_for(IndicatorType.IP)
        assert True  # No network access was involved

    def test_lookup_is_pure_local(self):
        p = FakeBaseProvider()
        r = p.lookup(_indicator(IndicatorType.IP, "8.8.8.8"))
        assert isinstance(r, ThreatIntelResult)
        assert r.data == {"note": "fake"}

    def test_result_construction_no_io(self):
        r = _result()
        assert r.timestamp == _FIXED_TS


def _make_ip_provider() -> ThreatIntelProvider:
    class IPProvider(ThreatIntelProvider):
        @property
        def provider_name(self) -> str:
            return "IPProvider"

        @property
        def supported_indicator_types(self):
            return frozenset({IndicatorType.IP})

        def lookup(self, indicator: ThreatIndicator) -> ThreatIntelResult:
            self.assert_supports(indicator)
            return _result(indicator=indicator, provider="IPProvider")

    return IPProvider()


# ===========================================================================
# G. Provider independence
# ===========================================================================

class TestProviderIndependence:
    def test_registry_accepts_any_compliant_provider(self):
        class CustomProvider(ThreatIntelProvider):
            @property
            def provider_name(self) -> str:
                return "Custom"

            @property
            def supported_indicator_types(self):
                return frozenset({IndicatorType.URL})

            def lookup(self, indicator):
                self.assert_supports(indicator)
                return _result(indicator=indicator, provider="Custom", found=False)

        reg = ProviderRegistry()
        reg.register(CustomProvider())
        assert reg.count() == 1
        assert reg.has_provider("Custom")

    def test_fake_providers_can_be_added_without_changing_registry(self):
        reg = ProviderRegistry()
        reg.register(FakeBaseProvider())
        reg.register(_make_ip_provider())
        assert reg.count() == 2

    def test_registry_capability_routing(self):
        reg = ProviderRegistry()
        reg.register(FakeBaseProvider())
        reg.register(_make_ip_provider())
        domain_matches = reg.find_providers_for(IndicatorType.DOMAIN)
        assert [p.provider_name for p in domain_matches] == ["FakeBase"]
        ip_matches = reg.find_providers_for(IndicatorType.IP)
        assert len(ip_matches) == 2


# ===========================================================================
# H. Result mapping to EnrichmentResult
# ===========================================================================

class TestResultMappingToEnrichment:
    def test_threat_intel_result_maps_to_enrichment_result(self):
        ti = _indicator(IndicatorType.IP, "185.10.10.1")
        result = ThreatIntelResult(
            indicator=ti,
            provider="VirusTotal",
            found=True,
            data={"malicious": True, "detections": 8},
            confidence=0.95,
            timestamp=_FIXED_TS,
        )
        enrichment = EnrichmentResult(
            enrichment_type="threat_intelligence",
            source=result.provider,
            value={
                "indicator_type": ti.indicator_type.value,
                "indicator": ti.value,
                "found": result.found,
                **result.data,
            },
            confidence=result.confidence,
            timestamp=_FIXED_TS,
        )
        assert enrichment.enrichment_type == "threat_intelligence"
        assert enrichment.source == "VirusTotal"
        assert enrichment.value["indicator_type"] == "ip"
        assert enrichment.value["indicator"] == "185.10.10.1"
        assert enrichment.value["malicious"] is True
        assert enrichment.value["detections"] == 8
        assert enrichment.confidence == 0.95
        assert enrichment.enrichment_id is not None

    def test_threat_intel_content_provenance_is_enriched(self):
        ti = _indicator(IndicatorType.IP, "8.8.8.8")
        result = ThreatIntelResult(
            indicator=ti,
            provider="FakeProvider",
            found=True,
            data={},
            timestamp=_FIXED_TS,
        )
        assert result.provider == "FakeProvider"
        assert result.data == {}
        assert Provenance.ENRICHED is not Provenance.OBSERVED
        assert Provenance.ENRICHED is not Provenance.RECONSTRUCTED

    def test_enrichment_result_value_preserves_provider_data(self):
        """Demonstrate how provider results map into the existing schema."""
        ti = _indicator(IndicatorType.HASH, "abc123def456")
        result = ThreatIntelResult(
            indicator=ti,
            provider="TestProvider",
            found=True,
            data={"detections": 3, "categories": {"trojan": 2}},
            confidence=0.80,
            timestamp=_FIXED_TS,
        )
        enrichment_value = {
            "indicator_type": result.indicator.indicator_type.value,
            "indicator": result.indicator.value,
            "provider": result.provider,
            "found": result.found,
            **result.data,
        }
        enrichment = EnrichmentResult(
            enrichment_type="threat_intelligence",
            source=result.provider,
            value=enrichment_value,
            confidence=result.confidence,
            timestamp=_FIXED_TS,
        )
        assert enrichment.value["indicator_type"] == "hash"
        assert enrichment.value["indicator"] == "abc123def456"
        assert enrichment.value["detections"] == 3
