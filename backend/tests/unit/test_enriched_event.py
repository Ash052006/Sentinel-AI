"""Tests for the Enrichment Contract.

Covers EnrichmentResult and EnrichedSecurityEvent schemas including
validation, data integrity, immutability, and multiple-enrichment
scenarios.

These are pure unit tests — no database, Kafka, or network connections
required.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.agents.normalization import NormalizationAgent
from app.schemas.enriched_event import (
    EnrichedSecurityEvent,
    EnrichmentResult,
)
from app.schemas.normalized_event import (
    EventCategory,
    EventOutcome,
    NormalizedSecurityEvent,
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
_ENRICHMENT_TS = datetime(2025, 6, 15, 12, 5, 0, tzinfo=timezone.utc)

agent = NormalizationAgent()


def _make_security_event(**overrides) -> SecurityEvent:
    """Create a minimal SecurityEvent for testing."""
    base = {
        "timestamp": _FIXED_TS,
        "source": "windows",
        "source_type": SourceType.OPERATING_SYSTEM,
        "event_type": "authentication",
        "raw_data": {
            "TargetUserName": "admin",
            "IpAddress": "192.168.1.100",
            "Status": "0x0",
        },
        "provenance": Provenance.OBSERVED,
    }
    base.update(overrides)
    return SecurityEvent(**base)


def _make_normalized_event(**overrides) -> NormalizedSecurityEvent:
    """Create a NormalizedSecurityEvent via the normalization agent."""
    raw = overrides.pop("raw_data", None)
    if raw is not None:
        event = _make_security_event(raw_data=raw)
    else:
        event = _make_security_event()
    normalized = agent.normalize(event)
    for k, v in overrides.items():
        object.__setattr__(normalized, k, v)
    return normalized


def _make_enrichment(**overrides) -> EnrichmentResult:
    """Create a minimal valid EnrichmentResult for testing."""
    base = {
        "enrichment_type": "ip_reputation",
        "source": "VirusTotal",
        "value": {"reputation": "benign", "score": 2},
        "confidence": 0.94,
        "timestamp": _ENRICHMENT_TS,
    }
    base.update(overrides)
    return EnrichmentResult(**base)


def _make_enriched_event(**overrides) -> EnrichedSecurityEvent:
    """Create a minimal valid EnrichedSecurityEvent for testing."""
    normalized = overrides.pop("normalized_event", None)
    if normalized is None:
        normalized = _make_normalized_event()
    base = {
        "event_id": normalized.event_id,
        "timestamp": normalized.timestamp,
        "normalized_event": normalized,
        "enrichments": [],
        "provenance": Provenance.ENRICHED,
    }
    base.update(overrides)
    return EnrichedSecurityEvent(**base)


# ===========================================================================
# 1. EnrichmentResult — valid construction
# ===========================================================================

class TestEnrichmentResultValid:
    def test_creates_valid_enrichment(self):
        result = _make_enrichment()
        assert isinstance(result.enrichment_id, uuid.UUID)
        assert result.enrichment_type == "ip_reputation"
        assert result.source == "VirusTotal"
        assert result.value == {"reputation": "benign", "score": 2}
        assert result.confidence == 0.94
        assert result.timestamp == _ENRICHMENT_TS
        assert result.metadata is None

    def test_with_metadata(self):
        result = _make_enrichment(metadata={"ttl": 3600, "lookup_id": "abc123"})
        assert result.metadata == {"ttl": 3600, "lookup_id": "abc123"}

    def test_with_nested_value(self):
        value = {
            "country": "US",
            "city": "New York",
            "coordinates": {"lat": 40.7, "lon": -74.0},
            "as_info": {"asn": 15169, "org": "Google LLC"},
        }
        result = _make_enrichment(value=value)
        assert result.value["coordinates"]["lat"] == 40.7


# ===========================================================================
# 2. EnrichmentResult — required fields
# ===========================================================================

class TestEnrichmentResultRequired:
    def test_missing_enrichment_type_rejected(self):
        with pytest.raises(Exception):
            EnrichmentResult(
                source="VirusTotal",
                value={"reputation": "benign"},
                timestamp=_ENRICHMENT_TS,
            )

    def test_missing_source_rejected(self):
        with pytest.raises(Exception):
            EnrichmentResult(
                enrichment_type="ip_reputation",
                value={"reputation": "benign"},
                timestamp=_ENRICHMENT_TS,
            )

    def test_missing_value_rejected(self):
        with pytest.raises(Exception):
            EnrichmentResult(
                enrichment_type="ip_reputation",
                source="VirusTotal",
                timestamp=_ENRICHMENT_TS,
            )

    def test_missing_timestamp_rejected(self):
        with pytest.raises(Exception):
            EnrichmentResult(
                enrichment_type="ip_reputation",
                source="VirusTotal",
                value={"reputation": "benign"},
            )


# ===========================================================================
# 3. EnrichmentResult — UUID validation
# ===========================================================================

class TestEnrichmentResultUUID:
    def test_auto_generated_uuid(self):
        result = _make_enrichment()
        assert isinstance(result.enrichment_id, uuid.UUID)

    def test_explicit_uuid_accepted(self):
        explicit = uuid.uuid4()
        result = _make_enrichment(enrichment_id=explicit)
        assert result.enrichment_id == explicit

    def test_invalid_uuid_rejected(self):
        with pytest.raises(Exception):
            _make_enrichment(enrichment_id="not-a-uuid")

    def test_int_uuid_rejected(self):
        with pytest.raises(Exception):
            _make_enrichment(enrichment_id=12345)

    def test_unique_ids_across_results(self):
        ids = {_make_enrichment().enrichment_id for _ in range(20)}
        assert len(ids) == 20


# ===========================================================================
# 4. EnrichmentResult — timestamp validation
# ===========================================================================

class TestEnrichmentResultTimestamp:
    def test_utc_timestamp_accepted(self):
        result = _make_enrichment(timestamp=_ENRICHMENT_TS)
        assert result.timestamp == _ENRICHMENT_TS

    def test_offset_timestamp_accepted(self):
        tz_plus2 = timezone(timedelta(hours=2))
        ts = datetime(2025, 6, 15, 14, 0, 0, tzinfo=tz_plus2)
        result = _make_enrichment(timestamp=ts)
        assert result.timestamp.utcoffset() == timedelta(hours=2)

    def test_naive_timestamp_rejected(self):
        naive = datetime(2025, 6, 15, 12, 0, 0)
        with pytest.raises(Exception):
            _make_enrichment(timestamp=naive)


# ===========================================================================
# 5. EnrichmentResult — confidence boundaries
# ===========================================================================

class TestEnrichmentResultConfidence:
    def test_confidence_zero_accepted(self):
        result = _make_enrichment(confidence=0.0)
        assert result.confidence == 0.0

    def test_confidence_one_accepted(self):
        result = _make_enrichment(confidence=1.0)
        assert result.confidence == 1.0

    def test_confidence_midpoint_accepted(self):
        result = _make_enrichment(confidence=0.5)
        assert result.confidence == 0.5

    def test_confidence_none_accepted(self):
        result = _make_enrichment(confidence=None)
        assert result.confidence is None

    def test_confidence_below_minimum_rejected(self):
        with pytest.raises(Exception):
            _make_enrichment(confidence=-0.01)

    def test_confidence_above_maximum_rejected(self):
        with pytest.raises(Exception):
            _make_enrichment(confidence=1.01)

    def test_confidence_very_negative_rejected(self):
        with pytest.raises(Exception):
            _make_enrichment(confidence=-100.0)

    def test_confidence_very_large_rejected(self):
        with pytest.raises(Exception):
            _make_enrichment(confidence=999.0)


# ===========================================================================
# 6. EnrichmentResult — value and metadata validation
# ===========================================================================

class TestEnrichmentResultValueMetadata:
    def test_empty_dict_value_accepted(self):
        result = _make_enrichment(value={})
        assert result.value == {}

    def test_non_json_value_rejected(self):
        with pytest.raises(Exception):
            _make_enrichment(value={"key": object()})

    def test_non_dict_value_rejected(self):
        with pytest.raises(Exception):
            EnrichmentResult(
                enrichment_type="ip_reputation",
                source="VirusTotal",
                value="not a dict",
                timestamp=_ENRICHMENT_TS,
            )

    def test_nested_json_value_accepted(self):
        value = {"scores": {"a": 1, "b": [2, 3]}, "tags": ["malware"]}
        result = _make_enrichment(value=value)
        assert result.value["tags"] == ["malware"]

    def test_none_metadata_accepted(self):
        result = _make_enrichment()
        assert result.metadata is None

    def test_valid_metadata_accepted(self):
        result = _make_enrichment(metadata={"key": "value"})
        assert result.metadata == {"key": "value"}

    def test_empty_metadata_accepted(self):
        result = _make_enrichment(metadata={})
        assert result.metadata == {}

    def test_non_json_metadata_rejected(self):
        with pytest.raises(Exception):
            _make_enrichment(metadata={"key": object()})


# ===========================================================================
# 7. EnrichmentResult — serialization
# ===========================================================================

class TestEnrichmentResultSerialization:
    def test_model_dump_produces_dict(self):
        result = _make_enrichment()
        dumped = result.model_dump()
        assert dumped["enrichment_type"] == "ip_reputation"
        assert dumped["source"] == "VirusTotal"
        assert dumped["confidence"] == 0.94

    def test_roundtrip_preserves_all_fields(self):
        result = _make_enrichment(metadata={"ttl": 3600})
        dumped = result.model_dump()
        restored = EnrichmentResult.model_validate(dumped)
        assert restored.enrichment_id == result.enrichment_id
        assert restored.enrichment_type == result.enrichment_type
        assert restored.source == result.source
        assert restored.value == result.value
        assert restored.confidence == result.confidence
        assert restored.metadata == result.metadata

    def test_uuid_serializes_as_string_in_json_mode(self):
        result = _make_enrichment()
        dumped = result.model_dump(mode="json")
        assert isinstance(dumped["enrichment_id"], str)

    def test_roundtrip_preserves_confidence(self):
        result = _make_enrichment(confidence=0.87)
        dumped = result.model_dump()
        restored = EnrichmentResult.model_validate(dumped)
        assert restored.confidence == 0.87

    def test_roundtrip_preserves_none_confidence(self):
        result = _make_enrichment(confidence=None)
        dumped = result.model_dump()
        restored = EnrichmentResult.model_validate(dumped)
        assert restored.confidence is None

    def test_roundtrip_preserves_metadata(self):
        result = _make_enrichment(
            metadata={"key": "value", "nested": {"a": 1}}
        )
        dumped = result.model_dump()
        restored = EnrichmentResult.model_validate(dumped)
        assert restored.metadata == {"key": "value", "nested": {"a": 1}}


# ===========================================================================
# 8. EnrichmentResult — enrichment type examples
# ===========================================================================

class TestEnrichmentTypes:
    def test_ip_reputation_type(self):
        result = _make_enrichment(
            enrichment_type="ip_reputation",
            value={"reputation": "malicious", "abuse_confidence": 85},
        )
        assert result.enrichment_type == "ip_reputation"

    def test_geolocation_type(self):
        result = _make_enrichment(
            enrichment_type="geolocation",
            source="MaxMind GeoIP",
            value={"country": "RU", "city": "Moscow"},
        )
        assert result.enrichment_type == "geolocation"

    def test_domain_reputation_type(self):
        result = _make_enrichment(
            enrichment_type="domain_reputation",
            source="AlienVault OTX",
            value={"domain": "evil.example.com", "malware": True},
        )
        assert result.enrichment_type == "domain_reputation"

    def test_hash_reputation_type(self):
        result = _make_enrichment(
            enrichment_type="hash_reputation",
            source="VirusTotal",
            value={"detections": 45, "total_engines": 72},
        )
        assert result.enrichment_type == "hash_reputation"

    def test_user_context_type(self):
        result = _make_enrichment(
            enrichment_type="user_context",
            source="internal_asset_inventory",
            value={"department": "Engineering", "role": "admin"},
        )
        assert result.enrichment_type == "user_context"

    def test_asset_context_type(self):
        result = _make_enrichment(
            enrichment_type="asset_context",
            source="CMDB",
            value={"os": "Windows Server 2022", "criticality": "high"},
        )
        assert result.enrichment_type == "asset_context"


# ===========================================================================
# 9. EnrichedSecurityEvent — valid construction
# ===========================================================================

class TestEnrichedSecurityEventValid:
    def test_creates_valid_enriched_event(self):
        enriched = _make_enriched_event()
        assert isinstance(enriched.event_id, uuid.UUID)
        assert enriched.timestamp == _FIXED_TS
        assert isinstance(enriched.normalized_event, NormalizedSecurityEvent)
        assert enriched.enrichments == []
        assert enriched.provenance == Provenance.ENRICHED

    def test_has_enrichments_false_when_empty(self):
        enriched = _make_enriched_event()
        assert enriched.has_enrichments is False

    def test_has_enrichments_true_with_results(self):
        e = _make_enrichment()
        enriched = _make_enriched_event(enrichments=[e])
        assert enriched.has_enrichments is True


# ===========================================================================
# 10. EnrichedSecurityEvent — event ID preservation
# ===========================================================================

class TestEnrichedEventIDPreservation:
    def test_event_id_matches_normalized(self):
        normalized = _make_normalized_event()
        enriched = _make_enriched_event(normalized_event=normalized)
        assert enriched.event_id == normalized.event_id

    def test_event_id_not_regenerated(self):
        normalized = _make_normalized_event()
        explicit_id = normalized.event_id
        enriched = _make_enriched_event(normalized_event=normalized)
        assert enriched.event_id == explicit_id

    def test_event_id_differs_from_enrichment_id(self):
        e = _make_enrichment()
        enriched = _make_enriched_event(enrichments=[e])
        assert enriched.event_id != e.enrichment_id


# ===========================================================================
# 11. EnrichedSecurityEvent — timestamp preservation
# ===========================================================================

class TestEnrichedEventTimestamp:
    def test_timestamp_matches_normalized(self):
        normalized = _make_normalized_event()
        enriched = _make_enriched_event(normalized_event=normalized)
        assert enriched.timestamp == normalized.timestamp


# ===========================================================================
# 12. EnrichedSecurityEvent — normalized event preservation
# ===========================================================================

class TestEnrichedNormalizedEventPreservation:
    def test_normalized_event_preserved(self):
        normalized = _make_normalized_event()
        enriched = _make_enriched_event(normalized_event=normalized)
        assert enriched.normalized_event is normalized

    def test_normalized_event_category_preserved(self):
        normalized = _make_normalized_event()
        enriched = _make_enriched_event(normalized_event=normalized)
        assert enriched.normalized_event.event_category == EventCategory.AUTHENTICATION

    def test_normalized_event_outcome_preserved(self):
        normalized = _make_normalized_event()
        enriched = _make_enriched_event(normalized_event=normalized)
        assert enriched.normalized_event.outcome == EventOutcome.SUCCESS


# ===========================================================================
# 13. EnrichedSecurityEvent — empty/single/multiple enrichments
# ===========================================================================

class TestEnrichedEventEnrichmentLists:
    def test_default_enrichments_empty(self):
        normalized = _make_normalized_event()
        enriched = EnrichedSecurityEvent(
            event_id=normalized.event_id,
            timestamp=normalized.timestamp,
            normalized_event=normalized,
        )
        assert enriched.enrichments == []

    def test_single_enrichment_present(self):
        e = _make_enrichment()
        enriched = _make_enriched_event(enrichments=[e])
        assert len(enriched.enrichments) == 1
        assert enriched.enrichments[0].enrichment_type == "ip_reputation"

    def test_three_enrichments_coexist(self):
        e1 = _make_enrichment(
            enrichment_type="ip_reputation", source="VirusTotal",
            value={"reputation": "malicious"},
        )
        e2 = _make_enrichment(
            enrichment_type="geolocation", source="MaxMind GeoIP",
            value={"country": "RU"},
        )
        e3 = _make_enrichment(
            enrichment_type="domain_reputation", source="AlienVault OTX",
            value={"domain": "evil.example.com"},
        )
        enriched = _make_enriched_event(enrichments=[e1, e2, e3])
        assert len(enriched.enrichments) == 3
        assert enriched.enrichments[0].enrichment_type == "ip_reputation"
        assert enriched.enrichments[1].enrichment_type == "geolocation"
        assert enriched.enrichments[2].enrichment_type == "domain_reputation"

    def test_different_sources_preserved(self):
        e1 = _make_enrichment(source="VirusTotal")
        e2 = _make_enrichment(source="AbuseIPDB")
        e3 = _make_enrichment(source="AlienVault OTX")
        enriched = _make_enriched_event(enrichments=[e1, e2, e3])
        sources = [e.source for e in enriched.enrichments]
        assert sources == ["VirusTotal", "AbuseIPDB", "AlienVault OTX"]

    def test_independent_enrichment_ids(self):
        e1 = _make_enrichment()
        e2 = _make_enrichment()
        e3 = _make_enrichment()
        enriched = _make_enriched_event(enrichments=[e1, e2, e3])
        ids = {e.enrichment_id for e in enriched.enrichments}
        assert len(ids) == 3

    def test_enrichment_ids_differ_from_event_id(self):
        e1 = _make_enrichment()
        e2 = _make_enrichment()
        enriched = _make_enriched_event(enrichments=[e1, e2])
        for e in enriched.enrichments:
            assert e.enrichment_id != enriched.event_id

    def test_no_overwriting_between_enrichments(self):
        e1 = _make_enrichment(value={"reputation": "malicious", "score": 95})
        e2 = _make_enrichment(value={"country": "RU", "city": "Moscow"})
        enriched = _make_enriched_event(enrichments=[e1, e2])
        assert enriched.enrichments[0].value["reputation"] == "malicious"
        assert "country" not in enriched.enrichments[0].value
        assert enriched.enrichments[1].value["country"] == "RU"
        assert "reputation" not in enriched.enrichments[1].value

    def test_many_enrichments(self):
        enrichments = [
            _make_enrichment(enrichment_type=f"type_{i}", source=f"source_{i}")
            for i in range(50)
        ]
        enriched = _make_enriched_event(enrichments=enrichments)
        assert len(enriched.enrichments) == 50
        for i, e in enumerate(enriched.enrichments):
            assert e.enrichment_type == f"type_{i}"


# ===========================================================================
# 14. EnrichedSecurityEvent — provenance handling
# ===========================================================================

class TestEnrichedEventProvenance:
    def test_default_provenance_enriched(self):
        enriched = _make_enriched_event()
        assert enriched.provenance == Provenance.ENRICHED

    def test_normalized_provenance_observed_preserved(self):
        normalized = _make_normalized_event()
        assert normalized.provenance == Provenance.OBSERVED
        enriched = _make_enriched_event(normalized_event=normalized)
        assert enriched.normalized_event.provenance == Provenance.OBSERVED

    def test_normalized_provenance_enriched_preserved(self):
        normalized = _make_normalized_event()
        normalized.provenance = Provenance.ENRICHED
        enriched = _make_enriched_event(normalized_event=normalized)
        assert enriched.normalized_event.provenance == Provenance.ENRICHED

    def test_normalized_provenance_reconstructed_preserved(self):
        normalized = _make_normalized_event()
        normalized.provenance = Provenance.RECONSTRUCTED
        enriched = _make_enriched_event(normalized_event=normalized)
        assert enriched.normalized_event.provenance == Provenance.RECONSTRUCTED


# ===========================================================================
# 15. Data integrity — original normalized event is not mutated
# ===========================================================================

class TestDataIntegrity:
    def test_original_event_not_mutated_by_enrichment(self):
        normalized = _make_normalized_event()
        original_actor = normalized.actor
        original_endpoint = normalized.source_endpoint
        original_category = normalized.event_category
        original_outcome = normalized.outcome
        original_source = normalized.source
        original_source_type = normalized.source_type
        original_provenance = normalized.provenance
        original_event_id = normalized.event_id
        original_timestamp = normalized.timestamp
        original_data = dict(normalized.normalized_data)

        e = _make_enrichment()
        _make_enriched_event(normalized_event=normalized, enrichments=[e])

        assert normalized.actor == original_actor
        assert normalized.source_endpoint == original_endpoint
        assert normalized.event_category == original_category
        assert normalized.outcome == original_outcome
        assert normalized.source == original_source
        assert normalized.source_type == original_source_type
        assert normalized.provenance == original_provenance
        assert normalized.event_id == original_event_id
        assert normalized.timestamp == original_timestamp
        assert normalized.normalized_data == original_data

    def test_normalized_fields_unchanged_after_multiple_enrichments(self):
        normalized = _make_normalized_event()
        original_username = normalized.actor.username
        original_ip = normalized.source_endpoint.ip

        e1 = _make_enrichment(enrichment_type="ip_reputation")
        e2 = _make_enrichment(enrichment_type="geolocation")
        e3 = _make_enrichment(enrichment_type="asset_context")
        _make_enriched_event(
            normalized_event=normalized, enrichments=[e1, e2, e3]
        )
        assert normalized.actor.username == original_username
        assert normalized.source_endpoint.ip == original_ip

    def test_normalized_provenance_unchanged(self):
        normalized = _make_normalized_event()
        assert normalized.provenance == Provenance.OBSERVED
        e = _make_enrichment()
        _make_enriched_event(normalized_event=normalized, enrichments=[e])
        assert normalized.provenance == Provenance.OBSERVED

    def test_normalized_event_identity_preserved(self):
        normalized = _make_normalized_event()
        enriched = _make_enriched_event(normalized_event=normalized)
        assert enriched.normalized_event is normalized


# ===========================================================================
# 16. EnrichedSecurityEvent — required fields
# ===========================================================================

class TestEnrichedEventRequired:
    def test_missing_event_id_rejected(self):
        normalized = _make_normalized_event()
        with pytest.raises(Exception):
            EnrichedSecurityEvent(
                timestamp=normalized.timestamp,
                normalized_event=normalized,
            )

    def test_missing_timestamp_rejected(self):
        normalized = _make_normalized_event()
        with pytest.raises(Exception):
            EnrichedSecurityEvent(
                event_id=normalized.event_id,
                normalized_event=normalized,
            )

    def test_missing_normalized_event_rejected(self):
        normalized = _make_normalized_event()
        with pytest.raises(Exception):
            EnrichedSecurityEvent(
                event_id=normalized.event_id,
                timestamp=normalized.timestamp,
            )


# ===========================================================================
# 17. EnrichedSecurityEvent — validation
# ===========================================================================

class TestEnrichedEventValidation:
    def test_malformed_event_id_rejected(self):
        normalized = _make_normalized_event()
        with pytest.raises(Exception):
            EnrichedSecurityEvent(
                event_id="not-a-uuid",
                timestamp=normalized.timestamp,
                normalized_event=normalized,
            )

    def test_naive_timestamp_rejected(self):
        normalized = _make_normalized_event()
        naive = datetime(2025, 6, 15, 12, 0, 0)
        with pytest.raises(Exception):
            EnrichedSecurityEvent(
                event_id=normalized.event_id,
                timestamp=naive,
                normalized_event=normalized,
            )

    def test_invalid_provenance_rejected(self):
        normalized = _make_normalized_event()
        with pytest.raises(Exception):
            EnrichedSecurityEvent(
                event_id=normalized.event_id,
                timestamp=normalized.timestamp,
                normalized_event=normalized,
                provenance="invalid_provenance",
            )

    def test_invalid_normalized_event_rejected(self):
        with pytest.raises(Exception):
            EnrichedSecurityEvent(
                event_id=uuid.uuid4(),
                timestamp=_FIXED_TS,
                normalized_event="not a normalized event",
            )

    def test_invalid_enrichment_in_list_rejected(self):
        normalized = _make_normalized_event()
        with pytest.raises(Exception):
            EnrichedSecurityEvent(
                event_id=normalized.event_id,
                timestamp=normalized.timestamp,
                normalized_event=normalized,
                enrichments=["not an enrichment"],
            )


# ===========================================================================
# 18. EnrichedSecurityEvent — serialization
# ===========================================================================

class TestEnrichedEventSerialization:
    def test_model_dump_produces_dict(self):
        enriched = _make_enriched_event()
        dumped = enriched.model_dump()
        assert "event_id" in dumped
        assert "timestamp" in dumped
        assert "normalized_event" in dumped
        assert "enrichments" in dumped
        assert "provenance" in dumped

    def test_roundtrip_preserves_enrichments(self):
        e1 = _make_enrichment(enrichment_type="ip_reputation")
        e2 = _make_enrichment(enrichment_type="geolocation")
        enriched = _make_enriched_event(enrichments=[e1, e2])
        dumped = enriched.model_dump()
        restored = EnrichedSecurityEvent.model_validate(dumped)
        assert len(restored.enrichments) == 2
        assert restored.enrichments[0].enrichment_type == "ip_reputation"
        assert restored.enrichments[1].enrichment_type == "geolocation"

    def test_roundtrip_preserves_event_id(self):
        enriched = _make_enriched_event()
        dumped = enriched.model_dump()
        restored = EnrichedSecurityEvent.model_validate(dumped)
        assert restored.event_id == enriched.event_id

    def test_json_serializable(self):
        import json
        enriched = _make_enriched_event(enrichments=[_make_enrichment()])
        dumped = enriched.model_dump(mode="json")
        json_str = json.dumps(dumped)
        assert isinstance(json_str, str)

    def test_provenance_serializes_as_string(self):
        enriched = _make_enriched_event()
        dumped = enriched.model_dump()
        assert dumped["provenance"] == "enriched"

    def test_empty_enrichment_list_in_serialization(self):
        enriched = _make_enriched_event(enrichments=[])
        dumped = enriched.model_dump()
        assert dumped["enrichments"] == []
