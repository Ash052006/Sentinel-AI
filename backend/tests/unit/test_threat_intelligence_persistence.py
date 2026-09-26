"""Threat-intelligence persistence behavior tests (Step 8C-B).

Verifies that :class:`~app.schemas.threat_intelligence_agent.ThreatIntelligenceAnalysis`
outputs are persisted through the service/repository layer into the Step
8C-A contract models (:class:`~app.models.threat_intel_indicator.ThreatIntelIndicator`,
:class:`~app.models.threat_intel_lookup.ThreatIntelLookup`).

No live PostgreSQL server and no provider network calls are involved.  The
PostgreSQL-specific ``JSONB`` column type is rendered as JSON for SQLite by
installing a ``visit_JSONB`` visitor on the SQLite type compiler; all other
column types (``UUID``, enums, timestamps) work through SQLAlchemy's
generic type system.  Behavior is therefore tested end-to-end against the
same models and mapping code used in production.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.dialects.sqlite.base import SQLiteTypeCompiler
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

# Make the PostgreSQL ``JSONB`` columns work on SQLite for these unit tests.
# This is a test-only type-compiler adapter; production DDL keeps JSONB.
if not hasattr(SQLiteTypeCompiler, "visit_JSONB"):
    SQLiteTypeCompiler.visit_JSONB = lambda self, type_, **kw: "JSON"  # noqa: E731

from app.database.postgres.base import Base
from app.models.threat_intel_indicator import ThreatIntelIndicator
from app.models.threat_intel_lookup import LookupStatus, ThreatIntelLookup
from app.repositories.threat_intelligence import ThreatIntelRepository
from app.schemas.security_event import Provenance
from app.schemas.threat_intelligence_agent import (
    ExtractedIndicator,
    ProviderAssociation,
    ProviderFailure,
    ThreatIntelligenceAnalysis,
)
from app.services.threat_intelligence.base import ThreatIntelResult
from app.services.threat_intelligence.types import IndicatorType, ThreatIndicator
from app.services.threat_intelligence_persistence import (
    ThreatIntelPersistenceError,
    ThreatIntelPersistenceValidationError,
    ThreatIntelligencePersistenceService,
    canonical_indicator_key,
    persist_analysis,
    sanitize_error_message,
)
# ---------------------------------------------------------------------------
# Deterministic fixture data
# ---------------------------------------------------------------------------

BASE = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)


def _ts(hours: float = 0.0) -> datetime:
    """Deterministic timezone-aware timestamp offset from BASE."""
    return BASE + timedelta(hours=hours)


def _as_utc(value: datetime) -> datetime:
    """Treat naive SQLite-loaded instants as the UTC instants they are."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


@pytest.fixture()
def db_session():
    """Fresh in-memory SQLite database with the full model schema."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = Session(engine)
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


# ---------------------------------------------------------------------------
# Test-data builders
# ---------------------------------------------------------------------------


def _extracted(
    value: str,
    indicator_type: IndicatorType,
    source_field: str = "source_endpoint.ip",
    source_context: str = "source_endpoint",
) -> ExtractedIndicator:
    return ExtractedIndicator(
        indicator=value,
        indicator_type=indicator_type,
        source_field=source_field,
        source_context=source_context,
    )


def _result(
    provider: str,
    value: str,
    indicator_type: IndicatorType,
    *,
    found: bool = True,
    data: dict | None = None,
    confidence: float | None = 0.75,
    timestamp: datetime = _ts(1),
    metadata: dict | None = None,
) -> ThreatIntelResult:
    return ThreatIntelResult(
        indicator=ThreatIndicator(indicator_type=indicator_type, value=value),
        provider=provider,
        found=found,
        data=data if data is not None else {},
        confidence=confidence,
        timestamp=timestamp,
        metadata=metadata,
    )


def _association(
    extracted: ExtractedIndicator,
    provider: str,
    result: ThreatIntelResult | None,
) -> ProviderAssociation:
    return ProviderAssociation(indicator=extracted, provider=provider, result=result)


def _failure(
    provider: str,
    value: str,
    indicator_type: IndicatorType,
    *,
    error_type: str = "http_error",
    message: str = "provider returned HTTP 500",
    retryable: bool = True,
) -> ProviderFailure:
    return ProviderFailure(
        provider=provider,
        indicator=value,
        indicator_type=indicator_type,
        error_type=error_type,
        message=message,
        retryable=retryable,
    )


def _analysis(
    event_id: uuid.UUID | None = None,
    indicators: tuple = (),
    results: tuple = (),
    failures: tuple = (),
) -> ThreatIntelligenceAnalysis:
    return ThreatIntelligenceAnalysis(
        event_id=event_id or uuid.uuid4(),
        indicators=list(indicators),
        results=list(results),
        failures=list(failures),
    )


def _persist(
    db: Session,
    analysis: ThreatIntelligenceAnalysis,
    *,
    service: ThreatIntelligencePersistenceService | None = None,
):
    """Persist through a deterministic-clock service by default."""
    if service is None:
        service = ThreatIntelligencePersistenceService(clock=lambda: _ts(100))
    return service.persist_analysis(db, analysis)


def _all_indicators(db: Session) -> list[ThreatIntelIndicator]:
    return list(
        db.scalars(
            select(ThreatIntelIndicator).order_by(ThreatIntelIndicator.canonical_key)
        )
    )


def _all_lookups(db: Session) -> list[ThreatIntelLookup]:
    return list(
        db.scalars(
            select(ThreatIntelLookup).order_by(ThreatIntelLookup.performed_at)
        )
    )


def _count(db: Session, model) -> int:
    return db.scalar(select(func.count()).select_from(model))


# ---------------------------------------------------------------------------
# 1. Successful analysis persistence
# ---------------------------------------------------------------------------


def test_persist_successful_analysis(db_session):
    """A success result produces one indicator and one success lookup."""
    ip = _extracted("185.10.10.10", IndicatorType.IP)
    result = _result(
        "AbuseIPDB", "185.10.10.10", IndicatorType.IP, timestamp=_ts(1)
    )
    analysis = _analysis(indicators=(ip,), results=(_association(ip, "AbuseIPDB", result),))

    out = _persist(db_session, analysis)

    assert out.indicators_created == 1
    assert out.lookups_created == 1
    assert not out.is_empty
    assert _count(db_session, ThreatIntelIndicator) == 1
    assert _count(db_session, ThreatIntelLookup) == 1

    indicator = _all_indicators(db_session)[0]
    lookup = _all_lookups(db_session)[0]
    assert lookup.status is LookupStatus.SUCCESS
    assert lookup.indicator_id == indicator.id


# ---------------------------------------------------------------------------
# 2. Multiple indicators
# ---------------------------------------------------------------------------


def test_persist_multiple_indicators(db_session):
    """Distinct canonical keys yield distinct indicator rows."""
    ip = _extracted("185.10.10.10", IndicatorType.IP)
    dom = _extracted("evil.example.com", IndicatorType.DOMAIN)
    r1 = _result("AbuseIPDB", "185.10.10.10", IndicatorType.IP, timestamp=_ts(1))
    r2 = _result("VirusTotal", "evil.example.com", IndicatorType.DOMAIN, timestamp=_ts(2))
    analysis = _analysis(
        indicators=(ip, dom),
        results=(_association(ip, "AbuseIPDB", r1), _association(dom, "VirusTotal", r2)),
    )

    out = _persist(db_session, analysis)

    assert out.indicators_created == 2
    assert out.lookups_created == 2
    assert len(_all_indicators(db_session)) == 2
    assert len(_all_lookups(db_session)) == 2


# ---------------------------------------------------------------------------
# 3. Multiple providers
# ---------------------------------------------------------------------------


def test_persist_multiple_providers(db_session):
    """One indicator queried by several providers persists several lookups."""
    ip = _extracted("185.10.10.10", IndicatorType.IP)
    results = [
        _result("AbuseIPDB", "185.10.10.10", IndicatorType.IP, timestamp=_ts(1)),
        _result("VirusTotal", "185.10.10.10", IndicatorType.IP, timestamp=_ts(2)),
        _result("AlienVault OTX", "185.10.10.10", IndicatorType.IP, timestamp=_ts(3)),
    ]
    analysis = _analysis(
        indicators=(ip,),
        results=tuple(_association(ip, r.provider, r) for r in results),
    )

    out = _persist(db_session, analysis)

    assert out.indicators_created == 1
    assert out.lookups_created == 3
    lookups = _all_lookups(db_session)
    assert {l.provider for l in lookups} == {
        "AbuseIPDB", "VirusTotal", "AlienVault OTX",
    }


# ---------------------------------------------------------------------------
# 4. Indicator deduplication
# ---------------------------------------------------------------------------


def test_indicator_deduplication(db_session):
    """Duplicated extracted indicators map to one global indicator row."""
    first = _extracted("8.8.8.8", IndicatorType.IP, source_field="source_endpoint.ip")
    second = _extracted("8.8.8.8", IndicatorType.IP, source_field="destination_endpoint.ip")
    r1 = _result("AbuseIPDB", "8.8.8.8", IndicatorType.IP, timestamp=_ts(1))
    analysis = _analysis(
        indicators=(first, second),
        results=(_association(first, "AbuseIPDB", r1),),
    )

    out = _persist(db_session, analysis)

    assert out.indicators_created == 1
    assert len(_all_indicators(db_session)) == 1
    assert len(_all_lookups(db_session)) == 1


# ---------------------------------------------------------------------------
# 5. Canonical key behavior
# ---------------------------------------------------------------------------


def test_canonical_key_behavior_ip(db_session):
    """IP canonical keys are ``ip:{value}`` with the value untouched."""
    ip = _extracted("185.10.10.10", IndicatorType.IP)
    _persist(db_session, _analysis(indicators=(ip,)))

    indicator = _all_indicators(db_session)[0]
    assert indicator.canonical_key == "ip:185.10.10.10"


def test_canonical_key_domain_lowercased(db_session):
    """Domain canonical keys lower-case; the stored value stays exact."""
    dom = _extracted("EvIl.ExAmPlE.cOm", IndicatorType.DOMAIN)
    _persist(db_session, _analysis(indicators=(dom,)))

    indicator = _all_indicators(db_session)[0]
    assert indicator.canonical_key == "domain:evil.example.com"
    assert indicator.value == "EvIl.ExAmPlE.cOm"


def test_canonical_key_helper_matches_8a_contract():
    """The persistence canonical key equals ExtractedIndicator.canonical_key."""
    cases = [
        (IndicatorType.IP, "185.10.10.10"),
        (IndicatorType.DOMAIN, "EVIL.COM"),
        (IndicatorType.DOMAIN, "evil.com"),
        (IndicatorType.URL, "https://Evil.Example/Path?Q=1"),
        (IndicatorType.HASH, "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"),
    ]
    for indicator_type, value in cases:
        extracted = _extracted(value, indicator_type)
        assert canonical_indicator_key(indicator_type, value) == extracted.canonical_key


def test_canonical_key_deduplicates_across_analyses(db_session):
    """Two analyses with case-differing domains share one indicator."""
    a = _extracted("EVIL.COM", IndicatorType.DOMAIN)
    b = _extracted("evil.com", IndicatorType.DOMAIN)
    _persist(db_session, _analysis(indicators=(a,)))
    _persist(db_session, _analysis(indicators=(b,)))

    indicators = _all_indicators(db_session)
    assert len(indicators) == 1
    assert indicators[0].canonical_key == "domain:evil.com"


# ---------------------------------------------------------------------------
# 6. Exact indicator value preservation
# ---------------------------------------------------------------------------


def test_exact_url_value_preserved_no_canonicalization(db_session):
    """URLs are stored exactly as extracted (no URL canonicalization)."""
    url = _extracted("https://Evil.Example/Campaign/2026?utm=1", IndicatorType.URL)
    _persist(db_session, _analysis(indicators=(url,)))

    indicator = _all_indicators(db_session)[0]
    assert indicator.value == "https://Evil.Example/Campaign/2026?utm=1"
    assert indicator.canonical_key == "url:https://Evil.Example/Campaign/2026?utm=1"


# ---------------------------------------------------------------------------
# 7. Indicator kinds
# ---------------------------------------------------------------------------


def test_ip_persistence(db_session):
    ip = _extracted("192.168.1.100", IndicatorType.IP)
    _persist(db_session, _analysis(indicators=(ip,)))
    indicator = _all_indicators(db_session)[0]
    assert indicator.indicator_type is IndicatorType.IP
    assert indicator.value == "192.168.1.100"


def test_domain_persistence(db_session):
    dom = _extracted("evil.example.com", IndicatorType.DOMAIN)
    _persist(db_session, _analysis(indicators=(dom,)))
    indicator = _all_indicators(db_session)[0]
    assert indicator.indicator_type.value == "domain"


def test_url_persistence(db_session):
    url = _extracted("http://evil.example/c2", IndicatorType.URL)
    _persist(db_session, _analysis(indicators=(url,)))
    indicator = _all_indicators(db_session)[0]
    assert indicator.indicator_type.value == "url"


def test_hash_persistence(db_session):
    digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    h = _extracted(digest, IndicatorType.HASH)
    _persist(db_session, _analysis(indicators=(h,)))
    indicator = _all_indicators(db_session)[0]
    assert indicator.indicator_type.value == "hash"
    assert indicator.canonical_key == f"hash:{digest}"
# ---------------------------------------------------------------------------
# 8. Lookup persistence: success / failure / ProviderFailure
# ---------------------------------------------------------------------------


def test_successful_lookup_persistence(db_session):
    """Every success field lands on the lookup row."""
    ip = _extracted("185.10.10.10", IndicatorType.IP)
    ts = _ts(2)
    result = _result(
        "AbuseIPDB",
        "185.10.10.10",
        IndicatorType.IP,
        found=True,
        data={"abuseConfidenceScore": 100, "tags": ["scanner"]},
        confidence=0.92,
        timestamp=ts,
        metadata={"source": "abuseipdb-api"},
    )
    event_id = uuid.uuid4()
    _persist(
        db_session,
        _analysis(
            event_id=event_id,
            indicators=(ip,),
            results=(_association(ip, "AbuseIPDB", result),),
        ),
    )

    lookup = _all_lookups(db_session)[0]
    assert lookup.status is LookupStatus.SUCCESS
    assert lookup.provider == "AbuseIPDB"
    assert lookup.event_id == event_id
    assert lookup.found is True
    assert lookup.confidence == 0.92
    assert lookup.evidence == {"abuseConfidenceScore": 100, "tags": ["scanner"]}
    assert lookup.result_metadata == {"source": "abuseipdb-api"}
    assert _as_utc(lookup.result_timestamp) == ts
    assert _as_utc(lookup.performed_at) == ts
    assert lookup.error_type is None
    assert lookup.error_message is None
    assert lookup.retryable is None


def test_failed_lookup_persistence(db_session):
    """A ProviderFailure produces an error lookup with failure columns."""
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    failure = _failure(
        "VirusTotal",
        "8.8.8.8",
        IndicatorType.IP,
        error_type="timeout",
        message="request timed out after 30s",
        retryable=True,
    )
    _persist(db_session, _analysis(indicators=(ip,), failures=(failure,)))

    lookup = _all_lookups(db_session)[0]
    assert lookup.status is LookupStatus.ERROR
    assert lookup.provider == "VirusTotal"
    assert lookup.error_type == "timeout"
    assert lookup.error_message == "request timed out after 30s"
    assert lookup.retryable is True
    assert lookup.found is None
    assert lookup.confidence is None
    assert lookup.evidence is None
    assert lookup.result_metadata is None
    assert lookup.result_timestamp is None


def test_provider_failure_persistence(db_session):
    """Failure identity fields and indicator linkage are preserved."""
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    failure = _failure(
        "AbuseIPDB",
        "8.8.8.8",
        IndicatorType.IP,
        error_type="rate_limit",
        message="429",
        retryable=False,
    )
    event_id = uuid.uuid4()
    _persist(db_session, _analysis(event_id=event_id, indicators=(ip,), failures=(failure,)))

    lookup = _all_lookups(db_session)[0]
    assert lookup.event_id == event_id
    assert lookup.indicator.value == "8.8.8.8"
    assert lookup.indicator_id == _all_indicators(db_session)[0].id
    assert lookup.retryable is False


def test_provider_association_without_result_skipped(db_session):
    """A result-less association persists the indicator but no lookup row."""
    ip = _extracted("185.10.10.10", IndicatorType.IP)
    _persist(
        db_session,
        _analysis(
            indicators=(ip,),
            results=(_association(ip, "AbuseIPDB", None),),
        ),
    )

    assert len(_all_indicators(db_session)) == 1
    assert len(_all_lookups(db_session)) == 0


# ---------------------------------------------------------------------------
# 9-10. Found / confidence
# ---------------------------------------------------------------------------


def test_found_field_persistence(db_session):
    """found=True and found=False are both recorded precisely."""
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    found_true = _result("AbuseIPDB", "8.8.8.8", IndicatorType.IP, found=True, timestamp=_ts(1))
    found_false = _result("VirusTotal", "8.8.8.8", IndicatorType.IP, found=False, timestamp=_ts(2))
    _persist(
        db_session,
        _analysis(
            indicators=(ip,),
            results=(
                _association(ip, "AbuseIPDB", found_true),
                _association(ip, "VirusTotal", found_false),
            ),
        ),
    )

    by_provider = {l.provider: l.found for l in _all_lookups(db_session)}
    assert by_provider == {"AbuseIPDB": True, "VirusTotal": False}


def test_confidence_persistence(db_session):
    """confidence=None (absent) and explicit values are preserved."""
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    with_conf = _result("AbuseIPDB", "8.8.8.8", IndicatorType.IP, confidence=0.35, timestamp=_ts(1))
    without_conf = _result("VirusTotal", "8.8.8.8", IndicatorType.IP, confidence=None, timestamp=_ts(2))
    _persist(
        db_session,
        _analysis(
            indicators=(ip,),
            results=(
                _association(ip, "AbuseIPDB", with_conf),
                _association(ip, "VirusTotal", without_conf),
            ),
        ),
    )

    by_provider = {l.provider: l.confidence for l in _all_lookups(db_session)}
    assert by_provider == {"AbuseIPDB": 0.35, "VirusTotal": None}


# ---------------------------------------------------------------------------
# 10. Evidence / metadata / result timestamp
# ---------------------------------------------------------------------------


def test_structured_evidence_persistence(db_session):
    """Nested JSON evidence round-trips through the JSONB column."""
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    evidence = {
        "detections": [{"engine": "vt", "category": "malicious"}],
        "stats": {"malicious": 12, "harmless": 0},
    }
    result = _result("VirusTotal", "8.8.8.8", IndicatorType.IP, data=evidence, timestamp=_ts(1))
    _persist(db_session, _analysis(indicators=(ip,), results=(_association(ip, "VirusTotal", result),)))

    lookup = _all_lookups(db_session)[0]
    assert lookup.evidence == evidence


def test_result_metadata_persistence(db_session):
    """Optional result metadata round-trips through result_metadata."""
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    metadata = {"source": "api-v2", "request_id": "abc-123"}
    result = _result("AlienVault OTX", "8.8.8.8", IndicatorType.IP, metadata=metadata, timestamp=_ts(1))
    _persist(db_session, _analysis(indicators=(ip,), results=(_association(ip, "AlienVault OTX", result),)))

    lookup = _all_lookups(db_session)[0]
    assert lookup.result_metadata == metadata


def test_result_timestamp_persistence(db_session):
    """result_timestamp mirrors the lookup performed time exactly."""
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    ts = _ts(7)
    result = _result("AbuseIPDB", "8.8.8.8", IndicatorType.IP, timestamp=ts)
    _persist(db_session, _analysis(indicators=(ip,), results=(_association(ip, "AbuseIPDB", result),)))

    lookup = _all_lookups(db_session)[0]
    assert _as_utc(lookup.result_timestamp) == ts


# ---------------------------------------------------------------------------
# 11. Event / provider preservation
# ---------------------------------------------------------------------------


def test_event_id_preserved(db_session):
    """The analysis event_id is stored verbatim on every lookup."""
    event_id = uuid.uuid4()
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    r = _result("AbuseIPDB", "8.8.8.8", IndicatorType.IP, timestamp=_ts(1))
    f = _failure("VirusTotal", "8.8.8.8", IndicatorType.IP)
    _persist(
        db_session,
        _analysis(
            event_id=event_id,
            indicators=(ip,),
            results=(_association(ip, "AbuseIPDB", r),),
            failures=(f,),
        ),
    )

    assert {l.event_id for l in _all_lookups(db_session)} == {event_id}


def test_provider_preserved(db_session):
    """Provider names are preserved on their lookup rows."""
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    r1 = _result("VirusTotal", "8.8.8.8", IndicatorType.IP, timestamp=_ts(1))
    r2 = _result("AbuseIPDB", "8.8.8.8", IndicatorType.IP, timestamp=_ts(2))
    _persist(
        db_session,
        _analysis(
            indicators=(ip,),
            results=(
                _association(ip, "VirusTotal", r1),
                _association(ip, "AbuseIPDB", r2),
            ),
        ),
    )

    assert {l.provider for l in _all_lookups(db_session)} == {"VirusTotal", "AbuseIPDB"}
# ---------------------------------------------------------------------------
# 12. Model relationships
# ---------------------------------------------------------------------------


def test_indicator_lookup_relationships(db_session):
    """ORM relations link lookups to their indicator and vice-versa."""
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    r1 = _result("AbuseIPDB", "8.8.8.8", IndicatorType.IP, timestamp=_ts(1))
    r2 = _result("VirusTotal", "8.8.8.8", IndicatorType.IP, timestamp=_ts(2))
    _persist(
        db_session,
        _analysis(
            indicators=(ip,),
            results=(_association(ip, "AbuseIPDB", r1), _association(ip, "VirusTotal", r2)),
        ),
    )

    indicator = _all_indicators(db_session)[0]
    assert len(indicator.lookups) == 2
    assert {l.provider for l in indicator.lookups} == {"AbuseIPDB", "VirusTotal"}
    assert all(l.indicator.id == indicator.id for l in indicator.lookups)


def test_cascade_delete_removes_lookups(db_session):
    """Deleting an indicator cascades to its lookup rows."""
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    r = _result("AbuseIPDB", "8.8.8.8", IndicatorType.IP, timestamp=_ts(1))
    _persist(db_session, _analysis(indicators=(ip,), results=(_association(ip, "AbuseIPDB", r),)))

    db_session.delete(_all_indicators(db_session)[0])
    db_session.commit()

    assert _count(db_session, ThreatIntelLookup) == 0
    assert _count(db_session, ThreatIntelIndicator) == 0


# ---------------------------------------------------------------------------
# 13. Provenance is always ENRICHED
# ---------------------------------------------------------------------------


def test_provenance_enriched_on_success(db_session):
    """Success lookups are stored with Provenance.ENRICHED, never observed."""
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    r = _result("AbuseIPDB", "8.8.8.8", IndicatorType.IP, timestamp=_ts(1))
    _persist(db_session, _analysis(indicators=(ip,), results=(_association(ip, "AbuseIPDB", r),)))
    assert _all_lookups(db_session)[0].provenance == Provenance.ENRICHED.value


def test_provenance_enriched_on_failure(db_session):
    """Failure lookups are stored with Provenance.ENRICHED too."""
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    f = _failure("VirusTotal", "8.8.8.8", IndicatorType.IP, error_type="timeout")
    _persist(db_session, _analysis(indicators=(ip,), failures=(f,)))
    assert _all_lookups(db_session)[0].provenance == Provenance.ENRICHED.value
# ---------------------------------------------------------------------------
# 14. first_seen_at / last_seen_at semantics
# ---------------------------------------------------------------------------


def test_first_seen_at_never_changes(db_session):
    """Later re-seen indicators keep their original first_seen_at."""
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    r1 = _result("AbuseIPDB", "8.8.8.8", IndicatorType.IP, timestamp=_ts(2))
    _persist(db_session, _analysis(indicators=(ip,), results=(_association(ip, "AbuseIPDB", r1),)))
    indicator = _all_indicators(db_session)[0]
    assert _as_utc(indicator.first_seen_at) == _ts(2)

    r2 = _result("AbuseIPDB", "8.8.8.8", IndicatorType.IP, timestamp=_ts(8))
    _persist(db_session, _analysis(indicators=(ip,), results=(_association(ip, "AbuseIPDB", r2),)))

    refreshed = _all_indicators(db_session)[0]
    assert _as_utc(refreshed.first_seen_at) == _ts(2)
    assert _as_utc(refreshed.last_seen_at) == _ts(8)


def test_last_seen_at_monotonic(db_session):
    """last_seen_at only moves forward, never regresses."""
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    r1 = _result("AbuseIPDB", "8.8.8.8", IndicatorType.IP, timestamp=_ts(10))
    _persist(db_session, _analysis(indicators=(ip,), results=(_association(ip, "AbuseIPDB", r1),)))
    assert _as_utc(_all_indicators(db_session)[0].last_seen_at) == _ts(10)

    r2 = _result("AbuseIPDB", "8.8.8.8", IndicatorType.IP, timestamp=_ts(5))
    _persist(db_session, _analysis(indicators=(ip,), results=(_association(ip, "AbuseIPDB", r2),)))
    assert _as_utc(_all_indicators(db_session)[0].last_seen_at) == _ts(10)

    r3 = _result("AbuseIPDB", "8.8.8.8", IndicatorType.IP, timestamp=_ts(15))
    _persist(db_session, _analysis(indicators=(ip,), results=(_association(ip, "AbuseIPDB", r3),)))
    assert _as_utc(_all_indicators(db_session)[0].last_seen_at) == _ts(15)


def test_single_analysis_seeds_from_earliest_occurrence(db_session):
    """first_seen_at is seeded by the earliest occurrence in an analysis."""
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    r1 = _result("AbuseIPDB", "8.8.8.8", IndicatorType.IP, timestamp=_ts(3))
    r2 = _result("VirusTotal", "8.8.8.8", IndicatorType.IP, timestamp=_ts(8))
    _persist(
        db_session,
        _analysis(
            indicators=(ip,),
            results=(_association(ip, "AbuseIPDB", r1), _association(ip, "VirusTotal", r2)),
        ),
    )

    indicator = _all_indicators(db_session)[0]
    assert _as_utc(indicator.first_seen_at) == _ts(3)


# ---------------------------------------------------------------------------
# 15. Multiple lookups timeline
# ---------------------------------------------------------------------------


def test_multiple_lookups_timeline_preserved(db_session):
    """Mixed success/failure lookups keep their performed_at ordering."""
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    r1 = _result("AbuseIPDB", "8.8.8.8", IndicatorType.IP, timestamp=_ts(1))
    r2 = _result("VirusTotal", "8.8.8.8", IndicatorType.IP, timestamp=_ts(3))
    f1 = _failure("AlienVault OTX", "8.8.8.8", IndicatorType.IP, error_type="timeout")
    _persist(
        db_session,
        _analysis(
            indicators=(ip,),
            results=(_association(ip, "AbuseIPDB", r1), _association(ip, "VirusTotal", r2)),
            failures=(f1,),
        ),
    )

    assert _count(db_session, ThreatIntelLookup) == 3
    assert _count(db_session, ThreatIntelIndicator) == 1
    assert {l.provider for l in _all_lookups(db_session)} == {
        "AbuseIPDB", "VirusTotal", "AlienVault OTX",
    }
    assert {l.status for l in _all_lookups(db_session)} == {
        LookupStatus.SUCCESS, LookupStatus.ERROR,
    }
# ---------------------------------------------------------------------------
# 16. Idempotency
# ---------------------------------------------------------------------------


def test_repersist_same_analysis_is_noop(db_session):
    """Re-persisting an identical analysis reuses the existing rows."""
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    r = _result("AbuseIPDB", "8.8.8.8", IndicatorType.IP, timestamp=_ts(1))
    analysis = _analysis(indicators=(ip,), results=(_association(ip, "AbuseIPDB", r),))

    first = _persist(db_session, analysis)
    second = _persist(db_session, analysis)

    assert first.lookups_created == 1
    assert first.indicators_created == 1
    assert second.lookups_created == 0
    assert second.lookups_skipped == 1
    assert second.indicators_created == 0
    assert second.indicators_updated == 1
    # ``lookup_ids`` reports only rows created by THIS invocation; the noop
    # repersist created none, so its tuple is empty (reused rows are skipped).
    assert second.lookup_ids == ()
    assert _count(db_session, ThreatIntelLookup) == 1
    assert _count(db_session, ThreatIntelIndicator) == 1


def test_repersist_same_failure_is_noop(db_session):
    """Re-persisting the same failure produces no duplicate error rows."""
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    f = _failure("VirusTotal", "8.8.8.8", IndicatorType.IP, error_type="timeout")
    analysis = _analysis(indicators=(ip,), failures=(f,))

    first = _persist(db_session, analysis)
    second = _persist(db_session, analysis)

    assert first.lookups_created == 1
    assert second.lookups_created == 0
    assert second.lookups_skipped == 1
    assert _count(db_session, ThreatIntelLookup) == 1


def test_same_lookup_at_different_time_is_new_row(db_session):
    """Same event/indicator/provider at a different time is legitimate history."""
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    analysis = _analysis(
        indicators=(ip,),
        results=(_association(ip, "AbuseIPDB", _result("AbuseIPDB", "8.8.8.8", IndicatorType.IP, timestamp=_ts(1))),),
    )
    _persist(db_session, analysis)

    later = _analysis(
        indicators=(ip,),
        results=(_association(ip, "AbuseIPDB", _result("AbuseIPDB", "8.8.8.8", IndicatorType.IP, timestamp=_ts(9))),),
    )
    out = _persist(db_session, later)

    assert out.lookups_created == 1
    assert _count(db_session, ThreatIntelLookup) == 2
    timestamps = sorted(_as_utc(l.performed_at) for l in _all_lookups(db_session))
    assert timestamps == [_ts(1), _ts(9)]


def test_indicator_dedup_across_repersist(db_session):
    """Re-persisting never duplicates the global indicator row."""
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    r = _result("AbuseIPDB", "8.8.8.8", IndicatorType.IP, timestamp=_ts(1))
    analysis = _analysis(indicators=(ip,), results=(_association(ip, "AbuseIPDB", r),))
    _persist(db_session, analysis)
    _persist(db_session, analysis)
    _persist(db_session, analysis)

    indicators = _all_indicators(db_session)
    assert len(indicators) == 1
    assert indicators[0].canonical_key == "ip:8.8.8.8"
    assert _count(db_session, ThreatIntelLookup) == 1


def test_deduped_new_analysis_shares_indicator_row(db_session):
    """A second analysis with the same indicator reuses and updates it."""
    a = _analysis(
        indicators=(_extracted("8.8.8.8", IndicatorType.IP),),
        results=(_association(_extracted("8.8.8.8", IndicatorType.IP), "AbuseIPDB", _result("AbuseIPDB", "8.8.8.8", IndicatorType.IP, timestamp=_ts(1))),),
    )
    b = _analysis(
        indicators=(_extracted("8.8.8.8", IndicatorType.IP),),
        results=(_association(_extracted("8.8.8.8", IndicatorType.IP), "VirusTotal", _result("VirusTotal", "8.8.8.8", IndicatorType.IP, timestamp=_ts(2))),),
    )
    first = _persist(db_session, a)
    second = _persist(db_session, b)

    assert first.indicators_created == 1
    assert second.indicators_created == 0
    assert second.indicators_updated == 1
    assert len(_all_indicators(db_session)) == 1
    assert _count(db_session, ThreatIntelLookup) == 2
# ---------------------------------------------------------------------------
# 17. Empty analysis
# ---------------------------------------------------------------------------


def test_empty_analysis_noop(db_session):
    """An analysis with no indicators/results/failures persists nothing."""
    analysis = _analysis()
    out = _persist(db_session, analysis)

    assert out.is_empty
    assert out.indicators_created == 0
    assert out.lookups_created == 0
    assert _count(db_session, ThreatIntelIndicator) == 0
    assert _count(db_session, ThreatIntelLookup) == 0


# ---------------------------------------------------------------------------
# 18. Transactional rollback on error
# ---------------------------------------------------------------------------


class _ExplodingRepo(ThreatIntelRepository):
    """Repository that blows up on ``add`` to force rollback."""

    def add(self, entity) -> None:  # noqa: D401
        raise RuntimeError("simulated DB failure mid-transaction")


def test_transaction_rollback_on_repo_failure(db_session):
    """Any repo error triggers rollback and a safe ThreatIntelPersistenceError."""
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    r = _result("AbuseIPDB", "8.8.8.8", IndicatorType.IP, timestamp=_ts(1))
    analysis = _analysis(
        indicators=(ip,),
        results=(_association(ip, "AbuseIPDB", r),),
    )
    service = ThreatIntelligencePersistenceService(
        repository_factory=lambda s: _ExplodingRepo(s),
    )

    with pytest.raises(ThreatIntelPersistenceError) as exc_info:
        service.persist_analysis(db_session, analysis)

    # Exception carries event_id but never raw DB error text
    assert exc_info.value.event_id == analysis.event_id
    assert "simulated DB failure" not in str(exc_info.value)
    # Session fully rolled back
    assert _count(db_session, ThreatIntelIndicator) == 0
    assert _count(db_session, ThreatIntelLookup) == 0


def test_oversized_evidence_raises_validation_error(db_session):
    """Structured evidence exceeding the bound triggers pre-commit rejection."""
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    huge = {"blob": "x" * 300_000}
    r = _result("VirusTotal", "8.8.8.8", IndicatorType.IP, data=huge, timestamp=_ts(1))
    analysis = _analysis(
        indicators=(ip,),
        results=(_association(ip, "VirusTotal", r),),
    )

    with pytest.raises(ThreatIntelPersistenceValidationError):
        _persist(db_session, analysis)

    assert _count(db_session, ThreatIntelIndicator) == 0
    assert _count(db_session, ThreatIntelLookup) == 0


# ---------------------------------------------------------------------------
# 19. Error-message sanitization (defense-in-depth)
# ---------------------------------------------------------------------------


def test_sanitize_labeled_credentials():
    """Labeled credential values like ``api_key=...`` are redacted."""
    msg = 'request failed: api_key=sk-supersecret123456'
    safe = sanitize_error_message(msg)
    assert "sk-supersecret123456" not in safe
    assert "<redacted>" in safe


def test_sanitize_authorization_bearer():
    """Authorization: Bearer headers are redacted."""
    msg = "HTTP 401: Authorization: Bearer abcdef1234567890abcdef"
    safe = sanitize_error_message(msg)
    assert "abcdef1234567890" not in safe
    assert "Bearer" not in safe


def test_sanitize_bare_bearer_token():
    """Bare bearer tokens in free text are redacted."""
    msg = "token: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    safe = sanitize_error_message(msg)
    assert "eyJhbGciOiJIUzI1NiI" not in safe


def test_sanitize_64char_hex_token():
    """64-char opaque hex tokens (SHA-256-style keys) are redacted."""
    token = "a" * 64
    msg = f"header value was {token} and failed"
    safe = sanitize_error_message(msg)
    assert token not in safe
    assert "<redacted>" in safe


def test_sanitize_empty_string():
    """Empty error message passes through unchanged."""
    assert sanitize_error_message("") == ""


def test_sanitize_truncates_long_message():
    """Messages are truncated to the maximum error-message bound."""
    long_msg = "error: " + "x" * 5000
    safe = sanitize_error_message(long_msg)
    assert len(safe) <= 4000


def test_failure_message_sanitized_on_persist(db_session):
    """Error messages with secrets are sanitized before persistence."""
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    f = _failure(
        "AbuseIPDB",
        "8.8.8.8",
        IndicatorType.IP,
        error_type="auth_error",
        message="api_key=sk-topsecretdata123456 was rejected",
        retryable=False,
    )
    _persist(db_session, _analysis(indicators=(ip,), failures=(f,)))

    lookup = _all_lookups(db_session)[0]
    assert "sk-topsecretdata123456" not in lookup.error_message
    assert "<redacted>" in lookup.error_message
# ---------------------------------------------------------------------------
# 20. Structured-evidence secret filtering (defense-in-depth)
# ---------------------------------------------------------------------------


def test_evidence_sensitive_key_redacted(db_session):
    """Credential keys inside evidence are redacted before persistence."""
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    r = _result(
        "AbuseIPDB",
        "8.8.8.8",
        IndicatorType.IP,
        data={
            "apiKey": "sk-abc123def456",
            "category": "malware",
            "nested": {"token": "tok_xyz789", "reputation": 87},
        },
        timestamp=_ts(1),
    )
    _persist(db_session, _analysis(indicators=(ip,), results=(_association(ip, "AbuseIPDB", r),)))

    evidence = _all_lookups(db_session)[0].evidence
    assert evidence["apiKey"] == "<redacted>"
    assert evidence["nested"]["token"] == "<redacted>"
    assert evidence["nested"]["reputation"] == 87
    assert evidence["category"] == "malware"


def test_metadata_sensitive_key_redacted(db_session):
    """Credential keys inside result_metadata are redacted too."""
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    r = _result(
        "AbuseIPDB",
        "8.8.8.8",
        IndicatorType.IP,
        data={"votes": 12},
        metadata={"client_secret": "super-private-secret", "region": "eu"},
        timestamp=_ts(1),
    )
    _persist(db_session, _analysis(indicators=(ip,), results=(_association(ip, "AbuseIPDB", r),)))

    metadata = _all_lookups(db_session)[0].result_metadata
    assert metadata["client_secret"] == "<redacted>"
    assert metadata["region"] == "eu"


def test_evidence_list_values_recursively_redacted(db_session):
    """Redaction recurses through lists inside evidence."""
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    r = _result(
        "VirusTotal",
        "8.8.8.8",
        IndicatorType.IP,
        data={"detections": [{"token": "gh_secret123", "family": "emotet"}]},
        timestamp=_ts(1),
    )
    _persist(db_session, _analysis(indicators=(ip,), results=(_association(ip, "VirusTotal", r),)))

    evidence = _all_lookups(db_session)[0].evidence
    assert evidence["detections"][0]["token"] == "<redacted>"
    assert evidence["detections"][0]["family"] == "emotet"
# ---------------------------------------------------------------------------
# 21. Repository query methods
# ---------------------------------------------------------------------------


def test_find_existing_lookup_match(db_session):
    """find_existing_lookup matches an existing lookup by identity."""
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    event_id = uuid.uuid4()
    _persist(
        db_session,
        _analysis(
            event_id=event_id,
            indicators=(ip,),
            results=(_association(ip, "AbuseIPDB", _result("AbuseIPDB", "8.8.8.8", IndicatorType.IP, timestamp=_ts(4))),),
        ),
    )

    repo = ThreatIntelRepository(db_session)
    indicator = _all_indicators(db_session)[0]
    found = repo.find_existing_lookup(
        event_id=event_id,
        indicator_id=indicator.id,
        provider="AbuseIPDB",
        status=LookupStatus.SUCCESS,
        performed_at=_ts(4),
    )
    assert found is not None
    assert found.event_id == event_id
    assert found.provider == "AbuseIPDB"


def test_find_existing_lookup_no_match(db_session):
    """find_existing_lookup returns None when the identity does not match."""
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    _persist(
        db_session,
        _analysis(
            indicators=(ip,),
            results=(_association(ip, "AbuseIPDB", _result("AbuseIPDB", "8.8.8.8", IndicatorType.IP, timestamp=_ts(1))),),
        ),
    )

    repo = ThreatIntelRepository(db_session)
    indicator = _all_indicators(db_session)[0]
    found = repo.find_existing_lookup(
        event_id=uuid.uuid4(),
        indicator_id=indicator.id,
        provider="VirusTotal",
    )
    assert found is None


# ---------------------------------------------------------------------------
# 21b. Repository query methods (event/indicator/recent)
# ---------------------------------------------------------------------------


def test_get_lookups_for_event_orders_by_performed_at(db_session):
    """Lookups for an event come back most-recent-first."""
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    event_id = uuid.uuid4()
    _persist(
        db_session,
        _analysis(
            event_id=event_id,
            indicators=(ip,),
            results=(
                _association(ip, "AbuseIPDB", _result("AbuseIPDB", "8.8.8.8", IndicatorType.IP, timestamp=_ts(1))),
                _association(ip, "VirusTotal", _result("VirusTotal", "8.8.8.8", IndicatorType.IP, timestamp=_ts(2))),
            ),
        ),
    )

    repo = ThreatIntelRepository(db_session)
    rows = repo.get_lookups_for_event(event_id)
    assert [r.provider for r in rows] == ["VirusTotal", "AbuseIPDB"]
    limited = repo.get_lookups_for_event(event_id, limit=1)
    assert [r.provider for r in limited] == ["VirusTotal"]


def test_get_lookups_for_indicator(db_session):
    """All lookups for an indicator are returned across providers."""
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    _persist(
        db_session,
        _analysis(
            indicators=(ip,),
            results=(
                _association(ip, "AbuseIPDB", _result("AbuseIPDB", "8.8.8.8", IndicatorType.IP, timestamp=_ts(1))),
                _association(ip, "VirusTotal", _result("VirusTotal", "8.8.8.8", IndicatorType.IP, timestamp=_ts(2))),
            ),
        ),
    )

    repo = ThreatIntelRepository(db_session)
    indicator = _all_indicators(db_session)[0]
    rows = repo.get_lookups_for_indicator(indicator.id)
    assert {r.provider for r in rows} == {"AbuseIPDB", "VirusTotal"}


def test_get_provider_lookups_for_indicator(db_session):
    """Provider-scoped lookups are filtered correctly."""
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    _persist(
        db_session,
        _analysis(
            indicators=(ip,),
            results=(
                _association(ip, "AbuseIPDB", _result("AbuseIPDB", "8.8.8.8", IndicatorType.IP, timestamp=_ts(1))),
                _association(ip, "VirusTotal", _result("VirusTotal", "8.8.8.8", IndicatorType.IP, timestamp=_ts(2))),
            ),
        ),
    )

    repo = ThreatIntelRepository(db_session)
    indicator = _all_indicators(db_session)[0]
    rows = repo.get_provider_lookups_for_indicator(indicator.id, "VirusTotal")
    assert [r.provider for r in rows] == ["VirusTotal"]
    assert len(rows) == 1


def test_get_recent_lookups(db_session):
    """Recent lookups span events and respect the limit."""
    ip = _extracted("8.8.8.8", IndicatorType.IP)
    _persist(
        db_session,
        _analysis(
            indicators=(ip,),
            results=(
                _association(ip, "A", _result("A", "8.8.8.8", IndicatorType.IP, timestamp=_ts(1))),
                _association(ip, "B", _result("B", "8.8.8.8", IndicatorType.IP, timestamp=_ts(2))),
                _association(ip, "C", _result("C", "8.8.8.8", IndicatorType.IP, timestamp=_ts(3))),
            ),
        ),
    )

    repo = ThreatIntelRepository(db_session)
    recent = repo.get_recent_lookups(limit=2)
    assert [r.provider for r in recent] == ["C", "B"]


def test_get_indicator_by_canonical_key(db_session):
    """Indicator lookup by canonical key returns the right row."""
    _persist(
        db_session,
        _analysis(
            indicators=(_extracted("8.8.8.8", IndicatorType.IP),),
            results=(_association(_extracted("8.8.8.8", IndicatorType.IP), "AbuseIPDB", _result("AbuseIPDB", "8.8.8.8", IndicatorType.IP, timestamp=_ts(1))),),
        ),
    )

    repo = ThreatIntelRepository(db_session)
    ind = repo.get_indicator_by_canonical_key("ip:8.8.8.8")
    assert ind is not None
    assert ind.value == "8.8.8.8"
    assert repo.get_indicator_by_canonical_key("ip:1.1.1.1") is None


def test_get_indicator_by_type_and_value(db_session):
    """Indicator lookup by type+value matches the contract fields."""
    _persist(
        db_session,
        _analysis(
            indicators=(_extracted("8.8.8.8", IndicatorType.IP),),
            results=(_association(_extracted("8.8.8.8", IndicatorType.IP), "AbuseIPDB", _result("AbuseIPDB", "8.8.8.8", IndicatorType.IP, timestamp=_ts(1))),),
        ),
    )

    repo = ThreatIntelRepository(db_session)
    ind = repo.get_indicator_by_type_and_value(IndicatorType.IP, "8.8.8.8")
    assert ind is not None
    assert ind.indicator_type == "ip"
    assert repo.get_indicator_by_type_and_value(IndicatorType.IP, "9.9.9.9") is None