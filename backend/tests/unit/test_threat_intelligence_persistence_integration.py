"""Threat-intelligence pipeline integration tests (Step 8C-C).

Exercises the full Step 8B agent -> Step 8C persistence path:

    ThreatIntelligenceAgent.analyze(event, persistence=...)
        -> ThreatIntelligenceAnalysis
        -> ThreatIntelligencePersistenceService.persist_analysis(db, analysis)
            -> ThreatIntelIndicator / ThreatIntelLookup (PostgreSQL)

The agent runs with deterministic fake providers (no network).  Persistence
runs through the *real* :class:`ThreatIntelligencePersistenceService` against
an in-memory SQLite engine (the PostgreSQL ``JSONB`` column is rendered as
``JSON`` for SQLite with a test-only type-compiler visitor, exactly as the
existing Step 8C-B persistence tests do).

These tests verify the new pipeline boundary introduced in Step 8C-C:

* a completed analysis is persisted through the injected sink,
* multiple indicators / providers / failures are all persisted,
* retryable and non-retryable failures retain their status,
* repeated indicator occurrence never duplicates global indicator rows,
* event/provider traceability is preserved,
* persistence failure is handled per the existing service conventions, and
* Step 8B behavior is unchanged when no persistence (or a mock) is supplied.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.dialects.sqlite.base import SQLiteTypeCompiler
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

# Make the PostgreSQL ``JSONB`` columns work on SQLite for these unit tests.
# This mirrors the test-only adapter used by the Step 8C-B persistence tests.
if not hasattr(SQLiteTypeCompiler, "visit_JSONB"):
    SQLiteTypeCompiler.visit_JSONB = lambda self, type_, **kw: "JSON"  # noqa: E731

from app.agents.threat_intelligence import (
    ThreatIntelligenceAgent,
    persist_analysis_bound,
)
from app.database.postgres.base import Base
from app.models.threat_intel_indicator import ThreatIntelIndicator
from app.models.threat_intel_lookup import LookupStatus, ThreatIntelLookup
from app.schemas.enriched_event import EnrichedSecurityEvent
from app.schemas.normalized_event import (
    Endpoint,
    EventCategory,
    EventOutcome,
    FileInfo,
    NormalizedSecurityEvent,
)
from app.schemas.security_event import Provenance, SourceType
from app.schemas.threat_intelligence_agent import ThreatIntelligenceAnalysis
from app.services.threat_intelligence.base import ThreatIntelProvider, ThreatIntelResult
from app.services.threat_intelligence.exceptions import ProviderLookupError, RateLimitError
from app.services.threat_intelligence.registry import ProviderRegistry
from app.services.threat_intelligence.types import IndicatorType, ThreatIndicator
from app.services.threat_intelligence_persistence import (
    ThreatIntelPersistenceError,
    ThreatIntelligencePersistenceService,
)

_FIXED_TS = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
_CLOCK_TS = datetime(2026, 9, 1, 13, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Deterministic fake provider (no network)
# ---------------------------------------------------------------------------


class FakeProvider(ThreatIntelProvider):
    """In-memory provider configured to succeed or fail deterministically."""

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
    ) -> None:
        self._name = name
        self._types = types
        self._found = found
        self._data = data or {}
        self._confidence = confidence
        self.raise_exc = raise_exc
        self.timestamp = timestamp

    @property
    def provider_name(self) -> str:
        return self._name

    @property
    def supported_indicator_types(self) -> frozenset[IndicatorType]:
        return self._types

    def lookup(self, indicator: ThreatIndicator) -> ThreatIntelResult:
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
# Fixtures / builders
# ---------------------------------------------------------------------------


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


def _make_event(
    *,
    source_ip: str | None = None,
    dest_ip: str | None = None,
    file_hash: str | None = None,
    normalized_data: dict | None = None,
) -> EnrichedSecurityEvent:
    """Build a valid EnrichedSecurityEvent with the requested indicator fields."""
    normalized = NormalizedSecurityEvent(
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
    return EnrichedSecurityEvent(
        event_id=normalized.event_id,
        timestamp=normalized.timestamp,
        normalized_event=normalized,
        enrichments=[],
        provenance=Provenance.ENRICHED,
    )


def _count(db: Session, model) -> int:
    return db.scalar(select(func.count()).select_from(model))


def _all_indicators(db: Session) -> list[ThreatIntelIndicator]:
    return list(
        db.scalars(select(ThreatIntelIndicator).order_by(ThreatIntelIndicator.canonical_key))
    )


def _all_lookups(db: Session) -> list[ThreatIntelLookup]:
    return list(
        db.scalars(select(ThreatIntelLookup).order_by(ThreatIntelLookup.provider))
    )


def _real_persistence(db: Session):
    """Bind the real persistence service to *db* with a deterministic clock."""
    service = ThreatIntelligencePersistenceService(clock=lambda: _CLOCK_TS)
    return persist_analysis_bound(db, service=service)



# ---------------------------------------------------------------------------
# A. Successful analysis is persisted
# ---------------------------------------------------------------------------


def test_successful_analysis_is_persisted(db_session):
    event = _make_event(source_ip="185.10.10.10")
    agent = ThreatIntelligenceAgent(
        ProviderRegistry([FakeProvider(name="AbuseIPDB", found=True, data={"score": 87})])
    )

    analysis = agent.analyze(event, persistence=_real_persistence(db_session))

    assert isinstance(analysis, ThreatIntelligenceAnalysis)
    assert _count(db_session, ThreatIntelIndicator) == 1
    assert _count(db_session, ThreatIntelLookup) == 1
    lookup = _all_lookups(db_session)[0]
    assert lookup.status is LookupStatus.SUCCESS
    assert lookup.provider == "AbuseIPDB"
    assert lookup.event_id == event.event_id
    ind = _all_indicators(db_session)[0]
    assert lookup.indicator_id == ind.id
    assert ind.value == "185.10.10.10"


# ---------------------------------------------------------------------------
# B. Multiple indicators are persisted
# ---------------------------------------------------------------------------


def test_multiple_indicators_persisted(db_session):
    event = _make_event(
        source_ip="185.10.10.10",
        normalized_data={"domain": "evil.example.com"},
    )
    agent = ThreatIntelligenceAgent(
        ProviderRegistry(
            [
                FakeProvider(name="AbuseIPDB", types=frozenset({IndicatorType.IP})),
                FakeProvider(
                    name="VT",
                    types=frozenset({IndicatorType.DOMAIN}),
                ),
            ]
        )
    )

    agent.analyze(event, persistence=_real_persistence(db_session))

    assert _count(db_session, ThreatIntelIndicator) == 2
    assert {i.value for i in _all_indicators(db_session)} == {
        "185.10.10.10",
        "evil.example.com",
    }


# ---------------------------------------------------------------------------
# C. Multiple provider results are persisted
# ---------------------------------------------------------------------------


def test_multiple_provider_results_persisted(db_session):
    event = _make_event(source_ip="185.10.10.10")
    agent = ThreatIntelligenceAgent(
        ProviderRegistry(
            [
                FakeProvider(name="AbuseIPDB", data={"score": 1}),
                FakeProvider(name="VT", data={"malicious": 5}),
            ]
        )
    )

    agent.analyze(event, persistence=_real_persistence(db_session))

    assert _count(db_session, ThreatIntelLookup) == 2
    providers = {l.provider for l in _all_lookups(db_session)}
    assert providers == {"AbuseIPDB", "VT"}
    assert all(l.status is LookupStatus.SUCCESS for l in _all_lookups(db_session))


# ---------------------------------------------------------------------------
# D. Provider failures are persisted correctly
# ---------------------------------------------------------------------------


def test_provider_failure_persisted(db_session):
    event = _make_event(source_ip="185.10.10.10")
    agent = ThreatIntelligenceAgent(
        ProviderRegistry(
            [
                FakeProvider(name="Good", found=True, data={"ok": 1}),
                FakeProvider(
                    name="Bad",
                    raise_exc=ProviderLookupError("Bad", "boom"),
                ),
            ]
        )
    )

    analysis = agent.analyze(event, persistence=_real_persistence(db_session))

    # Both a success and a failure lookup were persisted; the failure is
    # isolated and never wipes out the success result.
    assert len(analysis.failures) == 1
    assert len(analysis.results) == 1
    assert _count(db_session, ThreatIntelLookup) == 2
    lookups = _all_lookups(db_session)
    success = next(l for l in lookups if l.status is LookupStatus.SUCCESS)
    failure = next(l for l in lookups if l.status is LookupStatus.ERROR)
    assert success.provider == "Good"
    assert failure.provider == "Bad"
    assert failure.error_type == "provider_error"


# ---------------------------------------------------------------------------
# E. Retryable and non-retryable failures retain their status
# ---------------------------------------------------------------------------


def test_retryable_and_non_retryable_failures_retain_status(db_session):
    event = _make_event(
        source_ip="185.10.10.10",
        normalized_data={"domain": "evil.example.com"},
    )
    agent = ThreatIntelligenceAgent(
        ProviderRegistry(
            [
                # RateLimitError is classified retryable=True.
                FakeProvider(
                    name="RateLimited",
                    types=frozenset({IndicatorType.IP}),
                    raise_exc=RateLimitError("RateLimited"),
                ),
                # ProviderLookupError without a timeout is non-retryable.
                FakeProvider(
                    name="Permanent",
                    types=frozenset({IndicatorType.DOMAIN}),
                    raise_exc=ProviderLookupError("Permanent", "rejected"),
                ),
            ]
        )
    )

    analysis = agent.analyze(event, persistence=_real_persistence(db_session))

    assert len(analysis.failures) == 2
    assert _count(db_session, ThreatIntelLookup) == 2
    lookups = _all_lookups(db_session)
    rate = next(l for l in lookups if l.provider == "RateLimited")
    perm = next(l for l in lookups if l.provider == "Permanent")
    assert rate.retryable is True
    assert perm.retryable is False
    assert rate.status is LookupStatus.ERROR
    assert perm.status is LookupStatus.ERROR


# ---------------------------------------------------------------------------
# F. Repeated indicator occurrence does not create duplicate indicator rows
# ---------------------------------------------------------------------------


def test_repeated_indicator_occurrence_no_duplicate_rows(db_session):
    # Same IP is present in both source and destination, but the provider
    # only ever looks the canonical indicator up once.
    event = _make_event(source_ip="8.8.8.8", dest_ip="8.8.8.8")
    agent = ThreatIntelligenceAgent(ProviderRegistry([FakeProvider(name="AbuseIPDB")]))

    first = agent.analyze(event, persistence=_real_persistence(db_session))
    second = agent.analyze(event, persistence=_real_persistence(db_session))

    assert len(_all_indicators(db_session)) == 1
    assert _count(db_session, ThreatIntelLookup) == 1  # idempotent re-persist
    assert first.event_id == second.event_id
# ---------------------------------------------------------------------------
# G. Event/provider association remains traceable
# ---------------------------------------------------------------------------


def test_event_provider_traceability(db_session):
    event = _make_event(
        source_ip="185.10.10.10",
        normalized_data={"domain": "evil.example.com"},
    )
    agent = ThreatIntelligenceAgent(
        ProviderRegistry(
            [
                FakeProvider(name="AbuseIPDB", types=frozenset({IndicatorType.IP})),
                FakeProvider(name="VT", types=frozenset({IndicatorType.IP})),
                FakeProvider(name="OTX", types=frozenset({IndicatorType.DOMAIN})),
            ]
        )
    )

    agent.analyze(event, persistence=_real_persistence(db_session))

    # Every persisted lookup is traceable to both the event and its indicator.
    lookups = _all_lookups(db_session)
    indicators = {i.canonical_key: i for i in _all_indicators(db_session)}
    ip_ind = indicators["ip:185.10.10.10"]
    dom_ind = indicators["domain:evil.example.com"]
    for lookup in lookups:
        assert lookup.event_id == event.event_id
        # Each lookup's indicator must be the one the provider queried.
        assert lookup.indicator_id in (ip_ind.id, dom_ind.id)
        if lookup.provider in ("AbuseIPDB", "VT"):
            assert lookup.indicator_id == ip_ind.id
        else:
            assert lookup.indicator_id == dom_ind.id
    assert {l.provider for l in lookups} == {"AbuseIPDB", "VT", "OTX"}


# ---------------------------------------------------------------------------
# H. Persistence failure is handled per existing service conventions
# ---------------------------------------------------------------------------


def test_persistence_failure_propagates_safe_error(db_session):
    event = _make_event(source_ip="185.10.10.10")
    agent = ThreatIntelligenceAgent(ProviderRegistry([FakeProvider(name="AbuseIPDB")]))

    # A persistence sink that always fails, as the real service would when a
    # database error occurs (raises the sanitized ThreatIntelPersistenceError).
    def failing_persistence(analysis):
        raise ThreatIntelPersistenceError(event_id=analysis.event_id)

    with pytest.raises(ThreatIntelPersistenceError) as exc_info:
        agent.analyze(event, persistence=failing_persistence)

    assert exc_info.value.event_id == event.event_id
    # no rows were persisted by the failing sink
    assert _count(db_session, ThreatIntelIndicator) == 0
    assert _count(db_session, ThreatIntelLookup) == 0


def test_real_persistence_failure_rolls_back_and_raises_safe_error(db_session):
    """A real persistence failure is surfaced as a sanitized error, and the
    session holds no partial rows (the service owns the transaction)."""
    service = ThreatIntelligencePersistenceService(clock=lambda: _CLOCK_TS)
    failing_bound = persist_analysis_bound(db_session, service=service)

    # Force a deterministic persistence failure from the *real* service by
    # exceeding the bounded evidence size.  The service raises a safe
    # ThreatIntelPersistenceValidationError (a subclass of
    # ThreatIntelPersistenceError) and rolls the transaction back; the agent
    # surfaces it unchanged.
    from app.services.threat_intelligence_persistence import (
        ThreatIntelPersistenceValidationError,
    )

    provider = FakeProvider(name="Big", data={"blob": "x" * 300_000})
    agent_big = ThreatIntelligenceAgent(ProviderRegistry([provider]))
    event_big = _make_event(source_ip="203.0.113.9")

    with pytest.raises(ThreatIntelPersistenceError) as exc_info:
        agent_big.analyze(event_big, persistence=failing_bound)

    # Sanitized error semantics: the safe type, never DB/SQL text.
    assert isinstance(exc_info.value, ThreatIntelPersistenceValidationError)
    assert "threat-intelligence analysis" in str(exc_info.value)
    assert "Traceback" not in str(exc_info.value)
    # Transaction rolled back: nothing persisted by the failing sink.
    assert _count(db_session, ThreatIntelIndicator) == 0
    assert _count(db_session, ThreatIntelLookup) == 0


# ---------------------------------------------------------------------------
# I. Step 8B behavior unchanged when persistence is not supplied or mocked
# ---------------------------------------------------------------------------


def test_no_persistence_supplied_unchanged():
    event = _make_event(source_ip="185.10.10.10")
    agent = ThreatIntelligenceAgent(ProviderRegistry([FakeProvider(name="AbuseIPDB")]))

    analysis = agent.analyze(event)

    assert isinstance(analysis, ThreatIntelligenceAnalysis)
    assert len(analysis.indicators) == 1
    assert len(analysis.results) == 1
    assert analysis.has_results
    # No persistence side effect is expected to run; the analysis stands alone.


def test_mocked_persistence_receives_analysis():
    event = _make_event(source_ip="185.10.10.10")
    agent = ThreatIntelligenceAgent(ProviderRegistry([FakeProvider(name="AbuseIPDB")]))

    captured: list[ThreatIntelligenceAnalysis] = []

    def mock_persistence(analysis):
        captured.append(analysis)
        return None

    analysis = agent.analyze(event, persistence=mock_persistence)

    assert len(captured) == 1
    assert captured[0] is analysis
    assert captured[0].event_id == event.event_id