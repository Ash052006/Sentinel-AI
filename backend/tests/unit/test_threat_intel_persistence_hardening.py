"""Focused tests for Threat Intelligence Persistence Hardening.

Covers:
1. Event lookup idempotency under concurrency (P0).
2. Manual lookup history preservation (P1).
3. Correct indicator rollups using latest outcome per provider (P0).
4. Database validation of lookup origin and migration downgrade safety (P1).
5. Manual lookup rate limiting (P1).
6. Non-public IP protection regression (documentation ranges).
"""

from __future__ import annotations

import collections
from datetime import datetime, timedelta, timezone
import uuid
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.dialects.sqlite.base import SQLiteTypeCompiler
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

# Enable PostgreSQL JSONB on SQLite
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
from app.services.threat_intelligence.rate_limiter import InMemoryRateLimiter, RateLimitStatus
from app.services.threat_intelligence.types import IndicatorType, ThreatIndicator
from app.services.threat_intelligence.validation import (
    classify_non_public_ip,
    is_non_public_ip,
    should_skip_external_lookup,
)
from app.services.threat_intelligence_persistence import (
    ThreatIntelligencePersistenceService,
    canonical_indicator_key,
)
from app.services.threat_intelligence_query import ThreatIntelQueryService, indicator_status


def _utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


@pytest.fixture
def sqlite_engine():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture
def db(sqlite_engine):
    with Session(sqlite_engine) as session:
        yield session


def _make_indicator(
    session: Session, value: str = "1.1.1.1", indicator_type: IndicatorType = IndicatorType.IP
) -> ThreatIntelIndicator:
    repo = ThreatIntelRepository(session)
    key = canonical_indicator_key(indicator_type, value)
    now = datetime.now(timezone.utc)
    ind, _ = repo.get_or_create_indicator(
        value=value,
        indicator_type=indicator_type,
        canonical_key=key,
        seen_at=now,
    )
    session.commit()
    return ind


# ===========================================================================
# 1. Persistence & Idempotency Tests
# ===========================================================================


class TestEventLookupIdempotency:
    def test_repeated_event_lookup_updates_existing_record_with_different_timestamp(
        self, db: Session
    ) -> None:
        service = ThreatIntelligencePersistenceService()
        event_id = uuid.uuid4()
        t1 = datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)

        ind = ExtractedIndicator(
            indicator="8.8.8.8",
            indicator_type=IndicatorType.IP,
            source_field="dst_ip",
            source_context="test",
        )
        res1 = ThreatIntelResult(
            provider="VirusTotal",
            indicator=ThreatIndicator(indicator_type=IndicatorType.IP, value="8.8.8.8"),
            found=True,
            confidence=0.8,
            timestamp=t1,
            data={"score": 10},
        )
        analysis1 = ThreatIntelligenceAnalysis(
            event_id=event_id,
            indicators=[ind],
            results=[ProviderAssociation(indicator=ind, provider="VirusTotal", result=res1)],
            failures=[],
        )
        p_res1 = service.persist_analysis(db, analysis1)
        assert p_res1.lookups_created == 1
        assert p_res1.lookups_updated == 0

        # Verify initial lookup record
        row1 = db.scalar(select(ThreatIntelLookup).where(ThreatIntelLookup.event_id == event_id))
        assert row1 is not None
        assert _utc(row1.performed_at) == t1
        assert row1.confidence == 0.8
        initial_id = row1.id

        # Re-persist with different timestamp t2 and updated score
        res2 = ThreatIntelResult(
            provider="VirusTotal",
            indicator=ThreatIndicator(indicator_type=IndicatorType.IP, value="8.8.8.8"),
            found=True,
            confidence=0.95,
            timestamp=t2,
            data={"score": 25},
        )
        analysis2 = ThreatIntelligenceAnalysis(
            event_id=event_id,
            indicators=[ind],
            results=[ProviderAssociation(indicator=ind, provider="VirusTotal", result=res2)],
            failures=[],
        )
        p_res2 = service.persist_analysis(db, analysis2)
        assert p_res2.lookups_created == 0
        assert p_res2.lookups_updated == 1

        # Must be exactly one lookup record, updated in-place with t2
        all_rows = list(db.scalars(select(ThreatIntelLookup).where(ThreatIntelLookup.event_id == event_id)))
        assert len(all_rows) == 1
        assert all_rows[0].id == initial_id
        assert _utc(all_rows[0].performed_at) == t2
        assert all_rows[0].confidence == 0.95
        assert all_rows[0].evidence == {"score": 25}

    def test_error_to_success_retry_replaces_failure(self, db: Session) -> None:
        service = ThreatIntelligencePersistenceService()
        event_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        ind = ExtractedIndicator(
            indicator="8.8.4.4",
            indicator_type=IndicatorType.IP,
            source_field="dst_ip",
            source_context="test",
        )

        # Initial analysis resulted in provider error
        failure = ProviderFailure(
            provider="VirusTotal",
            indicator="8.8.4.4",
            indicator_type=IndicatorType.IP,
            error_type="Timeout",
            message="Connection timed out",
            retryable=True,
        )
        analysis_fail = ThreatIntelligenceAnalysis(
            event_id=event_id,
            indicators=[ind],
            results=[],
            failures=[failure],
        )
        service.persist_analysis(db, analysis_fail)

        row = db.scalar(select(ThreatIntelLookup).where(ThreatIntelLookup.event_id == event_id))
        assert row is not None
        assert row.status == LookupStatus.ERROR
        assert row.error_type == "Timeout"
        assert row.found is None

        # Retry succeeds
        res_ok = ThreatIntelResult(
            provider="VirusTotal",
            indicator=ThreatIndicator(indicator_type=IndicatorType.IP, value="8.8.4.4"),
            found=True,
            confidence=0.9,
            timestamp=now,
            data={"status": "clean"},
        )
        analysis_ok = ThreatIntelligenceAnalysis(
            event_id=event_id,
            indicators=[ind],
            results=[ProviderAssociation(indicator=ind, provider="VirusTotal", result=res_ok)],
            failures=[],
        )
        p_res = service.persist_analysis(db, analysis_ok)
        assert p_res.lookups_updated == 1

        # The authoritative record must now be SUCCESS, and failure fields cleared
        all_rows = list(db.scalars(select(ThreatIntelLookup).where(ThreatIntelLookup.event_id == event_id)))
        assert len(all_rows) == 1
        assert all_rows[0].status == LookupStatus.SUCCESS
        assert all_rows[0].found is True
        assert all_rows[0].confidence == 0.9
        assert all_rows[0].error_type is None
        assert all_rows[0].error_message is None
        assert all_rows[0].retryable is None

    def test_different_events_retain_separate_lookup_records(self, db: Session) -> None:
        service = ThreatIntelligencePersistenceService()
        event1 = uuid.uuid4()
        event2 = uuid.uuid4()
        now = datetime.now(timezone.utc)
        ind = ExtractedIndicator(
            indicator="1.1.1.1",
            indicator_type=IndicatorType.IP,
            source_field="dst_ip",
            source_context="test",
        )
        res = ThreatIntelResult(
            provider="VirusTotal",
            indicator=ThreatIndicator(indicator_type=IndicatorType.IP, value="1.1.1.1"),
            found=True,
            confidence=0.8,
            timestamp=now,
            data={"val": 1},
        )

        service.persist_analysis(
            db,
            ThreatIntelligenceAnalysis(
                event_id=event1,
                indicators=[ind],
                results=[ProviderAssociation(indicator=ind, provider="VirusTotal", result=res)],
                failures=[],
            ),
        )
        service.persist_analysis(
            db,
            ThreatIntelligenceAnalysis(
                event_id=event2,
                indicators=[ind],
                results=[ProviderAssociation(indicator=ind, provider="VirusTotal", result=res)],
                failures=[],
            ),
        )

        rows = list(db.scalars(select(ThreatIntelLookup).where(ThreatIntelLookup.origin == "event")))
        assert len(rows) == 2
        assert {r.event_id for r in rows} == {event1, event2}

    def test_manual_lookup_history_preservation(self, db: Session) -> None:
        service = ThreatIntelligencePersistenceService()
        t1 = datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 11, 1, 11, 0, 0, tzinfo=timezone.utc)
        ind = ExtractedIndicator(
            indicator="9.9.9.9",
            indicator_type=IndicatorType.IP,
            source_field="manual",
            source_context="test",
        )

        # First manual lookup
        res1 = ThreatIntelResult(
            provider="VirusTotal",
            indicator=ThreatIndicator(indicator_type=IndicatorType.IP, value="9.9.9.9"),
            found=True,
            confidence=0.7,
            timestamp=t1,
            data={"scan": 1},
        )
        service.persist_analysis(
            db,
            ThreatIntelligenceAnalysis(
                event_id=None,
                indicators=[ind],
                results=[ProviderAssociation(indicator=ind, provider="VirusTotal", result=res1)],
                failures=[],
            ),
        )

        # Second manual lookup at later timestamp
        res2 = ThreatIntelResult(
            provider="VirusTotal",
            indicator=ThreatIndicator(indicator_type=IndicatorType.IP, value="9.9.9.9"),
            found=True,
            confidence=0.9,
            timestamp=t2,
            data={"scan": 2},
        )
        service.persist_analysis(
            db,
            ThreatIntelligenceAnalysis(
                event_id=None,
                indicators=[ind],
                results=[ProviderAssociation(indicator=ind, provider="VirusTotal", result=res2)],
                failures=[],
            ),
        )

        # Both manual attempts must be preserved as historical records
        manual_rows = list(db.scalars(select(ThreatIntelLookup).where(ThreatIntelLookup.origin == "manual")))
        assert len(manual_rows) == 2
        for r in manual_rows:
            assert r.event_id is None
            assert r.origin == "manual"
        timestamps = {_utc(r.performed_at) for r in manual_rows}
        assert timestamps == {t1, t2}

    def test_mixed_manual_and_event_lookups_coexist(self, db: Session) -> None:
        service = ThreatIntelligencePersistenceService()
        event_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        ind = ExtractedIndicator(
            indicator="8.8.8.8",
            indicator_type=IndicatorType.IP,
            source_field="ip",
            source_context="test",
        )
        res = ThreatIntelResult(
            provider="VirusTotal",
            indicator=ThreatIndicator(indicator_type=IndicatorType.IP, value="8.8.8.8"),
            found=True,
            confidence=0.8,
            timestamp=now,
            data={},
        )

        # Event lookup
        service.persist_analysis(
            db,
            ThreatIntelligenceAnalysis(
                event_id=event_id,
                indicators=[ind],
                results=[ProviderAssociation(indicator=ind, provider="VirusTotal", result=res)],
                failures=[],
            ),
        )
        # Manual lookup
        service.persist_analysis(
            db,
            ThreatIntelligenceAnalysis(
                event_id=None,
                indicators=[ind],
                results=[ProviderAssociation(indicator=ind, provider="VirusTotal", result=res)],
                failures=[],
            ),
        )

        rows = list(db.scalars(select(ThreatIntelLookup)))
        assert len(rows) == 2
        origins = {r.origin for r in rows}
        assert origins == {"event", "manual"}

    def test_concurrent_event_insert_race_condition_handled_gracefully(self, db: Session) -> None:
        """Simulate race condition where two workers attempt to insert the same event lookup concurrently."""
        service = ThreatIntelligencePersistenceService()
        event_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        ind_row = _make_indicator(db, "1.1.1.1")

        # Worker 1 succeeds in inserting
        lookup1 = ThreatIntelLookup(
            event_id=event_id,
            origin="event",
            indicator_id=ind_row.id,
            provider="VirusTotal",
            status=LookupStatus.ERROR,
            performed_at=now,
            provenance="enriched",
            error_type="Timeout",
        )
        db.add(lookup1)
        db.commit()

        # Worker 2 attempts persist_analysis with SUCCESS result
        ind = ExtractedIndicator(
            indicator="1.1.1.1",
            indicator_type=IndicatorType.IP,
            source_field="ip",
            source_context="test",
        )
        res_ok = ThreatIntelResult(
            provider="VirusTotal",
            indicator=ThreatIndicator(indicator_type=IndicatorType.IP, value="1.1.1.1"),
            found=True,
            confidence=0.99,
            timestamp=now,
            data={"clean": True},
        )
        analysis = ThreatIntelligenceAnalysis(
            event_id=event_id,
            indicators=[ind],
            results=[ProviderAssociation(indicator=ind, provider="VirusTotal", result=res_ok)],
            failures=[],
        )

        p_res = service.persist_analysis(db, analysis)
        assert p_res.lookups_updated == 1

        all_rows = list(db.scalars(select(ThreatIntelLookup).where(ThreatIntelLookup.event_id == event_id)))
        assert len(all_rows) == 1
        assert all_rows[0].status == LookupStatus.SUCCESS
        assert all_rows[0].confidence == 0.99


# ===========================================================================
# 2. Indicator Rollups Tests (Latest Outcome Per Provider)
# ===========================================================================


class TestIndicatorRollups:
    def test_error_followed_by_success_current_provider_outcome_successful(self, db: Session) -> None:
        ind = _make_indicator(db, "2.2.2.2")
        t1 = datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)

        # Lookup 1: ERROR at t1
        db.add(
            ThreatIntelLookup(
                event_id=None,
                origin="manual",
                indicator_id=ind.id,
                provider="VirusTotal",
                status=LookupStatus.ERROR,
                performed_at=t1,
                provenance="enriched",
                error_type="RateLimit",
            )
        )
        # Lookup 2: SUCCESS at t2
        db.add(
            ThreatIntelLookup(
                event_id=None,
                origin="manual",
                indicator_id=ind.id,
                provider="VirusTotal",
                status=LookupStatus.SUCCESS,
                performed_at=t2,
                provenance="enriched",
                found=True,
            )
        )
        db.commit()

        query_svc = ThreatIntelQueryService(db)
        page = query_svc.list_indicators(value_filter="2.2.2.2")
        record = page.items[0]

        # Total lookup history count is 2, but latest outcome is enriched!
        assert record.lookup_count == 2
        assert record.success_count == 1
        assert record.error_count == 0
        assert record.status == "enriched"

        # Detail endpoint must agree
        detail = query_svc.get_indicator(ind.id)
        assert detail.indicator.status == "enriched"
        assert detail.indicator.success_count == 1
        assert detail.indicator.error_count == 0

    def test_success_followed_by_error_current_provider_outcome_failed(self, db: Session) -> None:
        ind = _make_indicator(db, "3.3.3.3")
        t1 = datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)

        db.add(
            ThreatIntelLookup(
                event_id=None,
                origin="manual",
                indicator_id=ind.id,
                provider="VirusTotal",
                status=LookupStatus.SUCCESS,
                performed_at=t1,
                provenance="enriched",
                found=True,
            )
        )
        db.add(
            ThreatIntelLookup(
                event_id=None,
                origin="manual",
                indicator_id=ind.id,
                provider="VirusTotal",
                status=LookupStatus.ERROR,
                performed_at=t2,
                provenance="enriched",
                error_type="Timeout",
            )
        )
        db.commit()

        query_svc = ThreatIntelQueryService(db)
        record = query_svc.list_indicators(value_filter="3.3.3.3").items[0]
        assert record.lookup_count == 2
        assert record.success_count == 0
        assert record.error_count == 1
        assert record.status == "failed"

    def test_mixed_provider_outcomes_partial(self, db: Session) -> None:
        ind = _make_indicator(db, "4.4.4.4")
        now = datetime.now(timezone.utc)

        # VirusTotal SUCCESS
        db.add(
            ThreatIntelLookup(
                event_id=None,
                origin="manual",
                indicator_id=ind.id,
                provider="VirusTotal",
                status=LookupStatus.SUCCESS,
                performed_at=now,
                provenance="enriched",
                found=True,
            )
        )
        # AbuseIPDB ERROR
        db.add(
            ThreatIntelLookup(
                event_id=None,
                origin="manual",
                indicator_id=ind.id,
                provider="abuseipdb",
                status=LookupStatus.ERROR,
                performed_at=now,
                provenance="enriched",
                error_type="RateLimit",
            )
        )
        db.commit()

        query_svc = ThreatIntelQueryService(db)
        record = query_svc.list_indicators(value_filter="4.4.4.4").items[0]
        assert record.lookup_count == 2
        assert record.success_count == 1
        assert record.error_count == 1
        assert record.status == "partial"
        assert record.providers == ["VirusTotal", "abuseipdb"]

    def test_equal_timestamps_deterministic_tie_breaker(self, db: Session) -> None:
        ind = _make_indicator(db, "5.5.5.5")
        same_time = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)
        id1 = uuid.UUID("00000000-0000-0000-0000-000000000001")
        id2 = uuid.UUID("00000000-0000-0000-0000-000000000002")

        # id1 is ERROR, id2 is SUCCESS (id2 > id1, so id2 wins tie-breaker)
        db.add(
            ThreatIntelLookup(
                id=id1,
                event_id=None,
                origin="manual",
                indicator_id=ind.id,
                provider="VirusTotal",
                status=LookupStatus.ERROR,
                performed_at=same_time,
                provenance="enriched",
                error_type="Timeout",
            )
        )
        db.add(
            ThreatIntelLookup(
                id=id2,
                event_id=None,
                origin="manual",
                indicator_id=ind.id,
                provider="VirusTotal",
                status=LookupStatus.SUCCESS,
                performed_at=same_time,
                provenance="enriched",
                found=True,
            )
        )
        db.commit()

        query_svc = ThreatIntelQueryService(db)
        record = query_svc.list_indicators(value_filter="5.5.5.5").items[0]
        assert record.status == "enriched"
        assert record.success_count == 1
        assert record.error_count == 0

    def test_indicator_with_no_lookups_reports_no_lookup(self, db: Session) -> None:
        ind = _make_indicator(db, "6.6.6.6")
        query_svc = ThreatIntelQueryService(db)
        record = query_svc.list_indicators(value_filter="6.6.6.6").items[0]
        assert record.lookup_count == 0
        assert record.success_count == 0
        assert record.error_count == 0
        assert record.status == "no_lookup"


# ===========================================================================
# 3. Origin Validation & Migration Safety
# ===========================================================================


class TestOriginValidationAndMigrationSafety:
    def test_origin_check_constraint_rejects_invalid_origin(self, db: Session) -> None:
        ind = _make_indicator(db, "7.7.7.7")
        now = datetime.now(timezone.utc)
        invalid_lookup = ThreatIntelLookup(
            event_id=None,
            origin="invalid_origin_value",
            indicator_id=ind.id,
            provider="VirusTotal",
            status=LookupStatus.SUCCESS,
            performed_at=now,
            provenance="enriched",
        )
        db.add(invalid_lookup)
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()

    def test_downgrade_precondition_aborts_when_manual_records_exist(self) -> None:
        from app.database.postgres.migrations.versions.e7f8a9b0c1d2_allow_manual_threat_intel_lookups import downgrade
        mock_op = MagicMock()
        mock_bind = MagicMock()
        mock_bind.execute.return_value.scalar.return_value = 5  # 5 manual records exist
        mock_op.get_bind.return_value = mock_bind

        with patch("app.database.postgres.migrations.versions.e7f8a9b0c1d2_allow_manual_threat_intel_lookups.op", mock_op):
            with pytest.raises(RuntimeError) as exc_info:
                downgrade()
            assert "Cannot downgrade migration e7f8a9b0c1d2: 5 manual lookup record(s) exist" in str(exc_info.value)

    def test_downgrade_precondition_succeeds_when_no_manual_records_exist(self) -> None:
        from app.database.postgres.migrations.versions.e7f8a9b0c1d2_allow_manual_threat_intel_lookups import downgrade
        mock_op = MagicMock()
        mock_bind = MagicMock()
        mock_bind.execute.return_value.scalar.return_value = 0  # 0 manual records
        mock_op.get_bind.return_value = mock_bind

        with patch("app.database.postgres.migrations.versions.e7f8a9b0c1d2_allow_manual_threat_intel_lookups.op", mock_op):
            downgrade()
            mock_op.drop_constraint.assert_called_once_with('ck_threat_intel_lookups_origin_valid', 'threat_intel_lookups', type_='check')
            mock_op.drop_column.assert_called_once_with('threat_intel_lookups', 'origin')

    def test_duplicate_preflight_check_aborts_if_duplicates_exist(self) -> None:
        from app.database.postgres.migrations.versions.f8a9b0c1d2e3_event_lookup_idempotency_index import upgrade
        mock_op = MagicMock()
        mock_bind = MagicMock()
        mock_bind.execute.return_value.fetchall.return_value = [
            (uuid.uuid4(), uuid.uuid4(), "VirusTotal", 2)
        ]
        mock_op.get_bind.return_value = mock_bind

        with patch("app.database.postgres.migrations.versions.f8a9b0c1d2e3_event_lookup_idempotency_index.op", mock_op):
            with pytest.raises(RuntimeError) as exc_info:
                upgrade()
            assert "Cannot create unique index ix_threat_intel_lookups_event_indicator_provider: found 1 duplicate group(s)" in str(exc_info.value)


# ===========================================================================
# 4. Rate Limiting Tests
# ===========================================================================


class TestRateLimiting:
    def test_in_memory_rate_limiter_allows_under_limit(self) -> None:
        limiter = InMemoryRateLimiter(requests_per_minute=3)
        user = "test_user_1"

        assert limiter.check(user).allowed is True
        assert limiter.check(user).allowed is True
        assert limiter.check(user).allowed is True
        # 4th request exceeds limit
        status = limiter.check(user)
        assert status.allowed is False
        assert status.remaining == 0
        assert status.reset_after > 0

    def test_independent_authenticated_identities(self) -> None:
        limiter = InMemoryRateLimiter(requests_per_minute=2)
        u1 = "user_alpha"
        u2 = "user_beta"

        assert limiter.check(u1).allowed is True
        assert limiter.check(u1).allowed is True
        assert limiter.check(u1).allowed is False

        # u2 has its own separate quota
        assert limiter.check(u2).allowed is True
        assert limiter.check(u2).allowed is True
        assert limiter.check(u2).allowed is False

    def test_disabled_rate_limiter_always_allows(self) -> None:
        limiter = InMemoryRateLimiter(requests_per_minute=1)
        limiter.enabled = False
        user = "user_test"

        assert limiter.check(user).allowed is True
        assert limiter.check(user).allowed is True


# ===========================================================================
# 5. Non-Public IP Protection Regression (Documentation Ranges)
# ===========================================================================


class TestDocumentationIPProtectionRegression:
    @pytest.mark.parametrize(
        "doc_ip,expected_substring",
        [
            ("192.0.2.1", "documentation IPv4 address"),
            ("192.0.2.254", "documentation IPv4 address"),
            ("198.51.100.1", "documentation IPv4 address"),
            ("198.51.100.254", "documentation IPv4 address"),
            ("203.0.113.1", "documentation IPv4 address"),
            ("203.0.113.254", "documentation IPv4 address"),
            ("2001:db8::1", "documentation IPv6 address"),
            ("2001:db8:ffff:ffff::1", "documentation IPv6 address"),
        ],
    )
    def test_all_documentation_ranges_skipped_in_production(
        self, doc_ip: str, expected_substring: str
    ) -> None:
        """In production, documentation IP ranges must be classified as non-public and skipped."""
        reason = classify_non_public_ip(doc_ip)
        assert reason is not None
        assert expected_substring in reason
        assert is_non_public_ip(doc_ip) is True

        skip, skip_reason = should_skip_external_lookup(IndicatorType.IP, doc_ip)
        assert skip is True
        assert skip_reason == reason

    @pytest.mark.parametrize(
        "public_ip",
        [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "185.10.10.10",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
        ],
    )
    def test_public_ips_remain_eligible_for_lookup(self, public_ip: str) -> None:
        assert classify_non_public_ip(public_ip) is None
        assert is_non_public_ip(public_ip) is False
        skip, _ = should_skip_external_lookup(IndicatorType.IP, public_ip)
        assert skip is False

    def test_explicit_test_only_configuration_permits_documentation_ips_when_opted_in(
        self,
    ) -> None:
        """When explicitly opted in for mock provider test suites, documentation IPs are allowed."""
        doc_ip = "192.0.2.10"
        # Production default: strictly blocked
        assert classify_non_public_ip(doc_ip) is not None

        # Test-only explicit opt-in: permitted
        assert classify_non_public_ip(doc_ip, allow_documentation_ips=True) is None
        assert is_non_public_ip(doc_ip, allow_documentation_ips=True) is False
        skip, _ = should_skip_external_lookup(IndicatorType.IP, doc_ip, allow_documentation_ips=True)
        assert skip is False
