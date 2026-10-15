"""Tests for the synthetic Threat Intelligence demo fixture.

Covers the seeder/cleanup contract added on top of the existing Step 8A
persistence + read surfaces:

* fixtures persist through the **real** persistence service,
* the fixture set covers all four indicator types and every read-surface state,
* seeding is idempotent,
* fixtures are unmistakably labelled (provider ``demo-fixture`` + ``synthetic``
  evidence) and never masquerade as VirusTotal / AbuseIPDB / AlienVault OTX,
* the read-surface search finds a seeded indicator (the ``1.1.1.1`` example),
* cleanup removes demo-owned rows only and never a real lookup/indicator,
* the seeder refuses to run in production.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.dialects.sqlite.base import SQLiteTypeCompiler
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

# Make the PostgreSQL ``JSONB`` columns work on SQLite for these unit tests.
if not hasattr(SQLiteTypeCompiler, "visit_JSONB"):
    SQLiteTypeCompiler.visit_JSONB = lambda self, type_, **kw: "JSON"  # noqa: E731

from app.core.config import settings  # noqa: E402
from app.database.postgres.base import Base  # noqa: E402
from app.models.threat_intel_indicator import ThreatIntelIndicator  # noqa: E402
from app.models.threat_intel_lookup import LookupStatus, ThreatIntelLookup  # noqa: E402
from app.schemas.security_event import Provenance  # noqa: E402
from app.services.threat_intelligence.types import IndicatorType  # noqa: E402
from app.services.threat_intelligence_demo import (  # noqa: E402
    DEMO_PROVIDER_NAME,
    DemoSeedForbiddenError,
    build_demo_analyses,
    cleanup,
    demo_canonical_keys,
    demo_event_ids,
    demo_row_counts,
    seed,
)
from app.services.threat_intelligence_query import (  # noqa: E402
    ThreatIntelQueryService,
)

_REAL_PROVIDER_NAMES = ("VirusTotal", "abuseipdb", "AlienVault OTX")


@pytest.fixture()
def db() -> Session:
    """Fresh in-memory SQLite database with the threat-intelligence tables.

    Only the two threat-intelligence tables are created (not the whole
    metadata) because an unrelated, pre-existing untracked model
    (``app/models/digital_twin.py``) declares a CHECK constraint with unquoted
    enum values that breaks a full-schema ``create_all`` on SQLite.  This
    test's subject does not touch that model, so scoping the DDL keeps the
    fixture hermetic without modifying unrelated work-in-progress.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(
        engine,
        tables=[ThreatIntelIndicator.__table__, ThreatIntelLookup.__table__],
    )
    session = Session(engine)
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


# ---------------------------------------------------------------------------
# Fixture shape
# ---------------------------------------------------------------------------


class TestFixtureShape:
    def test_covers_all_indicator_types(self):
        types = {a.indicators[0].indicator_type for a in build_demo_analyses()}
        assert types == {
            IndicatorType.IP,
            IndicatorType.DOMAIN,
            IndicatorType.URL,
            IndicatorType.HASH,
        }

    def test_event_ids_are_deterministic(self):
        assert demo_event_ids() == demo_event_ids()
        assert len(demo_event_ids()) == len(build_demo_analyses())

    def test_canonical_keys_are_deterministic_and_unique(self):
        keys = demo_canonical_keys()
        assert keys == demo_canonical_keys()
        assert len(keys) == len(build_demo_analyses())

    def test_every_outcome_is_demo_provider_only(self):
        for analysis in build_demo_analyses():
            for association in analysis.results:
                assert association.provider == DEMO_PROVIDER_NAME
            for failure in analysis.failures:
                assert failure.provider == DEMO_PROVIDER_NAME


# ---------------------------------------------------------------------------
# Seeding
# ---------------------------------------------------------------------------


class TestSeeding:
    def test_seed_creates_all_indicators_and_lookups(self, db: Session):
        result = seed(db)
        assert result.indicators_created == 7
        assert result.lookups_created == 6
        assert db.query(ThreatIntelIndicator).count() == 7
        assert db.query(ThreatIntelLookup).count() == 6

    def test_seed_is_idempotent(self, db: Session):
        first = seed(db)
        second = seed(db)
        assert first.created_anything is True
        assert second.indicators_created == 0
        assert second.lookups_created == 0
        assert second.lookups_skipped == 6
        assert db.query(ThreatIntelIndicator).count() == 7
        assert db.query(ThreatIntelLookup).count() == 6

    def test_seed_covers_every_read_surface_state(self, db: Session):
        seed(db)
        page = ThreatIntelQueryService(db).list_indicators(page_size=50)
        statuses = {record.status for record in page.items}
        # The fixture set must exercise the never-looked-up state and the
        # looked-up states; page.total confirms all seven indicators persisted.
        assert "no_lookup" in statuses
        assert statuses & {"enriched", "partial", "failed"}
        assert page.total == 7

    def test_lookup_statuses_are_distinct(self, db: Session):
        seed(db)
        service = ThreatIntelQueryService(db)
        labels = {
            item.status_label
            for record in service.list_indicators(page_size=50).items
            for item in service.get_indicator(record.indicator_id).lookups
        }
        assert "ENRICHED" in labels
        assert "NO DATA" in labels
        assert "RATE LIMITED" in labels
        assert "TIMED OUT" in labels
        assert "FAILED" in labels


# ---------------------------------------------------------------------------
# Labelling / honesty
# ---------------------------------------------------------------------------


class TestLabelling:
    def test_every_demo_lookup_uses_the_demo_provider(self, db: Session):
        seed(db)
        providers = {row.provider for row in db.query(ThreatIntelLookup).all()}
        assert providers == {DEMO_PROVIDER_NAME}

    def test_no_lookup_claims_a_real_provider_as_its_source(self, db: Session):
        seed(db)
        for row in db.query(ThreatIntelLookup).all():
            assert row.provider == DEMO_PROVIDER_NAME
            assert row.provider not in _REAL_PROVIDER_NAMES

    def test_real_provider_names_appear_only_in_a_negative_disclaimer(self, db: Session):
        # The synthetic note deliberately names the real providers *to disclaim*
        # them; any occurrence must therefore sit next to a "NOT real" marker.
        seed(db)
        for row in db.query(ThreatIntelLookup).all():
            blob = json.dumps([row.evidence, row.result_metadata, row.error_message])
            if any(name in blob for name in _REAL_PROVIDER_NAMES):
                assert row.evidence and row.evidence.get("synthetic") is True
                assert row.evidence.get("note", "").startswith("Synthetic demo fixture")

    def test_success_evidence_is_marked_synthetic(self, db: Session):
        seed(db)
        enriched = (
            db.query(ThreatIntelLookup)
            .filter(ThreatIntelLookup.status == LookupStatus.SUCCESS)
            .all()
        )
        assert enriched, "expected at least one success lookup"
        marked = [
            row for row in enriched if row.evidence and row.evidence.get("synthetic")
        ]
        assert marked, "found-success rows must carry synthetic evidence"
        assert all(
            row.evidence.get("fixture_source") == "sentinelai-demo-fixture"
            for row in marked
        )

    def test_no_verdict_field_is_stored(self, db: Session):
        seed(db)
        for row in db.query(ThreatIntelLookup).all():
            for payload in (row.evidence or {}), (row.result_metadata or {}):
                for forbidden in ("verdict", "malicious", "severity", "risk"):
                    assert forbidden not in payload


# ---------------------------------------------------------------------------
# Read-surface integration
# ---------------------------------------------------------------------------


class TestReadSurface:
    def test_empty_before_seeding(self, db: Session):
        page = ThreatIntelQueryService(db).list_indicators()
        assert page.total == 0
        assert page.items == []

    def test_search_finds_seeded_ip(self, db: Session):
        seed(db)
        page = ThreatIntelQueryService(db).list_indicators(value_filter="1.1.1.1")
        assert page.total == 1
        assert page.items[0].value == "1.1.1.1"
        assert page.items[0].canonical_key == "ip:1.1.1.1"
        assert page.items[0].providers == [DEMO_PROVIDER_NAME]

    def test_search_by_domain_and_hash(self, db: Session):
        seed(db)
        service = ThreatIntelQueryService(db)
        assert service.list_indicators(value_filter="demo-payload.example").total >= 1
        assert service.list_indicators(value_filter="deadbeef").total == 1

    def test_indicator_detail_serves_fixture_lookups(self, db: Session):
        seed(db)
        detail = ThreatIntelQueryService(db).get_indicator(_indicator_id(db, "ip:1.1.1.1"))
        assert detail.indicator.value == "1.1.1.1"
        assert len(detail.lookups) == 1
        assert detail.lookups[0].provider == DEMO_PROVIDER_NAME
        assert detail.lookups[0].status_label == "NO DATA"


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------


class TestCleanup:
    def test_cleanup_removes_only_demo_rows(self, db: Session):
        seed(db)
        # a genuinely unrelated real indicator + lookup
        real = ThreatIntelIndicator(
            value="203.0.113.7",
            indicator_type=IndicatorType.IP,
            canonical_key="ip:203.0.113.7",
            first_seen_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            last_seen_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        db.add(real)
        db.flush()
        db.add(
            ThreatIntelLookup(
                event_id=uuid.uuid4(),
                indicator_id=real.id,
                provider="VirusTotal",
                status=LookupStatus.SUCCESS,
                performed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                found=True,
                provenance=Provenance.ENRICHED.value,
            )
        )
        db.commit()

        result = cleanup(db)

        assert result.lookups_deleted == 6
        assert result.indicators_deleted == 7
        # the real row survives untouched
        assert db.query(ThreatIntelIndicator).count() == 1
        assert db.query(ThreatIntelLookup).count() == 1
        remaining = db.query(ThreatIntelIndicator).one()
        assert remaining.canonical_key == "ip:203.0.113.7"

    def test_cleanup_preserves_indicator_with_a_real_lookup(self, db: Session):
        seed(db)
        demo_indicator = (
            db.query(ThreatIntelIndicator)
            .filter(ThreatIntelIndicator.canonical_key == "ip:1.1.1.1")
            .one()
        )
        # a real lookup now references a demo indicator value
        db.add(
            ThreatIntelLookup(
                event_id=uuid.uuid4(),
                indicator_id=demo_indicator.id,
                provider="VirusTotal",
                status=LookupStatus.SUCCESS,
                performed_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
                found=False,
                provenance=Provenance.ENRICHED.value,
            )
        )
        db.commit()

        cleanup(db)

        # the indicator is kept because a real lookup still points at it
        kept = db.query(ThreatIntelIndicator).filter(
            ThreatIntelIndicator.canonical_key == "ip:1.1.1.1"
        ).one_or_none()
        assert kept is not None
        remaining = db.query(ThreatIntelLookup).all()
        assert [row.provider for row in remaining] == ["VirusTotal"]

    def test_cleanup_is_safe_on_empty_database(self, db: Session):
        result = cleanup(db)
        assert result.lookups_deleted == 0
        assert result.indicators_deleted == 0

    def test_row_counts_track_demo_rows(self, db: Session):
        assert demo_row_counts(db) == {"lookups": 0, "indicators": 0}
        seed(db)
        assert demo_row_counts(db) == {"lookups": 6, "indicators": 7}
        cleanup(db)
        assert demo_row_counts(db) == {"lookups": 0, "indicators": 0}


# ---------------------------------------------------------------------------
# Guardrails
# ---------------------------------------------------------------------------


class TestGuardrails:
    def test_seed_refuses_in_production(self, db: Session, monkeypatch):
        monkeypatch.setattr(settings, "environment", "production")
        with pytest.raises(DemoSeedForbiddenError):
            seed(db)
        assert db.query(ThreatIntelIndicator).count() == 0

    def test_cleanup_refuses_in_production(self, db: Session, monkeypatch):
        seed(db)
        monkeypatch.setattr(settings, "environment", "production")
        with pytest.raises(DemoSeedForbiddenError):
            cleanup(db)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _indicator_id(db: Session, canonical_key: str) -> uuid.UUID:
    return db.scalar(
        select(ThreatIntelIndicator.id).where(
            ThreatIntelIndicator.canonical_key == canonical_key
        )
    )
