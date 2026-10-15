"""Tests for the read-only Threat Intelligence API (Step 8A read surface).

Covers the ``GET /api/threat-intelligence/...`` contract added on top of the
existing Step 8A persistence layer.  Two layers are exercised:

* **Transport** — through the real FastAPI app with the real JWT
  authentication and ``require_role`` RBAC dependencies, so auth and RBAC are
  tested as deployed rather than re-implemented.
* **Service** — against a fresh in-memory database seeded with rows that
  mirror what ``ThreatIntelligencePersistenceService`` writes, so ordering,
  filtering, pagination bounds, and UTC normalization are verified
  deterministically without depending on rows left behind by other tests.

Security properties pinned here:

1.  Authentication and RBAC are enforced.
2.  Only ``GET`` routes exist; the read surface cannot write.
3.  No provider credential, raw response body, or raw exception escapes.
4.  Reads are bounded and deterministically ordered.
5.  No verdict/severity/risk field is ever emitted.
6.  Provenance stays ``observed`` on indicators and ``enriched`` on lookups.
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
# Test-only type-compiler adapter; production DDL keeps JSONB.
if not hasattr(SQLiteTypeCompiler, "visit_JSONB"):
    SQLiteTypeCompiler.visit_JSONB = lambda self, type_, **kw: "JSON"  # noqa: E731

from app.database.postgres.base import Base  # noqa: E402
from app.models.threat_intel_indicator import ThreatIntelIndicator  # noqa: E402
from app.models.threat_intel_lookup import LookupStatus, ThreatIntelLookup  # noqa: E402
from app.schemas.security_event import Provenance  # noqa: E402
from app.services.threat_intelligence.types import IndicatorType  # noqa: E402
from app.services.threat_intelligence_query import (  # noqa: E402
    MAX_LOOKUPS_PER_INDICATOR,
    MAX_PAGE_SIZE,
    ThreatIntelIndicatorNotFoundError,
    ThreatIntelQueryService,
    ThreatIntelQueryValidationError,
    sanitize_evidence,
    sanitize_free_text,
)

INDICATORS_URL = "/api/threat-intelligence/indicators"
BASE_TIME = datetime(2026, 9, 28, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def ti_db():
    """Fresh in-memory SQLite database with the full model schema.

    Named ``ti_db`` rather than ``db_session`` so it does not shadow the
    session-scoped ``db_session`` in ``tests/conftest.py`` that the shared
    auth fixtures depend on.
    """
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


@pytest.fixture()
def service(ti_db: Session) -> ThreatIntelQueryService:
    return ThreatIntelQueryService(ti_db)


def make_indicator(
    session: Session,
    *,
    value: str = "8.8.8.8",
    indicator_type: IndicatorType = IndicatorType.IP,
    first_seen: datetime = BASE_TIME - timedelta(days=2),
    last_seen: datetime = BASE_TIME - timedelta(hours=1),
) -> ThreatIntelIndicator:
    """Insert an indicator exactly as the persistence service would."""
    row = ThreatIntelIndicator(
        value=value,
        indicator_type=indicator_type,
        canonical_key=f"{indicator_type.value}:{value.lower() if indicator_type in (IndicatorType.DOMAIN, IndicatorType.HASH) else value}",
        first_seen_at=first_seen,
        last_seen_at=last_seen,
    )
    session.add(row)
    session.flush()
    return row


def make_lookup(
    session: Session,
    indicator: ThreatIntelIndicator,
    *,
    event_id: uuid.UUID | None = None,
    provider: str = "VirusTotal",
    status: LookupStatus = LookupStatus.SUCCESS,
    performed_at: datetime = BASE_TIME,
    found: bool | None = True,
    confidence: float | None = None,
    error_type: str | None = None,
    error_message: str | None = None,
    retryable: bool | None = None,
    result_timestamp: datetime | None = None,
    evidence: dict | None = None,
    result_metadata: dict | None = None,
) -> ThreatIntelLookup:
    """Insert a lookup row with the ``enriched`` provenance the table enforces."""
    row = ThreatIntelLookup(
        event_id=event_id or uuid.uuid4(),
        indicator_id=indicator.id,
        provider=provider,
        status=status,
        performed_at=performed_at,
        found=found,
        confidence=confidence,
        error_type=error_type,
        error_message=error_message,
        retryable=retryable,
        evidence=evidence,
        result_metadata=result_metadata,
        result_timestamp=(
            result_timestamp
            if result_timestamp is not None
            else (performed_at if status == LookupStatus.SUCCESS else None)
        ),
        provenance=Provenance.ENRICHED.value,
    )
    session.add(row)
    session.flush()
    return row


# ---------------------------------------------------------------------------
# 1/2. Authentication and RBAC
# ---------------------------------------------------------------------------


class TestAuthentication:
    def test_list_requires_authentication(self, client) -> None:
        """An anonymous caller gets 401, never data."""
        response = client.get(INDICATORS_URL)
        assert response.status_code == 401

    def test_detail_requires_authentication(self, client) -> None:
        response = client.get(f"{INDICATORS_URL}/{uuid.uuid4()}")
        assert response.status_code == 401

    def test_events_endpoint_requires_authentication(self, client) -> None:
        response = client.get(f"{INDICATORS_URL}/{uuid.uuid4()}/events")
        assert response.status_code == 401

    def test_rejects_a_malformed_bearer_token(self, client) -> None:
        response = client.get(INDICATORS_URL, headers={"Authorization": "Bearer nope"})
        assert response.status_code == 401

    def test_rejects_an_empty_bearer_token(self, client) -> None:
        response = client.get(INDICATORS_URL, headers={"Authorization": "Bearer "})
        assert response.status_code == 401


class TestRbac:
    @pytest.mark.parametrize(
        "token_fixture", ["admin_token", "analyst_token", "ciso_token"]
    )
    def test_read_roles_are_allowed(self, client, request, token_fixture: str) -> None:
        """admin, analyst, and ciso all have threat-intelligence read access."""
        token = request.getfixturevalue(token_fixture)
        response = client.get(INDICATORS_URL, headers=auth(token))
        assert response.status_code == 200

    def test_viewer_role_is_denied(self, client, db_session: Session) -> None:
        """viewer is excluded, consistent with the other SOC read surfaces."""
        from app.core.security import create_access_token, hash_password
        from app.models.role import Role
        from app.models.user import User

        role = db_session.execute(
            select(Role).where(Role.name == "viewer")
        ).scalar_one_or_none()
        if role is None:
            role = Role(name="viewer", description="read-mostly role")
            db_session.add(role)
            db_session.commit()

        user = User(
            email=f"test-viewer-{uuid.uuid4().hex[:8]}@example.com",
            password_hash=hash_password("TestPassword123!"),
            is_active=True,
            role_id=role.id,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        response = client.get(
            INDICATORS_URL, headers=auth(create_access_token(str(user.id)))
        )
        assert response.status_code == 403
        assert response.json()["detail"] == "Insufficient permissions"

    def test_authorization_denial_is_audited(self, client, db_session: Session) -> None:
        """A denied read is recorded by require_role, like every other route."""
        from app.core.security import create_access_token, hash_password
        from app.models.audit_log import AuditLog
        from app.models.role import Role
        from app.models.user import User

        role = db_session.execute(
            select(Role).where(Role.name == "viewer")
        ).scalar_one_or_none()
        if role is None:
            role = Role(name="viewer", description="read-mostly role")
            db_session.add(role)
            db_session.commit()

        user = User(
            email=f"test-audit-viewer-{uuid.uuid4().hex[:8]}@example.com",
            password_hash=hash_password("TestPassword123!"),
            is_active=True,
            role_id=role.id,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        before = db_session.execute(
            select(func.count()).select_from(AuditLog)
        ).scalar_one()
        response = client.get(
            INDICATORS_URL, headers=auth(create_access_token(str(user.id)))
        )
        assert response.status_code == 403
        db_session.expire_all()
        after = db_session.execute(
            select(func.count()).select_from(AuditLog)
        ).scalar_one()
        assert after == before + 1

        latest = db_session.execute(
            select(AuditLog)
            .where(AuditLog.user_id == user.id)
            .order_by(AuditLog.created_at.desc())
            .limit(1)
        ).scalar_one()
        assert latest.action == "auth.authorization.denied"
        assert "admin, analyst, ciso" in (latest.details or "")


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


class TestTransportValidation:
    """Invalid input must be a clean 4xx, never a 500.

    These exercise the service's validation raises through the real route, so
    a raise that escapes ``_call_service`` is caught here rather than in
    production logs.
    """

    def test_unknown_indicator_type_is_422(self, client, admin_token: str) -> None:
        response = client.get(
            f"{INDICATORS_URL}?indicator_type=banana", headers=auth(admin_token)
        )
        assert response.status_code == 422
        assert "indicator_type" in response.json()["detail"]

    def test_oversized_search_filter_is_422(self, client, admin_token: str) -> None:
        response = client.get(
            f"{INDICATORS_URL}?q={'x' * 513}", headers=auth(admin_token)
        )
        assert response.status_code == 422
        assert "q" in response.json()["detail"]

    def test_page_below_one_is_422(self, client, admin_token: str) -> None:
        assert (
            client.get(f"{INDICATORS_URL}?page=0", headers=auth(admin_token)).status_code
            == 422
        )

    def test_page_size_above_the_cap_is_422(self, client, admin_token: str) -> None:
        assert (
            client.get(
                f"{INDICATORS_URL}?page_size={MAX_PAGE_SIZE + 1}",
                headers=auth(admin_token),
            ).status_code
            == 422
        )

    def test_non_numeric_pagination_is_422(self, client, admin_token: str) -> None:
        assert (
            client.get(f"{INDICATORS_URL}?page=many", headers=auth(admin_token)).status_code
            == 422
        )

    def test_malformed_indicator_id_is_422(self, client, admin_token: str) -> None:
        response = client.get(f"{INDICATORS_URL}/not-a-uuid", headers=auth(admin_token))
        assert response.status_code == 422

    def test_unknown_indicator_id_is_404(self, client, admin_token: str) -> None:
        response = client.get(
            f"{INDICATORS_URL}/{uuid.uuid4()}", headers=auth(admin_token)
        )
        assert response.status_code == 404
        assert response.json()["detail"] == "Indicator not found"

    def test_events_for_unknown_indicator_is_404(self, client, admin_token: str) -> None:
        response = client.get(
            f"{INDICATORS_URL}/{uuid.uuid4()}/events", headers=auth(admin_token)
        )
        assert response.status_code == 404

    def test_valid_filters_are_accepted(self, client, admin_token: str) -> None:
        response = client.get(
            f"{INDICATORS_URL}?indicator_type=ip&q=8.8.8.8&page=1&page_size=10",
            headers=auth(admin_token),
        )
        assert response.status_code == 200
        body = response.json()
        assert body["read_only"] is True
        assert body["verdict_available"] is False
        assert isinstance(body["items"], list)

    def test_wildcard_search_does_not_match_everything(
        self, client, admin_token: str
    ) -> None:
        """A bare ``%`` must not widen the filter into a full scan."""
        response = client.get(f"{INDICATORS_URL}?q=%25", headers=auth(admin_token))
        assert response.status_code == 200
        # Whatever the demo data holds, a literal '%' matches no real indicator.
        assert response.json()["items"] == []


# ---------------------------------------------------------------------------
# 5/6. Empty database, list contents, filters
# ---------------------------------------------------------------------------


class TestList:
    def test_empty_database_returns_an_empty_collection(self, service) -> None:
        """No data means an empty page, never demo rows."""
        result = service.list_indicators()
        assert result.items == []
        assert result.total == 0
        assert result.page == 1
        assert result.page_size == 50

    def test_returns_persisted_indicators(self, service, ti_db: Session) -> None:
        make_indicator(ti_db, value="8.8.8.8")
        make_indicator(
            ti_db,
            value="google.com",
            indicator_type=IndicatorType.DOMAIN,
            first_seen=BASE_TIME - timedelta(days=1),
            last_seen=BASE_TIME - timedelta(minutes=5),
        )
        ti_db.commit()

        result = service.list_indicators()
        assert result.total == 2
        assert {row.value for row in result.items} == {"8.8.8.8", "google.com"}
        assert result.read_only is True
        assert result.verdict_available is False

    def test_indicator_with_no_lookups_reports_no_lookup(self, service, ti_db: Session) -> None:
        make_indicator(ti_db, value="1.1.1.1")
        ti_db.commit()

        record = service.list_indicators().items[0]
        assert record.status == "no_lookup"
        assert record.lookup_count == 0
        assert record.providers == []
        assert record.latest_lookup_at is None

    def test_filters_by_indicator_type(self, service, ti_db: Session) -> None:
        make_indicator(ti_db, value="8.8.8.8")
        make_indicator(
            ti_db, value="google.com", indicator_type=IndicatorType.DOMAIN
        )
        ti_db.commit()

        result = service.list_indicators(indicator_type="domain")
        assert result.total == 1
        assert result.items[0].value == "google.com"

    def test_filters_by_value_substring(self, service, ti_db: Session) -> None:
        make_indicator(ti_db, value="8.8.8.8")
        make_indicator(
            ti_db, value="google.com", indicator_type=IndicatorType.DOMAIN
        )
        ti_db.commit()

        result = service.list_indicators(value_filter="goog")
        assert result.total == 1
        assert result.items[0].value == "google.com"

    def test_search_is_case_insensitive(self, service, ti_db: Session) -> None:
        make_indicator(
            ti_db, value="Google.COM", indicator_type=IndicatorType.DOMAIN
        )
        ti_db.commit()

        assert service.list_indicators(value_filter="GOOGLE").total == 1

    def test_search_treats_wildcards_as_literals(self, service, ti_db: Session) -> None:
        """A caller cannot turn the filter into a match-everything pattern."""
        make_indicator(ti_db, value="8.8.8.8")
        make_indicator(
            ti_db, value="google.com", indicator_type=IndicatorType.DOMAIN
        )
        ti_db.commit()

        assert service.list_indicators(value_filter="%").total == 0
        assert service.list_indicators(value_filter="_").total == 0

    def test_rolls_up_provider_lookups(self, service, ti_db: Session) -> None:
        indicator = make_indicator(ti_db, value="8.8.8.8")
        make_lookup(
            ti_db, indicator, provider="VirusTotal", evidence={"asn": 15169}
        )
        make_lookup(
            ti_db,
            indicator,
            provider="abuseipdb",
            status=LookupStatus.ERROR,
            found=None,
            error_type="rate_limit",
            error_message="rate limited",
        )
        ti_db.commit()

        record = service.list_indicators().items[0]
        assert record.lookup_count == 2
        assert record.success_count == 1
        assert record.error_count == 1
        assert record.providers == ["VirusTotal", "abuseipdb"]
        assert record.status == "partial"

    def test_reports_enriched_only_when_no_lookup_failed(
        self, service, ti_db: Session
    ) -> None:
        indicator = make_indicator(ti_db)
        make_lookup(ti_db, indicator, provider="VirusTotal", evidence={"a": 1})
        ti_db.commit()

        record = service.list_indicators().items[0]
        assert record.status == "enriched"
        assert record.error_count == 0

    def test_reports_failed_when_every_lookup_failed(
        self, service, ti_db: Session
    ) -> None:
        indicator = make_indicator(ti_db)
        make_lookup(
            ti_db,
            indicator,
            status=LookupStatus.ERROR,
            found=None,
            error_type="timeout",
        )
        ti_db.commit()

        record = service.list_indicators().items[0]
        assert record.status == "failed"
        assert record.success_count == 0

    def test_providers_do_not_leak_between_indicators(
        self, service, ti_db: Session
    ) -> None:
        """Each indicator gets its own provider list."""
        first = make_indicator(ti_db, value="8.8.8.8")
        second = make_indicator(
            ti_db, value="google.com", indicator_type=IndicatorType.DOMAIN
        )
        make_lookup(ti_db, first, provider="VirusTotal")
        make_lookup(ti_db, second, provider="AlienVault OTX")
        ti_db.commit()

        by_value = {row.value: row for row in service.list_indicators().items}
        assert by_value["8.8.8.8"].providers == ["VirusTotal"]
        assert by_value["google.com"].providers == ["AlienVault OTX"]


# ---------------------------------------------------------------------------
# 4. Deterministic ordering
# ---------------------------------------------------------------------------


class TestOrdering:
    """Ordering is ``last_seen_at`` DESC, then ``id`` ASC.

    The assertions below check the *invariants* of that clause rather than
    hard-coding which row wins a tie: ``last_seen_at`` must be
    non-increasing across the page, and within one timestamp group the ids
    must come back ascending.  That is dialect-independent -- comparing
    Python ``uuid.UUID`` values to the database's own UUID collation is not,
    and a test that depended on it would be testing the store, not the
    query.
    """

    def _seed(self, session: Session) -> None:
        """Seed distinct ``last_seen`` values plus one deliberate tie."""
        make_indicator(session, value="1.1.1.1", last_seen=BASE_TIME - timedelta(hours=3))
        make_indicator(session, value="8.8.8.8", last_seen=BASE_TIME - timedelta(hours=1))
        make_indicator(session, value="9.9.9.9", last_seen=BASE_TIME - timedelta(hours=2))
        make_indicator(session, value="4.4.4.4", last_seen=BASE_TIME)
        make_indicator(session, value="5.5.5.5", last_seen=BASE_TIME)
        session.commit()

    def test_last_seen_is_non_increasing(self, service, ti_db: Session) -> None:
        self._seed(ti_db)
        records = service.list_indicators().items
        assert len(records) == 5
        seen = [r.last_seen for r in records]
        assert seen == sorted(seen, reverse=True)

    def test_most_recently_observed_indicator_is_first(
        self, service, ti_db: Session
    ) -> None:
        self._seed(ti_db)
        records = service.list_indicators().items
        # 8.8.8.8 is the most recent non-tied observation.
        assert records[2].value == "8.8.8.8"
        assert records[-1].value == "1.1.1.1"

    def test_indicators_sharing_a_timestamp_come_back_in_id_order(
        self, service, ti_db: Session
    ) -> None:
        """The id tie-break is what makes equal timestamps deterministic."""
        self._seed(ti_db)
        tied_group = [
            r for r in service.list_indicators().items if r.last_seen == BASE_TIME
        ]
        assert len(tied_group) == 2
        ids = [r.indicator_id for r in tied_group]
        assert ids == sorted(ids)
        assert {r.value for r in tied_group} == {"4.4.4.4", "5.5.5.5"}

    def test_pages_do_not_duplicate_or_drop_tied_rows(
        self, service, ti_db: Session
    ) -> None:
        self._seed(ti_db)
        pages = [
            [r.indicator_id for r in service.list_indicators(page_size=2, page=n).items]
            for n in (1, 2, 3)
        ]
        flat = [i for page in pages for i in page]
        assert len(flat) == len(set(flat)) == 5
        # Walking the pages in order reproduces the single-page order.
        single_page = [
            r.indicator_id for r in service.list_indicators(page_size=5).items
        ]
        assert flat == single_page

    def test_repeated_reads_return_the_same_order(
        self, service, ti_db: Session
    ) -> None:
        self._seed(ti_db)
        runs = [
            [row.indicator_id for row in service.list_indicators().items]
            for _ in range(5)
        ]
        assert all(run == runs[0] for run in runs)

    def test_lookups_sharing_a_timestamp_are_ordered_by_id(
        self, service, ti_db: Session
    ) -> None:
        indicator = make_indicator(ti_db)
        for provider in ("VirusTotal", "abuseipdb", "AlienVault OTX"):
            make_lookup(ti_db, indicator, provider=provider, performed_at=BASE_TIME)
        ti_db.commit()

        lookups = service.get_indicator(indicator.id).lookups
        ids = [lookup.lookup_id for lookup in lookups]
        assert len(lookups) == 3
        assert ids == sorted(ids)


# ---------------------------------------------------------------------------
# 3. Pagination bounds
# ---------------------------------------------------------------------------


class TestPagination:
    def _seed_many(self, session: Session, count: int) -> None:
        for index in range(count):
            make_indicator(
                session,
                value=f"10.0.0.{index}",
                last_seen=BASE_TIME - timedelta(minutes=index),
            )
        session.commit()

    def test_paginates_within_bounds(self, service, ti_db: Session) -> None:
        self._seed_many(ti_db, 7)
        page = service.list_indicators(page=2, page_size=3)
        assert len(page.items) == 3
        assert page.total == 7
        assert page.page == 2
        assert page.page_size == 3

    def test_last_partial_page_is_short(self, service, ti_db: Session) -> None:
        self._seed_many(ti_db, 7)
        assert len(service.list_indicators(page=3, page_size=3).items) == 1

    def test_total_is_independent_of_page_size(
        self, service, ti_db: Session
    ) -> None:
        self._seed_many(ti_db, 7)
        assert service.list_indicators(page=1, page_size=1).total == 7
        assert service.list_indicators(page=7, page_size=1).total == 7

    def test_page_beyond_the_end_returns_no_rows(
        self, service, ti_db: Session
    ) -> None:
        self._seed_many(ti_db, 3)
        assert service.list_indicators(page=99, page_size=10).items == []

    def test_rejects_a_page_below_one(self, service) -> None:
        with pytest.raises(ThreatIntelQueryValidationError):
            service.list_indicators(page=0)

    def test_rejects_a_non_positive_page_size(self, service) -> None:
        with pytest.raises(ThreatIntelQueryValidationError):
            service.list_indicators(page_size=0)

    def test_rejects_a_page_size_above_the_cap(self, service) -> None:
        with pytest.raises(ThreatIntelQueryValidationError):
            service.list_indicators(page_size=MAX_PAGE_SIZE + 1)

    def test_accepts_the_page_size_cap(self, service) -> None:
        assert service.list_indicators(page_size=MAX_PAGE_SIZE).page_size == MAX_PAGE_SIZE

    def test_rejects_non_integer_pagination(self, service) -> None:
        with pytest.raises(ThreatIntelQueryValidationError):
            service.list_indicators(page="many")  # type: ignore[arg-type]

    def test_lookup_history_is_bounded(self, service, ti_db: Session) -> None:
        indicator = make_indicator(ti_db)
        for index in range(MAX_LOOKUPS_PER_INDICATOR + 5):
            make_lookup(
                ti_db,
                indicator,
                performed_at=BASE_TIME - timedelta(seconds=index),
            )
        ti_db.commit()

        detail = service.get_indicator(indicator.id)
        assert len(detail.lookups) == MAX_LOOKUPS_PER_INDICATOR
        assert detail.lookups_truncated is True
        # The rollup still counts the full history, not the bounded window.
        assert detail.indicator.lookup_count == MAX_LOOKUPS_PER_INDICATOR + 5


# ---------------------------------------------------------------------------
# 7/8/9. Detail and provider lookups
# ---------------------------------------------------------------------------


class TestDetail:
    def test_returns_a_persisted_indicator(self, service, ti_db: Session) -> None:
        row = make_indicator(ti_db, value="8.8.8.8")
        ti_db.commit()

        detail = service.get_indicator(row.id)
        assert detail.indicator.indicator_id == row.id
        assert detail.indicator.value == "8.8.8.8"
        assert detail.indicator.canonical_key == "ip:8.8.8.8"
        assert detail.lookups == []
        assert detail.read_only is True
        assert detail.verdict_available is False

    def test_associated_provider_lookups_are_returned(
        self, service, ti_db: Session
    ) -> None:
        row = make_indicator(ti_db, value="8.8.8.8")
        make_lookup(ti_db, row, provider="VirusTotal", found=True)
        make_lookup(ti_db, row, provider="abuseipdb", found=False)
        make_lookup(ti_db, row, provider="AlienVault OTX", found=False)
        ti_db.commit()

        detail = service.get_indicator(row.id)
        assert {l.provider for l in detail.lookups} == {
            "VirusTotal",
            "abuseipdb",
            "AlienVault OTX",
        }

    def test_lookups_are_ordered_newest_first(self, service, ti_db: Session) -> None:
        row = make_indicator(ti_db)
        make_lookup(ti_db, row, performed_at=BASE_TIME - timedelta(hours=2))
        make_lookup(ti_db, row, performed_at=BASE_TIME - timedelta(hours=1))
        make_lookup(ti_db, row, performed_at=BASE_TIME)
        ti_db.commit()

        times = [l.performed_at for l in service.get_indicator(row.id).lookups]
        assert times == sorted(times, reverse=True)

    def test_no_data_is_distinct_from_failed(
        self, service, ti_db: Session
    ) -> None:
        """A provider that answered with nothing is not a failure."""
        row = make_indicator(ti_db)
        make_lookup(
            ti_db,
            row,
            provider="AlienVault OTX",
            found=False,
            evidence={"pulse_info": {"count": 0}},
        )
        ti_db.commit()

        lookup = service.get_indicator(row.id).lookups[0]
        assert lookup.status == "success"
        assert lookup.status_label == "ENRICHED"
        assert lookup.found is False
        assert lookup.provider_result_available is True

    def test_provider_success_without_stored_data_is_no_data(
        self, service, ti_db: Session
    ) -> None:
        row = make_indicator(ti_db)
        make_lookup(ti_db, row, found=True, evidence=None, result_metadata=None)
        ti_db.commit()

        lookup = service.get_indicator(row.id).lookups[0]
        assert lookup.status_label == "NO DATA"
        assert lookup.provider_result_available is False

    def test_confidence_is_only_returned_when_persisted(
        self, service, ti_db: Session
    ) -> None:
        row = make_indicator(ti_db)
        make_lookup(ti_db, row, confidence=None)
        make_lookup(ti_db, row, provider="abuseipdb", confidence=0.87)
        ti_db.commit()

        by_provider = {l.provider: l for l in service.get_indicator(row.id).lookups}
        assert by_provider["VirusTotal"].confidence is None
        assert by_provider["abuseipdb"].confidence == pytest.approx(0.87)

    def test_returns_correlated_event_ids(self, service, ti_db: Session) -> None:
        row = make_indicator(ti_db)
        first_event = uuid.uuid4()
        second_event = uuid.uuid4()
        make_lookup(ti_db, row, event_id=first_event)
        make_lookup(ti_db, row, event_id=second_event)
        make_lookup(ti_db, row, event_id=first_event)
        ti_db.commit()

        detail = service.get_indicator(row.id)
        assert set(detail.events) == {first_event, second_event}
        assert len(detail.events) == 2  # deduplicated

    def test_events_endpoint_returns_distinct_ids(
        self, service, ti_db: Session
    ) -> None:
        row = make_indicator(ti_db)
        event_id = uuid.uuid4()
        make_lookup(ti_db, row, event_id=event_id)
        make_lookup(ti_db, row, event_id=event_id)
        ti_db.commit()

        result = service.list_indicator_events(row.id)
        assert result.events == [event_id]
        assert result.total == 1
        assert result.truncated is False
        assert result.read_only is True
        # The response explains that these ids are not dereferenced.
        assert "no security-event" in result.note

    def test_unknown_indicator_raises_not_found(self, service) -> None:
        with pytest.raises(ThreatIntelIndicatorNotFoundError):
            service.get_indicator(uuid.uuid4())

    def test_unknown_indicator_rejects_a_malformed_id(self, service) -> None:
        with pytest.raises(ThreatIntelQueryValidationError):
            service.get_indicator("not-a-uuid")

    def test_truncated_events_report_the_true_total(
        self, service, ti_db: Session
    ) -> None:
        """A bounded page still reports how many event ids really exist."""
        from app.services.threat_intelligence_query import MAX_EVENTS_PER_INDICATOR

        indicator = make_indicator(ti_db)
        for index in range(MAX_EVENTS_PER_INDICATOR + 40):
            make_lookup(
                ti_db,
                indicator,
                event_id=uuid.uuid4(),
                performed_at=BASE_TIME - timedelta(seconds=index),
            )
        ti_db.commit()

        result = service.list_indicator_events(indicator.id, limit=10)
        assert len(result.events) == 10
        assert result.truncated is True
        assert result.total == MAX_EVENTS_PER_INDICATOR + 40

    def test_events_for_unknown_indicator_raises_not_found(self, service) -> None:
        with pytest.raises(ThreatIntelIndicatorNotFoundError):
            service.list_indicator_events(uuid.uuid4())

    def test_rejects_an_unknown_indicator_type(self, service) -> None:
        with pytest.raises(ThreatIntelQueryValidationError):
            service.list_indicators(indicator_type="banana")

    def test_rejects_an_oversized_search_filter(self, service) -> None:
        with pytest.raises(ThreatIntelQueryValidationError):
            service.list_indicators(value_filter="x" * 513)

    def test_blank_search_filter_is_ignored(self, service, ti_db: Session) -> None:
        make_indicator(ti_db)
        ti_db.commit()
        assert service.list_indicators(value_filter="   ").total == 1


# ---------------------------------------------------------------------------
# 9/10. Failure representation and secret safety
# ---------------------------------------------------------------------------


class TestFailureRepresentation:
    def test_a_failed_lookup_is_reported_as_a_failure(
        self, service, ti_db: Session
    ) -> None:
        row = make_indicator(ti_db)
        make_lookup(
            ti_db,
            row,
            provider="AlienVault OTX",
            status=LookupStatus.ERROR,
            found=None,
            error_type="provider_error",
            error_message="Provider lookup failed: bad request",
            retryable=False,
        )
        ti_db.commit()

        lookup = service.get_indicator(row.id).lookups[0]
        assert lookup.status == "error"
        assert lookup.status_label == "FAILED"
        assert lookup.found is None
        assert lookup.error_type == "provider_error"
        assert lookup.retryable is False
        assert lookup.provider_result_available is False
        assert lookup.evidence is None

    @pytest.mark.parametrize(
        ("error_type", "expected"),
        [
            ("rate_limit", "RATE LIMITED"),
            ("timeout", "TIMED OUT"),
            ("provider_error", "FAILED"),
            ("invalid_indicator", "REJECTED"),
            ("unexpected", "UNAVAILABLE"),
            ("something_new", "UNAVAILABLE"),
            (None, "UNAVAILABLE"),
        ],
    )
    def test_error_types_map_to_honest_labels(
        self, service, ti_db: Session, error_type, expected
    ) -> None:
        row = make_indicator(ti_db)
        make_lookup(
            ti_db,
            row,
            status=LookupStatus.ERROR,
            found=None,
            error_type=error_type,
        )
        ti_db.commit()

        assert service.get_indicator(row.id).lookups[0].status_label == expected

    def test_a_failed_lookup_is_never_reported_as_found(
        self, service, ti_db: Session
    ) -> None:
        row = make_indicator(ti_db)
        make_lookup(
            ti_db,
            row,
            status=LookupStatus.ERROR,
            found=None,
            error_type="provider_error",
        )
        ti_db.commit()

        record = service.get_indicator(row.id)
        assert record.lookups[0].found is None
        assert record.lookups[0].provider_result_available is False


class TestSecretSafety:
    """Defence in depth: the read layer re-sanitizes on the way out."""

    def test_credential_keys_in_evidence_are_redacted(self) -> None:
        sanitized = sanitize_evidence(
            {
                "api_key": "SECRET",
                "x-api-key": "SECRET",
                "vt_api_key": "SECRET",
                "apiKey": "SECRET",
                "password": "SECRET",
                "authToken": "SECRET",
                "authorization": "Bearer SECRET",
                "nested": {"secret": "SECRET", "domain": "google.com"},
            }
        )
        for key in ("api_key", "x-api-key", "vt_api_key", "apiKey", "password",
                    "authToken", "authorization"):
            assert sanitized[key] == "<redacted>", key
        assert sanitized["nested"]["secret"] == "<redacted>"
        # Benign provider data is preserved.
        assert sanitized["nested"]["domain"] == "google.com"

    def test_raw_response_envelopes_are_dropped(self) -> None:
        sanitized = sanitize_evidence(
            {
                "raw_response_body": "everything",
                "raw_body": "everything",
                "response_headers": {"Set-Cookie": "x"},
                "response_body": "everything",
                "body": "everything",
                "asn": 15169,
            }
        )
        for key in ("raw_response_body", "raw_body", "response_headers",
                    "response_body", "body"):
            assert key not in sanitized, key
        assert sanitized["asn"] == 15169

    def test_evidence_is_depth_bounded(self) -> None:
        deep = current = {}
        for _ in range(20):
            current["next"] = {}
            current = current["next"]
        current["leaf"] = "value"

        sanitized = sanitize_evidence({"deep": deep})
        assert "<redacted>" in str(sanitized)

    def test_evidence_list_length_is_bounded(self) -> None:
        sanitized = sanitize_evidence({"items": list(range(100))})
        assert len(sanitized["items"]) <= 21
        assert any("truncated" in str(item) for item in sanitized["items"])

    def test_evidence_key_count_is_bounded(self) -> None:
        sanitized = sanitize_evidence({f"key{index}": index for index in range(100)})
        assert len(sanitized) <= 41
        assert "_truncated" in sanitized

    def test_evidence_string_length_is_bounded(self) -> None:
        assert len(sanitize_evidence({"note": "x" * 5000})["note"]) == 512

    def test_a_real_sha256_evidence_value_is_not_over_redacted(self) -> None:
        """A hash is legitimate indicator data, not a leaked credential."""
        digest = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        assert sanitize_evidence({"sha256": digest})["sha256"] == digest

    def test_error_messages_are_redacted_on_read(self, service, ti_db: Session) -> None:
        row = make_indicator(ti_db)
        make_lookup(
            ti_db,
            row,
            status=LookupStatus.ERROR,
            found=None,
            error_type="provider_error",
            error_message="request failed api_key=SUPERSECRET123 Authorization: Bearer abcdefghijklmnop",
        )
        ti_db.commit()

        message = service.get_indicator(row.id).lookups[0].error_message
        assert "SUPERSECRET123" not in message
        assert "abcdefghijklmnop" not in message
        assert "<redacted>" in message

    def test_jwt_shaped_tokens_are_redacted(self) -> None:
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.sig"
        assert jwt not in (sanitize_free_text(f"token was {jwt}") or "")

    def test_bare_opaque_tokens_are_redacted(self) -> None:
        assert "a" * 64 not in (sanitize_free_text("key " + "a" * 64) or "")

    def test_no_provider_api_key_can_be_reached(
        self, service, ti_db: Session
    ) -> None:
        from app.core.config import settings

        keys = {
            settings.virustotal_api_key,
            settings.abuseipdb_api_key,
            settings.otx_api_key,
        }
        keys.discard("")

        row = make_indicator(ti_db)
        make_lookup(
            ti_db,
            row,
            evidence={"headers": {"x-apikey": next(iter(keys))}, "asn": 15169},
        )
        ti_db.commit()

        detail = service.get_indicator(row.id)
        assert "headers" not in (detail.lookups[0].evidence or {})
        serialized = str(detail.model_dump())
        for key in keys:
            assert key not in serialized


# ---------------------------------------------------------------------------
# 11. No write through the read surface
# ---------------------------------------------------------------------------


class TestReadOnlyGuarantee:
    def test_only_get_routes_are_registered(self, client) -> None:
        schema = client.get("/openapi.json").json()
        paths = {
            path: set(methods)
            for path, methods in schema["paths"].items()
            if path.startswith("/api/threat-intelligence")
        }
        assert paths, "no threat-intelligence paths registered"
        for path, methods in paths.items():
            assert methods == {"get"}, f"{path} exposes {methods}"

    def test_indicator_and_lookup_rows_are_unchanged_by_reads(
        self, service, ti_db: Session
    ) -> None:
        row = make_indicator(ti_db, value="8.8.8.8")
        make_lookup(ti_db, row, provider="VirusTotal", evidence={"asn": 15169})
        ti_db.commit()

        indicator_count = ti_db.execute(
            select(func.count()).select_from(ThreatIntelIndicator)
        ).scalar_one()
        lookup_count = ti_db.execute(
            select(func.count()).select_from(ThreatIntelLookup)
        ).scalar_one()
        original_last_seen = ti_db.get(ThreatIntelIndicator, row.id).last_seen_at

        for _ in range(3):
            service.list_indicators()
            service.get_indicator(row.id)
            service.list_indicator_events(row.id)

        assert ti_db.execute(
            select(func.count()).select_from(ThreatIntelIndicator)
        ).scalar_one() == indicator_count
        assert ti_db.execute(
            select(func.count()).select_from(ThreatIntelLookup)
        ).scalar_one() == lookup_count
        assert ti_db.get(ThreatIntelIndicator, row.id).last_seen_at == original_last_seen

    def test_a_write_attempt_is_rejected(self, client, admin_token: str) -> None:
        for method, path, payload in (
            ("post", INDICATORS_URL, {"value": "8.8.8.8"}),
            ("post", f"{INDICATORS_URL}/{uuid.uuid4()}", {"value": "x"}),
            ("put", f"{INDICATORS_URL}/{uuid.uuid4()}", {"value": "x"}),
            ("patch", f"{INDICATORS_URL}/{uuid.uuid4()}", {"value": "x"}),
            ("delete", f"{INDICATORS_URL}/{uuid.uuid4()}", None),
        ):
            headers = auth(admin_token)
            if payload is None:
                response = getattr(client, method)(path, headers=headers)
            else:
                response = getattr(client, method)(
                    path, headers=headers, json=payload
                )
            # 405 = the path exists but only allows GET; 404 = no such route.
            assert response.status_code in (404, 405), (
                f"{method.upper()} {path} returned {response.status_code}"
            )

    def test_repeated_reads_are_stable(self, service, ti_db: Session) -> None:
        """No read-time state mutation, e.g. no counter drifting."""
        row = make_indicator(ti_db)
        make_lookup(ti_db, row)
        ti_db.commit()

        first = service.get_indicator(row.id).model_dump()
        for _ in range(3):
            assert service.get_indicator(row.id).model_dump() == first


# ---------------------------------------------------------------------------
# 14. UTC normalization
# ---------------------------------------------------------------------------


class TestUtcNormalization:
    def test_naive_timestamps_are_treated_as_utc(self, service, ti_db: Session) -> None:
        """SQLite hands back naive UTC; the read layer must still emit aware UTC."""
        naive = datetime(2026, 9, 28, 12, 0, 0)  # no tzinfo
        row = ThreatIntelIndicator(
            value="8.8.8.8",
            indicator_type=IndicatorType.IP,
            canonical_key="ip:8.8.8.8",
            first_seen_at=naive,
            last_seen_at=naive,
            created_at=naive,
            updated_at=naive,
        )
        ti_db.add(row)
        ti_db.flush()
        make_lookup(ti_db, row, performed_at=naive, result_timestamp=naive)
        ti_db.commit()

        detail = service.get_indicator(row.id)
        for value in (
            detail.indicator.first_seen,
            detail.indicator.last_seen,
            detail.indicator.created_at,
            detail.lookups[0].performed_at,
            detail.lookups[0].result_timestamp,
        ):
            assert value.tzinfo is not None
            assert value.utcoffset() == timedelta(0)

    @pytest.mark.parametrize(
        ("stored", "expected_hour"),
        [
            # Aware non-UTC values are converted, not reinterpreted.
            (datetime(2026, 9, 28, 14, 0, 0, tzinfo=timezone(timedelta(hours=2))), 12),
            (datetime(2026, 9, 28, 12, 0, 0, tzinfo=timezone.utc), 12),
            (datetime(2026, 9, 28, 9, 0, 0, tzinfo=timezone(timedelta(hours=-5))), 14),
        ],
    )
    def test_aware_instants_are_converted_to_utc(
        self, stored: datetime, expected_hour: int
    ) -> None:
        """The read boundary normalizes whatever offset the column returns.

        Exercised through ``_as_utc`` rather than through SQLite, because
        SQLite's DATETIME silently drops offsets on write, so a round-trip
        test would not prove anything about non-UTC inputs.
        """
        from app.services.threat_intelligence_query import _as_utc

        result = _as_utc(stored)
        assert result is not None
        assert result.utcoffset() == timedelta(0)
        assert result.hour == expected_hour

    def test_none_stays_none(self) -> None:
        from app.services.threat_intelligence_query import _as_utc

        assert _as_utc(None) is None


# ---------------------------------------------------------------------------
# 15. Provenance integrity
# ---------------------------------------------------------------------------


class TestProvenance:
    def test_indicator_provenance_is_observed(
        self, service, ti_db: Session
    ) -> None:
        row = make_indicator(ti_db)
        ti_db.commit()
        record = service.get_indicator(row.id).indicator
        assert record.provenance == Provenance.OBSERVED

    def test_lookup_provenance_is_enriched(
        self, service, ti_db: Session
    ) -> None:
        row = make_indicator(ti_db)
        make_lookup(ti_db, row)
        ti_db.commit()
        assert service.get_indicator(row.id).lookups[0].provenance == Provenance.ENRICHED

    def test_the_database_still_enforces_enriched_on_lookups(self, ti_db: Session) -> None:
        """The read surface does not weaken the persistence CHECK constraint."""
        from sqlalchemy.exc import IntegrityError

        row = make_indicator(ti_db)
        ti_db.commit()

        bad = ThreatIntelLookup(
            event_id=uuid.uuid4(),
            indicator_id=row.id,
            provider="VirusTotal",
            status=LookupStatus.SUCCESS,
            performed_at=BASE_TIME,
            provenance=Provenance.OBSERVED.value,
        )
        ti_db.add(bad)
        with pytest.raises(IntegrityError):
            ti_db.commit()
        ti_db.rollback()


# ---------------------------------------------------------------------------
# No fabricated analytic conclusions
# ---------------------------------------------------------------------------


class TestNoFabricatedVerdicts:
    def test_response_models_expose_no_verdict_field(self) -> None:
        """The read models must not grow a malicious/severity/risk field.

        ``verdict_available`` is allowed and expected: it is the honest
        read-only notice that is always ``False``.  The forbidden list is
        any field that would *carry* an analytic verdict.
        """
        from app.schemas import threat_intelligence_query as schemas

        forbidden = (
            "verdict",
            "malicious",
            "benign",
            "severity",
            "risk",
            "score",
            "threat_level",
            "classification",
        )
        for name in (
            "ThreatIntelLookupRecord",
            "ThreatIntelIndicatorRecord",
            "ThreatIntelIndicatorPage",
            "ThreatIntelIndicatorDetail",
            "ThreatIntelIndicatorEvents",
        ):
            model = getattr(schemas, name)
            for field in model.model_fields:
                if field == "verdict_available":
                    assert model.model_fields[field].default is False
                    continue
                assert not any(
                    token in field.lower() for token in forbidden
                ), f"{name}.{field}"

    def test_no_lookup_record_field_claims_a_verdict(self) -> None:
        """A provider outcome is status + found, never a conclusion."""
        from app.schemas.threat_intelligence_query import ThreatIntelLookupRecord

        assert set(ThreatIntelLookupRecord.model_fields) >= {
            "status",
            "status_label",
            "found",
            "provider_result_available",
            "confidence",
        }
        assert not any(
            token in field.lower()
            for field in ThreatIntelLookupRecord.model_fields
            for token in ("malicious", "benign", "verdict", "severity", "risk")
            if field != "verdict_available"
        )

    def test_payloads_declare_that_no_verdict_is_available(
        self, service, ti_db: Session
    ) -> None:
        row = make_indicator(ti_db)
        make_lookup(ti_db, row)
        ti_db.commit()

        assert service.list_indicators().verdict_available is False
        assert service.get_indicator(row.id).verdict_available is False
