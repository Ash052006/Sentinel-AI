"""Unit tests for Manual Threat Intelligence Lookup API (POST /api/v1/threat-intelligence/lookup).

Covers all 22 required scenarios:
1. Valid public IP manual lookup.
2. Valid domain lookup.
3. Valid URL lookup.
4. Valid hash lookup.
5. Invalid IP.
6. Invalid domain.
7. Invalid URL.
8. Invalid hash.
9. Unsupported indicator type.
10. Private IP rejected/skipped without provider calls.
11. All providers succeed.
12. One provider fails while others succeed.
13. Provider returns no match.
14. All providers fail.
15. No provider configured.
16. Indicator already exists.
17. Manual lookup without an event ID.
18. Persistence failure and transaction rollback.
19. Authentication required.
20. Role authorization.
21. Replay behavior and lookup idempotency.
22. Existing event-based enrichment remains unaffected.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.dialects.sqlite.base import SQLiteTypeCompiler
from sqlalchemy.orm import Session

# Enable PostgreSQL JSONB columns on SQLite for unit tests
if not hasattr(SQLiteTypeCompiler, "visit_JSONB"):
    SQLiteTypeCompiler.visit_JSONB = lambda self, type_, **kw: "JSON"  # noqa: E731

from app.api.dependencies import get_db
from app.api.routes.threat_intelligence_lookup import get_provider_registry
from app.main import app
from app.models.threat_intel_indicator import ThreatIntelIndicator
from app.models.threat_intel_lookup import LookupStatus, ThreatIntelLookup
from app.repositories.threat_intelligence import ThreatIntelRepository
from app.schemas.security_event import Provenance
from app.services.threat_intelligence.base import (
    ThreatIntelProvider,
    ThreatIntelResult,
)
from app.services.threat_intelligence.exceptions import (
    ProviderLookupError,
    RateLimitError,
)
from app.services.threat_intelligence.registry import ProviderRegistry
from app.services.threat_intelligence.types import IndicatorType, ThreatIndicator

LOOKUP_URL = "/api/v1/threat-intelligence/lookup"

@pytest.fixture(autouse=True)
def _cleanup_test_state(db_session: Session):
    from app.api.routes.threat_intelligence_lookup import _manual_lookup_limiter
    _manual_lookup_limiter.reset()
    yield
    _manual_lookup_limiter.reset()
    app.dependency_overrides.clear()
    try:
        db_session.rollback()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Test Providers
# ---------------------------------------------------------------------------


class MockTIProvider(ThreatIntelProvider):
    """Configurable mock threat intelligence provider."""

    def __init__(
        self,
        name: str = "MockVT",
        supported_types: set[IndicatorType] | None = None,
        found: bool = True,
        confidence: float | None = 0.85,
        data: dict[str, Any] | None = None,
        exception_to_raise: Exception | None = None,
    ) -> None:
        self._name = name
        self._supported_types = supported_types or {
            IndicatorType.IP,
            IndicatorType.DOMAIN,
            IndicatorType.URL,
            IndicatorType.HASH,
        }
        self._found = found
        self._confidence = confidence
        self._data = data if data is not None else {"status": "analyzed"}
        self._exception = exception_to_raise
        self.call_count = 0

    @property
    def provider_name(self) -> str:
        return self._name

    @property
    def supported_indicator_types(self) -> set[IndicatorType]:
        return self._supported_types

    def lookup(self, indicator: ThreatIndicator) -> ThreatIntelResult:
        self.call_count += 1
        if self._exception is not None:
            raise self._exception
        return ThreatIntelResult(
            indicator=indicator,
            provider=self.provider_name,
            found=self._found,
            data=self._data,
            confidence=self._confidence,
            timestamp=datetime.now(timezone.utc),
        )


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# 1-4. Valid Lookups (IP, Domain, URL, Hash)
# ---------------------------------------------------------------------------


class TestValidManualLookups:
    def test_valid_public_ip_manual_lookup(
        self, client, analyst_token: str, db_session: Session
    ) -> None:
        test_ip = f"93.184.216.{uuid.uuid4().int % 150 + 50}"
        existing_ind = db_session.query(ThreatIntelIndicator).filter_by(canonical_key=f"ip:{test_ip}").first()
        if existing_ind:
            db_session.query(ThreatIntelLookup).filter_by(indicator_id=existing_ind.id).delete()
            db_session.delete(existing_ind)
            db_session.commit()

        provider = MockTIProvider("MockVT", {IndicatorType.IP})
        app.dependency_overrides[get_provider_registry] = lambda: ProviderRegistry([provider])

        response = client.post(
            LOOKUP_URL,
            headers=_auth(analyst_token),
            json={"indicator": test_ip, "indicator_type": "ip"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["normalized_indicator_value"] == test_ip
        assert data["indicator_type"] == "ip"
        assert data["canonical_key"] == f"ip:{test_ip}"
        assert data["status"] == "enriched"
        assert data["providers_attempted"] == 1
        assert data["providers_succeeded"] == 1
        assert data["providers_failed"] == 0
        assert data["providers_skipped"] == 0
        assert data["is_new_indicator"] is True
        assert data["first_seen"] is None
        assert data["last_seen"] is None
        assert len(data["results"]) == 1
        assert data["results"][0]["provider"] == "MockVT"
        assert data["results"][0]["status"] == "success"
        assert data["results"][0]["found"] is True
        assert provider.call_count == 1

    def test_valid_domain_lookup(
        self, client, analyst_token: str, db_session: Session
    ) -> None:
        provider = MockTIProvider("MockOTX", {IndicatorType.DOMAIN})
        app.dependency_overrides[get_provider_registry] = lambda: ProviderRegistry([provider])

        response = client.post(
            LOOKUP_URL,
            headers=_auth(analyst_token),
            json={"indicator": "Evil-Domain.com", "indicator_type": "domain"},
        )
        assert response.status_code == 200
        data = response.json()
        # Normalization lowercases domain
        assert data["normalized_indicator_value"] == "evil-domain.com"
        assert data["canonical_key"] == "domain:evil-domain.com"
        assert data["status"] == "enriched"
        assert provider.call_count == 1

    def test_valid_url_lookup(
        self, client, analyst_token: str, db_session: Session
    ) -> None:
        provider = MockTIProvider("MockVT", {IndicatorType.URL})
        app.dependency_overrides[get_provider_registry] = lambda: ProviderRegistry([provider])

        response = client.post(
            LOOKUP_URL,
            headers=_auth(analyst_token),
            json={"indicator": "https://malicious.org/path/payload.exe", "indicator_type": "url"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["normalized_indicator_value"] == "https://malicious.org/path/payload.exe"
        assert data["canonical_key"] == "url:https://malicious.org/path/payload.exe"
        assert data["status"] == "enriched"
        assert provider.call_count == 1

    def test_valid_hash_lookup(
        self, client, analyst_token: str, db_session: Session
    ) -> None:
        sha256 = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        provider = MockTIProvider("MockVT", {IndicatorType.HASH})
        app.dependency_overrides[get_provider_registry] = lambda: ProviderRegistry([provider])

        response = client.post(
            LOOKUP_URL,
            headers=_auth(analyst_token),
            json={"indicator": sha256, "indicator_type": "hash"},
        )
        assert response.status_code == 200
        data = response.json()
        # Normalization lowercases hash
        assert data["normalized_indicator_value"] == sha256.lower()
        assert data["canonical_key"] == f"hash:{sha256.lower()}"
        assert data["status"] == "enriched"
        assert provider.call_count == 1


# ---------------------------------------------------------------------------
# 5-9. Validation Errors (422)
# ---------------------------------------------------------------------------


class TestInputValidation:
    def test_invalid_ip_returns_422(self, client, analyst_token: str) -> None:
        for invalid_ip in ["999.999.999.999", "not-an-ip", "256.1.1.1"]:
            response = client.post(
                LOOKUP_URL,
                headers=_auth(analyst_token),
                json={"indicator": invalid_ip, "indicator_type": "ip"},
            )
            assert response.status_code == 422
            assert "Invalid IP" in response.json()["detail"]

    def test_invalid_domain_returns_422(self, client, analyst_token: str) -> None:
        for invalid_domain in ["http://has-scheme.com", "nodot", "has space.com", "-leading.com", "trailing-.com"]:
            response = client.post(
                LOOKUP_URL,
                headers=_auth(analyst_token),
                json={"indicator": invalid_domain, "indicator_type": "domain"},
            )
            assert response.status_code == 422
            assert "Invalid domain" in response.json()["detail"]

    def test_invalid_url_returns_422(self, client, analyst_token: str) -> None:
        for invalid_url in ["ftp://not-http.com", "just-a-string", "http://", "https:// has space"]:
            response = client.post(
                LOOKUP_URL,
                headers=_auth(analyst_token),
                json={"indicator": invalid_url, "indicator_type": "url"},
            )
            assert response.status_code == 422
            assert "Invalid URL" in response.json()["detail"]

    def test_invalid_hash_returns_422(self, client, analyst_token: str) -> None:
        for invalid_hash in ["too_short", "12345", "zzzz" * 8, "g" * 64]:
            response = client.post(
                LOOKUP_URL,
                headers=_auth(analyst_token),
                json={"indicator": invalid_hash, "indicator_type": "hash"},
            )
            assert response.status_code == 422
            assert "Invalid hash" in response.json()["detail"]

    def test_unsupported_indicator_type_returns_422(self, client, analyst_token: str) -> None:
        response = client.post(
            LOOKUP_URL,
            headers=_auth(analyst_token),
            json={"indicator": "CVE-2024-1234", "indicator_type": "cve"},
        )
        assert response.status_code == 422
        assert "Unsupported indicator type" in response.json()["detail"]


# ---------------------------------------------------------------------------
# 10. Non-Public IP Protection
# ---------------------------------------------------------------------------


class TestNonPublicIpProtection:
    def test_private_ip_skipped_without_provider_calls(
        self, client, analyst_token: str, db_session: Session
    ) -> None:
        provider = MockTIProvider("MockAbuse", {IndicatorType.IP})
        app.dependency_overrides[get_provider_registry] = lambda: ProviderRegistry([provider])

        response = client.post(
            LOOKUP_URL,
            headers=_auth(analyst_token),
            json={"indicator": "10.20.30.40", "indicator_type": "ip"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "no_lookup"
        assert data["providers_attempted"] == 0
        assert data["providers_skipped"] == 1
        assert provider.call_count == 0
        assert len(data["results"]) == 1
        assert data["results"][0]["status"] == "skipped"
        assert "Lookup skipped" in data["results"][0]["error_message"]

        # Indicator was persisted in database
        ind = db_session.query(ThreatIntelIndicator).filter_by(value="10.20.30.40").first()
        assert ind is not None

        # Zero lookups written to lookups table
        lookups = db_session.query(ThreatIntelLookup).filter_by(indicator_id=ind.id).all()
        assert len(lookups) == 0


# ---------------------------------------------------------------------------
# 11-15. Multi-Provider Scenarios
# ---------------------------------------------------------------------------


class TestProviderScenarios:
    def test_all_providers_succeed(
        self, client, analyst_token: str, db_session: Session
    ) -> None:
        p1 = MockTIProvider("ProviderA", {IndicatorType.IP}, found=True)
        p2 = MockTIProvider("ProviderB", {IndicatorType.IP}, found=True)
        app.dependency_overrides[get_provider_registry] = lambda: ProviderRegistry([p1, p2])

        response = client.post(
            LOOKUP_URL,
            headers=_auth(analyst_token),
            json={"indicator": "93.184.216.34", "indicator_type": "ip"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "enriched"
        assert data["providers_attempted"] == 2
        assert data["providers_succeeded"] == 2
        assert data["providers_failed"] == 0
        assert len(data["results"]) == 2

    def test_one_provider_fails_while_others_succeed(
        self, client, analyst_token: str, db_session: Session
    ) -> None:
        p1 = MockTIProvider("HealthyProvider", {IndicatorType.IP}, found=True)
        p2 = MockTIProvider(
            "BrokenProvider",
            {IndicatorType.IP},
            exception_to_raise=ProviderLookupError("BrokenProvider", "504 Gateway Timeout"),
        )
        app.dependency_overrides[get_provider_registry] = lambda: ProviderRegistry([p1, p2])

        response = client.post(
            LOOKUP_URL,
            headers=_auth(analyst_token),
            json={"indicator": "1.1.1.1", "indicator_type": "ip"},
        )
        assert response.status_code == 200
        data = response.json()
        # Mixed success + error = "partial"
        assert data["status"] == "partial"
        assert data["providers_attempted"] == 2
        assert data["providers_succeeded"] == 1
        assert data["providers_failed"] == 1

        results = {r["provider"]: r for r in data["results"]}
        assert results["HealthyProvider"]["status"] == "success"
        assert results["BrokenProvider"]["status"] == "error"
        assert "504 Gateway Timeout" in results["BrokenProvider"]["error_message"]

    def test_provider_returns_no_match(
        self, client, analyst_token: str, db_session: Session
    ) -> None:
        # found=False represents a successful lookup where provider had no record
        p = MockTIProvider("CleanProvider", {IndicatorType.IP}, found=False, data={})
        app.dependency_overrides[get_provider_registry] = lambda: ProviderRegistry([p])

        response = client.post(
            LOOKUP_URL,
            headers=_auth(analyst_token),
            json={"indicator": "8.8.4.4", "indicator_type": "ip"},
        )
        assert response.status_code == 200
        data = response.json()
        # Not a failure! Status is enriched because lookup succeeded
        assert data["status"] == "enriched"
        assert data["providers_attempted"] == 1
        assert data["providers_succeeded"] == 1
        assert data["providers_failed"] == 0
        assert data["results"][0]["found"] is False

    def test_all_providers_fail(
        self, client, analyst_token: str, db_session: Session
    ) -> None:
        p1 = MockTIProvider(
            "Provider1",
            {IndicatorType.IP},
            exception_to_raise=RateLimitError("Provider1", retry_after=60.0),
        )
        p2 = MockTIProvider(
            "Provider2",
            {IndicatorType.IP},
            exception_to_raise=ProviderLookupError("Provider2", "Server Error"),
        )
        app.dependency_overrides[get_provider_registry] = lambda: ProviderRegistry([p1, p2])

        response = client.post(
            LOOKUP_URL,
            headers=_auth(analyst_token),
            json={"indicator": "1.0.0.1", "indicator_type": "ip"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "failed"
        assert data["providers_attempted"] == 2
        assert data["providers_succeeded"] == 0
        assert data["providers_failed"] == 2

    def test_no_provider_configured(
        self, client, analyst_token: str, db_session: Session
    ) -> None:
        # Registry with no providers for DOMAIN
        p = MockTIProvider("IPOnlyProvider", {IndicatorType.IP})
        app.dependency_overrides[get_provider_registry] = lambda: ProviderRegistry([p])

        response = client.post(
            LOOKUP_URL,
            headers=_auth(analyst_token),
            json={"indicator": "no-provider.org", "indicator_type": "domain"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "no_lookup"
        assert data["providers_attempted"] == 0
        assert data["providers_succeeded"] == 0
        assert data["providers_failed"] == 0
        assert data["providers_skipped"] == 0
        assert data["results"] == []


# ---------------------------------------------------------------------------
# 16-18. Persistence & Schema Semantics
# ---------------------------------------------------------------------------


class TestPersistenceSemantics:
    def test_indicator_already_exists(
        self, client, analyst_token: str, db_session: Session
    ) -> None:
        test_ip = f"198.51.103.{uuid.uuid4().int % 150 + 50}"
        p = MockTIProvider("MockProvider", {IndicatorType.IP})
        app.dependency_overrides[get_provider_registry] = lambda: ProviderRegistry([p])

        # Pre-seed indicator
        repo = ThreatIntelRepository(db_session)
        now = datetime.now(timezone.utc)
        ind, created = repo.get_or_create_indicator(
            value=test_ip,
            indicator_type=IndicatorType.IP,
            canonical_key=f"ip:{test_ip}",
            seen_at=now,
        )
        db_session.commit()
        assert created is True

        # Run manual lookup
        response = client.post(
            LOOKUP_URL,
            headers=_auth(analyst_token),
            json={"indicator": test_ip, "indicator_type": "ip"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["is_new_indicator"] is False
        assert data["indicator_id"] == str(ind.id)
        assert data["first_seen"] is not None
        assert data["last_seen"] is not None

    def test_manual_lookup_without_event_id(
        self, client, analyst_token: str, db_session: Session
    ) -> None:
        p = MockTIProvider("MockVT", {IndicatorType.IP})
        app.dependency_overrides[get_provider_registry] = lambda: ProviderRegistry([p])

        response = client.post(
            LOOKUP_URL,
            headers=_auth(analyst_token),
            json={"indicator": "198.51.100.8", "indicator_type": "ip"},
        )
        assert response.status_code == 200
        indicator_id = uuid.UUID(response.json()["indicator_id"])

        # Check database row has event_id = None and origin = "manual"
        lookup_row = db_session.query(ThreatIntelLookup).filter_by(indicator_id=indicator_id).first()
        assert lookup_row is not None
        assert lookup_row.event_id is None
        assert lookup_row.origin == "manual"
        assert lookup_row.provenance == Provenance.ENRICHED.value

    def test_persistence_failure_and_transaction_rollback(
        self, client, analyst_token: str
    ) -> None:
        p = MockTIProvider("MockVT", {IndicatorType.IP})
        app.dependency_overrides[get_provider_registry] = lambda: ProviderRegistry([p])

        with patch("app.api.routes.threat_intelligence_lookup.persist_analysis_bound") as mock_persist:
            def _fail_sink(analysis):
                raise RuntimeError("Database connection lost")
            mock_persist.return_value = _fail_sink

            response = client.post(
                LOOKUP_URL,
                headers=_auth(analyst_token),
                json={"indicator": "93.184.216.99", "indicator_type": "ip"},
            )
            assert response.status_code == 500
            assert "Failed to execute or persist" in response.json()["detail"]


# ---------------------------------------------------------------------------
# 19-20. Authentication & Authorization
# ---------------------------------------------------------------------------


class TestAuthAndRbac:
    def test_authentication_required(self, client) -> None:
        response = client.post(
            LOOKUP_URL,
            json={"indicator": "8.8.8.8", "indicator_type": "ip"},
        )
        assert response.status_code == 401

    def test_role_authorization(
        self, client, request, admin_token: str, analyst_token: str, ciso_token: str, db_session: Session
    ) -> None:
        from app.core.security import create_access_token, hash_password
        from app.models.role import Role
        from app.models.user import User

        p = MockTIProvider("MockVT", {IndicatorType.IP})
        app.dependency_overrides[get_provider_registry] = lambda: ProviderRegistry([p])

        # admin, analyst, ciso are allowed
        for token in [admin_token, analyst_token, ciso_token]:
            resp = client.post(
                LOOKUP_URL,
                headers=_auth(token),
                json={"indicator": "8.8.8.8", "indicator_type": "ip"},
            )
            assert resp.status_code == 200

        # viewer is denied
        viewer_role = db_session.execute(select(Role).where(Role.name == "viewer")).scalar_one_or_none()
        if viewer_role is None:
            viewer_role = Role(name="viewer", description="Viewer")
            db_session.add(viewer_role)
            db_session.commit()

        user = User(
            email=f"viewer-{uuid.uuid4().hex[:6]}@example.com",
            password_hash=hash_password("Pass123!"),
            is_active=True,
            role_id=viewer_role.id,
        )
        db_session.add(user)
        db_session.commit()

        viewer_token = create_access_token(str(user.id))
        denied_resp = client.post(
            LOOKUP_URL,
            headers=_auth(viewer_token),
            json={"indicator": "8.8.8.8", "indicator_type": "ip"},
        )
        assert denied_resp.status_code == 403


# ---------------------------------------------------------------------------
# 21-22. Replay & Event Enrichment Isolation
# ---------------------------------------------------------------------------


class TestReplayAndEnrichmentSafety:
    def test_replay_behavior_and_lookup_idempotency(
        self, client, analyst_token: str, db_session: Session
    ) -> None:
        test_ip = f"142.250.190.{uuid.uuid4().int % 150 + 50}"
        existing_ind = db_session.query(ThreatIntelIndicator).filter_by(canonical_key=f"ip:{test_ip}").first()
        if existing_ind:
            db_session.query(ThreatIntelLookup).filter_by(indicator_id=existing_ind.id).delete()
            db_session.delete(existing_ind)
            db_session.commit()

        p = MockTIProvider("MockVT", {IndicatorType.IP})
        app.dependency_overrides[get_provider_registry] = lambda: ProviderRegistry([p])

        # First manual lookup
        resp1 = client.post(
            LOOKUP_URL,
            headers=_auth(analyst_token),
            json={"indicator": test_ip, "indicator_type": "ip"},
        )
        assert resp1.status_code == 200
        assert resp1.json()["is_new_indicator"] is True

        # Replay lookup for the same indicator
        resp2 = client.post(
            LOOKUP_URL,
            headers=_auth(analyst_token),
            json={"indicator": test_ip, "indicator_type": "ip"},
        )
        assert resp2.status_code == 200
        assert resp2.json()["is_new_indicator"] is False
        assert resp1.json()["indicator_id"] == resp2.json()["indicator_id"]

    def test_existing_event_based_enrichment_unaffected(
        self, db_session: Session
    ) -> None:
        from app.agents.threat_intelligence import ThreatIntelligenceAgent
        from app.schemas.enriched_event import EnrichedSecurityEvent
        from app.schemas.normalized_event import (
            Endpoint,
            EventCategory,
            EventOutcome,
            NormalizedSecurityEvent,
        )
        from app.services.threat_intelligence_persistence import (
            ThreatIntelligencePersistenceService,
        )

        p = MockTIProvider("MockVT", {IndicatorType.IP})
        registry = ProviderRegistry([p])
        agent = ThreatIntelligenceAgent(registry)

        event_id = uuid.uuid4()
        test_ip = f"93.184.216.{uuid.uuid4().int % 150 + 50}"
        existing_ind = db_session.query(ThreatIntelIndicator).filter_by(canonical_key=f"ip:{test_ip}").first()
        if existing_ind:
            db_session.query(ThreatIntelLookup).filter_by(indicator_id=existing_ind.id).delete()
            db_session.delete(existing_ind)
            db_session.commit()

        now_dt = datetime.now(timezone.utc)
        event = EnrichedSecurityEvent(
            event_id=event_id,
            timestamp=now_dt,
            normalized_event=NormalizedSecurityEvent(
                event_id=event_id,
                source="firewall",
                source_type="security_device",
                source_endpoint=Endpoint(ip=test_ip),
                event_category=EventCategory.NETWORK,
                event_outcome=EventOutcome.SUCCESS,
                timestamp=now_dt,
            ),
        )

        analysis = agent.analyze(event)
        persistence = ThreatIntelligencePersistenceService()
        result = persistence.persist_analysis(db_session, analysis)

        assert result.indicators_created == 1
        assert result.lookups_created == 1

        # Lookup created via event has event_id set and origin="event"
        lookup_row = db_session.query(ThreatIntelLookup).filter_by(event_id=event_id).first()
        assert lookup_row is not None
        assert lookup_row.origin == "event"


class TestManualLookupRateLimiting:
    def test_manual_lookup_rate_limiting_enforced(
        self, client, analyst_token: str
    ) -> None:
        from app.api.routes.threat_intelligence_lookup import _manual_lookup_limiter
        _manual_lookup_limiter.reset()
        _manual_lookup_limiter.requests_per_minute = 2

        p = MockTIProvider("MockVT", {IndicatorType.IP})
        app.dependency_overrides[get_provider_registry] = lambda: ProviderRegistry([p])

        # 1st request allowed
        r1 = client.post(LOOKUP_URL, headers=_auth(analyst_token), json={"indicator": "8.8.8.8", "indicator_type": "ip"})
        assert r1.status_code == 200

        # 2nd request allowed
        r2 = client.post(LOOKUP_URL, headers=_auth(analyst_token), json={"indicator": "1.1.1.1", "indicator_type": "ip"})
        assert r2.status_code == 200

        # 3rd request blocked with HTTP 429
        r3 = client.post(LOOKUP_URL, headers=_auth(analyst_token), json={"indicator": "9.9.9.9", "indicator_type": "ip"})
        assert r3.status_code == 429
        assert "Rate limit exceeded" in r3.json()["detail"]
        assert "Retry-After" in r3.headers

        # Reset limiter for subsequent tests
        _manual_lookup_limiter.reset()
        _manual_lookup_limiter.requests_per_minute = 30

    def test_documentation_ip_skipped_in_manual_lookup(
        self, client, analyst_token: str
    ) -> None:
        p = MockTIProvider("MockVT", {IndicatorType.IP})
        app.dependency_overrides[get_provider_registry] = lambda: ProviderRegistry([p])

        response = client.post(
            LOOKUP_URL,
            headers=_auth(analyst_token),
            json={"indicator": "198.51.100.1", "indicator_type": "ip"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "no_lookup"
        assert data["providers_attempted"] == 0
        assert data["providers_skipped"] == 1
        assert "documentation" in data["results"][0]["error_message"]
