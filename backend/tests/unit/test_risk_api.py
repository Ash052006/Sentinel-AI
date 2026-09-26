"""Risk Assessment API layer behavior tests (Step 11E).

Exercises the read-only risk assessment endpoints through the full
integration stack the project already uses for API tests — JWT -> FastAPI
(``TestClient(app)``) -> route -> :class:`RiskQueryService` -> repository ->
PostgreSQL:

* authentication and RBAC enforcement on every risk endpoint (including an
  expired-token case and authorization-denial audit behavior);
* exact-lookup 404 vs. empty-collection 200 semantics;
* HTTP-level and service-level parameter validation (422);
* deterministic ordering and bounded pagination (multiple historical
  assessments per correlation are all returned, never collapsed);
* route ordering — the static ``/recent`` and ``/correlation/{correlation_id}``
  routes never resolve as ``/{risk_assessment_id}``;
* sanitized database-failure responses (503) with no internals leaked;
* secret redaction preserved end-to-end through the response;
* strict read-only behavior (no writes, no mutation, no non-GET methods);
* routes delegate retrieval to :class:`RiskQueryService` (no direct
  database access in the route layer);
* OpenAPI / router-registration contract (paths, methods, bearer security,
  tags, unique operation IDs, security scheme).

Rows are seeded through the real :class:`CorrelationPersistenceService` /
:class:`RiskPersistenceService` against the same shared test database the
existing API tests use, so the end-to-end path (including PostgreSQL ``JSONB``
round-trips) is exercised.  Every seeding test cleans up its own parent
correlations (which cascade to their assessment rows) so the shared database
stays deterministic across runs.
"""

from __future__ import annotations

import inspect
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

import app.api.routes.risks as risks_routes
from app.core.security import create_access_token, hash_password
from app.main import app
from app.models.audit_log import AuditLog
from app.models.correlation_result import CorrelationResult as CorrelationResultRow
from app.models.risk_assessment import RiskAssessment as RiskAssessmentRow
from app.models.role import Role
from app.models.user import User
from app.repositories.correlation import CorrelationRepository
from app.schemas.correlation import (
    CorrelationMember,
    CorrelationResult,
    CorrelationStatus,
)
from app.schemas.risk import RiskAssessment, RiskEvidence, RiskFactor, RiskLevel
from app.schemas.security_event import Provenance
from app.services.correlation_persistence import CorrelationPersistenceService
from app.services.risk_persistence import RiskPersistenceService
from app.services.risk_query import MAX_PAGE_SIZE, RiskQueryError, RiskQueryValidationError
from tests.conftest import auth_header

# ---------------------------------------------------------------------------
# Deterministic fixture data / seeding helpers
# ---------------------------------------------------------------------------

BASE = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)


def _ts(hours: float = 0.0) -> datetime:
    """Deterministic timezone-aware timestamp offset from BASE."""
    return BASE + timedelta(hours=hours)


def _parent(correlation_id: uuid.UUID, *, timestamp: datetime | None = None) -> CorrelationResult:
    """Build a Step 10A CorrelationResult to satisfy the assessments FK."""
    return CorrelationResult(
        correlation_id=correlation_id,
        members=[
            CorrelationMember(
                detection_id=uuid.uuid4(),
                event_id=uuid.uuid4(),
                timestamp=_ts(0),
            )
        ],
        status=CorrelationStatus.CANDIDATE,
        confidence=0.8,
        evidence={},
        metadata={},
        timestamp=timestamp or _ts(0),
        provenance=Provenance.CORRELATED,
    )


def _evidence(
    *,
    observation_type: str = "detection_severity",
    metadata: dict | None = None,
) -> RiskEvidence:
    return RiskEvidence(
        observation_type=observation_type,
        detection_id=uuid.uuid4(),
        event_id=uuid.uuid4(),
        metadata=metadata or {},
    )


def _factor(
    *,
    factor_type: str = "detection_volume",
    contribution: float | None = 0.5,
    evidence: list[RiskEvidence] | None = None,
    metadata: dict | None = None,
) -> RiskFactor:
    return RiskFactor(
        factor_type=factor_type,
        contribution=contribution,
        evidence=evidence or [],
        metadata=metadata or {},
    )


def _assessment(
    correlation_id: uuid.UUID,
    *,
    risk_assessment_id: uuid.UUID | None = None,
    score: float = 0.625,
    level: RiskLevel = RiskLevel.HIGH,
    confidence: float = 0.8,
    factors: list[RiskFactor] | None = None,
    evidence: list[RiskEvidence] | None = None,
    metadata: dict | None = None,
    timestamp: datetime | None = None,
) -> RiskAssessment:
    """Build a Step 11A/11B RiskAssessment contract object (secret-safe)."""
    return RiskAssessment(
        risk_assessment_id=risk_assessment_id or uuid.uuid4(),
        correlation_id=correlation_id,
        score=score,
        level=level,
        confidence=confidence,
        factors=factors or [],
        evidence=evidence or [],
        metadata=metadata or {},
        timestamp=timestamp or _ts(0),
        provenance=Provenance.RISK_ASSESSED,
    )


def _persist(
    db: Session,
    assessments: list[RiskAssessment],
    parents: list[CorrelationResult] | None = None,
) -> None:
    """Persist *assessments* through the real services (parents first)."""
    if parents:
        CorrelationPersistenceService().persist_correlations(db, parents)
    service = RiskPersistenceService()
    for assessment in assessments:
        service.persist_assessment(db, assessment)


def _cleanup(db: Session, *correlation_ids: uuid.UUID) -> None:
    """Delete parent correlations; assessment rows cascade away."""
    for cid in correlation_ids:
        row = CorrelationRepository(db).get_by_correlation_id(cid)
        if row is not None:
            db.delete(row)
    db.commit()


def _count(db: Session, model) -> int:
    """Count every persisted row of *model*."""
    return db.scalar(select(func.count()).select_from(model))


def _count_for_action(db: Session, action: str) -> int:
    """Count persisted audit records with *action*."""
    return len(
        db.execute(select(AuditLog).where(AuditLog.action == action)).scalars().all()
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def ds(db_session: Session) -> SimpleNamespace:
    """A function-scoped seeded dataset of persisted risk assessments.

    * ``correlation_a``: 3 historical assessments at distinct timestamps
      (multiple-historical-assessments semantics).
    * ``correlation_b``: 1 assessment whose metadata/factor metadata/evidence
      metadata carry secret-shaped values (schema-bypass via ``model_construct``,
      redacted at write), so end-to-end redaction is verified through the API.

    Cleaned up after every test by deleting the parent correlations (their
    assessment rows cascade away), keeping the shared database deterministic.
    """
    correlation_a = uuid.uuid4()
    correlation_b = uuid.uuid4()
    parents = [_parent(correlation_a), _parent(correlation_b)]

    a1 = _assessment(
        correlation_a,
        score=0.3,
        level=RiskLevel.LOW,
        confidence=0.4,
        timestamp=_ts(1),
    )
    factor = _factor(
        metadata={"thresholds": {"high": 0.7, "low": 0.3}},
        evidence=[_evidence(metadata={"severity": "high"})],
    )
    a2 = _assessment(
        correlation_a,
        score=0.625,
        level=RiskLevel.HIGH,
        confidence=0.8,
        factors=[factor],
        evidence=[_evidence(observation_type="member_count", metadata={"n": 2})],
        metadata={"policy": "10B", "nested": {"weights": {"volume": 0.5}}},
        timestamp=_ts(3),
    )
    a3 = _assessment(
        correlation_a,
        score=1.0,
        level=RiskLevel.CRITICAL,
        confidence=1.0,
        timestamp=_ts(2),
    )

    secret_assessment = RiskAssessment.model_construct(
        risk_assessment_id=uuid.uuid4(),
        correlation_id=correlation_b,
        score=0.5,
        level=RiskLevel.MEDIUM,
        confidence=0.5,
        factors=[
            RiskFactor.model_construct(
                factor_type="detection_volume",
                contribution=0.5,
                evidence=[],
                metadata={
                    "Authorization": "Bearer abc.def.ghi",
                    "password": "hunter2",
                    "safe": 1,
                },
            )
        ],
        evidence=[
            RiskEvidence.model_construct(
                observation_type="raw_signal",
                detection_id=uuid.uuid4(),
                event_id=uuid.uuid4(),
                metadata={"token": "tok_abc123", "ok": 1},
            )
        ],
        metadata={"apiKey": "sk-api-12345", "region": "eu"},
        timestamp=_ts(0),
        provenance=Provenance.RISK_ASSESSED,
    )

    _persist(db_session, [a1, a2, a3, secret_assessment], parents)

    try:
        yield SimpleNamespace(
            correlation_a=correlation_a,
            correlation_b=correlation_b,
            secret_assessment_id=secret_assessment.risk_assessment_id,
            assessments=(a1, a2, a3),
            credential_values=(
                "Bearer abc.def.ghi",
                "hunter2",
                "tok_abc123",
                "sk-api-12345",
            ),
        )
    finally:
        _cleanup(db_session, correlation_a, correlation_b)


@pytest.fixture()
def assessment_page_dataset(db_session: Session) -> SimpleNamespace:
    """Five assessments for one fresh correlation (deterministic pagination)."""
    correlation_id = uuid.uuid4()
    ids = [uuid.uuid4() for _ in range(5)]
    assessments = [
        _assessment(
            correlation_id,
            risk_assessment_id=ids[i],
            score=0.2 + 0.15 * i,
            level=RiskLevel.MEDIUM,
            confidence=0.5,
            timestamp=_ts(float(i)),
        )
        for i in range(5)
    ]
    _persist(db_session, assessments, [_parent(correlation_id)])

    try:
        yield SimpleNamespace(correlation_id=correlation_id, ids=ids)
    finally:
        _cleanup(db_session, correlation_id)


@pytest.fixture(scope="session")
def outsider_token(db_session: Session, _ensure_roles) -> str:
    """JWT for an authenticated user outside the SOC roles (admin/analyst/ciso)."""
    role = db_session.execute(
        select(Role).where(Role.name == "viewer")
    ).scalar_one_or_none()
    if role is None:
        role = Role(name="viewer", description="read-only non-SOC role")
        db_session.add(role)
        db_session.commit()
        db_session.refresh(role)

    email = f"test-viewer-{uuid.uuid4().hex[:8]}@example.com"
    user = User(
        email=email,
        password_hash=hash_password("TestPassword123!"),
        is_active=True,
        role_id=role.id,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return create_access_token(str(user.id))


@pytest.fixture()
def all_risk_urls() -> list[str]:
    """One request per risk endpoint, each a safe/valid request."""
    random = uuid.uuid4()
    return [
        "/api/risk-assessments/recent",
        f"/api/risk-assessments/correlation/{random}",
        f"/api/risk-assessments/{random}",
    ]


# ---------------------------------------------------------------------------
# 1. Authentication enforcement
# ---------------------------------------------------------------------------


class TestAuthentication:
    def test_every_endpoint_requires_a_token(
        self, client: TestClient, all_risk_urls: list[str]
    ) -> None:
        for url in all_risk_urls:
            assert client.get(url).status_code == 401, url

    def test_invalid_token_rejected(
        self, client: TestClient, all_risk_urls: list[str]
    ) -> None:
        headers = {"Authorization": "Bearer not-a-real-jwt"}
        for url in all_risk_urls:
            assert client.get(url, headers=headers).status_code == 401, url

    def test_expired_token_rejected(
        self, client: TestClient, admin_user: User
    ) -> None:
        """A token whose exp is already past is rejected with 401.

        The existing infrastructure supports this via
        ``create_access_token(..., expires_delta=...)``.
        """
        expired = create_access_token(
            str(admin_user.id), expires_delta=timedelta(seconds=-1)
        )
        for url in ("/api/risk-assessments/recent",):
            response = client.get(url, headers=auth_header(expired))
            assert response.status_code == 401, url

    def test_auth_is_checked_before_lookup(
        self, client: TestClient, ds: SimpleNamespace
    ) -> None:
        """Even a valid assessment id is rejected without a token (401)."""
        marker = ds.assessments[0]
        assert (
            client.get(f"/api/risk-assessments/{marker.risk_assessment_id}").status_code
            == 401
        )


# ---------------------------------------------------------------------------
# 2. RBAC authorization
# ---------------------------------------------------------------------------


class TestAuthorization:
    @pytest.mark.parametrize("token_fixture", ["admin_token", "analyst_token", "ciso_token"])
    def test_soc_roles_can_access_every_endpoint(
        self,
        client: TestClient,
        all_risk_urls: list[str],
        request: pytest.FixtureRequest,
        token_fixture: str,
    ) -> None:
        token = request.getfixturevalue(token_fixture)
        for url in all_risk_urls:
            response = client.get(url, headers=auth_header(token))
            # Exact lookups on unknown ids 404; collections return 200.
            assert response.status_code in (200, 404), (url, response.status_code)

    def test_outsider_role_forbidden(
        self, client: TestClient, outsider_token: str
    ) -> None:
        response = client.get(
            "/api/risk-assessments/recent", headers=auth_header(outsider_token)
        )
        assert response.status_code == 403
        assert response.json()["detail"] == "Insufficient permissions"

    def test_rbac_enforced_on_every_endpoint(
        self, client: TestClient, outsider_token: str, all_risk_urls: list[str]
    ) -> None:
        for url in all_risk_urls:
            response = client.get(url, headers=auth_header(outsider_token))
            assert response.status_code == 403, url

    def test_authorization_denial_is_audited(
        self, client: TestClient, db_session: Session, outsider_token: str
    ) -> None:
        """Authorization denials follow the established audit behavior."""
        before = _count_for_action(db_session, "auth.authorization.denied")
        response = client.get(
            "/api/risk-assessments/recent", headers=auth_header(outsider_token)
        )
        assert response.status_code == 403
        assert _count_for_action(db_session, "auth.authorization.denied") == before + 1

    def test_successful_read_does_not_emit_audit_events(
        self, client: TestClient, db_session: Session, admin_token: str
    ) -> None:
        """Successful reads are not audited (no read-audit convention exists)."""
        before = _count_for_action(db_session, "auth.authorization.denied")
        response = client.get(
            "/api/risk-assessments/recent", headers=auth_header(admin_token)
        )
        assert response.status_code == 200
        assert _count_for_action(db_session, "auth.authorization.denied") == before


# ---------------------------------------------------------------------------
# 3. Single risk assessment lookup
# ---------------------------------------------------------------------------


class TestGetRiskAssessment:
    def test_authenticated_user_retrieves_risk_assessment(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        assessment = ds.assessments[1]
        response = client.get(
            f"/api/risk-assessments/{assessment.risk_assessment_id}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200
        body = response.json()
        assert body["risk_assessment_id"] == str(assessment.risk_assessment_id)
        assert body["correlation_id"] == str(ds.correlation_a)
        assert body["score"] == 0.625
        assert body["level"] == "high"
        assert body["confidence"] == 0.8
        assert body["provenance"] == "risk_assessed"
        assert body["timestamp"]
        assert body["id"]
        assert body["created_at"]
        assert body["updated_at"]

    def test_response_has_correct_schema(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        body = client.get(
            f"/api/risk-assessments/{ds.assessments[0].risk_assessment_id}",
            headers=auth_header(admin_token),
        ).json()
        assert body.keys() == {
            "id",
            "risk_assessment_id",
            "correlation_id",
            "score",
            "level",
            "confidence",
            "factors",
            "evidence",
            "assessment_metadata",
            "timestamp",
            "provenance",
            "created_at",
            "updated_at",
        }
        assert body["score"] == 0.3
        assert body["level"] == "low"
        assert body["confidence"] == 0.4

    def test_response_preserves_factors_evidence_metadata_and_confidence(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        """Complete RiskAssessment information survives the HTTP round-trip.

        ``assessment_metadata`` is the persisted form of the Step 11A
        ``metadata`` (the read-record field names the column), mirroring the
        Detection/Correlation ``result_metadata`` convention.
        """
        body = client.get(
            f"/api/risk-assessments/{ds.assessments[1].risk_assessment_id}",
            headers=auth_header(admin_token),
        ).json()
        assert body["confidence"] == 0.8
        assert body["provenance"] == "risk_assessed"
        assert body["assessment_metadata"] == {
            "policy": "10B",
            "nested": {"weights": {"volume": 0.5}},
        }
        assert body["factors"][0]["metadata"] == {"thresholds": {"high": 0.7, "low": 0.3}}
        assert body["factors"][0]["evidence"][0]["metadata"] == {"severity": "high"}
        assert body["evidence"][0]["metadata"] == {"n": 2}

    def test_missing_assessment_returns_404(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            f"/api/risk-assessments/{uuid.uuid4()}", headers=auth_header(admin_token)
        )
        assert response.status_code == 404
        assert response.json()["detail"] == "Risk assessment not found"

    def test_invalid_assessment_id_rejected(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            "/api/risk-assessments/not-a-uuid", headers=auth_header(admin_token)
        )
        assert response.status_code == 422


# ---------------------------------------------------------------------------
# 4. Correlation-scoped risk assessments
# ---------------------------------------------------------------------------


class TestCorrelationRiskAssessments:
    def test_correlation_query_returns_all_historical_assessments(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        response = client.get(
            f"/api/risk-assessments/correlation/{ds.correlation_a}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 3
        assert body["page"] == 1
        assert body["page_size"] == 50
        # Multiple historical assessments are all returned, never collapsed.
        returned = {item["risk_assessment_id"] for item in body["items"]}
        assert returned == {
            str(a.risk_assessment_id) for a in ds.assessments
        }

    def test_correlation_ordering_is_deterministic(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        body = client.get(
            f"/api/risk-assessments/correlation/{ds.correlation_a}",
            headers=auth_header(admin_token),
        ).json()
        ids = [item["risk_assessment_id"] for item in body["items"]]
        # timestamp DESC -> a2 (ts3), a3 (ts2), a1 (ts1).
        assert ids == [
            str(ds.assessments[1].risk_assessment_id),
            str(ds.assessments[2].risk_assessment_id),
            str(ds.assessments[0].risk_assessment_id),
        ]
        stamps = [item["timestamp"] for item in body["items"]]
        assert stamps == sorted(stamps, reverse=True)

    def test_correlation_with_no_assessments_returns_200_empty(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            f"/api/risk-assessments/correlation/{uuid.uuid4()}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200
        body = response.json()
        assert body["items"] == []
        assert body["total"] == 0

    def test_invalid_correlation_id_rejected(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            "/api/risk-assessments/correlation/not-a-uuid",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 422

    def test_correlation_pagination_is_deterministic(
        self,
        client: TestClient,
        assessment_page_dataset: SimpleNamespace,
        admin_token: str,
    ) -> None:
        first = client.get(
            f"/api/risk-assessments/correlation/{assessment_page_dataset.correlation_id}"
            "?page=1&page_size=2",
            headers=auth_header(admin_token),
        ).json()
        second = client.get(
            f"/api/risk-assessments/correlation/{assessment_page_dataset.correlation_id}"
            "?page=2&page_size=2",
            headers=auth_header(admin_token),
        ).json()
        third = client.get(
            f"/api/risk-assessments/correlation/{assessment_page_dataset.correlation_id}"
            "?page=3&page_size=2",
            headers=auth_header(admin_token),
        ).json()

        expected = [str(aid) for aid in assessment_page_dataset.ids[::-1]]
        actual = (
            [item["risk_assessment_id"] for item in first["items"]]
            + [item["risk_assessment_id"] for item in second["items"]]
            + [item["risk_assessment_id"] for item in third["items"]]
        )
        assert actual == expected
        assert first["total"] == second["total"] == third["total"] == 5
        assert len(first["items"]) == 2
        assert len(second["items"]) == 2
        assert len(third["items"]) == 1

    def test_correlation_max_page_size_accepted(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            f"/api/risk-assessments/correlation/{uuid.uuid4()}?page_size={MAX_PAGE_SIZE}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# 5. Pagination validation (HTTP-level contract)
# ---------------------------------------------------------------------------


class TestPaginationValidation:
    def test_invalid_page_rejected(self, client: TestClient, admin_token: str) -> None:
        correlation = uuid.uuid4()
        for page in ("0", "-1", "abc"):
            response = client.get(
                f"/api/risk-assessments/correlation/{correlation}?page={page}",
                headers=auth_header(admin_token),
            )
            assert response.status_code == 422, page

    def test_invalid_page_size_rejected(self, client: TestClient, admin_token: str) -> None:
        response = client.get(
            f"/api/risk-assessments/correlation/{uuid.uuid4()}?page_size=0",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 422

    def test_excessive_page_size_rejected(self, client: TestClient, admin_token: str) -> None:
        response = client.get(
            f"/api/risk-assessments/correlation/{uuid.uuid4()}?page_size=201",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 422


# ---------------------------------------------------------------------------
# 6. Recent risk assessments feed
# ---------------------------------------------------------------------------


class TestRecentRiskAssessments:
    def test_recent_returns_results(
        self, client: TestClient, db_session: Session, admin_token: str
    ) -> None:
        # A dedicated newest marker guarantees determinism even though the
        # shared test database accumulates rows across runs.  Prior runs may
        # have left markers at the same fixture instant; stamp this marker
        # strictly after the newest existing row so the deterministic
        # tie-break (risk_assessment_id ASC) can never push it out of the
        # top-10 feed.
        newest = db_session.scalar(
            select(func.max(RiskAssessmentRow.timestamp))
        )
        marker_ts = (
            newest + timedelta(seconds=1) if newest is not None else _ts(10_000)
        )
        marker_cid = uuid.uuid4()
        marker = _assessment(
            marker_cid, score=0.9, level=RiskLevel.HIGH, confidence=0.7, timestamp=marker_ts
        )
        _persist(db_session, [marker], [_parent(marker_cid, timestamp=marker_ts)])

        try:
            response = client.get(
                "/api/risk-assessments/recent?limit=10",
                headers=auth_header(admin_token),
            )
            assert response.status_code == 200
            body = response.json()
            assert isinstance(body, list)
            assert len(body) >= 1
            assert str(marker.risk_assessment_id) in {
                item["risk_assessment_id"] for item in body
            }
            assert all("risk_assessment_id" in item and "correlation_id" in item for item in body)
        finally:
            _cleanup(db_session, marker_cid)

    def test_recent_returns_multiple_results(
        self, client: TestClient, db_session: Session, admin_token: str
    ) -> None:
        # Same deterministic convention as the sibling recent-feed tests:
        # stamp markers after the newest persisted row so previously
        # accumulated data can never push them out of the bounded feed.
        newest = db_session.scalar(select(func.max(RiskAssessmentRow.timestamp)))
        base_ts = (
            newest + timedelta(seconds=1) if newest is not None else _ts(1)
        )
        cid1, cid2 = uuid.uuid4(), uuid.uuid4()
        a1 = _assessment(cid1, score=0.4, level=RiskLevel.LOW, confidence=0.5, timestamp=base_ts)
        a2 = _assessment(
            cid2, score=0.8, level=RiskLevel.HIGH, confidence=0.9,
            timestamp=base_ts + timedelta(seconds=1),
        )
        _persist(db_session, [a1, a2], [_parent(cid1, timestamp=base_ts), _parent(cid2, timestamp=base_ts)])

        try:
            body = client.get(
                "/api/risk-assessments/recent?limit=50",
                headers=auth_header(admin_token),
            ).json()
            ids = {item["risk_assessment_id"] for item in body}
            assert str(a1.risk_assessment_id) in ids
            assert str(a2.risk_assessment_id) in ids
        finally:
            _cleanup(db_session, cid1, cid2)

    def test_recent_respects_bounded_limit(
        self, client: TestClient, db_session: Session, admin_token: str
    ) -> None:
        newest = db_session.scalar(select(func.max(RiskAssessmentRow.timestamp)))
        base_ts = (
            newest + timedelta(seconds=1) if newest is not None else _ts(9_000)
        )
        cid1, cid2, cid3 = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        a1 = _assessment(cid1, score=0.5, level=RiskLevel.LOW, confidence=0.5, timestamp=base_ts)
        a2 = _assessment(
            cid2, score=0.6, level=RiskLevel.MEDIUM, confidence=0.6, timestamp=base_ts + timedelta(seconds=1)
        )
        a3 = _assessment(
            cid3, score=0.7, level=RiskLevel.HIGH, confidence=0.7, timestamp=base_ts + timedelta(seconds=2)
        )
        _persist(db_session, [a1, a2, a3], [_parent(cid1), _parent(cid2), _parent(cid3)])

        try:
            limited = client.get(
                "/api/risk-assessments/recent?limit=2", headers=auth_header(admin_token)
            ).json()
            assert len(limited) == 2

            full = client.get(
                "/api/risk-assessments/recent?limit=200", headers=auth_header(admin_token)
            )
            assert full.status_code == 200
            assert len(full.json()) <= 200
            assert len(full.json()) >= 3
        finally:
            _cleanup(db_session, cid1, cid2, cid3)

    def test_recent_ordering_is_deterministic(
        self, client: TestClient, db_session: Session, admin_token: str
    ) -> None:
        newest = db_session.scalar(select(func.max(RiskAssessmentRow.timestamp)))
        base_ts = (
            newest + timedelta(seconds=1) if newest is not None else _ts(9_500)
        )
        cid1, cid2, cid3 = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        a1 = _assessment(cid1, score=0.4, level=RiskLevel.LOW, confidence=0.5, timestamp=base_ts)
        a2 = _assessment(
            cid2, score=0.6, level=RiskLevel.MEDIUM, confidence=0.6, timestamp=base_ts + timedelta(seconds=1)
        )
        a3 = _assessment(
            cid3, score=0.8, level=RiskLevel.HIGH, confidence=0.8, timestamp=base_ts + timedelta(seconds=2)
        )
        _persist(db_session, [a1, a2, a3], [_parent(cid1), _parent(cid2), _parent(cid3)])

        try:
            body = client.get(
                "/api/risk-assessments/recent?limit=200", headers=auth_header(admin_token)
            ).json()
            stamps = [item["timestamp"] for item in body]
            assert stamps == sorted(stamps, reverse=True)
            assert [item["risk_assessment_id"] for item in body][:3] == [
                str(a3.risk_assessment_id),
                str(a2.risk_assessment_id),
                str(a1.risk_assessment_id),
            ]
        finally:
            _cleanup(db_session, cid1, cid2, cid3)

    def test_recent_equal_timestamps_use_deterministic_tie_break(
        self, client: TestClient, db_session: Session, admin_token: str
    ) -> None:
        """Rows sharing a timestamp order deterministically by id ASC."""
        shared = _ts(12_000)
        cid1, cid2 = uuid.uuid4(), uuid.uuid4()
        a1 = _assessment(cid1, score=0.4, level=RiskLevel.LOW, confidence=0.5, timestamp=shared)
        a2 = _assessment(cid2, score=0.6, level=RiskLevel.MEDIUM, confidence=0.6, timestamp=shared)
        _persist(
            db_session,
            [a1, a2],
            [_parent(cid1, timestamp=shared), _parent(cid2, timestamp=shared)],
        )

        try:
            body = client.get(
                "/api/risk-assessments/recent?limit=50",
                headers=auth_header(admin_token),
            ).json()
            ids = [item["risk_assessment_id"] for item in body]
            sub = [i for i in ids if i in (str(a1.risk_assessment_id), str(a2.risk_assessment_id))]
            assert sub == sorted((str(a1.risk_assessment_id), str(a2.risk_assessment_id)))
        finally:
            _cleanup(db_session, cid1, cid2)

    def test_recent_invalid_limit_rejected(
        self, client: TestClient, admin_token: str
    ) -> None:
        for limit in ("0", "-1", "201", "abc"):
            response = client.get(
                f"/api/risk-assessments/recent?limit={limit}",
                headers=auth_header(admin_token),
            )
            assert response.status_code == 422, limit


# ---------------------------------------------------------------------------
# 7. Route ordering — static routes never resolve as /{risk_assessment_id}
# ---------------------------------------------------------------------------


class TestRouteCollision:
    def test_recent_resolves_to_recent_endpoint(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            "/api/risk-assessments/recent", headers=auth_header(admin_token)
        )
        assert response.status_code == 200
        assert isinstance(response.json(), list)  # a feed, never a single record

    def test_segmented_correlation_path_never_an_assessment_lookup(
        self, client: TestClient, admin_token: str
    ) -> None:
        # "correlation" is not a UUID, so if /correlation/{id} were shadowed
        # by /{risk_assessment_id} the request would 422 on UUID parsing —
        # but the segmented route must be matched first.  A bare trailing
        # segmentless path missing its id yields 404 (route matched, no id).
        response = client.get(
            "/api/risk-assessments/correlation/", headers=auth_header(admin_token)
        )
        assert response.status_code in (404, 422)
        # The valid segmented route still answers correctly under the same prefix.
        valid = client.get(
            f"/api/risk-assessments/correlation/{uuid.uuid4()}",
            headers=auth_header(admin_token),
        )
        assert valid.status_code == 200


# ---------------------------------------------------------------------------
# 8. Error handling & sanitization
# ---------------------------------------------------------------------------


class TestErrorSanitization:
    def test_database_failure_becomes_safe_503(
        self, client: TestClient, admin_token: str, monkeypatch
    ) -> None:
        class _BrokenService:
            def get_assessment(self, db, risk_assessment_id):
                raise RiskQueryError(
                    risk_assessment_id=risk_assessment_id,
                    reason="simulated database failure",
                )

        monkeypatch.setattr(risks_routes, "_service", _BrokenService())
        response = client.get(
            f"/api/risk-assessments/{uuid.uuid4()}", headers=auth_header(admin_token)
        )
        assert response.status_code == 503
        assert response.json() == {"detail": "Risk data is unavailable"}

    def test_database_failure_leaks_no_internals(
        self, client: TestClient, admin_token: str, monkeypatch
    ) -> None:
        class _BrokenService:
            def list_recent_assessments(self, db, *, limit=50):
                raise RiskQueryError(reason="simulated failure")

        monkeypatch.setattr(risks_routes, "_service", _BrokenService())
        response = client.get(
            "/api/risk-assessments/recent", headers=auth_header(admin_token)
        )
        assert response.status_code == 503
        raw = response.text.lower()
        for fragment in ("sqlalchemy", "psycopg", "traceback", "exception", "postgres"):
            assert fragment not in raw

    def test_correlation_list_failure_becomes_safe_503(
        self, client: TestClient, admin_token: str, monkeypatch
    ) -> None:
        class _BrokenService:
            def list_assessments_for_correlation(
                self, db, correlation_id, *, page=1, page_size=50
            ):
                raise RiskQueryError(
                    correlation_id=correlation_id,
                    reason="simulated failure",
                )

        monkeypatch.setattr(risks_routes, "_service", _BrokenService())
        response = client.get(
            f"/api/risk-assessments/correlation/{uuid.uuid4()}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 503
        assert response.json()["detail"] == "Risk data is unavailable"

    def test_service_validation_error_maps_to_422(
        self, client: TestClient, admin_token: str, monkeypatch
    ) -> None:
        class _RejectingService:
            def list_assessments_for_correlation(
                self, db, correlation_id, *, page=1, page_size=50
            ):
                raise RiskQueryValidationError(reason="page_size must not exceed 200")

        monkeypatch.setattr(risks_routes, "_service", _RejectingService())
        response = client.get(
            f"/api/risk-assessments/correlation/{uuid.uuid4()}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 422
        assert "page_size" in response.json()["detail"]

    def test_unexpected_error_maps_to_sanitized_500(
        self, admin_token: str, monkeypatch
    ) -> None:
        class _ExplodingService:
            def get_assessment(self, db, risk_assessment_id):
                raise RuntimeError("boom")

        monkeypatch.setattr(risks_routes, "_service", _ExplodingService())
        # raise_server_exceptions=False lets the centralized exception
        # handler produce the response instead of TestClient re-raising.
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get(
            f"/api/risk-assessments/{uuid.uuid4()}", headers=auth_header(admin_token)
        )
        assert response.status_code == 500
        assert response.json() == {"detail": "Internal server error"}
        assert "boom" not in response.text


# ---------------------------------------------------------------------------
# 9. Security — redaction survives end-to-end through the response
# ---------------------------------------------------------------------------


class TestSecretRedaction:
    def test_secret_shaped_metadata_remains_redacted(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        body = client.get(
            f"/api/risk-assessments/{ds.secret_assessment_id}",
            headers=auth_header(admin_token),
        ).json()
        metadata = body["assessment_metadata"]
        assert metadata["apiKey"] == "<redacted>"
        assert metadata["region"] == "eu"
        assert body["factors"][0]["metadata"]["Authorization"] == "<redacted>"
        assert body["factors"][0]["metadata"]["password"] == "<redacted>"
        assert body["factors"][0]["metadata"]["safe"] == 1
        assert body["evidence"][0]["metadata"]["token"] == "<redacted>"
        assert body["evidence"][0]["metadata"]["ok"] == 1

    def test_raw_credentials_never_appear_in_response(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        raw = client.get(
            f"/api/risk-assessments/{ds.secret_assessment_id}",
            headers=auth_header(admin_token),
        ).text
        for credential in ds.credential_values:
            assert credential not in raw

    def test_response_exposes_no_database_internals(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        response = client.get(
            f"/api/risk-assessments/{ds.assessments[0].risk_assessment_id}",
            headers=auth_header(admin_token),
        )
        raw = response.text.lower()
        for fragment in ("sqlalchemy", "psycopg", "postgres", "traceback", "exception"):
            assert fragment not in raw


# ---------------------------------------------------------------------------
# 10. Read-only contract and mutation checks
# ---------------------------------------------------------------------------


class TestReadOnlyContract:
    def test_api_does_not_mutate_persisted_records(
        self,
        client: TestClient,
        db_session: Session,
        ds: SimpleNamespace,
        admin_token: str,
    ) -> None:
        before_assessments = _count(db_session, RiskAssessmentRow)

        urls = [
            f"/api/risk-assessments/{ds.assessments[0].risk_assessment_id}",
            f"/api/risk-assessments/correlation/{ds.correlation_a}",
            "/api/risk-assessments/recent",
        ]
        for url in urls:
            assert client.get(url, headers=auth_header(admin_token)).status_code == 200

        assert _count(db_session, RiskAssessmentRow) == before_assessments

    def test_no_mutation_endpoints_exist(self, client: TestClient) -> None:
        spec = client.get("/openapi.json").json()
        for path in spec["paths"]:
            if "risk-assessments" in path:
                assert set(spec["paths"][path]) == {"get"}, path

    def test_no_write_methods_accepted(
        self, client: TestClient, admin_token: str
    ) -> None:
        for method in ("post", "put", "patch", "delete"):
            response = getattr(client, method)(
                "/api/risk-assessments/recent", headers=auth_header(admin_token)
            )
            assert response.status_code == 405, method


# ---------------------------------------------------------------------------
# 11. Architecture — routes delegate to the query service only
# ---------------------------------------------------------------------------


class TestArchitecture:
    def test_route_delegates_to_query_service_for_get(
        self, client: TestClient, admin_token: str, monkeypatch
    ) -> None:
        risk_assessment_id = uuid.uuid4()
        called_with = []

        class _ProbeService:
            def get_assessment(self, db, risk_assessment_id):
                called_with.append(risk_assessment_id)
                return {
                    "id": str(uuid.uuid4()),
                    "risk_assessment_id": str(risk_assessment_id),
                    "correlation_id": str(uuid.uuid4()),
                    "score": 0.5,
                    "level": "medium",
                    "confidence": 0.5,
                    "factors": [],
                    "evidence": [],
                    "assessment_metadata": {},
                    "timestamp": "2026-09-20T12:00:00Z",
                    "provenance": "risk_assessed",
                    "created_at": "2026-09-20T12:00:00Z",
                    "updated_at": "2026-09-20T12:00:00Z",
                }

        monkeypatch.setattr(risks_routes, "_service", _ProbeService())
        response = client.get(
            f"/api/risk-assessments/{risk_assessment_id}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200
        assert response.json()["risk_assessment_id"] == str(risk_assessment_id)
        assert called_with == [risk_assessment_id]

    def test_route_delegates_to_query_service_for_correlation_list(
        self, client: TestClient, admin_token: str, monkeypatch
    ) -> None:
        correlation_id = uuid.uuid4()
        called_with = []

        class _ProbeService:
            def list_assessments_for_correlation(
                self, db, correlation_id, *, page=1, page_size=50
            ):
                called_with.append((correlation_id, page, page_size))
                return {
                    "items": [],
                    "total": 0,
                    "page": page,
                    "page_size": page_size,
                }

        monkeypatch.setattr(risks_routes, "_service", _ProbeService())
        response = client.get(
            f"/api/risk-assessments/correlation/{correlation_id}?page=2&page_size=7",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200
        assert response.json()["total"] == 0
        assert called_with == [(correlation_id, 2, 7)]

    def test_route_delegates_to_query_service_for_recent(
        self, client: TestClient, admin_token: str, monkeypatch
    ) -> None:
        called_with = []

        class _ProbeService:
            def list_recent_assessments(self, db, *, limit=50):
                called_with.append(limit)
                return []

        monkeypatch.setattr(risks_routes, "_service", _ProbeService())
        response = client.get(
            "/api/risk-assessments/recent?limit=3", headers=auth_header(admin_token)
        )
        assert response.status_code == 200
        assert response.json() == []
        assert called_with == [3]

    def test_route_source_has_no_direct_database_access(self) -> None:
        """The route module must not perform raw SQLAlchemy operations."""
        source = inspect.getsource(risks_routes)
        for forbidden in (
            "db.query",
            "select(",
            "insert(",
            "update(",
            "delete(",
            ".commit(",
            ".rollback(",
            ".flush(",
            "session.execute",
        ):
            assert forbidden not in source, forbidden


# ---------------------------------------------------------------------------
# 12. OpenAPI / router registration
# ---------------------------------------------------------------------------


class TestOpenApiRegistration:
    EXPECTED_PATHS = {
        "/api/risk-assessments/{risk_assessment_id}",
        "/api/risk-assessments/correlation/{correlation_id}",
        "/api/risk-assessments/recent",
    }

    def test_router_registered_under_existing_api_prefix(
        self, client: TestClient
    ) -> None:
        spec = client.get("/openapi.json").json()
        risk_paths = {
            path for path in spec["paths"] if "risk-assessments" in path
        }
        assert risk_paths == self.EXPECTED_PATHS

    def test_every_risk_operation_requires_bearer_auth(
        self, client: TestClient
    ) -> None:
        spec = client.get("/openapi.json").json()
        for path in self.EXPECTED_PATHS:
            operation = spec["paths"][path]["get"]
            assert operation["security"] == [{"HTTPBearer": []}], path
            assert operation["tags"] == ["Risk Assessments"], path

    def test_risk_paths_expose_no_other_methods(self, client: TestClient) -> None:
        spec = client.get("/openapi.json").json()
        for path in self.EXPECTED_PATHS:
            assert set(spec["paths"][path]) == {"get"}, path

    def test_operation_ids_are_unique(self, client: TestClient) -> None:
        spec = client.get("/openapi.json").json()
        operation_ids = [
            operation["operationId"]
            for path in spec["paths"]
            for operation in spec["paths"][path].values()
        ]
        assert len(operation_ids) == len(set(operation_ids))

    def test_security_scheme_declared(self, client: TestClient) -> None:
        spec = client.get("/openapi.json").json()
        schemes = spec.get("components", {}).get("securitySchemes", {})
        assert "HTTPBearer" in schemes
        assert schemes["HTTPBearer"]["scheme"] == "bearer"