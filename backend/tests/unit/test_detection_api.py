"""Detection API layer behavior tests (Step 9H).

Exercises the read-only detection endpoints through the full integration
stack the project already uses for API tests — JWT -> FastAPI
(``TestClient(app)``) -> route -> :class:`DetectionQueryService` ->
repository -> PostgreSQL:

* authentication and RBAC enforcement on every detection endpoint;
* exact-lookup 404 vs. empty-collection 200 semantics;
* HTTP-level and service-level parameter validation (422);
* deterministic ordering and bounded pagination;
* sanitized database-failure responses (503) with no internals leaked;
* strict read-only behavior (no writes, no mutation, no non-GET methods).

Rows are seeded through the real :class:`DetectionPersistenceService`
against the same shared test database the existing API tests use, so the
end-to-end path (including PostgreSQL ``JSONB`` round-trips) is exercised.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

import app.api.routes.detections as detections_routes
from app.core.security import create_access_token, hash_password
from app.models.detection_result import DetectionResult as DetectionResultRow
from app.models.detection_rule_failure import (
    DetectionRuleFailure as DetectionRuleFailureRow,
)
from app.models.role import Role
from app.models.user import User
from app.schemas.detection import (
    DetectionEvidence,
    DetectionMetadata,
    DetectionResult,
    DetectionSeverity,
    RuleType,
)
from app.schemas.detection_agent import (
    DetectionAnalysis,
    DetectionAnalysisMetadata,
    DetectionFailure,
)
from app.services.detection_persistence import DetectionPersistenceService
from app.services.detection_query import (
    DetectionQueryError,
    DetectionQueryValidationError,
)
from tests.conftest import auth_header

# ---------------------------------------------------------------------------
# Deterministic fixture data / seeding helpers
# ---------------------------------------------------------------------------

BASE = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)


def _ts(hours: float = 0.0) -> datetime:
    """Deterministic timezone-aware timestamp offset from BASE."""
    return BASE + timedelta(hours=hours)


class _TickClock:
    """Incrementing clock so each persisted failure gets a distinct failed_at."""

    def __init__(self, start: float = 1.0, step: float = 1.0) -> None:
        self._value = start
        self._step = step

    def __call__(self) -> datetime:
        now = _ts(self._value)
        self._value += self._step
        return now


def _result(
    rule_id: str,
    *,
    event_id: uuid.UUID,
    rule_type: RuleType = RuleType.SIGMA,
    severity: DetectionSeverity = DetectionSeverity.HIGH,
    confidence: float = 0.9,
    detected_at: datetime | None = None,
    rule_version: str = "1.0.0",
    matched_conditions: tuple[str, ...] = ("selection_1",),
    matched_fields: dict | None = None,
    rule_references: dict | None = None,
    detection_context: dict | None = None,
    metadata_extra: dict | None = None,
    detection_id: uuid.UUID | None = None,
) -> DetectionResult:
    """Build a matched DetectionResult contract object."""
    return DetectionResult(
        detection_id=detection_id or uuid.uuid4(),
        event_id=event_id,
        rule_id=rule_id,
        rule_type=rule_type,
        matched=True,
        severity=severity,
        confidence=confidence,
        evidence=DetectionEvidence(
            matched_conditions=list(matched_conditions),
            matched_fields=matched_fields or {},
            rule_references=rule_references or {},
            detection_context=detection_context or {},
        ),
        timestamp=detected_at or _ts(0),
        metadata=DetectionMetadata(
            rule_version=rule_version,
            execution_time_ms=12.5,
            total_rules_evaluated=10,
            extra=metadata_extra or {},
        ),
    )


def _failure(
    engine: str = "sigma",
    rule_id: str = "sigma-bad",
    error_type: str = "malformed_rule",
    message: str = "rule could not be parsed",
) -> DetectionFailure:
    """Build a DetectionFailure contract object (secret-safe message)."""
    return DetectionFailure(
        engine=engine,
        rule_id=rule_id,
        error_type=error_type,
        message=message,
    )


def _analysis(
    event_id: uuid.UUID,
    results: tuple[DetectionResult, ...] = (),
    failures: tuple[DetectionFailure, ...] = (),
) -> DetectionAnalysis:
    """Build a DetectionAnalysis contract object."""
    return DetectionAnalysis(
        event_id=event_id,
        results=list(results),
        failures=list(failures),
        metadata=DetectionAnalysisMetadata(engines_executed=1),
        timestamp=_ts(0),
    )


def _persist(db: Session, analysis: DetectionAnalysis, clock=None) -> None:
    """Persist *analysis* through the real persistence service."""
    if clock is None:
        clock = _TickClock()
    DetectionPersistenceService(clock=clock).persist_analysis(db, analysis)


def _count(db: Session, model) -> int:
    """Count every persisted row of *model*."""
    return db.scalar(select(func.count()).select_from(model))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def ds(db_session: Session) -> SimpleNamespace:
    """A function-scoped seeded dataset of persisted detection rows.

    * ``event_a``: 3 results (distinct detected_at) + 2 failures (distinct
      failed_at, persisted in two calls because the persistence service
      stamps every failure of one analysis with a single ``now``).
    * ``event_b``: 1 result for the same rule as event_a's first result
      (``rule_sigma1`` spans two events); no failures.

    All rule IDs are unique per test so rule-scoped totals stay exact
    against the shared test database across runs.
    """
    event_a = uuid.uuid4()
    event_b = uuid.uuid4()

    rule_sigma1 = f"rule-win-powershell-{uuid.uuid4().hex[:8]}"
    rule_sigma2 = f"rule-win-lateral-{uuid.uuid4().hex[:8]}"
    rule_yara = f"rule-apt-backdoor-{uuid.uuid4().hex[:8]}"
    failure_sigma_rule = f"rule-win-broken-sigma-{uuid.uuid4().hex[:8]}"
    failure_yara_rule = f"rule-yara-broken-{uuid.uuid4().hex[:8]}"

    r1 = _result(
        rule_sigma1,
        event_id=event_a,
        severity=DetectionSeverity.HIGH,
        confidence=0.95,
        detected_at=_ts(0),
        matched_conditions=("sel_web",),
        matched_fields={"Image": "powershell.exe"},
        rule_references={"attack": "T1059.001"},
        detection_context={"engine": "sigma"},
        metadata_extra={"source": "api-test"},
    )
    r2 = _result(
        rule_sigma2,
        event_id=event_a,
        severity=DetectionSeverity.MEDIUM,
        confidence=0.8,
        detected_at=_ts(1),
    )
    r3 = _result(
        rule_yara,
        rule_type=RuleType.YARA,
        event_id=event_a,
        severity=DetectionSeverity.CRITICAL,
        confidence=0.99,
        detected_at=_ts(2),
        matched_conditions=("APT_backdoor",),
        matched_fields={"Process": "svchost.exe"},
    )
    r4 = _result(
        rule_sigma1,
        event_id=event_b,
        severity=DetectionSeverity.LOW,
        confidence=0.5,
        detected_at=_ts(3),
    )

    f1 = _failure("sigma", failure_sigma_rule, "malformed_rule", "rule could not be parsed")
    f2 = _failure("yara", failure_yara_rule, "unsupported_feature", "unsupported string modifier")

    # Failure f1 is stamped at 4h, failure f2 at 5h (separate persist calls).
    _persist(
        db_session,
        _analysis(event_a, results=(r1, r2, r3), failures=(f1,)),
        _TickClock(start=4.0),
    )
    _persist(
        db_session,
        _analysis(event_a, results=(r1, r2, r3), failures=(f2,)),
        _TickClock(start=5.0),
    )
    _persist(db_session, _analysis(event_b, results=(r4,)))

    return SimpleNamespace(
        event_a=event_a,
        event_b=event_b,
        rule_sigma1=rule_sigma1,
        rule_sigma2=rule_sigma2,
        rule_yara=rule_yara,
        failure_sigma_rule=failure_sigma_rule,
        failure_yara_rule=failure_yara_rule,
        detection_r1=r1.detection_id,
        detection_r2=r2.detection_id,
        detection_r3=r3.detection_id,
        detection_r4=r4.detection_id,
    )


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
def all_detection_urls() -> list[str]:
    """One request per detection endpoint, each a safe/valid request."""
    random = uuid.uuid4()
    return [
        "/api/detections/recent",
        f"/api/detections/event/{random}",
        "/api/detections/rule/rule-that-does-not-exist",
        f"/api/detections/{random}",
        f"/api/detection-analyses/{random}",
        f"/api/detection-analyses/{random}/failures",
    ]


# ---------------------------------------------------------------------------
# 1. Authentication enforcement
# ---------------------------------------------------------------------------


class TestAuthentication:
    def test_every_endpoint_requires_a_token(
        self, client: TestClient, all_detection_urls: list[str]
    ) -> None:
        for url in all_detection_urls:
            assert client.get(url).status_code == 401, url

    def test_invalid_token_rejected(
        self, client: TestClient, all_detection_urls: list[str]
    ) -> None:
        headers = {"Authorization": "Bearer not-a-real-jwt"}
        for url in all_detection_urls:
            assert client.get(url, headers=headers).status_code == 401, url


# ---------------------------------------------------------------------------
# 2. RBAC authorization
# ---------------------------------------------------------------------------


class TestAuthorization:
    @pytest.mark.parametrize("token_fixture", ["admin_token", "analyst_token", "ciso_token"])
    def test_soc_roles_can_access_every_endpoint(
        self,
        client: TestClient,
        all_detection_urls: list[str],
        request: pytest.FixtureRequest,
        token_fixture: str,
    ) -> None:
        token = request.getfixturevalue(token_fixture)
        for url in all_detection_urls:
            response = client.get(url, headers=auth_header(token))
            # Exact lookups on unknown ids 404; collections return 200.
            assert response.status_code in (200, 404), (url, response.status_code)

    def test_outsider_role_forbidden(
        self, client: TestClient, outsider_token: str
    ) -> None:
        response = client.get(
            "/api/detections/recent", headers=auth_header(outsider_token)
        )
        assert response.status_code == 403
        assert response.json()["detail"] == "Insufficient permissions"

    def test_rbac_enforced_on_every_endpoint(
        self, client: TestClient, outsider_token: str, all_detection_urls: list[str]
    ) -> None:
        for url in all_detection_urls:
            response = client.get(url, headers=auth_header(outsider_token))
            assert response.status_code == 403, url


# ---------------------------------------------------------------------------
# 3. Single detection lookup
# ---------------------------------------------------------------------------


class TestGetDetection:
    def test_authenticated_user_retrieves_detection(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        response = client.get(
            f"/api/detections/{ds.detection_r1}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200
        body = response.json()
        assert body["detection_id"] == str(ds.detection_r1)
        assert body["event_id"] == str(ds.event_a)
        assert body["rule_id"] == ds.rule_sigma1
        assert body["rule_type"] == "sigma"
        assert body["rule_version"] == "1.0.0"
        assert body["severity"] == "high"
        assert body["matched"] is True
        assert body["confidence"] == 0.95
        assert body["provenance"] == "detected"
        assert body["id"]  # persisted row pk present
        assert body["created_at"]
        assert body["updated_at"]

    def test_missing_detection_returns_404(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            f"/api/detections/{uuid.uuid4()}", headers=auth_header(admin_token)
        )
        assert response.status_code == 404
        assert response.json()["detail"] == "Detection not found"

    def test_invalid_detection_id_rejected(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            "/api/detections/not-a-uuid", headers=auth_header(admin_token)
        )
        assert response.status_code == 422

    def test_auth_is_checked_before_lookup(
        self, client: TestClient, ds: SimpleNamespace
    ) -> None:
        """Even a valid detection_id is rejected without a token (401)."""
        assert client.get(f"/api/detections/{ds.detection_r1}").status_code == 401


# ---------------------------------------------------------------------------
# 4. Event-scoped detections
# ---------------------------------------------------------------------------


class TestEventDetections:
    def test_event_query_returns_results(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        response = client.get(
            f"/api/detections/event/{ds.event_a}", headers=auth_header(admin_token)
        )
        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 3
        assert body["page"] == 1
        assert body["page_size"] == 50
        assert [item["detection_id"] for item in body["items"]] == [
            str(ds.detection_r3),
            str(ds.detection_r2),
            str(ds.detection_r1),
        ]

    def test_event_with_no_detections_returns_200_empty(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            f"/api/detections/event/{uuid.uuid4()}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200
        body = response.json()
        assert body["items"] == []
        assert body["total"] == 0

    def test_event_pagination_is_deterministic(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        first = client.get(
            f"/api/detections/event/{ds.event_a}?page=1&page_size=2",
            headers=auth_header(admin_token),
        ).json()
        second = client.get(
            f"/api/detections/event/{ds.event_a}?page=2&page_size=2",
            headers=auth_header(admin_token),
        ).json()
        assert len(first["items"]) == 2
        assert len(second["items"]) == 1
        assert first["total"] == 3 and second["total"] == 3
        page_1_ids = [item["detection_id"] for item in first["items"]]
        page_2_ids = [item["detection_id"] for item in second["items"]]
        assert page_1_ids + page_2_ids == [
            str(ds.detection_r3),
            str(ds.detection_r2),
            str(ds.detection_r1),
        ]
        assert not set(page_1_ids) & set(page_2_ids)

    def test_event_ordering_is_deterministic(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        body = client.get(
            f"/api/detections/event/{ds.event_a}", headers=auth_header(admin_token)
        ).json()
        stamps = [item["detected_at"] for item in body["items"]]
        assert stamps == sorted(stamps, reverse=True)

    def test_invalid_event_id_rejected(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            "/api/detections/event/not-a-uuid", headers=auth_header(admin_token)
        )
        assert response.status_code == 422


# ---------------------------------------------------------------------------
# 5. Rule-scoped detections
# ---------------------------------------------------------------------------


class TestRuleDetections:
    def test_rule_query_returns_results(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        response = client.get(
            f"/api/detections/rule/{ds.rule_sigma1}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 2
        assert {item["event_id"] for item in body["items"]} == {
            str(ds.event_a),
            str(ds.event_b),
        }

    def test_rule_with_no_detections_returns_200_empty(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            "/api/detections/rule/rule-that-never-matched",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200
        body = response.json()
        assert body["items"] == []
        assert body["total"] == 0

    def test_rule_id_matched_exactly_never_normalized(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        """A case-variant of a stored rule_id yields no results (no folding)."""
        response = client.get(
            f"/api/detections/rule/{ds.rule_sigma1.upper()}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200
        assert response.json()["items"] == []

    def test_rule_pagination_is_deterministic(
        self, client: TestClient, db_session: Session, admin_token: str
    ) -> None:
        event_id = uuid.uuid4()
        rule_id = f"rule-pagination-{uuid.uuid4().hex[:8]}"
        results = tuple(
            _result(
                rule_id,
                event_id=event_id,
                confidence=0.5 + i * 0.01,
                detected_at=_ts(i),
            )
            for i in range(5)
        )
        _persist(db_session, _analysis(event_id, results=results))

        page_1 = client.get(
            f"/api/detections/rule/{rule_id}?page=1&page_size=2",
            headers=auth_header(admin_token),
        ).json()
        page_2 = client.get(
            f"/api/detections/rule/{rule_id}?page=2&page_size=2",
            headers=auth_header(admin_token),
        ).json()
        page_3 = client.get(
            f"/api/detections/rule/{rule_id}?page=3&page_size=2",
            headers=auth_header(admin_token),
        ).json()

        expected = [str(r.detection_id) for r in results[::-1]]
        actual = (
            [item["detection_id"] for item in page_1["items"]]
            + [item["detection_id"] for item in page_2["items"]]
            + [item["detection_id"] for item in page_3["items"]]
        )
        assert actual == expected
        assert page_1["total"] == page_2["total"] == page_3["total"] == 5

    def test_equal_timestamp_tiebreak_is_deterministic(
        self, client: TestClient, db_session: Session, admin_token: str
    ) -> None:
        event_id = uuid.uuid4()
        rule_id = f"rule-tiebreak-{uuid.uuid4().hex[:8]}"
        id_a = uuid.uuid4()
        id_b = uuid.uuid4()
        id_lo, id_hi = sorted((id_a, id_b))  # UUID magnitude == DB ordering
        results = (
            _result(rule_id, event_id=event_id, detected_at=_ts(1), detection_id=id_lo),
            _result(rule_id, event_id=event_id, detected_at=_ts(1), detection_id=id_hi),
        )
        _persist(db_session, _analysis(event_id, results=results))

        body = client.get(
            f"/api/detections/rule/{rule_id}", headers=auth_header(admin_token)
        ).json()
        assert [item["detection_id"] for item in body["items"]] == [
            str(id_lo),
            str(id_hi),
        ]

    def test_rule_id_too_long_rejected_by_service_boundary(
        self, client: TestClient, admin_token: str
    ) -> None:
        over_long = "r" * 300
        response = client.get(
            f"/api/detections/rule/{over_long}", headers=auth_header(admin_token)
        )
        assert response.status_code == 422


# ---------------------------------------------------------------------------
# 6. Recent detections feed
# ---------------------------------------------------------------------------


class TestRecentDetections:
    def test_recent_returns_results(
        self, client: TestClient, db_session: Session, admin_token: str
    ) -> None:
        # A dedicated newest marker guarantees determinism even though the
        # shared test database accumulates rows across runs at the same
        # fixture instants.  Prior runs may have left markers at the same
        # timestamp; stamp this marker strictly after the newest existing
        # row so the deterministic tie-break (detection_id ASC) can never
        # push it out of the top-10 feed.
        newest = db_session.scalar(
            select(func.max(DetectionResultRow.detected_at))
        )
        marker_ts = (
            newest + timedelta(seconds=1) if newest is not None else _ts(10_000)
        )
        marker_event = uuid.uuid4()
        marker_rule = f"rule-recent-marker-{uuid.uuid4().hex[:8]}"
        _persist(
            db_session,
            _analysis(
                marker_event,
                results=(_result(marker_rule, event_id=marker_event, detected_at=marker_ts),),
            ),
        )

        response = client.get(
            "/api/detections/recent?limit=10", headers=auth_header(admin_token)
        )
        assert response.status_code == 200
        body = response.json()
        assert isinstance(body, list)
        assert len(body) >= 1
        # Prior runs may have left markers at the same instant; the
        # deterministic tie-break (detection_id ASC) keeps them all at the
        # newest position, so membership in the top-10 is the invariant.
        assert str(marker_event) in {item["event_id"] for item in body}
        assert all("detection_id" in item and "rule_id" in item for item in body)

    def test_recent_respects_bounded_limit(
        self, client: TestClient, admin_token: str
    ) -> None:
        limited = client.get(
            "/api/detections/recent?limit=2", headers=auth_header(admin_token)
        ).json()
        assert len(limited) == 2

        full = client.get(
            "/api/detections/recent?limit=200", headers=auth_header(admin_token)
        )
        assert full.status_code == 200
        assert len(full.json()) <= 200

    def test_recent_ordering_is_deterministic(
        self, client: TestClient, admin_token: str
    ) -> None:
        body = client.get(
            "/api/detections/recent?limit=200", headers=auth_header(admin_token)
        ).json()
        stamps = [item["detected_at"] for item in body]
        assert stamps == sorted(stamps, reverse=True)


# ---------------------------------------------------------------------------
# 7. Pagination validation (HTTP-level contract)
# ---------------------------------------------------------------------------


class TestPaginationValidation:
    def test_invalid_page_rejected(
        self, client: TestClient, admin_token: str
    ) -> None:
        event = uuid.uuid4()
        for page in ("0", "-1", "abc"):
            response = client.get(
                f"/api/detections/event/{event}?page={page}",
                headers=auth_header(admin_token),
            )
            assert response.status_code == 422, page

    def test_invalid_page_size_rejected(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            f"/api/detections/event/{uuid.uuid4()}?page_size=0",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 422

    def test_excessive_page_size_rejected(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            f"/api/detections/event/{uuid.uuid4()}?page_size=201",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 422

    def test_excessive_recent_limit_rejected(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            "/api/detections/recent?limit=201", headers=auth_header(admin_token)
        )
        assert response.status_code == 422

    def test_page_size_upper_bound_accepted(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            f"/api/detections/event/{uuid.uuid4()}?page_size=200",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# 8. Event-scoped analysis endpoint
# ---------------------------------------------------------------------------


class TestAnalysis:
    def test_analysis_retrieval_returns_full_record(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        response = client.get(
            f"/api/detection-analyses/{ds.event_a}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200
        body = response.json()
        # analysis identity is the event UUID (Step 9G contract)
        assert body["event_id"] == str(ds.event_a)
        assert body["result_count"] == 3
        assert body["failure_count"] == 2
        assert body["provenance"] == "detected"
        assert body["first_detected_at"] is not None
        assert body["last_detected_at"] is not None

    def test_analysis_contains_results_and_failures(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        body = client.get(
            f"/api/detection-analyses/{ds.event_a}",
            headers=auth_header(admin_token),
        ).json()
        assert [item["detection_id"] for item in body["results"]] == [
            str(ds.detection_r3),
            str(ds.detection_r2),
            str(ds.detection_r1),
        ]
        assert [item["rule_id"] for item in body["failures"]] == [
            ds.failure_yara_rule,
            ds.failure_sigma_rule,
        ]
        for item in body["failures"]:
            assert item["provenance"] == "detected"
            assert {"engine", "error_type", "error_message"} <= set(item)

    def test_missing_analysis_returns_404(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            f"/api/detection-analyses/{uuid.uuid4()}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 404
        assert response.json()["detail"] == "Detection analysis not found"

    def test_invalid_analysis_id_rejected(
        self, client: TestClient, admin_token: str
    ) -> None:
        response = client.get(
            "/api/detection-analyses/not-a-uuid",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 422


# ---------------------------------------------------------------------------
# 9. Detection analysis failures endpoint
# ---------------------------------------------------------------------------


class TestAnalysisFailures:
    def test_failure_endpoint_returns_persisted_failures(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        response = client.get(
            f"/api/detection-analyses/{ds.event_a}/failures",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 2
        assert body["page"] == 1
        assert body["page_size"] == 50
        assert [item["rule_id"] for item in body["items"]] == [
            ds.failure_yara_rule,
            ds.failure_sigma_rule,
        ]

    def test_failures_remain_failures_no_risk_assigned(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        body = client.get(
            f"/api/detection-analyses/{ds.event_a}/failures",
            headers=auth_header(admin_token),
        ).json()
        for item in body["items"]:
            serialized_keys = set(item)
            assert not {"risk", "severity", "confidence", "matched", "priority"} & serialized_keys

    def test_empty_failures_return_200_empty_list(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        # event_b has a result but no failures.
        response = client.get(
            f"/api/detection-analyses/{ds.event_b}/failures",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200
        assert response.json()["items"] == []
        assert response.json()["total"] == 0

        # Unknown events also return an empty failure page.
        unknown = client.get(
            f"/api/detection-analyses/{uuid.uuid4()}/failures",
            headers=auth_header(admin_token),
        )
        assert unknown.status_code == 200
        assert unknown.json()["items"] == []

    def test_failure_ordering_is_deterministic(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        body = client.get(
            f"/api/detection-analyses/{ds.event_a}/failures",
            headers=auth_header(admin_token),
        ).json()
        stamps = [item["failed_at"] for item in body["items"]]
        assert stamps == sorted(stamps, reverse=True)

    def test_failures_response_does_not_convert_to_detections(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        body = client.get(
            f"/api/detection-analyses/{ds.event_a}/failures",
            headers=auth_header(admin_token),
        ).json()
        assert all("detection_id" not in item for item in body["items"])


# ---------------------------------------------------------------------------
# 10. Response integrity (structured payloads, no secrets, no internals)
# ---------------------------------------------------------------------------


class TestResponseIntegrity:
    NO_SENSITIVE_FRAGMENTS = (
        "api_key",
        "bearer",
        "access_token",
        "password",
        "jwt",
        "sqlalchemy",
        "psycopg",
        "postgres",
        "traceback",
        "exception",
    )

    def test_evidence_remains_structured(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        body = client.get(
            f"/api/detections/{ds.detection_r1}",
            headers=auth_header(admin_token),
        ).json()
        assert body["evidence"] == {
            "matched_conditions": ["sel_web"],
            "matched_fields": {"Image": "powershell.exe"},
            "rule_references": {"attack": "T1059.001"},
            "detection_context": {"engine": "sigma"},
        }

    def test_metadata_remains_structured(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        body = client.get(
            f"/api/detections/{ds.detection_r1}",
            headers=auth_header(admin_token),
        ).json()
        assert body["result_metadata"]["rule_version"] == "1.0.0"
        assert body["result_metadata"]["execution_time_ms"] == 12.5
        assert body["result_metadata"]["total_rules_evaluated"] == 10
        assert body["result_metadata"]["extra"] == {"source": "api-test"}

    def test_provenance_severity_confidence_rule_event_intact(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        body = client.get(
            f"/api/detections/{ds.detection_r3}",
            headers=auth_header(admin_token),
        ).json()
        assert body["provenance"] == "detected"
        assert body["rule_type"] == "yara"
        assert body["severity"] == "critical"
        assert body["confidence"] == 0.99
        assert body["rule_id"] == ds.rule_yara
        assert body["event_id"] == str(ds.event_a)

    def test_response_exposes_no_database_internals(
        self, client: TestClient, ds: SimpleNamespace, admin_token: str
    ) -> None:
        response = client.get(
            f"/api/detections/{ds.detection_r1}",
            headers=auth_header(admin_token),
        )
        raw = response.text.lower()
        assert not any(fragment in raw for fragment in self.NO_SENSITIVE_FRAGMENTS)

    def test_response_exposes_no_authentication_secrets(
        self, client: TestClient, all_detection_urls: list[str], admin_token: str
    ) -> None:
        for url in all_detection_urls:
            response = client.get(url, headers=auth_header(admin_token))
            assert response.status_code in (200, 404)
            raw = response.text.lower()
            assert "authorization" not in raw, url
            assert "access_token" not in raw, url


# ---------------------------------------------------------------------------
# 11. Read-only contract and mutation checks
# ---------------------------------------------------------------------------


class TestReadOnlyContract:
    def test_api_does_not_mutate_persisted_records(
        self,
        client: TestClient,
        db_session: Session,
        ds: SimpleNamespace,
        admin_token: str,
    ) -> None:
        before_results = _count(db_session, DetectionResultRow)
        before_failures = _count(db_session, DetectionRuleFailureRow)

        urls = [
            f"/api/detections/{ds.detection_r1}",
            f"/api/detections/event/{ds.event_a}",
            f"/api/detections/rule/{ds.rule_sigma1}",
            "/api/detections/recent",
            f"/api/detection-analyses/{ds.event_a}",
            f"/api/detection-analyses/{ds.event_a}/failures",
        ]
        for url in urls:
            assert client.get(url, headers=auth_header(admin_token)).status_code == 200

        assert _count(db_session, DetectionResultRow) == before_results
        assert _count(db_session, DetectionRuleFailureRow) == before_failures

    def test_no_mutation_endpoints_exist(self, client: TestClient) -> None:
        spec = client.get("/openapi.json").json()
        for path in spec["paths"]:
            # The governed Detection-as-Code surface (V2.17) is the only
            # mutation-capable "detection" namespace; it is covered by its
            # own dedicated contract test below.
            if "detection" in path and not path.startswith(
                "/api/detection-as-code/"
            ) and path != "/api/detection-as-code":
                assert set(spec["paths"][path]) == {"get"}, path

    def test_governed_detection_as_code_surface(self, client: TestClient) -> None:
        """The V2.17 governed surface is exactly: reads GET-only, mutations POST-only."""
        spec = client.get("/openapi.json").json()
        dac_paths = {
            path: set(operations)
            for path, operations in spec["paths"].items()
            if path == "/api/detection-as-code"
            or path.startswith("/api/detection-as-code/")
        }
        assert dac_paths == {
            "/api/detection-as-code": {"get"},
            "/api/detection-as-code/{rule_id}": {"get"},
            "/api/detection-as-code/validate": {"post"},
            "/api/detection-as-code/release": {"post"},
            "/api/detection-as-code/deploy": {"post"},
            "/api/detection-as-code/rollback": {"post"},
            "/api/detection-as-code/enabled": {"post"},
        }

    def test_no_write_methods_accepted(
        self, client: TestClient, admin_token: str
    ) -> None:
        for method in ("post", "put", "patch", "delete"):
            response = getattr(client, method)(
                "/api/detections/recent", headers=auth_header(admin_token)
            )
            assert response.status_code == 405, method


# ---------------------------------------------------------------------------
# 12. Error sanitization
# ---------------------------------------------------------------------------


class TestErrorSanitization:
    def test_database_failure_becomes_safe_503(
        self, client: TestClient, admin_token: str, monkeypatch
    ) -> None:
        class _BrokenService:
            def get_result(self, db, detection_id):
                raise DetectionQueryError(reason="simulated database failure")

        monkeypatch.setattr(detections_routes, "_service", _BrokenService())
        response = client.get(
            f"/api/detections/{uuid.uuid4()}", headers=auth_header(admin_token)
        )
        assert response.status_code == 503
        assert response.json() == {"detail": "Detection data is unavailable"}

    def test_database_failure_leaks_no_internals(
        self, client: TestClient, admin_token: str, monkeypatch
    ) -> None:
        class _BrokenService:
            def list_recent_results(self, db, *, limit=50):
                raise DetectionQueryError(reason="simulated failure")

        monkeypatch.setattr(detections_routes, "_service", _BrokenService())
        response = client.get(
            "/api/detections/recent", headers=auth_header(admin_token)
        )
        raw = response.text.lower()
        for fragment in ("sqlalchemy", "psycopg", "traceback", "exception", "password"):
            assert fragment not in raw

    def test_service_validation_error_maps_to_422(
        self, client: TestClient, admin_token: str, monkeypatch
    ) -> None:
        class _RejectingService:
            def list_results_for_rule(self, db, rule_id, *, page=1, page_size=50):
                raise DetectionQueryValidationError(
                    reason="rule_id must not exceed 255 characters"
                )

        monkeypatch.setattr(detections_routes, "_service", _RejectingService())
        response = client.get(
            "/api/detections/rule/some-rule", headers=auth_header(admin_token)
        )
        assert response.status_code == 422
        assert "rule_id" in response.json()["detail"]


# ---------------------------------------------------------------------------
# 13. OpenAPI / router registration
# ---------------------------------------------------------------------------


class TestOpenApiRegistration:
    EXPECTED_PATHS = {
        "/api/detections/{detection_id}",
        "/api/detections/event/{event_id}",
        "/api/detections/rule/{rule_id}",
        "/api/detections/recent",
        "/api/detection-analyses/{event_id}",
        "/api/detection-analyses/{event_id}/failures",
        "/api/detection-rules",
        "/api/detection-rules/{rule_id}",
        "/api/detection-rules/analytics",
    }

    def test_router_registered_under_existing_api_prefix(
        self, client: TestClient
    ) -> None:
        spec = client.get("/openapi.json").json()
        detection_paths = {
            path
            for path in spec["paths"]
            if "detection" in path.lower()
            and not path.startswith("/api/correlations/")
            and path != "/api/detection-as-code"
            and not path.startswith("/api/detection-as-code/")
        }
        assert detection_paths == self.EXPECTED_PATHS

    def test_every_detection_operation_requires_bearer_auth(
        self, client: TestClient
    ) -> None:
        spec = client.get("/openapi.json").json()
        for path in self.EXPECTED_PATHS:
            operation = spec["paths"][path]["get"]
            assert operation["security"] == [{"HTTPBearer": []}], path
            assert operation["tags"] == ["Detections"], path

    def test_detection_paths_expose_no_other_methods(
        self, client: TestClient
    ) -> None:
        spec = client.get("/openapi.json").json()
        for path in self.EXPECTED_PATHS:
            assert set(spec["paths"][path]) == {"get"}, path