"""Risk query layer behavior tests (Step 11D).

Verifies the read-only retrieval layer
(:class:`~app.services.risk_query.RiskQueryService` and the
:class:`~app.repositories.risk.RiskRepository` read methods) over rows
produced by the Step 11C pipeline.

The query layer is read-only: these tests additionally assert that reads
never commit, flush, or stage writes, never mutate persisted data, never
emit INSERT/UPDATE/DELETE statements, and that database failures surface as
sanitized :class:`RiskQueryError` values with no raw driver/SQL text.

Same harness as Steps 10C/10D and 11C: in-memory SQLite with the PostgreSQL
``JSONB`` column rendered as ``JSON`` via a test-only type-compiler visitor,
plus ``PRAGMA foreign_keys=ON`` so FK enforcement matches PostgreSQL (each
risk assessment's parent correlation is persisted first, per the real
pipeline ordering).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine, event, func, select, text
from sqlalchemy.dialects.sqlite.base import SQLiteTypeCompiler
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

# Make the PostgreSQL ``JSONB`` columns work on SQLite for these tests.
if not hasattr(SQLiteTypeCompiler, "visit_JSONB"):
    SQLiteTypeCompiler.visit_JSONB = lambda self, type_, **kw: "JSON"  # noqa: E731

from app.database.postgres.base import Base
from app.models.risk_assessment import RiskAssessment as RiskAssessmentRow
from app.repositories.risk import RiskRepository
from app.schemas.correlation import (
    CorrelationMember as CorrelationMemberSchema,
)
from app.schemas.correlation import CorrelationResult
from app.schemas.correlation import CorrelationStatus
from app.schemas.risk import (
    RiskAssessment,
    RiskEvidence,
    RiskFactor,
    RiskLevel,
)
from app.schemas.security_event import Provenance
from app.services.correlation_persistence import CorrelationPersistenceService
from app.services.risk_persistence import RiskPersistenceService
from app.services.risk_query import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    MAX_RECENT_LIMIT,
    RiskQueryError,
    RiskQueryService,
    RiskQueryValidationError,
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


def _materialize(row):
    """Assign flush-time defaults so unflushed (mocked) rows are readable."""
    if row.id is None:
        row.id = uuid.uuid4()
    if row.created_at is None:
        row.created_at = _ts(0)
    if row.updated_at is None:
        row.updated_at = _ts(0)
    return row


@pytest.fixture()
def db_session():
    """Fresh in-memory SQLite database with the full model schema + FK checks."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = Session(engine)
    session.execute(text("PRAGMA foreign_keys=ON"))
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture()
def db_session_no_autoflush():
    """Read-only-behavior fixture: autoflush off so pending writes stay pending."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = Session(engine, autoflush=False)
    session.execute(text("PRAGMA foreign_keys=ON"))
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _seed_correlation(
    db: Session,
    *,
    correlation_id: uuid.UUID | None = None,
) -> CorrelationResult:
    """Persist a parent correlation through the real Step 10C service."""
    cid = correlation_id or uuid.uuid4()
    correlation = CorrelationResult(
        correlation_id=cid,
        members=[
            CorrelationMemberSchema(
                detection_id=uuid.uuid4(),
                event_id=uuid.uuid4(),
                timestamp=_ts(0),
            )
        ],
        status=CorrelationStatus.CANDIDATE,
        confidence=0.8,
        evidence={},
        metadata={},
        timestamp=_ts(0),
    )
    # Members are not materialized: the FK only requires the parent row.
    CorrelationPersistenceService(clock=lambda: _ts(0)).persist_correlation(
        db, correlation
    )
    return correlation


def _evidence(
    *,
    observation_type: str = "detection_severity",
    detection_id: uuid.UUID | None = None,
    event_id: uuid.UUID | None = None,
    metadata: dict | None = None,
) -> RiskEvidence:
    return RiskEvidence(
        observation_type=observation_type,
        detection_id=detection_id or uuid.uuid4(),
        event_id=event_id or uuid.uuid4(),
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
    *,
    correlation_id: uuid.UUID | None = None,
    risk_assessment_id: uuid.UUID | None = None,
    score: float = 0.625,
    level: RiskLevel | None = None,
    confidence: float = 0.8,
    factors: list[RiskFactor] | None = None,
    evidence: list[RiskEvidence] | None = None,
    metadata: dict | None = None,
    hours: float = 0.0,
) -> RiskAssessment:
    """Build a :class:`RiskAssessment` schema object (Step 11B shape)."""
    return RiskAssessment(
        risk_assessment_id=risk_assessment_id or uuid.uuid4(),
        correlation_id=correlation_id or uuid.uuid4(),
        score=score,
        level=level or RiskLevel.HIGH,
        confidence=confidence,
        factors=factors or [],
        evidence=evidence or [],
        metadata=metadata or {},
        timestamp=_ts(hours),
    )


def _persist(db: Session, assessment: RiskAssessment):
    """Persist *assessment* through the real Step 11C service."""
    return RiskPersistenceService(clock=lambda: _ts(1)).persist_assessment(
        db, assessment
    )


def _all_assessments(db: Session) -> list[RiskAssessmentRow]:
    return list(db.scalars(select(RiskAssessmentRow)))


def _count(db: Session, model) -> int:
    return db.scalar(select(func.count(model.id)))


# ---------------------------------------------------------------------------
# 1. Get by ID
# ---------------------------------------------------------------------------


def test_get_by_id_round_trip(db_session):
    """A persisted assessment is readable as a complete full record."""
    correlation = _seed_correlation(db_session)
    assessment = _assessment(
        correlation_id=correlation.correlation_id,
        score=0.625,
        level=RiskLevel.HIGH,
        confidence=0.8,
        factors=[_factor(contribution=0.5)],
        evidence=[_evidence(observation_type="correlation_confidence")],
        metadata={"engine": "DeterministicRiskScoringEngine"},
    )
    _persist(db_session, assessment)

    record = RiskQueryService().get_assessment(
        db_session, assessment.risk_assessment_id
    )

    assert record is not None
    assert record.risk_assessment_id == assessment.risk_assessment_id
    assert record.correlation_id == correlation.correlation_id
    assert record.score == 0.625
    assert record.level == RiskLevel.HIGH
    assert record.confidence == 0.8
    assert record.provenance == Provenance.RISK_ASSESSED
    assert _as_utc(record.timestamp) == assessment.timestamp
    assert isinstance(record.id, uuid.UUID)
    assert isinstance(record.created_at, datetime)
    assert isinstance(record.updated_at, datetime)


def test_get_by_id_missing_returns_none(db_session):
    correlation = _seed_correlation(db_session)
    assessment = _assessment(correlation_id=correlation.correlation_id)
    _persist(db_session, assessment)

    assert (
        RiskQueryService().get_assessment(db_session, uuid.uuid4()) is None
    )


def test_get_by_id_accepts_string_uuid(db_session):
    correlation = _seed_correlation(db_session)
    assessment = _assessment(correlation_id=correlation.correlation_id)
    _persist(db_session, assessment)

    record = RiskQueryService().get_assessment(
        db_session, str(assessment.risk_assessment_id)
    )

    assert record is not None
    assert record.risk_assessment_id == assessment.risk_assessment_id


def test_get_by_id_rejects_invalid_uuid_before_database(db_session):
    repo = MagicMock(spec=RiskRepository)
    service = RiskQueryService(repository_factory=lambda _db: repo)

    with pytest.raises(RiskQueryValidationError):
        service.get_assessment(db_session, "not-a-uuid")

    repo.get_by_risk_assessment_id.assert_not_called()


def test_get_by_id_fields_complete(db_session):
    """Every persisted column surfaces with the correct value."""
    correlation = _seed_correlation(db_session)
    ts = _ts(7)
    factors = [
        _factor(factor_type="detection_volume", contribution=0.4),
        _factor(factor_type="severity_impact", contribution=0.6),
    ]
    evidence = [_evidence(observation_type="member_count")]
    assessment = _assessment(
        correlation_id=correlation.correlation_id,
        score=0.9,
        level=RiskLevel.CRITICAL,
        confidence=0.1,
        factors=factors,
        evidence=evidence,
        metadata={"policy": "10B", "weights": {"volume": 0.4}},
        hours=7,
    )
    _persist(db_session, assessment)

    record = RiskQueryService().get_assessment(
        db_session, assessment.risk_assessment_id
    )

    assert record.score == 0.9
    assert record.level == RiskLevel.CRITICAL
    assert record.confidence == 0.1
    assert record.assessment_metadata == {"policy": "10B", "weights": {"volume": 0.4}}
    assert record.factors == [f.model_dump(mode="json") for f in factors]
    assert record.evidence == [e.model_dump(mode="json") for e in evidence]
    assert _as_utc(record.timestamp) == ts
    assert record.provenance == Provenance.RISK_ASSESSED


def test_get_by_id_structured_json_fidelity(db_session):
    """Nested structured factors/evidence/metadata survive the read exactly."""
    correlation = _seed_correlation(db_session)
    assessment = _assessment(
        correlation_id=correlation.correlation_id,
        factors=[
            _factor(
                factor_type="correlation_extent",
                contribution=0.3,
                evidence=[
                    _evidence(
                        observation_type="same_source",
                        metadata={"source": "endpoint", "count": 4},
                    )
                ],
                metadata={"thresholds": {"high": 0.7, "low": 0.3}},
            )
        ],
        evidence=[
            _evidence(
                observation_type="detection_severity",
                metadata={"severity": "high"},
            )
        ],
        metadata={"nested": {"policy": {"name": "10B", "version": 1}}},
    )
    _persist(db_session, assessment)

    record = RiskQueryService().get_assessment(
        db_session, assessment.risk_assessment_id
    )

    assert record.factors[0]["metadata"]["thresholds"] == {"high": 0.7, "low": 0.3}
    assert record.factors[0]["evidence"][0]["metadata"] == {
        "source": "endpoint",
        "count": 4,
    }
    assert record.assessment_metadata == {"nested": {"policy": {"name": "10B", "version": 1}}}


# ---------------------------------------------------------------------------
# 2. Get by correlation
# ---------------------------------------------------------------------------


def test_correlation_one_assessment(db_session):
    correlation = _seed_correlation(db_session)
    assessment = _assessment(correlation_id=correlation.correlation_id)
    _persist(db_session, assessment)

    page = RiskQueryService().list_assessments_for_correlation(
        db_session, correlation.correlation_id
    )

    assert page.total == 1
    assert [r.risk_assessment_id for r in page.items] == [
        assessment.risk_assessment_id
    ]


def test_correlation_multiple_historical_assessments(db_session):
    """A correlation legitimately carries several assessments (11C-A)."""
    correlation = _seed_correlation(db_session)
    ids = [uuid.uuid4(), uuid.uuid4(), uuid.uuid4()]
    for i, aid in enumerate(ids):
        _persist(
            db_session,
            _assessment(
                correlation_id=correlation.correlation_id,
                risk_assessment_id=aid,
                hours=float(i),
            ),
        )

    page = RiskQueryService().list_assessments_for_correlation(
        db_session, correlation.correlation_id, page=1, page_size=10
    )

    assert page.total == 3
    # Deterministic ordering: timestamp DESC -> risk_assessment_id ASC.
    assert [r.risk_assessment_id for r in page.items] == [ids[2], ids[1], ids[0]]


def test_correlation_no_assessments(db_session):
    correlation = _seed_correlation(db_session)
    page = RiskQueryService().list_assessments_for_correlation(
        db_session, correlation.correlation_id
    )
    assert page.total == 0
    assert page.items == []


def test_correlation_assessments_scoped_to_correlation(db_session):
    """Only the requested correlation's assessments are returned."""
    c_a = _seed_correlation(db_session).correlation_id
    c_b = _seed_correlation(db_session).correlation_id
    aid_a = uuid.uuid4()
    aid_b = uuid.uuid4()
    _persist(
        db_session, _assessment(correlation_id=c_a, risk_assessment_id=aid_a)
    )
    _persist(
        db_session, _assessment(correlation_id=c_b, risk_assessment_id=aid_b)
    )

    service = RiskQueryService()
    assert [
        r.risk_assessment_id
        for r in service.list_assessments_for_correlation(db_session, c_a).items
    ] == [aid_a]
    assert [
        r.risk_assessment_id
        for r in service.list_assessments_for_correlation(db_session, c_b).items
    ] == [aid_b]
    assert service.list_assessments_for_correlation(
        db_session, uuid.uuid4()
    ).items == []


def test_correlation_deterministic_tie_break(db_session):
    """Equal timestamps fall back to risk_assessment_id ascending."""
    correlation = _seed_correlation(db_session)
    id_a = uuid.UUID("deadbeef-dead-beef-dead-000000000001")
    id_b = uuid.UUID("deadbeef-dead-beef-dead-000000000002")
    id_c = uuid.UUID("deadbeef-dead-beef-dead-000000000003")
    # Insert in reverse so ordering is proven, not incidental.
    for aid in (id_c, id_a, id_b):
        _persist(
            db_session,
            _assessment(
                correlation_id=correlation.correlation_id,
                risk_assessment_id=aid,
                hours=0,
            ),
        )

    page = RiskQueryService().list_assessments_for_correlation(
        db_session, correlation.correlation_id, page=1, page_size=10
    )

    assert [r.risk_assessment_id for r in page.items] == [id_a, id_b, id_c]


def test_correlation_complete_fidelity(db_session):
    """Correlation-scoped reads preserve every structured field."""
    correlation = _seed_correlation(db_session)
    factors = [_factor(factor_type="detection_volume", contribution=0.5)]
    evidence = [_evidence(observation_type="member_count")]
    assessment = _assessment(
        correlation_id=correlation.correlation_id,
        score=0.42,
        level=RiskLevel.MEDIUM,
        confidence=0.77,
        factors=factors,
        evidence=evidence,
        metadata={"policy": "10B"},
    )
    _persist(db_session, assessment)

    page = RiskQueryService().list_assessments_for_correlation(
        db_session, correlation.correlation_id
    )
    record = page.items[0]

    assert record.score == 0.42
    assert record.level == RiskLevel.MEDIUM
    assert record.confidence == 0.77
    assert record.factors == [f.model_dump(mode="json") for f in factors]
    assert record.evidence == [e.model_dump(mode="json") for e in evidence]
    assert record.assessment_metadata == {"policy": "10B"}
    assert record.provenance == Provenance.RISK_ASSESSED


# ---------------------------------------------------------------------------
# 3. Recent assessments
# ---------------------------------------------------------------------------


def test_recent_ordered_newest_first(db_session):
    correlation = _seed_correlation(db_session)
    ids = [uuid.uuid4(), uuid.uuid4(), uuid.uuid4()]
    for hours, aid in zip((1, 3, 2), ids):
        _persist(
            db_session,
            _assessment(
                correlation_id=correlation.correlation_id,
                risk_assessment_id=aid,
                hours=hours,
            ),
        )

    feed = RiskQueryService().list_recent_assessments(db_session, limit=2)

    assert [r.risk_assessment_id for r in feed] == [ids[1], ids[2]]


def test_recent_deterministic_tie_break(db_session):
    """Equal timestamps produce a stable risk_assessment_id-ascending feed."""
    correlation = _seed_correlation(db_session)
    id_a = uuid.UUID("deadbeef-dead-beef-dead-00000000000a")
    id_b = uuid.UUID("deadbeef-dead-beef-dead-00000000000b")
    id_c = uuid.UUID("deadbeef-dead-beef-dead-00000000000c")
    for aid in (id_c, id_a, id_b):
        _persist(
            db_session,
            _assessment(
                correlation_id=correlation.correlation_id,
                risk_assessment_id=aid,
                hours=0,
            ),
        )

    feed = RiskQueryService().list_recent_assessments(db_session, limit=10)

    assert [r.risk_assessment_id for r in feed] == [id_a, id_b, id_c]


def test_recent_empty(db_session):
    assert RiskQueryService().list_recent_assessments(db_session, limit=10) == []


def test_recent_one_result(db_session):
    correlation = _seed_correlation(db_session)
    assessment = _assessment(correlation_id=correlation.correlation_id)
    _persist(db_session, assessment)

    feed = RiskQueryService().list_recent_assessments(db_session, limit=10)

    assert len(feed) == 1
    assert feed[0].risk_assessment_id == assessment.risk_assessment_id


def test_recent_default_limit_applied(db_session):
    """Recent-feed default limit is applied when none is supplied."""
    correlation = _seed_correlation(db_session)
    ids = [uuid.uuid4() for _ in range(DEFAULT_PAGE_SIZE + 10)]
    for hours, aid in enumerate(ids):
        _persist(
            db_session,
            _assessment(
                correlation_id=correlation.correlation_id,
                risk_assessment_id=aid,
                hours=float(hours),
            ),
        )

    feed = RiskQueryService().list_recent_assessments(db_session)

    assert len(feed) == DEFAULT_PAGE_SIZE
    assert feed[0].risk_assessment_id == ids[-1]


def test_recent_limit_boundary_and_maximum(db_session):
    """Exact-limit and maximum-limit reads work; both are bounded."""
    correlation = _seed_correlation(db_session)
    ids = [uuid.uuid4() for _ in range(5)]
    for hours, aid in enumerate(ids):
        _persist(
            db_session,
            _assessment(
                correlation_id=correlation.correlation_id,
                risk_assessment_id=aid,
                hours=float(hours),
            ),
        )

    service = RiskQueryService()
    assert len(service.list_recent_assessments(db_session, limit=5)) == 5
    assert len(service.list_recent_assessments(db_session, limit=1)) == 1
    assert (
        len(service.list_recent_assessments(db_session, limit=MAX_RECENT_LIMIT)) == 5
    )


# ---------------------------------------------------------------------------
# 4. Pagination
# ---------------------------------------------------------------------------


def test_pagination_first_middle_last_page(db_session):
    correlation = _seed_correlation(db_session)
    ids = [uuid.uuid4() for _ in range(7)]
    for hours, aid in enumerate(ids):
        _persist(
            db_session,
            _assessment(
                correlation_id=correlation.correlation_id,
                risk_assessment_id=aid,
                hours=float(hours),
            ),
        )

    service = RiskQueryService()
    p1 = service.list_assessments_for_correlation(
        db_session, correlation.correlation_id, page=1, page_size=2
    )
    p2 = service.list_assessments_for_correlation(
        db_session, correlation.correlation_id, page=2, page_size=2
    )
    p3 = service.list_assessments_for_correlation(
        db_session, correlation.correlation_id, page=3, page_size=2
    )
    p4 = service.list_assessments_for_correlation(
        db_session, correlation.correlation_id, page=4, page_size=2
    )

    assert p1.total == 7
    assert len(p1.items) == 2 and len(p2.items) == 2 and len(p3.items) == 2
    assert len(p4.items) == 1
    combined = [r.risk_assessment_id for r in p1.items + p2.items + p3.items + p4.items]
    assert combined == [ids[6], ids[5], ids[4], ids[3], ids[2], ids[1], ids[0]]
    assert p4.page == 4 and p4.page_size == 2


def test_pagination_page_beyond_available_records(db_session):
    correlation = _seed_correlation(db_session)
    _persist(db_session, _assessment(correlation_id=correlation.correlation_id))

    page = RiskQueryService().list_assessments_for_correlation(
        db_session, correlation.correlation_id, page=99, page_size=10
    )

    assert page.items == []
    assert page.total == 1


def test_pagination_total_unaffected_by_page(db_session):
    correlation = _seed_correlation(db_session)
    ids = [uuid.uuid4() for _ in range(5)]
    for hours, aid in enumerate(ids):
        _persist(
            db_session,
            _assessment(
                correlation_id=correlation.correlation_id,
                risk_assessment_id=aid,
                hours=float(hours),
            ),
        )

    service = RiskQueryService()
    for page in (1, 2, 3):
        result = service.list_assessments_for_correlation(
            db_session, correlation.correlation_id, page=page, page_size=2
        )
        assert result.total == 5


def test_pagination_min_and_max_page_size(db_session):
    correlation = _seed_correlation(db_session)
    for aid in (uuid.uuid4(), uuid.uuid4()):
        _persist(
            db_session,
            _assessment(
                correlation_id=correlation.correlation_id,
                risk_assessment_id=aid,
            ),
        )

    service = RiskQueryService()
    one = service.list_assessments_for_correlation(
        db_session, correlation.correlation_id, page=1, page_size=1
    )
    assert len(one.items) == 1
    cap = service.list_assessments_for_correlation(
        db_session, correlation.correlation_id, page=1, page_size=MAX_PAGE_SIZE
    )
    assert len(cap.items) == 2


def test_pagination_max_size_or_oversize_rejected(db_session):
    service = RiskQueryService()
    with pytest.raises(RiskQueryValidationError):
        service.list_assessments_for_correlation(
            db_session, uuid.uuid4(), page_size=MAX_PAGE_SIZE + 1
        )
    with pytest.raises(RiskQueryValidationError):
        service.list_recent_assessments(db_session, limit=MAX_PAGE_SIZE * 5)


def test_pagination_invalid_page_rejected(db_session):
    service = RiskQueryService()
    with pytest.raises(RiskQueryValidationError):
        service.list_assessments_for_correlation(db_session, uuid.uuid4(), page=0)
    with pytest.raises(RiskQueryValidationError):
        service.list_assessments_for_correlation(db_session, uuid.uuid4(), page=-1)
    with pytest.raises(RiskQueryValidationError):
        service.list_assessments_for_correlation(db_session, uuid.uuid4(), page="x")


def test_pagination_invalid_page_size_rejected(db_session):
    service = RiskQueryService()
    with pytest.raises(RiskQueryValidationError):
        service.list_assessments_for_correlation(
            db_session, uuid.uuid4(), page_size=0
        )
    with pytest.raises(RiskQueryValidationError):
        service.list_assessments_for_correlation(
            db_session, uuid.uuid4(), page_size=-5
        )
    with pytest.raises(RiskQueryValidationError):
        service.list_assessments_for_correlation(
            db_session, uuid.uuid4(), page_size="x"
        )


def test_pagination_invalid_recent_limit_rejected(db_session):
    service = RiskQueryService()
    with pytest.raises(RiskQueryValidationError):
        service.list_recent_assessments(db_session, limit=0)
    with pytest.raises(RiskQueryValidationError):
        service.list_recent_assessments(db_session, limit="x")


def test_pagination_invalid_correlation_uuid_rejected_before_db(db_session):
    repo = MagicMock(spec=RiskRepository)
    service = RiskQueryService(repository_factory=lambda _db: repo)

    with pytest.raises(RiskQueryValidationError):
        service.list_assessments_for_correlation(db_session, "not-a-uuid")

    repo.count_assessments_for_correlation.assert_not_called()


def test_pagination_stable_ordering_across_pages(db_session):
    """Every page re-uses the same total ordering; no drift between pages.

    Letter-bearing hex keeps these deterministic ids out of SQLite's NUMERIC
    affinity while remaining strictly sortable by risk_assessment_id.
    """
    correlation = _seed_correlation(db_session)
    aids = [
        uuid.UUID(f"deadbeef-dead-beef-dead-{i:012x}") for i in range(1, 6)
    ]
    for aid in aids:
        _persist(
            db_session,
            _assessment(
                correlation_id=correlation.correlation_id,
                risk_assessment_id=aid,
                hours=0,
            ),
        )

    service = RiskQueryService()
    pages = [
        service.list_assessments_for_correlation(
            db_session, correlation.correlation_id, page=p, page_size=2
        ).items
        for p in (1, 2, 3)
    ]

    order = [r.risk_assessment_id for r in pages[0] + pages[1] + pages[2]]
    assert order == sorted(aids)  # tie-break: risk_assessment_id ascending


# ---------------------------------------------------------------------------
# 5. Data fidelity
# ---------------------------------------------------------------------------


def test_round_trip_real_persistence_service(db_session):
    """An assessment persisted through 11C reads back through 11D identically."""
    correlation = _seed_correlation(db_session)
    factors = [
        _factor(
            factor_type="detection_volume",
            contribution=0.5,
            evidence=[_evidence(observation_type="detection_severity")],
        ),
        _factor(factor_type="severity_impact", contribution=0.3),
    ]
    evidence = [
        _evidence(observation_type="correlation_confidence", metadata={"src": "10A"}),
        _evidence(observation_type="member_count"),
    ]
    assessment = _assessment(
        correlation_id=correlation.correlation_id,
        score=0.625,
        level=RiskLevel.HIGH,
        confidence=0.8,
        factors=factors,
        evidence=evidence,
        metadata={"engine": "DeterministicRiskScoringEngine", "policy": "10B"},
    )
    _persist(db_session, assessment)

    record = RiskQueryService().get_assessment(
        db_session, assessment.risk_assessment_id
    )

    assert record is not None
    assert record.risk_assessment_id == assessment.risk_assessment_id
    assert record.correlation_id == correlation.correlation_id
    assert record.score == 0.625
    assert record.level == RiskLevel.HIGH
    assert record.confidence == 0.8
    assert record.factors == [f.model_dump(mode="json") for f in factors]
    assert record.evidence == [e.model_dump(mode="json") for e in evidence]
    assert record.assessment_metadata == {
        "engine": "DeterministicRiskScoringEngine",
        "policy": "10B",
    }
    assert _as_utc(record.timestamp) == assessment.timestamp
    assert record.provenance == Provenance.RISK_ASSESSED


def test_score_boundaries_round_trip(db_session):
    correlation = _seed_correlation(db_session)
    for score in (0.0, 0.5, 1.0):
        assessment = _assessment(
            correlation_id=correlation.correlation_id, score=score
        )
        _persist(db_session, assessment)
        record = RiskQueryService().get_assessment(
            db_session, assessment.risk_assessment_id
        )
        assert record.score == score


def test_confidence_boundaries_round_trip(db_session):
    correlation = _seed_correlation(db_session)
    for confidence in (0.0, 0.5, 1.0):
        assessment = _assessment(
            correlation_id=correlation.correlation_id, confidence=confidence
        )
        _persist(db_session, assessment)
        record = RiskQueryService().get_assessment(
            db_session, assessment.risk_assessment_id
        )
        assert record.confidence == confidence


def test_all_levels_round_trip(db_session):
    correlation = _seed_correlation(db_session)
    for level in (RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL):
        assessment = _assessment(
            correlation_id=correlation.correlation_id, level=level
        )
        _persist(db_session, assessment)
        record = RiskQueryService().get_assessment(
            db_session, assessment.risk_assessment_id
        )
        assert record.level == level


def test_empty_structures_round_trip(db_session):
    correlation = _seed_correlation(db_session)
    assessment = _assessment(correlation_id=correlation.correlation_id)
    _persist(db_session, assessment)

    record = RiskQueryService().get_assessment(
        db_session, assessment.risk_assessment_id
    )

    assert record.factors == []
    assert record.evidence == []
    assert record.assessment_metadata == {}


# ---------------------------------------------------------------------------
# 6. Security
# ---------------------------------------------------------------------------


def test_surfaces_redacted_at_write_metadata(db_session):
    """The query path returns the stored (redacted) form, never a raw secret.

    Round-trip through the real service: Step 11C redacts credential keys
    before write; the query layer must surface the redacted value — no
    weaker read path.
    """
    correlation = _seed_correlation(db_session)
    assessment = RiskAssessment.model_construct(
        risk_assessment_id=uuid.uuid4(),
        correlation_id=correlation.correlation_id,
        score=0.5,
        level=RiskLevel.HIGH,
        confidence=0.5,
        factors=[],
        evidence=[],
        metadata={"apiKey": "sk-abc123", "safe_field": "value"},
        timestamp=_ts(0),
        provenance=Provenance.RISK_ASSESSED,
    )
    _persist(db_session, assessment)

    record = RiskQueryService().get_assessment(
        db_session, assessment.risk_assessment_id
    )

    assert record.assessment_metadata["apiKey"] == "<redacted>"
    assert record.assessment_metadata["safe_field"] == "value"


def test_authorization_and_password_redacted_through_query_path(db_session):
    """Authorization/password-shaped factor metadata surfaces redacted."""
    correlation = _seed_correlation(db_session)
    assessment = RiskAssessment.model_construct(
        risk_assessment_id=uuid.uuid4(),
        correlation_id=correlation.correlation_id,
        score=0.5,
        level=RiskLevel.HIGH,
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
        evidence=[],
        metadata={},
        timestamp=_ts(0),
        provenance=Provenance.RISK_ASSESSED,
    )
    _persist(db_session, assessment)

    record = RiskQueryService().get_assessment(
        db_session, assessment.risk_assessment_id
    )

    assert record.factors[0]["metadata"]["Authorization"] == "<redacted>"
    assert record.factors[0]["metadata"]["password"] == "<redacted>"
    assert record.factors[0]["metadata"]["safe"] == 1


def test_evidence_metadata_redacted_through_query_path(db_session):
    """Nested credential values inside evidence metadata surface redacted."""
    correlation = _seed_correlation(db_session)
    assessment = RiskAssessment.model_construct(
        risk_assessment_id=uuid.uuid4(),
        correlation_id=correlation.correlation_id,
        score=0.5,
        level=RiskLevel.HIGH,
        confidence=0.5,
        factors=[
            RiskFactor.model_construct(
                factor_type="detection_volume",
                contribution=0.5,
                evidence=[
                    RiskEvidence.model_construct(
                        observation_type="raw_signal",
                        detection_id=uuid.uuid4(),
                        event_id=uuid.uuid4(),
                        metadata={"token": "tok_xyz", "ok": 1},
                    )
                ],
                metadata={},
            )
        ],
        evidence=[],
        metadata={},
        timestamp=_ts(0),
        provenance=Provenance.RISK_ASSESSED,
    )
    _persist(db_session, assessment)

    record = RiskQueryService().get_assessment(
        db_session, assessment.risk_assessment_id
    )

    assert record.factors[0]["evidence"][0]["metadata"]["token"] == "<redacted>"
    assert record.factors[0]["evidence"][0]["metadata"]["ok"] == 1


def test_query_error_contains_no_secrets_or_raw_sql(db_session):
    """A database failure surfaces sanitized: no raw SQL, no payloads."""
    repo = MagicMock(spec=RiskRepository)
    repo.get_by_risk_assessment_id.side_effect = OperationalError(
        "SELECT * FROM risk_assessments WHERE risk_assessment_id=:id",
        {},
        Exception("connection to server lost"),
    )
    service = RiskQueryService(repository_factory=lambda _db: repo)

    with pytest.raises(RiskQueryError) as exc_info:
        service.get_assessment(db_session, uuid.uuid4())

    message = str(exc_info.value)
    assert "Traceback" not in message
    assert "connection to server lost" not in message
    assert "SELECT" not in message
    assert "risk_assessments" not in message
    assert "failed to load risk assessment" in message
    assert exc_info.value.__cause__ is not None


def test_list_error_sanitized(db_session):
    correlation_id = uuid.uuid4()
    repo = MagicMock(spec=RiskRepository)
    repo.count_assessments_for_correlation.side_effect = OperationalError(
        "SELECT 1", {}, Exception("boom")
    )
    service = RiskQueryService(repository_factory=lambda _db: repo)

    with pytest.raises(RiskQueryError) as exc_info:
        service.list_assessments_for_correlation(db_session, correlation_id)

    message = str(exc_info.value)
    assert "boom" not in message
    assert "SELECT" not in message


# ---------------------------------------------------------------------------
# 7. Read-only contract
# ---------------------------------------------------------------------------


def test_query_service_never_writes_on_any_operation():
    """Every read goes through repository reads; the session is never touched."""
    correlation_id = uuid.uuid4()
    row = _materialize(
        RiskAssessmentRow(
            risk_assessment_id=uuid.uuid4(),
            correlation_id=correlation_id,
            score=0.625,
            level=RiskLevel.HIGH,
            confidence=0.8,
            factors=[],
            evidence=[],
            assessment_metadata={},
            timestamp=_ts(0),
            provenance="risk_assessed",
        )
    )

    repo = MagicMock(spec=RiskRepository)
    repo.get_by_risk_assessment_id.return_value = row
    repo.list_assessments_for_correlation.return_value = [row]
    repo.list_recent_assessments.return_value = [row]
    repo.count_assessments.return_value = 1
    repo.count_assessments_for_correlation.return_value = 1

    db = MagicMock(spec=Session)
    service = RiskQueryService(repository_factory=lambda _db: repo)

    service.get_assessment(db, uuid.uuid4())
    service.list_assessments_for_correlation(db, correlation_id)
    service.list_recent_assessments(db)
    service.count_assessments(db)
    service.count_assessments_for_correlation(db, correlation_id)

    db.commit.assert_not_called()
    db.flush.assert_not_called()
    db.add.assert_not_called()
    db.delete.assert_not_called()
    db.rollback.assert_not_called()
    repo.add.assert_not_called()


def test_query_service_reads_do_not_flush_pending_writes(db_session_no_autoflush):
    """Reads leave concurrently-staged (uncommitted) writes untouched."""
    correlation = _seed_correlation(db_session_no_autoflush)
    assessment = _assessment(correlation_id=correlation.correlation_id)
    _persist(db_session_no_autoflush, assessment)

    pending = _assessment(
        correlation_id=correlation.correlation_id, hours=9
    )
    db_session_no_autoflush.add(
        RiskAssessmentRow(
            risk_assessment_id=pending.risk_assessment_id,
            correlation_id=pending.correlation_id,
            score=pending.score,
            level=pending.level,
            confidence=pending.confidence,
            factors=[],
            evidence=[],
            assessment_metadata={},
            timestamp=pending.timestamp,
            provenance="risk_assessed",
        )
    )

    service = RiskQueryService()
    service.list_recent_assessments(db_session_no_autoflush)
    service.get_assessment(db_session_no_autoflush, assessment.risk_assessment_id)

    assert len(list(db_session_no_autoflush.new)) == 1  # still staged
    assert _count(db_session_no_autoflush, RiskAssessmentRow) == 1


def test_returned_records_are_independent_of_rows(db_session):
    """Mutating a returned record never mutates the stored row."""
    correlation = _seed_correlation(db_session)
    assessment = _assessment(
        correlation_id=correlation.correlation_id,
        factors=[_factor(contribution=0.5)],
        metadata={"safe": "value"},
    )
    _persist(db_session, assessment)

    record = RiskQueryService().get_assessment(
        db_session, assessment.risk_assessment_id
    )
    record.assessment_metadata["safe"] = "mutated"
    record.assessment_metadata["new"] = "tampered"
    record.factors[0]["metadata"]["extra"] = "injected"
    record.score = 0.0

    fresh = RiskQueryService().get_assessment(
        db_session, assessment.risk_assessment_id
    )
    assert fresh.assessment_metadata == {"safe": "value"}
    assert "new" not in fresh.assessment_metadata
    assert "extra" not in fresh.factors[0]["metadata"]
    assert fresh.score == 0.625
    assert fresh.factors == [f.model_dump(mode="json") for f in assessment.factors]


def test_reads_do_not_alter_persisted_values(db_session):
    """Querying never changes row count, values, timestamps, IDs, or metadata."""
    correlation = _seed_correlation(db_session)
    assessments = [
        _assessment(correlation_id=correlation.correlation_id, hours=float(i))
        for i in range(3)
    ]
    for assessment in assessments:
        _persist(db_session, assessment)

    before = _all_assessments(db_session)
    snapshot = {
        r.risk_assessment_id: (
            r.correlation_id,
            r.score,
            r.level,
            r.confidence,
            dict(r.factors or {}),
            dict(r.evidence or {}),
            dict(r.assessment_metadata or {}),
            _as_utc(r.timestamp),
            r.provenance,
        )
        for r in before
    }

    service = RiskQueryService()
    service.list_recent_assessments(db_session, limit=10)
    service.list_assessments_for_correlation(
        db_session, correlation.correlation_id, page=1, page_size=2
    )
    for assessment in assessments:
        service.get_assessment(db_session, assessment.risk_assessment_id)
    service.count_assessments(db_session)
    service.count_assessments_for_correlation(db_session, correlation.correlation_id)

    after = _all_assessments(db_session)
    assert len(after) == len(before)
    for r in after:
        got = (
            r.correlation_id,
            r.score,
            r.level,
            r.confidence,
            dict(r.factors or {}),
            dict(r.evidence or {}),
            dict(r.assessment_metadata or {}),
            _as_utc(r.timestamp),
            r.provenance,
        )
        assert snapshot[r.risk_assessment_id] == got


def test_queries_emit_only_select_statements(db_session):
    """A full query round-trip produces zero INSERT/UPDATE/DELETE statements."""
    correlation = _seed_correlation(db_session)
    for hours in range(3):
        _persist(
            db_session,
            _assessment(correlation_id=correlation.correlation_id, hours=float(hours)),
        )

    engine = db_session.get_bind()
    dml_count = {"n": 0}

    @event.listens_for(engine, "before_cursor_execute")
    def _count_dml(conn, cursor, statement, parameters, context, executemany):
        first = statement.strip().lower().split(None, 1)[0]
        if first in ("insert", "update", "delete"):
            dml_count["n"] += 1

    try:
        service = RiskQueryService()
        service.get_assessment(db_session, _all_assessments(db_session)[0].risk_assessment_id)
        service.list_assessments_for_correlation(
            db_session, correlation.correlation_id, page=1, page_size=2
        )
        service.list_recent_assessments(db_session, limit=10)
        service.count_assessments(db_session)
    finally:
        event.remove(engine, "before_cursor_execute", _count_dml)

    assert dml_count["n"] == 0


# ---------------------------------------------------------------------------
# 8. Database behavior
# ---------------------------------------------------------------------------


def test_empty_database_behavior(db_session):
    service = RiskQueryService()
    assert service.count_assessments(db_session) == 0
    assert service.get_assessment(db_session, uuid.uuid4()) is None
    assert service.list_recent_assessments(db_session) == []
    assert (
        service.list_assessments_for_correlation(db_session, uuid.uuid4()).items == []
    )
    assert (
        service.list_assessments_for_correlation(db_session, uuid.uuid4()).total == 0
    )


def test_count_total(db_session):
    correlation = _seed_correlation(db_session)
    for hours in range(4):
        _persist(
            db_session,
            _assessment(correlation_id=correlation.correlation_id, hours=float(hours)),
        )
    assert RiskQueryService().count_assessments(db_session) == 4
    assert (
        RiskQueryService().count_assessments_for_correlation(
            db_session, correlation.correlation_id
        )
        == 4
    )
    assert (
        RiskQueryService().count_assessments_for_correlation(db_session, uuid.uuid4())
        == 0
    )


def test_multiple_assessment_rows(db_session):
    correlation = _seed_correlation(db_session)
    assessments = [
        _assessment(correlation_id=correlation.correlation_id, hours=float(i))
        for i in range(5)
    ]
    for assessment in assessments:
        _persist(db_session, assessment)

    feed = RiskQueryService().list_recent_assessments(db_session, limit=10)
    assert {r.risk_assessment_id for r in feed} == {
        a.risk_assessment_id for a in assessments
    }
    assert RiskQueryService().count_assessments(db_session) == 5