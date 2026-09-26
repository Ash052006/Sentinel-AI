"""Risk assessment persistence behavior tests (Step 11C).

Verifies that Step 11A :class:`~app.schemas.risk.RiskAssessment` objects
are persisted through the service/repository layer into the Step 11C-A
contract model (:class:`~app.models.risk_assessment.RiskAssessment`).

The persistence layer is **faithful and non-scoring**: every test asserts
that what is stored matches exactly what the Step 11B engine produced
(``score``, ``level``, ``confidence``, structured ``factors``/``evidence``/
``metadata``, ``timestamp``, ``provenance``) and that `correlation_id` is
referenced, not duplicated.  No test calculates, re-derives, or reinterprets
risk.

Because ``risk_assessments.correlation_id`` is a real foreign key back to
``correlation_results.correlation_id`` (the Step 10C conventions), tests
that persist an assessment first seed its parent correlation row — exactly
as the real pipeline does (Step 10C persists correlations before Step 11C
persists assessments).

No live PostgreSQL server is involved.  The PostgreSQL-specific ``JSONB``
column type is rendered as JSON for SQLite by installing a ``visit_JSONB``
visitor on the SQLite type compiler; all other column types work through
SQLAlchemy's generic type system.
"""

from __future__ import annotations

import copy
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.dialects.sqlite.base import SQLiteTypeCompiler
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

# Make the PostgreSQL ``JSONB`` columns work on SQLite for these unit tests.
# This is a test-only type-compiler adapter; production DDL keeps JSONB.
if not hasattr(SQLiteTypeCompiler, "visit_JSONB"):
    SQLiteTypeCompiler.visit_JSONB = lambda self, type_, **kw: "JSON"  # noqa: E731

from app.database.postgres.base import Base
from app.models.correlation_result import (
    CorrelationResult as CorrelationResultRow,
)
from app.models.risk_assessment import RiskAssessment as RiskAssessmentRow
from app.repositories.risk import RiskRepository
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
from app.services.risk_persistence import (
    RiskPersistenceError,
    RiskPersistenceService,
    RiskPersistenceValidationError,
)
from app.schemas.correlation import CorrelationMember as CorrelationMemberSchema

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
    # SQLite enforces foreign keys only when explicitly enabled.  This lets
    # the tests exercise FK rejection/cascade behavior that PostgreSQL
    # enforces natively.
    from sqlalchemy import text

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


def _persist(
    db: Session,
    assessment: RiskAssessment,
    *,
    service: RiskPersistenceService | None = None,
):
    """Persist *assessment* through the real service with a fixed clock."""
    sink = service or RiskPersistenceService(clock=lambda: _ts(1))
    return sink.persist_assessment(db, assessment)


def _all_assessments(db: Session) -> list[RiskAssessmentRow]:
    return list(db.scalars(select(RiskAssessmentRow)))


def _count(db: Session, model) -> int:
    return db.scalar(select(func.count()).select_from(model))


# ---------------------------------------------------------------------------
# 1. Persistence fidelity (domain -> database)
# ---------------------------------------------------------------------------


def test_assessment_row_persisted_with_all_attributes(db_session):
    """A Step 11B assessment maps to a fully-populated risk_assessments row.

    Persistence is faithful: score (0.625), level (HIGH), confidence (0.8),
    structured factors/evidence/metadata, timestamp, and provenance are all
    stored exactly as produced.
    """
    correlation = _seed_correlation(db_session)
    correlation_id = correlation.correlation_id

    factors = [
        _factor(
            factor_type="detection_volume",
            contribution=0.5,
            evidence=[_evidence(observation_type="detection_severity")],
        ),
        _factor(factor_type="correlation_extent", contribution=0.3),
    ]
    evidence = [
        _evidence(observation_type="correlation_confidence", metadata={"src": "10A"}),
        _evidence(observation_type="member_count"),
    ]
    assessment = _assessment(
        correlation_id=correlation_id,
        score=0.625,
        level=RiskLevel.HIGH,
        confidence=0.8,
        factors=factors,
        evidence=evidence,
        metadata={"engine": "DeterministicRiskScoringEngine", "policy": "10B"},
    )

    summary = _persist(db_session, assessment)

    assert summary.risk_assessment_id == assessment.risk_assessment_id
    assert summary.correlation_id == correlation_id
    assert summary.assessments_created == 1
    assert not summary.is_empty

    rows = _all_assessments(db_session)
    assert len(rows) == 1
    row = rows[0]
    assert row.risk_assessment_id == assessment.risk_assessment_id
    assert row.correlation_id == correlation_id
    assert row.score == 0.625
    assert row.level is RiskLevel.HIGH
    assert row.confidence == 0.8
    assert row.factors == [f.model_dump(mode="json") for f in factors]
    assert row.evidence == [e.model_dump(mode="json") for e in evidence]
    assert row.assessment_metadata == {
        "engine": "DeterministicRiskScoringEngine",
        "policy": "10B",
    }
    assert _as_utc(row.timestamp) == assessment.timestamp
    assert row.provenance == "risk_assessed"


def test_empty_factors_evidence_metadata_persisted(db_session):
    """Absent (optional) Step 11A content persists as empty structures."""
    correlation = _seed_correlation(db_session)
    assessment = _assessment(correlation_id=correlation.correlation_id)

    _persist(db_session, assessment)

    row = _all_assessments(db_session)[0]
    assert row.factors == []
    assert row.evidence == []
    assert row.assessment_metadata == {}


# ---------------------------------------------------------------------------
# 2. Score/confidence boundaries (persisted exactly, never recomputed)
# ---------------------------------------------------------------------------


def test_score_boundary_zero(db_session):
    correlation = _seed_correlation(db_session)
    assessment = _assessment(
        correlation_id=correlation.correlation_id,
        score=0.0,
        level=RiskLevel.LOW,
    )
    _persist(db_session, assessment)
    assert _all_assessments(db_session)[0].score == 0.0


def test_score_boundary_one(db_session):
    correlation = _seed_correlation(db_session)
    assessment = _assessment(
        correlation_id=correlation.correlation_id,
        score=1.0,
        level=RiskLevel.CRITICAL,
    )
    _persist(db_session, assessment)
    assert _all_assessments(db_session)[0].score == 1.0


def test_score_middle_value_persisted_exactly(db_session):
    """A non-trivial score (0.625) is stored bit-for-bit, not recomputed."""
    correlation = _seed_correlation(db_session)
    assessment = _assessment(correlation_id=correlation.correlation_id, score=0.625)
    _persist(db_session, assessment)
    assert _all_assessments(db_session)[0].score == 0.625


def test_confidence_boundary_zero(db_session):
    correlation = _seed_correlation(db_session)
    assessment = _assessment(
        correlation_id=correlation.correlation_id,
        score=0.2,
        level=RiskLevel.LOW,
        confidence=0.0,
    )
    _persist(db_session, assessment)
    assert _all_assessments(db_session)[0].confidence == 0.0


def test_confidence_boundary_one(db_session):
    correlation = _seed_correlation(db_session)
    assessment = _assessment(
        correlation_id=correlation.correlation_id,
        confidence=1.0,
    )
    _persist(db_session, assessment)
    assert _all_assessments(db_session)[0].confidence == 1.0


def test_confidence_middle_value_persisted_exactly(db_session):
    correlation = _seed_correlation(db_session)
    assessment = _assessment(correlation_id=correlation.correlation_id, confidence=0.8)
    _persist(db_session, assessment)
    assert _all_assessments(db_session)[0].confidence == 0.8


# ---------------------------------------------------------------------------
# 3. Risk levels
# ---------------------------------------------------------------------------


def test_all_risk_levels_persist(db_session):
    """LOW / MEDIUM / HIGH / CRITICAL are all storable."""
    for level, score in (
        (RiskLevel.LOW, 0.1),
        (RiskLevel.MEDIUM, 0.4),
        (RiskLevel.HIGH, 0.6),
        (RiskLevel.CRITICAL, 0.9),
    ):
        correlation = _seed_correlation(db_session)
        _persist(
            db_session,
            _assessment(
                correlation_id=correlation.correlation_id,
                score=score,
                level=level,
            ),
        )

    stored = {row.level for row in _all_assessments(db_session)}
    assert stored == set(RiskLevel)


def test_invalid_level_rejected_by_persistence_service(db_session):
    """A level outside the RiskLevel enum is rejected at the boundary."""
    from types import SimpleNamespace

    correlation = _seed_correlation(db_session)
    assessment = RiskAssessment.model_construct(
        risk_assessment_id=uuid.uuid4(),
        correlation_id=correlation.correlation_id,
        score=0.5,
        level="extreme",  # invented level (schema bypass)
        confidence=0.5,
        factors=[],
        evidence=[],
        metadata={},
        timestamp=_ts(0),
        provenance=Provenance.RISK_ASSESSED,
    )

    with pytest.raises(RiskPersistenceError) as exc_info:
        _persist(db_session, assessment)

    assert isinstance(exc_info.value, RiskPersistenceValidationError)
    assert "level" in str(exc_info.value)
    assert _count(db_session, RiskAssessmentRow) == 0


# ---------------------------------------------------------------------------
# 4. Provenance
# ---------------------------------------------------------------------------


def test_provenance_defaults_to_risk_assessed(db_session):
    correlation = _seed_correlation(db_session)
    _persist(db_session, _assessment(correlation_id=correlation.correlation_id))
    assert _all_assessments(db_session)[0].provenance == "risk_assessed"


def test_provenance_check_blocks_non_risk_assessed(db_session):
    """A provenance other than RISK_ASSESSED is rejected before commit."""
    correlation = _seed_correlation(db_session)
    assessment = RiskAssessment.model_construct(
        risk_assessment_id=uuid.uuid4(),
        correlation_id=correlation.correlation_id,
        score=0.5,
        level=RiskLevel.HIGH,
        confidence=0.5,
        factors=[],
        evidence=[],
        metadata={},
        timestamp=_ts(0),
        provenance=Provenance.DETECTED,
    )

    with pytest.raises(RiskPersistenceError) as exc_info:
        _persist(db_session, assessment)

    assert isinstance(exc_info.value, RiskPersistenceValidationError)
    assert "provenance" in str(exc_info.value)
    assert _count(db_session, RiskAssessmentRow) == 0


# ---------------------------------------------------------------------------
# 5. Idempotency & UUID behavior
# ---------------------------------------------------------------------------


def test_duplicate_risk_assessment_id_skipped(db_session):
    """Re-persisting the same risk_assessment_id is an idempotent no-op."""
    correlation = _seed_correlation(db_session)
    assessment = _assessment(correlation_id=correlation.correlation_id)

    first = _persist(db_session, assessment)
    second = _persist(db_session, assessment)

    assert first.assessments_created == 1
    assert second.assessments_created == 0
    assert second.assessments_skipped == 1
    assert second.is_empty
    assert _count(db_session, RiskAssessmentRow) == 1


def test_multiple_assessments_for_one_correlation_coexist(db_session):
    """correlation_id is not unique — historical assessments accumulate.

    The same correlation may be re-scored over time; each new
    risk_assessment_id is a legitimate, separate historical row.
    """
    correlation = _seed_correlation(db_session)

    first = _assessment(correlation_id=correlation.correlation_id, hours=0)
    second = _assessment(correlation_id=correlation.correlation_id, hours=1)

    _persist(db_session, first)
    _persist(db_session, second)

    rows = _all_assessments(db_session)
    assert len(rows) == 2
    assert {r.risk_assessment_id for r in rows} == {
        first.risk_assessment_id,
        second.risk_assessment_id,
    }
    assert {r.correlation_id for r in rows} == {correlation.correlation_id}


def test_different_correlation_ids_are_distinct_rows(db_session):
    """Assessments over different correlations are stored independently."""
    c1 = _seed_correlation(db_session).correlation_id
    c2 = _seed_correlation(db_session).correlation_id

    _persist(db_session, _assessment(correlation_id=c1))
    _persist(db_session, _assessment(correlation_id=c2))

    rows = _all_assessments(db_session)
    assert len(rows) == 2
    assert {r.correlation_id for r in rows} == {c1, c2}


def test_malformed_risk_assessment_id_rejected(db_session):
    """A non-UUID risk_assessment_id is a controlled validation failure."""
    correlation = _seed_correlation(db_session)
    assessment = RiskAssessment.model_construct(
        risk_assessment_id="not-a-uuid",
        correlation_id=correlation.correlation_id,
        score=0.5,
        level=RiskLevel.HIGH,
        confidence=0.5,
        factors=[],
        evidence=[],
        metadata={},
        timestamp=_ts(0),
        provenance=Provenance.RISK_ASSESSED,
    )

    with pytest.raises(RiskPersistenceError) as exc_info:
        _persist(db_session, assessment)

    assert isinstance(exc_info.value, RiskPersistenceValidationError)
    assert "UUID" in str(exc_info.value)
    assert _count(db_session, RiskAssessmentRow) == 0


def test_malformed_correlation_id_rejected(db_session):
    """A non-UUID correlation_id is a controlled validation failure."""
    assessment = RiskAssessment.model_construct(
        risk_assessment_id=uuid.uuid4(),
        correlation_id="not-a-uuid",
        score=0.5,
        level=RiskLevel.HIGH,
        confidence=0.5,
        factors=[],
        evidence=[],
        metadata={},
        timestamp=_ts(0),
        provenance=Provenance.RISK_ASSESSED,
    )

    with pytest.raises(RiskPersistenceError) as exc_info:
        _persist(db_session, assessment)

    assert isinstance(exc_info.value, RiskPersistenceValidationError)
    assert "correlation_id" in str(exc_info.value)
    assert _count(db_session, RiskAssessmentRow) == 0


def test_duplicate_risk_assessment_id_rejected_at_database(db_session):
    """The unique risk_assessment_id constraint prevents duplicate records."""
    correlation = _seed_correlation(db_session)
    raid = uuid.uuid4()
    _persist(db_session, _assessment(correlation_id=correlation.correlation_id, risk_assessment_id=raid))

    row = RiskAssessmentRow(
        risk_assessment_id=raid,
        correlation_id=correlation.correlation_id,
        score=0.5,
        level=RiskLevel.HIGH,
        confidence=0.5,
        factors=[],
        evidence=[],
        assessment_metadata={},
        timestamp=_ts(1),
        provenance=Provenance.RISK_ASSESSED.value,
    )
    db_session.add(row)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


# ---------------------------------------------------------------------------
# 6. Structured factors / evidence / metadata
# ---------------------------------------------------------------------------


def test_factors_preserved_structured(db_session):
    """Factor contribution values survive a JSON round-trip exactly."""
    correlation = _seed_correlation(db_session)
    factors = [
        _factor(factor_type="detection_volume", contribution=0.5),
        _factor(factor_type="severity_impact", contribution=0.25),
        _factor(factor_type="correlation_extent", contribution=0.0),
        _factor(factor_type="diversity", contribution=1.0, evidence=[_evidence()]),
    ]
    _persist(
        db_session,
        _assessment(correlation_id=correlation.correlation_id, factors=factors),
    )

    stored = _all_assessments(db_session)[0].factors
    assert stored == [f.model_dump(mode="json") for f in factors]
    for entry in stored:
        assert isinstance(entry, dict)


def test_evidence_preserves_observation_ids(db_session):
    """Evidence carries its detection_id/event_id/metadata verbatim."""
    correlation = _seed_correlation(db_session)
    detection_id, event_id = uuid.uuid4(), uuid.uuid4()
    evidence = [
        _evidence(
            observation_type="correlation_confidence",
            detection_id=detection_id,
            event_id=event_id,
            metadata={"src": "engine", "value": 0.8},
        )
    ]
    _persist(
        db_session,
        _assessment(correlation_id=correlation.correlation_id, evidence=evidence),
    )

    stored = _all_assessments(db_session)[0].evidence
    assert stored == [e.model_dump(mode="json") for e in evidence]
    assert stored[0]["detection_id"] == str(detection_id)
    assert stored[0]["event_id"] == str(event_id)
    assert stored[0]["metadata"] == {"src": "engine", "value": 0.8}


def test_metadata_nested_and_bounded(db_session):
    """Assessment metadata is preserved as nested structured JSONB."""
    correlation = _seed_correlation(db_session)
    metadata = {
        "engine": "DeterministicRiskScoringEngine",
        "policy_version": "10B",
        "inputs": {"members": 5, "events": 3},
        "nested": {"list": [1, 2, 3], "flag": True, "nothing": None},
    }
    _persist(
        db_session,
        _assessment(correlation_id=correlation.correlation_id, metadata=metadata),
    )

    assert _all_assessments(db_session)[0].assessment_metadata == metadata


# ---------------------------------------------------------------------------
# 7. Secret safety / redaction (defense-in-depth)
# ---------------------------------------------------------------------------


def test_metadata_sensitive_key_redacted_at_persistence(db_session):
    """Credential-shaped keys are redacted before write (schema bypass)."""
    from types import SimpleNamespace

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

    stored = _all_assessments(db_session)[0].assessment_metadata
    assert stored["apiKey"] == "<redacted>"
    assert stored["safe_field"] == "value"


def test_authorization_and_password_keys_redacted(db_session):
    """Authorization headers and passwords are redacted like other secrets."""
    from types import SimpleNamespace

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

    stored_factors = _all_assessments(db_session)[0].factors
    assert stored_factors[0]["metadata"]["Authorization"] == "<redacted>"
    assert stored_factors[0]["metadata"]["password"] == "<redacted>"
    assert stored_factors[0]["metadata"]["safe"] == 1


def test_evidence_list_values_recursively_redacted(db_session):
    """Nested credential values inside evidence lists are redacted."""
    from types import SimpleNamespace

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

    stored = _all_assessments(db_session)[0].factors
    assert stored[0]["evidence"][0]["metadata"]["token"] == "<redacted>"
    assert stored[0]["evidence"][0]["metadata"]["ok"] == 1


def test_persistence_error_does_not_leak_payload(db_session):
    """Exception text never contains structured payload content."""
    correlation = _seed_correlation(db_session)
    metadata = {"blob": "x" * 300_000}
    assessment = _assessment(
        correlation_id=correlation.correlation_id, metadata=metadata
    )

    with pytest.raises(RiskPersistenceError) as exc_info:
        _persist(db_session, assessment)

    message = str(exc_info.value)
    assert "x" * 20 not in message
    assert len(message) < 200


def test_structured_size_bound_raises_and_rolls_back(db_session):
    """Oversized structured content aborts the unit with no partial rows."""
    correlation = _seed_correlation(db_session)
    assessment = _assessment(
        correlation_id=correlation.correlation_id,
        metadata={"blob": "y" * 300_000},
    )

    with pytest.raises(RiskPersistenceError) as exc_info:
        _persist(db_session, assessment)

    assert isinstance(exc_info.value, RiskPersistenceValidationError)
    assert _count(db_session, RiskAssessmentRow) == 0


def test_non_json_metadata_raises_validation_error(db_session):
    """Non-JSON-serializable structured data is a controlled failure."""
    correlation = _seed_correlation(db_session)
    assessment = RiskAssessment.model_construct(
        risk_assessment_id=uuid.uuid4(),
        correlation_id=correlation.correlation_id,
        score=0.5,
        level=RiskLevel.HIGH,
        confidence=0.5,
        factors=[],
        evidence=[],
        metadata={datetime.now(timezone.utc): "not-key-json"},
        timestamp=_ts(0),
        provenance=Provenance.RISK_ASSESSED,
    )

    with pytest.raises(RiskPersistenceError) as exc_info:
        _persist(db_session, assessment)

    assert isinstance(exc_info.value, RiskPersistenceValidationError)
    assert "JSON" in str(exc_info.value)
    assert _count(db_session, RiskAssessmentRow) == 0


# ---------------------------------------------------------------------------
# 8. Timestamps
# ---------------------------------------------------------------------------


def test_timestamps_round_trip_timezone_aware(db_session):
    """Persisted timestamps keep their exact UTC instant."""
    correlation = _seed_correlation(db_session)
    assessment_ts = _ts(6)
    assessment = _assessment(
        correlation_id=correlation.correlation_id, hours=6
    )
    assert assessment.timestamp == assessment_ts

    _persist(db_session, assessment)

    row = _all_assessments(db_session)[0]
    assert _as_utc(row.timestamp) == assessment_ts


def test_naive_timestamp_rejected_by_persistence_service(db_session):
    """Naive timestamps are rejected at the persistence boundary (bypass)."""
    correlation = _seed_correlation(db_session)
    assessment = RiskAssessment.model_construct(
        risk_assessment_id=uuid.uuid4(),
        correlation_id=correlation.correlation_id,
        score=0.5,
        level=RiskLevel.HIGH,
        confidence=0.5,
        factors=[],
        evidence=[],
        metadata={},
        timestamp=datetime(2026, 9, 1, 12, 0, 0),
        provenance=Provenance.RISK_ASSESSED,
    )

    with pytest.raises(RiskPersistenceError) as exc_info:
        _persist(db_session, assessment)

    assert isinstance(exc_info.value, RiskPersistenceValidationError)
    assert "timezone-aware" in str(exc_info.value)
    assert _count(db_session, RiskAssessmentRow) == 0


# ---------------------------------------------------------------------------
# 9. Input immutability
# ---------------------------------------------------------------------------


def test_input_assessment_not_mutated(db_session):
    """Persisting must not mutate the caller's RiskAssessment objects.

    Factors/evidence/metadata are serialized into independent, redacted
    copies; the source assessment must be unchanged after persistence.
    """
    correlation = _seed_correlation(db_session)
    factors = [_factor(metadata={"apiKey": "sk-abc123def456", "ok": 1})]
    evidence = [
        _evidence(
            observation_type="correlation_confidence",
            metadata={"token": "tok_xyz789", "ok": 1},
        )
    ]
    metadata = {"apikey": "val-abc123", "region": "eu"}
    assessment = _assessment(
        correlation_id=correlation.correlation_id,
        factors=factors,
        evidence=evidence,
        metadata=metadata,
    )

    factors_before = copy.deepcopy(
        [f.model_dump(mode="json") for f in assessment.factors]
    )
    evidence_before = copy.deepcopy(
        [e.model_dump(mode="json") for e in assessment.evidence]
    )
    metadata_before = copy.deepcopy(assessment.metadata)

    _persist(db_session, assessment)

    assert [f.model_dump(mode="json") for f in assessment.factors] == factors_before
    assert assessment.factors[0].metadata["apiKey"] == "sk-abc123def456"
    assert [e.model_dump(mode="json") for e in assessment.evidence] == evidence_before
    assert assessment.evidence[0].metadata["token"] == "tok_xyz789"
    assert assessment.metadata == metadata_before
    assert assessment.metadata["apikey"] == "val-abc123"


# ---------------------------------------------------------------------------
# 10. Non-RiskAssessment input & DB failures
# ---------------------------------------------------------------------------


def test_non_assessment_item_raises_and_rolls_back(db_session):
    """A non-RiskAssessment item aborts the unit."""
    with pytest.raises(RiskPersistenceError) as exc_info:
        _persist(db_session, "not-an-assessment")  # type: ignore[arg-type]

    assert isinstance(exc_info.value, RiskPersistenceValidationError)
    assert "RiskAssessment" in str(exc_info.value)
    assert _count(db_session, RiskAssessmentRow) == 0


def test_database_error_rolls_back_and_raises_safe_error(db_session):
    """A real DB failure surfaces as a sanitized persistence error."""
    from sqlalchemy import text

    correlation = _seed_correlation(db_session)

    db_session.execute(text("DROP TABLE risk_assessments"))
    db_session.commit()

    assessment = _assessment(correlation_id=correlation.correlation_id)
    with pytest.raises(RiskPersistenceError) as exc_info:
        _persist(db_session, assessment)

    assert "Traceback" not in str(exc_info.value)
    assert "risk assessment" in str(exc_info.value)


# ---------------------------------------------------------------------------
# 11. Foreign key behavior
# ---------------------------------------------------------------------------


def test_fk_requires_existing_parent_correlation(db_session):
    """An assessment referencing an unknown correlation fails safely.

    The real FK to ``correlation_results`` blocks orphans — an assessment
    for a correlation that was never persisted cannot be stored.
    """
    assessment = _assessment()

    with pytest.raises(RiskPersistenceError) as exc_info:
        _persist(db_session, assessment)

    message = str(exc_info.value)
    assert "Failed to persist risk assessment" in message
    assert "Traceback" not in message
    assert _count(db_session, RiskAssessmentRow) == 0


def test_fk_cascade_deletes_assessments_with_parent(db_session):
    """Deleting a correlation removes its assessment rows (CASCADE)."""
    correlation = _seed_correlation(db_session)
    cid = correlation.correlation_id
    _persist(db_session, _assessment(correlation_id=cid))
    _persist(db_session, _assessment(correlation_id=cid))

    assert _count(db_session, RiskAssessmentRow) == 2

    from app.repositories.correlation import CorrelationRepository

    db_session.delete(CorrelationRepository(db_session).get_by_correlation_id(cid))
    db_session.commit()

    assert _count(db_session, CorrelationResultRow) == 0
    assert _count(db_session, RiskAssessmentRow) == 0


# ---------------------------------------------------------------------------
# 12. Repository/service roles
# ---------------------------------------------------------------------------


def test_repository_does_not_commit(db_session):
    """The repository stages rows only; the caller owns the transaction."""
    correlation = _seed_correlation(db_session)
    repo = RiskRepository(db_session)
    repo.add(
        RiskAssessmentRow(
            risk_assessment_id=uuid.uuid4(),
            correlation_id=correlation.correlation_id,
            score=0.5,
            level=RiskLevel.HIGH,
            confidence=0.5,
            factors=[],
            evidence=[],
            assessment_metadata={},
            timestamp=_ts(0),
            provenance=Provenance.RISK_ASSESSED.value,
        )
    )
    db_session.rollback()
    assert _count(db_session, RiskAssessmentRow) == 0


def test_get_by_risk_assessment_id(db_session):
    """Repository looks up assessments by their unique risk_assessment_id."""
    correlation = _seed_correlation(db_session)
    raid = uuid.uuid4()
    _persist(
        db_session,
        _assessment(correlation_id=correlation.correlation_id, risk_assessment_id=raid),
    )

    repo = RiskRepository(db_session)
    found = repo.get_by_risk_assessment_id(raid)
    assert found is not None
    assert found.risk_assessment_id == raid
    assert repo.get_by_risk_assessment_id(uuid.uuid4()) is None


def test_single_service_call_is_transactional(db_session):
    """One persist call commits exactly once and rolls back on failure.

    The body of the transaction worked correctly (one row visible), and a
    validation failure leaves the database untouched.
    """
    correlation = _seed_correlation(db_session)
    service = RiskPersistenceService(clock=lambda: _ts(1))

    ok = _assessment(correlation_id=correlation.correlation_id)
    bad = RiskAssessment.model_construct(
        risk_assessment_id=uuid.uuid4(),
        correlation_id=correlation.correlation_id,
        score=0.5,
        level="extreme",
        confidence=0.5,
        factors=[],
        evidence=[],
        metadata={},
        timestamp=_ts(0),
        provenance=Provenance.RISK_ASSESSED,
    )

    assert service.persist_assessment(db_session, ok).assessments_created == 1
    with pytest.raises(RiskPersistenceValidationError):
        service.persist_assessment(db_session, bad)
    # The failing unit rolled back; only the successful row is persisted.
    assert _count(db_session, RiskAssessmentRow) == 1


def test_module_level_convenience_wrapper(db_session):
    """The module-level wrapper persists with a default service."""
    from app.services.risk_persistence import persist_risk_assessment

    correlation = _seed_correlation(db_session)
    assessment = _assessment(correlation_id=correlation.correlation_id)

    summary = persist_risk_assessment(db_session, assessment)
    assert summary.assessments_created == 1
    assert _count(db_session, RiskAssessmentRow) == 1