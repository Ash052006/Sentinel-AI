"""Risk scoring agent → persistence integration tests (Step 11C).

Verifies the Step 11C-B wiring: a Step 11B
:class:`~app.agents.risk_scoring.RiskScoringAgent` invoked with the
:class:`~app.agents.risk_scoring.persist_risk_assessment_bound` sink persists
its completed Step 11A :class:`~app.schemas.risk.RiskAssessment` atomically
through the Step 11C-B service — and that with no sink the agent remains a
purely in-memory orchestrator.

Because ``risk_assessments.correlation_id`` is a real FK back to
``correlation_results``, the correlation is persisted first (Step 10C) —
mirroring the real pipeline ordering.

Follows the same in-memory SQLite JSONB pattern as the persistence unit
tests: no live PostgreSQL server is required.
"""

from __future__ import annotations

import inspect
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.dialects.sqlite.base import SQLiteTypeCompiler
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

# Make the PostgreSQL ``JSONB`` columns work on SQLite for these unit tests.
# This is a test-only type-compiler adapter; production DDL keeps JSONB.
if not hasattr(SQLiteTypeCompiler, "visit_JSONB"):
    SQLiteTypeCompiler.visit_JSONB = lambda self, type_, **kw: "JSON"  # noqa: E731

from app.agents.risk_scoring import (
    RiskScoringAgent,
    persist_risk_assessment_bound,
)
from app.database.postgres.base import Base
from app.models.risk_assessment import RiskAssessment as RiskAssessmentRow
from app.schemas.correlation import (
    CorrelationMember as CorrelationMemberSchema,
)
from app.schemas.correlation import CorrelationResult as CorrelationResultSchema
from app.schemas.correlation import CorrelationStatus
from app.schemas.security_event import Provenance
from app.services.risk_persistence import RiskPersistenceService

_FIXED_TS = datetime(2025, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
_DETECTION_1 = uuid.UUID("11111111-1111-4111-8111-111111111111")
_DETECTION_2 = uuid.UUID("22222222-2222-4222-8222-222222222222")
_EVENT_1 = uuid.UUID("5a5a5a5a-5a5a-4a5a-8a5a-5a5a5a5a5a51")

from app.services.correlation_persistence import CorrelationPersistenceService


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
    # SQLite enforces foreign keys only when explicitly enabled.
    from sqlalchemy import text

    session.execute(text("PRAGMA foreign_keys=ON"))
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _count(db: Session, model) -> int:
    return db.scalar(select(func.count()).select_from(model))


def _all_assessments(db: Session) -> list[RiskAssessmentRow]:
    return list(db.scalars(select(RiskAssessmentRow)))


def _correlation(*, correlation_id: uuid.UUID | None = None) -> CorrelationResultSchema:
    """Build a Step 10A correlation over two detections of one event."""
    cid = correlation_id or uuid.uuid4()
    return CorrelationResultSchema(
        correlation_id=cid,
        members=[
            CorrelationMemberSchema(
                detection_id=_DETECTION_1,
                event_id=_EVENT_1,
                timestamp=_FIXED_TS,
            ),
            CorrelationMemberSchema(
                detection_id=_DETECTION_2,
                event_id=_EVENT_1,
                timestamp=_FIXED_TS,
            ),
        ],
        status=CorrelationStatus.CANDIDATE,
        confidence=0.8,
        evidence={"reason": "shared_event_id", "event_id": str(_EVENT_1)},
        metadata={},
        timestamp=_FIXED_TS,
        provenance=Provenance.CORRELATED,
    )


def _seed_correlation(db: Session, correlation: CorrelationResultSchema) -> None:
    """Persist the parent correlation through the real Step 10C service."""
    CorrelationPersistenceService(clock=lambda: _FIXED_TS).persist_correlation(
        db, correlation
    )


# ---------------------------------------------------------------------------
# No sink: the agent stays purely in-memory
# ---------------------------------------------------------------------------


def test_agent_without_sink_persists_nothing(db_session):
    """No injected sink means the agent performs zero persistence."""
    correlation = _correlation()
    agent = RiskScoringAgent()
    assessment = agent.analyze(correlation, clock=_FIXED_TS)

    assert assessment.correlation_id == correlation.correlation_id
    assert assessment.score > 0.0
    assert assessment.provenance is Provenance.RISK_ASSESSED
    assert _count(db_session, RiskAssessmentRow) == 0


# ---------------------------------------------------------------------------
# Sink: the assessment persists atomically through the agent
# ---------------------------------------------------------------------------


def test_agent_with_sink_persists_assessment(db_session):
    """The bound sink persists the agent's completed assessment."""
    correlation = _correlation()
    _seed_correlation(db_session, correlation)
    agent = RiskScoringAgent()
    sink = persist_risk_assessment_bound(db_session)

    assessment = agent.analyze(correlation, clock=_FIXED_TS, persistence=sink)

    rows = _all_assessments(db_session)
    assert len(rows) == 1
    row = rows[0]
    assert row.risk_assessment_id == assessment.risk_assessment_id
    assert row.correlation_id == correlation.correlation_id
    assert row.score == assessment.score
    assert row.provenance == "risk_assessed"


def test_agent_with_sink_is_idempotent_per_assessment(db_session):
    """Re-running the agent persists a new historical row per fresh UUID.

    Each analyze() call generates a fresh risk_assessment_id (Step 11A), so
    every evaluation is a legitimate new historical assessment of the same
    correlation — while the agent-level sink itself is only ever invoked
    once per analyze.
    """
    correlation = _correlation()
    _seed_correlation(db_session, correlation)
    agent = RiskScoringAgent()
    sink = persist_risk_assessment_bound(db_session)

    agent.analyze(correlation, clock=_FIXED_TS, persistence=sink)
    agent.analyze(correlation, clock=_FIXED_TS, persistence=sink)

    rows = _all_assessments(db_session)
    assert len(rows) == 2
    assert len({r.risk_assessment_id for r in rows}) == 2
    assert {r.correlation_id for r in rows} == {correlation.correlation_id}


def test_agent_with_custom_service_summary_returned(db_session):
    """The agent returns the assessment while the sink returns its summary."""
    correlation = _correlation()
    _seed_correlation(db_session, correlation)
    service = RiskPersistenceService(clock=lambda: _FIXED_TS)
    sink = persist_risk_assessment_bound(db_session, service=service)
    agent = RiskScoringAgent()

    assessment = agent.analyze(correlation, clock=_FIXED_TS, persistence=sink)
    assert assessment.risk_assessment_id is not None
    assert _count(db_session, RiskAssessmentRow) == 1


def test_agent_persistence_failure_propagates(db_session):
    """A sink failure surfaces (sanitized) through the agent call."""
    from sqlalchemy import text

    correlation = _correlation()
    _seed_correlation(db_session, correlation)

    db_session.execute(text("DROP TABLE risk_assessments"))
    db_session.commit()

    agent = RiskScoringAgent()
    sink = persist_risk_assessment_bound(db_session)
    with pytest.raises(Exception) as exc_info:
        agent.analyze(correlation, clock=_FIXED_TS, persistence=sink)

    assert "Failed to persist risk assessment" in str(exc_info.value)


def test_persist_risk_assessment_bound_returns_callable(db_session):
    """The bound helper returns a callable accepting an assessment."""
    correlation = _correlation()
    _seed_correlation(db_session, correlation)
    sink = persist_risk_assessment_bound(db_session)
    assert callable(sink)

    from app.schemas.risk import RiskAssessment as AssessmentSchema

    summary = sink(
        AssessmentSchema(
            correlation_id=correlation.correlation_id,
            score=0.5,
            level="high",
            confidence=0.5,
            timestamp=_FIXED_TS,
        )
    )
    assert summary.assessments_created == 1
    assert _count(db_session, RiskAssessmentRow) == 1


# ---------------------------------------------------------------------------
# Agent persistence boundary (pure orchestration)
# ---------------------------------------------------------------------------


def test_analyze_signature_has_no_database_parameter():
    """The agent API exposes no session/db parameter — it owns no database."""
    params = inspect.signature(RiskScoringAgent().analyze).parameters
    assert "db" not in params
    assert "session" not in params
    # Only the pure keyword arguments remain: correlation, clock,
    # persistence.
    assert set(params) == {"correlation", "clock", "persistence"}


def test_analyze_source_does_not_call_commit_or_rollback():
    """The agent delegates to the sink; it never commits or rolls back."""
    source = inspect.getsource(RiskScoringAgent.analyze)
    assert "commit(" not in source
    assert "rollback(" not in source
    assert "Session(" not in source


def test_agent_delegates_exclusively_to_persistence_callback():
    """With a supplied sink, the agent forwards the assessment and nothing
    else.

    The spy replaces the real persistence service entirely: if the agent
    touched the database directly the spy (which writes nothing) could not
    have captured the completed assessment.
    """
    captured: list = []

    def spy(assessment):
        captured.append(assessment)
        return "spy-summary"

    agent = RiskScoringAgent()
    correlation = _correlation()
    assessment = agent.analyze(
        correlation, clock=_FIXED_TS, persistence=spy
    )

    assert len(captured) == 1
    assert captured[0] == assessment


def test_agent_constructor_has_no_database_dependency():
    """RiskScoringAgent can be constructed and used with zero DB objects."""
    agent = RiskScoringAgent()
    assert agent._engine is not None
    correlation = _correlation()
    assessment = agent.analyze(correlation, clock=_FIXED_TS)
    assert assessment is not None