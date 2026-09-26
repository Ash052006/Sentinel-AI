"""Correlation agent → persistence integration tests (Step 10C).

Verifies the Step 10C-C wiring: a Step 10B
:class:`~app.agents.correlation.CorrelationAgent` invoked with the
:class:`~app.agents.correlation.persist_correlations_bound` sink persists
its completed Step 10A results atomically through the Step 10C-B service —
and that with no sink the agent remains a purely in-memory orchestrator.

Follows the same in-memory SQLite JSONB pattern as the persistence unit
tests: no live PostgreSQL server is required.
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
# This is a test-only type-compiler adapter; production DDL keeps JSONB.
if not hasattr(SQLiteTypeCompiler, "visit_JSONB"):
    SQLiteTypeCompiler.visit_JSONB = lambda self, type_, **kw: "JSON"  # noqa: E731

from app.agents.correlation import CorrelationAgent, persist_correlations_bound
from app.database.postgres.base import Base
from app.models.correlation_member import (
    CorrelationMember as CorrelationMemberRow,
)
from app.models.correlation_result import (
    CorrelationResult as CorrelationResultRow,
)
from app.schemas.correlation import CorrelationMember
from app.schemas.detection import DetectionSeverity, RuleType
from app.schemas.detection_correlation import (
    DetectionCorrelationBatch,
    DetectionCorrelationBatchMetadata,
    DetectionCorrelationInput,
)
from app.schemas.security_event import Provenance
from app.services.correlation_persistence import CorrelationPersistenceService

_FIXED_TS = datetime(2025, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
_EVENT_1 = uuid.UUID("5a5a5a5a-5a5a-4a5a-8a5a-5a5a5a5a5a51")


def _input(*, event_id: uuid.UUID = _EVENT_1, hours: int = 0) -> DetectionCorrelationInput:
    return DetectionCorrelationInput(
        detection_id=uuid.uuid4(),
        event_id=event_id,
        timestamp=_FIXED_TS.replace(hour=_FIXED_TS.hour + hours),
        rule_id="sigma-credential-access-001",
        rule_type=RuleType.SIGMA,
        rule_version="1.2.3",
        severity=DetectionSeverity.HIGH,
        confidence=0.9,
        evidence={"matched_conditions": ["condition_1"]},
        metadata={"rule_version": "1.2.3"},
        provenance=Provenance.DETECTED,
    )


def _batch(*inputs: DetectionCorrelationInput) -> DetectionCorrelationBatch:
    records = list(inputs)
    return DetectionCorrelationBatch(
        detections=records,
        metadata=DetectionCorrelationBatchMetadata(record_count=len(records)),
    )


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


def _member_rows(db: Session) -> list[CorrelationMemberRow]:
    return list(db.scalars(select(CorrelationMemberRow)))


# ---------------------------------------------------------------------------
# No sink: the agent stays purely in-memory
# ---------------------------------------------------------------------------


def test_agent_without_sink_persists_nothing(db_session):
    """No injected sink means the agent performs zero persistence."""
    agent = CorrelationAgent()
    results = agent.analyze(_batch(_input(), _input()), clock=_FIXED_TS)

    assert len(results) == 1
    assert _count(db_session, CorrelationResultRow) == 0
    assert _count(db_session, CorrelationMemberRow) == 0


def test_agent_empty_batch_with_sink_does_not_invoke_persistence(db_session):
    """An empty batch produces no results and the sink is not invoked."""
    agent = CorrelationAgent()
    sink = persist_correlations_bound(db_session)
    results = agent.analyze(_batch(), clock=_FIXED_TS, persistence=sink)

    assert results == []
    assert _count(db_session, CorrelationResultRow) == 0


# ---------------------------------------------------------------------------
# Sink: results persist atomically with their members
# ---------------------------------------------------------------------------


def test_agent_with_sink_persists_results_and_members(db_session):
    """The bound sink persists the agent's complete result set."""
    agent = CorrelationAgent()
    sink = persist_correlations_bound(db_session)
    results = agent.analyze(_batch(_input(), _input()), clock=_FIXED_TS, persistence=sink)

    assert len(results) == 1
    rows = list(db_session.scalars(select(CorrelationResultRow)))
    assert len(rows) == 1
    assert rows[0].correlation_id == results[0].correlation_id
    assert rows[0].provenance == "correlated"
    members = _member_rows(db_session)
    assert len(members) == 2
    assert [m.correlation_id for m in members] == [results[0].correlation_id] * 2
    assert [m.member_order for m in members] == [0, 1]


def test_agent_with_custom_service_summary_returned(db_session):
    """The agent returns results while the sink returns the service summary."""
    service = CorrelationPersistenceService(clock=lambda: _FIXED_TS)
    sink = persist_correlations_bound(db_session, service=service)
    agent = CorrelationAgent()

    results = agent.analyze(_batch(_input()), clock=_FIXED_TS, persistence=sink)
    assert len(results) == 1
    assert _count(db_session, CorrelationResultRow) == 1

    # Re-running the same batch produces a fresh correlation_id: a distinct,
    # legitimate new historical row (matching the correlation persistence
    # contract — deduplication happens on correlation_id only).
    results = agent.analyze(_batch(_input()), clock=_FIXED_TS, persistence=sink)
    assert len(results) == 1
    assert _count(db_session, CorrelationResultRow) == 2
    assert len(_member_rows(db_session)) == 2


def test_agent_persistence_failure_propagates(db_session):
    """A sink failure surfaces (sanitized) through the agent call."""
    from sqlalchemy import text

    db_session.execute(text("DROP TABLE correlation_results"))
    db_session.commit()

    agent = CorrelationAgent()
    sink = persist_correlations_bound(db_session)
    with pytest.raises(Exception) as exc_info:
        agent.analyze(_batch(_input()), clock=_FIXED_TS, persistence=sink)

    assert "Failed to persist correlation" in str(exc_info.value)


def test_persist_correlations_bound_returns_callable(db_session):
    """The bound helper returns a callable accepting CorrelationResults."""
    sink = persist_correlations_bound(db_session)
    assert callable(sink)
    correlation_id = uuid.uuid4()
    from app.schemas.correlation import CorrelationMember as MemberSchema
    from app.schemas.correlation import CorrelationResult as ResultSchema

    summary = sink(
        [
            ResultSchema(
                correlation_id=correlation_id,
                members=[
                    MemberSchema(
                        detection_id=uuid.uuid4(),
                        event_id=_EVENT_1,
                        timestamp=_FIXED_TS,
                    )
                ],
                timestamp=_FIXED_TS,
            )
        ]
    )
    assert summary.correlations_created == 1
    assert _count(db_session, CorrelationResultRow) == 1


# ---------------------------------------------------------------------------
# Agent persistence boundary (pure orchestration)
# ---------------------------------------------------------------------------


def test_analyze_signature_has_no_database_parameter():
    """The agent API exposes no session/db parameter — it owns no database."""
    import inspect

    params = inspect.signature(CorrelationAgent().analyze).parameters
    assert "db" not in params
    assert "session" not in params
    # Only the pure keyword arguments remain: batch, clock, persistence.
    assert set(params) == {"batch", "clock", "persistence"}


def test_analyze_source_does_not_call_commit_or_rollback():
    """The agent delegates to the sink; it never commits or rolls back.

    ``CorrelationAgent.analyze`` must contain no persistence primitives —
    transaction ownership belongs to the injected persistence service.
    """
    import inspect

    source = inspect.getsource(CorrelationAgent.analyze)
    assert "commit(" not in source
    assert "rollback(" not in source
    assert "Session(" not in source


def test_agent_delegates_exclusively_to_persistence_callback():
    """With a supplied sink, the agent forwards results and nothing else.

    The spy replaces the real persistence service entirely: if the agent
    touched the database directly the spy (which writes nothing) could not
    have captured the complete result set.
    """
    captured: list = []

    def spy(results):
        captured.append(results)
        return "spy-summary"

    agent = CorrelationAgent()
    results = agent.analyze(_batch(_input(), _input()), clock=_FIXED_TS, persistence=spy)

    assert len(results) == 1
    assert len(captured) == 1
    assert captured[0] == results


def test_agent_constructor_has_no_database_dependency():
    """CorrelationAgent can be constructed and used with zero DB objects."""
    agent = CorrelationAgent()
    assert agent._strategy is not None
    results = agent.analyze(_batch(_input()), clock=_FIXED_TS)
    assert len(results) == 1