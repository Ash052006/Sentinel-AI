"""Automatic knowledge-graph materialization on correlation persistence.

When a correlation is durably persisted, the persistence service materializes
its knowledge-graph subgraph as an isolated post-commit side effect: it runs
strictly after the commit, once per correlation, and a failure is logged and
swallowed so it can never roll back or mask the persisted correlation.

These tests are deliberately **fixture-independent** (no live database, no
``conftest`` fixtures).  Run them with::

    python -m pytest tests/unit/test_correlation_graph_materialization.py --noconftest

The PostgreSQL-specific ``JSONB`` column type is rendered as JSON for SQLite
by installing a ``visit_JSONB`` visitor on the SQLite type compiler, so the
same models and builder code used in production are exercised end-to-end.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.dialects.sqlite.base import SQLiteTypeCompiler
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

# Make the PostgreSQL ``JSONB`` columns work on SQLite for these unit tests.
# This is a test-only type-compiler adapter; production DDL keeps JSONB.
if not hasattr(SQLiteTypeCompiler, "visit_JSONB"):
    SQLiteTypeCompiler.visit_JSONB = lambda self, type_, **kw: "JSON"  # noqa: E731

from app.database.postgres.base import Base
from app.models.correlation_member import (
    CorrelationMember as CorrelationMemberRow,
)
from app.models.correlation_result import (
    CorrelationResult as CorrelationResultRow,
)
from app.models.detection_result import DetectionResult
from app.models.knowledge_graph import KnowledgeGraphEdge, KnowledgeGraphNode
from app.schemas.correlation import (
    CorrelationMember,
    CorrelationResult,
    CorrelationStatus,
)
from app.schemas.detection import DetectionSeverity, RuleType
from app.schemas.security_event import Provenance
from app.services.correlation_persistence import CorrelationPersistenceService
from app.services.knowledge_graph.builder import KnowledgeGraphBuilder

BASE = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)


def _ts(hours: float = 0.0) -> datetime:
    """Deterministic timezone-aware timestamp offset from BASE."""
    return BASE + timedelta(hours=hours)


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
    session.execute(text("PRAGMA foreign_keys=ON"))
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _member(
    *,
    detection_id: uuid.UUID | None = None,
    event_id: uuid.UUID | None = None,
) -> CorrelationMember:
    return CorrelationMember(
        detection_id=detection_id or uuid.uuid4(),
        event_id=event_id or uuid.uuid4(),
        timestamp=_ts(0),
    )


def _correlation(
    *,
    correlation_id: uuid.UUID | None = None,
    members: list[CorrelationMember] | None = None,
) -> CorrelationResult:
    return CorrelationResult(
        correlation_id=correlation_id or uuid.uuid4(),
        members=members or [_member()],
        status=CorrelationStatus.CANDIDATE,
        confidence=None,
        evidence={},
        metadata={},
        timestamp=_ts(0),
    )


def _detection_row(*, detection_id: uuid.UUID, event_id: uuid.UUID) -> DetectionResult:
    """A minimal persisted detection row for one member reference."""
    return DetectionResult(
        detection_id=detection_id,
        event_id=event_id,
        rule_id="sigma-credential-access-001",
        rule_type=RuleType.SIGMA,
        severity=DetectionSeverity.HIGH,
        matched=True,
        confidence=0.9,
        evidence={},
        result_metadata={},
        detected_at=_ts(0),
        provenance=Provenance.DETECTED.value,
    )


def _count(db: Session, model) -> int:
    return db.scalar(select(func.count()).select_from(model))


def _source_ids(db: Session, node_type: str) -> set[str]:
    return {
        row.source_id
        for row in db.scalars(
            select(KnowledgeGraphNode).where(
                KnowledgeGraphNode.node_type == node_type
            )
        )
    }


@pytest.fixture()
def sqlite_builder(monkeypatch):
    """Skip the threat-intel join, which binds Postgres UUID params.

    ``_derive_indicators`` joins ``threat_intel_lookups`` on a PostgreSQL
    ``UUID`` column and binds string event ids; that bind is fine on
    PostgreSQL but rejected by SQLite.  Indicator edges are not the subject of
    these tests, so the join is stubbed to keep the rest of the real builder
    (nodes, correlation/detection edges) exercising the same code as
    production.
    """
    monkeypatch.setattr(
        KnowledgeGraphBuilder,
        "_derive_indicators",
        lambda self, *args, **kwargs: None,
    )


class _RecordingMaterializer:
    """Spy that records calls and proves the correlation is already durable."""

    def __init__(self) -> None:
        self.calls: list[uuid.UUID] = []
        self.visible_at_call: list[bool] = []

    def __call__(self, db: Session, correlation_id: uuid.UUID) -> None:
        self.calls.append(correlation_id)
        row = db.execute(
            select(CorrelationResultRow.correlation_id).where(
                CorrelationResultRow.correlation_id == correlation_id
            )
        ).first()
        self.visible_at_call.append(row is not None)


# ---------------------------------------------------------------------------
# 1. The hook fires, once per correlation, strictly after the commit
# ---------------------------------------------------------------------------


def test_new_correlation_triggers_post_commit_materialization(db_session):
    """A created correlation is materialized once, after it is durable."""
    spy = _RecordingMaterializer()
    service = CorrelationPersistenceService(graph_materializer=spy)
    result = _correlation()

    summary = service.persist_correlations(db_session, [result])

    assert summary.correlations_created == 1
    assert spy.calls == [result.correlation_id]
    # The row was already committed when the hook ran: post-commit, never
    # from a transaction that could still roll back.
    assert spy.visible_at_call == [True]
    assert _count(db_session, CorrelationResultRow) == 1


def test_materialization_runs_once_per_correlation_in_batch(db_session):
    """A batch materializes each distinct correlation exactly once."""
    spy = _RecordingMaterializer()
    service = CorrelationPersistenceService(graph_materializer=spy)
    first, second = _correlation(), _correlation()

    service.persist_correlations(db_session, [first, second])

    assert len(spy.calls) == 2
    assert set(spy.calls) == {first.correlation_id, second.correlation_id}


def test_empty_batch_never_materializes(db_session):
    """Persisting nothing materializes nothing."""
    spy = _RecordingMaterializer()
    service = CorrelationPersistenceService(graph_materializer=spy)

    summary = service.persist_correlations(db_session, [])

    assert summary.is_empty
    assert spy.calls == []


# ---------------------------------------------------------------------------
# 2. Idempotent re-persist does not rebuild; a staged batch refreshes
# ---------------------------------------------------------------------------


def test_skipped_only_batch_does_not_materialize(db_session):
    """Re-persisting an already-stored correlation is a no-op for the graph."""
    spy = _RecordingMaterializer()
    service = CorrelationPersistenceService(graph_materializer=spy)
    result = _correlation()

    service.persist_correlations(db_session, [result])
    service.persist_correlations(db_session, [result])

    assert spy.calls == [result.correlation_id]


def test_staged_batch_refreshes_existing_correlation_too(db_session):
    """When a batch commits, every correlation it names is (re)materialized."""
    spy = _RecordingMaterializer()
    service = CorrelationPersistenceService(graph_materializer=spy)
    existing = _correlation()
    service.persist_correlations(db_session, [existing])
    spy.calls.clear()

    fresh = _correlation()
    service.persist_correlations(db_session, [existing, fresh])

    assert set(spy.calls) == {existing.correlation_id, fresh.correlation_id}


# ---------------------------------------------------------------------------
# 3. Failure isolation: observable, retryable, never masking the correlation
# ---------------------------------------------------------------------------


def test_materializer_failure_is_logged_and_correlation_survives(db_session, caplog):
    """A graph failure is logged with the id and never fails persistence."""

    def _boom(_db, _correlation_id) -> None:
        raise RuntimeError("graph builder unavailable")

    service = CorrelationPersistenceService(graph_materializer=_boom)
    result = _correlation()

    with caplog.at_level(logging.WARNING):
        summary = service.persist_correlations(db_session, [result])

    # The correlation is durably persisted despite the graph failure.
    assert summary.correlations_created == 1
    assert _count(db_session, CorrelationResultRow) == 1
    # The failure is observable and points at a retry mechanism.
    assert str(result.correlation_id) in caplog.text
    assert "build-knowledge-graph" in caplog.text


def test_materializer_failure_leaves_session_usable_and_retryable(
    db_session, sqlite_builder
):
    """After a failed materialization the graph can be built on demand."""

    def _boom(_db, _correlation_id) -> None:
        raise RuntimeError("graph builder unavailable")

    service = CorrelationPersistenceService(graph_materializer=_boom)
    result = _correlation(members=[_member(detection_id=uuid.uuid4())])
    service.persist_correlations(db_session, [result])

    assert _count(db_session, KnowledgeGraphNode) == 0
    # Retry (e.g. via `build-knowledge-graph --correlation-id`) succeeds.
    KnowledgeGraphBuilder().build_for_correlation(db_session, result.correlation_id)
    assert _count(db_session, KnowledgeGraphNode) >= 1


def test_one_failing_materialization_does_not_skip_the_rest(db_session):
    """A failure for one correlation does not prevent the others."""
    calls: list[uuid.UUID] = []

    def _flaky(_db, correlation_id) -> None:
        calls.append(correlation_id)
        if len(calls) == 1:
            raise RuntimeError("first build fails")

    service = CorrelationPersistenceService(graph_materializer=_flaky)
    first, second = _correlation(), _correlation()

    summary = service.persist_correlations(db_session, [first, second])

    assert summary.correlations_created == 2
    assert set(calls) == {first.correlation_id, second.correlation_id}
    assert _count(db_session, CorrelationResultRow) == 2


# ---------------------------------------------------------------------------
# 4. The default hook builds real nodes/edges from persisted rows, idempotently
# ---------------------------------------------------------------------------


def test_default_hook_materializes_real_nodes_and_edges(db_session, sqlite_builder):
    """The default hook derives the subgraph from the persisted correlation."""
    event_id = uuid.uuid4()
    detection_id = uuid.uuid4()
    db_session.add(_detection_row(detection_id=detection_id, event_id=event_id))
    db_session.commit()

    result = _correlation(
        members=[_member(detection_id=detection_id, event_id=event_id)]
    )
    CorrelationPersistenceService().persist_correlations(db_session, [result])

    assert str(result.correlation_id) in _source_ids(db_session, "CORRELATION")
    assert str(detection_id) in _source_ids(db_session, "DETECTION")
    assert str(event_id) in _source_ids(db_session, "EVENT")

    relationships = {
        row.relationship_type
        for row in db_session.scalars(select(KnowledgeGraphEdge))
    }
    assert "produced_detection" in relationships
    assert "member_of_correlation" in relationships


def test_default_hook_is_idempotent(db_session, sqlite_builder):
    """Re-materializing a correlation never duplicates nodes or edges."""
    event_id = uuid.uuid4()
    detection_id = uuid.uuid4()
    db_session.add(_detection_row(detection_id=detection_id, event_id=event_id))
    db_session.commit()
    result = _correlation(
        members=[_member(detection_id=detection_id, event_id=event_id)]
    )

    CorrelationPersistenceService().persist_correlations(db_session, [result])
    nodes_after_first = _count(db_session, KnowledgeGraphNode)
    edges_after_first = _count(db_session, KnowledgeGraphEdge)

    # A second, explicit build of the same correlation must converge.
    KnowledgeGraphBuilder().build_for_correlation(db_session, result.correlation_id)

    assert _count(db_session, KnowledgeGraphNode) == nodes_after_first
    assert _count(db_session, KnowledgeGraphEdge) == edges_after_first


# ---------------------------------------------------------------------------
# 5. The existing CLI backfill still materializes pre-existing correlations
# ---------------------------------------------------------------------------


def _seed_correlation(engine, *, correlation_id, detection_id, event_id) -> None:
    """Seed a persisted correlation + member + detection as a prior run would."""
    session = Session(engine)
    try:
        session.add(_detection_row(detection_id=detection_id, event_id=event_id))
        session.add(
            CorrelationResultRow(
                correlation_id=correlation_id,
                status="candidate",
                confidence=None,
                evidence={},
                result_metadata={},
                timestamp=_ts(0),
                provenance=Provenance.CORRELATED.value,
            )
        )
        session.flush()
        session.add(
            CorrelationMemberRow(
                correlation_id=correlation_id,
                detection_id=detection_id,
                event_id=event_id,
                timestamp=_ts(0),
                member_order=0,
            )
        )
        session.commit()
    finally:
        session.close()


def test_cli_backfill_materializes_a_preexisting_correlation(
    monkeypatch, sqlite_builder
):
    """`build-knowledge-graph --correlation-id` still backfills old rows."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    event_id = uuid.uuid4()
    detection_id = uuid.uuid4()
    correlation_id = uuid.uuid4()
    _seed_correlation(
        engine,
        correlation_id=correlation_id,
        detection_id=detection_id,
        event_id=event_id,
    )

    monkeypatch.setattr(
        "app.database.postgres.session.SessionLocal", lambda: Session(engine)
    )

    import app.cli as cli

    payload = cli._build_knowledge_graph(
        SimpleNamespace(
            correlation_id=str(correlation_id),
            all=False,
            max_correlations=500,
        )
    )

    assert payload["status"] == "PASS"
    assert payload["correlation_ids"] == [str(correlation_id)]
    assert payload["node_count"] >= 1
    with Session(engine) as check:
        assert _source_ids(check, "CORRELATION") == {str(correlation_id)}
    engine.dispose()
