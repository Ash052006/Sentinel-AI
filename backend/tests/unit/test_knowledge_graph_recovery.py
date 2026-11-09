"""No-schema knowledge-graph recovery and refresh.

The automatic materialization guarantee is made reliable **without** any new
persistent state: a failed build leaves no correlation node (the builder only
commits at the end and every caller rolls back on failure), so absence is a
durable recovery marker, and staleness is detected by re-deriving the expected
subgraph and asking whether every expected node/edge is already persisted.

These tests are deliberately **fixture-independent** (no live database, no
``conftest`` fixtures).  Run them with::

    python -m pytest tests/unit/test_knowledge_graph_recovery.py --noconftest
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.dialects.sqlite.base import SQLiteTypeCompiler
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

if not hasattr(SQLiteTypeCompiler, "visit_JSONB"):
    SQLiteTypeCompiler.visit_JSONB = lambda self, type_, **kw: "JSON"  # noqa: E731

from app.database.postgres.base import Base
from app.models.detection_result import DetectionResult
from app.models.knowledge_graph import KnowledgeGraphEdge, KnowledgeGraphNode
from app.models.risk_assessment import RiskAssessment as RiskAssessmentRow
from app.schemas.correlation import (
    CorrelationMember,
    CorrelationResult,
    CorrelationStatus,
)
from app.schemas.detection import DetectionSeverity, RuleType
from app.schemas.incident_memory import (
    IncidentMemory as IncidentMemorySchema,
)
from app.schemas.incident_memory import (
    MemoryIndicator,
    MemorySource,
    MemoryType,
)
from app.schemas.risk import RiskAssessment as RiskAssessmentSchema
from app.schemas.risk import RiskLevel
from app.schemas.security_event import Provenance
from app.services.correlation_persistence import CorrelationPersistenceService
from app.services.incident_memory_persistence import (
    IncidentMemoryPersistenceService,
)
from app.services.knowledge_graph import materialization as mat
from app.services.knowledge_graph.builder import KnowledgeGraphBuilder
from app.services.risk_persistence import RiskPersistenceService

BASE = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)


def _ts(hours: float = 0.0) -> datetime:
    return BASE + timedelta(hours=hours)


@pytest.fixture()
def db_session():
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
def sqlite_builder(monkeypatch):
    monkeypatch.setattr(
        KnowledgeGraphBuilder,
        "_derive_indicators",
        lambda self, *args, **kwargs: None,
    )


def _member(*, detection_id: uuid.UUID, event_id: uuid.UUID) -> CorrelationMember:
    return CorrelationMember(
        detection_id=detection_id, event_id=event_id, timestamp=_ts(0)
    )


def _detection_row(*, detection_id: uuid.UUID, event_id: uuid.UUID) -> DetectionResult:
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


def _seed_correlation(db: Session, *, correlation_id: uuid.UUID) -> uuid.UUID:
    """Persist a correlation + one member + its detection through real code."""
    event_id = uuid.uuid4()
    detection_id = uuid.uuid4()
    db.add(_detection_row(detection_id=detection_id, event_id=event_id))
    db.commit()
    result = CorrelationResult(
        correlation_id=correlation_id,
        members=[_member(detection_id=detection_id, event_id=event_id)],
        status=CorrelationStatus.CANDIDATE,
        confidence=None,
        evidence={},
        metadata={},
        timestamp=_ts(0),
    )
    CorrelationPersistenceService(
        graph_materializer=lambda _db, _cid: None
    ).persist_correlations(db, [result])
    return correlation_id


def _risk_row(*, correlation_id: uuid.UUID) -> RiskAssessmentRow:
    return RiskAssessmentRow(
        risk_assessment_id=uuid.uuid4(),
        correlation_id=correlation_id,
        score=0.6,
        level="high",
        confidence=0.8,
        factors=[],
        evidence=[],
        assessment_metadata={},
        timestamp=_ts(0),
        provenance=Provenance.RISK_ASSESSED.value,
    )


def _node_source_ids(db: Session, node_type: str) -> set[str]:
    return {
        row.source_id
        for row in db.scalars(
            select(KnowledgeGraphNode).where(
                KnowledgeGraphNode.node_type == node_type
            )
        )
    }


def _relationship_types(db: Session) -> set[str]:
    return {
        row.relationship_type for row in db.scalars(select(KnowledgeGraphEdge))
    }


class _Recording:
    def __init__(self) -> None:
        self.calls: list[uuid.UUID] = []

    def __call__(self, _db: Session, correlation_id: uuid.UUID):
        self.calls.append(correlation_id)
        return None


# ---------------------------------------------------------------------------
# 1. Durable recovery enumeration (no maintenance state)
# ---------------------------------------------------------------------------


def test_unmaterialized_ids_lists_correlations_without_nodes(db_session):
    cid = uuid.uuid4()
    _seed_correlation(db_session, correlation_id=cid)

    assert mat.unmaterialized_correlation_ids(db_session) == [cid]


def test_unmaterialized_ids_empty_after_materialization(db_session, sqlite_builder):
    cid = uuid.uuid4()
    _seed_correlation(db_session, correlation_id=cid)
    mat.refresh_correlation_graphs(db_session, [cid])

    assert mat.unmaterialized_correlation_ids(db_session) == []


def test_limit_bounds_the_scan_not_the_result(db_session):
    """``limit`` caps how many correlations are *examined*, in id order.

    Two unmaterialized correlations with ``limit=1`` yield exactly one: the
    bound is a scan cap, so callers must page or raise the limit to reach the
    rest.  Recorded here so the truncation is explicit, not silent.
    """
    first, second = sorted([uuid.uuid4(), uuid.uuid4()])
    _seed_correlation(db_session, correlation_id=first)
    _seed_correlation(db_session, correlation_id=second)

    assert mat.unmaterialized_correlation_ids(db_session, limit=1) == [first]
    assert mat.unmaterialized_correlation_ids(db_session, limit=2) == [first, second]


def test_refresh_dedupes_and_isolates_each_failure(db_session):
    first, second = uuid.uuid4(), uuid.uuid4()
    seen: list[uuid.UUID] = []

    def _flaky(_db, correlation_id):
        seen.append(correlation_id)
        if correlation_id == second:
            raise RuntimeError("boom")
        return None

    summary = mat.refresh_correlation_graphs(
        db_session, [first, first, second], materializer=_flaky
    )

    assert seen == [first, second]
    assert summary.materialized == (first,)
    assert summary.failed == (second,)
    assert summary.requested == (first, second)


# ---------------------------------------------------------------------------
# 2. Staleness by diffing expected V2 state against the persisted graph
# ---------------------------------------------------------------------------


def test_stale_ids_detects_evidence_added_after_the_build(db_session, sqlite_builder):
    cid = uuid.uuid4()
    _seed_correlation(db_session, correlation_id=cid)
    mat.refresh_correlation_graphs(db_session, [cid])

    # Freshly built: nothing is stale.
    assert mat.stale_correlation_ids(db_session) == []

    # Supporting evidence arrives after the build.
    db_session.add(_risk_row(correlation_id=cid))
    db_session.commit()

    assert mat.stale_correlation_ids(db_session) == [cid]


def test_partial_graph_missing_edge_is_stale_but_not_unmaterialized(
    db_session, sqlite_builder
):
    """A built correlation whose edge vanished must be found by staleness.

    This is the "partially materialized" case: every expected node is present
    (so the correlation is *not* reported as unmaterialized) but an expected
    edge is absent, so recovery must still pick the correlation up.
    """
    from sqlalchemy import delete

    cid = uuid.uuid4()
    _seed_correlation(db_session, correlation_id=cid)
    mat.refresh_correlation_graphs(db_session, [cid])

    assert mat.unmaterialized_correlation_ids(db_session) == []
    assert mat.stale_correlation_ids(db_session) == []

    # Simulate a partial persist: nodes survive, one edge does not.
    db_session.execute(
        delete(KnowledgeGraphEdge).where(
            KnowledgeGraphEdge.relationship_type == "member_of_correlation"
        )
    )
    db_session.commit()

    assert mat.unmaterialized_correlation_ids(db_session) == []
    assert mat.stale_correlation_ids(db_session) == [cid]

    mat.reconcile_correlation_graphs(db_session, include_stale=True)
    assert mat.stale_correlation_ids(db_session) == []


def test_reconcile_refreshes_stale_evidence_and_then_converges(
    db_session, sqlite_builder
):
    cid = uuid.uuid4()
    _seed_correlation(db_session, correlation_id=cid)
    mat.refresh_correlation_graphs(db_session, [cid])
    db_session.add(_risk_row(correlation_id=cid))
    db_session.commit()

    summary = mat.reconcile_correlation_graphs(db_session, include_stale=True)

    assert summary.materialized == (cid,)
    assert _node_source_ids(db_session, "RISK_ASSESSMENT")
    assert "assessed_by" in _relationship_types(db_session)
    assert mat.stale_correlation_ids(db_session) == []


def test_reconcile_missing_only_ignores_stale(db_session, sqlite_builder):
    materialized = uuid.uuid4()
    stale_only = uuid.uuid4()
    _seed_correlation(db_session, correlation_id=materialized)
    _seed_correlation(db_session, correlation_id=stale_only)
    mat.refresh_correlation_graphs(db_session, [stale_only])
    db_session.add(_risk_row(correlation_id=stale_only))
    db_session.commit()

    summary = mat.reconcile_correlation_graphs(db_session, include_stale=False)

    assert summary.requested == (materialized,)
    assert stale_only in mat.stale_correlation_ids(db_session)


# ---------------------------------------------------------------------------
# 3. Downstream writers refresh their correlation's graph after committing
# ---------------------------------------------------------------------------


def test_risk_persistence_refreshes_the_correlation_graph(db_session):
    cid = uuid.uuid4()
    _seed_correlation(db_session, correlation_id=cid)
    spy = _Recording()
    service = RiskPersistenceService(graph_materializer=spy)
    assessment = RiskAssessmentSchema(
        risk_assessment_id=uuid.uuid4(),
        correlation_id=cid,
        score=0.5,
        level=RiskLevel.HIGH,
        confidence=0.8,
        factors=[],
        evidence=[],
        metadata={},
        timestamp=_ts(0),
    )

    service.persist_assessment(db_session, assessment)

    assert spy.calls == [cid]
    # The assessment is durable regardless of the (injected) graph outcome.
    assert db_session.scalar(
        select(RiskAssessmentRow).where(RiskAssessmentRow.correlation_id == cid)
    ) is not None


def test_incident_memory_persistence_refreshes_the_correlation_graph(db_session):
    cid = uuid.uuid4()
    _seed_correlation(db_session, correlation_id=cid)
    spy = _Recording()
    service = IncidentMemoryPersistenceService(graph_materializer=spy)

    source = MemorySource(
        source_id=uuid.uuid4(),
        provenance=Provenance.OBSERVED,
        label="fixture",
        event_id=uuid.uuid4(),
        metadata={},
    )
    memory = IncidentMemorySchema(
        memory_id=uuid.uuid4(),
        memory_type=MemoryType.INCIDENT_SUMMARY,
        title="fixture memory",
        summary=None,
        correlation_id=cid,
        sources=[source],
        indicators=[
            MemoryIndicator(
                indicator_id=uuid.uuid4(),
                indicator_type="ipv4",
                value="198.51.100.7",
                source_ids=[source.source_id],
                metadata={},
            )
        ],
        entities=[],
        techniques=[],
        findings=[],
        actions=[],
        outcome=None,
        confidence=0.8,
        metadata={},
        created_at=_ts(0),
    )

    service.persist_memories(db_session, [memory])

    assert spy.calls == [cid]


# ---------------------------------------------------------------------------
# 4. CLI recovery modes
# ---------------------------------------------------------------------------


def _cli_payload(monkeypatch, engine, **flags):
    monkeypatch.setattr(
        "app.database.postgres.session.SessionLocal", lambda: Session(engine)
    )
    import app.cli as cli

    args = {"correlation_id": None, "all": False, "missing": False,
            "reconcile": False, "max_correlations": 500}
    args.update(flags)
    from types import SimpleNamespace

    return cli._build_knowledge_graph(SimpleNamespace(**args))


def _cli_main(monkeypatch, engine, argv):
    """Run ``app.cli.main`` end-to-end against *engine* (real argparse)."""
    monkeypatch.setattr(
        "app.database.postgres.session.SessionLocal", lambda: Session(engine)
    )
    import app.cli as cli

    return cli.main(list(argv))


def _fresh_engine():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return engine


def test_cli_missing_materializes_a_preexisting_correlation(
    monkeypatch, sqlite_builder
):
    engine = _fresh_engine()
    cid = uuid.uuid4()
    with Session(engine) as seed:
        _seed_correlation(seed, correlation_id=cid)

    payload = _cli_payload(monkeypatch, engine, missing=True)

    assert payload["status"] == "PASS"
    assert payload["scope"] == "missing"
    assert payload["correlation_ids"] == [str(cid)]
    with Session(engine) as check:
        assert _node_source_ids(check, "CORRELATION") == {str(cid)}
    engine.dispose()


def test_cli_reconcile_refreshes_stale_evidence(monkeypatch, sqlite_builder):
    engine = _fresh_engine()
    cid = uuid.uuid4()
    with Session(engine) as seed:
        _seed_correlation(seed, correlation_id=cid)
    # Build once, then add evidence the graph does not yet reflect.
    _cli_payload(monkeypatch, engine, missing=True)
    with Session(engine) as seed:
        seed.add(_risk_row(correlation_id=cid))
        seed.commit()

    payload = _cli_payload(monkeypatch, engine, reconcile=True)

    assert payload["scope"] == "reconcile"
    assert str(cid) in payload["correlation_ids"]
    with Session(engine) as check:
        assert _node_source_ids(check, "RISK_ASSESSMENT")
    engine.dispose()


# ---------------------------------------------------------------------------
# 5. Capped-scan reporting, failure reporting and CLI exit codes
# ---------------------------------------------------------------------------


def test_reconcile_capped_scan_reports_unexamined_correlations(
    db_session, sqlite_builder
):
    """A scan that hits its cap must say how many correlations it never saw.

    Truncation (scan capping) is reported independently of materialization
    failures: this run has *zero* failures and is still not a complete scan.
    """
    first, second, third = sorted([uuid.uuid4(), uuid.uuid4(), uuid.uuid4()])
    for cid in (first, second, third):
        _seed_correlation(db_session, correlation_id=cid)

    summary = mat.reconcile_correlation_graphs(
        db_session, limit=2, include_stale=False
    )

    assert summary.materialized == (first, second)
    assert summary.failed == ()
    assert summary.total_correlations == 3
    assert summary.examined_count == 2
    assert summary.unexamined_count == 1
    assert summary.truncated is True
    assert summary.outcome_status == "PARTIAL"


def test_reconcile_complete_scan_reports_full_coverage(db_session, sqlite_builder):
    """When the cap covers every correlation the scan is not truncated."""
    first, second = sorted([uuid.uuid4(), uuid.uuid4()])
    for cid in (first, second):
        _seed_correlation(db_session, correlation_id=cid)

    summary = mat.reconcile_correlation_graphs(
        db_session, limit=500, include_stale=False
    )

    assert summary.materialized == (first, second)
    assert summary.failed == ()
    assert summary.total_correlations == 2
    assert summary.examined_count == 2
    assert summary.unexamined_count == 0
    assert summary.truncated is False
    assert summary.outcome_status == "PASS"


def test_reconcile_truncation_and_failures_are_reported_independently(
    db_session
):
    """A capped scan that also failed shows BOTH facts, distinctly."""
    first, second, third = sorted([uuid.uuid4(), uuid.uuid4(), uuid.uuid4()])
    for cid in (first, second, third):
        _seed_correlation(db_session, correlation_id=cid)

    def _flaky(_db, correlation_id):
        raise RuntimeError("boom")

    summary = mat.reconcile_correlation_graphs(
        db_session, limit=2, include_stale=False, materializer=_flaky
    )

    assert summary.failed == (first, second)
    assert summary.unexamined_count == 1
    assert summary.outcome_status == "FAIL"
    payload = summary.as_build_dict("missing")
    assert payload["status"] == "FAIL"
    assert payload["truncated"] is True
    assert payload["unexamined_count"] == 1
    assert payload["failed_count"] == 2
    assert payload["truncated_reason"].startswith("scan reached max_correlations")
    # Failures are never laundered into "truncated_reason".
    assert "materialization failures" not in (payload["truncated_reason"] or "")


def test_cli_capped_scan_reports_unexamined_and_exits_nonzero(
    monkeypatch, sqlite_builder, capsys
):
    """``--max-correlations`` capping is reported in JSON and exit status."""
    engine = _fresh_engine()
    first, second = sorted([uuid.uuid4(), uuid.uuid4()])
    with Session(engine) as seed:
        _seed_correlation(seed, correlation_id=first)
        _seed_correlation(seed, correlation_id=second)

    code = _cli_main(
        monkeypatch, engine,
        ["build-knowledge-graph", "--missing",
         "--max-correlations", "1", "--json"],
    )

    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert payload["status"] == "PARTIAL"
    assert payload["truncated"] is True
    assert payload["truncated_reason"].startswith("scan reached max_correlations")
    assert payload["total_correlations"] == 2
    assert payload["examined_count"] == 1
    assert payload["unexamined_count"] == 1
    assert payload["failed_count"] == 0
    assert payload["correlation_ids"] == [str(first)]
    engine.dispose()


def test_cli_materialization_failure_is_reported_and_exits_nonzero(
    monkeypatch, sqlite_builder, capsys
):
    """Failed materializations are distinct from capping and exit non-zero."""
    engine = _fresh_engine()
    cid = uuid.uuid4()
    with Session(engine) as seed:
        _seed_correlation(seed, correlation_id=cid)

    def _boom(self, _db, _correlation_id):
        raise RuntimeError("materialization boom")

    monkeypatch.setattr(
        KnowledgeGraphBuilder, "build_for_correlation", _boom
    )

    code = _cli_main(
        monkeypatch, engine,
        ["build-knowledge-graph", "--missing", "--json"],
    )

    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert payload["status"] == "FAIL"
    assert payload["failed_count"] == 1
    assert payload["failed_correlation_ids"] == [str(cid)]
    # A full-coverage failure scan is not a *scan truncation*.
    assert payload["truncated"] is False
    assert payload["truncated_reason"] is None
    assert payload["unexamined_count"] == 0
    engine.dispose()


def test_cli_complete_success_exits_zero_with_pass_status(
    monkeypatch, sqlite_builder, capsys
):
    """A complete, failure-free recovery scan remains a success."""
    engine = _fresh_engine()
    cid = uuid.uuid4()
    with Session(engine) as seed:
        _seed_correlation(seed, correlation_id=cid)

    code = _cli_main(
        monkeypatch, engine,
        ["build-knowledge-graph", "--missing", "--json"],
    )

    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["status"] == "PASS"
    assert payload["truncated"] is False
    assert payload["failed_count"] == 0
    assert payload["unexamined_count"] == 0
    engine.dispose()


def test_cli_text_output_communicates_the_same_outcome(
    monkeypatch, sqlite_builder, capsys
):
    """The human-readable renderer states status, failures and unexamined
    work exactly as the JSON payload does."""
    engine = _fresh_engine()
    first, second = sorted([uuid.uuid4(), uuid.uuid4()])
    with Session(engine) as seed:
        _seed_correlation(seed, correlation_id=first)
        _seed_correlation(seed, correlation_id=second)

    code = _cli_main(
        monkeypatch, engine,
        ["build-knowledge-graph", "--missing", "--max-correlations", "1"],
    )
    text = capsys.readouterr().out
    assert code == 1
    assert "status           : PARTIAL" in text
    assert "unexamined       : 1 correlation(s)" in text
    assert "truncated        : True" in text

    def _boom(self, _db, _correlation_id):
        raise RuntimeError("materialization boom")

    monkeypatch.setattr(
        KnowledgeGraphBuilder, "build_for_correlation", _boom
    )
    code = _cli_main(
        monkeypatch, engine, ["build-knowledge-graph", "--missing"]
    )
    text = capsys.readouterr().out
    assert code == 1
    assert "status           : FAIL" in text
    assert "failed           : 1 correlation(s) failed to materialize" in text
    assert "retry            : build-knowledge-graph --correlation-id" in text
    engine.dispose()
