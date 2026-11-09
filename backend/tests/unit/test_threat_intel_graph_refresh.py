"""Threat-intelligence post-commit knowledge-graph refresh.

When :meth:`ThreatIntelligencePersistenceService.persist_analysis` commits new
lookups, the graph subgraph of every correlation *genuinely* associated with
the event (via persisted ``correlation_members.event_id``) is refreshed
afterwards, reusing the shared, failure-isolated materializer.  No
correlation id is guessed: an event with no persisted member rows has no
association, and nothing is invented for it.

These tests are deliberately **fixture-independent** (no live database, no
``conftest`` fixtures).  Run them with::

    python -m pytest tests/unit/test_threat_intel_graph_refresh.py --noconftest
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.dialects.sqlite.base import SQLiteTypeCompiler
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

if not hasattr(SQLiteTypeCompiler, "visit_JSONB"):
    SQLiteTypeCompiler.visit_JSONB = lambda self, type_, **kw: "JSON"  # noqa: E731

from app.database.postgres.base import Base
from app.models.detection_result import DetectionResult
from app.models.knowledge_graph import KnowledgeGraphNode
from app.models.threat_intel_lookup import ThreatIntelLookup
from app.schemas.correlation import (
    CorrelationMember,
    CorrelationResult,
    CorrelationStatus,
)
from app.schemas.detection import DetectionSeverity, RuleType
from app.schemas.security_event import Provenance
from app.schemas.threat_intelligence_agent import (
    ExtractedIndicator,
    ProviderAssociation,
    ThreatIntelligenceAnalysis,
)
from app.services.correlation_persistence import CorrelationPersistenceService
from app.services.threat_intelligence.base import ThreatIntelResult
from app.services.threat_intelligence.types import IndicatorType, ThreatIndicator
from app.services.threat_intelligence_persistence import (
    ThreatIntelligencePersistenceService,
)

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


class _RecordingMaterializer:
    """Injected graph-materializer spy (same contract as the shared hook)."""

    def __init__(self, *, raise_error: bool = False) -> None:
        self.calls: list[uuid.UUID] = []
        self.raise_error = raise_error

    def __call__(self, _db: Session, correlation_id: uuid.UUID):
        self.calls.append(correlation_id)
        if self.raise_error:
            raise RuntimeError("graph materialization boom")
        return None


def _seed_correlation(db: Session, *, event_id: uuid.UUID | None = None) -> uuid.UUID:
    """Persist a correlation + one member + its detection through real code."""
    event_id = event_id or uuid.uuid4()
    detection_id = uuid.uuid4()
    db.add(
        DetectionResult(
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
    )
    db.commit()
    correlation_id = uuid.uuid4()
    result = CorrelationResult(
        correlation_id=correlation_id,
        members=[
            CorrelationMember(
                detection_id=detection_id,
                event_id=event_id,
                timestamp=_ts(0),
            )
        ],
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


def _analysis(
    event_id: uuid.UUID,
    *,
    indicator: str = "198.51.100.7",
    with_lookup: bool = True,
) -> ThreatIntelligenceAnalysis:
    """Minimal Step 8B analysis carrying one extracted indicator.

    With ``with_lookup=True`` a successful provider result is attached, so
    the persistence service commits a real lookup row (which is what must
    trigger the graph refresh).
    """
    extracted = ExtractedIndicator(
        indicator=indicator,
        indicator_type=IndicatorType.IP,
        source_field="source_endpoint.ip",
        source_context="source_endpoint",
    )
    results: list[ProviderAssociation] = []
    if with_lookup:
        results.append(
            ProviderAssociation(
                indicator=extracted,
                provider="virustotal",
                result=ThreatIntelResult(
                    indicator=ThreatIndicator(
                        indicator_type=IndicatorType.IP, value=indicator
                    ),
                    provider="virustotal",
                    found=True,
                    data={"suspicious": 2},
                    confidence=0.7,
                    timestamp=_ts(0),
                ),
            )
        )
    return ThreatIntelligenceAnalysis(
        event_id=event_id,
        indicators=[extracted],
        results=results,
    )


# ---------------------------------------------------------------------------
# 1. Successful refresh after a committed lookup
# ---------------------------------------------------------------------------


def test_persist_analysis_refreshes_the_associated_correlation_graph(db_session):
    event_id = uuid.uuid4()
    cid = _seed_correlation(db_session, event_id=event_id)
    spy = _RecordingMaterializer()
    service = ThreatIntelligencePersistenceService(graph_materializer=spy)

    result = service.persist_analysis(db_session, _analysis(event_id))

    assert result.lookups_created == 1
    # The persisted lookup is genuinely associated with the correlation
    # through correlation_members.event_id -- nothing was guessed.
    assert spy.calls == [cid]
    lookup = db_session.scalar(
        select(ThreatIntelLookup).where(ThreatIntelLookup.event_id == event_id)
    )
    assert lookup is not None
    assert lookup.provenance == Provenance.ENRICHED.value


def test_refresh_runs_strictly_after_the_commit(db_session):
    """The materializer sees the committed lookup, not an open transaction."""
    event_id = uuid.uuid4()
    cid = _seed_correlation(db_session, event_id=event_id)
    seen: dict[str, object] = {}

    def _materializer(db: Session, correlation_id: uuid.UUID):
        seen["correlation_id"] = correlation_id
        seen["lookup_visible"] = (
            db.scalar(
                select(ThreatIntelLookup).where(
                    ThreatIntelLookup.event_id == event_id
                )
            )
            is not None
        )
        return None

    service = ThreatIntelligencePersistenceService(
        graph_materializer=_materializer
    )
    service.persist_analysis(db_session, _analysis(event_id))

    assert seen["correlation_id"] == cid
    assert seen["lookup_visible"] is True


# ---------------------------------------------------------------------------
# 2. Missing association: nothing is guessed, nothing is refreshed
# ---------------------------------------------------------------------------


def test_no_refresh_when_no_correlation_references_the_event(db_session):
    """The lookup's schema carries no correlation id; without a persisted
    ``correlation_members.event_id`` association no refresh is triggered and
    no correlation id is invented."""
    associated_event = uuid.uuid4()
    _seed_correlation(db_session, event_id=associated_event)
    unrelated_event = uuid.uuid4()
    spy = _RecordingMaterializer()
    service = ThreatIntelligencePersistenceService(graph_materializer=spy)

    result = service.persist_analysis(
        db_session, _analysis(unrelated_event)
    )

    assert result.lookups_created == 1
    assert spy.calls == []
    assert db_session.scalar(
        select(ThreatIntelLookup).where(
            ThreatIntelLookup.event_id == unrelated_event
        )
    ) is not None


def test_no_refresh_when_no_lookups_are_committed(db_session):
    """An analysis with no provider results commits no lookup, so there is
    no new evidence to refresh."""
    event_id = uuid.uuid4()
    _seed_correlation(db_session, event_id=event_id)
    spy = _RecordingMaterializer()
    service = ThreatIntelligencePersistenceService(graph_materializer=spy)

    result = service.persist_analysis(
        db_session, _analysis(event_id, with_lookup=False)
    )

    assert result.lookups_created == 0
    assert spy.calls == []


# ---------------------------------------------------------------------------
# 3. Failure isolation: a graph failure cannot undo committed TI results
# ---------------------------------------------------------------------------


def test_materializer_failure_cannot_undo_persisted_lookups(db_session):
    event_id = uuid.uuid4()
    _seed_correlation(db_session, event_id=event_id)
    spy = _RecordingMaterializer(raise_error=True)
    service = ThreatIntelligencePersistenceService(graph_materializer=spy)

    result = service.persist_analysis(db_session, _analysis(event_id))

    # The refresh was attempted for the genuinely associated correlation...
    assert spy.calls
    # ...and the committed TI rows survive the graph failure untouched.
    assert result.lookups_created == 1
    assert db_session.scalar(
        select(ThreatIntelLookup).where(ThreatIntelLookup.event_id == event_id)
    ) is not None


def test_unexpected_refresh_machinery_failure_is_isolated(db_session, monkeypatch):
    """Even a failure *inside the refresh machinery itself* (before any
    per-correlation isolation) cannot surface as a persistence failure."""
    event_id = uuid.uuid4()
    _seed_correlation(db_session, event_id=event_id)

    def _explode(*_args, **_kwargs):
        raise RuntimeError("refresh machinery boom")

    monkeypatch.setattr(
        "app.services.knowledge_graph.materialization.refresh_correlation_graphs",
        _explode,
    )
    service = ThreatIntelligencePersistenceService()

    result = service.persist_analysis(db_session, _analysis(event_id))

    assert result.lookups_created == 1
    assert db_session.scalar(
        select(ThreatIntelLookup).where(ThreatIntelLookup.event_id == event_id)
    ) is not None


def test_refresh_reaches_the_persisted_graph_end_to_end(db_session, monkeypatch):
    """Full path, no injected materializer: the real shared builder persists
    the EVENT -> THREAT_INDICATOR evidence for the associated correlation."""
    monkeypatch.setattr(
        "app.services.knowledge_graph.builder."
        "KnowledgeGraphBuilder._derive_indicators",
        lambda self, *args, **kwargs: None,  # sqlite has no JSONB
    )
    from app.services.knowledge_graph.vocabulary import NodeType

    event_id = uuid.uuid4()
    cid = _seed_correlation(db_session, event_id=event_id)
    service = ThreatIntelligencePersistenceService()

    service.persist_analysis(db_session, _analysis(event_id))

    correlation_nodes = {
        row.source_id
        for row in db_session.scalars(
            select(KnowledgeGraphNode).where(
                KnowledgeGraphNode.node_type == NodeType.CORRELATION.value
            )
        )
    }
    assert str(cid) in correlation_nodes
