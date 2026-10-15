"""Graph builder integration tests — V3.22.

Exercises derivation, determinism, idempotency, correlation semantics,
provenance, and integrity against a real PostgreSQL test database.

Every assertion is written against *persisted V2 rows*, so a fabricated
relationship cannot satisfy these tests.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.correlation_member import CorrelationMember
from app.models.correlation_result import CorrelationResult
from app.models.detection_result import DetectionResult
from app.models.knowledge_graph import KnowledgeGraphEdge, KnowledgeGraphNode
from app.models.risk_assessment import RiskAssessment
from app.schemas.correlation import CorrelationStatus
from app.schemas.detection import DetectionSeverity, RuleType
from app.schemas.risk import RiskLevel
from app.services.knowledge_graph.builder import KnowledgeGraphBuilder
from app.services.knowledge_graph.vocabulary import (
    NodeType,
    RelationshipType,
    deterministic_edge_id,
    deterministic_node_id,
)

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _ts(minutes: int = 0) -> datetime:
    return BASE + timedelta(minutes=minutes)


# ---------------------------------------------------------------------------
# Scenario construction
# ---------------------------------------------------------------------------


class Scenario:
    """A minimal, fully persisted V2 correlation with 7 detections / 1 event."""

    def __init__(self, detection_count: int = 7) -> None:
        self.correlation_id = uuid.uuid4()
        self.event_id = uuid.uuid4()
        self.risk_assessment_id = uuid.uuid4()
        self.detection_ids = [uuid.uuid4() for _ in range(detection_count)]

    def persist(self, db: Session) -> "Scenario":
        db.add(CorrelationResult(
            correlation_id=self.correlation_id,
            status=CorrelationStatus.ACTIVE,
            confidence=0.91,
            evidence={"note": "raw evidence jsonb never read by the graph"},
            result_metadata={},
            timestamp=_ts(60),
            provenance="correlated",
        ))
        # correlation_members.correlation_id references a non-primary-key
        # column, so SQLAlchemy cannot infer insert order for us.
        db.flush()
        for order, detection_id in enumerate(self.detection_ids):
            db.add(DetectionResult(
                event_id=self.event_id,
                detection_id=detection_id,
                rule_id=f"rule-{order:02d}",
                rule_type=RuleType.SIGMA,
                rule_version="1.0.0",
                severity=DetectionSeverity.HIGH,
                matched=True,
                confidence=0.8,
                evidence={"secret": "must never reach the graph"},
                result_metadata={"password": "hunter2"},
                detected_at=_ts(order),
                provenance="detected",
            ))
        db.flush()
        for order, detection_id in enumerate(self.detection_ids):
            db.add(CorrelationMember(
                correlation_id=self.correlation_id,
                detection_id=detection_id,
                event_id=self.event_id,
                timestamp=_ts(order),
                member_order=order,
            ))
        db.flush()
        db.add(RiskAssessment(
            risk_assessment_id=self.risk_assessment_id,
            correlation_id=self.correlation_id,
            score=0.785,  # V2 constrains score to 0.0-1.0
            level=RiskLevel.HIGH,
            confidence=0.7,
            factors=[{"name": "exploit"}],
            evidence=[{"detail": "ignored"}],
            assessment_metadata={},
            timestamp=_ts(70),
            provenance="risk_assessed",
        ))
        db.commit()
        return self


@pytest.fixture
def scenario(db_session: Session):
    """Persist a scenario and remove it (and all graph rows) afterwards."""
    created: list[Scenario] = []

    def _make(detection_count: int = 7) -> Scenario:
        # Graph rows are NOT wiped here: node ids are deterministic per V2
        # identity, so scenarios coexist. Tests that need a controlled graph
        # state clear it themselves.
        scenario = Scenario(detection_count).persist(db_session)
        created.append(scenario)
        return scenario

    yield _make

    db_session.rollback()
    db_session.execute(delete(KnowledgeGraphEdge))
    db_session.execute(delete(KnowledgeGraphNode))
    for item in created:
        db_session.execute(
            delete(RiskAssessment).where(
                RiskAssessment.risk_assessment_id == item.risk_assessment_id
            )
        )
        db_session.execute(
            delete(CorrelationMember).where(
                CorrelationMember.correlation_id == item.correlation_id
            )
        )
        db_session.execute(
            delete(DetectionResult).where(
                DetectionResult.detection_id.in_(item.detection_ids)
            )
        )
        db_session.execute(
            delete(CorrelationResult).where(
                CorrelationResult.correlation_id == item.correlation_id
            )
        )
    db_session.commit()


def _nodes_by_type(db: Session, node_type: NodeType) -> list[KnowledgeGraphNode]:
    return list(db.execute(
        select(KnowledgeGraphNode).where(
            KnowledgeGraphNode.node_type == node_type.value
        )
    ).scalars().all())


def _edges_by_type(db: Session, relationship: RelationshipType) -> list[KnowledgeGraphEdge]:
    return list(db.execute(
        select(KnowledgeGraphEdge).where(
            KnowledgeGraphEdge.relationship_type == relationship.value
        )
    ).scalars().all())


def _persisted(db: Session, ref: str) -> bool:
    """True when an evidence reference resolves to a live V2 row.

    V2 surrogate-PK tables are addressed by their natural key in evidence
    references (``detection_result:<detection_id>``), not by the ``id``
    surrogate, so each kind is resolved the way the builder cites it.
    """
    kind, _, identifier = ref.partition(":")
    if kind == "correlation_member":
        # correlation_members.id is itself the cited surrogate.
        return db.get(CorrelationMember, identifier) is not None
    if kind == "detection_result":
        return db.execute(
            select(DetectionResult.detection_id).where(
                DetectionResult.detection_id == identifier
            )
        ).scalar_one_or_none() is not None
    if kind == "risk_assessment":
        return db.execute(
            select(RiskAssessment.risk_assessment_id).where(
                RiskAssessment.risk_assessment_id == identifier
            )
        ).scalar_one_or_none() is not None
    return db.execute(
        select(KnowledgeGraphNode.id).where(
            KnowledgeGraphNode.source_reference == ref
        )
    ).scalar_one_or_none() is not None


def _node(db: Session, node_type: NodeType, source_id) -> KnowledgeGraphNode | None:
    """Resolve the single graph node for a persisted V2 identity."""
    return db.execute(
        select(KnowledgeGraphNode).where(
            KnowledgeGraphNode.node_type == node_type.value,
            KnowledgeGraphNode.source_id == str(source_id),
        )
    ).scalar_one_or_none()


def _edges_for(
    db: Session,
    scenario: "Scenario",
    relationship: RelationshipType,
) -> list[KnowledgeGraphEdge]:
    """Edges of ``relationship`` whose endpoints are in this scenario.

    The shared test database holds unrelated V2 rows, so graph-wide counts
    cannot be asserted; every assertion is scoped to the scenario it built.
    """
    endpoints: dict[UUID, set[UUID]] = {
        NodeType.EVENT: {scenario.event_id},
        NodeType.CORRELATION: {scenario.correlation_id},
        NodeType.RISK_ASSESSMENT: {scenario.risk_assessment_id},
        NodeType.DETECTION: set(scenario.detection_ids),
    }
    relevant: set[UUID] = set()
    for node_type, source_ids in endpoints.items():
        for source_id in source_ids:
            node = _node(db, node_type, source_id)
            if node is not None:
                relevant.add(node.id)

    return [
        edge for edge in _edges_by_type(db, relationship)
        if edge.source_node_id in relevant or edge.target_node_id in relevant
    ]


def _snapshot(db: Session) -> list[tuple]:
    """Byte-comparable snapshot of every persisted graph row."""
    out = []
    for n in db.execute(
        select(KnowledgeGraphNode).order_by(KnowledgeGraphNode.id)
    ).scalars().all():
        out.append((
            "N", str(n.id), n.node_type, n.source_id, n.source_reference,
            n.provenance, n.label, json.dumps(n.node_metadata, sort_keys=True),
        ))
    for e in db.execute(
        select(KnowledgeGraphEdge).order_by(KnowledgeGraphEdge.id)
    ).scalars().all():
        out.append((
            "E", str(e.id), str(e.source_node_id), str(e.target_node_id),
            e.relationship_type, e.source_reference,
            json.dumps(e.evidence_references, sort_keys=True),
        ))
    return out


# ---------------------------------------------------------------------------
# Correlation semantics — the brief's headline requirement
# ---------------------------------------------------------------------------


class TestCorrelationSemantics:
    def test_one_event_seven_detections_yields_one_event_and_seven_detections(
        self, db_session: Session, scenario
    ):
        built = scenario(7)
        KnowledgeGraphBuilder().build_all(db_session)

        events = [
            n for n in _nodes_by_type(db_session, NodeType.EVENT)
            if n.source_id == str(built.event_id)
        ]
        detections = [
            n for n in _nodes_by_type(db_session, NodeType.DETECTION)
            if n.source_id in {str(d) for d in built.detection_ids}
        ]
        assert len(events) == 1, "seven detections must not create seven events"
        assert len(detections) == 7

    def test_seven_detections_produce_seven_distinct_detection_nodes(
        self, db_session: Session, scenario
    ):
        built = scenario(7)
        KnowledgeGraphBuilder().build_all(db_session)

        ids = [
            _node(db_session, NodeType.DETECTION, d).source_id
            for d in built.detection_ids
        ]
        assert len(ids) == len(set(ids)) == 7

    def test_event_node_is_reference_only(self, db_session: Session, scenario):
        built = scenario(3)
        KnowledgeGraphBuilder().build_all(db_session)

        event = next(
            n for n in _nodes_by_type(db_session, NodeType.EVENT)
            if n.source_id == str(built.event_id)
        )
        # V2 persists no events table, so the node must say so honestly.
        assert event.provenance == "referenced_event_identifier"
        assert event.source_reference.startswith("event_reference:")
        assert not event.source_reference.startswith("event:")

    def test_member_of_correlation_edge_count_matches_persisted_members(
        self, db_session: Session, scenario
    ):
        built = scenario(7)
        KnowledgeGraphBuilder().build_all(db_session)

        persisted_members = db_session.execute(
            select(func.count()).select_from(CorrelationMember).where(
                CorrelationMember.correlation_id == built.correlation_id
            )
        ).scalar_one()
        edges = _edges_for(
            db_session, built, RelationshipType.MEMBER_OF_CORRELATION
        )
        assert len(edges) == persisted_members == 7

    def test_produced_detection_edge_count_matches_persisted_detections(
        self, db_session: Session, scenario
    ):
        built = scenario(7)
        KnowledgeGraphBuilder().build_all(db_session)

        edges = _edges_for(
            db_session, built, RelationshipType.PRODUCED_DETECTION
        )
        assert len(edges) == 7

    def test_risk_assessment_is_linked_to_its_correlation(
        self, db_session: Session, scenario
    ):
        built = scenario(2)
        KnowledgeGraphBuilder().build_all(db_session)

        edges = _edges_for(db_session, built, RelationshipType.ASSESSED_BY)
        assert len(edges) == 1
        source = db_session.get(KnowledgeGraphNode, edges[0].source_node_id)
        assert source.source_id == str(built.correlation_id)

    def test_correlation_without_members_yields_no_detections(
        self, db_session: Session, scenario
    ):
        """A correlation with no membership rows contributes no detections."""
        built = scenario(2)
        db_session.execute(
            delete(CorrelationMember).where(
                CorrelationMember.correlation_id == built.correlation_id
            )
        )
        db_session.commit()

        KnowledgeGraphBuilder().build_all(db_session)

        assert _node(db_session, NodeType.CORRELATION, built.correlation_id) is not None
        assert _node(db_session, NodeType.EVENT, built.event_id) is None
        for detection_id in built.detection_ids:
            assert _node(db_session, NodeType.DETECTION, detection_id) is None


# ---------------------------------------------------------------------------
# Determinism and idempotency
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_repeated_build_is_byte_identical(self, db_session: Session, scenario):
        scenario(7)
        builder = KnowledgeGraphBuilder()
        builder.build_all(db_session)
        before = _snapshot(db_session)

        builder.build_all(db_session)
        assert _snapshot(db_session) == before

    def test_repeated_build_creates_no_duplicate_rows(
        self, db_session: Session, scenario
    ):
        scenario(7)
        builder = KnowledgeGraphBuilder()
        builder.build_all(db_session)
        counts_before = (
            db_session.execute(select(func.count()).select_from(KnowledgeGraphNode)).scalar_one(),
            db_session.execute(select(func.count()).select_from(KnowledgeGraphEdge)).scalar_one(),
        )

        builder.build_all(db_session)
        builder.build_all(db_session)
        counts_after = (
            db_session.execute(select(func.count()).select_from(KnowledgeGraphNode)).scalar_one(),
            db_session.execute(select(func.count()).select_from(KnowledgeGraphEdge)).scalar_one(),
        )
        assert counts_before == counts_after

    def test_second_build_reports_zero_created(self, db_session: Session, scenario):
        scenario(3)
        builder = KnowledgeGraphBuilder()
        builder.build_all(db_session)
        second = builder.build_all(db_session)

        assert second.nodes_created == 0
        assert second.edges_created == 0

    def test_node_ids_match_the_deterministic_function(self, db_session: Session, scenario):
        built = scenario(2)
        KnowledgeGraphBuilder().build_all(db_session)

        node = next(
            n for n in _nodes_by_type(db_session, NodeType.DETECTION)
            if n.source_id == str(built.detection_ids[0])
        )
        assert node.id == deterministic_node_id(
            NodeType.DETECTION, str(built.detection_ids[0])
        )

    def test_edge_ids_match_the_deterministic_function(self, db_session: Session, scenario):
        scenario(2)
        KnowledgeGraphBuilder().build_all(db_session)

        edge = _edges_by_type(db_session, RelationshipType.PRODUCED_DETECTION)[0]
        assert edge.id == deterministic_edge_id(
            RelationshipType.PRODUCED_DETECTION,
            edge.source_node_id,
            edge.target_node_id,
        )

    def test_evidence_references_are_sorted(self, db_session: Session, scenario):
        scenario(3)
        KnowledgeGraphBuilder().build_all(db_session)

        for edge in db_session.execute(select(KnowledgeGraphEdge)).scalars().all():
            assert edge.evidence_references == sorted(edge.evidence_references)


# ---------------------------------------------------------------------------
# Provenance — every edge must trace to a persisted row
# ---------------------------------------------------------------------------


class TestProvenance:
    def test_member_of_correlation_cites_a_real_correlation_member_row(
        self, db_session: Session, scenario
    ):
        built = scenario(3)
        KnowledgeGraphBuilder().build_all(db_session)

        member_ids = {
            str(m.id) for m in db_session.execute(
                select(CorrelationMember).where(
                    CorrelationMember.correlation_id == built.correlation_id
                )
            ).scalars().all()
        }
        edges = _edges_for(
            db_session, built, RelationshipType.MEMBER_OF_CORRELATION
        )
        assert len(edges) == 3
        for edge in edges:
            prefix, _, identifier = edge.source_reference.partition(":")
            assert prefix == "correlation_member"
            assert identifier in member_ids

    def test_produced_detection_cites_the_detection_row_that_records_the_event(
        self, db_session: Session, scenario
    ):
        built = scenario(3)
        KnowledgeGraphBuilder().build_all(db_session)

        persisted = {
            str(d.detection_id)
            for d in db_session.execute(
                select(DetectionResult).where(
                    DetectionResult.event_id == built.event_id
                )
            ).scalars().all()
        }
        edges = _edges_for(
            db_session, built, RelationshipType.PRODUCED_DETECTION
        )
        assert len(edges) == 3
        for edge in edges:
            _, _, identifier = edge.source_reference.partition(":")
            assert identifier in persisted

    def test_assessed_by_cites_the_persisted_risk_assessment(
        self, db_session: Session, scenario
    ):
        built = scenario(2)
        KnowledgeGraphBuilder().build_all(db_session)

        persisted = {
            str(r.risk_assessment_id) for r in db_session.execute(
                select(RiskAssessment).where(
                    RiskAssessment.risk_assessment_id == built.risk_assessment_id
                )
            ).scalars().all()
        }
        edges = _edges_for(db_session, built, RelationshipType.ASSESSED_BY)
        assert len(edges) == 1
        assert edges[0].source_reference.split(":", 1)[1] in persisted

    def test_every_edge_has_a_source_reference(self, db_session: Session, scenario):
        scenario(3)
        KnowledgeGraphBuilder().build_all(db_session)

        for edge in db_session.execute(select(KnowledgeGraphEdge)).scalars().all():
            assert edge.source_reference.strip()

    def test_every_edge_has_non_empty_evidence(self, db_session: Session, scenario):
        scenario(3)
        KnowledgeGraphBuilder().build_all(db_session)

        for edge in db_session.execute(select(KnowledgeGraphEdge)).scalars().all():
            assert edge.evidence_references

    def test_evidence_cites_both_endpoints_and_the_source_reference(
        self, db_session: Session, scenario
    ):
        scenario(3)
        KnowledgeGraphBuilder().build_all(db_session)

        for edge in db_session.execute(select(KnowledgeGraphEdge)).scalars().all():
            source = db_session.get(KnowledgeGraphNode, edge.source_node_id)
            target = db_session.get(KnowledgeGraphNode, edge.target_node_id)
            assert source.source_reference in edge.evidence_references
            assert target.source_reference in edge.evidence_references
            assert edge.source_reference in edge.evidence_references

    def test_no_evidence_reference_is_fabricated(self, db_session: Session, scenario):
        """Every evidence reference must resolve to a real persisted row."""
        built = scenario(3)
        KnowledgeGraphBuilder().build_all(db_session)

        relationships = (
            RelationshipType.MEMBER_OF_CORRELATION,
            RelationshipType.PRODUCED_DETECTION,
            RelationshipType.ASSESSED_BY,
        )
        edges = [
            edge
            for relationship in relationships
            for edge in _edges_for(db_session, built, relationship)
        ]
        assert edges

        for edge in edges:
            for reference in edge.evidence_references:
                assert _persisted(db_session, reference), (
                    f"evidence {reference} does not resolve to a persisted row"
                )

    def test_every_node_has_a_provenance_value(self, db_session: Session, scenario):
        scenario(2)
        KnowledgeGraphBuilder().build_all(db_session)

        for node in db_session.execute(select(KnowledgeGraphNode)).scalars().all():
            assert node.provenance.strip()


# ---------------------------------------------------------------------------
# Integrity — no orphans, no duplicates
# ---------------------------------------------------------------------------


class TestIntegrity:
    def test_no_edge_has_a_missing_endpoint(self, db_session: Session, scenario):
        scenario(5)
        KnowledgeGraphBuilder().build_all(db_session)

        for edge in db_session.execute(select(KnowledgeGraphEdge)).scalars().all():
            assert db_session.get(KnowledgeGraphNode, edge.source_node_id) is not None
            assert db_session.get(KnowledgeGraphNode, edge.target_node_id) is not None

    def test_deleting_a_node_cascades_and_leaves_no_orphan_edge(
        self, db_session: Session, scenario
    ):
        built = scenario(5)
        KnowledgeGraphBuilder().build_all(db_session)

        edge = _edges_for(
            db_session, built, RelationshipType.PRODUCED_DETECTION
        )[0]
        edge_id = edge.id
        source_id = edge.source_node_id
        db_session.delete(db_session.get(KnowledgeGraphNode, source_id))
        db_session.commit()

        assert db_session.get(KnowledgeGraphEdge, edge_id) is None

    def test_duplicate_edge_is_rejected_by_the_database(self, db_session: Session, scenario):
        scenario(2)
        KnowledgeGraphBuilder().build_all(db_session)

        edge = db_session.execute(select(KnowledgeGraphEdge).limit(1)).scalar_one()
        with pytest.raises(IntegrityError):
            db_session.add(KnowledgeGraphEdge(
                id=uuid.uuid4(),  # different isolation id, same relationship
                source_node_id=edge.source_node_id,
                target_node_id=edge.target_node_id,
                relationship_type=edge.relationship_type,
                source_reference=edge.source_reference,
                evidence_references=edge.evidence_references,
            ))
            db_session.commit()
        db_session.rollback()

    def test_duplicate_node_is_rejected_by_the_database(self, db_session: Session, scenario):
        built = scenario(2)
        KnowledgeGraphBuilder().build_all(db_session)

        with pytest.raises(IntegrityError):
            db_session.add(KnowledgeGraphNode(
                id=uuid.uuid4(),  # different isolation id, same natural key
                node_type=NodeType.DETECTION.value,
                source_id=str(built.detection_ids[0]),
                source_reference=f"detection:{built.detection_ids[0]}",
                provenance="persisted_detection_result",
                label="duplicate",
                node_metadata={},
            ))
            db_session.commit()
        db_session.rollback()

    def test_deleted_v2_record_is_pruned_on_next_build(
        self, db_session: Session, scenario
    ):
        """A vanished V2 row must not linger as a stub in the graph."""
        built = scenario(5)
        KnowledgeGraphBuilder().build_all(db_session)

        assert db_session.execute(
            select(func.count()).select_from(KnowledgeGraphNode).where(
                KnowledgeGraphNode.source_id == str(built.detection_ids[0])
            )
        ).scalar_one() == 1

        db_session.execute(
            delete(DetectionResult).where(
                DetectionResult.detection_id == built.detection_ids[0]
            )
        )
        db_session.execute(
            delete(CorrelationMember).where(
                CorrelationMember.detection_id == built.detection_ids[0]
            )
        )
        db_session.commit()

        result = KnowledgeGraphBuilder().build_all(db_session)

        assert db_session.execute(
            select(func.count()).select_from(KnowledgeGraphNode).where(
                KnowledgeGraphNode.source_id == str(built.detection_ids[0])
            )
        ).scalar_one() == 0
        assert result.nodes_pruned >= 1

    def test_member_row_without_a_detection_row_creates_no_edge(
        self, db_session: Session, scenario
    ):
        """A membership row that cannot be demonstrated yields no edge."""
        built = scenario(3)
        db_session.execute(
            delete(DetectionResult).where(
                DetectionResult.detection_id == built.detection_ids[0]
            )
        )
        db_session.commit()

        KnowledgeGraphBuilder().build_all(db_session)

        assert _node(db_session, NodeType.DETECTION, built.detection_ids[0]) is None
        for detection_id in built.detection_ids[1:]:
            assert _node(db_session, NodeType.DETECTION, detection_id) is not None
        member_edges = _edges_for(
            db_session, built, RelationshipType.MEMBER_OF_CORRELATION
        )
        assert len(member_edges) == 2, "edge must not outlive its detection row"

    def test_soft_reference_to_a_missing_correlation_creates_no_edge(
        self, db_session: Session, scenario
    ):
        """V2 soft references may outlive a correlation; no dangling edge."""
        built = scenario(2)
        db_session.execute(
            delete(CorrelationResult).where(
                CorrelationResult.correlation_id == built.correlation_id
            )
        )
        db_session.commit()

        KnowledgeGraphBuilder().build_all(db_session)

        # correlation_members rows cascade away with the correlation, so the
        # correlation itself simply has no node.
        assert not [
            n for n in _nodes_by_type(db_session, NodeType.CORRELATION)
            if n.source_id == str(built.correlation_id)
        ]

    def test_build_for_a_correlation_only_touches_that_subgraph(
        self, db_session: Session, scenario
    ):
        first = scenario(2)
        KnowledgeGraphBuilder().build_all(db_session)
        first_detection_ids = {
            n.source_id for n in db_session.execute(
                select(KnowledgeGraphNode).where(
                    KnowledgeGraphNode.node_type == NodeType.DETECTION.value
                )
            ).scalars().all()
        }
        assert str(first.detection_ids[0]) in first_detection_ids

        second = scenario(3)
        KnowledgeGraphBuilder(prune=False).build_for_correlation(
            db_session, second.correlation_id
        )

        # The previously built correlation keeps every one of its nodes.
        surviving = {
            n.source_id for n in db_session.execute(
                select(KnowledgeGraphNode).where(
                    KnowledgeGraphNode.node_type == NodeType.DETECTION.value
                )
            ).scalars().all()
        }
        assert first_detection_ids.issubset(surviving)
        assert surviving.issuperset({str(d) for d in second.detection_ids})
        assert _node(db_session, NodeType.CORRELATION, first.correlation_id) is not None
        assert _node(db_session, NodeType.CORRELATION, second.correlation_id) is not None


# ---------------------------------------------------------------------------
# Secret safety of persisted graph content
# ---------------------------------------------------------------------------


class TestPersistedSecretSafety:
    def test_detection_evidence_json_is_never_copied_into_the_graph(
        self, db_session: Session, scenario
    ):
        scenario(3)
        KnowledgeGraphBuilder().build_all(db_session)

        for node in _nodes_by_type(db_session, NodeType.DETECTION):
            serialized = json.dumps(node.node_metadata)
            assert "hunter2" not in serialized
            assert "password" not in serialized
            assert "evidence" not in node.node_metadata

    def test_no_graph_column_holds_a_json_payload_column(
        self, db_session: Session, scenario
    ):
        from app.services.knowledge_graph.vocabulary import SAFE_METADATA_FIELDS

        scenario(3)
        KnowledgeGraphBuilder().build_all(db_session)

        forbidden = {
            "evidence", "result_metadata", "payload", "memory_metadata",
            "execution_metadata", "factors", "sources",
        }
        for node in db_session.execute(select(KnowledgeGraphNode)).scalars().all():
            node_type = NodeType(node.node_type)
            assert not set(node.node_metadata).intersection(forbidden)
            assert set(node.node_metadata).issubset(
                set(SAFE_METADATA_FIELDS[node_type])
            )


# ---------------------------------------------------------------------------
# Bounded builds
# ---------------------------------------------------------------------------


class TestBoundedBuild:
    def test_full_build_respects_max_correlations(
        self, db_session: Session, scenario
    ):
        scenario(2)
        scenario(2)
        db_session.execute(delete(KnowledgeGraphEdge))
        db_session.execute(delete(KnowledgeGraphNode))
        db_session.commit()

        result = KnowledgeGraphBuilder(max_correlations=1).build_all(db_session)

        assert result.truncated is True
        assert result.truncated_reason == "max_nodes"
        assert len(result.correlation_ids) == 1

    def test_truncation_is_reported_not_silent(self, db_session: Session, scenario):
        # Two correlations are required: `build_all` only reports truncation when
        # the scope exceeds the bound, so a single correlation at
        # max_correlations=1 is not a truncated build at all. The test used to
        # create only one, so it passed solely while unrelated rows happened to
        # exist in the database.
        scenario(2)
        scenario(2)
        result = KnowledgeGraphBuilder(max_correlations=1).build_all(db_session)
        payload = result.as_dict()

        assert payload["truncated"] is True
        assert payload["truncated_reason"] is not None

    def test_untruncated_build_reports_no_truncation(
        self, db_session: Session, scenario
    ):
        scenario(2)
        result = KnowledgeGraphBuilder().build_all(db_session)
        assert result.truncated is False
        assert result.as_dict()["truncated_reason"] is None


    def test_truncated_build_does_not_prune_unprocessed_correlations(
        self, db_session: Session, scenario
    ):
        """A bounded build must never delete rows it could not re-derive.

        Pruning is what makes graph state converge on V2 state, so it is only
        sound when the build actually covered the whole scope.  A build that
        stopped at ``max_correlations`` never looked at the remaining
        correlations, so deleting their rows would be data loss.
        """
        first = scenario(2)
        KnowledgeGraphBuilder().build_all(db_session)
        second = scenario(2)
        KnowledgeGraphBuilder().build_all(db_session)

        assert _node(db_session, NodeType.CORRELATION, first.correlation_id) is not None
        assert _node(db_session, NodeType.CORRELATION, second.correlation_id) is not None

        # Rebuild with a bound low enough to cover only part of the scope.
        KnowledgeGraphBuilder(max_correlations=1).build_all(db_session)

        survivors = {
            row.source_id
            for row in db_session.execute(
                select(KnowledgeGraphNode).where(
                    KnowledgeGraphNode.node_type == NodeType.CORRELATION.value
                )
            ).scalars().all()
        }
        assert str(first.correlation_id) in survivors
        assert str(second.correlation_id) in survivors, (
            "a truncated build pruned a correlation it never examined"
        )

    def test_duplicate_membership_rows_collapse_to_one_edge(
        self, db_session: Session, scenario
    ):
        """Two membership rows for one detection yield one relationship.

        ``correlation_members`` is unique on (correlation_id, member_order),
        not on (correlation_id, detection_id), so V2 can legitimately hold
        two rows describing the same membership.  The graph must express one
        ``member_of_correlation`` relationship while still citing both rows.
        """
        built = scenario(3)
        db_session.execute(delete(KnowledgeGraphEdge))
        db_session.execute(delete(KnowledgeGraphNode))
        db_session.commit()

        # A second member row for the same detection, at a new position.
        duplicate = CorrelationMember(
            correlation_id=built.correlation_id,
            detection_id=built.detection_ids[0],
            event_id=built.event_id,
            timestamp=_ts(99),
            member_order=90,
        )
        db_session.add(duplicate)
        db_session.commit()
        db_session.refresh(duplicate)
        duplicate_ref = f"correlation_member:{duplicate.id}"

        KnowledgeGraphBuilder().build_all(db_session)

        edges = _edges_for(
            db_session, built, RelationshipType.MEMBER_OF_CORRELATION
        )
        assert len(edges) == 3, "duplicate membership must not duplicate the edge"

        # Target the specific merged edge by the row it was built from, rather
        # than relying on whichever edge the database happened to return first.
        merged = [e for e in edges if duplicate_ref in e.evidence_references]
        assert len(merged) == 1, "exactly one edge may carry both member rows"

        # Both backing rows are cited, so no evidence is lost.
        member_refs = [
            r for r in merged[0].evidence_references
            if r.startswith("correlation_member:")
        ]
        assert len(member_refs) == 2

    def test_duplicate_membership_does_not_break_a_rebuild(
        self, db_session: Session, scenario
    ):
        """Re-running over duplicated backing rows stays idempotent."""
        built = scenario(3)
        db_session.add(CorrelationMember(
            correlation_id=built.correlation_id,
            detection_id=built.detection_ids[0],
            event_id=built.event_id,
            timestamp=_ts(99),
            member_order=91,
        ))
        db_session.commit()

        builder = KnowledgeGraphBuilder()
        builder.build_all(db_session)
        before = _snapshot(db_session)
        builder.build_all(db_session)

        assert _snapshot(db_session) == before

# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


class TestBuildCli:
    def test_cli_build_all_emits_no_secret_material(self, capsys, db_session, scenario):
        from app.cli import main

        scenario(2)
        exit_code = main(["build-knowledge-graph", "--all", "--json"])

        assert exit_code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["status"] == "PASS"
        blob = json.dumps(payload).lower()
        for marker in ("password", "api_key", "authorization", "secret", "$argon2"):
            assert marker not in blob

    def test_cli_build_for_correlation(self, capsys, db_session, scenario):
        from app.cli import main

        built = scenario(3)
        exit_code = main([
            "build-knowledge-graph",
            "--correlation-id", str(built.correlation_id),
            "--json",
        ])

        assert exit_code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["scope"] == "correlation"
        assert payload["correlation_ids"] == [str(built.correlation_id)]
        assert payload["node_count"] > 0

    def test_cli_rejects_an_invalid_correlation_id(self, capsys, db_session, scenario):
        from app.cli import main

        scenario(1)
        assert main([
            "build-knowledge-graph", "--correlation-id", "not-a-uuid",
        ]) == 1