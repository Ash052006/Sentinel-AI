"""Knowledge graph API integration tests — V3.22.

Covers authentication, RBAC, response shape, bounded traversal, truncation
reporting, and secret safety of the serialized payload.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete
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
from app.services.knowledge_graph.queries import GraphBounds, KnowledgeGraphQueries
from app.services.knowledge_graph.vocabulary import (
    DEFAULT_BOUNDS,
    NodeType,
    deterministic_node_id,
)
from tests.conftest import auth_header

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)
CORRELATION_PATH = "/api/knowledge-graph/correlations"


def _ts(minutes: int = 0) -> datetime:
    return BASE + timedelta(minutes=minutes)


@pytest.fixture(scope="module")
def graph_correlation(db_session: Session):
    """A persisted 7-detection / 1-event correlation, built into the graph."""
    correlation_id = uuid.uuid4()
    event_id = uuid.uuid4()
    risk_id = uuid.uuid4()
    detection_ids = [uuid.uuid4() for _ in range(7)]

    db_session.add(CorrelationResult(
        correlation_id=correlation_id,
        status=CorrelationStatus.ACTIVE,
        confidence=0.91,
        evidence={"note": "never exposed"},
        result_metadata={},
        timestamp=_ts(60),
        provenance="correlated",
    ))
    db_session.flush()
    for order, detection_id in enumerate(detection_ids):
        db_session.add(DetectionResult(
            event_id=event_id,
            detection_id=detection_id,
            rule_id=f"api-rule-{order:02d}",
            rule_type=RuleType.SIGMA,
            rule_version="1.0.0",
            severity=DetectionSeverity.HIGH,
            matched=True,
            confidence=0.8,
            evidence={"secret": "must never reach the API"},
            result_metadata={"api_key": "sk-should-never-appear-here"},
            detected_at=_ts(order),
            provenance="detected",
        ))
    db_session.flush()
    for order, detection_id in enumerate(detection_ids):
        db_session.add(CorrelationMember(
            correlation_id=correlation_id,
            detection_id=detection_id,
            event_id=event_id,
            timestamp=_ts(order),
            member_order=order,
        ))
    db_session.flush()
    db_session.add(RiskAssessment(
        risk_assessment_id=risk_id,
        correlation_id=correlation_id,
        score=0.785,
        level=RiskLevel.HIGH,
        confidence=0.7,
        factors=[{"name": "exploit"}],
        evidence=[{"detail": "ignored"}],
        assessment_metadata={},
        timestamp=_ts(70),
        provenance="risk_assessed",
    ))
    db_session.commit()

    KnowledgeGraphBuilder().build_all(db_session)

    yield {
        "correlation_id": correlation_id,
        "event_id": event_id,
        "risk_id": risk_id,
        "detection_ids": detection_ids,
        # Graph node ids are deterministic UUID5 values, not the V2 ids.
        "correlation_node_id": str(
            deterministic_node_id(NodeType.CORRELATION, str(correlation_id))
        ),
        "event_node_id": str(
            deterministic_node_id(NodeType.EVENT, str(event_id))
        ),
    }

    db_session.rollback()
    db_session.execute(delete(KnowledgeGraphEdge))
    db_session.execute(delete(KnowledgeGraphNode))
    db_session.execute(
        delete(RiskAssessment).where(RiskAssessment.risk_assessment_id == risk_id)
    )
    db_session.execute(
        delete(CorrelationMember).where(
            CorrelationMember.correlation_id == correlation_id
        )
    )
    db_session.execute(
        delete(DetectionResult).where(DetectionResult.event_id == event_id)
    )
    db_session.execute(
        delete(CorrelationResult).where(
            CorrelationResult.correlation_id == correlation_id
        )
    )
    db_session.commit()


# ---------------------------------------------------------------------------
# Authentication and RBAC
# ---------------------------------------------------------------------------


class TestAuthentication:
    def test_correlation_graph_requires_a_token(self, client, graph_correlation):
        response = client.get(f"{CORRELATION_PATH}/{graph_correlation['correlation_id']}")
        assert response.status_code == 401

    def test_node_endpoint_requires_a_token(self, client, graph_correlation):
        response = client.get(
            f"/api/knowledge-graph/nodes/{graph_correlation['event_node_id']}"
        )
        assert response.status_code == 401

    def test_neighbors_endpoint_requires_a_token(self, client, graph_correlation):
        response = client.get(
            f"/api/knowledge-graph/nodes/{graph_correlation['event_node_id']}/neighbors"
        )
        assert response.status_code == 401

    def test_vocabulary_endpoint_requires_a_token(self, client):
        assert client.get("/api/knowledge-graph/vocabulary").status_code == 401

    def test_a_forged_token_is_rejected(self, client, graph_correlation):
        response = client.get(
            f"{CORRELATION_PATH}/{graph_correlation['correlation_id']}",
            headers=auth_header("not.a.real.token"),
        )
        assert response.status_code == 401

    def test_every_read_role_is_allowed(
        self, client, graph_correlation, admin_token, analyst_token, ciso_token
    ):
        path = f"{CORRELATION_PATH}/{graph_correlation['correlation_id']}"
        for token in (admin_token, analyst_token, ciso_token):
            response = client.get(path, headers=auth_header(token))
            assert response.status_code == 200, response.text


# ---------------------------------------------------------------------------
# Correlation graph
# ---------------------------------------------------------------------------


class TestCorrelationGraph:
    def test_response_reports_expected_counts(self, client, graph_correlation, admin_token):
        response = client.get(
            f"{CORRELATION_PATH}/{graph_correlation['correlation_id']}",
            headers=auth_header(admin_token),
        )
        body = response.json()

        assert body["root_node_id"] == graph_correlation["correlation_node_id"]
        assert len(body["nodes"]) == 10  # 1 event + 7 detections + 1 correlation + 1 risk
        assert len(body["edges"]) == 15  # 7 produced + 7 member + 1 assessed
        assert body["node_count"] == 10
        assert body["edge_count"] == 15

    def test_response_reports_one_event_and_seven_detections(
        self, client, graph_correlation, admin_token
    ):
        body = client.get(
            f"{CORRELATION_PATH}/{graph_correlation['correlation_id']}",
            headers=auth_header(admin_token),
        ).json()

        by_type: dict[str, int] = {}
        for node in body["nodes"]:
            by_type[node["node_type"]] = by_type.get(node["node_type"], 0) + 1

        assert by_type[NodeType.EVENT.value] == 1
        assert by_type[NodeType.DETECTION.value] == 7
        assert by_type[NodeType.CORRELATION.value] == 1
        assert by_type[NodeType.RISK_ASSESSMENT.value] == 1

    def test_every_node_exposes_provenance(
        self, client, graph_correlation, admin_token
    ):
        body = client.get(
            f"{CORRELATION_PATH}/{graph_correlation['correlation_id']}",
            headers=auth_header(admin_token),
        ).json()

        for node in body["nodes"]:
            assert node["source_id"]
            assert node["source_reference"]
            assert node["provenance"]
            assert node["label"]

    def test_every_edge_exposes_evidence(
        self, client, graph_correlation, admin_token
    ):
        body = client.get(
            f"{CORRELATION_PATH}/{graph_correlation['correlation_id']}",
            headers=auth_header(admin_token),
        ).json()

        for edge in body["edges"]:
            assert edge["source_reference"]
            assert edge["evidence_references"]

    def test_edges_reference_nodes_present_in_the_payload(
        self, client, graph_correlation, admin_token
    ):
        body = client.get(
            f"{CORRELATION_PATH}/{graph_correlation['correlation_id']}",
            headers=auth_header(admin_token),
        ).json()

        node_ids = {node["id"] for node in body["nodes"]}
        for edge in body["edges"]:
            assert edge["source_node_id"] in node_ids
            assert edge["target_node_id"] in node_ids

    def test_payload_contains_no_secret_material(
        self, client, graph_correlation, admin_token
    ):
        response = client.get(
            f"{CORRELATION_PATH}/{graph_correlation['correlation_id']}",
            headers=auth_header(admin_token),
        )
        blob = response.text.lower()

        assert "sk-should-never-appear-here" not in blob
        assert "never exposed" not in blob
        for marker in ("api_key", "password", "authorization", "$argon2"):
            assert marker not in blob

    def test_unknown_correlation_returns_404(self, client, admin_token):
        response = client.get(f"{CORRELATION_PATH}/{uuid.uuid4()}", headers=auth_header(admin_token))
        assert response.status_code == 404

    def test_malformed_correlation_id_is_rejected(self, client, admin_token):
        response = client.get(f"{CORRELATION_PATH}/not-a-uuid", headers=auth_header(admin_token))
        assert response.status_code in (404, 422)

    def test_response_is_deterministic_across_calls(
        self, client, graph_correlation, admin_token
    ):
        path = f"{CORRELATION_PATH}/{graph_correlation['correlation_id']}"
        headers = auth_header(admin_token)
        first = client.get(path, headers=headers).text
        second = client.get(path, headers=headers).text
        assert first == second


# ---------------------------------------------------------------------------
# Node and neighbour endpoints
# ---------------------------------------------------------------------------


class TestNodeEndpoints:
    def test_node_lookup_returns_the_event(
        self, client, graph_correlation, admin_token
    ):
        response = client.get(
            f"/api/knowledge-graph/nodes/{graph_correlation['event_node_id']}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200
        body = response.json()
        assert body["node_type"] == NodeType.EVENT.value
        assert body["source_id"] == str(graph_correlation["event_id"])
        assert body["provenance"] == "referenced_event_identifier"

    def test_unknown_node_returns_404(self, client, admin_token):
        response = client.get(
            f"/api/knowledge-graph/nodes/{uuid.uuid4()}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 404

    def test_malformed_node_id_is_rejected(self, client, admin_token):
        response = client.get(
            "/api/knowledge-graph/nodes/not-a-uuid", headers=auth_header(admin_token)
        )
        assert response.status_code in (404, 422)

    def test_neighbors_of_an_event_include_its_detections(
        self, client, graph_correlation, admin_token
    ):
        response = client.get(
            f"/api/knowledge-graph/nodes/{graph_correlation['event_node_id']}/neighbors",
            headers=auth_header(admin_token),
        )
        body = response.json()

        assert body["root_node_id"] == graph_correlation["event_node_id"]
        assert body["node_count"] >= 2
        assert body["edge_count"] >= 1

    def test_neighbors_reports_truncation_explicitly(
        self, client, graph_correlation, admin_token
    ):
        body = client.get(
            f"/api/knowledge-graph/nodes/{graph_correlation['event_node_id']}/neighbors",
            headers=auth_header(admin_token),
        ).json()

        assert "truncated" in body
        assert isinstance(body["truncated"], bool)
        if body["truncated"]:
            assert body["truncated_reason"]

    def test_neighbors_rejects_a_malformed_id(self, client, admin_token):
        response = client.get(
            "/api/knowledge-graph/nodes/not-a-uuid/neighbors",
            headers=auth_header(admin_token),
        )
        assert response.status_code in (404, 422)


# ---------------------------------------------------------------------------
# Vocabulary endpoint
# ---------------------------------------------------------------------------


class TestVocabularyEndpoint:
    def test_vocabulary_lists_nodes_and_relationships(
        self, client, admin_token
    ):
        body = client.get(
            "/api/knowledge-graph/vocabulary", headers=auth_header(admin_token)
        ).json()

        assert len(body["node_types"]) == 10
        assert len(body["relationship_types"]) == 10

    def test_vocabulary_reports_available_bounds(self, client, admin_token):
        body = client.get(
            "/api/knowledge-graph/vocabulary", headers=auth_header(admin_token)
        ).json()

        assert body["bounds"]["max_nodes"] == 500
        assert body["bounds"]["max_edges"] == 2000
        assert body["bounds"]["max_depth"] == 5


# ---------------------------------------------------------------------------
# Read-only surface
# ---------------------------------------------------------------------------


class TestReadOnlySurface:
    def test_no_write_verbs_are_exposed_on_the_correlation_path(
        self, client, graph_correlation, admin_token
    ):
        path = f"{CORRELATION_PATH}/{graph_correlation['correlation_id']}"
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            response = getattr(client, method.lower())(
                path, headers=auth_header(admin_token)
            )
            assert response.status_code in (404, 405), method

    def test_no_write_verbs_are_exposed_on_the_node_path(
        self, client, graph_correlation, admin_token
    ):
        path = f"/api/knowledge-graph/nodes/{graph_correlation['event_node_id']}"
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            response = getattr(client, method.lower())(
                path, headers=auth_header(admin_token)
            )
            assert response.status_code in (404, 405), method


# ---------------------------------------------------------------------------
# Bounded traversal at the service layer
# ---------------------------------------------------------------------------


class TestShortFormAlias:
    """``GET /api/knowledge-graph/{correlation_id}`` must also work."""

    def test_short_form_matches_the_namespaced_route(
        self, client, graph_correlation, admin_token
    ):
        headers = auth_header(admin_token)
        short = client.get(
            f"/api/knowledge-graph/{graph_correlation['correlation_id']}",
            headers=headers,
        )
        namespaced = client.get(
            f"{CORRELATION_PATH}/{graph_correlation['correlation_id']}",
            headers=headers,
        )
        assert short.status_code == 200
        assert short.json() == namespaced.json()

    def test_short_form_requires_a_token(self, client, graph_correlation):
        response = client.get(
            f"/api/knowledge-graph/{graph_correlation['correlation_id']}"
        )
        assert response.status_code == 401

    def test_short_form_rejects_a_non_uuid(self, client, admin_token):
        response = client.get(
            "/api/knowledge-graph/not-a-uuid", headers=auth_header(admin_token)
        )
        assert response.status_code == 422

    def test_short_form_does_not_shadow_vocabulary(self, client, admin_token):
        response = client.get(
            "/api/knowledge-graph/vocabulary", headers=auth_header(admin_token)
        )
        assert response.status_code == 200
        assert "node_types" in response.json()

    def test_short_form_does_not_shadow_node_routes(
        self, client, graph_correlation, admin_token
    ):
        response = client.get(
            f"/api/knowledge-graph/nodes/{graph_correlation['event_node_id']}",
            headers=auth_header(admin_token),
        )
        assert response.status_code == 200
        assert response.json()["node_type"] == NodeType.EVENT.value


class TestBoundedTraversal:
    """The API pins production bounds; these exercise tunable, stricter limits."""

    @staticmethod
    def _payload(db_session: Session, correlation_id, bounds: GraphBounds):
        db_session.expire_all()
        return KnowledgeGraphQueries(bounds).get_correlation_graph(
            db_session, correlation_id
        ).as_dict()

    def test_max_nodes_is_enforced(self, db_session, graph_correlation):
        bounds = GraphBounds(max_nodes=4, max_edges=100, max_depth=5)
        payload = self._payload(
            db_session, graph_correlation["correlation_id"], bounds
        )
        assert len(payload["nodes"]) <= 4
        assert payload["truncated"] is True

    def test_max_edges_is_enforced(self, db_session, graph_correlation):
        bounds = GraphBounds(max_nodes=100, max_edges=3, max_depth=5)
        payload = self._payload(
            db_session, graph_correlation["correlation_id"], bounds
        )
        assert len(payload["edges"]) <= 3
        assert payload["truncated"] is True

    def test_truncation_is_never_silent(self, db_session, graph_correlation):
        bounds = GraphBounds(max_nodes=4, max_edges=100, max_depth=5)
        payload = self._payload(
            db_session, graph_correlation["correlation_id"], bounds
        )
        assert payload["truncated"] is True
        assert payload.get("truncated_reason") == "max_nodes"

    def test_edge_bound_reports_the_edge_reason(self, db_session, graph_correlation):
        bounds = GraphBounds(max_nodes=100, max_edges=3, max_depth=5)
        payload = self._payload(
            db_session, graph_correlation["correlation_id"], bounds
        )
        assert payload.get("truncated_reason") == "max_edges"

    def test_depth_bound_is_reported(self, db_session, graph_correlation):
        bounds = GraphBounds(max_nodes=100, max_edges=100, max_depth=1)
        payload = self._payload(
            db_session, graph_correlation["correlation_id"], bounds
        )
        assert payload["max_depth_reached"] <= 1
        if payload["truncated"]:
            assert "max_depth" in payload["truncated_reason"]

    def test_reported_bounds_match_the_bounds_applied(
        self, db_session, graph_correlation
    ):
        """A caller must never be told the defaults when stricter ones ran."""
        bounds = GraphBounds(max_nodes=4, max_edges=3, max_depth=2)
        payload = self._payload(
            db_session, graph_correlation["correlation_id"], bounds
        )
        assert payload["bounds"] == {"max_nodes": 4, "max_edges": 3, "max_depth": 2}

    def test_default_bounds_match_the_contract(self):
        assert DEFAULT_BOUNDS.max_nodes == 500
        assert DEFAULT_BOUNDS.max_edges == 2000
        assert DEFAULT_BOUNDS.max_depth == 5
        assert DEFAULT_BOUNDS.default_page_size == 100
        assert DEFAULT_BOUNDS.max_page_size == 200

    def test_page_size_cannot_exceed_the_maximum(self):
        with pytest.raises(ValueError):
            GraphBounds(max_page_size=50, default_page_size=100)

    def test_depth_cannot_be_zero_or_negative(self):
        with pytest.raises(ValueError):
            GraphBounds(max_depth=0)
        with pytest.raises(ValueError):
            GraphBounds(max_depth=-1)

    def test_node_bound_cannot_be_zero(self):
        with pytest.raises(ValueError):
            GraphBounds(max_nodes=0)

    def test_page_size_limit_is_honoured_by_neighbors(
        self, db_session, graph_correlation
    ):
        db_session.expire_all()
        graph = KnowledgeGraphQueries().get_neighbors(
            db_session, graph_correlation["event_node_id"], limit=2
        )
        assert graph.node_count <= 2
        if graph.truncated:
            assert "page_size" in (graph.truncated_reason or "")
