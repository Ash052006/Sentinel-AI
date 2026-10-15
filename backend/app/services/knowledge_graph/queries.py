"""Deterministic, bounded graph traversal — V3.22.

Read-only queries over the persisted knowledge graph.

Every traversal is bounded three ways — maximum nodes, maximum edges, and
maximum depth — and **explicitly reports** when a bound was hit.  Truncation is
never silent.  Response ordering is fully deterministic (sorted by node/edge
id) so two identical requests return byte-identical payloads.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models.knowledge_graph import KnowledgeGraphEdge, KnowledgeGraphNode
from app.services.knowledge_graph.redaction import (
    sanitize_label,
    sanitize_metadata,
)
from app.services.knowledge_graph.vocabulary import (
    DEFAULT_BOUNDS,
    GraphBounds,
    NodeType,
    TruncationReason,
    UNAVAILABLE_GRAPH_ENTITIES,
)


class GraphNodeNotFound(LookupError):
    """Raised when a requested graph node does not exist."""


@dataclass
class BoundedGraph:
    """A bounded traversal result."""

    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    root_node_id: uuid.UUID | None = None
    max_depth_reached: int = 0
    truncated: bool = False
    truncated_reason: str | None = None
    #: The bounds actually applied to this traversal.  Reported back so a
    #: caller can never be told the default limits when stricter ones were
    #: used to produce the result.
    bounds: "GraphBounds | None" = None

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    def as_dict(self) -> dict[str, Any]:
        applied = self.bounds or DEFAULT_BOUNDS
        payload: dict[str, Any] = {
            "root_node_id": str(self.root_node_id) if self.root_node_id else None,
            "nodes": self.nodes,
            "edges": self.edges,
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "max_depth_reached": self.max_depth_reached,
            "truncated": self.truncated,
            "bounds": {
                "max_nodes": applied.max_nodes,
                "max_edges": applied.max_edges,
                "max_depth": applied.max_depth,
            },
        }
        if self.truncated_reason:
            payload["truncated_reason"] = self.truncated_reason
        return payload


class KnowledgeGraphQueries:
    """Bounded, deterministic, read-only graph queries."""

    def __init__(self, bounds: GraphBounds = DEFAULT_BOUNDS) -> None:
        self._bounds = bounds

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    @staticmethod
    def _serialize_node(row: KnowledgeGraphNode) -> dict[str, Any]:
        return {
            "id": str(row.id),
            "node_type": row.node_type,
            "source_id": row.source_id,
            "label": sanitize_label(row.label),
            "source_reference": row.source_reference,
            "provenance": row.provenance,
            # Second secret-safety layer; metadata is already allowlisted.
            "metadata": sanitize_metadata(row.node_metadata or {}),
            "observed_at": (
                row.observed_at.isoformat() if row.observed_at else None
            ),
        }

    @staticmethod
    def _serialize_edge(row: KnowledgeGraphEdge) -> dict[str, Any]:
        return {
            "id": str(row.id),
            "relationship_type": row.relationship_type,
            "source_node_id": str(row.source_node_id),
            "target_node_id": str(row.target_node_id),
            "source_reference": row.source_reference,
            "evidence_references": list(row.evidence_references or []),
        }

    # ------------------------------------------------------------------
    # Public queries
    # ------------------------------------------------------------------

    def get_correlation_graph(
        self,
        db: Session,
        correlation_id: uuid.UUID | str,
        *,
        max_depth: int | None = None,
    ) -> BoundedGraph:
        """Bounded correlation-centered graph.

        Raises :class:`GraphNodeNotFound` when the correlation has no node,
        which the API maps to 404.
        """
        node = self._correlation_node(db, correlation_id)
        return self.traverse(db, node.id, max_depth=max_depth)

    def get_node(self, db: Session, node_id: uuid.UUID | str) -> dict[str, Any]:
        """Single node with its persisted source information."""
        parsed = _as_uuid(node_id)
        if parsed is None:
            raise GraphNodeNotFound(f"invalid node id: {node_id!r}")
        row = db.get(KnowledgeGraphNode, parsed)
        if row is None:
            raise GraphNodeNotFound(f"graph node {parsed} does not exist")
        return self._serialize_node(row)

    def get_neighbors(
        self,
        db: Session,
        node_id: uuid.UUID | str,
        *,
        max_depth: int | None = None,
        limit: int | None = None,
    ) -> BoundedGraph:
        """Bounded neighbor set of one node.

        ``limit`` bounds the total nodes returned, independent of the depth
        bound, and is reported through the same explicit truncation field.
        """
        parsed = _as_uuid(node_id)
        if parsed is None:
            raise GraphNodeNotFound(f"invalid node id: {node_id!r}")
        row = db.get(KnowledgeGraphNode, parsed)
        if row is None:
            raise GraphNodeNotFound(f"graph node {parsed} does not exist")

        page_size = _clamp(
            limit if limit is not None else self._bounds.default_page_size,
            minimum=1,
            maximum=self._bounds.max_page_size,
        )
        graph = self.traverse(db, parsed, max_depth=max_depth)
        return _apply_page_limit(graph, page_size, self._bounds)

    # ------------------------------------------------------------------
    # Traversal
    # ------------------------------------------------------------------

    def traverse(
        self,
        db: Session,
        root_node_id: uuid.UUID,
        *,
        max_depth: int | None = None,
    ) -> BoundedGraph:
        """Breadth-first traversal bounded on nodes, edges, and depth."""
        depth_bound = _clamp(
            max_depth if max_depth is not None else self._bounds.max_depth,
            minimum=1,
            maximum=self._bounds.max_depth,
        )

        root = db.get(KnowledgeGraphNode, root_node_id)
        if root is None:
            raise GraphNodeNotFound(f"graph node {root_node_id} does not exist")

        graph = BoundedGraph(
            root_node_id=root.id, max_depth_reached=0, bounds=self._bounds
        )
        collected: dict[uuid.UUID, KnowledgeGraphNode] = {root.id: root}
        edge_ids: list[uuid.UUID] = []
        frontier: list[uuid.UUID] = [root.id]
        depth = 0

        while frontier:
            if depth >= depth_bound:
                # More nodes existed beyond the depth bound: report it.
                if self._has_unvisited(db, frontier, collected):
                    graph.truncated = True
                    graph.truncated_reason = TruncationReason.MAX_DEPTH.value
                break
            depth += 1

            edges = self._incident_edges(db, frontier)
            if not edges:
                break

            fresh_edges = [e for e in edges if e.id not in edge_ids]

            # Resolve the not-yet-collected endpoints of those edges so we can
            # decide whether the whole expansion fits inside the bounds.
            candidates: dict[uuid.UUID, KnowledgeGraphNode] = {}
            for edge in fresh_edges:
                for endpoint in (edge.source_node_id, edge.target_node_id):
                    if endpoint in collected or endpoint in candidates:
                        continue
                    node = db.get(KnowledgeGraphNode, endpoint)
                    if node is not None:
                        candidates[endpoint] = node

            # Enforce the bounds *before* mutating the result, so a truncated
            # traversal never returns more nodes or edges than allowed.
            node_room = self._bounds.max_nodes - len(collected)
            edge_room = self._bounds.max_edges - len(edge_ids)
            if len(candidates) > node_room or len(fresh_edges) > edge_room:
                graph.truncated = True
                graph.truncated_reason = (
                    TruncationReason.MAX_NODES.value
                    if len(candidates) > node_room
                    else TruncationReason.MAX_EDGES.value
                )
                break

            collected.update(candidates)
            edge_ids.extend(e.id for e in fresh_edges)
            frontier = sorted(candidates, key=str) or frontier

        graph.max_depth_reached = depth
        graph.nodes = [
            self._serialize_node(collected[node_id])
            for node_id in sorted(collected, key=str)
        ]
        if edge_ids:
            rows = db.execute(
                select(KnowledgeGraphEdge)
                .where(KnowledgeGraphEdge.id.in_(edge_ids))
                .order_by(KnowledgeGraphEdge.id)
            ).scalars().all()
            graph.edges = [self._serialize_edge(r) for r in rows]
        return graph

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _incident_edges(
        self, db: Session, node_ids: list[uuid.UUID]
    ) -> list[KnowledgeGraphEdge]:
        if not node_ids:
            return []
        return list(db.execute(
            select(KnowledgeGraphEdge).where(
                or_(
                    KnowledgeGraphEdge.source_node_id.in_(node_ids),
                    KnowledgeGraphEdge.target_node_id.in_(node_ids),
                )
            ).order_by(KnowledgeGraphEdge.id)
        ).scalars().all())

    @staticmethod
    def _has_unvisited(
        db: Session, frontier: list[uuid.UUID], collected: dict[uuid.UUID, Any]
    ) -> bool:
        """True when a frontier node still has a neighbour outside the result.

        Used to distinguish "depth bound reached and there was more to see"
        from "depth bound reached but the subgraph was complete".
        """
        rows = db.execute(
            select(
                KnowledgeGraphEdge.source_node_id,
                KnowledgeGraphEdge.target_node_id,
            ).where(
                or_(
                    KnowledgeGraphEdge.source_node_id.in_(frontier),
                    KnowledgeGraphEdge.target_node_id.in_(frontier),
                )
            )
        ).all()
        for source, target in rows:
            if source not in collected or target not in collected:
                return True
        return False

    def _correlation_node(
        self, db: Session, correlation_id: uuid.UUID | str
    ) -> KnowledgeGraphNode:
        from app.services.knowledge_graph.vocabulary import deterministic_node_id

        parsed = _as_uuid(correlation_id)
        if parsed is None:
            raise GraphNodeNotFound(f"invalid correlation id: {correlation_id!r}")
        node_id = deterministic_node_id(NodeType.CORRELATION, str(parsed))
        row = db.get(KnowledgeGraphNode, node_id)
        if row is None:
            raise GraphNodeNotFound(f"no knowledge graph for correlation {parsed}")
        return row

    # ------------------------------------------------------------------
    # Vocabulary
    # ------------------------------------------------------------------

    @staticmethod
    def vocabulary() -> dict[str, Any]:
        from app.services.knowledge_graph.vocabulary import vocabulary_document

        return vocabulary_document()

    @staticmethod
    def unavailable_entity_types() -> dict[str, str]:
        """Entity kinds the brief asks about that V2 cannot evidence."""
        return dict(UNAVAILABLE_GRAPH_ENTITIES)


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _as_uuid(value: uuid.UUID | str) -> uuid.UUID | None:
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError):
        return None


def _clamp(value: int, *, minimum: int, maximum: int) -> int:
    return max(minimum, min(int(value), maximum))


def _apply_page_limit(
    graph: BoundedGraph, page_size: int, bounds: GraphBounds
) -> BoundedGraph:
    """Trim to a page size, keeping the root and reporting truncation."""
    if len(graph.nodes) <= page_size and len(graph.edges) <= bounds.max_edges:
        return graph

    keep: set[str] = set()
    if graph.root_node_id:
        keep.add(str(graph.root_node_id))
    ordered = sorted(graph.nodes, key=lambda n: str(n["id"]))
    for node in ordered:
        if len(keep) >= page_size:
            break
        keep.add(node["id"])

    nodes = [n for n in graph.nodes if n["id"] in keep]
    edges = [e for e in graph.edges
             if e["source_node_id"] in keep and e["target_node_id"] in keep]
    graph.nodes = nodes
    graph.edges = edges
    graph.truncated = True
    existing = graph.truncated_reason
    graph.truncated_reason = (
        TruncationReason.PAGE_SIZE.value
        if existing is None
        else f"{existing},{TruncationReason.PAGE_SIZE.value}"
    )
    return graph


__all__ = [
    "BoundedGraph",
    "GraphNodeNotFound",
    "KnowledgeGraphQueries",
]