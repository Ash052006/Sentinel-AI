"""Knowledge Graph API — V3.22, read-only transport.

Exposes the bounded, deterministic knowledge-graph queries as a thin,
authenticated, RBAC-protected FastAPI surface.

Architecture::

    HTTP request
        -> JWT authentication (existing get_current_user dependency)
        -> RBAC authorization (existing require_role: admin/analyst/ciso)
        -> KnowledgeGraphQueries (bounded, read-only)
        -> GraphTraversalResponse / GraphNodeResponse / GraphVocabularyResponse
        -> HTTP response

Design principles:

* **Read-only** — only ``GET`` endpoints exist.  Graph state is written solely
  by the deterministic builder (``app.cli build-knowledge-graph``); no graph
  route ever builds, mutates, or repairs the graph.  A read must never cause a
  write.
* **Thin transport** — each route validates input, calls one query method, and
  returns a schema.  No route constructs SQL or filters in Python.
* **Bounded** — every traversal is capped on nodes, edges, and depth, and
  reports truncation explicitly.  No request can return an unbounded graph.
* **Deterministic** — nodes and edges are returned in sorted-id order, so two
  identical requests produce byte-identical payloads.
* **No LLM, no RAG, no network** — the read path is pure database access.
* **Reuses existing V2 security** — the existing ``HTTPBearer`` dependency and
  ``require_role`` factory are used verbatim.  There is no anonymous endpoint.

Route ordering note: the collection root ``/vocabulary`` is registered before
the ``/nodes/...`` and ``/correlations/...`` parameterised routes so a literal
path segment can never be parsed as an identifier.
"""

from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_db, require_role
from app.models.user import User
from app.schemas.knowledge_graph import (
    GraphBoundsResponse,
    GraphNodeResponse,
    GraphTraversalResponse,
    GraphVocabularyResponse,
)
from app.services.knowledge_graph.queries import (
    GraphNodeNotFound,
    KnowledgeGraphQueries,
)
from app.services.knowledge_graph.vocabulary import DEFAULT_BOUNDS

logger = logging.getLogger(__name__)

router = APIRouter(
    # No prefix here: app/api/router.py supplies "/knowledge-graph" and
    # app.main mounts that under "/api", giving /api/knowledge-graph/...
    tags=["knowledge-graph"],
)

#: SOC read access, identical to the existing V2 read conventions.
GRAPH_READ_ROLES = ("admin", "analyst", "ciso")


def _queries() -> KnowledgeGraphQueries:
    return KnowledgeGraphQueries(DEFAULT_BOUNDS)


def _bounds_response() -> GraphBoundsResponse:
    return GraphBoundsResponse(
        max_nodes=DEFAULT_BOUNDS.max_nodes,
        max_edges=DEFAULT_BOUNDS.max_edges,
        max_depth=DEFAULT_BOUNDS.max_depth,
        max_page_size=DEFAULT_BOUNDS.max_page_size,
    )


@router.get(
    "/vocabulary",
    response_model=GraphVocabularyResponse,
    summary="Knowledge graph node and relationship vocabulary",
)
def get_vocabulary(
    current_user: User = Depends(require_role(*GRAPH_READ_ROLES)),
) -> GraphVocabularyResponse:
    """Return the closed vocabulary with each type's V2 source-of-truth.

    Read-only and requires SOC read access.  Intentionally does not touch the
    database: the vocabulary is static and self-describing, which is what makes
    the edge vocabulary auditable.
    """
    document = _queries().vocabulary()
    return GraphVocabularyResponse(**document)


@router.get(
    "/correlations/{correlation_id}",
    response_model=GraphTraversalResponse,
    summary="Bounded knowledge graph for one correlation",
)
def get_correlation_graph(
    correlation_id: str = Path(
        ...,
        description="Correlation UUID (correlation_results.correlation_id).",
        min_length=36,
        max_length=36,
    ),
    max_depth: int = Query(
        DEFAULT_BOUNDS.max_depth,
        ge=1,
        le=DEFAULT_BOUNDS.max_depth,
        description="Traversal depth bound; the response reports truncation.",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*GRAPH_READ_ROLES)),
) -> GraphTraversalResponse:
    """Return the bounded, correlation-centered graph.

    404 when the correlation has no persisted graph node — which includes the
    case where the correlation itself does not exist, so the endpoint does not
    disclose the existence of non-graph correlations.
    """
    return _correlation_graph_response(db, correlation_id, max_depth)


@router.get(
    "/nodes/{node_id}",
    response_model=GraphNodeResponse,
    summary="One knowledge graph node with its persisted source information",
)
def get_graph_node(
    node_id: str = Path(
        ...,
        description="Graph node UUID (deterministic uuid5).",
        min_length=36,
        max_length=36,
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*GRAPH_READ_ROLES)),
) -> GraphNodeResponse:
    """Return one node, including the source reference an auditor needs."""
    try:
        node = _queries().get_node(db, node_id)
    except GraphNodeNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    return GraphNodeResponse(**node)


@router.get(
    "/nodes/{node_id}/neighbors",
    response_model=GraphTraversalResponse,
    summary="Bounded neighbor set of one knowledge graph node",
)
def get_graph_node_neighbors(
    node_id: str = Path(
        ...,
        description="Graph node UUID (deterministic uuid5).",
        min_length=36,
        max_length=36,
    ),
    max_depth: int = Query(
        1,
        ge=1,
        le=DEFAULT_BOUNDS.max_depth,
        description="Neighbor traversal depth bound.",
    ),
    limit: int = Query(
        DEFAULT_BOUNDS.default_page_size,
        ge=1,
        le=DEFAULT_BOUNDS.max_page_size,
        description="Maximum nodes returned; truncation is reported explicitly.",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*GRAPH_READ_ROLES)),
) -> GraphTraversalResponse:
    """Return the bounded neighbor subgraph around one node.

    Pagination bounds node count; the response sets ``truncated`` and
    ``truncated_reason`` rather than silently trimming.
    """
    try:
        graph = _queries().get_neighbors(
            db, node_id, max_depth=max_depth, limit=limit
        )
    except GraphNodeNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc

    return GraphTraversalResponse(
        root_node_id=str(graph.root_node_id) if graph.root_node_id else None,
        nodes=graph.nodes,
        edges=graph.edges,
        node_count=graph.node_count,
        edge_count=graph.edge_count,
        max_depth_reached=graph.max_depth_reached,
        truncated=graph.truncated,
        truncated_reason=graph.truncated_reason,
        bounds=_bounds_response(),
    )


@router.get(
    "/{correlation_id}",
    response_model=GraphTraversalResponse,
    summary="Bounded knowledge graph for one correlation (short form)",
    include_in_schema=False,
)
def get_correlation_graph_short(
    correlation_id: uuid.UUID = Path(
        ...,
        description="Correlation UUID (correlation_results.correlation_id).",
    ),
    max_depth: int = Query(
        DEFAULT_BOUNDS.max_depth,
        ge=1,
        le=DEFAULT_BOUNDS.max_depth,
        description="Traversal depth bound; the response reports truncation.",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*GRAPH_READ_ROLES)),
) -> GraphTraversalResponse:
    """Compatibility alias for ``GET /api/knowledge-graph/{correlation_id}``.

    The namespaced ``/correlations/{correlation_id}`` route above is the
    canonical spelling; this one exists so the shortest documented path also
    works.  It is declared *after* ``/vocabulary`` and the multi-segment
    ``/nodes/...`` and ``/correlations/...`` routes so a literal segment can
    never be parsed as an identifier, and the typed ``uuid.UUID`` parameter
    means a non-UUID segment is rejected with 422 rather than looked up.
    """
    return _correlation_graph_response(db, correlation_id, max_depth)


def _correlation_graph_response(
    db: Session, correlation_id: uuid.UUID | str, max_depth: int
) -> GraphTraversalResponse:
    """Run one bounded correlation traversal and shape the response.

    A missing correlation node is reported as 404, which covers both "no such
    correlation" and "correlation is not in the graph" without disclosing which.
    """
    try:
        graph = _queries().get_correlation_graph(db, correlation_id, max_depth=max_depth)
    except GraphNodeNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc

    return GraphTraversalResponse(
        root_node_id=str(graph.root_node_id) if graph.root_node_id else None,
        nodes=graph.nodes,
        edges=graph.edges,
        node_count=graph.node_count,
        edge_count=graph.edge_count,
        max_depth_reached=graph.max_depth_reached,
        truncated=graph.truncated,
        truncated_reason=graph.truncated_reason,
        bounds=_bounds_response(),
        unavailable_entity_types=KnowledgeGraphQueries.unavailable_entity_types(),
    )


__all__ = ["GRAPH_READ_ROLES", "router"]