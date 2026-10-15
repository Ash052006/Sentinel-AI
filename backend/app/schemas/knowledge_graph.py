"""Knowledge graph API schemas — V3.22.

Response contracts only.  Every field is either an identifier, a closed-vocabulary
value, or an explicitly redacted value; no raw V2 payload is ever modeled here.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class GraphNodeResponse(BaseModel):
    """One persisted V2 entity represented as a node."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(description="Deterministic graph node id (uuid5).")
    node_type: str = Field(description="Closed node vocabulary value.")
    source_id: str = Field(description="Native V2 identifier, verbatim.")
    label: str = Field(description="Bounded, redacted human-readable identity.")
    source_reference: str = Field(
        description="Typed reference to the persisted V2 entity, e.g. 'detection:<id>'."
    )
    provenance: str = Field(description="Closed provenance vocabulary value.")
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Allowlisted, redacted scalar metadata only.",
    )
    observed_at: str | None = Field(default=None)


class GraphEdgeResponse(BaseModel):
    """One real persisted V2 relationship represented as an edge."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(description="Deterministic graph edge id (uuid5).")
    relationship_type: str = Field(
        description="Closed relationship vocabulary value."
    )
    source_node_id: str
    target_node_id: str
    source_reference: str = Field(
        description="The exact persisted V2 row/column justifying this edge."
    )
    evidence_references: list[str] = Field(
        description="Sorted, non-empty list of real persisted V2 references."
    )


class GraphBoundsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_nodes: int
    max_edges: int
    max_depth: int
    max_page_size: int


class GraphTraversalResponse(BaseModel):
    """A bounded graph traversal with explicit truncation reporting."""

    model_config = ConfigDict(extra="forbid")

    root_node_id: str | None = None
    nodes: list[GraphNodeResponse] = Field(default_factory=list)
    edges: list[GraphEdgeResponse] = Field(default_factory=list)
    node_count: int = 0
    edge_count: int = 0
    max_depth_reached: int = 0
    truncated: bool = Field(
        description="True when a bound was hit. Truncation is never silent."
    )
    truncated_reason: str | None = Field(
        default=None,
        description="Which bound was hit, e.g. max_nodes / max_edges / max_depth / page_size.",
    )
    bounds: GraphBoundsResponse
    unavailable_entity_types: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Entity kinds the graph cannot represent because V2 persists no "
            "identity for them."
        ),
    )


class GraphVocabularyResponse(BaseModel):
    """The closed node/relationship vocabulary and its source-of-truth."""

    model_config = ConfigDict(extra="forbid")

    node_types: list[dict[str, Any]]
    relationship_types: list[dict[str, Any]]
    unavailable_entity_types: dict[str, str]
    bounds: dict[str, int]


__all__ = [
    "GraphBoundsResponse",
    "GraphEdgeResponse",
    "GraphNodeResponse",
    "GraphTraversalResponse",
    "GraphVocabularyResponse",
]