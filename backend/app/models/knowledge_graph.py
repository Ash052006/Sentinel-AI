"""Relational knowledge-graph persistence — V3.22.

Two tables form a relationship/index layer over existing SentinelAI V2
records.  **No V2 record is duplicated here**: a graph node stores only a
deterministic id, the V2 native identifier, a bounded label, an explicit
allowlisted metadata subset, and provenance.

Design points that matter for auditability:

* ``id`` is a deterministic ``uuid5`` of the natural key, so identical V2
  state always produces identical rows (determinism) and re-running the
  builder is idempotent.
* UNIQUE ``(node_type, source_id)`` makes a duplicate node impossible.
* UNIQUE ``(source_node_id, target_node_id, relationship_type)`` makes a
  duplicate edge impossible.
* Both edge endpoints are foreign keys with ``ON DELETE CASCADE``, so the
  graph cannot accumulate structurally orphaned edges.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.postgres.base import Base, UUIDTimestampMixin

#: Varchar widths. Node source ids are V2 UUIDs (36 chars) except hunt ids
#: (varchar 36) and indicator values, which are addressed by row id, so 64 is
#: ample. References are ``prefix:identifier``; 128 is ample for all.
_SOURCE_ID_LENGTH = 64
_REFERENCE_LENGTH = 160
_LABEL_LENGTH = 512
_TYPE_LENGTH = 48
_PROVENANCE_LENGTH = 48


class KnowledgeGraphNode(UUIDTimestampMixin, Base):
    """One persisted V2 entity, represented as a graph node."""

    __tablename__ = "knowledge_graph_nodes"

    __table_args__ = (
        UniqueConstraint(
            "node_type",
            "source_id",
            name="uq_knowledge_graph_nodes_node_type_source_id",
        ),
        Index("ix_knowledge_graph_nodes_node_type", "node_type"),
        Index("ix_knowledge_graph_nodes_source_id", "source_id"),
    )

    node_type: Mapped[str] = mapped_column(
        String(_TYPE_LENGTH),
        nullable=False,
        comment="Closed node vocabulary value (see knowledge_graph.vocabulary).",
    )
    source_id: Mapped[str] = mapped_column(
        String(_SOURCE_ID_LENGTH),
        nullable=False,
        comment="Native V2 identifier this node represents, verbatim.",
    )
    source_reference: Mapped[str] = mapped_column(
        String(_REFERENCE_LENGTH),
        nullable=False,
        comment="Typed reference, e.g. 'detection:<detection_id>'.",
    )
    provenance: Mapped[str] = mapped_column(
        String(_PROVENANCE_LENGTH),
        nullable=False,
        comment="Closed provenance vocabulary value.",
    )
    label: Mapped[str] = mapped_column(
        String(_LABEL_LENGTH),
        nullable=False,
        default="",
        comment="Bounded human-readable identity; never raw payload.",
    )
    node_metadata: Mapped[dict] = mapped_column(
        "metadata",
        JSON,
        nullable=False,
        default=dict,
        comment="Allowlisted, redacted scalar metadata only.",
    )
    observed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment=(
            "Deterministic timestamp used for ordering (V2 entity observation "
            "time, or build time for reference-only nodes)."
        ),
    )

    outgoing_edges: Mapped[list["KnowledgeGraphEdge"]] = relationship(
        "KnowledgeGraphEdge",
        back_populates="source_node",
        foreign_keys="KnowledgeGraphEdge.source_node_id",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    incoming_edges: Mapped[list["KnowledgeGraphEdge"]] = relationship(
        "KnowledgeGraphEdge",
        back_populates="target_node",
        foreign_keys="KnowledgeGraphEdge.target_node_id",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return (
            f"<KnowledgeGraphNode {self.node_type}:{self.source_id} "
            f"provenance={self.provenance}>"
        )


class KnowledgeGraphEdge(UUIDTimestampMixin, Base):
    """One real persisted V2 relationship, represented as a graph edge."""

    __tablename__ = "knowledge_graph_edges"

    __table_args__ = (
        UniqueConstraint(
            "source_node_id",
            "target_node_id",
            "relationship_type",
            name="uq_knowledge_graph_edges_endpoints_relationship",
        ),
        Index("ix_knowledge_graph_edges_source_node_id", "source_node_id"),
        Index("ix_knowledge_graph_edges_target_node_id", "target_node_id"),
        Index("ix_knowledge_graph_edges_relationship_type", "relationship_type"),
    )

    source_node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "knowledge_graph_nodes.id",
            ondelete="CASCADE",
            name="fk_knowledge_graph_edges_source_node_id_knowledge_graph_nodes",
        ),
        nullable=False,
    )
    target_node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "knowledge_graph_nodes.id",
            ondelete="CASCADE",
            name="fk_knowledge_graph_edges_target_node_id_knowledge_graph_nodes",
        ),
        nullable=False,
    )
    relationship_type: Mapped[str] = mapped_column(
        String(_TYPE_LENGTH),
        nullable=False,
        comment="Closed relationship vocabulary value.",
    )
    source_reference: Mapped[str] = mapped_column(
        String(_REFERENCE_LENGTH),
        nullable=False,
        comment=(
            "The exact persisted V2 row/column justifying this edge, e.g. "
            "'correlation_member:<id>'."
        ),
    )
    evidence_references: Mapped[list] = mapped_column(
        JSON,
        nullable=False,
        default=list,
        comment="Sorted, non-empty list of real persisted V2 entity references.",
    )

    source_node: Mapped[KnowledgeGraphNode] = relationship(
        "KnowledgeGraphNode",
        back_populates="outgoing_edges",
        foreign_keys=[source_node_id],
    )
    target_node: Mapped[KnowledgeGraphNode] = relationship(
        "KnowledgeGraphNode",
        back_populates="incoming_edges",
        foreign_keys=[target_node_id],
    )

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return (
            f"<KnowledgeGraphEdge {self.relationship_type} "
            f"{self.source_node_id}->{self.target_node_id}>"
        )


__all__ = ["KnowledgeGraphEdge", "KnowledgeGraphNode"]