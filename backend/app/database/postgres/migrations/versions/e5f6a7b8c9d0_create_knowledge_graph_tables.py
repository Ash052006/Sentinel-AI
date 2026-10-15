"""create knowledge graph node and edge tables (V3.22)

Adds the relational persistence for the V3.22 Knowledge Graph Engine.  The
graph is a relationship/index layer over existing V2 evidence: it stores no
V2 record content, only a deterministic node id, the V2 native identifier, a
bounded label, an allowlisted metadata subset, and provenance.

``knowledge_graph_nodes``
    UNIQUE (node_type, source_id) makes a duplicate node impossible and makes
    the builder idempotent, since the node id is a deterministic uuid5 of that
    same natural key.

``knowledge_graph_edges``
    UNIQUE (source_node_id, target_node_id, relationship_type) makes a
    duplicate edge impossible.  Both endpoints are foreign keys with
    ON DELETE CASCADE, so an edge cannot outlive its endpoint nodes and the
    graph cannot accumulate structurally orphaned edges.

Every edge carries ``source_reference`` plus a non-empty
``evidence_references`` list of real persisted V2 entity references, so an
auditor can always prove why the edge exists.  There is no default on
``metadata``/``evidence_references`` at the database level; the defaults live
in the ORM so an INSERT that bypasses the application still cannot produce a
row with empty evidence.

No V2 table is altered and no existing row is touched.

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a1b2c3
Create Date: 2026-10-04 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'e5f6a7b8c9d0'
down_revision: Union[str, Sequence[str], None] = 'd4e5f6a1b2c3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_SOURCE_ID_LENGTH = 64
_REFERENCE_LENGTH = 160
_LABEL_LENGTH = 512
_TYPE_LENGTH = 48
_PROVENANCE_LENGTH = 48


def upgrade() -> None:
    op.create_table(
        'knowledge_graph_nodes',
        sa.Column('node_type', sa.String(length=_TYPE_LENGTH), nullable=False,
                  comment='Closed node vocabulary value (see knowledge_graph.vocabulary).'),
        sa.Column('source_id', sa.String(length=_SOURCE_ID_LENGTH), nullable=False,
                  comment='Native V2 identifier this node represents, verbatim.'),
        sa.Column('source_reference', sa.String(length=_REFERENCE_LENGTH), nullable=False,
                  comment="Typed reference, e.g. 'detection:<detection_id>'."),
        sa.Column('provenance', sa.String(length=_PROVENANCE_LENGTH), nullable=False,
                  comment='Closed provenance vocabulary value.'),
        sa.Column('label', sa.String(length=_LABEL_LENGTH), nullable=False,
                  comment='Bounded human-readable identity; never raw payload.'),
        sa.Column('metadata', sa.JSON(), nullable=False,
                  comment='Allowlisted, redacted scalar metadata only.'),
        sa.Column('observed_at', sa.DateTime(timezone=True), nullable=True,
                  comment='Deterministic timestamp used for ordering (V2 entity observation '
                          'time, or build time for reference-only nodes).'),
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id', name='pk_knowledge_graph_nodes'),
        sa.UniqueConstraint('node_type', 'source_id',
                            name='uq_knowledge_graph_nodes_node_type_source_id'),
    )
    op.create_index('ix_knowledge_graph_nodes_node_type',
                    'knowledge_graph_nodes', ['node_type'])
    op.create_index('ix_knowledge_graph_nodes_source_id',
                    'knowledge_graph_nodes', ['source_id'])

    op.create_table(
        'knowledge_graph_edges',
        sa.Column('source_node_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('target_node_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('relationship_type', sa.String(length=_TYPE_LENGTH), nullable=False,
                  comment='Closed relationship vocabulary value.'),
        sa.Column('source_reference', sa.String(length=_REFERENCE_LENGTH), nullable=False,
                  comment="The exact persisted V2 row/column justifying this edge, e.g. "
                           "'correlation_member:<id>'."),
        sa.Column('evidence_references', sa.JSON(), nullable=False,
                  comment='Sorted, non-empty list of real persisted V2 entity references.'),
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id', name='pk_knowledge_graph_edges'),
        sa.ForeignKeyConstraint(
            ['source_node_id'], ['knowledge_graph_nodes.id'],
            name='fk_knowledge_graph_edges_source_node_id_knowledge_graph_nodes',
            ondelete='CASCADE'),
        sa.ForeignKeyConstraint(
            ['target_node_id'], ['knowledge_graph_nodes.id'],
            name='fk_knowledge_graph_edges_target_node_id_knowledge_graph_nodes',
            ondelete='CASCADE'),
        sa.UniqueConstraint('source_node_id', 'target_node_id', 'relationship_type',
                            name='uq_knowledge_graph_edges_endpoints_relationship'),
    )
    op.create_index('ix_knowledge_graph_edges_source_node_id',
                    'knowledge_graph_edges', ['source_node_id'])
    op.create_index('ix_knowledge_graph_edges_target_node_id',
                    'knowledge_graph_edges', ['target_node_id'])
    op.create_index('ix_knowledge_graph_edges_relationship_type',
                    'knowledge_graph_edges', ['relationship_type'])


def downgrade() -> None:
    op.drop_index('ix_knowledge_graph_edges_relationship_type',
                  table_name='knowledge_graph_edges')
    op.drop_index('ix_knowledge_graph_edges_target_node_id',
                  table_name='knowledge_graph_edges')
    op.drop_index('ix_knowledge_graph_edges_source_node_id',
                  table_name='knowledge_graph_edges')
    op.drop_table('knowledge_graph_edges')

    op.drop_index('ix_knowledge_graph_nodes_source_id',
                  table_name='knowledge_graph_nodes')
    op.drop_index('ix_knowledge_graph_nodes_node_type',
                  table_name='knowledge_graph_nodes')
    op.drop_table('knowledge_graph_nodes')