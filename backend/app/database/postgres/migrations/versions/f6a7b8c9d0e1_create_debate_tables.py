"""create debate session, round, assessment, argument, and consensus tables (V3.23)

Adds relational persistence for the V3.23 Multi-Agent Debate Engine.

These tables hold **analytical reasoning only**.  Every ``evidence_references``
value is a reference string (for example ``detection:<uuid>``) into persisted V2
evidence; no V2 record content is copied, and the knowledge graph is never
written.  A debate is downstream analytical state, so a debate row may outlive
the V2 row it discusses.

``debate_sessions``
    The primary key is a deterministic ``uuid5`` over
    ``(correlation_id, graph_snapshot_digest, configuration_digest)``.  That
    makes idempotency a database guarantee: repeating a debate over the same
    immutable graph snapshot collides on the key rather than inserting a
    duplicate.  Because the digests are part of the key, changed evidence
    produces a new debate instead of mutating an existing one.

``debate_consensus``
    UNIQUE ``(debate_id)`` allows at most one reconciliation outcome per
    debate.  ``state`` is CHECK-constrained to the four-state closed
    vocabulary, and ``consensus_strength``/``confidence`` are range-constrained,
    so a malformed or out-of-range outcome cannot be persisted.

``debate_arguments``
    Holds arguments and counterarguments, distinguished by a CHECK-constrained
    ``kind``.  A CHECK constraint enforces that ``evidence_references`` is a
    non-empty array, which is the database-level half of the rule that every
    claim must cite real graph evidence.

Every table CHECK-pins ``provenance = 'ai_generated'``.  Debate output is
AI-generated reasoning and must never serialize as observed, detected,
correlated, or risk_assessed provenance, which belong to the V2 entities that
genuinely produced them.  This is why no V2 table or V2 enum is altered.

No V2 table is altered and no existing row is touched.

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-10-04 18:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'f6a7b8c9d0e1'
down_revision: Union[str, Sequence[str], None] = 'e5f6a7b8c9d0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_PROVENANCE_LENGTH = 32
_TYPE_LENGTH = 48
_ID_LENGTH = 64
_DIGEST_LENGTH = 64
_TEXT_LENGTH = 1024


def _pinned_provenance(name: str) -> sa.CheckConstraint:
    return sa.CheckConstraint(
        f"provenance = 'ai_generated'",
        name=name,
    )


def upgrade() -> None:
    op.create_table(
        'debate_sessions',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('correlation_id', postgresql.UUID(as_uuid=True), nullable=False,
                  comment='V2 correlation under debate; a soft reference by design.'),
        sa.Column('graph_snapshot_digest', sa.String(length=_DIGEST_LENGTH), nullable=False,
                  comment='SHA-256 of the canonical bounded V3.22 graph.  Part of the deterministic session identity: a changed graph means a new debate, not a mutated one.'),
        sa.Column('configuration_digest', sa.String(length=_DIGEST_LENGTH), nullable=False,
                  comment='SHA-256 of the bounds and agent roster used for this debate.'),
        sa.Column('status', sa.String(length=24), nullable=False,
                  comment="Lifecycle status; 'failed' records a governed failure, never a fake consensus."),
        sa.Column('provider', sa.String(length=_TYPE_LENGTH), nullable=False,
                  comment='Non-secret provider identifier.'),
        sa.Column('model', sa.String(length=_TYPE_LENGTH), nullable=True,
                  comment='Non-secret model identifier.'),
        sa.Column('engine_version', sa.String(length=_TYPE_LENGTH), nullable=False,
                  comment='Debate engine version.'),
        sa.Column('provenance', sa.String(length=_PROVENANCE_LENGTH), nullable=False,
                  comment='Always ai_generated: debate output is reasoning, not evidence.'),
        sa.Column('session_payload', sa.JSON(), nullable=False,
                  comment='Canonical JSON document of the completed debate. The normalized child tables (rounds, assessments, arguments, consensus) are the queryable and auditable projection of the same write; this column is the lossless read model so a GET returns exactly what the POST produced, including engine-derived facts and evidence scope, which are pure functions of the graph snapshot this session pins.'),
        sa.Column('graph_node_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('graph_edge_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('evidence_reference_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('agent_count', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('failure_code', sa.String(length=_TYPE_LENGTH), nullable=True,
                  comment="Stable failure code when status='failed'; never free-form text."),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        _pinned_provenance('provenance_ai_generated'),
        sa.CheckConstraint(
            "status IN ('pending','running','completed','failed')",
            name='debate_sessions_status_check',
        ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_debate_sessions_correlation_id', 'debate_sessions',
                    ['correlation_id'], unique=False)
    op.create_index('ix_debate_sessions_graph_snapshot_digest', 'debate_sessions',
                    ['graph_snapshot_digest'], unique=False)
    op.create_index('ix_debate_sessions_status', 'debate_sessions',
                    ['status'], unique=False)

    op.create_table(
        'debate_rounds',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('debate_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('round_number', sa.Integer(), nullable=False,
                  comment='0 = shared evidence context; 1-4 = the bounded debate rounds.'),
        sa.Column('round_kind', sa.String(length=_TYPE_LENGTH), nullable=False),
        sa.Column('summary', sa.String(length=_TEXT_LENGTH), nullable=False,
                  comment='Round summary; bounded.'),
        sa.Column('agent_ids', sa.JSON(), nullable=False,
                  comment='Agent ids participating.'),
        sa.Column('argument_ids', sa.JSON(), nullable=False,
                  comment='Argument ids raised.'),
        sa.Column('counterargument_ids', sa.JSON(), nullable=False,
                  comment='Counterargument ids raised.'),
        sa.Column('provenance', sa.String(length=_PROVENANCE_LENGTH), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        _pinned_provenance('provenance_ai_generated'),
        sa.ForeignKeyConstraint(
            ['debate_id'], ['debate_sessions.id'],
            name='fk_debate_rounds_debate_id_debate_sessions',
            ondelete='CASCADE',
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('debate_id', 'round_number',
                            name='uq_debate_rounds_debate_round'),
    )
    op.create_index('ix_debate_rounds_debate_id', 'debate_rounds',
                    ['debate_id'], unique=False)

    op.create_table(
        'debate_agent_assessments',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('debate_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('agent_id', sa.String(length=_ID_LENGTH), nullable=False,
                  comment="Stable 'agent:<role>' identity."),
        sa.Column('role', sa.String(length=_TYPE_LENGTH), nullable=False),
        sa.Column('objective', sa.String(length=_TEXT_LENGTH), nullable=False,
                  comment="The agent's stated objective."),
        sa.Column('confidence', sa.Float(), nullable=False,
                  comment="The agent's own calibrated confidence."),
        sa.Column('observations', sa.JSON(), nullable=False,
                  comment='Evidenced observations as {claim_id, statement, evidence_references, confidence}.  Never facts: facts are engine-derived and stored on the session-level fact list.'),
        sa.Column('hypotheses', sa.JSON(), nullable=False,
                  comment='Interpretations as {claim_id, statement, evidence_references, confidence}.'),
        sa.Column('evidence_references', sa.JSON(), nullable=False,
                  comment='Evidence references as {reference, entity_kind, node_id} pointers into persisted V2 evidence. Pointers only; never copied V2 records.'),
        sa.Column('limitations', sa.JSON(), nullable=False,
                  comment='What the agent could not establish from the supplied evidence.'),
        sa.Column('provenance', sa.String(length=_PROVENANCE_LENGTH), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        _pinned_provenance('provenance_ai_generated'),
        sa.ForeignKeyConstraint(
            ['debate_id'], ['debate_sessions.id'],
            name='fk_debate_agent_assessments_debate_id_debate_sessions',
            ondelete='CASCADE',
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('debate_id', 'agent_id',
                            name='uq_debate_agent_assessments_debate_agent'),
    )
    op.create_index('ix_debate_agent_assessments_debate_id', 'debate_agent_assessments',
                    ['debate_id'], unique=False)

    op.create_table(
        'debate_arguments',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('debate_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('argument_id', sa.String(length=_ID_LENGTH), nullable=False,
                  comment='Deterministic uuid5 of (round, author, target, statement).'),
        sa.Column('kind', sa.String(length=24), nullable=False),
        sa.Column('author_agent_id', sa.String(length=_ID_LENGTH), nullable=False),
        sa.Column('author_role', sa.String(length=_TYPE_LENGTH), nullable=False),
        sa.Column('target_agent_id', sa.String(length=_ID_LENGTH), nullable=True),
        sa.Column('target_role', sa.String(length=_TYPE_LENGTH), nullable=True),
        sa.Column('target_hypothesis_id', sa.String(length=_ID_LENGTH), nullable=True,
                  comment='Hypothesis this argument takes a position on; null for counterarguments.'),
        sa.Column('target_argument_id', sa.String(length=_ID_LENGTH), nullable=True,
                  comment='Argument this counterargument challenges; null for arguments.'),
        sa.Column('stance', sa.String(length=16), nullable=True,
                  comment="'supports' or 'opposes'; null for counterarguments."),
        sa.Column('weakness', sa.String(length=48), nullable=True,
                  comment='Closed weakness vocabulary; null for arguments.'),
        sa.Column('statement', sa.String(length=_TEXT_LENGTH), nullable=False,
                  comment='Bounded analytical statement.'),
        sa.Column('evidence_references', sa.JSON(), nullable=False,
                  comment='Sorted evidence references as {reference, entity_kind, node_id}. Pointers into persisted V2 evidence only: no V2 record content is copied. A CHECK constraint requires at least one.'),
        sa.Column('provenance', sa.String(length=_PROVENANCE_LENGTH), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        _pinned_provenance('provenance_ai_generated'),
        sa.CheckConstraint(
            "kind IN ('argument','counterargument')",
            name='debate_arguments_kind_check',
        ),
        sa.CheckConstraint(
            "json_array_length(evidence_references) > 0",
            name='debate_arguments_evidence_present_check',
        ),
        sa.ForeignKeyConstraint(
            ['debate_id'], ['debate_sessions.id'],
            name='fk_debate_arguments_debate_id_debate_sessions',
            ondelete='CASCADE',
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('debate_id', 'argument_id',
                            name='uq_debate_arguments_debate_argument'),
    )
    op.create_index('ix_debate_arguments_debate_id', 'debate_arguments',
                    ['debate_id'], unique=False)
    op.create_index('ix_debate_arguments_target_hypothesis_id', 'debate_arguments',
                    ['target_hypothesis_id'], unique=False)
    op.create_index('ix_debate_arguments_target_argument_id', 'debate_arguments',
                    ['target_argument_id'], unique=False)

    op.create_table(
        'debate_consensus',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('debate_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('state', sa.String(length=32), nullable=False,
                  comment='Closed consensus vocabulary; never free-form.'),
        sa.Column('leading_hypothesis', sa.String(length=_TEXT_LENGTH), nullable=True,
                  comment='Engine-selected leading hypothesis; null when none was raised.'),
        sa.Column('leading_hypothesis_id', sa.String(length=_ID_LENGTH), nullable=True),
        sa.Column('consensus_strength', sa.Float(), nullable=False, server_default='0',
                  comment='Share of the agent roster supporting the leading hypothesis.'),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0',
                  comment='Deterministically computed from agreement, evidence support, completeness, and contradiction.  Never a blind average.'),
        sa.Column('supporting_argument_ids', sa.JSON(), nullable=False),
        sa.Column('opposing_argument_ids', sa.JSON(), nullable=False),
        sa.Column('dissent', sa.JSON(), nullable=False,
                  comment='Recorded losing positions; a debate never discards them.'),
        sa.Column('unresolved_questions', sa.JSON(), nullable=False),
        sa.Column('evidence_gaps', sa.JSON(), nullable=False,
                  comment='Entity kinds the graph could not supply for this debate.'),
        sa.Column('evidence_references', sa.JSON(), nullable=False),
        sa.Column('provenance', sa.String(length=_PROVENANCE_LENGTH), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        _pinned_provenance('provenance_ai_generated'),
        sa.CheckConstraint(
            "state IN ('consensus','partial_consensus','contested','insufficient_evidence')",
            name='debate_consensus_state_check',
        ),
        sa.CheckConstraint(
            "consensus_strength >= 0.0 AND consensus_strength <= 1.0",
            name='debate_consensus_strength_range_check',
        ),
        sa.CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name='debate_consensus_confidence_range_check',
        ),
        sa.ForeignKeyConstraint(
            ['debate_id'], ['debate_sessions.id'],
            name='fk_debate_consensus_debate_id_debate_sessions',
            ondelete='CASCADE',
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('debate_id', name='uq_debate_consensus_debate_id'),
    )
    op.create_index('ix_debate_consensus_debate_id', 'debate_consensus',
                    ['debate_id'], unique=False)
    op.create_index('ix_debate_consensus_state', 'debate_consensus',
                    ['state'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_debate_consensus_state', table_name='debate_consensus')
    op.drop_index('ix_debate_consensus_debate_id', table_name='debate_consensus')
    op.drop_table('debate_consensus')

    op.drop_index('ix_debate_arguments_target_argument_id', table_name='debate_arguments')
    op.drop_index('ix_debate_arguments_target_hypothesis_id', table_name='debate_arguments')
    op.drop_index('ix_debate_arguments_debate_id', table_name='debate_arguments')
    op.drop_table('debate_arguments')

    op.drop_index('ix_debate_agent_assessments_debate_id', table_name='debate_agent_assessments')
    op.drop_table('debate_agent_assessments')

    op.drop_index('ix_debate_rounds_debate_id', table_name='debate_rounds')
    op.drop_table('debate_rounds')

    op.drop_index('ix_debate_sessions_status', table_name='debate_sessions')
    op.drop_index('ix_debate_sessions_graph_snapshot_digest', table_name='debate_sessions')
    op.drop_index('ix_debate_sessions_correlation_id', table_name='debate_sessions')
    op.drop_table('debate_sessions')