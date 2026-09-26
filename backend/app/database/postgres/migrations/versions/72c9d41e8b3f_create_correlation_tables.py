"""create correlation persistence tables

Revision ID: 72c9d41e8b3f
Revises: e2f4a6c8d1e3
Create Date: 2026-09-19 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '72c9d41e8b3f'
down_revision: Union[str, Sequence[str], None] = 'e2f4a6c8d1e3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('correlation_results',
    sa.Column('correlation_id', postgresql.UUID(as_uuid=True), nullable=False, comment='Step 10A CorrelationResult.correlation_id.  Unique identity of a persisted correlation — the idempotency key for re-persists.'),
    sa.Column('status', sa.Enum('candidate', 'active', 'closed', name='correlation_status', native_enum=False), nullable=False, comment='Neutral lifecycle state of the correlation (candidate / active / closed).  Bookkeeping only; never a verdict.'),
    sa.Column('confidence', sa.Float(), nullable=True, comment='Optional correlation-level confidence in [0.0, 1.0] (CHECK-constrained).  NULL when the engine produced no numeric confidence; never an aggregate of detection confidence and never a risk score.'),
    sa.Column('evidence', postgresql.JSONB(astext_type=sa.Text()), nullable=False, comment="Structured correlation evidence (JSONB).  Holds the engine's structured non-secret evidence — never a raw rule, event, or detection payload blob."),
    sa.Column('result_metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=False, comment='Optional safe, non-secret correlation metadata (JSONB).'),
    sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False, comment='When the correlation was established (10A result timestamp, UTC, tz-aware).  Descriptive bookkeeping, not evidence.'),
    sa.Column('provenance', sa.String(length=32), nullable=False, comment='Correlation provenance.  Correlations are derived analytical conclusions and are constrained to CORRELATED by CHECK constraint; they can never be stored as observed/enriched/reconstructed/detected.'),
    sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint('confidence IS NULL OR (confidence >= 0.0 AND confidence <= 1.0)', name='correlation_confidence_range'),
    sa.CheckConstraint("provenance = 'correlated'", name='provenance_correlated'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_correlation_results'))
    )
    op.create_index(op.f('ix_correlation_results_correlation_id'), 'correlation_results', ['correlation_id'], unique=True)
    op.create_index(op.f('ix_correlation_results_timestamp'), 'correlation_results', ['timestamp'], unique=False)
    op.create_table('correlation_members',
    sa.Column('correlation_id', postgresql.UUID(as_uuid=True), nullable=False, comment='Step 10A CorrelationResult.correlation_id.  Identifies the parent correlation; deleted with it (ON DELETE CASCADE).'),
    sa.Column('detection_id', postgresql.UUID(as_uuid=True), nullable=False, comment='Exact identity of the referenced detection.  A reference, not a copy of the DetectionResult record.'),
    sa.Column('event_id', postgresql.UUID(as_uuid=True), nullable=False, comment='Exact identity of the source security event for the member detection.  Preserved; never replaced with a correlation/incident/alert identifier.'),
    sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False, comment="The member detection's own evaluation timestamp (Step 10A member timestamp).  A descriptive temporal boundary, not correlation evidence."),
    sa.Column('member_order', sa.Integer(), nullable=False, comment='0-based position of the member within the correlation.  Preserves the Step 10A members order exactly.'),
    sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['correlation_id'], ['correlation_results.correlation_id'], name=op.f('fk_correlation_members_correlation_id_correlation_results'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_correlation_members')),
    sa.UniqueConstraint('correlation_id', 'member_order', name='uq_correlation_members_correlation_order')
    )
    op.create_index(op.f('ix_correlation_members_detection_id'), 'correlation_members', ['detection_id'], unique=False)
    op.create_index(op.f('ix_correlation_members_event_id'), 'correlation_members', ['event_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_correlation_members_event_id'), table_name='correlation_members')
    op.drop_index(op.f('ix_correlation_members_detection_id'), table_name='correlation_members')
    op.drop_table('correlation_members')
    op.drop_index(op.f('ix_correlation_results_timestamp'), table_name='correlation_results')
    op.drop_index(op.f('ix_correlation_results_correlation_id'), table_name='correlation_results')
    op.drop_table('correlation_results')