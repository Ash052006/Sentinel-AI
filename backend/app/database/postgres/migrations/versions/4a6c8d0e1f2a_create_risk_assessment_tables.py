"""create risk assessment tables

Revision ID: 4a6c8d0e1f2a
Revises: 72c9d41e8b3f
Create Date: 2026-09-20 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '4a6c8d0e1f2a'
down_revision: Union[str, Sequence[str], None] = '72c9d41e8b3f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('risk_assessments',
    sa.Column('risk_assessment_id', postgresql.UUID(as_uuid=True), nullable=False, comment='Step 11A RiskAssessment.risk_assessment_id.  Unique identity of a persisted assessment — the idempotency key for re-persists.'),
    sa.Column('correlation_id', postgresql.UUID(as_uuid=True), nullable=False, comment='Step 11A RiskAssessment.correlation_id.  The evaluated correlation, referenced by FK; deleted with it (ON DELETE CASCADE).  Not unique — multiple assessments for one correlation are allowed.'),
    sa.Column('score', sa.Float(), nullable=False, comment='Step 11B risk score in [0.0, 1.0] (CHECK-constrained), persisted exactly as the engine produced it.  Never recalculated by persistence.'),
    sa.Column('level', sa.Enum('low', 'medium', 'high', 'critical', name='risk_level', native_enum=False), nullable=False, comment='Controlled risk level (low / medium / high / critical) persisted exactly as scored.  Bookkeeping only; never a verdict.'),
    sa.Column('confidence', sa.Float(), nullable=False, comment='Step 11B assessment confidence in [0.0, 1.0] (CHECK-constrained), persisted exactly as produced.  Independent of score/level; never a risk score.'),
    sa.Column('factors', postgresql.JSONB(astext_type=sa.Text()), nullable=False, comment='Structured Step 11A risk factors (JSONB).  Preserves the structured factors exactly — never flattened into prose or reinterpreted.'),
    sa.Column('evidence', postgresql.JSONB(astext_type=sa.Text()), nullable=False, comment='Structured Step 11A risk evidence (JSONB).  Preserves the structured observations exactly — never flattened into prose.'),
    sa.Column('assessment_metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=False, comment='Safe, non-secret Step 11A assessment metadata (JSONB).'),
    sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False, comment='When the assessment was produced (11A result timestamp, UTC, tz-aware).  Descriptive bookkeeping, not evidence.'),
    sa.Column('provenance', sa.String(length=32), nullable=False, comment='Risk-assessment provenance.  Assessments are derived analytical conclusions and are constrained to RISK_ASSESSED by CHECK constraint; they can never be stored as observed/enriched/reconstructed/detected/correlated.'),
    sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint('score >= 0.0 AND score <= 1.0', name='risk_score_range'),
    sa.CheckConstraint('confidence >= 0.0 AND confidence <= 1.0', name='risk_confidence_range'),
    sa.CheckConstraint("provenance = 'risk_assessed'", name='provenance_risk_assessed'),
    sa.ForeignKeyConstraint(['correlation_id'], ['correlation_results.correlation_id'], name=op.f('fk_risk_assessments_correlation_id_correlation_results'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_risk_assessments'))
    )
    op.create_index(op.f('ix_risk_assessments_risk_assessment_id'), 'risk_assessments', ['risk_assessment_id'], unique=True)
    op.create_index(op.f('ix_risk_assessments_correlation_id'), 'risk_assessments', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_risk_assessments_timestamp'), 'risk_assessments', ['timestamp'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_risk_assessments_timestamp'), table_name='risk_assessments')
    op.drop_index(op.f('ix_risk_assessments_correlation_id'), table_name='risk_assessments')
    op.drop_index(op.f('ix_risk_assessments_risk_assessment_id'), table_name='risk_assessments')
    op.drop_table('risk_assessments')