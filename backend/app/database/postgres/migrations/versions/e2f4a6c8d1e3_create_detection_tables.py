"""create detection persistence tables

Revision ID: e2f4a6c8d1e3
Revises: 8c0b00d20101
Create Date: 2026-09-12 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'e2f4a6c8d1e3'
down_revision: Union[str, Sequence[str], None] = '8c0b00d20101'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('detection_results',
    sa.Column('event_id', postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column('detection_id', postgresql.UUID(as_uuid=True), nullable=False, comment='Step 9A DetectionResult.detection_id.  Unique identity of a persisted detection match — the idempotency key for re-persists.'),
    sa.Column('rule_id', sa.String(length=255), nullable=False),
    sa.Column('rule_type', sa.Enum('sigma', 'yara', name='rule_type', native_enum=False), nullable=False),
    sa.Column('rule_version', sa.String(length=64), nullable=False, comment="Version of the evaluated rule.  Falls back to 'unknown' when the result metadata carries no rule version."),
    sa.Column('severity', sa.Enum('low', 'medium', 'high', 'critical', name='detection_severity', native_enum=False), nullable=False),
    sa.Column('matched', sa.Boolean(), nullable=False, comment='Always true.  The agent only emits matched results, and the CHECK constraint is the database-level enforcement; non-matches are represented by the absence of a row.'),
    sa.Column('confidence', sa.Float(), nullable=False, comment='Engine confidence in [0.0, 1.0] (CHECK-constrained).'),
    sa.Column('evidence', postgresql.JSONB(astext_type=sa.Text()), nullable=False, comment="Structured match evidence (JSONB).  Holds the engine's structured non-secret evidence — never a raw rule or event payload blob."),
    sa.Column('result_metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=False, comment='Optional safe, non-secret evaluation metadata (JSONB).'),
    sa.Column('detected_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('provenance', sa.String(length=32), nullable=False, comment='Evidence provenance.  Detection evidence is a derived analytical conclusion and is constrained to DETECTED by CHECK constraint; it can never be stored as observed/enriched/reconstructed.'),
    sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint('matched = true', name='detection_matched_required'),
    sa.CheckConstraint('confidence >= 0.0 AND confidence <= 1.0', name='detection_confidence_range'),
    sa.CheckConstraint("provenance = 'detected'", name='provenance_detected'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_detection_results'))
    )
    op.create_index(op.f('ix_detection_results_detected_at'), 'detection_results', ['detected_at'], unique=False)
    op.create_index(op.f('ix_detection_results_detection_id'), 'detection_results', ['detection_id'], unique=True)
    op.create_index(op.f('ix_detection_results_event_id'), 'detection_results', ['event_id'], unique=False)
    op.create_index(op.f('ix_detection_results_rule_id'), 'detection_results', ['rule_id'], unique=False)
    op.create_index(op.f('ix_detection_results_severity'), 'detection_results', ['severity'], unique=False)
    op.create_table('detection_rule_failures',
    sa.Column('event_id', postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column('engine', sa.String(length=64), nullable=False),
    sa.Column('rule_id', sa.String(length=255), nullable=False),
    sa.Column('error_type', sa.String(length=64), nullable=False),
    sa.Column('error_message', sa.Text(), nullable=False, comment='Secret-safe human-readable error message.'),
    sa.Column('failed_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('provenance', sa.String(length=32), nullable=False, comment='Evidence provenance.  Detection failures are analytical outcomes of the detection phase and are constrained to DETECTED by CHECK constraint.'),
    sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("provenance = 'detected'", name='provenance_detected'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_detection_rule_failures'))
    )
    op.create_index(op.f('ix_detection_rule_failures_engine'), 'detection_rule_failures', ['engine'], unique=False)
    op.create_index(op.f('ix_detection_rule_failures_event_id'), 'detection_rule_failures', ['event_id'], unique=False)
    op.create_index(op.f('ix_detection_rule_failures_failed_at'), 'detection_rule_failures', ['failed_at'], unique=False)
    op.create_index(op.f('ix_detection_rule_failures_rule_id'), 'detection_rule_failures', ['rule_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_detection_rule_failures_rule_id'), table_name='detection_rule_failures')
    op.drop_index(op.f('ix_detection_rule_failures_failed_at'), table_name='detection_rule_failures')
    op.drop_index(op.f('ix_detection_rule_failures_event_id'), table_name='detection_rule_failures')
    op.drop_index(op.f('ix_detection_rule_failures_engine'), table_name='detection_rule_failures')
    op.drop_table('detection_rule_failures')
    op.drop_index(op.f('ix_detection_results_severity'), table_name='detection_results')
    op.drop_index(op.f('ix_detection_results_rule_id'), table_name='detection_results')
    op.drop_index(op.f('ix_detection_results_event_id'), table_name='detection_results')
    op.drop_index(op.f('ix_detection_results_detection_id'), table_name='detection_results')
    op.drop_index(op.f('ix_detection_results_detected_at'), table_name='detection_results')
    op.drop_table('detection_results')