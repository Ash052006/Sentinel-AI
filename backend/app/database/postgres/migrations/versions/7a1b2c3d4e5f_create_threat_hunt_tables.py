"""create threat hunt tables

Revision ID: 7a1b2c3d4e5f
Revises: 6a1b2c3d4e5f
Create Date: 2026-09-24 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '7a1b2c3d4e5f'
down_revision: Union[str, Sequence[str], None] = '6a1b2c3d4e5f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'threat_hunts',
        sa.Column('hunt_id', sa.String(length=36), nullable=False, comment='Unique identity of the hunt.'),
        sa.Column('name', sa.String(length=120), nullable=False, comment='Analyst-assigned hunt name.'),
        sa.Column('description', sa.Text(), nullable=False, comment='Analyst description (free-form, not executed).'),
        sa.Column('hunt_type', sa.String(length=64), nullable=False, comment='Closed hunt template identifier.'),
        sa.Column('status', sa.String(length=32), nullable=False, comment='Closed lifecycle status.'),
        sa.Column('start_time', sa.DateTime(timezone=True), nullable=False, comment='Start of the bounded hunting window.'),
        sa.Column('end_time', sa.DateTime(timezone=True), nullable=False, comment='End of the bounded hunting window (exclusive).'),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=False, comment='Trusted identity that created the hunt.'),
        sa.Column('created_by_role', sa.String(length=32), nullable=False, comment='Role label of the creating actor.'),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True, comment='When the run began.'),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True, comment='When the run completed or failed.'),
        sa.Column('filters', postgresql.JSONB(astext_type=sa.Text()), nullable=False, comment='Persisted structured filters (JSONB array of objects).'),
        sa.Column('result_count', sa.Integer(), nullable=False, comment='Total evidence items collected by the run.'),
        sa.Column('finding_count', sa.Integer(), nullable=False, comment='Total findings produced by the run.'),
        sa.Column('timeline_count', sa.Integer(), nullable=False, comment='Total timeline items produced by the run.'),
        sa.Column('error_code', sa.String(length=64), nullable=True, comment='Sanitized structured error code when the run failed.'),
        sa.Column('error_message', sa.String(length=500), nullable=True, comment='Sanitized human-readable error message when the run failed.'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("hunt_type IN ('authentication_anomaly', 'indicator_hunt', 'privilege_activity', 'multi_stage_activity', 'detection_review')", name='ck_threat_hunts_hunt_type_allowed'),
        sa.CheckConstraint("status IN ('draft', 'running', 'completed', 'failed', 'cancelled')", name='ck_threat_hunts_status_allowed'),
        sa.CheckConstraint('end_time > start_time', name='ck_threat_hunts_bounded_window'),
sa.ForeignKeyConstraint(['created_by'], ['users.id'], name='fk_threat_hunts_created_by_users'),
        sa.PrimaryKeyConstraint('hunt_id', name=op.f('pk_threat_hunts')),
    )
    op.create_table(
        'threat_hunt_evidence',
        sa.Column('hunt_id', sa.String(length=36), nullable=False, comment='Owning hunt.'),
        sa.Column('evidence_id', sa.String(length=36), nullable=False, comment='Deterministic artifact id within the hunt.'),
        sa.Column('evidence_key', sa.String(length=64), nullable=False, comment='Closed evidence key (surface/provenance edge).'),
        sa.Column('evidence_type', sa.String(length=32), nullable=False, comment='Closed evidence kind.'),
        sa.Column('reference_id', sa.String(length=36), nullable=False, comment='Identity of the referenced existing record.'),
        sa.Column('event_id', sa.String(length=36), nullable=True),
        sa.Column('correlation_id', sa.String(length=36), nullable=True),
        sa.Column('provenance', sa.String(length=32), nullable=False, comment='Inherited envelope provenance.'),
        sa.Column('severity', sa.String(length=16), nullable=True, comment='Inherited severity/level when the source carries one.'),
        sa.Column('subject', sa.String(length=255), nullable=True, comment='Deterministic grouping subject carried from the source record (e.g. actor IP, indicator value).'),
        sa.Column('observed_at', sa.DateTime(timezone=True), nullable=True, comment='The source record\'s own event timestamp.'),
        sa.Column('title', sa.String(length=200), nullable=False, comment='Short deterministic descriptor.'),
        sa.Column('summary', sa.String(length=500), nullable=False, comment='Deterministic, secret-free one-line summary.'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("evidence_type IN ('audit_log', 'detection', 'correlation', 'correlation_member', 'risk_assessment', 'indicator', 'indicator_lookup', 'incident_memory')", name='ck_threat_hunt_evidence_evidence_type_allowed'),
        sa.CheckConstraint("provenance IN ('correlated', 'detected', 'enriched', 'observed', 'recalled', 'risk_assessed')", name='ck_threat_hunt_evidence_provenance_allowed'),
        sa.ForeignKeyConstraint(['hunt_id'], ['threat_hunts.hunt_id'], name='fk_threat_hunt_evidence_hunt_id_threat_hunts'),
        sa.PrimaryKeyConstraint('hunt_id', 'evidence_id', name=op.f('pk_threat_hunt_evidence')),
    )
    op.create_index('ix_threat_hunt_evidence_hunt_observed', 'threat_hunt_evidence', ['hunt_id', 'observed_at'], unique=False)
    op.create_index('ix_threat_hunt_evidence_hunt_provenance', 'threat_hunt_evidence', ['hunt_id', 'provenance'], unique=False)

    op.create_table(
        'threat_hunt_findings',
        sa.Column('hunt_id', sa.String(length=36), nullable=False, comment='Owning hunt.'),
        sa.Column('finding_id', sa.String(length=36), nullable=False, comment='Deterministic artifact id within the hunt.'),
        sa.Column('title', sa.String(length=200), nullable=False, comment='Short deterministic finding title.'),
        sa.Column('description', sa.String(length=1000), nullable=False, comment='Deterministic, evidence-derived description.'),
        sa.Column('severity', sa.String(length=16), nullable=True, comment='Inherited severity/level when defensible from evidence.'),
        sa.Column('provenance', sa.String(length=32), nullable=False, comment='Provenance of the underlying evidence.'),
        sa.Column('observed_at', sa.DateTime(timezone=True), nullable=True, comment='Earliest evidence timestamp in the finding.'),
        sa.Column('evidence_ids', postgresql.JSONB(astext_type=sa.Text()), nullable=False, comment='Bounded list of hunt-scoped evidence ids (JSONB).'),
        sa.Column('context', postgresql.JSONB(astext_type=sa.Text()), nullable=False, comment='Deterministic grouping context (JSONB; e.g. rule_id, counts).'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("provenance IN ('correlated', 'detected', 'enriched', 'observed', 'recalled', 'risk_assessed')", name='ck_threat_hunt_findings_provenance_allowed'),
        sa.ForeignKeyConstraint(['hunt_id'], ['threat_hunts.hunt_id'], name='fk_threat_hunt_findings_hunt_id_threat_hunts'),
        sa.PrimaryKeyConstraint('hunt_id', 'finding_id', name=op.f('pk_threat_hunt_findings')),
    )

    op.create_table(
        'threat_hunt_timeline_items',
        sa.Column('hunt_id', sa.String(length=36), nullable=False, comment='Owning hunt.'),
        sa.Column('timeline_item_id', sa.String(length=36), nullable=False, comment='Deterministic artifact id within the hunt.'),
        sa.Column('evidence_id', sa.String(length=36), nullable=False, comment='The hunt-scoped evidence item this entry references.'),
        sa.Column('reference_id', sa.String(length=36), nullable=False, comment='Underlying existing record identity.'),
        sa.Column('observed_at', sa.DateTime(timezone=True), nullable=True, comment='Chronological key: the evidence\'s own timestamp.'),
        sa.Column('evidence_type', sa.String(length=32), nullable=False, comment='Evidence kind of the referenced item.'),
        sa.Column('evidence_summary', sa.String(length=500), nullable=False, comment='Deterministic summary copied from the referenced evidence.'),
        sa.Column('provenance', sa.String(length=32), nullable=False, comment='Provenance of the referenced evidence.'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("evidence_type IN ('audit_log', 'detection', 'correlation', 'correlation_member', 'risk_assessment', 'indicator', 'indicator_lookup', 'incident_memory')", name='ck_threat_hunt_timeline_items_evidence_type_allowed'),
        sa.CheckConstraint("provenance IN ('correlated', 'detected', 'enriched', 'observed', 'recalled', 'risk_assessed')", name='ck_threat_hunt_timeline_items_provenance_allowed'),
        sa.ForeignKeyConstraint(['hunt_id'], ['threat_hunts.hunt_id'], name='fk_threat_hunt_timeline_items_hunt_id_threat_hunts'),
        sa.PrimaryKeyConstraint('hunt_id', 'timeline_item_id', name=op.f('pk_threat_hunt_timeline_items')),
    )
    op.create_index('ix_threat_hunt_timeline_hunt_observed', 'threat_hunt_timeline_items', ['hunt_id', 'observed_at'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_threat_hunt_timeline_hunt_observed', table_name='threat_hunt_timeline_items')
    op.drop_table('threat_hunt_timeline_items')

    op.drop_table('threat_hunt_findings')

    op.drop_index('ix_threat_hunt_evidence_hunt_provenance', table_name='threat_hunt_evidence')
    op.drop_index('ix_threat_hunt_evidence_hunt_observed', table_name='threat_hunt_evidence')
    op.drop_table('threat_hunt_evidence')

    op.drop_table('threat_hunts')