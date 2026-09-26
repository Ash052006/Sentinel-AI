"""create incident reports table

Revision ID: 8a1b2c3d4e5f
Revises: 7a1b2c3d4e5f
Create Date: 2026-09-25 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '8a1b2c3d4e5f'
down_revision: Union[str, Sequence[str], None] = '7a1b2c3d4e5f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'incident_reports',
        sa.Column('report_id', sa.String(length=36), nullable=False, comment='Unique identity of the report row.'),
        sa.Column('correlation_id', sa.String(length=36), nullable=False, comment='The correlation the report anchors to.  Deliberately a plain UUID with NO foreign key: a report must outlive the correlation lifecycle it cites (mirrors the incident-memory convention).'),
        sa.Column('status', sa.String(length=16), nullable=False, comment='generated / failed (CHECK-pinned).'),
        sa.Column('payload', postgresql.JSONB(astext_type=sa.Text()), nullable=True, comment='The full assembled IncidentReport payload (JSONB).  Present only for generated rows; failed rows never carry partial content.'),
        sa.Column('title', sa.String(length=255), nullable=True, comment='Generated title (generated rows only).'),
        sa.Column('model', sa.String(length=128), nullable=True, comment='Model identifier used (generated rows only).'),
        sa.Column('generated_by', postgresql.UUID(as_uuid=True), nullable=False, comment='Trusted identity that generated the report.'),
        sa.Column('generated_by_role', sa.String(length=32), nullable=False, comment='Role label of the generating actor.'),
        sa.Column('generated_at', sa.DateTime(timezone=True), nullable=True, comment='Completion instant (generated rows only).'),
        sa.Column('error_code', sa.String(length=64), nullable=True, comment='Sanitized structured error code (failed rows only).'),
        sa.Column('error_message', sa.String(length=500), nullable=True, comment='Sanitized human-readable failure reason (failed rows only).'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("status IN ('generated', 'failed')", name='ck_incident_reports_status_allowed'),
        sa.CheckConstraint("(status = 'generated') = (payload IS NOT NULL)", name='ck_incident_reports_generated_has_payload'),
        sa.CheckConstraint("(status = 'failed') = (error_code IS NOT NULL)", name='ck_incident_reports_failed_has_error'),
        sa.ForeignKeyConstraint(['generated_by'], ['users.id'], name='fk_incident_reports_generated_by_users', ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('report_id', name=op.f('pk_incident_reports')),
    )
    op.create_index('ix_incident_reports_correlation_id', 'incident_reports', ['correlation_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_incident_reports_correlation_id', table_name='incident_reports')
    op.drop_table('incident_reports')