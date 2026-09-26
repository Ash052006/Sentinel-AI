"""create incident memory tables

Revision ID: 5b7e9f0a2c3d
Revises: 4a6c8d0e1f2a
Create Date: 2026-09-21 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '5b7e9f0a2c3d'
down_revision: Union[str, Sequence[str], None] = '4a6c8d0e1f2a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

#: Shared alphanumeric-identifier pattern used for the DB-side provenance /
#: type pinning of Step 17 structured content.
def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'incident_memories',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False, comment='Step 17 IncidentMemory envelope primary key (isolation identity; not evidence).'),
        sa.Column('memory_id', postgresql.UUID(as_uuid=True), nullable=False, comment='Step 16 IncidentMemory.memory_id — the idempotency identity of a recalled memory.  One memory_id = one persisted envelope forever; re-persisting the same UUID is a no-op.'),
        sa.Column('memory_type', sa.String(length=24), nullable=False, comment='Step 16 MemoryType value (incident_summary / indicator_observation / attack_pattern / investigation_finding / mitigation_outcome).  Pinned by CHECK to the five Step 16 members.'),
        sa.Column('title', sa.String(length=200), nullable=False, comment='Short human-readable title of the recalled memory.  Bounded to 200 characters by CHECK.'),
        sa.Column('summary', sa.String(length=2000), nullable=False, comment='Optional plain-language summary of the memory.  Bounded to 2000 characters by CHECK.'),
        sa.Column('confidence', sa.Float(), nullable=True, comment='Optional memory confidence in [0.0, 1.0] (CHECK-constrained; never a risk score).'),
        sa.Column('provenance', sa.String(length=24), nullable=False, comment='Envelope-level provenance.  Incident memory is historical — always RECALLED, enforced by CHECK, so a recalled memory can never masquerade as observed/enriched/detected evidence.'),
        sa.Column('correlation_id', postgresql.UUID(as_uuid=True), nullable=True, comment='Optional Step 10A correlation the memory recalls.  Deliberately stored as a plain UUID with NO foreign key: historical memory must outlive the correlation lifecycle it cites (documented in incident_memory_persistence.md).'),
        sa.Column('sources', postgresql.JSONB(astext_type=sa.Text()), nullable=False, comment='Structured source references (JSONB) — non-secret, bounded, already-redacted by the Step 17 service.'),
        sa.Column('indicators', postgresql.JSONB(astext_type=sa.Text()), nullable=False, comment='Structured indicator references (JSONB) — non-secret, bounded, already-redacted.'),
        sa.Column('entities', postgresql.JSONB(astext_type=sa.Text()), nullable=False, comment='Structured entity references (JSONB) — non-secret, bounded, already-redacted.'),
        sa.Column('techniques', postgresql.JSONB(astext_type=sa.Text()), nullable=False, comment='Structured technique references (JSONB) — non-secret, bounded, already-redacted.'),
        sa.Column('findings', postgresql.JSONB(astext_type=sa.Text()), nullable=False, comment='Structured investigation findings (JSONB) — non-secret, bounded, already-redacted.'),
        sa.Column('actions', postgresql.JSONB(astext_type=sa.Text()), nullable=False, comment='Structured recommended actions (JSONB) — non-secret, bounded, already-redacted.'),
        sa.Column('outcomes', postgresql.JSONB(astext_type=sa.Text()), nullable=False, comment='Structured outcome references (JSONB) — non-secret, bounded, already-redacted.'),
        sa.Column('memory_metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=False, comment='Structured memory metadata (JSONB) — non-secret, bounded, already-redacted. Provenance of individual references preserved verbatim inside; the envelope-level provenance value is always RECALLED.'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, comment='Step 17 insertion timestamp (UTC, tz-aware).  Descriptive bookkeeping, not evidence and never a verdict.'),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, comment='Step 17 last-update timestamp (UTC, tz-aware).  Historical memory is immutable; updated_at generally equals created_at.'),
        sa.CheckConstraint("char_length(title) <= 200", name='ck_incident_memories_incident_memory_title_length'),
        sa.CheckConstraint("char_length(summary) <= 2000", name='ck_incident_memories_incident_memory_summary_length'),
        sa.CheckConstraint('confidence IS NULL OR (confidence >= 0.0 AND confidence <= 1.0)', name='ck_incident_memories_incident_memory_confidence_range'),
        sa.CheckConstraint("provenance = 'recalled'", name='ck_incident_memories_incident_memory_provenance_recalled'),
        sa.CheckConstraint("memory_type IN ('incident_summary', 'indicator_observation', 'attack_pattern', 'investigation_finding', 'mitigation_outcome')", name='ck_incident_memories_incident_memory_memory_type'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_incident_memories')),
    )
    op.create_index(op.f('ix_incident_memories_memory_id'), 'incident_memories', ['memory_id'], unique=True)
    op.create_index(op.f('ix_incident_memories_correlation_id'), 'incident_memories', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_incident_memories_provenance'), 'incident_memories', ['provenance'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_incident_memories_provenance'), table_name='incident_memories')
    op.drop_index(op.f('ix_incident_memories_correlation_id'), table_name='incident_memories')
    op.drop_index(op.f('ix_incident_memories_memory_id'), table_name='incident_memories')
    op.drop_table('incident_memories')
