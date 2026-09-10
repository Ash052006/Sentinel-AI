"""create threat intel tables

Revision ID: 8c0b00d20101
Revises: f121c4c8aa7d
Create Date: 2026-09-06 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '8c0b00d20101'
down_revision: Union[str, Sequence[str], None] = 'f121c4c8aa7d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('threat_intel_indicators',
    sa.Column('value', sa.String(length=2048), nullable=False, comment='Indicator value exactly as extracted.  No URL canonicalization is performed; Step 8A intentionally keeps URLs as-is.'),
    sa.Column('indicator_type', sa.Enum('ip', 'domain', 'url', 'hash', name='indicator_type', native_enum=False), nullable=False),
    sa.Column('canonical_key', sa.String(length=2200), nullable=False, comment='Deterministic Step 8A deduplication key `{type}:{normalized_value}`.  Enforces indicator global uniqueness for the same normalized type+value.'),
    sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_threat_intel_indicators')),
    sa.UniqueConstraint('indicator_type', 'value', name='uq_threat_intel_indicators_type_value')
    )
    op.create_index(op.f('ix_threat_intel_indicators_canonical_key'), 'threat_intel_indicators', ['canonical_key'], unique=True)
    op.create_index(op.f('ix_threat_intel_indicators_indicator_type'), 'threat_intel_indicators', ['indicator_type'], unique=False)
    op.create_index(op.f('ix_threat_intel_indicators_value'), 'threat_intel_indicators', ['value'], unique=False)
    op.create_table('threat_intel_lookups',
    sa.Column('event_id', postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column('indicator_id', postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column('provider', sa.String(length=255), nullable=False),
    sa.Column('status', sa.Enum('success', 'error', name='lookup_status', native_enum=False), nullable=False),
    sa.Column('performed_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('retryable', sa.Boolean(), nullable=True),
    sa.Column('error_type', sa.String(length=64), nullable=True),
    sa.Column('error_message', sa.Text(), nullable=True, comment='Secret-safe human-readable error message.'),
    sa.Column('found', sa.Boolean(), nullable=True),
    sa.Column('confidence', sa.Float(), nullable=True, comment='Optional confidence in [0.0, 1.0].'),
    sa.Column('result_timestamp', sa.DateTime(timezone=True), nullable=True),
    sa.Column('evidence', postgresql.JSONB(astext_type=sa.Text()), nullable=True, comment="Structured provider-specific evidence (JSONB).  This holds the provider's structured payload \u2014 never a raw HTTP response or a dump-everything blob."),
    sa.Column('result_metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=True, comment='Optional safe, non-secret provider metadata (JSONB).'),
    sa.Column('provenance', sa.String(length=32), nullable=False, comment='Evidence provenance.  Threat-intelligence evidence is enrichment and is constrained to ENRICHED by CHECK constraint; it can never be stored as observed/reconstructed.'),
    sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("provenance = 'enriched'", name='provenance_enriched'),
    sa.ForeignKeyConstraint(['indicator_id'], ['threat_intel_indicators.id'], name=op.f('fk_threat_intel_lookups_indicator_id_threat_intel_indicators')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_threat_intel_lookups'))
    )
    op.create_index(op.f('ix_threat_intel_lookups_event_id'), 'threat_intel_lookups', ['event_id'], unique=False)
    op.create_index(op.f('ix_threat_intel_lookups_indicator_id'), 'threat_intel_lookups', ['indicator_id'], unique=False)
    op.create_index(op.f('ix_threat_intel_lookups_performed_at'), 'threat_intel_lookups', ['performed_at'], unique=False)
    op.create_index(op.f('ix_threat_intel_lookups_provider'), 'threat_intel_lookups', ['provider'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_threat_intel_lookups_provider'), table_name='threat_intel_lookups')
    op.drop_index(op.f('ix_threat_intel_lookups_performed_at'), table_name='threat_intel_lookups')
    op.drop_index(op.f('ix_threat_intel_lookups_indicator_id'), table_name='threat_intel_lookups')
    op.drop_index(op.f('ix_threat_intel_lookups_event_id'), table_name='threat_intel_lookups')
    op.drop_table('threat_intel_lookups')
    op.drop_index(op.f('ix_threat_intel_indicators_value'), table_name='threat_intel_indicators')
    op.drop_index(op.f('ix_threat_intel_indicators_indicator_type'), table_name='threat_intel_indicators')
    op.drop_index(op.f('ix_threat_intel_indicators_canonical_key'), table_name='threat_intel_indicators')
    op.drop_table('threat_intel_indicators')
