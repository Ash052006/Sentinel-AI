"""create detection-as-code tables

Revision ID: 4c8f2d1a9b3e
Revises: a1b2c3d4e5f6
Create Date: 2026-09-23 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '4c8f2d1a9b3e'
down_revision: Union[str, Sequence[str], None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'detection_rule_versions',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False, comment='Detection-as-Code version persistence-row primary key (isolation identity, not evidence).'),
        sa.Column('version_id', postgresql.UUID(as_uuid=True), nullable=False, comment='Deterministic immutable version identity (UUIDv5 over rule_id | version | source_hash).  Unique — two different rule contents can never share a version identity.'),
        sa.Column('rule_id', sa.String(length=128), nullable=False, comment='Stable, unique rule identifier.'),
        sa.Column('version', sa.String(length=32), nullable=False, comment='Strict MAJOR.MINOR.PATCH semantic version; unique together with rule_id.'),
        sa.Column('rule_type', sa.String(length=8), nullable=False, comment='sigma | yara (CHECK-pinned).'),
        sa.Column('severity', sa.String(length=16), nullable=False, comment='low / medium / high / critical (CHECK-pinned).'),
        sa.Column('title', sa.String(length=200), nullable=False, comment='Rule title from the source.'),
        sa.Column('description', sa.String(length=1000), nullable=False, comment='Rule description from the source.'),
        sa.Column('author', sa.String(length=100), nullable=True, comment='Rule author from the source, when present.'),
        sa.Column('status', sa.String(length=32), nullable=True, comment='Documented rule status (stable / experimental / ...).'),
        sa.Column('category', sa.String(length=64), nullable=True, comment='Management category (Sigma logsource or \'file\' for YARA).'),
        sa.Column('source_path', sa.String(length=255), nullable=False, comment='Controlled-repo source path relative to the rules root (never absolute).'),
        sa.Column('hash_algorithm', sa.String(length=16), nullable=False, comment="Only 'sha256' is supported for source integrity."),
        sa.Column('source_hash', sa.String(length=64), nullable=False, comment='Recorded SHA-256 digest of the source file (hex, 64 chars, CHECK-pinned).'),
        sa.Column('tags', postgresql.JSONB(astext_type=sa.Text()), nullable=False, comment='Stable classification tags (JSONB).'),
        sa.Column('enabled', sa.Boolean(), nullable=False, comment='Whether the deployed version is evaluated at runtime.'),
        sa.Column('validation_status', sa.String(length=16), nullable=False, comment='none / validating / validated / failed (CHECK-pinned).'),
        sa.Column('validation_error', sa.String(length=500), nullable=True, comment='Sanitized first validation failure message (never content).'),
        sa.Column('compiled', sa.Boolean(), nullable=False, comment='Real-engine compile success for this version.'),
        sa.Column('positive_passed', sa.Boolean(), nullable=False, comment='Positive fixture matched through the real engine.'),
        sa.Column('negative_passed', sa.Boolean(), nullable=False, comment='Negative fixture stayed silent through the real engine.'),
        sa.Column('rollback_from', postgresql.UUID(as_uuid=True), nullable=True, comment='Id of the version this version replaced via rollback.'),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True, comment='Trusted identity that created this version.'),
        sa.Column('created_by_role', sa.String(length=32), nullable=True, comment='Role label of the creating actor.'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, comment='Version-row insertion timestamp (UTC, tz-aware). Descriptive bookkeeping, not evidence.'),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, comment='Version-row last-update timestamp (UTC, tz-aware).'),
        sa.CheckConstraint("rule_type IN ('sigma', 'yara')", name='ck_detection_rule_versions_detection_as_code_rule_type'),
        sa.CheckConstraint("severity IN ('low', 'medium', 'high', 'critical')", name='ck_detection_rule_versions_detection_as_code_severity'),
        sa.CheckConstraint("validation_status IN ('none', 'validating', 'validated', 'failed')", name='ck_detection_rule_versions_detection_as_code_validation_status'),
        sa.CheckConstraint("length(hash_algorithm) <= 16", name='ck_detection_rule_versions_detection_as_code_hash_algorithm_length'),
        sa.CheckConstraint("length(source_hash) = 64", name='ck_detection_rule_versions_detection_as_code_source_hash_length'),
        sa.CheckConstraint("length(rule_id) <= 128", name='ck_detection_rule_versions_detection_as_code_rule_id_length'),
        sa.CheckConstraint("length(version) <= 32", name='ck_detection_rule_versions_detection_as_code_version_length'),
        sa.CheckConstraint("length(title) <= 200", name='ck_detection_rule_versions_detection_as_code_title_length'),
        sa.CheckConstraint("length(description) <= 1000", name='ck_detection_rule_versions_detection_as_code_description_length'),
        sa.CheckConstraint("length(source_path) <= 255", name='ck_detection_rule_versions_detection_as_code_source_path_length'),
        sa.ForeignKeyConstraint(['rollback_from'], ['detection_rule_versions.id'], name='fk_dac_versions_rollback_from'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], name='fk_dac_versions_created_by_users'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_detection_rule_versions')),
        sa.UniqueConstraint('rule_id', 'version', name='uq_detection_rule_versions_rule_version'),
    )
    op.create_index(op.f('ix_detection_rule_versions_version_id'), 'detection_rule_versions', ['version_id'], unique=True)
    op.create_index(op.f('ix_detection_rule_versions_rule_id'), 'detection_rule_versions', ['rule_id'], unique=False)
    op.create_index(op.f('ix_detection_rule_versions_source_hash'), 'detection_rule_versions', ['source_hash'], unique=False)

    op.create_table(
        'detection_rule_releases',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False, comment='Release lifecycle persistence-row primary key.'),
        sa.Column('release_id', postgresql.UUID(as_uuid=True), nullable=False, comment='Deterministic release identity (UUIDv5 over rule_id | version).  Unique.'),
        sa.Column('version_id', postgresql.UUID(as_uuid=True), nullable=True, comment='Version identity this release targets.'),
        sa.Column('rule_id', sa.String(length=128), nullable=False, comment='Stable, unique rule identifier.'),
        sa.Column('version', sa.String(length=32), nullable=False, comment='Strict semantic version being released; unique together with rule_id.'),
        sa.Column('release_state', sa.String(length=16), nullable=False, comment='draft / validating / validated / released / failed (CHECK-pinned).'),
        sa.Column('deployment_state', sa.String(length=16), nullable=False, comment='undeployed / deployed (CHECK-pinned; deployed implies released).'),
        sa.Column('validated_at', sa.DateTime(timezone=True), nullable=True, comment='When this version validated successfully.'),
        sa.Column('released_at', sa.DateTime(timezone=True), nullable=True, comment='When this version was released.'),
        sa.Column('deployed_at', sa.DateTime(timezone=True), nullable=True, comment='When this version was deployed.'),
        sa.Column('rollback_target_version', sa.String(length=32), nullable=True, comment='Version active immediately before this version was deployed (deterministic rollback reference).'),
        sa.Column('released_by', postgresql.UUID(as_uuid=True), nullable=True, comment='Trusted identity that released the version.'),
        sa.Column('deployed_by', postgresql.UUID(as_uuid=True), nullable=True, comment='Trusted identity that deployed the version.'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, comment='Release-row insertion timestamp (UTC, tz-aware).'),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, comment='Release-row last-update timestamp (UTC, tz-aware).'),
        sa.CheckConstraint("release_state IN ('draft', 'validating', 'validated', 'released', 'failed')", name='ck_detection_rule_releases_detection_as_code_release_state'),
        sa.CheckConstraint("deployment_state IN ('undeployed', 'deployed')", name='ck_detection_rule_releases_detection_as_code_deployment_state'),
        sa.CheckConstraint("deployment_state <> 'deployed' OR release_state = 'released'", name='ck_detection_rule_releases_detection_as_code_deployed_implies_released'),
        sa.CheckConstraint("rollback_target_version IS NULL OR length(rollback_target_version) <= 32", name='ck_detection_rule_releases_detection_as_code_rollback_target_length'),
        sa.ForeignKeyConstraint(['version_id'], ['detection_rule_versions.id'], name='fk_dac_releases_version_id'),
        sa.ForeignKeyConstraint(['released_by'], ['users.id'], name='fk_dac_releases_released_by_users'),
        sa.ForeignKeyConstraint(['deployed_by'], ['users.id'], name='fk_dac_releases_deployed_by_users'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_detection_rule_releases')),
        sa.UniqueConstraint('rule_id', 'version', name='uq_detection_rule_releases_rule_version'),
    )
    op.create_index(op.f('ix_detection_rule_releases_release_id'), 'detection_rule_releases', ['release_id'], unique=True)
    op.create_index(op.f('ix_detection_rule_releases_rule_id'), 'detection_rule_releases', ['rule_id'], unique=False)

    op.create_table(
        'detection_rule_changes',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False, comment='Change-ledger persistence-row primary key.'),
        sa.Column('change_id', postgresql.UUID(as_uuid=True), nullable=False, comment='Deterministic change identity (append-only, never updated).  Unique.'),
        sa.Column('rule_id', sa.String(length=128), nullable=False, comment='Rule affected by the change.'),
        sa.Column('change_kind', sa.String(length=16), nullable=False, comment='initialized / version_added / rolled_back (CHECK-pinned).'),
        sa.Column('from_version', sa.String(length=32), nullable=True, comment='Prior version (None for initial onboarding).'),
        sa.Column('to_version', sa.String(length=32), nullable=False, comment='Version after the change.'),
        sa.Column('to_source_hash', sa.String(length=64), nullable=False, comment='SHA-256 digest of the post-change source (never content; CHECK-pinned hex).'),
        sa.Column('bump_class', sa.String(length=8), nullable=True, comment='major / minor / patch classification of the transition, if any.'),
        sa.Column('change_reason', sa.String(length=500), nullable=True, comment='Accountability reason supplied by the author for the change.'),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True, comment='Trusted identity that performed the change.'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, comment='Change-row insertion timestamp (UTC, tz-aware).'),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, comment='Change-row last-update timestamp (UTC, tz-aware).'),
        sa.CheckConstraint("change_kind IN ('initialized', 'version_added', 'rolled_back')", name='ck_detection_rule_changes_detection_as_code_change_kind'),
        sa.CheckConstraint("length(rule_id) <= 128", name='ck_detection_rule_changes_detection_as_code_change_rule_id_length'),
        sa.CheckConstraint("length(to_version) <= 32", name='ck_detection_rule_changes_detection_as_code_change_version_length'),
        sa.CheckConstraint("to_source_hash ~ '^[0-9a-f]{64}$'", name='ck_detection_rule_changes_detection_as_code_change_source_hash_hex'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_detection_rule_changes')),
    )
    op.create_index(op.f('ix_detection_rule_changes_change_id'), 'detection_rule_changes', ['change_id'], unique=True)
    op.create_index(op.f('ix_detection_rule_changes_rule_id'), 'detection_rule_changes', ['rule_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_detection_rule_changes_rule_id'), table_name='detection_rule_changes')
    op.drop_index(op.f('ix_detection_rule_changes_change_id'), table_name='detection_rule_changes')
    op.drop_table('detection_rule_changes')

    op.drop_index(op.f('ix_detection_rule_releases_rule_id'), table_name='detection_rule_releases')
    op.drop_index(op.f('ix_detection_rule_releases_release_id'), table_name='detection_rule_releases')
    op.drop_table('detection_rule_releases')

    op.drop_index(op.f('ix_detection_rule_versions_source_hash'), table_name='detection_rule_versions')
    op.drop_index(op.f('ix_detection_rule_versions_rule_id'), table_name='detection_rule_versions')
    op.drop_index(op.f('ix_detection_rule_versions_version_id'), table_name='detection_rule_versions')
    op.drop_table('detection_rule_versions')