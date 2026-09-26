"""create soar tables

Revision ID: 6a1b2c3d4e5f
Revises: 5d9e0b7c2f4a6d81
Create Date: 2026-09-24 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '6a1b2c3d4e5f'
down_revision: Union[str, Sequence[str], None] = '5d9e0b7c2f4a6d81'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'soar_playbooks',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('playbook_id', sa.String(length=128), nullable=False, comment='Stable, allow-listed playbook identifier (unique).'),
        sa.Column('name', sa.String(length=200), nullable=False, comment='Human-readable playbook name.'),
        sa.Column('description', sa.String(length=1000), nullable=False, comment='Secret-free playbook description.'),
        sa.Column('schema_version', sa.String(length=16), nullable=False, comment='Declarative playbook schema version (1.0.0 only).'),
        sa.Column('version', sa.String(length=32), nullable=False, comment='Current active semantic version of the playbook.'),
        sa.Column('version_id', postgresql.UUID(as_uuid=True), nullable=False, comment='Deterministic identity of the current active version (UUIDv5 over playbook_id|version|source_hash).'),
        sa.Column('source_hash', sa.String(length=64), nullable=False, comment='Recorded SHA-256 digest of the canonical definition (hex).'),
        sa.Column('primary_action', sa.String(length=32), nullable=False, comment='The action the playbook orchestrates (CHECK-pinned).'),
        sa.Column('failure_policy', sa.String(length=32), nullable=False, comment='stop_on_failure | continue_on_failure (CHECK-pinned).'),
        sa.Column('steps', postgresql.JSONB(astext_type=sa.Text()), nullable=False, comment="Read mirror of the active version's declarative steps."),
        sa.Column('enabled', sa.Boolean(), nullable=False, comment='Whether the playbook may be executed.'),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True, comment='Trusted identity that registered this playbook.'),
        sa.Column('created_by_role', sa.String(length=32), nullable=True, comment='Role label of the registering actor.'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("length(playbook_id) <= 128", name='ck_soar_playbooks_soar_playbooks_playbook_id_length'),
        sa.CheckConstraint("length(name) <= 200", name='ck_soar_playbooks_soar_playbooks_name_length'),
        sa.CheckConstraint("length(description) <= 1000", name='ck_soar_playbooks_soar_playbooks_description_length'),
        sa.CheckConstraint("length(schema_version) <= 16", name='ck_soar_playbooks_soar_playbooks_schema_version_length'),
        sa.CheckConstraint("length(version) <= 32", name='ck_soar_playbooks_soar_playbooks_version_length'),
        sa.CheckConstraint("primary_action IN ('block_ip', 'block_domain', 'quarantine_file', 'disable_account', 'terminate_session', 'isolate_endpoint')", name='ck_soar_playbooks_soar_playbooks_primary_action'),
        sa.CheckConstraint("failure_policy IN ('stop_on_failure', 'continue_on_failure')", name='ck_soar_playbooks_soar_playbooks_failure_policy'),
        sa.CheckConstraint("length(source_hash) = 64", name='ck_soar_playbooks_soar_playbooks_source_hash_length'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], name='fk_soar_playbooks_created_by_users'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_soar_playbooks')),
    )
    op.create_index(op.f('ix_soar_playbooks_playbook_id'), 'soar_playbooks', ['playbook_id'], unique=True)
    op.create_index(op.f('ix_soar_playbooks_version_id'), 'soar_playbooks', ['version_id'], unique=True)

    op.create_table(
        'soar_playbook_versions',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('playbook_row_id', postgresql.UUID(as_uuid=True), nullable=True, comment='The playbook row this version belongs to.'),
        sa.Column('version_id', postgresql.UUID(as_uuid=True), nullable=False, comment='Deterministic immutable version identity (UUIDv5 over playbook_id|version|source_hash).'),
        sa.Column('playbook_id', sa.String(length=128), nullable=False, comment='Stable playbook identifier (mirrored for history reads).'),
        sa.Column('version', sa.String(length=32), nullable=False, comment='Strict MAJOR.MINOR.PATCH semantic version (unique with playbook_id).'),
        sa.Column('source_hash', sa.String(length=64), nullable=False, comment='Recorded SHA-256 digest of the canonical definition (hex).'),
        sa.Column('definition', postgresql.JSONB(astext_type=sa.Text()), nullable=False, comment='The immutable declarative definition of this version (JSONB).'),
        sa.Column('status', sa.String(length=16), nullable=False, comment='active | superseded (CHECK-pinned).'),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True, comment='Trusted identity that registered this version.'),
        sa.Column('created_by_role', sa.String(length=32), nullable=True, comment='Role label of the registering actor.'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("length(playbook_id) <= 128", name='ck_soar_playbook_versions_soar_playbook_versions_playbo_8e19'),
        sa.CheckConstraint("length(version) <= 32", name='ck_soar_playbook_versions_soar_playbook_versions_version_length'),
        sa.CheckConstraint("status IN ('active', 'superseded')", name='ck_soar_playbook_versions_soar_playbook_versions_status'),
        sa.CheckConstraint("length(source_hash) = 64", name='ck_soar_playbook_versions_soar_playbook_versions_source_377d'),
        sa.ForeignKeyConstraint(['playbook_row_id'], ['soar_playbooks.id'], name='fk_soar_playbook_versions_playbook_id'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], name='fk_soar_playbook_versions_created_by_users'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_soar_playbook_versions')),
        sa.UniqueConstraint('playbook_id', 'version', name='uq_soar_playbook_versions_playbook_version'),
    )
    op.create_index(op.f('ix_soar_playbook_versions_version_id'), 'soar_playbook_versions', ['version_id'], unique=True)
    op.create_index(op.f('ix_soar_playbook_versions_playbook_id'), 'soar_playbook_versions', ['playbook_id'], unique=False)

    op.create_table(
        'soar_executions',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('execution_id', postgresql.UUID(as_uuid=True), nullable=False, comment='Deterministic domain identity of this execution (unique).'),
        sa.Column('idempotency_key', sa.String(length=128), nullable=False, comment='Content-derived SHA-256 idempotency key (policy decision, approval, response, playbook, target, action).  Unique.'),
        sa.Column('policy_decision_id', postgresql.UUID(as_uuid=True), nullable=False, comment='The authorizing Step 24 policy decision.'),
        sa.Column('correlation_id', postgresql.UUID(as_uuid=True), nullable=False, comment='The correlation the workflow concerns.'),
        sa.Column('approval_id', postgresql.UUID(as_uuid=True), nullable=True, comment='The human approval grant consulted, when applicable.'),
        sa.Column('response_id', postgresql.UUID(as_uuid=True), nullable=False, comment='The Step 25 Response result this run builds upon.'),
        sa.Column('playbook_id', sa.String(length=128), nullable=False, comment='The registered playbook that ran.'),
        sa.Column('playbook_version', sa.String(length=32), nullable=False, comment='The playbook version that ran.'),
        sa.Column('primary_action', sa.String(length=32), nullable=False, comment='The authorized action orchestrated (CHECK-pinned).'),
        sa.Column('target', sa.String(length=512), nullable=False, comment='The canonical target inherited from the decision.'),
        sa.Column('status', sa.String(length=16), nullable=False, comment='pending/running/succeeded/failed/partial/cancelled/rejected.'),
        sa.Column('failure_policy', sa.String(length=32), nullable=False, comment='stop_on_failure | continue_on_failure (CHECK-pinned).'),
        sa.Column('simulated', sa.Boolean(), nullable=False, comment='True only for a dry-run projection (never a real run).'),
        sa.Column('error_code', sa.String(length=64), nullable=True, comment='Sanitized failure/rejection code when applicable.'),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True, comment='Timezone-aware instant execution began (None when rejected).'),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True, comment='Timezone-aware instant execution finished.'),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=False, comment='Trusted identity that requested the run.'),
        sa.Column('created_by_role', sa.String(length=32), nullable=False, comment='Role label of the requesting actor.'),
        sa.Column('execution_metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=False, comment='Structured, secret-free bookkeeping (JSONB).'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("status IN ('pending', 'running', 'succeeded', 'failed', 'partial', 'cancelled', 'rejected')", name='ck_soar_executions_soar_executions_status'),
        sa.CheckConstraint("failure_policy IN ('stop_on_failure', 'continue_on_failure')", name='ck_soar_executions_soar_executions_failure_policy'),
        sa.CheckConstraint("primary_action IN ('block_ip', 'block_domain', 'quarantine_file', 'disable_account', 'terminate_session', 'isolate_endpoint')", name='ck_soar_executions_soar_executions_primary_action'),
        sa.CheckConstraint("length(playbook_id) <= 128", name='ck_soar_executions_soar_executions_playbook_id_length'),
        sa.CheckConstraint("length(target) <= 512", name='ck_soar_executions_soar_executions_target_length'),
        sa.CheckConstraint("length(error_code) <= 64", name='ck_soar_executions_soar_executions_error_code_length'),
        sa.CheckConstraint("completed_at IS NULL OR started_at IS NULL OR completed_at >= started_at", name='ck_soar_executions_soar_executions_time_ordering'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_soar_executions')),
    )
    op.create_index(op.f('ix_soar_executions_execution_id'), 'soar_executions', ['execution_id'], unique=True)
    op.create_index(op.f('ix_soar_executions_idempotency_key'), 'soar_executions', ['idempotency_key'], unique=True)
    op.create_index(op.f('ix_soar_executions_policy_decision_id'), 'soar_executions', ['policy_decision_id'], unique=False)
    op.create_index(op.f('ix_soar_executions_approval_id'), 'soar_executions', ['approval_id'], unique=False)
    op.create_index(op.f('ix_soar_executions_playbook_id'), 'soar_executions', ['playbook_id'], unique=False)

    op.create_table(
        'soar_step_executions',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('step_execution_id', postgresql.UUID(as_uuid=True), nullable=False, comment='Deterministic domain identity of this step execution.'),
        sa.Column('execution_id', postgresql.UUID(as_uuid=True), nullable=False, comment='The parent execution row this step belongs to.'),
        sa.Column('step_number', sa.Integer(), nullable=False, comment='1-based position within the playbook (unique with execution).'),
        sa.Column('label', sa.String(length=120), nullable=False, comment="The step's label."),
        sa.Column('provider_id', sa.String(length=64), nullable=False, comment='The registered provider adapter that ran the step.'),
        sa.Column('operation', sa.String(length=32), nullable=False, comment='The closed operation performed (CHECK-pinned).'),
        sa.Column('target', sa.String(length=512), nullable=False, comment='The canonical target the step applied.'),
        sa.Column('status', sa.String(length=16), nullable=False, comment='pending/running/succeeded/failed/skipped/timed_out/cancelled.'),
        sa.Column('retries_attempted', sa.Integer(), nullable=False, comment='How many retryable attempts occurred before the final one.'),
        sa.Column('error_code', sa.String(length=64), nullable=True, comment='Sanitized failure/rejection code when applicable.'),
        sa.Column('message', sa.String(length=500), nullable=True, comment='Sanitized, template-built message (never raw payloads).'),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True, comment='Timezone-aware instant the step began (None if never run).'),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True, comment='Timezone-aware instant the step finished.'),
        sa.Column('step_metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=False, comment='Structured, secret-free bookkeeping (JSONB).'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("status IN ('pending', 'running', 'succeeded', 'failed', 'skipped', 'timed_out', 'cancelled')", name='ck_soar_step_executions_soar_step_executions_status'),
        sa.CheckConstraint("operation IN ('block_ip', 'block_domain', 'quarantine_file', 'disable_account', 'terminate_session', 'isolate_endpoint')", name='ck_soar_step_executions_soar_step_executions_operation'),
        sa.CheckConstraint('step_number >= 1', name='ck_soar_step_executions_soar_step_executions_step_number_min'),
        sa.CheckConstraint('retries_attempted >= 0 AND retries_attempted <= 3', name='ck_soar_step_executions_soar_step_executions_retries_bounded'),
        sa.CheckConstraint("length(provider_id) <= 64", name='ck_soar_step_executions_soar_step_executions_provider_id_length'),
        sa.CheckConstraint("length(label) <= 120", name='ck_soar_step_executions_soar_step_executions_label_length'),
        sa.CheckConstraint("length(target) <= 512", name='ck_soar_step_executions_soar_step_executions_target_length'),
        sa.CheckConstraint("length(error_code) <= 64", name='ck_soar_step_executions_soar_step_executions_error_code_length'),
        sa.CheckConstraint("length(message) <= 500", name='ck_soar_step_executions_soar_step_executions_message_length'),
        sa.CheckConstraint("completed_at IS NULL OR started_at IS NULL OR completed_at >= started_at", name='ck_soar_step_executions_soar_step_executions_time_ordering'),
        sa.ForeignKeyConstraint(['execution_id'], ['soar_executions.id'], name='fk_soar_step_executions_execution'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_soar_step_executions')),
        sa.UniqueConstraint('execution_id', 'step_number', name='uq_soar_step_executions_execution_step'),
    )
    op.create_index(op.f('ix_soar_step_executions_execution_id'), 'soar_step_executions', ['execution_id'], unique=False)
    op.create_index(op.f('ix_soar_step_executions_step_execution_id'), 'soar_step_executions', ['step_execution_id'], unique=True)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_soar_step_executions_step_execution_id'), table_name='soar_step_executions')
    op.drop_index(op.f('ix_soar_step_executions_execution_id'), table_name='soar_step_executions')
    op.drop_table('soar_step_executions')

    op.drop_index(op.f('ix_soar_executions_playbook_id'), table_name='soar_executions')
    op.drop_index(op.f('ix_soar_executions_approval_id'), table_name='soar_executions')
    op.drop_index(op.f('ix_soar_executions_policy_decision_id'), table_name='soar_executions')
    op.drop_index(op.f('ix_soar_executions_idempotency_key'), table_name='soar_executions')
    op.drop_index(op.f('ix_soar_executions_execution_id'), table_name='soar_executions')
    op.drop_table('soar_executions')

    op.drop_index(op.f('ix_soar_playbook_versions_playbook_id'), table_name='soar_playbook_versions')
    op.drop_index(op.f('ix_soar_playbook_versions_version_id'), table_name='soar_playbook_versions')
    op.drop_table('soar_playbook_versions')

    op.drop_index(op.f('ix_soar_playbooks_version_id'), table_name='soar_playbooks')
    op.drop_index(op.f('ix_soar_playbooks_playbook_id'), table_name='soar_playbooks')
    op.drop_table('soar_playbooks')