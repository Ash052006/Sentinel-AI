"""create approval request tables

Revision ID: a1b2c3d4e5f6
Revises: 5b7e9f0a2c3d
Create Date: 2026-09-23 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = '5b7e9f0a2c3d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'approval_requests',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False, comment='V2.16 ApprovalRecord persistence-row primary key (isolation identity, not evidence).'),
        sa.Column('approval_id', postgresql.UUID(as_uuid=True), nullable=False, comment='Deterministic domain identity (UUIDv5 over decision/action/target/requester content).  Unique — one approval = one identity forever.'),
        sa.Column('policy_decision_id', postgresql.UUID(as_uuid=True), nullable=False, comment='The Step 24 policy decision being routed.  Unique — one decision has exactly one approval lifecycle.'),
        sa.Column('correlation_id', postgresql.UUID(as_uuid=True), nullable=False, comment='The Step 10A correlation the decision concerns.  Deliberately a plain UUID with NO foreign key: an approval record must outlive the correlation lifecycle it cites (mirrors the incident-memory convention).'),
        sa.Column('action_type', sa.String(length=32), nullable=False, comment='Proposed action, inherited from Step 24, pinned by CHECK to the six members.  Never supplied by the client.'),
        sa.Column('target', sa.String(length=512), nullable=False, comment='Canonicalized controlled target identifier, structurally validated per action by the Response validator.  Bounded to 512 characters by CHECK.'),
        sa.Column('status', sa.String(length=16), nullable=False, comment='pending / approved / rejected / expired / cancelled (CHECK-pinned).  Terminal states never transition; approved is idempotent and never re-executes.'),
        sa.Column('reason', sa.String(length=500), nullable=False, comment='The decision\u2019s deterministic policy reason, preserved verbatim and bounded to 500 characters by CHECK.'),
        sa.Column('policy_rule_id', sa.String(length=64), nullable=False, comment='The policy rule that required approval (the rule id cited by the decision).'),
        sa.Column('risk_level', sa.String(length=16), nullable=False, comment='Risk level carried from the decision (low/medium/high/critical).'),
        sa.Column('risk_score', sa.Float(), nullable=True, comment='Risk score carried from the decision, when available, in [0.0, 1.0].'),
        sa.Column('confidence', sa.Float(), nullable=True, comment='Confidence carried from the decision, when available, in [0.0, 1.0].'),
        sa.Column('evidence', postgresql.JSONB(astext_type=sa.Text()), nullable=False, comment='Sanitized, structured references preserved from the decision (JSONB) — never fabricated, never rewritten.'),
        sa.Column('decision', postgresql.JSONB(astext_type=sa.Text()), nullable=False, comment='Full Step 24 decision snapshot (JSONB) preserved verbatim so the approved path can reconstruct the exact decision and re-present it to the Step 25 executor.'),
        sa.Column('request_note', sa.String(length=500), nullable=True, comment='Optional secret-free requester note for the human reviewer.'),
        sa.Column('requested_by', postgresql.UUID(as_uuid=True), nullable=False, comment='Authenticated identity of the requester (trusted identity store).'),
        sa.Column('requested_by_role', sa.String(length=32), nullable=False, comment='The requester\u2019s role as read from the trusted identity store.'),
        sa.Column('requested_at', sa.DateTime(timezone=True), nullable=False, comment='Timezone-aware instant the request was created.'),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False, comment='Timezone-aware instant the pending request expires (fixed TTL; lazy-expired, no scheduler).'),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True, comment='Timezone-aware instant a human (or lapse) resolved the request.'),
        sa.Column('resolved_by', postgresql.UUID(as_uuid=True), nullable=True, comment='Authenticated identity of the human who resolved the request.'),
        sa.Column('resolution_reason', sa.String(length=500), nullable=True, comment='The human\u2019s own comment, or the documentary expiry reason.'),
        sa.Column('response_status', sa.String(length=16), nullable=True, comment='What the Step 25 Response layer did after an APPROVED grant (\'executed\'/\'failed\'/\'skipped\'/\'rejected\', CHECK-pinned).  Distinct from and never conflated with the approval status.'),
        sa.Column('response_provider', sa.String(length=64), nullable=True, comment='Which provider ran when an approved grant reached the Response layer (simulated mock in V2.16), or None when nothing ran.'),
        sa.Column('response_error_code', sa.String(length=64), nullable=True, comment='Sanitized response error/rejection code when applicable.'),
        sa.Column('provenance', sa.String(length=32), nullable=False, comment='Envelope-level provenance, constrained by CHECK to approval_reviewed — an approval is a human governance action and can never be stored as any prior value.'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, comment='Approval-row insertion timestamp (UTC, tz-aware).  Descriptive bookkeeping, not evidence.'),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, comment='Approval-row last-update timestamp (UTC, tz-aware).'),
        sa.CheckConstraint("action_type IN ('block_ip', 'block_domain', 'quarantine_file', 'disable_account', 'terminate_session', 'isolate_endpoint')", name='ck_approval_requests_approval_action_type'),
        sa.CheckConstraint("risk_level IN ('low', 'medium', 'high', 'critical')", name='ck_approval_requests_approval_risk_level'),
        sa.CheckConstraint("status IN ('pending', 'approved', 'rejected', 'expired', 'cancelled')", name='ck_approval_requests_approval_status'),
        sa.CheckConstraint("response_status IS NULL OR response_status IN ('executed', 'failed', 'skipped', 'rejected')", name='ck_approval_requests_approval_response_status'),
        sa.CheckConstraint("length(target) <= 512", name='ck_approval_requests_approval_target_length'),
        sa.CheckConstraint("length(reason) <= 500", name='ck_approval_requests_approval_reason_length'),
        sa.CheckConstraint("length(policy_rule_id) <= 64", name='ck_approval_requests_approval_rule_id_length'),
        sa.CheckConstraint("request_note IS NULL OR length(request_note) <= 500", name='ck_approval_requests_approval_request_note_length'),
        sa.CheckConstraint("length(requested_by_role) <= 32", name='ck_approval_requests_approval_requested_by_role_length'),
        sa.CheckConstraint("resolution_reason IS NULL OR length(resolution_reason) <= 500", name='ck_approval_requests_approval_resolution_reason_length'),
        sa.CheckConstraint('risk_score IS NULL OR (risk_score >= 0.0 AND risk_score <= 1.0)', name='ck_approval_requests_approval_risk_score_range'),
        sa.CheckConstraint('confidence IS NULL OR (confidence >= 0.0 AND confidence <= 1.0)', name='ck_approval_requests_approval_confidence_range'),
        sa.CheckConstraint("provenance = 'approval_reviewed'", name='ck_approval_requests_approval_provenance'),
        sa.CheckConstraint("status = 'pending' OR resolved_at IS NOT NULL", name='ck_approval_requests_approval_resolved_at'),
        sa.CheckConstraint("status IN ('pending', 'expired') OR resolved_by IS NOT NULL", name='ck_approval_requests_approval_resolved_by'),
        sa.ForeignKeyConstraint(['requested_by'], ['users.id'], name='fk_approval_requests_requested_by_users'),
        sa.ForeignKeyConstraint(['resolved_by'], ['users.id'], name='fk_approval_requests_resolved_by_users'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_approval_requests')),
    )
    op.create_index(op.f('ix_approval_requests_approval_id'), 'approval_requests', ['approval_id'], unique=True)
    op.create_index(op.f('ix_approval_requests_policy_decision_id'), 'approval_requests', ['policy_decision_id'], unique=True)
    op.create_index(op.f('ix_approval_requests_correlation_id'), 'approval_requests', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_approval_requests_status'), 'approval_requests', ['status'], unique=False)
    op.create_index(op.f('ix_approval_requests_requested_at'), 'approval_requests', ['requested_at'], unique=False)
    op.create_index(op.f('ix_approval_requests_expires_at'), 'approval_requests', ['expires_at'], unique=False)
    op.create_index(op.f('ix_approval_requests_provenance'), 'approval_requests', ['provenance'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_approval_requests_provenance'), table_name='approval_requests')
    op.drop_index(op.f('ix_approval_requests_expires_at'), table_name='approval_requests')
    op.drop_index(op.f('ix_approval_requests_requested_at'), table_name='approval_requests')
    op.drop_index(op.f('ix_approval_requests_status'), table_name='approval_requests')
    op.drop_index(op.f('ix_approval_requests_correlation_id'), table_name='approval_requests')
    op.drop_index(op.f('ix_approval_requests_policy_decision_id'), table_name='approval_requests')
    op.drop_index(op.f('ix_approval_requests_approval_id'), table_name='approval_requests')
    op.drop_table('approval_requests')