"""create playbook tables

V3.25 — AI Playbook Generation.

Four tables record a *proposal*: the session, its ordered steps, the actions
within them, and the evidence each action cites.  They store references and
reasoning text only; no V2 record, no V3.22 graph row, no V3.23 debate row and
no V3.24 prediction row is duplicated or modified.

Two guarantees are enforced here rather than in application code.

``provenance`` is CHECK-pinned to ``ai_generated`` on every table, so a
regression that tried to persist a proposal as ``observed``, ``detected``,
``correlated`` or ``risk_assessed`` fails the constraint instead of quietly
writing evidence.

``playbook_sessions.lifecycle`` is CHECK-pinned to ``('proposed',
'approval_required')``.  Together with the *absence* of any execution-outcome,
result or gate-timestamp column anywhere in this schema, that makes "this
playbook was approved and executed" unrepresentable here rather than merely
absent.  Granting a human gate and dispatching a response belong to the HITL and
response subsystems; this schema only ever records that a gate is *expected*, and
it never records that one was passed.

Column comments are duplicated verbatim from the ORM models.  They are written
out rather than imported on purpose: a migration is a snapshot of one moment, so
a later model edit must not silently rewrite history.  ``alembic check``
compares comments, so both copies have to agree.

Revision ID: b8c9d0e1f2a3
Revises: a7b8c9d0e1f2
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "b8c9d0e1f2a3"
down_revision: str | None = "a7b8c9d0e1f2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('playbook_sessions',
    sa.Column('correlation_id', postgresql.UUID(as_uuid=True), nullable=False, comment='V2 correlation addressed; a soft reference by design.'),
    sa.Column('graph_snapshot_digest', sa.String(length=64), nullable=False, comment='SHA-256 of the canonical bounded V3.22 graph that was read.'),
    sa.Column('playbook_configuration_digest', sa.String(length=64), nullable=False, comment='SHA-256 of the bounds and engine version used for this run.'),
    sa.Column('debate_id', postgresql.UUID(as_uuid=True), nullable=True, comment='V3.23 debate consumed; NULL when none was available.'),
    sa.Column('prediction_session_id', postgresql.UUID(as_uuid=True), nullable=True, comment='V3.24 prediction session consumed; NULL when none was available.'),
    sa.Column('status', sa.String(length=32), nullable=False, comment="Session outcome. 'insufficient_evidence' is a successful outcome, not an error: declining to propose is correct when no persisted evidence resolves to an addressable target."),
    sa.Column('lifecycle', sa.String(length=32), nullable=False, comment="Only 'proposed' and 'approval_required' are permitted. Approved, executing, executed and verified are structurally unrepresentable here; those states belong to the approval and response subsystems."),
    sa.Column('engine_version', sa.String(length=64), nullable=False, comment='Playbook engine version.'),
    sa.Column('action_count', sa.Integer(), nullable=False, comment='Actions proposed in this run.'),
    sa.Column('step_count', sa.Integer(), nullable=False, comment='Ordered steps in this run.'),
    sa.Column('approval_required_count', sa.Integer(), nullable=False, comment='Actions the frozen table classifies as approval_required.'),
    sa.Column('not_executable_count', sa.Integer(), nullable=False, comment='Actions with no execution path today. Recorded explicitly so a proposal is never mistaken for an executable plan.'),
    sa.Column('confidence', sa.Float(), nullable=False, comment='Mean confidence of the proposed actions: how well supported the proposal is. Not execution probability, not risk, not prediction confidence.'),
    sa.Column('graph_node_count', sa.Integer(), nullable=False, comment='Bounded graph nodes consumed.'),
    sa.Column('graph_edge_count', sa.Integer(), nullable=False, comment='Bounded graph edges consumed.'),
    sa.Column('target_count', sa.Integer(), nullable=False, comment='Indicator values that passed structural target validation.'),
    sa.Column('provenance', sa.String(length=32), nullable=False, comment='Always ai_generated: a proposal is neither evidence nor a finding.'),
    sa.Column('playbook_payload', sa.JSON(), nullable=False, comment='Canonical JSON document of the completed run. The normalized child tables are the queryable projection of the same write; this column is the lossless read model, so a GET returns exactly what the POST produced. Contains no prompt text, no API key, no provider payload and no source record content.'),
    sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("lifecycle IN ('proposed', 'approval_required')", name=op.f('ck_playbook_sessions_playbook_sessions_lifecycle_check')),
    sa.CheckConstraint("provenance = 'ai_generated'", name=op.f('ck_playbook_sessions_provenance_ai_generated')),
    sa.CheckConstraint("status IN ('proposed', 'insufficient_evidence', 'contested')", name=op.f('ck_playbook_sessions_playbook_sessions_status_check')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_playbook_sessions'))
    )
    op.create_index(
        "ix_playbook_sessions_correlation_id", "playbook_sessions", ['correlation_id'], unique=False
    )
    op.create_index(
        "ix_playbook_sessions_graph_snapshot_digest", "playbook_sessions", ['graph_snapshot_digest'], unique=False
    )
    op.create_index(
        "ix_playbook_sessions_lifecycle", "playbook_sessions", ['lifecycle'], unique=False
    )
    op.create_index(
        "ix_playbook_sessions_prediction_session_id", "playbook_sessions", ['prediction_session_id'], unique=False
    )
    op.create_index(
        "ix_playbook_sessions_status", "playbook_sessions", ['status'], unique=False
    )
    op.create_table('playbook_steps',
    sa.Column('session_id', postgresql.UUID(as_uuid=True), nullable=False, comment='Owning playbook session.'),
    sa.Column('step_number', sa.Integer(), nullable=False, comment='1-based position in the proposed sequence.'),
    sa.Column('name', sa.String(length=128), nullable=False, comment='Bounded step name from the closed set.'),
    sa.Column('purpose', sa.String(length=512), nullable=False, comment='Why this phase comes first.'),
    sa.Column('depends_on_steps', sa.JSON(), nullable=False, comment='Preceding step numbers, derived from the action dependency edges.'),
    sa.Column('provenance', sa.String(length=32), nullable=False, comment='Always ai_generated, matching the parent session.'),
    sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("provenance = 'ai_generated'", name=op.f('ck_playbook_steps_provenance_ai_generated')),
    sa.CheckConstraint('step_number >= 1 AND step_number <= 64', name=op.f('ck_playbook_steps_playbook_steps_step_number_bound')),
    sa.ForeignKeyConstraint(['session_id'], ['playbook_sessions.id'], name=op.f('fk_playbook_steps_session_id_playbook_sessions'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_playbook_steps')),
    sa.UniqueConstraint('session_id', 'step_number', name='uq_playbook_steps_session_step_number')
    )
    op.create_index(
        "ix_playbook_steps_session_id", "playbook_steps", ['session_id'], unique=False
    )
    op.create_index(
        "ix_playbook_steps_step_number", "playbook_steps", ['step_number'], unique=False
    )
    op.create_table('playbook_actions',
    sa.Column('session_id', postgresql.UUID(as_uuid=True), nullable=False, comment='Owning playbook session.'),
    sa.Column('step_id', postgresql.UUID(as_uuid=True), nullable=False, comment='Owning step within the sequence.'),
    sa.Column('action_id', postgresql.UUID(as_uuid=True), nullable=False, comment='Deterministic uuid5 over the action, its target reference and its occurrence, so re-generation over unchanged inputs collides instead of inserting a duplicate proposal.'),
    sa.Column('position', sa.Integer(), nullable=False, comment='Position within the owning step; the topological order is stored here.'),
    sa.Column('action', sa.String(length=64), nullable=False, comment='Closed action vocabulary value from the frozen action table.'),
    sa.Column('category', sa.String(length=64), nullable=False, comment='Closed category vocabulary.'),
    sa.Column('target_type', sa.String(length=64), nullable=False, comment='Closed target vocabulary; structurally validated before persistence.'),
    sa.Column('target_reference', sa.String(length=256), nullable=False, comment='Typed pointer to the persisted source that resolved this target. The target value itself is recorded in action_payload; this column is the pointer that makes the pointer auditable.'),
    sa.Column('target_basis', sa.String(length=512), nullable=False, comment='Why this value was accepted as an addressable target.'),
    sa.Column('capability', sa.String(length=16), nullable=False, comment="'available' only when a provider exists today; otherwise 'unavailable', so the proposal never implies a capability SentinelAI lacks."),
    sa.Column('execution_backend', sa.String(length=16), nullable=False, comment="'mock_sandbox' for the six dispatchable actions; otherwise 'none'."),
    sa.Column('approval_requirement', sa.String(length=32), nullable=False, comment='Recommended human authorization for this action. This column records a recommendation only; granting approval is not modelled here.'),
    sa.Column('response_action', sa.String(length=64), nullable=True, comment='Matching ResponseActionType in the existing response layer; NULL when no execution path exists.'),
    sa.Column('rollback_supported', sa.Boolean(), nullable=False, comment='Whether a compensating action exists in the closed vocabulary. Compensation is proposed separately and is never automatic.'),
    sa.Column('rollback_action', sa.String(length=64), nullable=True, comment='The compensating action, or NULL when nothing safely reverses this one.'),
    sa.Column('risk_level', sa.String(length=16), nullable=False, comment='bounded low/medium/high.'),
    sa.Column('priority', sa.String(length=16), nullable=False, comment='Closed priority vocabulary.'),
    sa.Column('expected_outcome', sa.String(length=512), nullable=False, comment='What the proposal aims to achieve.'),
    sa.Column('verification_required', sa.Boolean(), nullable=False, comment='Whether an analyst should confirm the effect afterwards.'),
    sa.Column('confidence', sa.Float(), nullable=False, comment='How well supported this proposal is, in [0, 1].'),
    sa.Column('confidence_band', sa.String(length=16), nullable=False, comment='Discrete band over the confidence value.'),
    sa.Column('confidence_basis', sa.JSON(), nullable=False, comment='Deterministic component breakdown, retained so the reported confidence can be recomputed by hand from the record.'),
    sa.Column('grounding_basis', sa.String(length=32), nullable=False, comment='established_evidence, prediction_supported, or both. A prediction may justify preparation; it may never, alone, justify a disruptive action.'),
    sa.Column('provenance', sa.String(length=32), nullable=False, comment='Always ai_generated: a proposed action is never a finding.'),
    sa.Column('action_payload', sa.JSON(), nullable=False, comment='Canonical JSON of this action as returned by the API.'),
    sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("approval_requirement IN ('no_approval','approval_required','not_executable')", name=op.f('ck_playbook_actions_playbook_actions_approval_requirement_check')),
    sa.CheckConstraint("capability IN ('available','unavailable')", name=op.f('ck_playbook_actions_playbook_actions_capability_check')),
    sa.CheckConstraint("execution_backend IN ('mock_sandbox','none')", name=op.f('ck_playbook_actions_playbook_actions_execution_backend_check')),
    sa.CheckConstraint("grounding_basis IN ('established_evidence','prediction_supported','both')", name=op.f('ck_playbook_actions_playbook_actions_grounding_basis_check')),
    sa.CheckConstraint("provenance = 'ai_generated'", name=op.f('ck_playbook_actions_provenance_ai_generated')),
    sa.CheckConstraint('confidence >= 0.0 AND confidence <= 1.0', name=op.f('ck_playbook_actions_playbook_actions_confidence_range')),
    sa.ForeignKeyConstraint(['session_id'], ['playbook_sessions.id'], name=op.f('fk_playbook_actions_session_id_playbook_sessions'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['step_id'], ['playbook_steps.id'], name=op.f('fk_playbook_actions_step_id_playbook_steps'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_playbook_actions')),
    sa.UniqueConstraint('session_id', 'action_id', name='uq_playbook_actions_session_action_id')
    )
    op.create_index(
        "ix_playbook_actions_action", "playbook_actions", ['action'], unique=False
    )
    op.create_index(
        "ix_playbook_actions_capability", "playbook_actions", ['capability'], unique=False
    )
    op.create_index(
        "ix_playbook_actions_session_id", "playbook_actions", ['session_id'], unique=False
    )
    op.create_index(
        "ix_playbook_actions_step_id", "playbook_actions", ['step_id'], unique=False
    )
    op.create_index(
        "ix_playbook_actions_target_reference", "playbook_actions", ['target_reference'], unique=False
    )
    op.create_table('playbook_action_evidence',
    sa.Column('action_id', postgresql.UUID(as_uuid=True), nullable=False, comment='Owning proposed action.'),
    sa.Column('source', sa.String(length=32), nullable=False, comment='Closed evidence-source vocabulary value.'),
    sa.Column('reference', sa.String(length=256), nullable=False, comment="Typed '<evidence_source>:<id>' pointer; never source content."),
    sa.Column('stance', sa.String(length=16), nullable=False, comment='supporting or contradicting. Contradictions are recorded rather than suppressed, so disagreement survives into the stored proposal.'),
    sa.Column('detail', sa.String(length=512), nullable=False, comment='Secret-safe, engine-authored reason this pointer matters. Never a restatement of the cited record.'),
    sa.Column('provenance', sa.String(length=32), nullable=False, comment='Always ai_generated, matching the parent action.'),
    sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("provenance = 'ai_generated'", name=op.f('ck_playbook_action_evidence_provenance_ai_generated')),
    sa.CheckConstraint("source IN ('event','detection','correlation','risk_assessment','investigation','threat_intelligence','incident_memory','attack_path','debate_claim','prediction')", name=op.f('ck_playbook_action_evidence_playbook_action_evidence_source_check')),
    sa.CheckConstraint("stance IN ('supporting','contradicting')", name=op.f('ck_playbook_action_evidence_playbook_action_evidence_stance_check')),
    sa.ForeignKeyConstraint(['action_id'], ['playbook_actions.id'], name=op.f('fk_playbook_action_evidence_action_id_playbook_actions'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_playbook_action_evidence')),
    sa.UniqueConstraint('action_id', 'reference', 'stance', name='uq_playbook_action_evidence_reference_stance')
    )
    op.create_index(
        "ix_playbook_action_evidence_action_id", "playbook_action_evidence", ['action_id'], unique=False
    )
    op.create_index(
        "ix_playbook_action_evidence_reference", "playbook_action_evidence", ['reference'], unique=False
    )
    op.create_index(
        "ix_playbook_action_evidence_source", "playbook_action_evidence", ['source'], unique=False
    )
    op.create_index(
        "ix_playbook_action_evidence_stance", "playbook_action_evidence", ['stance'], unique=False
    )


def downgrade() -> None:
    # Reverse creation order so each foreign key is dropped after its dependants.
    op.drop_index(
        "ix_playbook_action_evidence_stance", table_name="playbook_action_evidence"
    )
    op.drop_index("ix_playbook_action_evidence_source", table_name="playbook_action_evidence")
    op.drop_index("ix_playbook_action_evidence_reference", table_name="playbook_action_evidence")
    op.drop_index("ix_playbook_action_evidence_action_id", table_name="playbook_action_evidence")
    op.drop_table("playbook_action_evidence")
    op.drop_index("ix_playbook_actions_target_reference", table_name="playbook_actions")
    op.drop_index("ix_playbook_actions_step_id", table_name="playbook_actions")
    op.drop_index("ix_playbook_actions_session_id", table_name="playbook_actions")
    op.drop_index("ix_playbook_actions_capability", table_name="playbook_actions")
    op.drop_index("ix_playbook_actions_action", table_name="playbook_actions")
    op.drop_table("playbook_actions")
    op.drop_index("ix_playbook_steps_step_number", table_name="playbook_steps")
    op.drop_index("ix_playbook_steps_session_id", table_name="playbook_steps")
    op.drop_table("playbook_steps")
    op.drop_index("ix_playbook_sessions_status", table_name="playbook_sessions")
    op.drop_index("ix_playbook_sessions_prediction_session_id", table_name="playbook_sessions")
    op.drop_index("ix_playbook_sessions_lifecycle", table_name="playbook_sessions")
    op.drop_index("ix_playbook_sessions_graph_snapshot_digest", table_name="playbook_sessions")
    op.drop_index("ix_playbook_sessions_correlation_id", table_name="playbook_sessions")
    op.drop_table("playbook_sessions")
