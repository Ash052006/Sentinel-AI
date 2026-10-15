"""create attack prediction tables

V3.24 — Attack Prediction Engine.

Four tables record the analytical output of a prediction run.  They store
references and reasoning text only; no V2 record, no V3.22 graph row and no
V3.23 debate row is duplicated or modified.

``provenance`` is CHECK-pinned to ``ai_generated`` on every table.  That
constraint is the firewall of record: a regression that tried to persist a
prediction as ``observed``, ``detected``, ``correlated`` or ``risk_assessed``
would fail the constraint rather than quietly writing evidence.

Column comments are duplicated verbatim from the ORM models.  They are written
out rather than imported on purpose: a migration is a snapshot of one moment,
so a later model edit must not silently rewrite history.  ``alembic check``
compares comments, so both copies have to agree.

Revision ID: a7b8c9d0e1f2
Revises: f6a7b8c9d0e1
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "a7b8c9d0e1f2"
down_revision: str | None = "f6a7b8c9d0e1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PROVENANCE = "ai_generated"

_STATUSES = "'predicted','low_confidence','insufficient_evidence','contested'"


def upgrade() -> None:
    op.create_table(
        "attack_prediction_sessions",
        sa.Column(
            "correlation_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            comment="V2 correlation under prediction; a soft reference by design.",
        ),
        sa.Column(
            "graph_snapshot_digest",
            sa.String(length=64),
            nullable=False,
            comment="SHA-256 of the canonical bounded V3.22 graph that was read.",
        ),
        sa.Column(
            "prediction_configuration_digest",
            sa.String(length=64),
            nullable=False,
            comment="SHA-256 of the bounds and engine version used for this run.",
        ),
        sa.Column(
            "debate_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
            comment="V3.23 debate consumed; NULL when no debate was available.",
        ),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            comment=(
                "Session outcome. 'insufficient_evidence' is a successful outcome, "
                "not an error: declining to speculate is the correct result when no "
                "evidence names a plausible next stage."
            ),
        ),
        sa.Column(
            "engine_version",
            sa.String(length=64),
            nullable=False,
            comment="Prediction engine version.",
        ),
        sa.Column(
            "graph_node_count",
            sa.Integer(),
            nullable=False,
            comment="Bounded graph nodes consumed.",
        ),
        sa.Column(
            "graph_edge_count",
            sa.Integer(),
            nullable=False,
            comment="Bounded graph edges consumed.",
        ),
        sa.Column(
            "observed_technique_count",
            sa.Integer(),
            nullable=False,
            comment="Persisted ATT&CK techniques found; 0 means none may be asserted.",
        ),
        sa.Column(
            "max_depth",
            sa.Integer(),
            nullable=False,
            comment="Prediction horizon used; architecturally capped at 2.",
        ),
        sa.Column(
            "provenance",
            sa.String(length=32),
            nullable=False,
            comment="Always ai_generated: a prediction is analysis, never evidence.",
        ),
        sa.Column(
            "session_payload",
            sa.JSON(),
            nullable=False,
            comment=(
                "Canonical JSON document of the completed prediction session. The "
                "normalized child tables (predictions, evidence, uncertainties) are the "
                "queryable and auditable projection of the same write; this column is "
                "the lossless read model so a GET returns exactly what the POST "
                "produced. Contains no prompt text, no API key, and no raw provider "
                "payload, because the engine has no provider."
            ),
        ),
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            f"provenance = '{_PROVENANCE}'",
            name="provenance_ai_generated",
        ),
        sa.CheckConstraint(
            f"status IN ({_STATUSES})",
            name="attack_prediction_sessions_status_check",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_attack_prediction_sessions_correlation_id",
        "attack_prediction_sessions",
        ["correlation_id"],
    )
    op.create_index(
        "ix_attack_prediction_sessions_status", "attack_prediction_sessions", ["status"]
    )
    op.create_index(
        "ix_attack_prediction_sessions_graph_snapshot_digest",
        "attack_prediction_sessions",
        ["graph_snapshot_digest"],
    )
    op.create_index(
        "ix_attack_prediction_sessions_debate_id",
        "attack_prediction_sessions",
        ["debate_id"],
    )

    op.create_table(
        "attack_predictions",
        sa.Column(
            "session_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            comment="Owning prediction session.",
        ),
        sa.Column(
            "prediction_kind",
            sa.String(length=64),
            nullable=False,
            comment="Closed prediction category.",
        ),
        sa.Column(
            "depth",
            sa.Integer(),
            nullable=False,
            comment="1 = plausible next stage; 2 = one subsequent stage. Never deeper.",
        ),
        sa.Column(
            "prediction_status",
            sa.String(length=32),
            nullable=False,
            comment="Prediction outcome vocabulary; never an evidence state.",
        ),
        sa.Column(
            "target",
            sa.String(length=128),
            nullable=False,
            comment="Bounded predicted-stage label.",
        ),
        sa.Column(
            "target_basis",
            sa.String(length=64),
            nullable=False,
            comment="How the target was identified (persisted / debate / analytical).",
        ),
        sa.Column(
            "basis",
            sa.String(length=64),
            nullable=False,
            comment="Why the candidate was permitted to exist.",
        ),
        sa.Column(
            "technique_id",
            sa.String(length=10),
            nullable=True,
            comment="Persisted ATT&CK technique id; NULL when no mapping supports one.",
        ),
        sa.Column(
            "technique_name",
            sa.String(length=128),
            nullable=True,
            comment="Persisted ATT&CK technique name.",
        ),
        sa.Column(
            "tactic",
            sa.String(length=64),
            nullable=True,
            comment="Persisted ATT&CK tactic name.",
        ),
        sa.Column(
            "technique_id_reason",
            sa.String(length=512),
            nullable=False,
            comment="Why the technique id is present or absent.",
        ),
        sa.Column(
            "confidence",
            sa.Float(),
            nullable=False,
            comment=(
                "Confidence that the proposed future progression is plausible. Not a "
                "risk score, not debate confidence, not agent confidence."
            ),
        ),
        sa.Column(
            "confidence_band",
            sa.String(length=16),
            nullable=False,
            comment="Discrete band over the confidence value.",
        ),
        sa.Column(
            "evidence_support",
            sa.String(length=32),
            nullable=False,
            comment="Whether support is persisted evidence, a debate claim, or both.",
        ),
        sa.Column(
            "rationale_summary",
            sa.String(length=1024),
            nullable=False,
            comment="Secret-safe one-line rationale.",
        ),
        sa.Column(
            "basis_detail",
            sa.String(length=512),
            nullable=False,
            comment="Why the recorded basis applies.",
        ),
        sa.Column(
            "provenance",
            sa.String(length=32),
            nullable=False,
            comment="Always ai_generated: a prediction is analysis, never evidence.",
        ),
        sa.Column(
            "prediction_payload",
            sa.JSON(),
            nullable=False,
            comment="Canonical JSON of this prediction as returned by the API.",
        ),
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["session_id"], ["attack_prediction_sessions.id"], ondelete="CASCADE"
        ),
        sa.CheckConstraint(
            f"provenance = '{_PROVENANCE}'",
            name="provenance_ai_generated",
        ),
        sa.CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="attack_predictions_confidence_range",
        ),
        sa.CheckConstraint(
            "depth >= 1 AND depth <= 2", name="attack_predictions_depth_bound"
        ),
        sa.CheckConstraint(
            f"prediction_status IN ({_STATUSES})",
            name="attack_predictions_status_check",
        ),
        sa.CheckConstraint(
            "evidence_support IN ('persisted_evidence','debate_claim','mixed')",
            name="attack_predictions_evidence_support_check",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_attack_predictions_session_id", "attack_predictions", ["session_id"]
    )
    op.create_index(
        "ix_attack_predictions_prediction_kind", "attack_predictions", ["prediction_kind"]
    )
    op.create_index(
        "ix_attack_predictions_status", "attack_predictions", ["prediction_status"]
    )
    op.create_index(
        "ix_attack_predictions_technique_id", "attack_predictions", ["technique_id"]
    )

    op.create_table(
        "attack_prediction_evidence",
        sa.Column(
            "prediction_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            comment="Owning prediction.",
        ),
        sa.Column(
            "reference",
            sa.String(length=128),
            nullable=False,
            comment="Persisted V2 source reference; a pointer, never source content.",
        ),
        sa.Column(
            "entity_kind",
            sa.String(length=64),
            nullable=False,
            comment="V3.22 node type of the cited source.",
        ),
        sa.Column(
            "node_id",
            sa.String(length=128),
            nullable=False,
            comment="Deterministic V3.22 graph node id.",
        ),
        sa.Column(
            "stance",
            sa.String(length=16),
            nullable=False,
            comment="supporting or contradicting; contradictions are never suppressed.",
        ),
        sa.Column(
            "detail",
            sa.String(length=512),
            nullable=False,
            comment="Secret-safe reason this citation matters.",
        ),
        sa.Column(
            "provenance",
            sa.String(length=32),
            nullable=False,
            comment="Always ai_generated, matching the parent prediction.",
        ),
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["prediction_id"], ["attack_predictions.id"], ondelete="CASCADE"
        ),
        sa.CheckConstraint(
            f"provenance = '{_PROVENANCE}'",
            name="provenance_ai_generated",
        ),
        sa.CheckConstraint(
            "stance IN ('supporting','contradicting')",
            name="attack_prediction_evidence_stance_check",
        ),
        sa.PrimaryKeyConstraint("id"),
        # A citation is identified by what it points at, its owner and its
        # stance. Enforced in the database so no code path can inflate a
        # prediction's evidence count by re-inserting the same citation — which
        # would silently raise its confidence, since support is a count.
        sa.UniqueConstraint(
            "prediction_id",
            "reference",
            "stance",
            name="uq_attack_prediction_evidence_reference_stance",
        ),
    )
    op.create_index(
        "ix_attack_prediction_evidence_prediction_id",
        "attack_prediction_evidence",
        ["prediction_id"],
    )
    op.create_index(
        "ix_attack_prediction_evidence_reference",
        "attack_prediction_evidence",
        ["reference"],
    )
    op.create_index(
        "ix_attack_prediction_evidence_stance", "attack_prediction_evidence", ["stance"]
    )

    op.create_table(
        "attack_prediction_uncertainties",
        sa.Column(
            "prediction_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            comment="Owning prediction; one uncertainty row per prediction.",
        ),
        sa.Column(
            "confidence",
            sa.Float(),
            nullable=False,
            comment="Bounded prediction confidence.",
        ),
        sa.Column(
            "confidence_band",
            sa.String(length=16),
            nullable=False,
            comment="Discrete confidence band.",
        ),
        sa.Column(
            "confidence_basis",
            sa.JSON(),
            nullable=False,
            comment="Deterministic component breakdown of the confidence formula.",
        ),
        sa.Column(
            "supporting_count",
            sa.Integer(),
            nullable=False,
            comment="Supporting citation count.",
        ),
        sa.Column(
            "contradicting_count",
            sa.Integer(),
            nullable=False,
            comment=(
                "Contradicting citation count. Recorded explicitly so a prediction "
                "cannot quietly lose its opposition."
            ),
        ),
        sa.Column(
            "evidence_gaps",
            sa.JSON(),
            nullable=False,
            comment="Recorded evidence gaps.",
        ),
        sa.Column(
            "unresolved_questions",
            sa.JSON(),
            nullable=False,
            comment="Recorded unresolved questions.",
        ),
        sa.Column(
            "limitations",
            sa.JSON(),
            nullable=False,
            comment="Typed limitation records.",
        ),
        sa.Column(
            "provenance",
            sa.String(length=32),
            nullable=False,
            comment="Always ai_generated, matching the parent prediction.",
        ),
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["prediction_id"], ["attack_predictions.id"], ondelete="CASCADE"
        ),
        sa.CheckConstraint(
            f"provenance = '{_PROVENANCE}'",
            name="provenance_ai_generated",
        ),
        sa.CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="attack_prediction_uncertainties_confidence_range",
        ),
        sa.PrimaryKeyConstraint("id"),
        # One uncertainty per prediction, at the database level. uselist=False on
        # the ORM relationship only describes the read shape; without this a
        # second row could exist, leaving the persisted contradicting count
        # ambiguous about which record is authoritative.
        sa.UniqueConstraint(
            "prediction_id", name="uq_attack_prediction_uncertainties_prediction_id"
        ),
    )
    op.create_index(
        "ix_attack_prediction_uncertainties_prediction_id",
        "attack_prediction_uncertainties",
        ["prediction_id"],
    )


def downgrade() -> None:
    # Reverse creation order so each foreign key is dropped after its dependants.
    op.drop_index(
        "ix_attack_prediction_uncertainties_prediction_id",
        table_name="attack_prediction_uncertainties",
    )
    op.drop_table("attack_prediction_uncertainties")

    op.drop_index(
        "ix_attack_prediction_evidence_stance", table_name="attack_prediction_evidence"
    )
    op.drop_index(
        "ix_attack_prediction_evidence_reference", table_name="attack_prediction_evidence"
    )
    op.drop_index(
        "ix_attack_prediction_evidence_prediction_id",
        table_name="attack_prediction_evidence",
    )
    op.drop_table("attack_prediction_evidence")

    op.drop_index("ix_attack_predictions_technique_id", table_name="attack_predictions")
    op.drop_index("ix_attack_predictions_status", table_name="attack_predictions")
    op.drop_index(
        "ix_attack_predictions_prediction_kind", table_name="attack_predictions"
    )
    op.drop_index("ix_attack_predictions_session_id", table_name="attack_predictions")
    op.drop_table("attack_predictions")

    op.drop_index(
        "ix_attack_prediction_sessions_debate_id", table_name="attack_prediction_sessions"
    )
    op.drop_index(
        "ix_attack_prediction_sessions_graph_snapshot_digest",
        table_name="attack_prediction_sessions",
    )
    op.drop_index(
        "ix_attack_prediction_sessions_status", table_name="attack_prediction_sessions"
    )
    op.drop_index(
        "ix_attack_prediction_sessions_correlation_id",
        table_name="attack_prediction_sessions",
    )
    op.drop_table("attack_prediction_sessions")