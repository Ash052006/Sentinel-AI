"""SOAR execution persistence model (V2.18).

One immutable, auditable SOAR execution.  The row records the full trace:
``policy_decision_id -> approval_id -> response_id -> playbook_id``, the
canonical target, status, failure policy, simulated flag, and timing.

Design intent
-------------
* ``execution_id`` is deterministic (UUIDv5 over content): the same
  governed submission always derives the same identity.
* ``idempotency_key`` (content-derived SHA-256) is unique so an identical
  already-processed submission never re-executes.
* ``simulated`` distinguishes a live sandbox run (``False``) from a
  validated dry-run projection (``True``).  Dry-runs are **not** persisted
  in V2.18 — this flag is preserved on the model for forward use and the
  read surface, but dry-run projections are returned in-band only.
* Contains no secrets and no executable content.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    String,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.postgres.base import Base, UUIDTimestampMixin
from app.schemas.soar import (
    SOAR_MAX_ERROR_CODE_LENGTH,
    SOAR_MAX_PLAYBOOK_ID_LENGTH,
    SOAR_MAX_TARGET_LENGTH,
    SOAR_MAX_VERSION_LENGTH,
)


class SoarExecutionRow(UUIDTimestampMixin, Base):
    """One auditable SOAR execution."""

    __tablename__ = "soar_executions"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'running', 'succeeded', 'failed', "
            "'partial', 'cancelled', 'rejected')",
            name="soar_executions_status",
        ),
        CheckConstraint(
            "failure_policy IN ('stop_on_failure', 'continue_on_failure')",
            name="soar_executions_failure_policy",
        ),
        CheckConstraint(
            "primary_action IN ('block_ip', 'block_domain', 'quarantine_file', "
            "'disable_account', 'terminate_session', 'isolate_endpoint')",
            name="soar_executions_primary_action",
        ),
        CheckConstraint(
            f"length(playbook_id) <= {SOAR_MAX_PLAYBOOK_ID_LENGTH}",
            name="soar_executions_playbook_id_length",
        ),
        CheckConstraint(
            f"length(target) <= {SOAR_MAX_TARGET_LENGTH}",
            name="soar_executions_target_length",
        ),
        CheckConstraint(
            f"length(error_code) <= {SOAR_MAX_ERROR_CODE_LENGTH}",
            name="soar_executions_error_code_length",
        ),
        CheckConstraint(
            "completed_at IS NULL OR started_at IS NULL OR completed_at >= started_at",
            name="soar_executions_time_ordering",
        ),
    )

    execution_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        unique=True,
        index=True,
        nullable=False,
        comment="Deterministic domain identity of this execution (unique).",
    )

    idempotency_key: Mapped[str] = mapped_column(
        String(128),
        unique=True,
        index=True,
        nullable=False,
        comment=(
            "Content-derived SHA-256 idempotency key (policy decision, "
            "approval, response, playbook, target, action).  Unique."
        ),
    )

    policy_decision_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        index=True,
        nullable=False,
        comment="The authorizing Step 24 policy decision.",
    )

    correlation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        comment="The correlation the workflow concerns.",
    )

    approval_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        index=True,
        nullable=True,
        comment="The human approval grant consulted, when applicable.",
    )

    response_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        comment="The Step 25 Response result this run builds upon.",
    )

    playbook_id: Mapped[str] = mapped_column(
        String(SOAR_MAX_PLAYBOOK_ID_LENGTH),
        index=True,
        nullable=False,
        comment="The registered playbook that ran.",
    )

    playbook_version: Mapped[str] = mapped_column(
        String(SOAR_MAX_VERSION_LENGTH),
        nullable=False,
        comment="The playbook version that ran.",
    )

    primary_action: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="The authorized action orchestrated (CHECK-pinned).",
    )

    target: Mapped[str] = mapped_column(
        String(SOAR_MAX_TARGET_LENGTH),
        nullable=False,
        comment="The canonical target inherited from the decision.",
    )

    status: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        comment="pending/running/succeeded/failed/partial/cancelled/rejected.",
    )

    failure_policy: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="stop_on_failure | continue_on_failure (CHECK-pinned).",
    )

    simulated: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        comment="True only for a dry-run projection (never a real run).",
    )

    error_code: Mapped[str | None] = mapped_column(
        String(SOAR_MAX_ERROR_CODE_LENGTH),
        nullable=True,
        comment="Sanitized failure/rejection code when applicable.",
    )

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timezone-aware instant execution began (None when rejected).",
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timezone-aware instant execution finished.",
    )

    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        comment="Trusted identity that requested the run.",
    )

    created_by_role: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="Role label of the requesting actor.",
    )

    execution_metadata: Mapped[dict] = mapped_column(
        JSONB().with_variant(JSON, "sqlite"),
        default=dict,
        nullable=False,
        comment="Structured, secret-free bookkeeping (JSONB).",
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<SoarExecutionRow id={self.id} status={self.status} "
            f"playbook={self.playbook_id} simulated={self.simulated}>"
        )