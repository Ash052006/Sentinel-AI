"""SOAR step-execution persistence model (V2.18).

One step result within a SOAR execution, kept for full fidelity of the
trace (``soar_execution_id -> step_execution_id -> provider result``).
Each row records the provider adapter that ran, the operation, the
canonical target, the outcome, bounded retries and sanitized failure
details — never secrets, never raw payloads, never executable content.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.postgres.base import Base, UUIDTimestampMixin
from app.schemas.soar import (
    SOAR_MAX_ERROR_CODE_LENGTH,
    SOAR_MAX_MESSAGE_LENGTH,
    SOAR_MAX_PROVIDER_ID_LENGTH,
    SOAR_MAX_RETRIES,
    SOAR_MAX_STEP_LABEL_LENGTH,
    SOAR_MAX_TARGET_LENGTH,
)


class SoarStepExecutionRow(UUIDTimestampMixin, Base):
    """One step result within a SOAR execution."""

    __tablename__ = "soar_step_executions"
    __table_args__ = (
        UniqueConstraint(
            "execution_id",
            "step_number",
            name="uq_soar_step_executions_execution_step",
        ),
        CheckConstraint(
            "status IN ('pending', 'running', 'succeeded', 'failed', "
            "'skipped', 'timed_out', 'cancelled')",
            name="soar_step_executions_status",
        ),
        CheckConstraint(
            "operation IN ('block_ip', 'block_domain', 'quarantine_file', "
            "'disable_account', 'terminate_session', 'isolate_endpoint')",
            name="soar_step_executions_operation",
        ),
        CheckConstraint(
            "step_number >= 1",
            name="soar_step_executions_step_number_min",
        ),
        CheckConstraint(
            f"retries_attempted >= 0 AND retries_attempted <= {SOAR_MAX_RETRIES}",
            name="soar_step_executions_retries_bounded",
        ),
        CheckConstraint(
            f"length(provider_id) <= {SOAR_MAX_PROVIDER_ID_LENGTH}",
            name="soar_step_executions_provider_id_length",
        ),
        CheckConstraint(
            f"length(label) <= {SOAR_MAX_STEP_LABEL_LENGTH}",
            name="soar_step_executions_label_length",
        ),
        CheckConstraint(
            f"length(target) <= {SOAR_MAX_TARGET_LENGTH}",
            name="soar_step_executions_target_length",
        ),
        CheckConstraint(
            f"length(error_code) <= {SOAR_MAX_ERROR_CODE_LENGTH}",
            name="soar_step_executions_error_code_length",
        ),
        CheckConstraint(
            f"length(message) <= {SOAR_MAX_MESSAGE_LENGTH}",
            name="soar_step_executions_message_length",
        ),
        CheckConstraint(
            "completed_at IS NULL OR started_at IS NULL OR completed_at >= started_at",
            name="soar_step_executions_time_ordering",
        ),
    )

    step_execution_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        unique=True,
        index=True,
        nullable=False,
        comment="Deterministic domain identity of this step execution.",
    )

    execution_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("soar_executions.id", name="fk_soar_step_executions_execution"),
        index=True,
        nullable=False,
        comment="The parent execution row this step belongs to.",
    )

    step_number: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="1-based position within the playbook (unique with execution).",
    )

    label: Mapped[str] = mapped_column(
        String(SOAR_MAX_STEP_LABEL_LENGTH),
        nullable=False,
        comment="The step's label.",
    )

    provider_id: Mapped[str] = mapped_column(
        String(SOAR_MAX_PROVIDER_ID_LENGTH),
        nullable=False,
        comment="The registered provider adapter that ran the step.",
    )

    operation: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="The closed operation performed (CHECK-pinned).",
    )

    target: Mapped[str] = mapped_column(
        String(SOAR_MAX_TARGET_LENGTH),
        nullable=False,
        comment="The canonical target the step applied.",
    )

    status: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        comment="pending/running/succeeded/failed/skipped/timed_out/cancelled.",
    )

    retries_attempted: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
        comment="How many retryable attempts occurred before the final one.",
    )

    error_code: Mapped[str | None] = mapped_column(
        String(SOAR_MAX_ERROR_CODE_LENGTH),
        nullable=True,
        comment="Sanitized failure/rejection code when applicable.",
    )

    message: Mapped[str | None] = mapped_column(
        String(SOAR_MAX_MESSAGE_LENGTH),
        nullable=True,
        comment="Sanitized, template-built message (never raw payloads).",
    )

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timezone-aware instant the step began (None if never run).",
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timezone-aware instant the step finished.",
    )

    step_metadata: Mapped[dict] = mapped_column(
        JSONB().with_variant(JSON, "sqlite"),
        default=dict,
        nullable=False,
        comment="Structured, secret-free bookkeeping (JSONB).",
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<SoarStepExecutionRow id={self.id} step={self.step_number} "
            f"status={self.status}>"
        )