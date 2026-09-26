"""Detection-as-Code release lifecycle persistence model (V2.17).

One release lifecycle per ``(rule_id, version)``.  Release state and
deployment state are separate on purpose: a validated+released rule is NOT
automatically deployed.  ``release_id`` is the deterministic release identity
and is unique; ``(rule_id, version)`` is unique too, so a version can be
released only once (re-release is idempotent on the same row).

Deployment bookkeeping:
* ``deployment_state`` ``deployed`` implies ``release_state`` ``released``,
  enforced by the CHECK constraint below; the repository guarantees the row
  was ``released`` before deploy.
* ``rollback_target_version`` records the version that was active just
  before this version was deployed — the deterministic rollback reference
  (demotion of this version and promotion of the target happens in the
  lifecycle service).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.postgres.base import Base, UUIDTimestampMixin
from app.schemas.detection_as_code import (
    MAX_RULE_ID_LENGTH,
    MAX_VERSION_LENGTH,
    DeploymentState,
    ReleaseState,
)


class DetectionRuleReleaseRow(UUIDTimestampMixin, Base):
    """One release/deployment lifecycle row for a governed rule version."""

    __tablename__ = "detection_rule_releases"
    __table_args__ = (
        UniqueConstraint(
            "rule_id",
            "version",
            name="uq_detection_rule_releases_rule_version",
        ),
        CheckConstraint(
            "release_state IN "
            "('draft', 'validating', 'validated', 'released', 'failed')",
            name="detection_as_code_release_state",
        ),
        CheckConstraint(
            "deployment_state IN ('undeployed', 'deployed')",
            name="detection_as_code_deployment_state",
        ),
        CheckConstraint(
            "deployment_state <> 'deployed' OR release_state = 'released'",
            name="detection_as_code_deployed_implies_released",
        ),
        CheckConstraint(
            "rollback_target_version IS NULL OR "
            f"length(rollback_target_version) <= {MAX_VERSION_LENGTH}",
            name="detection_as_code_rollback_target_length",
        ),
    )

    release_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        unique=True,
        index=True,
        comment="Deterministic release identity (UUIDv5).",
    )

    version_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("detection_rule_versions.id", name="fk_dac_releases_version_id"),
        nullable=True,
        comment="Version identity this release targets.",
    )

    rule_id: Mapped[str] = mapped_column(
        String(MAX_RULE_ID_LENGTH),
        nullable=False,
        index=True,
        comment="Stable, unique rule identifier.",
    )

    version: Mapped[str] = mapped_column(
        String(MAX_VERSION_LENGTH),
        nullable=False,
        comment="Strict MAJOR.MINOR.PATCH semantic version being released.",
    )

    release_state: Mapped[str] = mapped_column(
        String(16),
        default=ReleaseState.DRAFT.value,
        nullable=False,
        comment="draft/validating/validated/released/failed (CHECK-pinned).",
    )

    deployment_state: Mapped[str] = mapped_column(
        String(16),
        default=DeploymentState.UNDEPLOYED.value,
        nullable=False,
        comment="undeployed/deployed (CHECK-pinned; deployed implies released).",
    )

    validated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When this version's validation completed successfully.",
    )

    released_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When this version was released.",
    )

    deployed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When this version was deployed.",
    )

    rollback_target_version: Mapped[str | None] = mapped_column(
        String(MAX_VERSION_LENGTH),
        nullable=True,
        comment=(
            "Version active immediately before this version was deployed "
            "(deterministic rollback reference)."
        ),
    )

    released_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", name="fk_dac_releases_released_by_users"),
        nullable=True,
        comment="Trusted identity that released the version.",
    )

    deployed_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", name="fk_dac_releases_deployed_by_users"),
        nullable=True,
        comment="Trusted identity that deployed the version.",
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<DetectionRuleReleaseRow id={self.id} "
            f"rule={self.rule_id} version={self.version} "
            f"release={self.release_state} deploy={self.deployment_state}>"
        )