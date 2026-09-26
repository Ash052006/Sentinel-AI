"""Detection-as-Code rule version persistence model (V2.17).

The **persistence contract** for one immutable, versioned detection rule.

Design intent
-------------
* ``version_id`` (the deterministic domain identity derived from
  ``rule_id|version|source_hash``) and the ``(rule_id, version)`` pair are
  both **unique**: a content change always changes ``version_id`` even if
  the version string is unchanged, so two different rule contents can never
  silently share an immutable release identity, and a version string is
  never reused for different content.
* The full rule **content is never persisted here** — ``source_path`` +
  ``source_hash`` reference the controlled rule repository.  Persistence
  records lifecycle *metadata* (validation/test outcomes, enabled state,
  release/deployment status, actor) and history, never a second copy of the
  rule body, so there is a single source of truth for content.
* ``rollback_from`` (self-reference to another version row) is the
  deterministic rollback reference for the immutable target.

This model defines the layout only; the repository/service that drives it
(V2.17) is implemented separately at
``app/services/detection_as_code/``.
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
from app.schemas.detection_as_code import (
    MAX_DESCRIPTION_LENGTH,
    MAX_RULE_ID_LENGTH,
    MAX_SOURCE_HASH_LENGTH,
    MAX_TITLE_LENGTH,
    MAX_VERSION_LENGTH,
    HASH_ALGORITHM,
    MAX_AUTHOR_LENGTH,
    MAX_CATEGORY_LENGTH,
    MAX_CHANGE_REASON_LENGTH,
    MAX_ROLE_LENGTH,
    MAX_SOURCE_PATH_LENGTH,
    MAX_VALIDATION_ERROR_LENGTH,
    ValidationOutcome,
)


class DetectionRuleVersionRow(UUIDTimestampMixin, Base):
    """One immutable, governed version of a detection rule."""

    __tablename__ = "detection_rule_versions"
    __table_args__ = (
        UniqueConstraint(
            "rule_id",
            "version",
            name="uq_detection_rule_versions_rule_version",
        ),
        CheckConstraint(
            "rule_type IN ('sigma', 'yara')",
            name="detection_as_code_rule_type",
        ),
        CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'critical')",
            name="detection_as_code_severity",
        ),
        CheckConstraint(
            "validation_status IN "
            "('none', 'validating', 'validated', 'failed')",
            name="detection_as_code_validation_status",
        ),
        CheckConstraint(
            f"length(hash_algorithm) <= 16",
            name="detection_as_code_hash_algorithm_length",
        ),
        CheckConstraint(
            f"length(source_hash) = 64",
            name="detection_as_code_source_hash_length",
        ),
        CheckConstraint(
            f"length(rule_id) <= {MAX_RULE_ID_LENGTH}",
            name="detection_as_code_rule_id_length",
        ),
        CheckConstraint(
            f"length(version) <= {MAX_VERSION_LENGTH}",
            name="detection_as_code_version_length",
        ),
        CheckConstraint(
            f"length(title) <= {MAX_TITLE_LENGTH}",
            name="detection_as_code_title_length",
        ),
        CheckConstraint(
            f"length(description) <= {MAX_DESCRIPTION_LENGTH}",
            name="detection_as_code_description_length",
        ),
        CheckConstraint(
            f"length(source_path) <= {MAX_SOURCE_PATH_LENGTH}",
            name="detection_as_code_source_path_length",
        ),
    )

    version_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        unique=True,
        index=True,
        comment=(
            "Deterministic immutable identity (UUIDv5 over rule_id|version|"
            "source_hash).  Different content always derives a different "
            "identity even for the same version string."
        ),
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
        comment="Strict MAJOR.MINOR.PATCH semantic version of this content.",
    )

    rule_type: Mapped[str] = mapped_column(
        String(8),
        nullable=False,
        comment="sigma | yara (CHECK-pinned).",
    )

    severity: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        comment="low | medium | high | critical (CHECK-pinned).",
    )

    title: Mapped[str] = mapped_column(
        String(MAX_TITLE_LENGTH),
        nullable=False,
        comment="Rule title from the source.",
    )

    description: Mapped[str] = mapped_column(
        String(MAX_DESCRIPTION_LENGTH),
        nullable=False,
        comment="Rule description from the source.",
    )

    author: Mapped[str | None] = mapped_column(
        String(MAX_AUTHOR_LENGTH),
        nullable=True,
        comment="Rule author from the source, when present.",
    )

    status: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
        comment="Documented rule status (stable/experimental/...).",
    )

    category: Mapped[str | None] = mapped_column(
        String(MAX_CATEGORY_LENGTH),
        nullable=True,
        comment="Management category (Sigma logsource or 'file' for YARA).",
    )

    source_path: Mapped[str] = mapped_column(
        String(MAX_SOURCE_PATH_LENGTH),
        nullable=False,
        comment="Controlled-repo source path relative to the rules root.",
    )

    hash_algorithm: Mapped[str] = mapped_column(
        String(16),
        default=HASH_ALGORITHM,
        nullable=False,
        comment="Only 'sha256' is supported for source integrity.",
    )

    source_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        comment="Recorded SHA-256 digest of the source file (hex, 64 chars).",
    )

    tags: Mapped[list] = mapped_column(
        JSONB().with_variant(JSON, "sqlite"),
        default=list,
        nullable=False,
        comment="Stable classification tags (JSONB).",
    )

    enabled: Mapped[bool] = mapped_column(
        default=True,
        nullable=False,
        comment="Whether the deployed version is evaluated at runtime.",
    )

    validation_status: Mapped[str] = mapped_column(
        String(16),
        default=ValidationOutcome.NONE.value,
        nullable=False,
        comment="none / validating / validated / failed (CHECK-pinned).",
    )

    validation_error: Mapped[str | None] = mapped_column(
        String(MAX_VALIDATION_ERROR_LENGTH),
        nullable=True,
        comment="Sanitized first validation failure message (never content).",
    )

    compiled: Mapped[bool] = mapped_column(
        default=False,
        nullable=False,
        comment="Real-engine compile success for this version.",
    )

    positive_passed: Mapped[bool] = mapped_column(
        default=False,
        nullable=False,
        comment="Positive fixture matched through the real engine.",
    )

    negative_passed: Mapped[bool] = mapped_column(
        default=False,
        nullable=False,
        comment="Negative fixture stayed silent through the real engine.",
    )

    rollback_from: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("detection_rule_versions.id", name="fk_dac_versions_rollback_from"),
        nullable=True,
        comment="Id of the version this version replaced via rollback.",
    )

    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", name="fk_dac_versions_created_by_users"),
        nullable=True,
        comment="Trusted identity that created this version.",
    )

    created_by_role: Mapped[str | None] = mapped_column(
        String(MAX_ROLE_LENGTH),
        nullable=True,
        comment="Role label of the creating actor.",
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<DetectionRuleVersionRow id={self.id} "
            f"rule={self.rule_id} version={self.version} "
            f"validation={self.validation_status}>"
        )