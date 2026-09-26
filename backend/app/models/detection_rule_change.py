"""Detection-as-Code versioning/rollback change ledger (V2.17).

One deterministic, append-only event row for every lifecycle change that
moved the rule's *content identity*: initial onboarding (``initialized``),
a source change that produced a new version (``version_added``) and a
rollback to a previously released version (``rolled_back``).

Immutability: the ledger is append-only; rows are created with the
deterministic ``change_id`` and are never updated.  Nothing here duplicates
rule content — ``to_source_hash`` is a digest reference to the controlled
repository.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.postgres.base import Base, UUIDTimestampMixin
from app.schemas.detection_as_code import (
    MAX_CHANGE_REASON_LENGTH,
    MAX_RULE_ID_LENGTH,
    MAX_SOURCE_HASH_LENGTH,
    MAX_VERSION_LENGTH,
    ChangeKind,
)


class DetectionRuleChangeRow(UUIDTimestampMixin, Base):
    """One immutable ledger event for a versioning/rollback transition."""

    __tablename__ = "detection_rule_changes"
    __table_args__ = (
        CheckConstraint(
            "change_kind IN ('initialized', 'version_added', 'rolled_back')",
            name="detection_as_code_change_kind",
        ),
        CheckConstraint(
            f"length(rule_id) <= {MAX_RULE_ID_LENGTH}",
            name="detection_as_code_change_rule_id_length",
        ),
        CheckConstraint(
            f"length(to_version) <= {MAX_VERSION_LENGTH}",
            name="detection_as_code_change_version_length",
        ),
        CheckConstraint(
            "length(to_source_hash) = 64",
            name="detection_as_code_change_source_hash_length",
        ),
    )

    change_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        unique=True,
        index=True,
        comment="Deterministic change identity (append-only, never updated).",
    )

    rule_id: Mapped[str] = mapped_column(
        String(MAX_RULE_ID_LENGTH),
        nullable=False,
        index=True,
        comment="Rule affected by the change.",
    )

    change_kind: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        comment="initialized/version_added/rolled_back (CHECK-pinned).",
    )

    from_version: Mapped[str | None] = mapped_column(
        String(MAX_VERSION_LENGTH),
        nullable=True,
        comment="Prior version (None for initial onboarding).",
    )

    to_version: Mapped[str] = mapped_column(
        String(MAX_VERSION_LENGTH),
        nullable=False,
        comment="Version after the change.",
    )

    to_source_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="SHA-256 digest of the post-change source (never content).",
    )

    bump_class: Mapped[str | None] = mapped_column(
        String(8),
        nullable=True,
        comment="major/minor/patch classification of this transition, if any.",
    )

    change_reason: Mapped[str | None] = mapped_column(
        String(MAX_CHANGE_REASON_LENGTH),
        nullable=True,
        comment="Accountability reason supplied by the author for the change.",
    )

    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        comment="Trusted identity that performed the change.",
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<DetectionRuleChangeRow id={self.id} "
            f"rule={self.rule_id} kind={self.change_kind} "
            f"to={self.to_version}>"
        )