"""SOAR playbook version persistence model (V2.18).

Immutable, deterministic versions of each registered playbook.  Mirrors the
Detection-as-Code versioning doctrine: ``version_id`` is a UUIDv5 over
``playbook_id | version | source_hash`` so a content change always derives a
different identity, and the version string is never reused for different
content.
"""

from __future__ import annotations

import uuid

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    ForeignKey,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.postgres.base import Base, UUIDTimestampMixin
from app.schemas.soar import (
    SOAR_MAX_PLAYBOOK_ID_LENGTH,
    SOAR_MAX_VERSION_LENGTH,
)


class SoarPlaybookVersionRow(UUIDTimestampMixin, Base):
    """One immutable, governed version of a SOAR playbook."""

    __tablename__ = "soar_playbook_versions"
    __table_args__ = (
        UniqueConstraint(
            "playbook_id",
            "version",
            name="uq_soar_playbook_versions_playbook_version",
        ),
        CheckConstraint(
            f"length(playbook_id) <= {SOAR_MAX_PLAYBOOK_ID_LENGTH}",
            name="soar_playbook_versions_playbook_id_length",
        ),
        CheckConstraint(
            f"length(version) <= {SOAR_MAX_VERSION_LENGTH}",
            name="soar_playbook_versions_version_length",
        ),
        CheckConstraint(
            "status IN ('active', 'superseded')",
            name="soar_playbook_versions_status",
        ),
        CheckConstraint(
            "length(source_hash) = 64",
            name="soar_playbook_versions_source_hash_length",
        ),
    )

    playbook_row_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("soar_playbooks.id", name="fk_soar_playbook_versions_playbook_id"),
        nullable=True,
        comment="The playbook row this version belongs to.",
    )

    version_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        unique=True,
        index=True,
        nullable=False,
        comment=(
            "Deterministic immutable version identity (UUIDv5 over "
            "playbook_id|version|source_hash)."
        ),
    )

    playbook_id: Mapped[str] = mapped_column(
        String(SOAR_MAX_PLAYBOOK_ID_LENGTH),
        index=True,
        nullable=False,
        comment="Stable playbook identifier (mirrored for history reads).",
    )

    version: Mapped[str] = mapped_column(
        String(SOAR_MAX_VERSION_LENGTH),
        nullable=False,
        comment="Strict MAJOR.MINOR.PATCH semantic version (unique with playbook_id).",
    )

    source_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="Recorded SHA-256 digest of the canonical definition (hex).",
    )

    definition: Mapped[dict] = mapped_column(
        JSONB().with_variant(JSON, "sqlite"),
        nullable=False,
        comment="The immutable declarative definition of this version (JSONB).",
    )

    status: Mapped[str] = mapped_column(
        String(16),
        default="active",
        nullable=False,
        comment="active | superseded (CHECK-pinned).",
    )

    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", name="fk_soar_playbook_versions_created_by_users"),
        nullable=True,
        comment="Trusted identity that registered this version.",
    )

    created_by_role: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
        comment="Role label of the registering actor.",
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<SoarPlaybookVersionRow id={self.id} "
            f"playbook={self.playbook_id} version={self.version}>"
        )