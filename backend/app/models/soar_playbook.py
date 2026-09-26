"""SOAR playbook persistence model (V2.18).

The **persistence contract** for one registered declarative playbook.

Design intent
-------------
* ``playbook_id`` is the stable, allow-listed identifier of the playbook
  (unique).  The full declarative definition lives in the versioned
  ``soar_playbook_versions`` table — this row carries the *current* active
  version reference (``version``/``version_id``/``source_hash``) plus the
  normalized display metadata.
* ``steps`` (JSONB) mirrors the current active definition's steps so the
  list/read surface can render a playbook without joining; it is a read
  mirror, never a second source of truth.
* Contains **no secrets** and no executable content — steps are
  declarative operation directives only.
"""

from __future__ import annotations

import uuid

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
    SOAR_MAX_DESCRIPTION_LENGTH,
    SOAR_MAX_PLAYBOOK_ID_LENGTH,
    SOAR_MAX_PLAYBOOK_NAME_LENGTH,
    SOAR_MAX_SCHEMA_VERSION_LENGTH,
    SOAR_MAX_VERSION_LENGTH,
)


class SoarPlaybookRow(UUIDTimestampMixin, Base):
    """One registered SOAR playbook (current active version)."""

    __tablename__ = "soar_playbooks"
    __table_args__ = (
        CheckConstraint(
            f"length(playbook_id) <= {SOAR_MAX_PLAYBOOK_ID_LENGTH}",
            name="soar_playbooks_playbook_id_length",
        ),
        CheckConstraint(
            f"length(name) <= {SOAR_MAX_PLAYBOOK_NAME_LENGTH}",
            name="soar_playbooks_name_length",
        ),
        CheckConstraint(
            f"length(description) <= {SOAR_MAX_DESCRIPTION_LENGTH}",
            name="soar_playbooks_description_length",
        ),
        CheckConstraint(
            f"length(schema_version) <= {SOAR_MAX_SCHEMA_VERSION_LENGTH}",
            name="soar_playbooks_schema_version_length",
        ),
        CheckConstraint(
            f"length(version) <= {SOAR_MAX_VERSION_LENGTH}",
            name="soar_playbooks_version_length",
        ),
        CheckConstraint(
            "primary_action IN ('block_ip', 'block_domain', 'quarantine_file', "
            "'disable_account', 'terminate_session', 'isolate_endpoint')",
            name="soar_playbooks_primary_action",
        ),
        CheckConstraint(
            "failure_policy IN ('stop_on_failure', 'continue_on_failure')",
            name="soar_playbooks_failure_policy",
        ),
        CheckConstraint(
            "length(source_hash) = 64",
            name="soar_playbooks_source_hash_length",
        ),
    )

    playbook_id: Mapped[str] = mapped_column(
        String(SOAR_MAX_PLAYBOOK_ID_LENGTH),
        unique=True,
        index=True,
        nullable=False,
        comment="Stable, allow-listed playbook identifier (unique).",
    )

    name: Mapped[str] = mapped_column(
        String(SOAR_MAX_PLAYBOOK_NAME_LENGTH),
        nullable=False,
        comment="Human-readable playbook name.",
    )

    description: Mapped[str] = mapped_column(
        String(SOAR_MAX_DESCRIPTION_LENGTH),
        nullable=False,
        comment="Secret-free playbook description.",
    )

    schema_version: Mapped[str] = mapped_column(
        String(SOAR_MAX_SCHEMA_VERSION_LENGTH),
        nullable=False,
        comment="Declarative playbook schema version (1.0.0 only).",
    )

    version: Mapped[str] = mapped_column(
        String(SOAR_MAX_VERSION_LENGTH),
        nullable=False,
        comment="Current active semantic version of the playbook.",
    )

    version_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        unique=True,
        index=True,
        nullable=False,
        comment=(
            "Deterministic identity of the current active version (UUIDv5 "
            "over playbook_id|version|source_hash)."
        ),
    )

    source_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="Recorded SHA-256 digest of the canonical definition (hex).",
    )

    primary_action: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="The action the playbook orchestrates (CHECK-pinned).",
    )

    failure_policy: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="stop_on_failure | continue_on_failure (CHECK-pinned).",
    )

    steps: Mapped[list] = mapped_column(
        JSONB().with_variant(JSON, "sqlite"),
        default=list,
        nullable=False,
        comment="Read mirror of the active version's declarative steps.",
    )

    enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        comment="Whether the playbook may be executed.",
    )

    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", name="fk_soar_playbooks_created_by_users"),
        nullable=True,
        comment="Trusted identity that registered this playbook.",
    )

    created_by_role: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
        comment="Role label of the registering actor.",
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<SoarPlaybookRow id={self.id} "
            f"playbook={self.playbook_id} version={self.version} "
            f"enabled={self.enabled}>"
        )