"""portable detection-as-code source-hash check

Replace the PostgreSQL-only regex CHECK on detection_rule_changes.to_source_hash
(``to_source_hash ~ '^[0-9a-f]{64}$'``) with a cross-engine length CHECK
(``length(to_source_hash) = 64``) so the governed tables can also be created on
SQLite (in-memory test harnesses).  Full hex-64 integrity is enforced by the
service layer; this keeps a length guard in the schema that compiles on every
backend.

The constraint names are operated on explicitly.  ``op.*`` helpers re-apply
this repository's ``ck_%(table_name)s_%(constraint_name)s`` naming convention,
so the altered constraints are referenced by their stored names (SQLAlchemy's
truncation hash suffix is deterministic for this repos pinned dependency set;
``IF EXISTS`` keeps this idempotent).

Revision ID: 5d9e0b7c2f4a6d81
Revises: 4c8f2d1a9b3e
Create Date: 2026-09-23 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '5d9e0b7c2f4a6d81'
down_revision: Union[str, Sequence[str], None] = '4c8f2d1a9b3e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE = 'detection_rule_changes'
_COLUMN = 'to_source_hash'
_HEX_CHECK = "to_source_hash ~ '^[0-9a-f]{64}$'"
_HEX_NAME = 'ck_detection_rule_changes_ck_detection_rule_changes_det_082a'
_LENGTH_NAME = 'ck_dac_changes_source_hash_len'


def upgrade() -> None:
    """Upgrade schema."""
    op.execute(
        f"ALTER TABLE {_TABLE} DROP CONSTRAINT IF EXISTS {_HEX_NAME}"
    )
    op.execute(
        f"ALTER TABLE {_TABLE} ADD CONSTRAINT {_LENGTH_NAME} "
        f"CHECK (length({_COLUMN}) = 64)"
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.execute(
        f"ALTER TABLE {_TABLE} DROP CONSTRAINT IF EXISTS {_LENGTH_NAME}"
    )
    op.execute(
        f"ALTER TABLE {_TABLE} ADD CONSTRAINT {_HEX_NAME} "
        f"CHECK ({_HEX_CHECK})"
    )