"""seed foundational SOC roles (data migration)

The V2 ``roles`` reference data (admin / analyst / ciso) is required by
:func:`app.api.routes.auth.register` (the first registered user atomically
maps to ``admin``), but the founding table migration only created the
empty table — a fresh database had no roles, so registration and login
failed with a 500.  This data migration seeds the three SOC roles
idempotently, with deterministic identities, so any database — whether
fresh or already carrying rows — converges to the same reference data.

Revision ID: 9c2d4e6f8a1b
Revises: 8a1b2c3d4e5f
Create Date: 2026-09-26 09:00:00.000000

"""
import uuid
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '9c2d4e6f8a1b'
down_revision: Union[str, Sequence[str], None] = '8a1b2c3d4e5f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

#: Deterministic identity of each seeded role (UUIDv5 over a fixed URL
#: namespace) so the migration is idempotent across environments and the
#: identities never collide across re-runs.
_NAMESPACE = uuid.NAMESPACE_URL

_roles: tuple[tuple[str, str], ...] = (
    ("admin", "Full administrative access to the SentinelAI SOC platform. The first registered user is mapped to this role."),
    ("analyst", "Security analyst. Authorized to triage detections, drive the human-in-the-loop governance workflow, and read platform data."),
    ("ciso", "Chief Information Security Officer. Authorized to grant or reject human-in-the-loop governance requests and review platform posture."),
)


def _seed_rows() -> list[dict[str, object]]:
    rows = []
    for name, description in _roles:
        rows.append(
            {
                "name": name,
                "description": description,
                "id": uuid.uuid5(_NAMESPACE, f"sentinelai/role/{name}"),
                "created_at": sa.func.now(),
                "updated_at": sa.func.now(),
            }
        )
    return rows


def upgrade() -> None:
    """Seed the three SOC roles idempotently (ON CONFLICT DO NOTHING)."""
    bind = op.get_bind()
    table = sa.table(
        "roles",
        sa.column("id", sa.UUID()),
        sa.column("name", sa.String()),
        sa.column("description", sa.String()),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    for row in _seed_rows():
        bind.execute(
            postgresql.insert(table)
            .on_conflict_do_nothing(index_elements=["name"])
            .values(row)
        )


def downgrade() -> None:
    """Remove exactly the seeded roles (by their deterministic ids).

    Safe on a fresh database; on a database where users reference a seeded
    role the foreign key will refuse the delete, which is the correct
    conservative failure for a downgrade.
    """
    bind = op.get_bind()
    table = sa.table("roles", sa.column("id", sa.UUID()))
    ids = [uuid.uuid5(_NAMESPACE, f"sentinelai/role/{name}") for name, _ in _roles]
    bind.execute(table.delete().where(table.c.id.in_(ids)))