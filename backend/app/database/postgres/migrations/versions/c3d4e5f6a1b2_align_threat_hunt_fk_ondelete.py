"""align threat-hunt foreign keys with the model's delete semantics

The V2.19 hunt migration (``7a1b2c3d4e5f``) created the four hunt foreign
keys without an ``ondelete`` action, so PostgreSQL applied its default
``NO ACTION``.  The models have always declared the intended behaviour::

    threat_hunts.created_by            -> users.id            ON DELETE RESTRICT
    threat_hunt_evidence.hunt_id       -> threat_hunts.hunt_id ON DELETE CASCADE
    threat_hunt_findings.hunt_id       -> threat_hunts.hunt_id ON DELETE CASCADE
    threat_hunt_timeline_items.hunt_id -> threat_hunts.hunt_id ON DELETE CASCADE

The database therefore did not implement the documented contract: removing a
hunt that still had evidence, findings or timeline rows raised an FK
violation (surfacing as an IntegrityError/500) instead of cascading, and the
drift was invisible until ``alembic check`` compared the live schema against
the models.

This migration drops and recreates each constraint with the declared action,
so the live schema matches the models.  Recreating a constraint takes a brief
``ACCESS EXCLUSIVE`` lock on the table; these are small governance tables and
the operation is metadata-only, so no long-running rewrite or table lock is
involved.  Existing rows are untouched and no data is rewritten.

Revision ID: c3d4e5f6a1b2
Revises: 9c2d4e6f8a1b
Create Date: 2026-09-27 11:00:00.000000

"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'c3d4e5f6a1b2'
down_revision: Union[str, Sequence[str], None] = '9c2d4e6f8a1b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


#: ``(constraint_name, table, column, referenced_table, referenced_column,
#: ondelete)`` for every hunt foreign key whose delete action must change.
_FOREIGN_KEYS: tuple[tuple[str, str, str, str, str, str], ...] = (
    (
        'fk_threat_hunts_created_by_users',
        'threat_hunts',
        'created_by',
        'users',
        'id',
        'RESTRICT',
    ),
    (
        'fk_threat_hunt_evidence_hunt_id_threat_hunts',
        'threat_hunt_evidence',
        'hunt_id',
        'threat_hunts',
        'hunt_id',
        'CASCADE',
    ),
    (
        'fk_threat_hunt_findings_hunt_id_threat_hunts',
        'threat_hunt_findings',
        'hunt_id',
        'threat_hunts',
        'hunt_id',
        'CASCADE',
    ),
    (
        'fk_threat_hunt_timeline_items_hunt_id_threat_hunts',
        'threat_hunt_timeline_items',
        'hunt_id',
        'threat_hunts',
        'hunt_id',
        'CASCADE',
    ),
)


def upgrade() -> None:
    """Recreate each hunt foreign key with its declared ON DELETE action."""
    for name, table, column, ref_table, ref_column, ondelete in _FOREIGN_KEYS:
        op.drop_constraint(name, table, type_='foreignkey')
        op.create_foreign_key(
            name,
            table,
            ref_table,
            [column],
            [ref_column],
            ondelete=ondelete,
        )


def downgrade() -> None:
    """Restore the original ``NO ACTION`` delete behaviour."""
    for name, table, column, ref_table, ref_column, _ondelete in _FOREIGN_KEYS:
        op.drop_constraint(name, table, type_='foreignkey')
        op.create_foreign_key(
            name,
            table,
            ref_table,
            [column],
            [ref_column],
        )
