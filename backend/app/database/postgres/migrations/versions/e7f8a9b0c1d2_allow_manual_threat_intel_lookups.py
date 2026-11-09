"""allow manual threat intel lookups (nullable event_id and origin)

Revision ID: e7f8a9b0c1d2
Revises: 6b15aae93f78
Create Date: 2026-11-07 22:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'e7f8a9b0c1d2'
down_revision: Union[str, Sequence[str], None] = '6b15aae93f78'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema to allow manual threat intelligence lookups."""
    # 1. Alter event_id column to be nullable so manual lookups without an event can be stored.
    op.alter_column(
        'threat_intel_lookups',
        'event_id',
        existing_type=postgresql.UUID(as_uuid=True),
        nullable=True,
    )

    # 2. Add an origin column to distinguish 'event' and 'manual' lookups.
    op.add_column(
        'threat_intel_lookups',
        sa.Column(
            'origin',
            sa.String(length=32),
            nullable=False,
            server_default='event',
            comment="Origin of the lookup: 'event' or 'manual'.",
        ),
    )

    # 3. Add CHECK constraint enforcing valid origin values.
    op.create_check_constraint(
        'ck_threat_intel_lookups_origin_valid',
        'threat_intel_lookups',
        "origin IN ('event', 'manual')",
    )


def downgrade() -> None:
    """Downgrade schema safely without silently deleting or corrupting manual lookups.

    Non-destructive downgrade precondition:
    Aborts if any records have event_id IS NULL or origin = 'manual'.
    """
    bind = op.get_bind()
    manual_count = bind.execute(
        sa.text(
            "SELECT COUNT(*) FROM threat_intel_lookups WHERE event_id IS NULL OR origin = 'manual'"
        )
    ).scalar()
    if manual_count:
        raise RuntimeError(
            f"Cannot downgrade migration e7f8a9b0c1d2: {manual_count} manual lookup record(s) exist "
            "with null event_id or origin='manual'. Reconcile, archive, or export these records before "
            "downgrading, as event_id cannot be set to NOT NULL without deleting or corrupting manual lookups."
        )

    op.drop_constraint('ck_threat_intel_lookups_origin_valid', 'threat_intel_lookups', type_='check')
    op.drop_column('threat_intel_lookups', 'origin')
    op.alter_column(
        'threat_intel_lookups',
        'event_id',
        existing_type=postgresql.UUID(as_uuid=True),
        nullable=False,
    )
