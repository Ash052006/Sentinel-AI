"""add event lookup idempotency partial unique index

Revision ID: f8a9b0c1d2e3
Revises: e7f8a9b0c1d2
Create Date: 2026-11-07 23:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f8a9b0c1d2e3'
down_revision: Union[str, Sequence[str], None] = 'e7f8a9b0c1d2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create partial unique index for event-origin lookups after duplicate preflight check."""
    bind = op.get_bind()

    # Preflight check: detect existing duplicates for (event_id, indicator_id, provider) on event-origin lookups
    duplicate_rows = bind.execute(sa.text("""
        SELECT event_id, indicator_id, provider, COUNT(*) as cnt
        FROM threat_intel_lookups
        WHERE event_id IS NOT NULL AND origin = 'event'
        GROUP BY event_id, indicator_id, provider
        HAVING COUNT(*) > 1
    """)).fetchall()

    if duplicate_rows:
        sample = [
            f"(event_id={row[0]}, indicator_id={row[1]}, provider={row[2]}, count={row[3]})"
            for row in duplicate_rows[:5]
        ]
        raise RuntimeError(
            f"Cannot create unique index ix_threat_intel_lookups_event_indicator_provider: "
            f"found {len(duplicate_rows)} duplicate group(s) among event-origin lookups. "
            f"Precondition failed. Manual reconciliation is required before creating the unique index. "
            f"Sample duplicates: {', '.join(sample)}"
        )

    op.create_index(
        'ix_threat_intel_lookups_event_indicator_provider',
        'threat_intel_lookups',
        ['event_id', 'indicator_id', 'provider'],
        unique=True,
        postgresql_where=sa.text("event_id IS NOT NULL AND origin = 'event'"),
        sqlite_where=sa.text("event_id IS NOT NULL AND origin = 'event'"),
    )


def downgrade() -> None:
    """Drop the partial unique index."""
    op.drop_index(
        'ix_threat_intel_lookups_event_indicator_provider',
        table_name='threat_intel_lookups',
    )
