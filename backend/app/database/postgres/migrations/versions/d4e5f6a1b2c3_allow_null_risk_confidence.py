"""make risk_assessments.confidence nullable

The risk engine propagated an absent correlation confidence by substituting a
``0.0`` baseline, which the schema then enforced as mandatory.  That made an
*unproduced* confidence indistinguishable from a *measured* zero by any reader
of the API, the database, or the UI: a bare ``0.0`` reads as a measurement.

The engine now propagates ``None`` (see
``app/services/risk/engine.py::confidence_for_correlation``), mirroring
``correlation_results.confidence``, which is already nullable for exactly this
reason.  This migration drops the NOT NULL constraint so the database can store
the honest value.

The ``risk_confidence_range`` CHECK constraint (``0.0 <= confidence <= 1.0``)
is deliberately left in place: it continues to constrain every non-null value,
and SQL CHECK semantics let a NULL row through.

Existing rows are untouched and no data is rewritten.  Dropping a NOT NULL in
PostgreSQL only rewrites the table's metadata, not its rows.

Revision ID: d4e5f6a1b2c3
Revises: c3d4e5f6a1b2
Create Date: 2026-10-03 20:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'd4e5f6a1b2c3'
down_revision: Union[str, Sequence[str], None] = 'c3d4e5f6a1b2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_TABLE = 'risk_assessments'
_COLUMN = 'confidence'

_COMMENT = (
    "Step 11B assessment confidence in [0.0, 1.0] "
    "(CHECK-constrained), persisted exactly as produced.  "
    "Independent of score/level; never a risk score.  "
    "NULL means the source correlation asserted no confidence, so "
    "none was produced -- it does not mean zero confidence."
)

_PRIOR_COMMENT = (
    "Step 11B assessment confidence in [0.0, 1.0] "
    "(CHECK-constrained), persisted exactly as produced.  "
    "Independent of score/level; never a risk score."
)


def upgrade() -> None:
    op.alter_column(
        _TABLE,
        _COLUMN,
        existing_type=postgresql.DOUBLE_PRECISION(),
        nullable=True,
        existing_comment=_PRIOR_COMMENT,
        comment=_COMMENT,
    )


def downgrade() -> None:
    # A downgrade cannot restore NOT NULL while null rows exist: doing so would
    # fail.  Refuse loudly rather than silently substituting a fabricated 0.0,
    # which is the very confusion this migration removes.
    message = (
        f"cannot restore NOT NULL on {_TABLE}.{_COLUMN}: rows with no recorded "
        f"confidence exist. Replace them explicitly if that is truly intended; "
        f"this migration will not invent a 0.0 for them."
    )
    op.execute(
        "DO $$ BEGIN "
        f"IF EXISTS (SELECT 1 FROM {_TABLE} WHERE {_COLUMN} IS NULL) THEN "
        f"RAISE EXCEPTION '{message}'; "
        "END IF; END $$;"
    )
    op.alter_column(
        _TABLE,
        _COLUMN,
        existing_type=postgresql.DOUBLE_PRECISION(),
        nullable=False,
        existing_comment=_COMMENT,
        comment=_PRIOR_COMMENT,
    )