"""Seed (or remove) clearly-labelled synthetic Threat Intelligence demo data.

Companion script for :mod:`app.services.threat_intelligence_demo`.  Use it to
populate a local database so the ``/threat-intelligence`` console has something
honest to render, without ever fabricating a real-provider result.

Every synthetic lookup is filed under the invented provider name
``demo-fixture`` and carries ``{"synthetic": true, ...}`` evidence, so a fixture
is always visibly distinct from live intelligence.

Usage::

    python scripts/seed_threat_intel_demo.py --list      # show fixtures + counts (no writes)
    python scripts/seed_threat_intel_demo.py --seed      # idempotent insert
    python scripts/seed_threat_intel_demo.py --cleanup   # delete demo-owned rows only
    python scripts/seed_threat_intel_demo.py --seed --database-url postgresql+psycopg://.../demo

Safety: the seeder refuses to run when ``ENVIRONMENT=production``.  It writes
directly to the database and never contacts Kafka or any external provider.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import Session, sessionmaker  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.services.threat_intelligence_demo import (  # noqa: E402
    DEMO_PROVIDER_NAME,
    DemoSeedForbiddenError,
    build_demo_analyses,
    cleanup,
    demo_row_counts,
    seed,
)


def _open_session(database_url: str | None) -> tuple[Session, str]:
    """Open a session against *database_url*, else the configured database."""
    if database_url:
        engine = create_engine(database_url)
        return sessionmaker(bind=engine)(), database_url
    from app.database.postgres.session import SessionLocal

    return SessionLocal(), settings.database_url


def _describe_fixtures() -> None:
    print(f"provider label for every fixture: {DEMO_PROVIDER_NAME!r}")
    print("indicators (value / type / outcome):")
    for analysis in build_demo_analyses():
        indicator = analysis.indicators[0]
        if analysis.results:
            outcome = "returned data" if analysis.results[0].result.found else "no match"
        elif analysis.failures:
            outcome = analysis.failures[0].error_type
        else:
            outcome = "never looked up"
        print(f"  {indicator.indicator:<48} {indicator.indicator_type.value:<6} {outcome}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--list", action="store_true", help="Show fixtures and exit.")
    group.add_argument("--seed", action="store_true", help="Add the demo fixtures.")
    group.add_argument(
        "--cleanup", action="store_true", help="Remove demo-owned rows only."
    )
    parser.add_argument(
        "--database-url",
        default=None,
        help=(
            "Run against this database instead of the configured one.  Point it "
            "at an isolated local demo database to keep demo data separate."
        ),
    )
    args = parser.parse_args()

    if args.list or not (args.seed or args.cleanup):
        _describe_fixtures()
        db, url = _open_session(args.database_url)
        try:
            counts = demo_row_counts(db)
        finally:
            db.close()
        print()
        print(f"target database: {url or '<configured DATABASE_URL>'}")
        print(f"current demo rows: {counts['indicators']} indicator(s), {counts['lookups']} lookup(s)")
        print("run with --seed to add, --cleanup to remove.")
        return 0

    db, url = _open_session(args.database_url)
    try:
        if args.seed:
            try:
                result = seed(db)
            except DemoSeedForbiddenError as exc:
                print(f"refused: {exc}", file=sys.stderr)
                return 1
            print(f"target database: {url or '<configured DATABASE_URL>'}")
            print(
                f"seeded {result.events} event(s): "
                f"indicators +{result.indicators_created}/~{result.indicators_updated}, "
                f"lookups +{result.lookups_created} (skipped {result.lookups_skipped} identical)"
            )
            if not result.created_anything:
                print("nothing new created (already seeded -- idempotent).")
            print(
                "Open /threat-intelligence; every row is provider "
                f"{DEMO_PROVIDER_NAME!r} and marked synthetic."
            )
        else:
            try:
                result = cleanup(db)
            except DemoSeedForbiddenError as exc:
                print(f"refused: {exc}", file=sys.stderr)
                return 1
            print(
                f"removed {result.lookups_deleted} demo lookup(s) and "
                f"{result.indicators_deleted} demo indicator(s); real rows untouched."
            )
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
