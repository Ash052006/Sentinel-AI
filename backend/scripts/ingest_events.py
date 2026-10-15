"""Ingest a JSON Lines file into the SentinelAI detection pipeline.

Runs the same service the HTTP endpoint uses
(:func:`app.services.ingest_service.ingest_jsonl`), so terminal and browser
ingestion behave identically:

    FileLogCollector -> NormalizationAgent -> DetectionAgent -> persistence

Usage:
    python scripts/ingest_events.py path/to/events.jsonl
    python scripts/ingest_events.py events.jsonl --json
    python scripts/ingest_events.py events.jsonl --dry-run

The active rule set is rebuilt from the governed deployment table and
fails closed if any deployed rule is missing or its source hash changed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.database.postgres.session import SessionLocal  # noqa: E402
from app.services.ingest_service import (  # noqa: E402
    IngestRuleSetUnavailableError,
    ingest_jsonl,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Ingest a JSON Lines file into the detection pipeline.",
    )
    parser.add_argument("path", type=Path, help="Path to the .jsonl file to ingest.")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the run summary as JSON instead of a table.",
    )
    parser.add_argument(
        "--max-events",
        type=int,
        default=5_000,
        help="Maximum number of events to process (default: 5000).",
    )
    args = parser.parse_args()

    if not args.path.is_file():
        print(f"error: no such file: {args.path}", file=sys.stderr)
        return 2

    content = args.path.read_text(encoding="utf-8")

    with SessionLocal() as db:
        try:
            summary = ingest_jsonl(db, content, max_events=args.max_events)
        except IngestRuleSetUnavailableError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 3
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.json:
        # The per-event raw/normalized trace is an HTTP-console affordance;
        # it is excluded here so the CLI's JSON output stays a run summary.
        print(
            json.dumps(
                summary.model_dump(mode="json", exclude={"events"}), indent=2
            )
        )
        return 0

    print()
    print(f"  file                {args.path}")
    print(f"  active rules        {summary.active_rule_count}")
    print(f"  records read        {summary.total_records}")
    print(f"  events accepted     {summary.accepted_events}")
    print(f"  records rejected    {summary.rejected_records}")
    print(f"  events processed    {summary.events_processed}")
    print(f"  detections          {summary.detections}")
    print(f"  events with hits    {summary.events_with_detections}")
    print(f"  results written     {summary.detection_results_created}")
    print(f"  rule failures       {summary.rule_failures}")
    print(f"  duration            {summary.duration_ms} ms")

    if summary.errors:
        shown = summary.errors[:10]
        print()
        print(f"  Rejected lines ({len(shown)} shown"
              f"{', truncated' if summary.truncated_errors else ''}):")
        for err in shown:
            where = f"line {err.line_number}" if err.line_number else "event"
            print(f"    {where}: {err.reason}")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
