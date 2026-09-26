"""Detection-as-Code quality report (V2.17).

Builds a deterministic report over the **governed database inventory**
joined with the controlled manifest.  Every field is derived from persisted
state or live re-validation — never fabricated.  Asserts the task's global
invariants:

* the inventory is exactly the expected baseline: Sigma 28 + YARA 25;
* ``all_rules_pass`` is true — every governed rule is validated, released
  and deployed, and every rule compiles + passes its fixtures.

Exits non-zero when either invariant fails.  Writes a machine-readable
report to ``backend/app/services/detection/detection_as_code_quality_report.json``.

Usage:
    python scripts/detection_as_code_quality_report.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.database.postgres.session import SessionLocal
from app.services.detection_as_code.quality import (
    DetectionAsCodeQualityReportService,
)

_REPORT_PATH = (
    Path("app/services/detection/detection_as_code_quality_report.json")
)


def main() -> int:
    db = SessionLocal()
    try:
        service = DetectionAsCodeQualityReportService(db)
        report = service.build()
        payload = service.to_dict(report)

        _REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        _REPORT_PATH.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        counts = payload["quality_report"]["inventory_counts"]
        ok = (
            counts["sigma"] == 28
            and counts["yara"] == 25
            and counts["total_sources"] == 53
        )
        if not ok:
            print(
                "FATAL inventory mismatch: "
                f"sigma={counts['sigma']} yara={counts['yara']} "
                f"total={counts['total_sources']}"
            )
            return 1

        print(
            f"sigma={counts['sigma']} yara={counts['yara']} "
            f"total={counts['total_sources']} "
            f"governed={counts['governed_versions']} "
            f"all_rules_pass={report.all_rules_pass} "
            f"-> {_REPORT_PATH}"
        )
        if not report.all_rules_pass:
            for entry in report.entries:
                if not (
                    entry.loads
                    and entry.compiles
                    and entry.positive_passed
                    and entry.negative_passed
                    and entry.validation
                    and entry.release
                    and entry.deployment
                ):
                    print(
                        "FAIL",
                        entry.rule_id,
                        entry.version,
                        dict(
                            loads=entry.loads,
                            compiles=entry.compiles,
                            positive=entry.positive_passed,
                            negative=entry.negative_passed,
                            validation=entry.validation,
                            release=entry.release,
                            deployment=entry.deployment,
                        ),
                    )
            return 1
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())