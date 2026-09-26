"""Detection-as-Code baseline onboarding (V2.17).

Validates, releases and deploys the **entire controlled rule set** against
PostgreSQL so the baseline inventory is fully governed.  Idempotent: on a
second run every rule is already validated/released/deployed and this
script is a no-op (still reporting the same counts).

Every version stays 1.0.0 unless the content changed since its governed
version — any content change on a later run requires the explicit
validate/release/deploy flow with a bumped version.

Usage:
    python scripts/detection_as_code_onboard.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.database.postgres.session import SessionLocal
from app.services.detection_as_code.lifecycle import LifecycleService
from app.services.detection_as_code.manifest import load_manifest


def main() -> int:
    root = Path("app/services/detection/rules").resolve()
    manifest = load_manifest(root)

    db = SessionLocal()
    try:
        lifecycle = LifecycleService(db, actor_role="admin")
        started = time.time()

        validated = released = deployed = 0
        failures: list[str] = []
        for entry in sorted(manifest.rules, key=lambda e: e.rule_id):
            try:
                lifecycle.validate_rule(entry.rule_id)
                validated += 1
                lifecycle.release(entry.rule_id, entry.version)
                released += 1
                lifecycle.deploy(entry.rule_id, entry.version)
                deployed += 1
            except Exception as exc:  # noqa: BLE001 - report and continue
                failures.append(f"{entry.rule_id}: {exc}")

        print(
            f"onboarded {validated}/{len(manifest.rules)} validated, "
            f"{released} released, {deployed} deployed "
            f"in {time.time() - started:.1f}s"
        )
        if failures:
            for failure in failures:
                print("FAIL", failure)
            return 1
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())