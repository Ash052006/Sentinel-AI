"""Detection-as-Code validate-all (V2.17).

Runs the full validation pipeline over the **entire controlled manifest**
with no database, no network, no LLM.  Every governed rule must pass every
gate (source exists, path safe, hash matches, secret safe, compiles,
positive fixture matches, negative fixture silent) or the script exits
non-zero with the failures.

Usage:
    python scripts/detection_as_code_validate_all.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.services.detection_as_code.manifest import load_manifest
from app.services.detection_as_code.validation import (
    DetectionRuleValidationService,
)


def main() -> int:
    root = Path("app/services/detection/rules").resolve()
    manifest = load_manifest(root)
    validator = DetectionRuleValidationService(rules_root=root)

    passed = 0
    failed: list[tuple[str, str, list[str]]] = []
    started = time.time()

    for entry in sorted(manifest.rules, key=lambda e: e.rule_id):
        detail = validator.validate(entry, manifest)
        if detail.passed:
            passed += 1
        else:
            failed.append((entry.rule_id, entry.source, list(detail.errors)))

    print(
        f"validated {passed}/{len(manifest.rules)} rules "
        f"in {time.time() - started:.1f}s"
    )
    if failed:
        for rule_id, source, errors in failed:
            print(f"FAIL {rule_id} ({source}): {errors[:2]}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())