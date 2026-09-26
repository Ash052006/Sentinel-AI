"""Detection rule quality report generator — Batch 1.

Evaluates the **entire shipped repository rule set** (28 Sigma + 25 YARA)
through the real engines without any database, network, or LLM:

* ``loads``          — the rule loaded from disk as a ``DetectionRule``.
* ``compiles``       — Sigma: parses via ``SigmaCollection.from_dicts``
  and passes engine validation; YARA: ``yara.compile(source=...)``.
* ``positive_test``  — fires on its intended positive synthetic fixture.
* ``negative_test``  — stays silent on its benign negative fixture.

Writes a deterministic, machine-readable report to
``backend/app/services/detection/detection_rule_quality_report.json`` whose
records carry ``{rule_id, rule_type, title, severity, version, loads,
compiles, positive_test, negative_test}`` plus aggregate counts.  The report
contains no secrets.

Exits non-zero if any rule fails any check.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.schemas.detection import RuleType  # noqa: E402
from app.services.detection.batch1_content import (  # noqa: E402
    YARA_BENIGN_BYTES,
    YARA_POSITIVES,
    benign_event,
    positive_sigma_event,
)
from app.services.detection.rule_loader import load_detection_rules  # noqa: E402
from app.services.detection.sigma.engine import SigmaDetectionEngine  # noqa: E402
from app.services.detection.yara.engine import YaraDetectionEngine  # noqa: E402
from app.services.detection.yara.target_adapter import YaraTarget  # noqa: E402

REPORT_PATH = REPO_ROOT / "app" / "services" / "detection" / "detection_rule_quality_report.json"


def _sigma_record(rule, sigma_by_id, engine: SigmaDetectionEngine) -> dict:
    loaded = True
    compiles = True
    positive = False
    negative = False

    try:
        positive_event = positive_sigma_event(rule.rule_id)
    except KeyError:
        positive_event = None

    # Compilation + benign negative evaluation in one pass over the full set.
    benign_rules = list(sigma_by_id.values())
    benign_report = engine.evaluate(benign_event(rule.rule_id), rules=benign_rules)
    for failure in benign_report.failures:
        if failure.rule_id == rule.rule_id:
            compiles = False
            break
    negative = bool(compiles and not benign_report.results)

    if compiles and positive_event is not None:
        positive_report = engine.evaluate(positive_event, rules=[sigma_by_id[rule.rule_id]])
        if not positive_report.failures:
            positive = any(r.rule_id == rule.rule_id for r in positive_report.results)

    return {
        "rule_id": str(rule.rule_id),
        "rule_type": "sigma",
        "title": rule.name,
        "severity": rule.severity.value,
        "version": rule.version or "1.0.0",
        "loads": loaded,
        "compiles": compiles,
        "positive_test": positive,
        "negative_test": negative,
    }


def _yara_record(rule, yara_by_id, engine: YaraDetectionEngine) -> dict:
    loaded = True
    compiles = True
    positive = False
    negative = False

    try:
        positive_bytes = YARA_POSITIVES[rule.rule_id]
    except KeyError:
        positive_bytes = None

    negative_report = engine.evaluate_target(
        YaraTarget(content=YARA_BENIGN_BYTES, file_name="app.log"),
        rules=[rule],
    )
    if negative_report.failures:
        compiles = False
    negative = bool(compiles and not negative_report.results)

    if compiles and positive_bytes is not None:
        positive_report = engine.evaluate_target(
            YaraTarget(content=positive_bytes, file_name="hit.bin"),
            rules=[rule],
        )
        if not positive_report.failures:
            positive = any(r.rule_id == rule.rule_id for r in positive_report.results)

    return {
        "rule_id": str(rule.rule_id),
        "rule_type": "yara",
        "title": rule.name,
        "severity": rule.severity.value,
        "version": rule.version or "1.0.0",
        "loads": loaded,
        "compiles": compiles,
        "positive_test": positive,
        "negative_test": negative,
    }


def main() -> int:
    rules = load_detection_rules()
    if len(rules) != 53:
        print(f"FAIL: expected 53 rules, loaded {len(rules)}")
        return 1

    sigma_by_id = {r.rule_id: r for r in rules if r.rule_type is RuleType.SIGMA}
    yara_by_id = {r.rule_id: r for r in rules if r.rule_type is RuleType.YARA}

    sigma_engine = SigmaDetectionEngine()
    yara_engine = YaraDetectionEngine()

    records: list[dict] = []
    for rule in rules:
        if rule.rule_type is RuleType.SIGMA:
            records.append(_sigma_record(rule, sigma_by_id, sigma_engine))
        else:
            records.append(_yara_record(rule, yara_by_id, yara_engine))

    counts = {
        "sigma_total": len([r for r in records if r["rule_type"] == "sigma"]),
        "yara_total": len([r for r in records if r["rule_type"] == "yara"]),
        "total": len(records),
        "sigma_positive": sum(
            1 for r in records if r["rule_type"] == "sigma" and r["positive_test"]
        ),
        "yara_positive": sum(
            1 for r in records if r["rule_type"] == "yara" and r["positive_test"]
        ),
        "sigma_negative": sum(
            1 for r in records if r["rule_type"] == "sigma" and r["negative_test"]
        ),
        "yara_negative": sum(
            1 for r in records if r["rule_type"] == "yara" and r["negative_test"]
        ),
        "compiles": sum(1 for r in records if r["compiles"]),
    }

    report = {"generated_utc": None, "counts": counts, "rules": records}

    all_ok = (
        counts["sigma_total"] >= 28
        and counts["yara_total"] >= 25
        and counts["total"] >= 53
        and counts["sigma_positive"] == counts["sigma_total"]
        and counts["yara_positive"] == counts["yara_total"]
        and counts["sigma_negative"] == counts["sigma_total"]
        and counts["yara_negative"] == counts["yara_total"]
        and counts["compiles"] == counts["total"]
    )
    report["all_rules_pass"] = bool(all_ok)

    REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"Wrote {REPORT_PATH}")

    print("\nRule quality summary:")
    print(f"  Sigma : {counts['sigma_total']:>2} loaded  "
          f"positive {counts['sigma_positive']:>2}/{counts['sigma_total']:>2}  "
          f"negative {counts['sigma_negative']:>2}/{counts['sigma_total']:>2}")
    print(f"  YARA  : {counts['yara_total']:>2} loaded  "
          f"positive {counts['yara_positive']:>2}/{counts['yara_total']:>2}  "
          f"negative {counts['yara_negative']:>2}/{counts['yara_total']:>2}")
    print(f"  Total : {counts['total']:>2} rules  "
          f"{counts['compiles']}/{counts['total']} compile")
    print(f"  all_rules_pass: {all_ok}")

    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())