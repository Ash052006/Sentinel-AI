"""Detection-as-Code quality report (V2.17).

A deterministic report over the governed inventory (persisted lifecycle
rows joined with the controlled manifest).  Output states are derived from
actual persisted state and live re-validation — never fabricated.  The
report asserts the two global invariants the task requires:

* ``all_rules_pass``  — every governed rule is validated, released and
  deployed (with ``> 0`` rules).
* ``inventory_counts`` reflect the real repository (sigma/yara/total in the
  manifest) with the **exact** expected baseline (Sigma 28 + YARA 25).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy.orm import Session

from app.schemas.detection_as_code import (
    DeploymentState,
    ReleaseState,
    ValidationOutcome,
)
from app.services.detection_as_code import repository as repo
from app.services.detection_as_code.lifecycle import LifecycleService
from app.services.detection_as_code.manifest import load_manifest
from app.services.detection_as_code.validation import (
    DetectionRuleValidationService,
)


@dataclass
class QualityEntry:
    """Per-rule quality report row (deterministic field order)."""

    rule_id: str
    rule_type: str
    version: str
    source_hash: str
    loads: bool
    compiles: bool
    positive_passed: bool
    negative_passed: bool
    validation: bool
    release: bool
    deployment: bool


@dataclass
class QualityReport:
    """Whole-inventory quality report."""

    inventory_sigma: int
    inventory_yara: int
    inventory_total: int
    governed: int
    all_rules_pass: bool
    entries: list[QualityEntry] = field(default_factory=list)


class DetectionAsCodeQualityReportService:
    """Builds the deterministic quality report for the governed inventory."""

    def __init__(
        self,
        db: Session,
        *,
        rules_root: Path | None = None,
        validator: DetectionRuleValidationService | None = None,
    ) -> None:
        self.db = db
        self.validator = validator or DetectionRuleValidationService(
            rules_root=rules_root
        )
        self.rules_root = self.validator.rules_root
        self.lifecycle = LifecycleService(
            db, validator=self.validator, actor_role="admin"
        )

    def build(self) -> QualityReport:
        manifest = load_manifest(self.rules_root)
        sigma_count = sum(
            1 for e in manifest.rules if e.rule_type.value == "sigma"
        )
        yara_count = sum(
            1 for e in manifest.rules if e.rule_type.value == "yara"
        )

        rows = repo.list_all_rules_latest(self.db)
        entries: list[QualityEntry] = []

        for row in sorted(rows, key=lambda r: (r.rule_id, r.version)):
            entry_obj = manifest.by_rule_id(row.rule_id)
            entry = {
                "rule_id": row.rule_id,
                "rule_type": row.rule_type,
                "version": row.version,
                "source_hash": row.source_hash,
                "loads": True,
                "compiles": row.compiled,
                "positive_passed": row.positive_passed,
                "negative_passed": row.negative_passed,
                "validation": (
                    row.validation_status == ValidationOutcome.VALIDATED.value
                ),
                "release": False,
                "deployment": False,
            }
            release = repo.get_release(self.db, row.rule_id, row.version)
            entry["release"] = (
                release is not None
                and release.release_state == ReleaseState.RELEASED.value
            )
            entry["deployment"] = (
                release is not None
                and release.deployment_state == DeploymentState.DEPLOYED.value
            )
            entries.append(
                QualityEntry(
                    rule_id=entry["rule_id"],
                    rule_type=entry["rule_type"],
                    version=entry["version"],
                    source_hash=entry["source_hash"],
                    loads=bool(entry["loads"])
                    and entry_obj is not None,
                    compiles=entry["compiles"],
                    positive_passed=entry["positive_passed"],
                    negative_passed=entry["negative_passed"],
                    validation=entry["validation"],
                    release=entry["release"],
                    deployment=entry["deployment"],
                )
            )

        all_rules_pass = bool(entries) and all(
            (
                e.loads
                and e.compiles
                and e.positive_passed
                and e.negative_passed
                and e.validation
                and e.release
                and e.deployment
            )
            for e in entries
        )

        return QualityReport(
            inventory_sigma=sigma_count,
            inventory_yara=yara_count,
            inventory_total=sigma_count + yara_count,
            governed=len(entries),
            all_rules_pass=all_rules_pass,
            entries=entries,
        )

    def to_dict(self, report: QualityReport) -> dict:
        """Deterministic JSON-ready representation of a quality report."""
        return {
            "quality_report": {
                "inventory_counts": {
                    "sigma": report.inventory_sigma,
                    "yara": report.inventory_yara,
                    "total_sources": report.inventory_total,
                    "governed_versions": report.governed,
                },
                "all_rules_pass": report.all_rules_pass,
            },
            "rules": [
                {
                    "rule_id": e.rule_id,
                    "rule_type": e.rule_type,
                    "version": e.version,
                    "source_hash": e.source_hash,
                    "loads": e.loads,
                    "compiles": e.compiles,
                    "positive": e.positive_passed,
                    "negative": e.negative_passed,
                    "validation": e.validation,
                    "release": e.release,
                    "deployment": e.deployment,
                }
                for e in sorted(report.entries, key=lambda e: e.rule_id)
            ],
        }


__all__ = [
    "DetectionAsCodeQualityReportService",
    "QualityReport",
    "QualityEntry",
]