"""Detection-as-Code validation pipeline (V2.17) — fail-closed.

Validates one governed rule through the **real** Sigma/YARA engines, every
gate server-side, deterministic, and honest:

=============  =============================================================
gate           meaning
=============  =============================================================
manifest_valid  the manifest entry is unique + contract-valid (schema check)
source_exists   the controlled source file is present
path_safe       source/fixtures resolve inside the rules root (path guards)
source_hash     recomputed SHA-256 matches the manifest digest (server-side)
secret_safe     no credential-value leakage in source/fixtures
rule_type_      source root + extension + loaded rule type match the entry
matches
severity_valid  severity is a member of the closed vocabulary and equals the
               source verdict (never guessed)
metadata_full   title/description/author/date are all non-blank in source
compiles        rule parses and passes real-engine validation
positive_pass   the positive fixture matched through the real engine
negative_pass   the negative fixture stayed silent through the real engine
=============  =============================================================

A rule is ``validated`` only when *every* gate holds.  Nothing here runs a
subprocess, compiles arbitrary code paths, or accepts client-supplied
hashes/paths.  Error messages are sanitized and bounded.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from sigma.collection import SigmaCollection

from app.schemas.detection import DetectionRule, RuleType
from app.schemas.detection_as_code import (
    RuleSourceManifest,
    RuleSourceManifestEntry,
    ValidationDetail,
    ValidationOutcome,
)
from app.services.detection.rule_loader import (
    DEFAULT_RULES_DIR,
    load_sigma_rules,
    load_yara_rules,
)
from app.services.detection.sigma.engine import SigmaDetectionEngine
from app.services.detection.yara.engine import YaraDetectionEngine
from app.services.detection.yara.target_adapter import YaraTarget
from app.services.detection_as_code.hashing import sha256_file
from app.services.detection_as_code.paths import (
    UnsafePathError,
    ensure_not_executable,
    ensure_source_extension,
    resolve_safe,
)
from app.services.detection_as_code.security import scan_secret_leakage

_MAX_ERRORS = 4


class DetectionRuleValidationService:
    """Runs the full validation pipeline for one governed rule."""

    def __init__(
        self,
        rules_root: Path | None = None,
        *,
        sigma_engine: SigmaDetectionEngine | None = None,
        yara_engine: YaraDetectionEngine | None = None,
    ) -> None:
        self.rules_root = rules_root or DEFAULT_RULES_DIR
        self._sigma_engine = sigma_engine or SigmaDetectionEngine()
        self._yara_engine = yara_engine or YaraDetectionEngine()

    # -- entry point ------------------------------------------------------

    def validate(
        self,
        entry: RuleSourceManifestEntry,
        manifest: RuleSourceManifest | None = None,
    ) -> ValidationDetail:
        """Validate *entry*; outcome is VALIDATED or FAILED (never partial)."""
        gates: dict[str, bool] = {}
        errors: list[str] = []

        gates["manifest_valid"] = self._gate_manifest_valid(entry, manifest)
        if not gates["manifest_valid"]:
            errors.append("rule is not uniquely referenced by the controlled manifest")

        gates["source_exists"] = self._gate_source_exists(entry)
        if not gates["source_exists"]:
            errors.append("controlled source file is missing")

        gates["path_safe"] = self._gate_path_safe(entry)
        if not gates["path_safe"]:
            errors.append("source or fixture paths violate the containment guards")

        rule = None
        if gates["source_exists"] and gates["path_safe"]:
            try:
                rule = self._load_single_rule(entry)
            except Exception as exc:  # noqa: BLE001 - captured, not raised
                errors.append(
                    f"rule source cannot be loaded as a DetectionRule: {_sanitize(str(exc))}"
                )

        gates["source_hash_match"] = self._gate_source_hash(entry)
        if rule is not None and not gates["source_hash_match"]:
            errors.append("source hash does not match the manifest digest")

        gates["secret_safe"] = self._gate_secret_safe(entry)
        if not gates["secret_safe"]:
            errors.append("credential-shaped content found in rule source or fixtures")

        gates["rule_type_matches"] = self._gate_rule_type_matches(entry, rule)
        if not gates["rule_type_matches"]:
            errors.append("source root/extension/type does not match the manifest entry")

        gates["severity_valid"] = self._gate_severity_valid(entry, rule)
        if not gates["severity_valid"]:
            errors.append("source severity verdict does not match the manifest entry")

        gates["metadata_complete"] = self._gate_metadata_complete(rule)
        if not gates["metadata_complete"]:
            errors.append("required title/description/author/date metadata is missing")

        gates["compiles"] = False
        gates["positive_passed"] = False
        gates["negative_passed"] = False
        if (
            rule is not None
            and gates["source_hash_match"]
            and gates["rule_type_matches"]
        ):
            compiles_ok, engine_error = self._gate_compiles(entry, rule)
            gates["compiles"] = compiles_ok
            if not compiles_ok:
                errors.append(f"real-engine compile failed: {engine_error or 'unspecified'}")

        if gates["compiles"]:
            gates["positive_passed"] = self._gate_positive(entry, rule)
            gates["negative_passed"] = self._gate_negative(entry, rule)
            if not gates["positive_passed"]:
                errors.append("positive fixture did not match through the real engine")
            if not gates["negative_passed"]:
                errors.append("negative fixture matched through the real engine")

        all_pass = all(gates.values())
        outcome = (
            ValidationOutcome.VALIDATED
            if all_pass
            else ValidationOutcome.FAILED
        )
        ordered = [
            "manifest_valid",
            "source_exists",
            "source_hash_match",
            "path_safe",
            "secret_safe",
            "rule_type_matches",
            "severity_valid",
            "metadata_complete",
            "compiles",
            "positive_passed",
            "negative_passed",
        ]
        return ValidationDetail(
            rule_id=entry.rule_id,
            version=entry.version,
            outcome=outcome,
            manifest_valid=gates["manifest_valid"],
            source_exists=gates["source_exists"],
            source_hash_match=gates["source_hash_match"],
            path_safe=gates["path_safe"],
            secret_safe=gates["secret_safe"],
            rule_type_matches=gates["rule_type_matches"],
            severity_valid=gates["severity_valid"],
            metadata_complete=gates["metadata_complete"],
            compiles=gates["compiles"],
            positive_passed=gates["positive_passed"],
            negative_passed=gates["negative_passed"],
            errors=errors[:_MAX_ERRORS],
        )

    def first_error(self, detail: ValidationDetail) -> str | None:
        """Deterministic single error for persistence (first failed gate)."""
        if detail.passed:
            return None
        return detail.errors[0] if detail.errors else "validation failed"

    # -- gates ------------------------------------------------------------

    @staticmethod
    def _gate_manifest_valid(
        entry: RuleSourceManifestEntry, manifest: RuleSourceManifest | None
    ) -> bool:
        if manifest is None:
            return True
        matches = [e for e in manifest.rules if e.rule_id == entry.rule_id]
        return len(matches) == 1 and matches[0] is entry

    def _gate_source_exists(self, entry: RuleSourceManifestEntry) -> bool:
        try:
            path = resolve_safe(self.rules_root, entry.source)
            return path.is_file()
        except UnsafePathError:
            return False

    def _gate_source_hash(self, entry: RuleSourceManifestEntry) -> bool:
        try:
            path = resolve_safe(self.rules_root, entry.source)
        except UnsafePathError:
            return False
        if not path.is_file():
            return False
        return sha256_file(path) == entry.source_hash

    def _gate_path_safe(self, entry: RuleSourceManifestEntry) -> bool:
        try:
            ensure_source_extension(entry.source, entry.rule_type.value)
            source = resolve_safe(self.rules_root, entry.source)
            ensure_not_executable(source)
            positive = resolve_safe(self.rules_root, entry.positive_fixture)
            negative = resolve_safe(self.rules_root, entry.negative_fixture)
            return source.is_file() and positive.is_file() and negative.is_file()
        except (UnsafePathError, FileNotFoundError):
            return False

    def _gate_secret_safe(self, entry: RuleSourceManifestEntry) -> bool:
        try:
            texts: list[str] = []
            source = resolve_safe(self.rules_root, entry.source)
            if source.is_file():
                texts.append(source.read_text(encoding="utf-8"))
            for ref in (entry.positive_fixture, entry.negative_fixture):
                path = resolve_safe(self.rules_root, ref)
                if path.is_file():
                    try:
                        texts.append(path.read_text(encoding="utf-8"))
                    except UnicodeDecodeError:
                        continue  # binary fixture, not credential text
            return all(scan_secret_leakage(text) == [] for text in texts)
        except UnsafePathError:
            return False

    def _gate_rule_type_matches(
        self, entry: RuleSourceManifestEntry, rule: DetectionRule | None
    ) -> bool:
        if rule is None or rule.rule_type is not entry.rule_type:
            return False
        if entry.rule_type is RuleType.SIGMA and not entry.source.startswith("sigma/"):
            return False
        if entry.rule_type is RuleType.YARA and not entry.source.startswith("yara/"):
            return False
        return True

    def _gate_severity_valid(
        self, entry: RuleSourceManifestEntry, rule: DetectionRule | None
    ) -> bool:
        return rule is not None and rule.severity is entry.severity

    def _gate_metadata_complete(self, rule: DetectionRule | None) -> bool:
        if rule is None:
            return False
        extra = rule.metadata.extra or {}
        title = (rule.name or "").strip()
        description = (rule.description or "").strip()
        author = (extra.get("author") or "").strip()
        date = (extra.get("date") or "").strip()
        return bool(title and description and author and date)

    def _gate_compiles(
        self, entry: RuleSourceManifestEntry, rule: DetectionRule
    ) -> tuple[bool, str | None]:
        """Real-engine compile + validation, measured on the negative fixture."""
        try:
            if entry.rule_type is RuleType.SIGMA:
                content = rule.content
                if isinstance(content, str):
                    SigmaCollection.from_strings([content])
                else:
                    SigmaCollection.from_dicts([dict(content)])
                report = self._sigma_engine.evaluate(
                    self._negative_evt(entry), rules=[rule]
                )
            else:
                report = self._yara_engine.evaluate_target(
                    YaraTarget(
                        content=self._negative_bytes(entry),
                        file_name=f"{entry.rule_id}.fixture.bin",
                        origin_event_id=None,
                    ),
                    rules=[rule],
                )
            if report.failures:
                failure = report.failures[0]
                return False, _sanitize(failure.message)
            return True, None
        except Exception as exc:  # noqa: BLE001 - captured, not raised
            return False, _sanitize(str(exc))

    def _gate_positive(
        self, entry: RuleSourceManifestEntry, rule: DetectionRule
    ) -> bool:
        try:
            if entry.rule_type is RuleType.SIGMA:
                report = self._sigma_engine.evaluate(
                    self._positive_evt(entry), rules=[rule]
                )
            else:
                report = self._yara_engine.evaluate_target(
                    YaraTarget(
                        content=self._positive_bytes(entry),
                        file_name=f"{entry.rule_id}.fixture.bin",
                        origin_event_id=None,
                    ),
                    rules=[rule],
                )
            if report.failures:
                return False
            return any(result.rule_id == rule.rule_id for result in report.results)
        except Exception:  # noqa: BLE001 - fail closed
            return False

    def _gate_negative(
        self, entry: RuleSourceManifestEntry, rule: DetectionRule
    ) -> bool:
        try:
            if entry.rule_type is RuleType.SIGMA:
                report = self._sigma_engine.evaluate(
                    self._negative_evt(entry), rules=[rule]
                )
            else:
                report = self._yara_engine.evaluate_target(
                    YaraTarget(
                        content=self._negative_bytes(entry),
                        file_name=f"{entry.rule_id}.fixture.bin",
                        origin_event_id=None,
                    ),
                    rules=[rule],
                )
            if report.failures:
                return False
            return not any(
                result.rule_id == rule.rule_id and result.matched
                for result in report.results
            )
        except Exception:  # noqa: BLE001 - fail closed
            return False

    # -- source loading ---------------------------------------------------

    def _load_single_rule(
        self, entry: RuleSourceManifestEntry
    ) -> DetectionRule:
        if entry.rule_type is RuleType.SIGMA:
            candidates = load_sigma_rules(self.rules_root / "sigma")
        else:
            candidates = load_yara_rules(self.rules_root / "yara")
        for rule in candidates:
            if rule.rule_id == entry.rule_id:
                return rule
        raise SourceIntegrityLoadingError(
            f"rule {entry.rule_id!r} not found under the controlled rules root"
        )

    # -- fixture loading --------------------------------------------------

    def _positive_evt(self, entry: RuleSourceManifestEntry):
        from app.services.detection_as_code.fixtures import load_sigma_event

        return load_sigma_event(self.rules_root, entry.positive_fixture)

    def _negative_evt(self, entry: RuleSourceManifestEntry):
        from app.services.detection_as_code.fixtures import load_sigma_event

        return load_sigma_event(self.rules_root, entry.negative_fixture)

    def _positive_bytes(self, entry: RuleSourceManifestEntry) -> bytes:
        from app.services.detection_as_code.fixtures import load_yara_bytes

        return load_yara_bytes(self.rules_root, entry.positive_fixture)

    def _negative_bytes(self, entry: RuleSourceManifestEntry) -> bytes:
        from app.services.detection_as_code.fixtures import load_yara_bytes

        return load_yara_bytes(self.rules_root, entry.negative_fixture)


def _sanitize(message: str) -> str:
    message = (message or "").replace("\n", " ").replace("\r", " ").strip()
    if len(message) > 300:
        message = message[:300] + "..."
    return message


class SourceIntegrityLoadingError(ValueError):
    """The controlled rule source cannot be turned into a DetectionRule."""