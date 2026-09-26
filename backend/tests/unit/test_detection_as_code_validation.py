"""Detection-as-Code validation pipeline tests (V2.17).

Drives ``DetectionRuleValidationService`` against the **real** Sigma/YARA
engines on a temporary governed rules root cloned from the shipped
inventory plus one synthetic YARA rule.  Verifies every gate separately by
tampering with content, manifests, fixtures, hashes and metadata — never
touching the shipped inventory.
"""

import copy

from app.schemas.detection_as_code import RuleType, ValidationOutcome
from app.services.detection_as_code.hashing import sha256_file
from app.services.detection_as_code.validation import (
    DetectionRuleValidationService,
)

from tests.unit.dac_test_helpers import (
    make_governed_root,
    positive_v1,
    unique_rule_id,
    yara_v1,
)


def _validator_on(root, manifest):
    validator = DetectionRuleValidationService(rules_root=root)
    entry = manifest.by_rule_id(manifest.rules[-1].rule_id)
    return validator, entry


class TestValidSyntheticRule:
    def test_full_validation_passes(self, tmp_path):
        root, manifest = make_governed_root(tmp_path, unique_rule_id("yara-dac"))
        validator = DetectionRuleValidationService(rules_root=root)
        entry = manifest.by_rule_id(manifest.rules[-1].rule_id)
        detail = validator.validate(entry, manifest)
        assert detail.outcome is ValidationOutcome.VALIDATED
        assert detail.passed
        assert detail.errors == []

    def test_first_error_none_when_passed(self, tmp_path):
        root, manifest = make_governed_root(tmp_path, unique_rule_id("yara-dac"))
        validator, entry = _validator_on(root, manifest)
        detail = validator.validate(entry, manifest)
        assert validator.first_error(detail) is None


class TestGateFailures:
    def test_source_hash_tamper_fails(self, tmp_path):
        root, manifest = make_governed_root(tmp_path, unique_rule_id("yara-dac"))
        validator, entry = _validator_on(root, manifest)
        source = root / "yara" / "dac_test_beacon.yar"
        source.write_text(yara_v1(entry.rule_id).replace("strings:", "# strings:"), encoding="utf-8")
        detail = validator.validate(entry, manifest)
        assert detail.source_hash_match is False
        assert detail.compiles is False
        assert detail.outcome is ValidationOutcome.FAILED

    def test_hash_requirement_from_manifest_recomputed(self, tmp_path):
        root, manifest = make_governed_root(tmp_path, unique_rule_id("yara-dac"))
        validator, entry = _validator_on(root, manifest)
        assert entry.source_hash == sha256_file(root / entry.source)
        detail = validator.validate(entry, manifest)
        assert detail.source_hash_match is True
        assert detail.outcome is ValidationOutcome.VALIDATED

    def test_secret_leak_fails(self, tmp_path):
        root, manifest = make_governed_root(tmp_path, unique_rule_id("yara-dac"))
        validator, entry = _validator_on(root, manifest)
        source = root / "yara" / "dac_test_beacon.yar"
        source.write_text(
            yara_v1(entry.rule_id) + '    $leak = "AKIAIOSFODNN7EXAMPLE"\n',
            encoding="utf-8",
        )
        detail = validator.validate(entry, manifest)
        assert detail.secret_safe is False
        assert detail.outcome is ValidationOutcome.FAILED

    def test_negative_fixture_match_fails(self, tmp_path):
        root, manifest = make_governed_root(
            tmp_path, unique_rule_id("yara-dac"), negative=positive_v1()
        )
        validator, entry = _validator_on(root, manifest)
        detail = validator.validate(entry, manifest)
        assert detail.negative_passed is False
        assert detail.outcome is ValidationOutcome.FAILED

    def test_positive_fixture_miss_fails(self, tmp_path):
        root, manifest = make_governed_root(
            tmp_path, unique_rule_id("yara-dac"), positive=b"benign text, no marker"
        )
        validator, entry = _validator_on(root, manifest)
        detail = validator.validate(entry, manifest)
        assert detail.positive_passed is False
        assert detail.outcome is ValidationOutcome.FAILED

    def test_missing_positive_fixture_fails(self, tmp_path):
        root, manifest = make_governed_root(tmp_path, unique_rule_id("yara-dac"))
        (root / "yara" / "fixtures" / manifest.rules[-1].rule_id / "positive.bin").unlink()
        validator, entry = _validator_on(root, manifest)
        detail = validator.validate(entry, manifest)
        assert detail.path_safe is False
        assert detail.outcome is ValidationOutcome.FAILED

    def test_no_manifest_reference_outcome(self, tmp_path):
        root, manifest = make_governed_root(tmp_path, unique_rule_id("yara-dac"))
        validator, entry = _validator_on(root, manifest)
        # A manifest that no longer references the entry -> gate must fail,
        # and the whole validation must be FAILED (never validated).
        stripped = manifest.model_copy(deep=True)
        stripped.rules = [e for e in stripped.rules if e.rule_id != entry.rule_id]
        detail = validator.validate(entry, stripped)
        assert detail.manifest_valid is False
        assert detail.outcome is ValidationOutcome.FAILED


class TestSigmaShippedRuleValidates:
    def test_shipped_sigma_rule_passes(self, tmp_path):
        root, manifest = make_governed_root(tmp_path, unique_rule_id("yara-dac"))
        # Reuse an actual shipped sigma rule entry from the cloned manifest.
        entry = next(e for e in manifest.rules if e.rule_type is RuleType.SIGMA)
        validator = DetectionRuleValidationService(rules_root=root)
        detail = validator.validate(entry, manifest)
        assert detail.outcome is ValidationOutcome.VALIDATED
        assert detail.compiles is True
        assert detail.positive_passed is True
        assert detail.negative_passed is True
        assert detail.source_hash_match is True