"""Detection-as-Code contract tests (V2.17).

Pure unit tests for the domain contract in
``app/schemas/detection_as_code.py``: strict semver semantics, bump
classification, deterministic identities, manifest entry validation and
the mutation request payloads.  No database, no filesystem, no engines.
"""

import uuid

import pytest
from pydantic import ValidationError

from app.schemas.detection_as_code import (
    BumpClass,
    HASH_ALGORITHM,
    INITIAL_VERSION,
    ChangeKind,
    DeployRequest,
    DetectionSeverity,
    ReleaseRequest,
    RollbackRequest,
    RuleSourceManifest,
    RuleSourceManifestEntry,
    RuleType,
    SetEnabledRequest,
    ValidateRuleRequest,
    change_identity,
    classify_bump,
    compare_versions,
    parse_semver,
    release_identity,
    version_identity,
)


class TestParseSemver:
    def test_accepts_strict_numeric_versions(self):
        assert parse_semver("1.2.3") == (1, 2, 3)
        assert parse_semver("0.0.0") == (0, 0, 0)
        assert parse_semver("10.20.30") == (10, 20, 30)

    def test_rejects_prerelease_suffixes(self):
        for version in ("1.0.0-alpha", "1.0.0+build", "1.0.0-rc.1"):
            with pytest.raises(ValueError):
                parse_semver(version)

    def test_rejects_missing_segments(self):
        for version in ("1.0", "1", "1.0.", ".0.0", "1..0"):
            with pytest.raises(ValueError):
                parse_semver(version)

    def test_rejects_leading_zeros(self):
        with pytest.raises(ValueError):
            parse_semver("01.0.0")

    def test_rejects_non_numeric_segments(self):
        with pytest.raises(ValueError):
            parse_semver("1.a.0")


class TestCompareVersions:
    def test_orders(self):
        assert compare_versions("1.0.0", "1.0.0") == 0
        assert compare_versions("1.2.3", "1.2.2") == 1
        assert compare_versions("1.2.2", "1.2.3") == -1
        assert compare_versions("2.0.0", "1.9.9") == 1
        assert compare_versions("1.10.0", "1.9.0") == 1


class TestClassifyBump:
    def test_rejects_initial_version(self):
        with pytest.raises(ValueError):
            classify_bump(None, "1.0.0")

    def test_patch(self):
        assert classify_bump("1.0.0", "1.0.1") is BumpClass.PATCH

    def test_minor(self):
        assert classify_bump("1.0.0", "1.1.0") is BumpClass.MINOR

    def test_major(self):
        assert classify_bump("1.0.0", "2.0.0") is BumpClass.MAJOR

    def test_rejects_non_increasing(self):
        with pytest.raises(ValueError):
            classify_bump("1.1.0", "1.0.9")
        with pytest.raises(ValueError):
            classify_bump("1.0.0", "1.0.0")


class TestDeterministicIdentities:
    def test_version_identity_deterministic(self):
        first = version_identity("rule-1", "1.0.0", "a" * 64)
        second = version_identity("rule-1", "1.0.0", "a" * 64)
        assert first == second

    def test_version_identity_changes_with_content(self):
        assert version_identity("rule-1", "1.0.0", "a" * 64) != version_identity(
            "rule-1", "1.0.0", "b" * 64
        )

    def test_version_identity_changes_with_version(self):
        assert version_identity("rule-1", "1.0.0", "a" * 64) != version_identity(
            "rule-1", "1.0.1", "a" * 64
        )

    def test_release_identity_stable(self):
        assert release_identity("rule-1", "1.0.0") == release_identity(
            "rule-1", "1.0.0"
        )

    def test_change_identity_stable(self):
        assert change_identity(
            "rule-1", ChangeKind.VERSION_ADDED, "1.0.0", "1.0.1", "a" * 64
        ) == change_identity(
            "rule-1", ChangeKind.VERSION_ADDED, "1.0.0", "1.0.1", "a" * 64
        )

    def test_identities_are_uuids(self):
        identities = [
            version_identity("r", "1.0.0", "a" * 64),
            release_identity("r", "1.0.0"),
            change_identity("r", ChangeKind.VERSION_ADDED, "1.0.0", "1.0.1", "a" * 64),
        ]
        assert all(isinstance(value, uuid.UUID) for value in identities)


def _entry(**overrides) -> dict:
    base = {
        "rule_id": "sigma-001",
        "rule_type": RuleType.SIGMA.value,
        "version": INITIAL_VERSION,
        "severity": DetectionSeverity.HIGH.value,
        "source": "sigma/01-test.yml",
        "source_hash": "a" * 64,
        "hash_algorithm": HASH_ALGORITHM,
        "positive_fixture": "sigma/fixtures/sigma-001/positive.json",
        "negative_fixture": "sigma/fixtures/sigma-001/negative.json",
        "tags": ["test"],
        "status": "stable",
    }
    base.update(overrides)
    return base


class TestManifestEntry:
    def test_valid_entry(self):
        entry = RuleSourceManifestEntry(**_entry())
        assert entry.rule_id == "sigma-001"

    def test_rejects_absolute_source(self):
        with pytest.raises(ValidationError):
            RuleSourceManifestEntry(**_entry(source="/etc/passwd"))

    def test_rejects_traversal(self):
        with pytest.raises(ValidationError):
            RuleSourceManifestEntry(**_entry(source="sigma/../other.yml"))

    def test_rejects_windows_drive_source(self):
        with pytest.raises(ValidationError):
            RuleSourceManifestEntry(**_entry(source="C:sigma/x.yml"))

    def test_rejects_wrong_extension_for_type(self):
        with pytest.raises(ValidationError):
            RuleSourceManifestEntry(**_entry(source="sigma/01-test.yar"))

    def test_rejects_source_outside_sigma_root(self):
        with pytest.raises(ValidationError):
            RuleSourceManifestEntry(**_entry(source="yara/01-test.yml"))

    def test_rejects_bad_hash_shape(self):
        with pytest.raises(ValidationError):
            RuleSourceManifestEntry(**_entry(source_hash="not-a-hash"))

    def test_rejects_non_sha256_algorithm(self):
        with pytest.raises(ValidationError):
            RuleSourceManifestEntry(**_entry(hash_algorithm="md5"))

    def test_rejects_bad_semver(self):
        with pytest.raises(ValidationError):
            RuleSourceManifestEntry(**_entry(version="latest"))


class TestManifest:
    def test_duplicate_rule_ids_rejected(self):
        with pytest.raises(ValidationError):
            RuleSourceManifest(rules=[RuleSourceManifestEntry(**_entry()), RuleSourceManifestEntry(**_entry())])

    def test_duplicate_sources_rejected(self):
        with pytest.raises(ValidationError):
            RuleSourceManifest(
                rules=[
                    RuleSourceManifestEntry(**_entry(rule_id="sigma-001")),
                    RuleSourceManifestEntry(**_entry(rule_id="sigma-002")),
                ]
            )

    def test_by_rule_id_found_and_missing(self):
        manifest = RuleSourceManifest(rules=[RuleSourceManifestEntry(**_entry())])
        assert manifest.by_rule_id("sigma-001") is not None
        assert manifest.by_rule_id("nope") is None


class TestMutationPayloads:
    def test_validate_rule_allows_plain_validate(self):
        payload = ValidateRuleRequest(rule_id="sigma-001")
        assert payload.version is None

    def test_validate_rule_requires_bump_pair(self):
        with pytest.raises(ValidationError):
            ValidateRuleRequest(rule_id="x", version="1.1.0")
        with pytest.raises(ValidationError):
            ValidateRuleRequest(rule_id="x", bump_class=BumpClass.MINOR)

    def test_validate_rule_requires_reason_for_bump(self):
        with pytest.raises(ValidationError):
            ValidateRuleRequest(
                rule_id="x", version="1.1.0", bump_class=BumpClass.MINOR
            )

    def test_validate_rule_bump_with_reason_accepted(self):
        payload = ValidateRuleRequest(
            rule_id="x",
            version="1.1.0",
            bump_class=BumpClass.MINOR,
            change_reason="flattened detection",
        )
        assert payload.change_reason == "flattened detection"

    def test_release_deploy_rollback_enabled_accept_rule_and_version(self):
        for model in (ReleaseRequest, DeployRequest, RollbackRequest, SetEnabledRequest):
            payload = model(rule_id="sigma-001", version="1.0.0")
            assert payload.rule_id == "sigma-001"

    def test_enabled_defaults_true(self):
        assert SetEnabledRequest(rule_id="x", version="1.0.0").enabled is True