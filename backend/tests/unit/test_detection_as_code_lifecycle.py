"""Detection-as-Code lifecycle tests (V2.17).

Drives ``LifecycleService`` against the real development PostgreSQL database,
using a synthetic rule governed inside a temporary rules root.  Every test
uses a unique rule id and cleans its rows up afterwards, so the suite is
idempotent and never touches the shipped 53-rule inventory.
"""

from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.detection_rule_change import DetectionRuleChangeRow
from app.models.detection_rule_release import DetectionRuleReleaseRow
from app.models.detection_rule_version import DetectionRuleVersionRow
from app.schemas.detection_as_code import (
    BumpClass,
    DeploymentState,
    INITIAL_VERSION,
    ReleaseState,
    ValidationOutcome,
)
from app.services.detection.yara.engine import YaraDetectionEngine
from app.services.detection.yara.target_adapter import to_yara_target_from_bytes
from app.services.detection_as_code.exceptions import (
    DetectionRuleNotFoundError,
    VersionConflictError,
)
from app.services.detection_as_code.fixtures import default_fixture_refs
from app.services.detection_as_code.hashing import sha256_file
from app.services.detection_as_code.lifecycle import LifecycleService
from app.services.detection_as_code.manifest import build_entry, write_manifest
from app.services.detection_as_code.validation import (
    DetectionRuleValidationService,
)

from tests.unit.dac_test_helpers import (
    cleanup_rule,
    make_governed_root,
    positive_v1,
    unique_rule_id,
    yara_v1,
)


def _lifecycle(db, root, *, actor_user_id=None, actor_role="admin"):
    return LifecycleService(
        db,
        validator=DetectionRuleValidationService(rules_root=root),
        actor_user_id=actor_user_id,
        actor_role=actor_role,
    )


def _bump_rule(root: Path, rule_id: str, manifest, content: str, version: str) -> None:
    """Rewrite the synthetic rule's source + manifest for a new version."""
    source = root / "yara" / "dac_test_beacon.yar"
    source.write_text(content, encoding="utf-8")
    positive_ref, negative_ref = default_fixture_refs(rule_id, "yara")
    manifest.rules = [e for e in manifest.rules if e.rule_id != rule_id]
    manifest.rules.append(
        build_entry(
            rule_id=rule_id,
            rule_type="yara",
            version=version,
            severity="critical",
            source="yara/dac_test_beacon.yar",
            source_hash=sha256_file(source),
            positive_fixture=positive_ref,
            negative_fixture=negative_ref,
            tags=["dac", "synthetic", "test"],
            status="stable",
        )
    )
    write_manifest(root, manifest)


def _row_count(db: Session, model, rule_id: str) -> int:
    return db.execute(
        select(func.count()).select_from(model).where(model.rule_id == rule_id)
    ).scalar()


class TestFullLifecycle:
    def test_validate_release_deploy_roundtrip(self, db_session, tmp_path):
        rule_id = unique_rule_id("yara-dac")
        root, manifest = make_governed_root(tmp_path, rule_id)
        try:
            service = _lifecycle(db_session, root)
            version = service.validate_rule(rule_id)
            assert version.version == INITIAL_VERSION
            assert version.validation_status is ValidationOutcome.VALIDATED

            released = service.release(rule_id, version.version)
            assert released.release_state is ReleaseState.RELEASED

            deployed = service.deploy(rule_id, version.version)
            assert deployed.deployment_state is DeploymentState.DEPLOYED
        finally:
            cleanup_rule(db_session, rule_id)

    def test_rows_persisted(self, db_session, tmp_path):
        rule_id = unique_rule_id("yara-dac")
        root, manifest = make_governed_root(tmp_path, rule_id)
        try:
            service = _lifecycle(db_session, root)
            version = service.validate_rule(rule_id)
            service.release(rule_id, version.version)
            service.deploy(rule_id, version.version)

            assert _row_count(db_session, DetectionRuleVersionRow, rule_id) == 1
            assert _row_count(db_session, DetectionRuleReleaseRow, rule_id) == 1
            assert _row_count(db_session, DetectionRuleChangeRow, rule_id) >= 1
        finally:
            cleanup_rule(db_session, rule_id)

    def test_idempotent_revalidate_same_content(self, db_session, tmp_path):
        rule_id = unique_rule_id("yara-dac")
        root, manifest = make_governed_root(tmp_path, rule_id)
        try:
            service = _lifecycle(db_session, root)
            first = service.validate_rule(rule_id)
            again = service.validate_rule(rule_id)
            assert again.version == first.version
            assert _row_count(db_session, DetectionRuleVersionRow, rule_id) == 1
        finally:
            cleanup_rule(db_session, rule_id)

    def test_content_change_requires_version_bump(self, db_session, tmp_path):
        rule_id = unique_rule_id("yara-dac")
        root, manifest = make_governed_root(tmp_path, rule_id)
        try:
            service = _lifecycle(db_session, root)
            service.validate_rule(rule_id)

            _bump_rule(root, rule_id, manifest, yara_v1(rule_id).replace("strings:", "strings: "), "1.1.0")
            service = _lifecycle(db_session, root)
            with pytest.raises(VersionConflictError):
                service.validate_rule(rule_id)

            bumped = service.validate_rule(
                rule_id,
                version="1.1.0",
                bump_class=BumpClass.MINOR,
                change_reason="test: detection comment changed",
            )
            assert bumped.version == "1.1.0"
        finally:
            cleanup_rule(db_session, rule_id)

    def test_redeploy_active_version_idempotent(self, db_session, tmp_path):
        rule_id = unique_rule_id("yara-dac")
        root, manifest = make_governed_root(tmp_path, rule_id)
        try:
            service = _lifecycle(db_session, root)
            version = service.validate_rule(rule_id)
            service.release(rule_id, version.version)
            service.deploy(rule_id, version.version)
            for _ in range(2):
                active = service.deploy(rule_id, version.version)
                assert active.deployment_state is DeploymentState.DEPLOYED
        finally:
            cleanup_rule(db_session, rule_id)

    def test_deploy_unreleased_rejected(self, db_session, tmp_path):
        rule_id = unique_rule_id("yara-dac")
        root, manifest = make_governed_root(tmp_path, rule_id)
        try:
            service = _lifecycle(db_session, root)
            version = service.validate_rule(rule_id)
            with pytest.raises(Exception):
                service.deploy(rule_id, version.version)
        finally:
            cleanup_rule(db_session, rule_id)

    def test_unknown_rule_rejected(self, db_session, tmp_path):
        rule_id = unique_rule_id("yara-dac")
        root, manifest = make_governed_root(tmp_path, rule_id)
        try:
            service = _lifecycle(db_session, root)
            with pytest.raises(DetectionRuleNotFoundError):
                service.validate_rule("does-not-exist")
            with pytest.raises(Exception):
                service.rollback(rule_id, "9.9.9")
        finally:
            cleanup_rule(db_session, rule_id)


class TestRollback:
    def test_rollback_restores_prior_version(self, db_session, tmp_path):
        rule_id = unique_rule_id("yara-dac")
        root, manifest = make_governed_root(tmp_path, rule_id)
        try:
            service = _lifecycle(db_session, root)
            v1 = service.validate_rule(rule_id)
            service.release(rule_id, v1.version)
            service.deploy(rule_id, v1.version)

            _bump_rule(root, rule_id, manifest, yara_v1(rule_id).replace("strings:", "strings: "), "1.1.0")
            v2 = service.validate_rule(
                rule_id,
                version="1.1.0",
                bump_class=BumpClass.MINOR,
                change_reason="test: rollback setup",
            )
            service.release(rule_id, v2.version)
            service.deploy(rule_id, v2.version)

            # Restore the v1 governed source bytes so the fail-closed source
            # verification matches the rollback target content.
            _bump_rule(root, rule_id, manifest, yara_v1(rule_id), v1.version)
            rolled = service.rollback(rule_id, v1.version)
            assert rolled.version == v1.version
            assert rolled.deployment_state is DeploymentState.DEPLOYED
        finally:
            cleanup_rule(db_session, rule_id)

    def test_rollback_unknown_version_rejected(self, db_session, tmp_path):
        rule_id = unique_rule_id("yara-dac")
        root, manifest = make_governed_root(tmp_path, rule_id)
        try:
            service = _lifecycle(db_session, root)
            with pytest.raises(Exception):
                service.rollback(rule_id, "9.9.9")
        finally:
            cleanup_rule(db_session, rule_id)

    def test_set_enabled_toggles(self, db_session, tmp_path):
        rule_id = unique_rule_id("yara-dac")
        root, manifest = make_governed_root(tmp_path, rule_id)
        try:
            service = _lifecycle(db_session, root)
            version = service.validate_rule(rule_id)
            service.release(rule_id, version.version)
            service.deploy(rule_id, version.version)

            off = service.set_enabled(rule_id, version.version, False)
            assert off.enabled is False
            on = service.set_enabled(rule_id, version.version, True)
            assert on.enabled is True
        finally:
            cleanup_rule(db_session, rule_id)


class TestReadModelsAndRegistry:
    def test_get_rule_detail(self, db_session, tmp_path):
        rule_id = unique_rule_id("yara-dac")
        root, manifest = make_governed_root(tmp_path, rule_id)
        try:
            service = _lifecycle(db_session, root)
            version = service.validate_rule(rule_id)
            service.release(rule_id, version.version)
            service.deploy(rule_id, version.version)

            detail = service.get_rule_detail(rule_id)
            assert detail.current.rule_id == rule_id
            assert any(r.version == version.version for r in detail.releases)
        finally:
            cleanup_rule(db_session, rule_id)

    def test_list_rules_includes_synthetic(self, db_session, tmp_path):
        rule_id = unique_rule_id("yara-dac")
        root, manifest = make_governed_root(tmp_path, rule_id)
        try:
            service = _lifecycle(db_session, root)
            version = service.validate_rule(rule_id)
            service.release(rule_id, version.version)
            service.deploy(rule_id, version.version)

            page = service.list_rules(page=1, page_size=200)
            assert page.total >= 54  # 53 shipped inventory + the governed synthetic
            assert any(item.rule_id == rule_id for item in page.items)
        finally:
            cleanup_rule(db_session, rule_id)

    def test_deployed_registry_serves_rule(self, db_session, tmp_path):
        rule_id = unique_rule_id("yara-dac")
        root, manifest = make_governed_root(tmp_path, rule_id)
        try:
            service = _lifecycle(db_session, root)
            version = service.validate_rule(rule_id)
            service.release(rule_id, version.version)
            service.deploy(rule_id, version.version)

            registry = service.build_deployed_registry()
            deployed = registry.get(rule_id)
            assert deployed is not None
            assert (deployed.metadata.extra or {}).get("dac_version") == version.version

            engine = YaraDetectionEngine()
            report = engine.evaluate_target(
                to_yara_target_from_bytes(positive_v1(), file_name="dac.bin"),
                rules=[deployed],
            )
            assert any(r.rule_id == rule_id and r.matched for r in report.results)

            service.set_enabled(rule_id, version.version, False)
            registry = service.build_deployed_registry()
            disabled = registry.get(rule_id)
            assert disabled.enabled is False
        finally:
            cleanup_rule(db_session, rule_id)