"""Detection-as-Code end-to-end demonstration (V2.17).

Walks the **entire governed lifecycle** against a synthetic rule in a
temporary rules root — never touching the shipped inventory:

    validate -> release -> deploy -> build_deployed_registry
        -> real YARA engine match on the deployed rule
        -> version bump (1.0.0 -> 1.1.0) -> deploy 1.1.0
        -> rollback -> 1.0.0 active again

Everything is persisted to PostgreSQL exactly like the baseline onboarding,
so the read models and the deployed registry are real, not stubs.  The
temporary rules root is created under the system temp dir and removed
afterwards.  Idempotent: re-running reuses the same rule ids.

Usage:
    python scripts/detection_as_code_e2e.py
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.database.postgres.session import SessionLocal
from app.schemas.detection import RuleType
from app.schemas.detection_as_code import (
    BumpClass,
    INITIAL_VERSION,
    ReleaseState,
    RuleSourceManifest,
)
from app.services.detection.rule_loader import DEFAULT_RULES_DIR
from app.services.detection.yara.engine import YaraDetectionEngine
from app.services.detection.yara.target_adapter import to_yara_target_from_bytes
from app.services.detection_as_code.exceptions import (
    DetectionRuleNotFoundError,
    SourceIntegrityError,
)
from app.services.detection_as_code.fixtures import (
    default_fixture_refs,
    write_yara_fixture,
)
from app.services.detection_as_code.hashing import sha256_file
from app.services.detection_as_code.lifecycle import LifecycleService
from app.services.detection_as_code.manifest import (
    build_entry,
    load_manifest,
    write_manifest,
)
from app.services.detection_as_code.validation import (
    DetectionRuleValidationService,
)
from app.models.detection_rule_change import DetectionRuleChangeRow
from app.models.detection_rule_release import DetectionRuleReleaseRow
from app.models.detection_rule_version import DetectionRuleVersionRow

_RULE_ID = "yara-e2e-beacon-v1"
_SOURCE_NAME = "e2e_beacon.yar"
_MARKER = b"SENTINEL_E2E_BEACON"

_YARA_V1 = f"""\
rule Sentry_E2E_Beacon
{{
    meta:
        id = "{_RULE_ID}"
        title = "E2E Beacon Marker"
        description = "Detects the synthetic E2E beacon marker string in artifact content."
        author = "SentinelAI Detection Team"
        date = "2026-09-23"
        severity = "critical"
        tags = "e2e synthetic"
    strings:
        $beacon = "SENTINEL_E2E_BEACON"
    condition:
        $beacon
}}
"""

_YARA_V2 = _YARA_V1.replace(
    "Detects the synthetic E2E beacon marker",
    "Detects the extended synthetic E2E beacon marker",
)

_POSITIVE_V1 = (
    b"MZ\x90\x00\x03\x00\x00\x00" + _MARKER + b"|2f54bb84-0c5e-4e5f-9a1d-3f0c0e6a0d01"
)
_POSITIVE_V2 = _POSITIVE_V1 + b"/2f54bb84-0c5e-4e5f-9a1d-3f0c0e6a0d01"
_NEGATIVE = b"benign artifact without any marker payload inside"


def _manifest_entry(root: Path, version: str) -> RuleSourceManifest:
    """Cloned shipped manifest plus the synthetic rule entry."""
    positive_ref, negative_ref = default_fixture_refs(_RULE_ID, "yara")
    source = root / "yara" / _SOURCE_NAME
    manifest = load_manifest(root)
    manifest.rules = [
        entry
        for entry in manifest.rules
        if entry.rule_id != _RULE_ID
    ]
    manifest.rules.append(
        build_entry(
            rule_id=_RULE_ID,
            rule_type=RuleType.YARA.value,
            version=version,
            severity="critical",
            source=f"yara/{_SOURCE_NAME}",
            source_hash=sha256_file(source),
            positive_fixture=positive_ref,
            negative_fixture=negative_ref,
            tags=["e2e", "synthetic"],
            status="stable",
        )
    )
    return manifest


def _write_source(root: Path, content: str) -> None:
    (root / "yara").mkdir(parents=True, exist_ok=True)
    (root / "yara" / _SOURCE_NAME).write_text(content, encoding="utf-8")


def _engine_matches(
    engine: YaraDetectionEngine, registry_rule, payload: bytes
) -> bool:
    report = engine.evaluate_target(
        to_yara_target_from_bytes(payload, file_name="e2e.bin"),
        rules=[registry_rule],
    )
    return any(
        result.rule_id == registry_rule.rule_id and result.matched
        for result in report.results
    )


def _reset_rule(db) -> None:
    """Deterministic reset of the demo rule's governed rows (idempotent)."""
    from sqlalchemy import delete

    db.execute(delete(DetectionRuleChangeRow).where(DetectionRuleChangeRow.rule_id == _RULE_ID))
    db.execute(delete(DetectionRuleReleaseRow).where(DetectionRuleReleaseRow.rule_id == _RULE_ID))
    db.execute(delete(DetectionRuleVersionRow).where(DetectionRuleVersionRow.rule_id == _RULE_ID))
    db.commit()


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="dac_e2e_"))
    db = SessionLocal()
    try:
        _reset_rule(db)
        shutil.copytree(
            DEFAULT_RULES_DIR,
            tmp,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns("*__pycache__*"),
        )
        _write_source(tmp, _YARA_V1)
        write_yara_fixture(tmp, _RULE_ID, "positive.bin", _POSITIVE_V1)
        write_yara_fixture(tmp, _RULE_ID, "negative.bin", _NEGATIVE)
        write_manifest(tmp, _manifest_entry(tmp, INITIAL_VERSION))

        validator = DetectionRuleValidationService(rules_root=tmp)
        lifecycle = LifecycleService(
            db,
            validator=validator,
            actor_role="admin",
            actor_user_id=None,
        )
        engine = YaraDetectionEngine()
        started = time.time()

        # 1. Govern the rule: validate -> release -> deploy.
        version = lifecycle.validate_rule(_RULE_ID)
        assert version.validation_status.value == "validated"
        lifecycle.release(_RULE_ID, version.version)
        released = _release(lifecycle, version.version)
        assert released.release_state is ReleaseState.RELEASED
        lifecycle.deploy(_RULE_ID, version.version)
        active = _release(lifecycle, version.version)
        assert active.deployment_state.value == "deployed"

        # 2. Rebuild the governed registry and run the real engine.
        registry = lifecycle.build_deployed_registry()
        deployed_rule = registry.get(_RULE_ID)
        assert (deployed_rule.metadata.extra or {}).get("dac_version") == "1.0.0"
        assert _engine_matches(engine, deployed_rule, _POSITIVE_V1)
        assert not _engine_matches(engine, deployed_rule, _NEGATIVE)
        print(f"[1] governed {_RULE_ID}@1.0.0 validated/released/deployed in {time.time() - started:.1f}s")
        print("[2] deployed registry rebuilt; real YARA engine matched positive, stayed silent on negative")

        # 3. Version bump: source changed -> explicit 1.1.0 with bump class + reason.
        _write_source(tmp, _YARA_V2)
        write_yara_fixture(tmp, _RULE_ID, "positive.bin", _POSITIVE_V2)
        write_manifest(tmp, _manifest_entry(tmp, "1.1.0"))
        bumped = lifecycle.validate_rule(
            _RULE_ID,
            version="1.1.0",
            bump_class=BumpClass.MINOR,
            change_reason=f"e2e: widened {_RULE_ID} marker payloads",
        )
        assert bumped.version == "1.1.0"
        lifecycle.release(_RULE_ID, "1.1.0")
        lifecycle.deploy(_RULE_ID, "1.1.0")

        registry = lifecycle.build_deployed_registry()
        updated_rule = registry.get(_RULE_ID)
        assert (updated_rule.metadata.extra or {}).get("dac_version") == "1.1.0"
        assert _engine_matches(engine, updated_rule, _POSITIVE_V2)
        print("[3] version bump 1.0.0 -> 1.1.0 validated/released/deployed with accountability record")
        print("[4] registry now serves dac_version=1.1.0; expanded payload still matched by the engine")

        # 4. Rollback to 1.0.0 (restore the governed source bytes first, matching the target content).
        _write_source(tmp, _YARA_V1)
        write_yara_fixture(tmp, _RULE_ID, "positive.bin", _POSITIVE_V1)
        write_manifest(tmp, _manifest_entry(tmp, INITIAL_VERSION))
        rolled_back = lifecycle.rollback(_RULE_ID, "1.0.0")
        assert rolled_back.version == "1.0.0"
        assert rolled_back.deployment_state.value == "deployed"

        registry = lifecycle.build_deployed_registry()
        restored_rule = registry.get(_RULE_ID)
        assert (restored_rule.metadata.extra or {}).get("dac_version") == "1.0.0"
        assert _engine_matches(engine, restored_rule, _POSITIVE_V1)
        print("[5] rollback to 1.0.0 successful; deployed registry rebuilt and engine re-verified")

        # 5. Fail-closed guards: a disabled rule stays registered but inactive;
        #    an unreleased rollback target must be rejected.
        _flip_enabled(lifecycle, "1.0.0", False)
        registry = lifecycle.build_deployed_registry()
        disabled_rule = registry.get(_RULE_ID)
        assert not disabled_rule.enabled
        assert not _engine_matches(engine, disabled_rule, _POSITIVE_V1)
        _flip_enabled(lifecycle, "1.0.0", True)
        registry = lifecycle.build_deployed_registry()
        assert _engine_matches(engine, registry.get(_RULE_ID), _POSITIVE_V1)

        try:
            lifecycle.rollback(_RULE_ID, "9.9.9")
            raise AssertionError("non-governed rollback target must be rejected")
        except DetectionRuleNotFoundError:
            print("[6] fail-closed guards hold: disabled rules inactive; non-governed version rejected")

        print(f"\nDAC E2E PASSED in {time.time() - started:.1f}s")
        return 0
    finally:
        # Restore the development database to its governed baseline (the 53
        # shipped rules) so a later build_deployed_registry() never needs the
        # removed synthetic source.
        _reset_rule(db)
        db.close()
        shutil.rmtree(tmp, ignore_errors=True)


def _release(lifecycle: LifecycleService, version: str):
    """Read the persisted release record for *rule_id*@*version*."""
    detail = lifecycle.get_rule_detail(_RULE_ID)
    for release in detail.releases:
        if release.version == version:
            return release
    raise AssertionError(f"release record missing for {_RULE_ID}@{version}")


def _flip_enabled(lifecycle: LifecycleService, version: str, enabled: bool) -> None:
    lifecycle.set_enabled(_RULE_ID, version, enabled)


if __name__ == "__main__":
    sys.exit(main())