"""Detection-as-Code lifecycle service (V2.17).

Governs the pipeline ``source -> manifest -> validate -> release -> deploy``
and the rollback/enable/disable transitions, with strict state transitions,
deterministic identities and full server-side verification.  The service
**never** trusts client hashes, paths or versions:

* source hashes are always recomputed from the controlled repository;
* versions are strict ``MAJOR.MINOR.PATCH`` and are only accepted with an
  explicit, author-supplied bump classification that must match the real
  transition — none is ever guessed;
* a rule is *validated* only through the real engines (never declared by
  the client); *release* and *deploy* require the prior state, enforced
  here and pinned by database CHECKs;
* rollback promotes an existing validated + released version and records
  the deterministic change in the ledger.

State machine
-------------
validation:    none -> validating -> validated | failed
release:       draft -> validating -> validated -> released | failed
deployment:    undeployed -> deployed (deployed implies released; CHECK)
change kinds:  initialized (first version) / version_added (content change)
               / rolled_back (rollback transition)

Audit actions (all logged through ``app.services.audit_service.log_action``,
never echoing rule content or credentials):

    detection_as_code.validation.started|completed|failed
    detection_as_code.released / deployed / enabled / disabled / rolled_back
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.detection_rule_change import DetectionRuleChangeRow
from app.models.detection_rule_release import DetectionRuleReleaseRow
from app.models.detection_rule_version import DetectionRuleVersionRow
from app.schemas.detection import (
    DetectionMetadata,
    DetectionRule,
    RuleType,
)
from app.schemas.detection_as_code import (
    BumpClass,
    ChangeKind,
    DeploymentState,
    DetectionAsCodeRuleDetail,
    DetectionAsCodeRulePage,
    DetectionRuleChangeRecord,
    DetectionRuleReleaseRecord,
    DetectionRuleVersionRecord,
    ReleaseState,
    ValidationOutcome,
    change_identity,
    classify_bump,
    parse_semver,
    release_identity,
    version_identity,
)
from app.services.audit_service import log_action
from app.services.detection.registry import DetectionRuleRegistry
from app.services.detection.rule_loader import (
    DEFAULT_RULES_DIR,
    load_sigma_rules,
    load_yara_rules,
)
from app.services.detection_as_code.exceptions import (
    DeploymentConflictError,
    DetectionRuleNotFoundError,
    ManifestValidationError,
    ReleaseConflictError,
    SourceIntegrityError,
    ValidationConflictError,
    VersionConflictError,
)
from app.services.detection_as_code.hashing import sha256_file
from app.services.detection_as_code.manifest import (
    MANIFEST_FILENAME,
    load_manifest,
)
from app.services.detection_as_code import repository as repo
from app.services.detection_as_code.validation import (
    DetectionRuleValidationService,
)

#: The three trusted roles of the DAC surface.
ADMIN_ROLE = "admin"
ANALYST_ROLE = "analyst"
CISO_ROLE = "ciso"

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class LifecycleService:
    """Composes validation + persistence into the governed lifecycle."""

    def __init__(
        self,
        db: Session,
        *,
        validator: DetectionRuleValidationService | None = None,
        actor_user_id: uuid.UUID | None = None,
        actor_role: str | None = None,
    ) -> None:
        self.db = db
        self.validator = validator or DetectionRuleValidationService()
        self.rules_root = self.validator.rules_root
        self.actor_user_id = actor_user_id
        self.actor_role = actor_role

    # ------------------------------------------------------------------
    # Validation (Step: validate)
    # ------------------------------------------------------------------

    def validate_rule(
        self,
        rule_id: str,
        *,
        version: str | None = None,
        bump_class: BumpClass | None = None,
        change_reason: str | None = None,
    ) -> DetectionRuleVersionRecord:
        """Validate a governed rule server-side; returns the version record."""
        manifest = load_manifest(self.rules_root)
        entry = manifest.by_rule_id(rule_id)
        if entry is None:
            raise DetectionRuleNotFoundError(
                f"no governed rule with id {rule_id!r}"
            )

        source_hash = self._server_side_source_hash(entry.source)

        latest = repo.latest_version(self.db, rule_id)

        if latest is not None and latest.source_hash == source_hash:
            if latest.validation_status == ValidationOutcome.VALIDATED.value:
                # Idempotent revalidate: identical content, identical version.
                self._audit(
                    "detection_as_code.validation.started",
                    rule_id,
                    f"rule_id={rule_id} version={latest.version}",
                )
                self._audit(
                    "detection_as_code.validation.completed",
                    rule_id,
                    f"rule_id={rule_id} version={latest.version} idempotent",
                )
                return self._version_record(latest)
            # Same content, previously failed/never validated -> revalidate
            # the same version with no bump.
            return self._run_validation(
                entry, manifest, source_hash, version=latest.version
            )

        if latest is not None:
            # Content changed -> a new explicit version is mandatory.
            if version is None or bump_class is None:
                raise VersionConflictError(
                    "source changed since the governed version; supply version "
                    "and bump_class for the new version"
                )
            if not (change_reason or "").strip():
                raise VersionConflictError(
                    "a version bump requires an accountability change_reason"
                )
            parse_semver(version)
            expected = classify_bump(latest.version, version)
            if expected is not bump_class:
                raise VersionConflictError(
                    f"declared bump_class {bump_class.value} does not match the "
                    f"actual transition ({expected.value}) from {latest.version}"
                )
            return self._run_validation(
                entry, manifest, source_hash, version=version,
                bump_class=bump_class, change_reason=change_reason,
                from_version=latest.version,
            )

        # First governance of this rule -> explicit initial version.
        target_version = version or entry.version
        parse_semver(target_version)
        return self._run_validation(
            entry, manifest, source_hash, version=target_version
        )

    def _run_validation(
        self,
        entry,  # RuleSourceManifestEntry
        manifest,
        source_hash: str,
        *,
        version: str,
        bump_class: BumpClass | None = None,
        change_reason: str | None = None,
        from_version: str | None = None,
    ) -> DetectionRuleVersionRecord:
        self._audit(
            "detection_as_code.validation.started",
            entry.rule_id,
            f"rule_id={entry.rule_id} version={version}",
        )

        detail = self.validator.validate(entry, manifest)

        existing = repo.get_version(self.db, entry.rule_id, version)
        if (
            existing is not None
            and existing.source_hash != source_hash
        ):
            # The same version string for different content is a conflict.
            raise VersionConflictError(
                f"version {version} already exists with different content for "
                f"rule {entry.rule_id}"
            )
        if existing is not None and existing.validation_status in (
            ValidationOutcome.VALIDATED.value,
            ValidationOutcome.VALIDATING.value,
        ):
            # Same content + same version revalidation.
            existing.validation_status = ValidationOutcome.VALIDATED.value
            existing.validation_error = None
            existing.compiled = detail.compiles
            existing.positive_passed = detail.positive_passed
            existing.negative_passed = detail.negative_passed
            existing.updated_at = _now()
            version_row = existing
        else:
            rule = self._load_rule(entry)
            version_row = DetectionRuleVersionRow(
                version_id=version_identity(
                    entry.rule_id, version, source_hash
                ),
                rule_id=entry.rule_id,
                version=version,
                rule_type=entry.rule_type.value,
                severity=entry.severity.value,
                title=(rule.name or "")[:200],
                description=(rule.description or "")[:1000],
                author=(rule.metadata.extra or {}).get("author"),
                status=(rule.metadata.extra or {}).get("status"),
                category=(rule.metadata.extra or {}).get("category"),
                source_path=entry.source,
                hash_algorithm=entry.hash_algorithm,
                source_hash=source_hash,
                tags=list(entry.tags),
                enabled=True,
                validation_status=(
                    ValidationOutcome.VALIDATED.value
                    if detail.passed
                    else ValidationOutcome.FAILED.value
                ),
                validation_error=self.validator.first_error(detail),
                compiled=detail.compiles,
                positive_passed=detail.positive_passed,
                negative_passed=detail.negative_passed,
                created_by=self.actor_user_id,
                created_by_role=self.actor_role,
            )
            self.db.add(version_row)
            self.db.flush()
            self._write_change_row(
                rule_id=entry.rule_id,
                kind=(
                    ChangeKind.INITIALIZED
                    if from_version is None
                    else ChangeKind.VERSION_ADDED
                ),
                from_version=from_version,
                to_version=version,
                to_source_hash=source_hash,
                bump_class=bump_class,
                change_reason=change_reason,
            )
            version_row = (
                self.db.scalar(
                    select(DetectionRuleVersionRow)
                    .where(DetectionRuleVersionRow.rule_id == entry.rule_id)
                    .where(DetectionRuleVersionRow.version == version)
                )
                or version_row
            )

        self._touch_release(entry, version, detail.passed)

        if detail.passed:
            self._audit(
                "detection_as_code.validation.completed",
                entry.rule_id,
                f"rule_id={entry.rule_id} version={version} outcome=validated",
            )
        else:
            self._audit(
                "detection_as_code.validation.failed",
                entry.rule_id,
                f"rule_id={entry.rule_id} version={version} outcome=failed",
            )
        self.db.commit()
        self.db.refresh(version_row)
        return self._version_record(version_row)

    # ------------------------------------------------------------------
    # Release
    # ------------------------------------------------------------------

    def release(
        self, rule_id: str, version: str
    ) -> DetectionRuleReleaseRecord:
        parse_semver(version)
        row = repo.get_version(self.db, rule_id, version)
        if row is None:
            raise DetectionRuleNotFoundError(
                f"no governed version {version} for rule {rule_id}"
            )
        self._verify_source(row)

        release = repo.get_release(self.db, rule_id, version)
        if release is None:
            release = DetectionRuleReleaseRow(
                release_id=release_identity(rule_id, version),
                version_id=row.id,
                rule_id=rule_id,
                version=version,
                release_state=ReleaseState.DRAFT.value,
                deployment_state=DeploymentState.UNDEPLOYED.value,
            )
            self.db.add(release)
            self.db.flush()
        elif release.version_id is None:
            release.version_id = row.id

        if row.validation_status != ValidationOutcome.VALIDATED.value:
            release.release_state = ReleaseState.FAILED.value
            self.db.commit()
            raise ValidationConflictError(
                f"version {version} is not validated; cannot release"
            )

        if release.release_state == ReleaseState.RELEASED.value:
            # Idempotent re-release of the same immutable version.
            self.db.commit()
            return self._release_record(release)

        if release.release_state not in (
            ReleaseState.DRAFT.value,
            ReleaseState.VALIDATED.value,
            ReleaseState.FAILED.value,
        ):
            self.db.commit()
            raise ReleaseConflictError(
                f"version {version} cannot be released from "
                f"{release.release_state}"
            )

        release.release_state = ReleaseState.RELEASED.value
        release.released_at = _now()
        release.released_by = self.actor_user_id
        self._audit(
            "detection_as_code.released",
            rule_id,
            f"rule_id={rule_id} version={version}",
        )
        self.db.commit()
        self.db.refresh(release)
        return self._release_record(release)

    # ------------------------------------------------------------------
    # Deploy
    # ------------------------------------------------------------------

    def deploy(self, rule_id: str, version: str) -> DetectionRuleReleaseRecord:
        parse_semver(version)
        row = repo.get_version(self.db, rule_id, version)
        if row is None:
            raise DetectionRuleNotFoundError(
                f"no governed version {version} for rule {rule_id}"
            )
        self._verify_source(row)

        release = repo.get_release(self.db, rule_id, version)
        if release is None or release.release_state != ReleaseState.RELEASED.value:
            raise DeploymentConflictError(
                f"version {version} of rule {rule_id} is not released; "
                "release it before deploying"
            )

        previous = repo.deployed_release(self.db, rule_id)
        if previous is not None and previous.version == version:
            # Idempotent deploy of the already-active immutable version.
            self.db.commit()
            return self._release_record(release)

        if previous is not None and previous.release_state != ReleaseState.RELEASED.value:
            raise DeploymentConflictError(
                "currently deployed version is not released; cannot demote it"
            )

        # Demote the previously active version.
        if previous is not None:
            previous.deployment_state = DeploymentState.UNDEPLOYED.value
            previous.updated_at = _now()

        release.deployment_state = DeploymentState.DEPLOYED.value
        release.deployed_at = _now()
        release.deployed_by = self.actor_user_id
        release.rollback_target_version = (
            previous.version if previous is not None and previous.version != version else None
        )
        self._audit(
            "detection_as_code.deployed",
            rule_id,
            f"rule_id={rule_id} version={version}"
            + (f" demoted={previous.version}" if previous is not None else ""),
        )
        self.db.commit()
        self.db.refresh(release)
        return self._release_record(release)

    # ------------------------------------------------------------------
    # Rollback
    # ------------------------------------------------------------------

    def rollback(self, rule_id: str, version: str) -> DetectionRuleReleaseRecord:
        parse_semver(version)
        target = repo.get_version(self.db, rule_id, version)
        if target is None:
            raise DetectionRuleNotFoundError(
                f"no governed version {version} for rule {rule_id}"
            )
        self._verify_source(target)

        current = repo.deployed_release(self.db, rule_id)
        if current is None:
            raise DeploymentConflictError(
                f"rule {rule_id} has no deployed version to roll back"
            )
        if current.version == version:
            # Idempotent rollback to the already-active target.
            self.db.commit()
            return self._release_record(current)

        target_release = repo.get_release(self.db, rule_id, version)
        if target_release is None or target_release.release_state != ReleaseState.RELEASED.value:
            raise ReleaseConflictError(
                f"rollback target {version} is not a released version"
            )
        if target.validation_status != ValidationOutcome.VALIDATED.value:
            raise ValidationConflictError(
                f"rollback target {version} is not validated"
            )

        current.deployment_state = DeploymentState.UNDEPLOYED.value
        current.updated_at = _now()

        target_release.deployment_state = DeploymentState.DEPLOYED.value
        target_release.deployed_at = _now()
        target_release.deployed_by = self.actor_user_id
        target_release.rollback_target_version = None

        target.rollback_from = current.version_id
        self._write_change_row(
            rule_id=rule_id,
            kind=ChangeKind.ROLLED_BACK,
            from_version=current.version,
            to_version=version,
            to_source_hash=target.source_hash,
            bump_class=None,
            change_reason=None,
        )
        self._audit(
            "detection_as_code.rolled_back",
            rule_id,
            f"rule_id={rule_id} from={current.version} to={version}",
        )
        self.db.commit()
        self.db.refresh(target_release)
        return self._release_record(target_release)

    # ------------------------------------------------------------------
    # Enable / disable
    # ------------------------------------------------------------------

    def set_enabled(
        self, rule_id: str, version: str, enabled: bool
    ) -> DetectionRuleVersionRecord:
        parse_semver(version)
        row = repo.get_version(self.db, rule_id, version)
        if row is None:
            raise DetectionRuleNotFoundError(
                f"no governed version {version} for rule {rule_id}"
            )
        self._verify_source(row)
        row.enabled = enabled
        row.updated_at = _now()
        self._audit(
            "detection_as_code.enabled"
            if enabled
            else "detection_as_code.disabled",
            rule_id,
            f"rule_id={rule_id} version={version}",
        )
        self.db.commit()
        self.db.refresh(row)
        return self._version_record(row)

    # ------------------------------------------------------------------
    # Reads (deterministic; validation detail is always re-derived)
    # ------------------------------------------------------------------

    def list_rules(self, page: int, page_size: int) -> DetectionAsCodeRulePage:
        rows = repo.list_all_rules_latest(self.db)
        start = (page - 1) * page_size
        records = [
            self._version_record(row) for row in rows[start : start + page_size]
        ]
        return DetectionAsCodeRulePage(
            items=records,
            total=len(rows),
            page=page,
            page_size=page_size,
        )

    def get_rule_detail(self, rule_id: str) -> DetectionAsCodeRuleDetail:
        row = repo.latest_version(self.db, rule_id)
        if row is None:
            manifest = load_manifest(self.rules_root)
            if manifest.by_rule_id(rule_id) is None:
                raise DetectionRuleNotFoundError(
                    f"no governed rule with id {rule_id!r}"
                )
            raise DetectionRuleNotFoundError(
                f"rule {rule_id} has no governed version yet; validate it first"
            )
        record = self._version_record(row)
        manifest = load_manifest(self.rules_root)
        entry = manifest.by_rule_id(rule_id)
        validation = (
            self.validator.validate(entry, manifest)
            if entry is not None
            else self.validator_failed_record(record)
        )
        releases = [
            self._release_record(r) for r in repo.list_releases(self.db, rule_id)
        ]
        changes = [
            self._change_record(c) for c in repo.list_changes(self.db, rule_id)
        ]
        return DetectionAsCodeRuleDetail(
            current=record,
            validation=validation,
            releases=releases,
            changes=changes,
        )

    # ------------------------------------------------------------------
    # Deployed registry (the governed evaluation set for the agent)
    # ------------------------------------------------------------------

    def build_deployed_registry(self) -> DetectionRuleRegistry:
        """Reconstruct the governed :class:`DetectionRuleRegistry`.

        Only *deployed + released + validated* versions participate.  Fail
        closed: any broken deployed entry (missing source, hash mismatch,
        invalid state) is a hard error, never a silently skipped rule.
        """
        registry = DetectionRuleRegistry()
        deployed = repo.all_deployed_releases(self.db)
        for release in sorted(deployed, key=lambda r: r.rule_id):
            row = repo.get_version(self.db, release.rule_id, release.version)
            if row is None:
                raise SourceIntegrityError(
                    f"deployed version {release.version} of {release.rule_id} "
                    "has no governed version row"
                )
            if row.validation_status != ValidationOutcome.VALIDATED.value:
                raise SourceIntegrityError(
                    f"deployed version {release.version} of {release.rule_id} "
                    "is not validated"
                )
            self._verify_source(row)
            rule = self._build_deployed_rule(row)
            registry.register(rule)
        return registry

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _server_side_source_hash(self, source_path: str) -> str:
        path = self.rules_root / source_path
        if not path.is_file():
            raise SourceIntegrityError(
                f"controlled source file missing: {source_path}"
            )
        return sha256_file(path)

    def _verify_source(self, row: DetectionRuleVersionRow) -> None:
        """Fail closed if the source no longer matches the governed version."""
        current_hash = self._server_side_source_hash(row.source_path)
        if current_hash != row.source_hash:
            raise SourceIntegrityError(
                f"source for rule {row.rule_id} version {row.version} does not "
                "match its governed hash; re-validate before any lifecycle action"
            )

    def _load_rule(self, entry) -> DetectionRule:
        if entry.rule_type is RuleType.SIGMA:
            for rule in load_sigma_rules(self.rules_root / "sigma"):
                if rule.rule_id == entry.rule_id:
                    return rule
        else:
            for rule in load_yara_rules(self.rules_root / "yara"):
                if rule.rule_id == entry.rule_id:
                    return rule
        raise SourceIntegrityError(
            f"rule {entry.rule_id!r} not found in the controlled rules root"
        )

    def _build_deployed_rule(self, row: DetectionRuleVersionRow) -> DetectionRule:
        entry_type, root_dir = self._type_dir(row.rule_type)
        for rule in load_sigma_rules(root_dir) if entry_type is RuleType.SIGMA else load_yara_rules(root_dir):
            if rule.rule_id == row.rule_id:
                extra = dict(rule.metadata.extra or {})
                extra["dac_version"] = row.version
                extra["dac_version_id"] = str(row.version_id)
                return rule.model_copy(
                    update={
                        "version": row.version,
                        "enabled": row.enabled,
                        "metadata": DetectionMetadata(extra=extra),
                    }
                )
        raise SourceIntegrityError(
            f"deployed rule {row.rule_id!r} missing from the controlled rules root"
        )

    def _type_dir(self, rule_type: str):
        if rule_type == RuleType.SIGMA.value:
            return RuleType.SIGMA, self.rules_root / "sigma"
        return RuleType.YARA, self.rules_root / "yara"

    def _touch_release(self, entry, version: str, validated: bool) -> None:
        version_row = repo.get_version(self.db, entry.rule_id, version)
        release = repo.get_release(self.db, entry.rule_id, version)
        if release is None:
            release = DetectionRuleReleaseRow(
                release_id=release_identity(entry.rule_id, version),
                version_id=version_row.id if version_row else None,
                rule_id=entry.rule_id,
                version=version,
                release_state=(
                    ReleaseState.VALIDATED.value
                    if validated
                    else ReleaseState.FAILED.value
                ),
                deployment_state=DeploymentState.UNDEPLOYED.value,
                validated_at=_now() if validated else None,
            )
            self.db.add(release)
        else:
            if release.version_id is None and version_row is not None:
                release.version_id = version_row.id
            release.release_state = (
                ReleaseState.VALIDATED.value
                if validated
                else ReleaseState.FAILED.value
            )
            release.validated_at = _now() if validated else None
            release.updated_at = _now()

    def _write_change_row(
        self,
        *,
        rule_id: str,
        kind: ChangeKind,
        from_version: str | None,
        to_version: str,
        to_source_hash: str,
        bump_class: BumpClass | None,
        change_reason: str | None,
    ) -> None:
        identity = change_identity(
            rule_id, kind, from_version, to_version, to_source_hash
        )
        row = repo.get_change(self.db, identity)
        if row is not None:
            return  # append-only ledger; deterministic identity dedupes
        self.db.add(
            DetectionRuleChangeRow(
                change_id=identity,
                rule_id=rule_id,
                change_kind=kind.value,
                from_version=from_version,
                to_version=to_version,
                to_source_hash=to_source_hash,
                bump_class=bump_class.value if bump_class else None,
                change_reason=change_reason,
                created_by=self.actor_user_id,
            )
        )

    def _audit(self, action: str, rule_id: str, detail: str) -> None:
        log_action(
            db=self.db,
            action=action,
            user_id=self.actor_user_id,
            resource=f"rule:{rule_id}",
            details=detail[:500],
        )

    # ------------------------------------------------------------------
    # Read-model builders
    # ------------------------------------------------------------------

    def _version_record(self, row: DetectionRuleVersionRow) -> DetectionRuleVersionRecord:
        release = repo.get_release(self.db, row.rule_id, row.version)
        return DetectionRuleVersionRecord(
            version_id=row.version_id,
            rule_id=row.rule_id,
            version=row.version,
            rule_type=row.rule_type,
            severity=row.severity,
            title=row.title,
            description=row.description,
            author=row.author,
            status=row.status,
            category=row.category,
            source_path=row.source_path,
            source_hash=row.source_hash,
            hash_algorithm=row.hash_algorithm,
            tags=list(row.tags or []),
            enabled=row.enabled,
            validation_status=ValidationOutcome(row.validation_status),
            validation_error=row.validation_error,
            compiled=row.compiled,
            positive_passed=row.positive_passed,
            negative_passed=row.negative_passed,
            release_state=(
                ReleaseState(release.release_state)
                if release is not None
                else ReleaseState.DRAFT
            ),
            deployment_state=(
                DeploymentState(release.deployment_state)
                if release is not None
                else DeploymentState.UNDEPLOYED
            ),
            rollback_from=row.rollback_from,
            created_by=row.created_by,
            created_by_role=row.created_by_role,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    def _release_record(
        self, row: DetectionRuleReleaseRow
    ) -> DetectionRuleReleaseRecord:
        return DetectionRuleReleaseRecord(
            release_id=row.release_id,
            version_id=row.version_id,
            rule_id=row.rule_id,
            version=row.version,
            release_state=ReleaseState(row.release_state),
            deployment_state=DeploymentState(row.deployment_state),
            validated_at=row.validated_at,
            released_at=row.released_at,
            deployed_at=row.deployed_at,
            rollback_target_version=row.rollback_target_version,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    def _change_record(
        self, row: DetectionRuleChangeRow
    ) -> DetectionRuleChangeRecord:
        return DetectionRuleChangeRecord(
            change_id=row.change_id,
            rule_id=row.rule_id,
            change_kind=ChangeKind(row.change_kind),
            from_version=row.from_version,
            to_version=row.to_version,
            to_source_hash=row.to_source_hash,
            bump_class=(
                BumpClass(row.bump_class) if row.bump_class is not None else None
            ),
            change_reason=row.change_reason,
            created_by=row.created_by,
            created_at=row.created_at,
        )

    def validator_failed_record(self, record: DetectionRuleVersionRecord):
        """Validation detail shape for a record with no manifest entry."""
        from app.schemas.detection_as_code import ValidationDetail

        return ValidationDetail(
            rule_id=record.rule_id,
            version=record.version,
            outcome=ValidationOutcome.FAILED,
            manifest_valid=False,
            source_exists=False,
            source_hash_match=False,
            path_safe=False,
            secret_safe=False,
            rule_type_matches=False,
            severity_valid=False,
            metadata_complete=False,
            compiles=False,
            positive_passed=False,
            negative_passed=False,
            errors=["rule is not referenced by the controlled manifest"],
        )


def _now() -> datetime:
    return datetime.now(timezone.utc)


def resolve_deployment_target(session: Session, rule_id: str) -> str | None:
    """Latest released version for *rule_id*, or None (rollback hint)."""
    releases = repo.list_releases(session, rule_id)
    for release in releases:
        if release.release_state == ReleaseState.RELEASED.value:
            return release.version
    return None


__all__ = [
    "LifecycleService",
    "ADMIN_ROLE",
    "ANALYST_ROLE",
    "CISO_ROLE",
]