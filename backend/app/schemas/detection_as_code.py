"""Detection-as-Code Domain Contract — V2.17.

Defines the foundational **domain contract** for the SentinelAI
Detection-as-Code lifecycle: the manifest vocabulary that describes every
governed rule, the closed validation/release/deployment state vocabularies,
the versioning rules, and the persisted read models for rule *versions*,
*releases* and *changes*.

Most important boundary (documented in ``docs/development/detection_as_code.md``):

    Detection-as-Code manages and validates detection content.
    It does NOT replace the Sigma/YARA detection engines.

This module contains **contract only** — no validation pipeline, no engine
invocation, no filesystem access, no persistence, and no API.  It mirrors the
Step 9A contract philosophy (``app/schemas/detection.py``): enums and bounds
that every other layer imports so there is a single, documented source of
truth for the vocabulary.

Design principles:

* **Reuse, don't duplicate.** :class:`~app.schemas.detection.RuleType` and
  :class:`~app.schemas.detection.DetectionSeverity` are imported from the
  existing Step 9A contract and used verbatim.  The runtime representation of
  a rule stays :class:`~app.schemas.detection.DetectionRule`; everything here
  describes its *lifecycle* and *source metadata*.
* **Closed state vocabularies.**  Validation is ``none/validating/validated/
  failed``, release is ``draft/validating/validated/released/failed`` and
  deployment is ``undeployed/deployed``; release state and deployment state
  are separate fields on purpose (an approved + released rule is *not*
  automatically deployed).  Change kinds are ``initialized/version_added/
  rolled_back``.
* **Deterministic identity.**  ``version_id``, ``release_id`` and
  ``change_id`` are UUIDv5 values over the fixed ``DAC_NAMESPACE`` plus the
  rule/version/hash/content tuple — two different rule contents can never
  share an immutable version identity, and the same operation always derives
  the same identity (idempotency is an identity test, never a guess).
* **Manifest = metadata + references.**  The manifest entry records metadata
  (rule id, type, version, expected severity, tags, source hash) and
  *references* to source + fixtures; it never embeds rule content.  The
  manifest is deterministic — the source hash is recorded so the source,
  the manifest and the persisted version can be cross-checked.
* **Verbatim-vs-scanned.**  Rule *content* is scanned for credential-value
  leakage (real credentials embedded as values), never for ordinary English
  words such as ``secret`` that legitimate detection markers contain (see
  ``credential_exposure.yar``).  Governance comments are free-form bounded
  strings.
* **No secrets.**  No field here may hold credentials; hashes are digests,
  not content.

Relationship to the pipeline::

    DetectionRule (Step 9A runtime definition)
        <- Detection-as-Code lifecycle validation/release/deploy (V2.17)
        <- RuleSourceManifestEntry            (this module)
        <- DetectionRuleVersionRecord         (this module, persisted)
        <- DetectionRuleReleaseRecord         (this module, persisted)
        <- DetectionRuleChangeRecord          (this module, persisted)

The pipeline::

    Source file  ->  manifest entry  ->  source hash  ->  validation
        ->  version  ->  release  ->  deploy  ->  DetectionRuleRegistry
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from app.schemas.detection import DetectionSeverity, RuleType


# ---------------------------------------------------------------------------
# Bounds & constants (single source of truth)
# ---------------------------------------------------------------------------

#: Deterministic UUIDv5 namespace for all Detection-as-Code identities.
#: Fixed so the same (rule, version, hash) tuple always derives the same
#: immutable version identity — the lifecycle never uses randomness.
DAC_NAMESPACE = uuid.UUID("4d0a1c2e-3f4a-4b5c-9d6e-0f1a2b3c4d5e")

#: Length bounds for governed fields (mirrored by the migration CHECKs).
MAX_RULE_ID_LENGTH = 128
MAX_VERSION_LENGTH = 32
MAX_TITLE_LENGTH = 200
MAX_DESCRIPTION_LENGTH = 1000
MAX_AUTHOR_LENGTH = 100
MAX_SOURCE_PATH_LENGTH = 255
MAX_SOURCE_HASH_LENGTH = 64
MAX_CATEGORY_LENGTH = 64
MAX_ROLE_LENGTH = 32
MAX_CHANGE_REASON_LENGTH = 500
MAX_VALIDATION_ERROR_LENGTH = 500

#: Only SHA-256 is used for source integrity.
HASH_ALGORITHM = "sha256"
HEX_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")

#: Initial version for every onboarded rule (existing 53 keep their
#: detection semantics; the DAC lifecycle starts the version history at
#: the compatible initial version ``1.0.0``).
INITIAL_VERSION = "1.0.0"

#: Allowed source-file extensions per rule type.
SIGMA_SOURCE_EXTENSIONS = frozenset({".yml", ".yaml"})
YARA_SOURCE_EXTENSIONS = frozenset({".yar", ".yara"})

#: Manifest source-root subdirectories (relative layout, posix separators).
SIGMA_SOURCE_ROOT = "sigma"
YARA_SOURCE_ROOT = "yara"

#: Credential-value leakage patterns (see app/services/detection_as_code/security.py
#: for the full scanner).  Keys that legitimately appear as *detection
#: markers* without an attached value (``client_secret=``) are not leaks.
SECRET_CONFIG_KEYS = frozenset(
    {
        "api_key",
        "apikey",
        "api-key",
        "client_secret",
        "client-secret",
        "access_key",
        "access_key_id",
        "secret",
        "secret_key",
        "token",
        "password",
        "passwd",
        "private_key",
        "aws_secret_access_key",
        "aws_access_key_id",
    }
)

#: Placeholder values that are never a leak (tests/demos/fixtures).
_SAFE_SECRET_VALUES = frozenset(
    {
        "redacted",
        "redact",
        "xxx",
        "xxxx",
        "example",
        "test",
        "change_me",
        "changeme",
        "fake",
        "placeholder",
        "placeholder_value",
        "value",
        "none",
        "null",
        "empty",
    }
)

#: Version bump classes (MAJOR / MINOR / PATCH).  The version transition is
#: derived from semantic-version comparison server-side; the client can only
#: classify, never fabricate a version string that does not change.
class BumpClass(str, Enum):
    MAJOR = "major"
    MINOR = "minor"
    PATCH = "patch"


#: Closed validation outcome vocabulary.
class ValidationOutcome(str, Enum):
    NONE = "none"
    VALIDATING = "validating"
    VALIDATED = "validated"
    FAILED = "failed"


#: Closed release lifecycle vocabulary.
class ReleaseState(str, Enum):
    DRAFT = "draft"
    VALIDATING = "validating"
    VALIDATED = "validated"
    RELEASED = "released"
    FAILED = "failed"


#: Closed deployment vocabulary (separate from release state on purpose).
class DeploymentState(str, Enum):
    UNDEPLOYED = "undeployed"
    DEPLOYED = "deployed"


#: Closed change-kind vocabulary for the versioning/rollback ledger.
class ChangeKind(str, Enum):
    INITIALIZED = "initialized"
    VERSION_ADDED = "version_added"
    ROLLED_BACK = "rolled_back"


# ---------------------------------------------------------------------------
# Semantic version helpers (deterministic)
# ---------------------------------------------------------------------------


def parse_semver(version: str) -> tuple[int, int, int]:
    """Return ``(major, minor, patch)`` for a strict ``X.Y.Z`` version.

    Raises ``ValueError`` for anything outside the strict numeric
    ``MAJOR.MINOR.PATCH`` shape (no suffixes, no leading zeros ambiguity —
    leading zeros are rejected to keep ordering unambiguous).
    """
    parts = version.split(".")
    if len(parts) != 3:
        raise ValueError("version must be in strict MAJOR.MINOR.PATCH form")
    values: list[int] = []
    for segment in parts:
        if not segment.isdigit() or (len(segment) > 1 and segment.startswith("0")):
            raise ValueError("version segments must be numeric without leading zeros")
        values.append(int(segment))
    return tuple(values)  # type: ignore[return-value]


def compare_versions(left: str, right: str) -> int:
    """Compare two strict semantic versions: -1, 0 or 1 like ``cmp``."""
    return (parse_semver(left) > parse_semver(right)) - (
        parse_semver(left) < parse_semver(right)
    )


def classify_bump(from_version: str | None, to_version: str) -> BumpClass:
    """Classify a version transition as MAJOR / MINOR / PATCH.

    ``from_version=None`` means an initial version (no transition — callers
    should only classify real transitions).  Raises ``ValueError`` when
    ``to_version`` does not strictly increase ``from_version``.
    """
    if from_version is None:
        raise ValueError("cannot classify an initial version as a bump")
    before = parse_semver(from_version)
    after = parse_semver(to_version)
    if after <= before:
        raise ValueError(
            f"new version {to_version} must be greater than {from_version}"
        )
    if after[0] != before[0]:
        return BumpClass.MAJOR
    if after[1] != before[1]:
        return BumpClass.MINOR
    return BumpClass.PATCH


# ---------------------------------------------------------------------------
# Deterministic identities
# ---------------------------------------------------------------------------


def version_identity(rule_id: str, version: str, source_hash: str) -> uuid.UUID:
    """Deterministic immutable identity of one versioned rule.

    The same (rule id, version, source hash) tuple always derives the same
    UUID, and a changed source hash produces a *different* identity even for
    the same version string — two different rule contents can never silently
    share the same immutable release identity.
    """
    return uuid.uuid5(DAC_NAMESPACE, f"version|{rule_id}|{version}|{source_hash}")


def release_identity(rule_id: str, version: str) -> uuid.UUID:
    """Deterministic identity of a release lifecycle for (rule, version)."""
    return uuid.uuid5(DAC_NAMESPACE, f"release|{rule_id}|{version}")


def change_identity(
    rule_id: str,
    kind: ChangeKind | str,
    from_version: str | None,
    to_version: str,
    to_source_hash: str,
) -> uuid.UUID:
    """Deterministic identity of a versioning/rollback change ledger row."""
    kind_value = kind.value if isinstance(kind, ChangeKind) else str(kind)
    return uuid.uuid5(
        DAC_NAMESPACE,
        f"change|{rule_id}|{kind_value}|{from_version or ''}|"
        f"{to_version}|{to_source_hash}",
    )


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


class RuleSourceManifestEntry(BaseModel):
    """One manifest entry: metadata + references for a governed rule.

    Never embeds rule content — ``source`` and the fixture references point
    at the controlled rule repository, and ``source_hash`` is the recorded
    digest the validation pipeline recomputes server-side.
    """

    model_config = {"extra": "forbid"}

    rule_id: str = Field(
        ...,
        min_length=1,
        max_length=MAX_RULE_ID_LENGTH,
        description="Stable, unique rule identifier (matches the rule source).",
    )
    rule_type: RuleType = Field(
        ..., description="sigma | yara — the engine the rule targets."
    )
    version: str = Field(
        default=INITIAL_VERSION,
        max_length=MAX_VERSION_LENGTH,
        description="Explicit semantic version of this rule content.",
    )
    severity: DetectionSeverity = Field(
        ..., description="Expected severity; must match the source verdict."
    )
    source: str = Field(
        ...,
        min_length=1,
        max_length=MAX_SOURCE_PATH_LENGTH,
        description=(
            "Repository source path relative to the rules root, posix "
            "separators, e.g. 'sigma/01-foo.yml'.  Never absolute."
        ),
    )
    source_hash: str = Field(
        ...,
        min_length=64,
        max_length=64,
        description="Recorded SHA-256 digest of the source file.",
    )
    hash_algorithm: str = Field(
        default=HASH_ALGORITHM,
        description="Hash algorithm used for source_hash ('sha256' only).",
    )
    positive_fixture: str = Field(
        ...,
        min_length=1,
        max_length=MAX_SOURCE_PATH_LENGTH,
        description="Positive fixture reference relative to the rules root.",
    )
    negative_fixture: str = Field(
        ...,
        min_length=1,
        max_length=MAX_SOURCE_PATH_LENGTH,
        description="Negative fixture reference relative to the rules root.",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Stable classification tags (matched against the source).",
    )
    status: str | None = Field(
        default=None,
        max_length=32,
        description="Documented rule status (stable/experimental/...).",
    )

    @field_validator("source", "positive_fixture", "negative_fixture")
    @classmethod
    def _ensure_relative_path(cls, v: str) -> str:
        value = v.replace("\\", "/")
        if value.startswith("/") or (":" in value.split("/", 1)[0]):
            raise ValueError(f"path must be relative and inside the rules root: {v!r}")
        parts = value.split("/")
        if any(part in ("..", "") for part in parts):
            raise ValueError(f"path must not contain '..' or empty segments: {v!r}")
        return value

    @field_validator("source_hash", "hash_algorithm")
    @classmethod
    def _ensure_hash_shape(cls, v: str, info: Any) -> str:
        if info.field_name == "source_hash":
            if not HEX_DIGEST_PATTERN.fullmatch(v):
                raise ValueError("source_hash must be a 64-char lowercase hex SHA-256 digest")
        elif v != HASH_ALGORITHM:
            raise ValueError("only sha256 is supported for source integrity")
        return v

    @field_validator("version")
    @classmethod
    def _ensure_semver(cls, v: str) -> str:
        parse_semver(v)  # raises ValueError otherwise
        return v

    @field_validator("source")
    @classmethod
    def _ensure_source_matches_type(cls, v: str, info: Any) -> str:
        rule_type = info.data.get("rule_type")
        suffix = v.rsplit(".", 1)[-1].lower() if "." in v else ""
        if rule_type is RuleType.SIGMA:
            if suffix not in {s.lstrip(".") for s in SIGMA_SOURCE_EXTENSIONS}:
                raise ValueError("sigma sources must be .yml/.yaml files")
            if not v.startswith(SIGMA_SOURCE_ROOT + "/"):
                raise ValueError("sigma sources must live under the 'sigma/' root")
        if rule_type is RuleType.YARA:
            if suffix not in {s.lstrip(".") for s in YARA_SOURCE_EXTENSIONS}:
                raise ValueError("yara sources must be .yar/.yara files")
            if not v.startswith(YARA_SOURCE_ROOT + "/"):
                raise ValueError("yara sources must live under the 'yara/' root")
        return v


class RuleSourceManifest(BaseModel):
    """Deterministic manifest for the controlled detection-rule repository."""

    model_config = {"extra": "forbid"}

    version: int = Field(default=1, ge=1, description="Manifest format version.")
    rules: list[RuleSourceManifestEntry] = Field(
        default_factory=list,
        description="One entry per governed rule.",
    )

    @model_validator(mode="after")
    def _ensure_unique_identities(self) -> "RuleSourceManifest":
        seen_ids: set[str] = set()
        seen_sources: set[str] = set()
        for entry in self.rules:
            if entry.rule_id in seen_ids:
                raise ValueError(f"duplicate rule_id in manifest: {entry.rule_id}")
            if entry.source in seen_sources:
                raise ValueError(
                    f"duplicate source reference in manifest: {entry.source}"
                )
            seen_ids.add(entry.rule_id)
            seen_sources.add(entry.source)
        return self

    def by_rule_id(self, rule_id: str) -> RuleSourceManifestEntry | None:
        for entry in self.rules:
            if entry.rule_id == rule_id:
                return entry
        return None


# ---------------------------------------------------------------------------
# Validation detail
# ---------------------------------------------------------------------------


class ValidationDetail(BaseModel):
    """Server-side validation detail for one rule (per check, never faked)."""

    rule_id: str = Field(..., description="Rule being validated.")
    version: str = Field(..., description="Version being validated.")
    outcome: ValidationOutcome = Field(
        ..., description="validated or failed (validating is transient, none is absent)."
    )
    manifest_valid: bool = Field(..., description="Manifest entry well-formed + unique.")
    source_exists: bool = Field(..., description="Controlled source file present.")
    source_hash_match: bool = Field(
        ..., description="Recomputed SHA-256 equals the manifest digest."
    )
    path_safe: bool = Field(
        ..., description="Source/fixtures resolve inside the rules root; no traversal."
    )
    secret_safe: bool = Field(..., description="No credential-value leakage.")
    rule_type_matches: bool = Field(..., description="Source root/extension matches type.")
    severity_valid: bool = Field(..., description="Severity is valid + matches source.")
    metadata_complete: bool = Field(
        ..., description="Required title/description/author/date metadata present."
    )
    compiles: bool = Field(..., description="Compiled through the real engine.")
    positive_passed: bool = Field(..., description="Positive fixture matched (engine).")
    negative_passed: bool = Field(..., description="Negative fixture stayed silent (engine).")
    errors: list[str] = Field(
        default_factory=list,
        description="Deterministic ordered error messages when checks failed.",
    )

    @property
    def passed(self) -> bool:
        """True when every gate passed (fail-closed)."""
        return self.outcome is ValidationOutcome.VALIDATED


# ---------------------------------------------------------------------------
# Persisted read models
# ---------------------------------------------------------------------------


class DetectionRuleVersionRecord(BaseModel):
    """Read model of one immutable rule version + its lifecycle state."""

    model_config = {"extra": "forbid"}

    version_id: uuid.UUID = Field(..., description="Deterministic immutable identity.")
    rule_id: str = Field(..., max_length=MAX_RULE_ID_LENGTH)
    version: str = Field(..., max_length=MAX_VERSION_LENGTH)
    rule_type: RuleType = Field(...)
    severity: DetectionSeverity = Field(...)
    title: str = Field(..., max_length=MAX_TITLE_LENGTH)
    description: str = Field(..., max_length=MAX_DESCRIPTION_LENGTH)
    author: str | None = Field(default=None, max_length=MAX_AUTHOR_LENGTH)
    status: str | None = Field(default=None, max_length=32)
    category: str | None = Field(default=None, max_length=MAX_CATEGORY_LENGTH)
    source_path: str = Field(..., max_length=MAX_SOURCE_PATH_LENGTH)
    source_hash: str = Field(..., min_length=64, max_length=64)
    hash_algorithm: str = Field(default=HASH_ALGORITHM)
    tags: list[str] = Field(default_factory=list)
    enabled: bool = Field(default=True)
    validation_status: ValidationOutcome = Field(default=ValidationOutcome.NONE)
    validation_error: str | None = Field(default=None, max_length=MAX_VALIDATION_ERROR_LENGTH)
    compiled: bool = Field(default=False)
    positive_passed: bool = Field(default=False)
    negative_passed: bool = Field(default=False)
    release_state: ReleaseState = Field(default=ReleaseState.DRAFT)
    deployment_state: DeploymentState = Field(default=DeploymentState.UNDEPLOYED)
    rollback_from: uuid.UUID | None = Field(
        default=None, description="Id of the version this version replaces via rollback."
    )
    created_by: uuid.UUID | None = Field(default=None)
    created_by_role: str | None = Field(default=None, max_length=MAX_ROLE_LENGTH)
    created_at: datetime = Field(...)
    updated_at: datetime = Field(...)


class DetectionRuleReleaseRecord(BaseModel):
    """Read model of one (rule, version) release/deployment lifecycle."""

    model_config = {"extra": "forbid"}

    release_id: uuid.UUID = Field(..., description="Deterministic release identity.")
    version_id: uuid.UUID = Field(..., description="Version identity being released.")
    rule_id: str = Field(..., max_length=MAX_RULE_ID_LENGTH)
    version: str = Field(..., max_length=MAX_VERSION_LENGTH)
    release_state: ReleaseState = Field(...)
    deployment_state: DeploymentState = Field(...)
    validated_at: datetime | None = Field(default=None)
    released_at: datetime | None = Field(default=None)
    deployed_at: datetime | None = Field(default=None)
    rollback_target_version: str | None = Field(
        default=None,
        description=(
            "Version that was active immediately before this version was "
            "deployed (deterministic rollback reference)."
        ),
    )
    created_at: datetime = Field(...)
    updated_at: datetime = Field(...)


class DetectionRuleChangeRecord(BaseModel):
    """Read model of one versioning/rollback history event."""

    model_config = {"extra": "forbid"}

    change_id: uuid.UUID = Field(..., description="Deterministic change identity.")
    rule_id: str = Field(..., max_length=MAX_RULE_ID_LENGTH)
    change_kind: ChangeKind = Field(...)
    from_version: str | None = Field(default=None)
    to_version: str = Field(..., max_length=MAX_VERSION_LENGTH)
    to_source_hash: str = Field(..., min_length=64, max_length=64)
    bump_class: BumpClass | None = Field(default=None)
    change_reason: str | None = Field(
        default=None, max_length=MAX_CHANGE_REASON_LENGTH
    )
    created_by: uuid.UUID | None = Field(default=None)
    created_at: datetime = Field(...)


class DetectionAsCodeRulePage(BaseModel):
    """Bounded page of rule version summaries."""

    items: list[DetectionRuleVersionRecord] = Field(default_factory=list)
    total: int = Field(..., ge=0)
    page: int = Field(..., ge=1)
    page_size: int = Field(..., ge=1, le=200)


class DetectionAsCodeRuleDetail(BaseModel):
    """One rule's current version plus its full lifecycle history."""

    current: DetectionRuleVersionRecord = Field(
        ..., description="Latest version record for the rule."
    )
    validation: ValidationDetail = Field(
        ..., description="Recomputable validation detail for the latest version."
    )
    releases: list[DetectionRuleReleaseRecord] = Field(
        default_factory=list,
        description="Release/deploy lifecycle rows, newest first.",
    )
    changes: list[DetectionRuleChangeRecord] = Field(
        default_factory=list,
        description="Versioning/rollback history, oldest first.",
    )


# ---------------------------------------------------------------------------
# Request payloads (mutation surface — never trust hashes or paths from here)
# ---------------------------------------------------------------------------


class ValidateRuleRequest(BaseModel):
    """Validate a rule from the controlled repository by ``rule_id``.

    Only ``rule_id`` is required.  ``version`` + ``bump_class`` are required
    *only* when the source changed since the latest governed version (a new
    version must be explicit — the system never guesses one).  Source hashes
    are always recomputed server-side; clients cannot supply them.
    """

    model_config = {"extra": "forbid"}

    rule_id: str = Field(..., min_length=1, max_length=MAX_RULE_ID_LENGTH)
    version: str | None = Field(
        default=None,
        max_length=MAX_VERSION_LENGTH,
        description="New semantic version when the source changed.",
    )
    bump_class: BumpClass | None = Field(
        default=None,
        description="MAJOR/MINOR/PATCH classification of the transition.",
    )
    change_reason: str | None = Field(
        default=None,
        max_length=MAX_CHANGE_REASON_LENGTH,
        description="Required accountability reason for a version bump.",
    )

    @model_validator(mode="after")
    def _ensure_bump_fields_pair(self) -> "ValidateRuleRequest":
        if (self.version is None) != (self.bump_class is None):
            raise ValueError("version and bump_class must be supplied together")
        if self.bump_class is not None and not (self.change_reason or "").strip():
            raise ValueError("change_reason is required for a version bump")
        return self


class ReleaseRequest(BaseModel):
    """Release an already-validated version."""

    model_config = {"extra": "forbid"}

    rule_id: str = Field(..., min_length=1, max_length=MAX_RULE_ID_LENGTH)
    version: str = Field(..., min_length=1, max_length=MAX_VERSION_LENGTH)


class DeployRequest(BaseModel):
    """Deploy a released rule version into the governed registry snapshot."""

    model_config = {"extra": "forbid"}

    rule_id: str = Field(..., min_length=1, max_length=MAX_RULE_ID_LENGTH)
    version: str = Field(..., min_length=1, max_length=MAX_VERSION_LENGTH)


class RollbackRequest(BaseModel):
    """Roll back a rule to an existing, validated, released version."""

    model_config = {"extra": "forbid"}

    rule_id: str = Field(..., min_length=1, max_length=MAX_RULE_ID_LENGTH)
    version: str = Field(..., min_length=1, max_length=MAX_VERSION_LENGTH)


class SetEnabledRequest(BaseModel):
    """Enable/disable a governed rule version."""

    model_config = {"extra": "forbid"}

    rule_id: str = Field(..., min_length=1, max_length=MAX_RULE_ID_LENGTH)
    version: str = Field(..., min_length=1, max_length=MAX_VERSION_LENGTH)
    enabled: bool = Field(
        default=True, description="True enables the governed version."
    )