"""Detection-as-Code controlled manifest loading/generation (V2.17).

The manifest is the **single governed inventory** at ``rules/manifest.yaml``:

* Every entry is metadata + references only (never rule content).
* It is deterministic: the generator recomputes source hashes and rewrites
  the whole file; the validator re-loads it, cross-checks source hashes,
  and flags orphaned source files or missing referenced files.
* Paths are relative to the rules root with posix separators; the manifest
  schema itself refuses ``..`` / absolute / empty-segment references.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from app.schemas.detection_as_code import (
    RuleSourceManifest,
    RuleSourceManifestEntry,
    SIGMA_SOURCE_EXTENSIONS,
    YARA_SOURCE_EXTENSIONS,
)

#: Manifest filename inside the controlled rules root.
MANIFEST_FILENAME = "manifest.yaml"

#: Source-extension matchers per rule type (used by the orphan scanner).
_SIGMA_SUFFIXES = {ext.lower() for ext in SIGMA_SOURCE_EXTENSIONS}
_YARA_SUFFIXES = {ext.lower() for ext in YARA_SOURCE_EXTENSIONS}


class ManifestFileError(ValueError):
    """The manifest file is missing, corrupt, or does not parse cleanly."""


def load_manifest(root: Path) -> RuleSourceManifest:
    """Load + schema-validate ``manifest.yaml`` under *root*.

    Raises :class:`ManifestFileError` when the file is absent or cannot be
    parsed into the closed manifest contract.
    """
    manifest_path = root / MANIFEST_FILENAME
    if not manifest_path.is_file():
        raise ManifestFileError(f"manifest missing at {manifest_path}")
    try:
        raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ManifestFileError(f"manifest does not parse as YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ManifestFileError("manifest must be a mapping")
    try:
        return RuleSourceManifest.model_validate(raw)
    except Exception as exc:
        raise ManifestFileError(f"manifest violates the contract: {exc}") from exc


def dumps_manifest(manifest: RuleSourceManifest) -> str:
    """Deterministic textual representation of a manifest."""
    entries = [
        {
            "rule_id": entry.rule_id,
            "rule_type": entry.rule_type.value,
            "version": entry.version,
            "severity": entry.severity.value,
            "source": entry.source,
            "source_hash": entry.source_hash,
            "hash_algorithm": entry.hash_algorithm,
            "positive_fixture": entry.positive_fixture,
            "negative_fixture": entry.negative_fixture,
            "tags": list(entry.tags),
            "status": entry.status,
        }
        for entry in sorted(manifest.rules, key=lambda e: e.rule_id)
    ]
    payload = {"version": manifest.version, "rules": entries}
    return yaml.safe_dump(
        payload,
        sort_keys=False,
        allow_unicode=False,
        default_flow_style=False,
        width=200,
    )


def write_manifest(root: Path, manifest: RuleSourceManifest) -> Path:
    """Atomically write the generated manifest under *root*."""
    path = root / MANIFEST_FILENAME
    temp = root / f".{MANIFEST_FILENAME}.tmp"
    temp.write_text(dumps_manifest(manifest), encoding="utf-8")
    temp.replace(path)
    return path


def find_orphan_sources(root: Path, manifest: RuleSourceManifest) -> list[str]:
    """Source files under the rules root not referenced by the manifest.

    Deterministic (sorted).  A governed validation environment must not
    contain unreferenced rule sources — the rule set and the manifest are
    synchronized artifacts.
    """
    referenced: set[str] = {entry.source for entry in manifest.rules}
    orphans: list[str] = []

    sigma_dir = root / "sigma"
    for path in sorted(sigma_dir.glob("*.*")) if sigma_dir.is_dir() else ():
        if path.suffix.lower() in _SIGMA_SUFFIXES:
            relative = f"sigma/{path.name}"
            if relative not in referenced:
                orphans.append(relative)

    yara_dir = root / "yara"
    for path in sorted(yara_dir.glob("*.*")) if yara_dir.is_dir() else ():
        if path.suffix.lower() in _YARA_SUFFIXES:
            relative = f"yara/{path.name}"
            if relative not in referenced:
                orphans.append(relative)

    return orphans


def find_invalid_sources(root: Path, manifest: RuleSourceManifest) -> list[str]:
    """Manifest source references whose files are absent/missing."""
    missing: list[str] = []
    for entry in manifest.rules:
        path = root / entry.source
        if not path.is_file():
            missing.append(entry.source)
    return missing


def build_entry(
    *,
    rule_id: str,
    rule_type: str,
    version: str,
    severity: str,
    source: str,
    source_hash: str,
    positive_fixture: str,
    negative_fixture: str,
    tags: list[str] | None = None,
    status: str | None = None,
) -> RuleSourceManifestEntry:
    """Construct a contract-valid manifest entry (used by the generator)."""
    return RuleSourceManifestEntry(
        rule_id=rule_id,
        rule_type=rule_type,
        version=version,
        severity=severity,
        source=source,
        source_hash=source_hash,
        positive_fixture=positive_fixture,
        negative_fixture=negative_fixture,
        tags=list(tags or []),
        status=status,
    )


__all__ = [
    "MANIFEST_FILENAME",
    "ManifestFileError",
    "load_manifest",
    "dumps_manifest",
    "write_manifest",
    "find_orphan_sources",
    "find_invalid_sources",
    "build_entry",
]