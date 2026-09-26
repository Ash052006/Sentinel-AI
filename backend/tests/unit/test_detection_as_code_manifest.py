"""Detection-as-Code manifest tests (V2.17)."""

from pathlib import Path

import pytest
import yaml

from app.services.detection_as_code.manifest import (
    MANIFEST_FILENAME,
    ManifestFileError,
    build_entry,
    dumps_manifest,
    find_invalid_sources,
    find_orphan_sources,
    load_manifest,
    write_manifest,
)
from app.schemas.detection_as_code import RuleSourceManifest


def _entry(rule_id="sigma-001", suffix="yml"):
    return build_entry(
        rule_id=rule_id,
        rule_type="sigma",
        version="1.0.0",
        severity="high",
        source=f"sigma/{rule_id}.{suffix}",
        source_hash="a" * 64,
        positive_fixture=f"sigma/fixtures/{rule_id}/positive.json",
        negative_fixture=f"sigma/fixtures/{rule_id}/negative.json",
        tags=["test"],
        status="stable",
    )


class TestManifestRoundTrip:
    def test_dump_load_round_trip(self, tmp_path):
        manifest = RuleSourceManifest(rules=[_entry()])
        serialized = dumps_manifest(manifest)
        (tmp_path / MANIFEST_FILENAME).write_text(serialized, encoding="utf-8")
        loaded = load_manifest(tmp_path)
        assert loaded.rules[0].rule_id == "sigma-001"
        assert loaded.rules[0].source_hash == "a" * 64

    def test_dump_is_deterministic(self):
        manifest = RuleSourceManifest(rules=[_entry(rule_id="b-2"), _entry(rule_id="a-1")])
        assert dumps_manifest(manifest) == dumps_manifest(manifest)

    def test_dump_sorts_by_rule_id(self):
        manifest = RuleSourceManifest(rules=[_entry(rule_id="b-2"), _entry(rule_id="a-1")])
        assert dumps_manifest(manifest).index("a-1") < dumps_manifest(manifest).index("b-2")

    def test_write_manifest_atomic(self, tmp_path):
        manifest = RuleSourceManifest(rules=[_entry()])
        path = write_manifest(tmp_path, manifest)
        assert path == tmp_path / MANIFEST_FILENAME
        assert (tmp_path / MANIFEST_FILENAME).is_file()

    def test_duplicate_rule_ids_rejected(self, tmp_path):
        rules = [_entry(), _entry(rule_id="sigma-002")]
        rules[1] = build_entry(
            rule_id="sigma-002",
            rule_type="sigma",
            version="1.0.0",
            severity="high",
            source="sigma/sigma-002.yml",
            source_hash="b" * 64,
            positive_fixture="sigma/fixtures/sigma-002/positive.json",
            negative_fixture="sigma/fixtures/sigma-002/negative.json",
        )
        manifest = RuleSourceManifest(rules=rules)
        # Duplicate rule_id in the raw YAML must fail validation.
        text = dumps_manifest(manifest).replace("sigma-002", "sigma-001")
        (tmp_path / MANIFEST_FILENAME).write_text(text, encoding="utf-8")
        with pytest.raises(ManifestFileError):
            load_manifest(tmp_path)


class TestManifestErrors:
    def test_missing_manifest(self, tmp_path):
        with pytest.raises(ManifestFileError):
            load_manifest(tmp_path)

    def test_non_mapping_manifest(self, tmp_path):
        (tmp_path / MANIFEST_FILENAME).write_text("- just\n- a\n- list\n", encoding="utf-8")
        with pytest.raises(ManifestFileError):
            load_manifest(tmp_path)

    def test_invalid_yaml(self, tmp_path):
        (tmp_path / MANIFEST_FILENAME).write_text("{unclosed", encoding="utf-8")
        with pytest.raises(ManifestFileError):
            load_manifest(tmp_path)

    def test_violating_contract(self, tmp_path):
        (tmp_path / MANIFEST_FILENAME).write_text(
            "rules:\n  - rule_id: x\n", encoding="utf-8"
        )
        with pytest.raises(ManifestFileError):
            load_manifest(tmp_path)


class TestOrphansAndInvalid:
    def test_orphan_source_detected(self, tmp_path):
        (tmp_path / "sigma").mkdir()
        (tmp_path / "sigma" / "unused.yml").write_text("rule: unused\n", encoding="utf-8")
        manifest = RuleSourceManifest(rules=[_entry()])
        assert find_orphan_sources(tmp_path, manifest) == ["sigma/unused.yml"]

    def test_no_orphans(self, tmp_path):
        (tmp_path / "sigma").mkdir()
        (tmp_path / "sigma" / "sigma-001.yml").write_text("rule: ok\n", encoding="utf-8")
        manifest = RuleSourceManifest(rules=[_entry()])
        assert find_orphan_sources(tmp_path, manifest) == []

    def test_yara_orphans(self, tmp_path):
        (tmp_path / "yara").mkdir()
        (tmp_path / "yara" / "gone.yar").write_text("rule: gone\n", encoding="utf-8")
        manifest = RuleSourceManifest(rules=[_entry()])
        assert find_orphan_sources(tmp_path, manifest) == ["yara/gone.yar"]

    def test_missing_referenced_source(self, tmp_path):
        manifest = RuleSourceManifest(rules=[_entry()])
        assert find_invalid_sources(tmp_path, manifest) == ["sigma/sigma-001.yml"]

    def test_non_source_extensions_ignored_for_orphans(self, tmp_path):
        (tmp_path / "sigma").mkdir()
        (tmp_path / "sigma" / "README.md").write_text("docs\n", encoding="utf-8")
        manifest = RuleSourceManifest(rules=[])
        assert find_orphan_sources(tmp_path, manifest) == []


class TestYamlSafety:
    def test_dump_is_not_binary(self, tmp_path):
        manifest = RuleSourceManifest(rules=[_entry()])
        (tmp_path / MANIFEST_FILENAME).write_text(dumps_manifest(manifest), encoding="utf-8")
        loaded_yaml = yaml.safe_load((tmp_path / MANIFEST_FILENAME).read_text("utf-8"))
        assert "rules" in loaded_yaml and isinstance(loaded_yaml["rules"], list)