"""Detection-as-Code path-safety tests (V2.17).

The DAC surface never accepts client-supplied filesystem paths; these tests
verify the controlled-manifest path guards stay strict.
"""

from pathlib import Path

import pytest

from app.services.detection_as_code.paths import (
    UnsafePathError,
    ensure_not_executable,
    ensure_source_extension,
    resolve_safe,
)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    rules = tmp_path / "rules"
    (rules / "sigma").mkdir(parents=True)
    return rules


class TestResolveSafe:
    def test_relative_inside_root_ok(self, root):
        resolved = resolve_safe(root, "sigma/a.yml")
        assert resolved == (root / "sigma/a.yml").resolve()
        assert resolved.is_relative_to(root.resolve())

    def test_empty_path_rejected(self, root):
        with pytest.raises(UnsafePathError):
            resolve_safe(root, "")

    def test_absolute_path_rejected(self, root):
        with pytest.raises(UnsafePathError):
            resolve_safe(root, "/etc/passwd")

    def test_traversal_rejected(self, root):
        with pytest.raises(UnsafePathError):
            resolve_safe(root, "sigma/../outside.yml")

    def test_dot_segment_rejected(self, root):
        with pytest.raises(UnsafePathError):
            resolve_safe(root, "sigma/./a.yml")

    def test_windows_drive_rejected(self, root):
        with pytest.raises(UnsafePathError):
            resolve_safe(root, "C:\\sigma\\a.yml")

    def test_duplicate_slash_rejected(self, root):
        with pytest.raises(UnsafePathError):
            resolve_safe(root, "sigma//a.yml")

    def test_symlink_escape_rejected(self, root, tmp_path):
        outside = tmp_path / "outside.txt"
        outside.write_text("secret")
        link = root / "sigma" / "link.yml"
        link.symlink_to(outside)
        with pytest.raises(UnsafePathError):
            resolve_safe(root, "sigma/link.yml")


class TestEnsureSourceExtension:
    def test_sigma_yml_ok(self):
        ensure_source_extension("sigma/a.yml", "sigma")

    def test_sigma_yaml_ok(self):
        ensure_source_extension("sigma/a.yaml", "sigma")

    def test_sigma_rejects_yar(self):
        with pytest.raises(UnsafePathError):
            ensure_source_extension("sigma/a.yar", "sigma")

    def test_yara_yar_ok(self):
        ensure_source_extension("yara/a.yar", "yara")
        ensure_source_extension("yara/a.yara", "yara")

    def test_yara_rejects_yml(self):
        with pytest.raises(UnsafePathError):
            ensure_source_extension("yara/a.yml", "yara")

    def test_rejects_script_extensions(self):
        for name in ("a.py", "a.sh", "a.js"):
            with pytest.raises(UnsafePathError):
                ensure_source_extension(f"sigma/{name}", "sigma")


class TestEnsureNotExecutable:
    def test_shell_script_rejected(self, tmp_path):
        script = tmp_path / "a.sh"
        script.write_text("#!/bin/bash\necho hi\n")
        with pytest.raises(UnsafePathError):
            ensure_not_executable(script)

    def test_nul_bytes_rejected(self, tmp_path):
        binary = tmp_path / "a.info"
        binary.write_bytes(b"RULE\x00\xff")
        with pytest.raises(UnsafePathError):
            ensure_not_executable(binary)

    def test_non_utf8_rejected(self, tmp_path):
        bad = tmp_path / "a.bin"
        bad.write_bytes(b"\xff\xfe\x00rule")
        with pytest.raises(UnsafePathError):
            ensure_not_executable(bad)

    def test_plain_text_ok(self, tmp_path):
        text = tmp_path / "a.txt"
        text.write_text("all good")
        ensure_not_executable(text)