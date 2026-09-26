"""Detection-as-Code hashing / integrity tests (V2.17)."""

import hashlib

from app.services.detection_as_code import hashing


class TestSha256:
    def test_digest_matches_hashlib(self):
        data = b"rule: demo\n"
        assert hashing.sha256_digest(data) == hashlib.sha256(data).hexdigest()

    def test_deterministic(self):
        data = b"rule: demo\n"
        assert hashing.sha256_digest(data) == hashing.sha256_digest(data)

    def test_digest_changes_with_content(self):
        assert hashing.sha256_digest(b"a") != hashing.sha256_digest(b"b")

    def test_file_digest(self, tmp_path):
        path = tmp_path / "rule.yar"
        path.write_bytes(b"rule: demo\n")
        assert hashing.sha256_file(path) == hashlib.sha256(b"rule: demo\n").hexdigest()

    def test_algorithm_name(self):
        assert hashing.hash_algorithm_name() == "sha256"