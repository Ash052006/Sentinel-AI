"""Source integrity hashing (V2.17).

Deterministic SHA-256 digests over raw rule-source bytes.  Timestamps are
never used as an integrity mechanism; only the digest of the content.

The manifest records the expected digest; the validation pipeline recomputes
it server-side and compares.  A content change always changes the digest.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from app.schemas.detection_as_code import HASH_ALGORITHM


def sha256_digest(data: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of *data*."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest of *path*'s raw bytes (streamed)."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hash_algorithm_name() -> str:
    """Return the canonical algorithm label recorded everywhere."""
    return HASH_ALGORITHM