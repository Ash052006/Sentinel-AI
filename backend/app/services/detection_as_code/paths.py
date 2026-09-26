"""Controlled-rule-repository path safety (V2.17).

The Detection-as-Code surface **never accepts filesystem paths from
clients**.  All source/fixture references originate in the controlled
manifest and are resolved relative to the rules root with these guards:

* ``..`` segments are rejected.
* Absolute paths (``/...``, Windows drives) are rejected.
* Symlinks cannot escape the root (the resolved real path must stay inside
  the root's real path).
* Unexpected / executable extensions are rejected.
* Binary (NUL-bearing / non-UTF-8) files are rejected.
"""

from __future__ import annotations

import os
from pathlib import Path

from app.schemas.detection_as_code import (
    SIGMA_SOURCE_EXTENSIONS,
    YARA_SOURCE_EXTENSIONS,
)

#: Extension families that can never be a rule source or fixture.
_EXECUTABLE_EXTENSIONS = frozenset(
    {
        ".exe",
        ".bin",
        ".dll",
        ".so",
        ".dylib",
        ".sh",
        ".bash",
        ".cmd",
        ".bat",
        ".py",
        ".pyc",
        ".js",
        ".mjs",
        ".ts",
        ".php",
        ".rb",
        ".pl",
        ".ps1",
    }
)


class UnsafePathError(ValueError):
    """Raised when a path reference violates a containment/type guard."""


def resolve_safe(root: Path, relative: str) -> Path:
    """Resolve *relative* against *root*, enforcing every containment guard.

    Raises :class:`UnsafePathError` on any violation.  Returns the resolved
    absolute file path *without* requiring it to exist (existence is the
    caller's concern).
    """
    if not isinstance(relative, str) or not relative:
        raise UnsafePathError("path reference must be a non-empty string")

    normalized = relative.replace("\\", "/")
    if normalized.startswith("/") or os.path.isabs(normalized):
        raise UnsafePathError("absolute paths are rejected")
    if ":/" in normalized or re_drive().match(normalized):
        raise UnsafePathError("drive-qualified paths are rejected")

    parts = normalized.split("/")
    if any(part in ("..", ".") for part in parts):
        raise UnsafePathError("path traversal segments are rejected")
    if any(part == "" for part in parts):
        raise UnsafePathError("empty path segments are rejected")

    root_real = root.resolve()
    candidate = (root / normalized).resolve()
    # realpath physically resolves symlinks; the candidate's real path must
    # remain a descendant of the root's real path (symlink-escape guard).
    candidate_real = Path(os.path.realpath(candidate))
    root_real_checked = Path(os.path.realpath(root_real))
    if not candidate_real.is_relative_to(root_real_checked):
        raise UnsafePathError(
            "path must stay inside the rules root (symlink escape rejected)"
        )
    return candidate_real


def re_drive():
    """Windows drive-letter matcher (defensive; POSIX hosts it never fires)."""
    import re

    return re.compile(r"^[A-Za-z]:[\\/]")


def ensure_source_extension(relative: str, rule_type: str) -> None:
    """Reject sources with a wrong/unexpected/executable extension."""
    suffix = Path(relative).suffix.lower()
    allowed = (
        SIGMA_SOURCE_EXTENSIONS
        if rule_type == "sigma"
        else YARA_SOURCE_EXTENSIONS
    )
    if suffix not in allowed:
        raise UnsafePathError(
            f"unexpected source extension {suffix!r} for {rule_type} rule"
        )
    if suffix in _EXECUTABLE_EXTENSIONS:
        raise UnsafePathError("executable file extensions are rejected")


def ensure_not_executable(path: Path) -> None:
    """Reject binary/executable-looking files by ext and content sniffing."""
    suffix = path.suffix.lower()
    if suffix:
        if suffix in _EXECUTABLE_EXTENSIONS or suffix in (
            ".bat",
            ".cmd",
            ".com",
        ):
            raise UnsafePathError(f"executable extension {suffix!r} rejected")
    if not path.exists():
        return
    try:
        with path.open("rb") as handle:
            head = handle.read(2048)
    except OSError as exc:
        raise UnsafePathError(f"cannot read source file: {exc}") from exc
    if b"\x00" in head:
        raise UnsafePathError("binary content (NUL bytes) is rejected")
    try:
        head.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UnsafePathError("non-UTF-8 binary content is rejected") from exc


__all__ = [
    "UnsafePathError",
    "resolve_safe",
    "ensure_source_extension",
    "ensure_not_executable",
]