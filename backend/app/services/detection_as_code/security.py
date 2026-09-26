"""Detection-as-Code content security scanning (V2.17).

Reject detection *content* (rule source and fixtures) that embeds **real
credentials as values**, while never rejecting legitimate detection markers.

Caution is deliberate: an existing shipped rule must keep passing.  For example
``credential_exposure.yar`` detects credential leakage and therefore contains
the literal marker strings ``client_secret=``, ``aws_secret_access_key=``,
``api_key=`` — none of which carry an attached *value*, so none is a leak.

Scan levels (deterministic, run against raw UTF-8 text):

* **Recognized credential formats** — AWS access keys (``AKIA...``), PEM
  private-key headers, JWTs, GitHub/Slack prefixed tokens.  These are
  unambiguous real-credential shapes.
* **Credential-key/value assignments with a plausible secret value** — a
  sensitive key (``password``, ``token``, ``api_key``, ...) assigned a
  value that *looks* like a real secret (mixed case + digits, >= 12 chars)
  and is not a documented placeholder.  Bare markers (``client_secret=``
  with no value, all-lowercase dictionary words, URLs/paths) are ignored.

This mirrors the Step 9A secret-safety philosophy without the substring
false positives a naive pattern scan would create against detection content.
"""

from __future__ import annotations

import re

from app.schemas.detection_as_code import (
    _SAFE_SECRET_VALUES,
    SECRET_CONFIG_KEYS,
)

#: Unambiguous real-credential shapes.
#: A PEM *private key* is a leak only when a **complete** block exists
#: (both the ``BEGIN`` and the matching ``END`` private-key header).  A
#: lone ``-----BEGIN PRIVATE KEY-----`` opening header is a legitimate
#: detection marker (the shipped ``credential_exposure.yar``/fixture use it
#: to *detect* keys) and is never by itself a leaked credential.
_PEM_BEGIN_RE = re.compile(
    r"-----BEGIN\s+(?:RSA\s+|OPENSSH\s+|EC\s+|DSA\s+)?PRIVATE\s+KEY-----"
)
_PEM_END_RE = re.compile(
    r"-----END\s+(?:RSA\s+|OPENSSH\s+|EC\s+|DSA\s+)?PRIVATE\s+KEY-----"
)

_CREDENTIAL_FORMATS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
)

#: Sensitive key followed by ``=``/``:`` and a possibly-quoted value.
_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?P<key>"
    r"(?:api[_-]?key|access[_-]?key|client[_-]?secret|secret[_-]?key|secret"
    r"|token|password|passwd|passw|pwd|private[_-]?key"
    r"|auth|authorization|credential)"
    r")\b\s*[=:]\s*(?P<quoted>[\"']?)(?P<value>[^\"'\s,;}]+)"
)

#: Placeholder value fragments that are never a leak.
_PLACEHOLDER_FRAGMENTS = ("redacted", "example", "xxxx", "change_me", "test")


def _classify_placeholder(value: str) -> bool:
    lowered = value.lower().rstrip("=_")
    if lowered in _SAFE_SECRET_VALUES:
        return True
    return any(fragment in lowered for fragment in _PLACEHOLDER_FRAGMENTS)


def _plausible_secret_value(value: str) -> bool:
    """True when *value* looks like a real secret (mixed case + digits)."""
    if len(value) < 12:
        return False
    if "/" in value or "\\" in value or value.startswith(("http:", "https:")):
        return False
    has_upper = any(ch.isupper() for ch in value)
    has_digit = any(ch.isdigit() for ch in value)
    has_lower = any(ch.islower() for ch in value)
    if not has_lower or not (has_upper or has_digit):
        return False
    return True


def scan_secret_leakage(text: str) -> list[str]:
    """Return ordered descriptions of credential-shaped findings in *text*.

    Deterministic: findings are collected then sorted by (kind, index).
    Empty list means the content is clean.
    """
    findings: list[tuple[str, int, str]] = []

    for kind, pattern in _CREDENTIAL_FORMATS:
        for match in pattern.finditer(text):
            findings.append(
                (kind, match.start(), f"credential-shaped content ({kind})")
            )

    if _PEM_BEGIN_RE.search(text) and _PEM_END_RE.search(text):
        findings.append(
            (
                "pem_private_key",
                _PEM_BEGIN_RE.search(text).start(),
                "credential-shaped content (pem_private_key)",
            )
        )

    for match in _ASSIGNMENT_RE.finditer(text):
        key = match.group("key").lower()
        if key not in SECRET_CONFIG_KEYS:
            continue
        value = match.group("value").strip()
        if not value or value in ("=", ":"):
            continue
        if _classify_placeholder(value):
            continue
        if _plausible_secret_value(value):
            findings.append(
                (
                    "key_value_assignment",
                    match.start(),
                    f"credential-key assignment ('{key}') with a plausible secret value",
                )
            )

    findings.sort(key=lambda item: (item[0], item[1]))
    return [label for _, _, label in findings]


__all__ = ["scan_secret_leakage"]