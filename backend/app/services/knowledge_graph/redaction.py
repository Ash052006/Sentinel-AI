"""Secret-safe serialization for graph payloads — V3.22.

Graph construction already uses a strict per-type metadata allowlist (see
:mod:`app.services.knowledge_graph.vocabulary`), so credential-shaped data
should never reach this module.  This is the second, independent layer: any
graph response is redacted on the way out, so a future metadata field cannot
turn the read API into a disclosure endpoint.

The redaction is *fail-safe rather than fail-closed* on purpose.  A graph read
must never return HTTP 500 because a stored label contained a
credential-shaped substring; instead the offending key is dropped and the
read succeeds with less data.  Construction-side validation remains the
primary control.
"""

from __future__ import annotations

import re
from typing import Any, Final

#: Reused from the V2 AI trust boundary so the two layers cannot drift apart.
from app.agents.investigation._safety import SECRET_PATTERNS

#: Longest string retained in any single metadata/label value.
MAX_STRING_LENGTH: Final[int] = 512

#: Longest string retained in a node label.
MAX_LABEL_LENGTH: Final[int] = 256

_REDACTED: Final[str] = "[redacted]"

#: Keys are matched after non-alphanumerics are removed, so ``api-key``,
#: ``API_KEY`` and ``apiKey`` are all recognised as the same credential name.
_SECRET_KEY_PATTERN: Final[re.Pattern[str]] = re.compile(
    "|".join(re.escape(p) for p in SECRET_PATTERNS), re.IGNORECASE
)

#: Supplementary credential key names beyond the V2 AI-boundary list.  These
#: are unambiguous credential names; none of them can collide with an
#: allowlisted graph metadata key.
_EXTRA_SECRET_KEYS: Final[tuple[str, ...]] = (
    "passphrase",
    "privatekey",
    "accesskey",
    "secretkey",
    "clientsecret",
    "connectionstring",
    "credential",
    "credentials",
)

_NORMALIZE_KEY: Final[re.Pattern[str]] = re.compile(r"[^a-z0-9]+")

#: The V2 secret patterns pre-normalized, so ``api_key`` and ``apiKey``
#: collapse to the same needle.
_NORMALIZED_SECRET_PATTERNS: Final[tuple[str, ...]] = tuple(
    _NORMALIZE_KEY.sub("", pattern.lower()) for pattern in SECRET_PATTERNS
)


def _normalize_key(key: str) -> str:
    """Lowercase and drop separators so key spellings collapse together."""
    return _NORMALIZE_KEY.sub("", str(key).lower())

#: Values that look like credentials even under an innocuous key.
_VALUE_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"\$argon2(id|i|d)\$", re.IGNORECASE),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{20,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
)

#: Credential material assigned inside free text, e.g. a label or an error
#: message that captured ``password=hunter2`` or ``authorization: Bearer x``.
#: Key-name matching alone cannot catch these, because the whole string is
#: stored under an innocuous key such as ``label`` or ``title``.
_ASSIGNMENT_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?i)\b(?:"
    r"api[_-]?keys?|apisecret|apikey|secret[_-]?key|secrets?|"
    r"password|passwd|pwd|passphrase|"
    r"access[_-]?token|refresh[_-]?token|session[_-]?token|auth[_-]?token|tokens?|"
    r"authorization|authorisation|auth[_-]?header|proxy[_-]?authorization|"
    r"client[_-]?secret|private[_-]?key|aws[_-]?secret[_-]?access[_-]?key|"
    r"connection[_-]?string|dsn|jwt|bearer|cookie|session[_-]?id|csrf[_-]?token"
    r")\b\s*[:=]\s*\S+"
)

#: ``Bearer <token>`` anywhere in free text.
_BEARER_PATTERN: Final[re.Pattern[str]] = re.compile(r"(?i)\bbearer\s+\S+")


def is_secret_key(key: str) -> bool:
    """True when a mapping key names credential material.

    Matching is spelling-insensitive: separators and case are normalized away
    so ``api_key``, ``API-KEY`` and ``apiKey`` are all caught.
    """
    if _SECRET_KEY_PATTERN.search(str(key)):
        return True
    normalized = _normalize_key(key)
    return any(
        secret in normalized
        for secret in _NORMALIZED_SECRET_PATTERNS + _EXTRA_SECRET_KEYS
    )


def looks_like_secret_value(value: str) -> bool:
    """True when a string carries credential-shaped content.

    Checks three independent shapes: a known credential token format, an
    explicit credential assignment (``password=...``), and a ``Bearer``
    header value.  The assignment check matters because stored labels and
    error text routinely capture a connection string verbatim.
    """
    if not isinstance(value, str):
        return False
    if any(pattern.search(value) for pattern in _VALUE_PATTERNS):
        return True
    if _ASSIGNMENT_PATTERN.search(value):
        return True
    if _BEARER_PATTERN.search(value):
        return True
    return False


def sanitize_text(value: Any, *, max_length: int = MAX_STRING_LENGTH) -> Any:
    """Return *value* redacted and length-bounded.

    Prompt-injection payloads are *data*: they can never become graph
    semantics, but they are still returned as inert text so an analyst can see
    what was stored.
    """
    if not isinstance(value, str):
        return value
    if looks_like_secret_value(value):
        return _REDACTED
    if len(value) > max_length:
        return value[:max_length] + "…[truncated]"
    return value


def sanitize_metadata(value: Any, *, _depth: int = 0) -> Any:
    """Recursively sanitize metadata for safe serialization.

    Drops credential-shaped keys outright and replaces credential-shaped
    values.  Depth is bounded so a pathological structure cannot recurse
    without limit.
    """
    if _depth > 6:
        return "[depth-limited]"
    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        for key, item in value.items():
            key_str = str(key)
            if is_secret_key(key_str):
                continue
            clean[key_str] = sanitize_metadata(item, _depth=_depth + 1)
        return clean
    if isinstance(value, (list, tuple)):
        return [sanitize_metadata(item, _depth=_depth + 1) for item in value][:64]
    return sanitize_text(value)


def sanitize_label(value: Any) -> str:
    """Bound and redact a node label."""
    if value is None:
        return ""
    text = str(value)
    if looks_like_secret_value(text):
        return _REDACTED
    return text[:MAX_LABEL_LENGTH]


def assert_serialization_safe(payload: Any) -> None:
    """Final gate: raise if a serialized payload still carries credentials.

    Used by tests and by the serializer's own self-check.  The API path calls
    :func:`sanitize_metadata` / :func:`sanitize_label`, which cannot raise.
    """
    if isinstance(payload, dict):
        for key, item in payload.items():
            if is_secret_key(key):
                raise ValueError(f"secret-shaped key survived redaction: {key!r}")
            assert_serialization_safe(item)
        return
    if isinstance(payload, (list, tuple)):
        for item in payload:
            assert_serialization_safe(item)
        return
    if isinstance(payload, str) and looks_like_secret_value(payload):
        raise ValueError("secret-shaped value survived redaction")


__all__ = [
    "MAX_LABEL_LENGTH",
    "MAX_STRING_LENGTH",
    "assert_serialization_safe",
    "is_secret_key",
    "looks_like_secret_value",
    "sanitize_label",
    "sanitize_metadata",
    "sanitize_text",
]