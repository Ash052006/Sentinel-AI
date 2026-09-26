"""YARA target adapter — event-to-bytes extraction for YARA evaluation.

YARA is content-oriented and requires **bytes** to evaluate against.
This module provides:

* :class:`YaraTarget` — a simple, explicit content wrapper for YARA
  evaluation.  Holds raw bytes and optional metadata.
* :func:`to_yara_target` — extracts file content bytes from a
  :class:`NormalizedSecurityEvent` if available.
* :func:`to_yara_target_from_bytes` — wraps raw bytes into a
  :class:`YaraTarget` directly.

Target safety
-------------

The adapter **never** reads arbitrary local filesystem paths.  File
content must already be present in the event's ``normalized_data`` dict
under one of the recognized keys (e.g. ``file_content``,
``file.content_bytes``).  A ``file.path`` field is **not** file content
and will never cause the engine to open a file.

If no applicable content is present, :func:`to_yara_target` raises
:class:`InvalidYaraTargetError` — it does not silently fabricate empty
content or return ``None``.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any

from app.schemas.normalized_event import NormalizedSecurityEvent
from app.services.detection.yara.exceptions import InvalidYaraTargetError

# Keys in normalized_data that may contain file content bytes.
# The adapter tries them in order; the first non-None value wins.
_CONTENT_KEYS: tuple[str, ...] = (
    "file_content",
    "file.content_bytes",
    "file.raw_content",
    "raw_file_content",
)


@dataclass(frozen=True)
class YaraTarget:
    """Explicit content target for YARA evaluation.

    This is the smallest safe abstraction for YARA matching: raw bytes
    that the YARA library will scan.  Optional metadata fields aid
    evidence production without requiring filesystem access.

    Attributes:
        content: Raw bytes to evaluate.  Never ``None`` or empty for
            a valid target.
        file_name: Optional file name for evidence context.  Not used
            for matching.
        file_path: Optional file path for evidence context.  **Never**
            read from the filesystem by the engine.
        origin_event_id: Optional event UUID this content originated
            from, for traceability.
    """

    content: bytes
    file_name: str | None = None
    file_path: str | None = None
    origin_event_id: Any = None
    extra: dict[str, Any] = field(default_factory=dict)


def to_yara_target_from_bytes(
    data: bytes,
    *,
    file_name: str | None = None,
    file_path: str | None = None,
    origin_event_id: Any = None,
) -> YaraTarget:
    """Wrap raw *data* bytes into a :class:`YaraTarget`.

    Raises:
        InvalidYaraTargetError: If *data* is ``None`` or empty.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise InvalidYaraTargetError(
            f"Expected bytes or bytearray, got {type(data).__name__}"
        )
    if len(data) == 0:
        raise InvalidYaraTargetError("Content bytes are empty")
    return YaraTarget(
        content=bytes(data),
        file_name=file_name,
        file_path=file_path,
        origin_event_id=origin_event_id,
    )


def to_yara_target(event: NormalizedSecurityEvent) -> YaraTarget:
    """Extract a :class:`YaraTarget` from a normalised event.

    Searches ``normalized_data`` for file content bytes under recognised
    keys.  If no content is found, raises
    :class:`InvalidYaraTargetError`.

    **Does not** read the filesystem.  Content must already be present
    in memory within the event's ``normalized_data``.
    """
    if event is None:
        raise InvalidYaraTargetError("Event must not be None")

    content: bytes | None = None
    source_key: str | None = None

    for key in _CONTENT_KEYS:
        candidate = event.normalized_data.get(key)
        if candidate is not None:
            # Handle base64-encoded content
            if isinstance(candidate, str):
                try:
                    content = base64.b64decode(candidate, validate=True)
                except Exception:
                    content = candidate.encode("utf-8")
                source_key = key
                break
            elif isinstance(candidate, (bytes, bytearray)):
                content = bytes(candidate)
                source_key = key
                break

    if content is None or len(content) == 0:
        raise InvalidYaraTargetError(
            "Event does not contain applicable file content. "
            "YARA evaluation requires explicit bytes in normalized_data "
            f"(searched keys: {', '.join(_CONTENT_KEYS)}). "
            "File paths, names, hashes, and extensions are not file content."
        )

    file_name = None
    file_path = None
    if event.file is not None:
        file_name = event.file.name
        file_path = event.file.path

    return YaraTarget(
        content=content,
        file_name=file_name,
        file_path=file_path,
        origin_event_id=event.event_id,
        extra={"source_key": source_key} if source_key else {},
    )
