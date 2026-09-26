"""Deterministic event-to-dict adapter for Sigma evaluation.

Converts a :class:`NormalizedSecurityEvent` into a flat dictionary
suitable for Sigma condition evaluation.

Field naming convention
-----------------------

Both standard Sigma field names (``CommandLine``, ``Image``, ``User``)
and structured dot-path names (``process.command_line``) are produced
so that rules authored against either convention can match.

When ``normalized_data`` contains a key colliding with a structured
key, the structured value wins and the collision is recorded.
``None`` fields are omitted from the evaluation dict.
"""

from __future__ import annotations

from typing import Any

from app.schemas.normalized_event import NormalizedSecurityEvent


def to_evaluation_dict(
    event: NormalizedSecurityEvent,
) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Return ``(eval_dict, collision_keys)`` for a normalised event."""
    d: dict[str, Any] = {}
    collisions: list[str] = []

    d["event_category"] = event.event_category.value
    if event.action is not None:
        d["action"] = event.action
    d["outcome"] = event.outcome.value
    d["source"] = event.source
    d["source_type"] = event.source_type.value

    _map_actor(d, event, collisions)
    _map_source_endpoint(d, event, collisions)
    _map_destination_endpoint(d, event, collisions)
    _map_process(d, event, collisions)
    _map_file(d, event, collisions)

    for key, value in event.normalized_data.items():
        if key in d:
            collisions.append(key)
        else:
            d[key] = value

    return d, tuple(collisions)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _set(
    d: dict[str, Any],
    key: str,
    value: Any,
    collisions: list[str],
) -> None:
    """Set *value* under *key* if not ``None``; record collisions."""
    if value is None:
        return
    if key in d:
        collisions.append(key)
    else:
        d[key] = value


def _map_actor(d: dict, event: NormalizedSecurityEvent, collisions: list) -> None:
    if event.actor is None:
        return
    a = event.actor
    _set(d, "User", a.username, collisions)
    _set(d, "UserSid", a.user_id, collisions)
    _set(d, "Domain", a.domain, collisions)
    _set(d, "actor.username", a.username, collisions)
    _set(d, "actor.user_id", a.user_id, collisions)
    _set(d, "actor.domain", a.domain, collisions)


def _map_source_endpoint(
    d: dict, event: NormalizedSecurityEvent, collisions: list
) -> None:
    if event.source_endpoint is None:
        return
    e = event.source_endpoint
    _set(d, "IpAddress", e.ip, collisions)
    _set(d, "SourceHostname", e.hostname, collisions)
    _set(d, "SourcePort", e.port, collisions)
    _set(d, "SourceProtocol", e.protocol, collisions)
    _set(d, "source_endpoint.ip", e.ip, collisions)
    _set(d, "source_endpoint.hostname", e.hostname, collisions)
    _set(d, "source_endpoint.port", e.port, collisions)
    _set(d, "source_endpoint.protocol", e.protocol, collisions)


def _map_destination_endpoint(
    d: dict, event: NormalizedSecurityEvent, collisions: list
) -> None:
    if event.destination_endpoint is None:
        return
    e = event.destination_endpoint
    _set(d, "DestinationAddress", e.ip, collisions)
    _set(d, "DestinationHostname", e.hostname, collisions)
    _set(d, "DestinationPort", e.port, collisions)
    _set(d, "DestinationProtocol", e.protocol, collisions)
    _set(d, "destination_endpoint.ip", e.ip, collisions)
    _set(d, "destination_endpoint.hostname", e.hostname, collisions)
    _set(d, "destination_endpoint.port", e.port, collisions)
    _set(d, "destination_endpoint.protocol", e.protocol, collisions)


def _map_process(d: dict, event: NormalizedSecurityEvent, collisions: list) -> None:
    if event.process is None:
        return
    p = event.process
    _set(d, "Image", p.executable or p.name, collisions)
    _set(d, "CommandLine", p.command_line, collisions)
    _set(d, "ProcessId", p.pid, collisions)
    _set(d, "ParentImage", p.parent_process, collisions)
    _set(d, "process.name", p.name, collisions)
    _set(d, "process.executable", p.executable, collisions)
    _set(d, "process.command_line", p.command_line, collisions)
    _set(d, "process.pid", p.pid, collisions)
    _set(d, "process.parent_process", p.parent_process, collisions)


def _map_file(d: dict, event: NormalizedSecurityEvent, collisions: list) -> None:
    if event.file is None:
        return
    f = event.file
    _set(d, "FileName", f.name, collisions)
    _set(d, "FilePath", f.path, collisions)
    _set(d, "FileExtension", f.extension, collisions)
    _set(d, "FileHash", f.hash, collisions)
    _set(d, "file.name", f.name, collisions)
    _set(d, "file.path", f.path, collisions)
    _set(d, "file.extension", f.extension, collisions)
    _set(d, "file.hash", f.hash, collisions)