"""SOAR identity hashing — deterministic identities (V2.18).

Every SOAR identity is content-derived, never random and never wall-clock
based:

* ``step_execution_id``  — UUIDv5 over the parent execution id + step number.
* ``playbook_version_id`` — UUIDv5 over playbook_id | version | source_hash.
* ``execution_id``       — UUIDv5 over the canonical idempotency content.

``source_hash`` is a SHA-256 digest of the canonical normalized playbook
definition (never of a wall-clock timestamp).
"""

from __future__ import annotations

import hashlib
import json
import uuid

from app.schemas.soar import SOAR_NAMESPACE

#: Canonical serialization kwargs — same separators as Step 24/25.
_JSON_KWARGS: dict[str, object] = {
    "sort_keys": True,
    "separators": (",", ":"),
    "default": str,
}


def canonical_json(value: object) -> str:
    """Canonical, compact JSON serialization used for identity derivation."""
    return json.dumps(value, **_JSON_KWARGS)


def sha256_digest(data: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of *data*."""
    return hashlib.sha256(data).hexdigest()


def playbook_source_hash(definition: object) -> str:
    """SHA-256 digest over the canonical normalized definition."""
    return sha256_digest(canonical_json(definition).encode("utf-8"))


def playbook_version_id(
    *,
    playbook_id: str,
    version: str,
    source_hash: str,
) -> uuid.UUID:
    """Deterministic immutable playbook-version identity."""
    return uuid.uuid5(
        SOAR_NAMESPACE,
        canonical_json(
            {
                "playbook_id": playbook_id,
                "version": version,
                "source_hash": source_hash,
            }
        ),
    )


def execution_idempotency_key(
    *,
    policy_decision_id: uuid.UUID,
    approval_id: uuid.UUID | None,
    response_id: uuid.UUID,
    playbook_id: str,
    playbook_version: str,
    target: str,
    action: str,
) -> str:
    """Content-derived SHA-256 idempotency key.

    Same governed submission always derives the same key (no randomness,
    no timestamps); an identical already-processed submission is never
    re-executed.  ``playbook_version`` is part of the content so a new
    playbook revision produces a distinct execution lineage.
    """
    canonical = canonical_json(
        {
            "policy_decision_id": str(policy_decision_id),
            "approval_id": str(approval_id) if approval_id is not None else "",
            "response_id": str(response_id),
            "playbook_id": playbook_id,
            "playbook_version": playbook_version,
            "target": target,
            "action": action,
        }
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def execution_id(
    *,
    idempotency_key: str,
) -> uuid.UUID:
    """Deterministic UUIDv5 execution id derived from the idempotency key."""
    return uuid.uuid5(SOAR_NAMESPACE, f"exec:{idempotency_key}")


def step_execution_id(
    *,
    execution_id: uuid.UUID,
    step_number: int,
) -> uuid.UUID:
    """Deterministic step-execution id within one execution."""
    return uuid.uuid5(
        SOAR_NAMESPACE,
        canonical_json(
            {
                "execution_id": str(execution_id),
                "step_number": step_number,
            }
        ),
    )


__all__ = [
    "canonical_json",
    "execution_id",
    "execution_idempotency_key",
    "playbook_source_hash",
    "playbook_version_id",
    "sha256_digest",
    "step_execution_id",
]