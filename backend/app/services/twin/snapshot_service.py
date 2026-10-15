from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence

from sqlalchemy.orm import Session

from app.models.digital_twin import (
    DigitalTwinEnvironment,
    EnvironmentSnapshot,
    SimulatedAsset,
)

from .twin_state_service import (
    CrossEnvironmentError,
    EnvironmentNotFoundError,
    TwinStateService,
)

__all__ = [
    "SnapshotService",
    "EnvironmentStateInconsistentError",
    "SnapshotDigestMismatchError",
    "SnapshotImmutabilityError",
]


class EnvironmentStateInconsistentError(Exception):
    """Environment state inconsistent for snapshot."""


class SnapshotDigestMismatchError(Exception):
    """Snapshot digest verification failed."""


class SnapshotImmutabilityError(Exception):
    """Snapshot is immutable."""


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class SnapshotService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.twin_state = TwinStateService(db)

    def _canonicalize_environment_state(self, env: DigitalTwinEnvironment) -> Mapping[str, Any]:
        assets = sorted(env.assets, key=lambda a: (str(a.asset_id), str(a.environment_id)))
        asset_ids = []
        assets_repr = []
        for a in assets:
            aid = str(a.asset_id)
            asset_ids.append(aid)
            assets_repr.append(
                {
                    "asset_id": aid,
                    "environment_id": str(a.environment_id),
                    "asset_category": a.asset_category,
                    "label": a.label,
                    "attributes": a.attributes,
                    "provenance": a.provenance,
                    "relationship_refs": sorted([str(r) for r in (a.relationship_refs or [])]),
                    "metadata": a.metadata,
                }
            )
        rel_refs = sorted([str(r) for r in (env.relationship_refs or [])]) if hasattr(env, "relationship_refs") else []
        state = {
            "environment_id": str(env.environment_id),
            "environment_name": env.name,
            "schema_version": env.schema_version,
            "simulation_only": bool(env.simulation_only),
            "provenance": env.provenance,
            "asset_ids": asset_ids,
            "assets": assets_repr,
            "relationship_refs": rel_refs,
            "config": env.config,
        }
        return state

    def compute_digest(self, state: Mapping[str, Any]) -> str:
        canonical = _canonical_json(state)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest().lower()

    def create_snapshot(self, environment_id: str, snapshot_id: str | None = None, snapshot_version: str = "v1") -> EnvironmentSnapshot:
        env = self.twin_state.get_environment(environment_id=environment_id)
        # capture state in transaction
        state = self._canonicalize_environment_state(env)
        digest = self.compute_digest(state)
        snap = EnvironmentSnapshot(
            snapshot_id=snapshot_id if snapshot_id else env.environment_id,
            environment_id=env.id,
            snapshot_version=snapshot_version,
            state_digest=digest,
            asset_ids=state["asset_ids"],
            relationship_refs=state["relationship_refs"],
            state_representation=state,
            immutable=True,
            provenance="synthetic",
        )
        self.db.add(snap)
        self.db.commit()
        self.db.refresh(snap)
        # verify digest
        if snap.state_digest != digest:
            raise SnapshotDigestMismatchError("stored digest mismatch")
        return snap

    def get_snapshot(self, snapshot_id: str) -> EnvironmentSnapshot:
        snap = (
            self.db.query(EnvironmentSnapshot)
            .filter(EnvironmentSnapshot.snapshot_id == snapshot_id)
            .one_or_none()
        )
        if snap is None:
            raise EnvironmentNotFoundError(snapshot_id)
        return snap

    def verify_snapshot_digest(self, snap: EnvironmentSnapshot) -> bool:
        state = snap.state_representation
        if not state:
            # reconstruct from env if needed - but prefer stored
            return False
        digest = self.compute_digest(state)
        return digest == (snap.state_digest or "").lower()
