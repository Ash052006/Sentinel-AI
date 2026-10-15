from __future__ import annotations

import uuid

import pytest
from sqlalchemy.orm import Session

from app.models.digital_twin import (
    DigitalTwinEnvironment,
    SimulatedAsset,
)
from app.services.twin.snapshot_service import (
    EnvironmentStateInconsistentError,
    SnapshotService,
)


def _make_env_with_asset(db: Session, name: str = "env") -> DigitalTwinEnvironment:
    env = DigitalTwinEnvironment(
        environment_id=uuid.uuid4(),
        name=name,
        description="test env",
        schema_version="v1",
        simulation_only=True,
        provenance="synthetic",
        config={"simulated": True},
    )
    db.add(env)
    db.commit()
    db.refresh(env)
    asset = SimulatedAsset(
        asset_id=uuid.uuid4(),
        environment_id=env.id,
        environment=env,
        asset_category="endpoint",
        label="ep1",
        attributes={"ip": "10.0.0.1"},
        provenance="synthetic",
        relationship_refs=[],
        metadata={"simulated": True},
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    db.refresh(env)
    return env


def test_snapshot_deterministic_digest(db_session: Session) -> None:
    svc = SnapshotService(db_session)
    env = _make_env_with_asset(db_session)
    snap1 = svc.create_snapshot(environment_id=str(env.environment_id), snapshot_version="v1")
    snap2 = svc.create_snapshot(environment_id=str(env.environment_id), snapshot_version="v1")
    assert snap1.state_digest == snap2.state_digest
    assert svc.verify_snapshot_digest(snap1)
