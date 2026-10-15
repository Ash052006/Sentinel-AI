from __future__ import annotations

import uuid

import pytest
from sqlalchemy.orm import Session

from app.models.digital_twin import (
    DigitalTwinEnvironment,
    SimulatedAsset,
)
from app.services.twin.twin_state_service import (
    AssetNotFoundError,
    CrossEnvironmentError,
    EnvironmentNotFoundError,
    TwinStateService,
)


def _make_env(db: Session, name: str = "env") -> DigitalTwinEnvironment:
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
    return env


def test_create_and_get_environment(db_session: Session) -> None:
    svc = TwinStateService(db_session)
    env = _make_env(db_session)
    got = svc.get_environment(environment_id=str(env.environment_id))
    assert got.id == env.id
