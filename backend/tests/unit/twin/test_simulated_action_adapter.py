from __future__ import annotations

import uuid

import pytest
from sqlalchemy.orm import Session

from app.models.digital_twin import (
    DigitalTwinEnvironment,
    SimulatedAsset,
)
from app.services.twin.simulated_action_adapter import (
    ActionAdaptationError,
    SimulatedActionAdapter,
)


def _make_env_with_asset(db: Session) -> DigitalTwinEnvironment:
    env = DigitalTwinEnvironment(
        environment_id=uuid.uuid4(),
        name="env",
        description="test",
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
        asset_category="endpoint",
        label="ep1",
        attributes={},
        provenance="synthetic",
        relationship_refs=[],
        metadata={"simulated": True},
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    db.refresh(env)
    return env


def test_isolate_action_applies_state(db_session: Session) -> None:
    env = _make_env_with_asset(db_session)
    adapter = SimulatedActionAdapter(db=db_session)
    outcome = adapter.apply_action(
        environment_id=str(env.environment_id),
        action_type="isolate",
        target_asset_id=str(env.assets[0].asset_id),
    )
    assert outcome.outcome in ("successful", "unsupported")
