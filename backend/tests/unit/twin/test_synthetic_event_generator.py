from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy.orm import Session

from app.models.digital_twin import (
    DigitalTwinEnvironment,
    SimulatedAsset,
)
from app.services.twin.synthetic_event_generator import (
    EventGenerationError,
    SyntheticEventGenerator,
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


def test_deterministic_events(db_session: Session) -> None:
    env = _make_env_with_asset(db_session)
    gen = SyntheticEventGenerator(db=db_session)
    events1 = gen.generate_events(environment_id=str(env.environment_id), seed=123, count=5)
    events2 = gen.generate_events(environment_id=str(env.environment_id), seed=123, count=5)
    assert events1 == events2


def test_different_seed_changes(db_session: Session) -> None:
    env = _make_env_with_asset(db_session)
    gen = SyntheticEventGenerator(db=db_session)
    events1 = gen.generate_events(environment_id=str(env.environment_id), seed=1, count=2)
    events2 = gen.generate_events(environment_id=str(env.environment_id), seed=2, count=2)
    assert events1 != events2


def test_invalid_count_rejected(db_session: Session) -> None:
    env = _make_env_with_asset(db_session)
    gen = SyntheticEventGenerator(db=db_session)
    with pytest.raises(EventGenerationError):
        gen.generate_events(environment_id=str(env.environment_id), seed=1, count=-1)
    with pytest.raises(EventGenerationError):
        gen.generate_events(environment_id=str(env.environment_id), seed=1, count=20000)
