from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.models.digital_twin import (
    DigitalTwinEnvironment,
    SimulatedAsset,
)
from app.services.twin.twin_state_service import (
    TwinStateService,
    CrossEnvironmentError,
)


def _make_env(db: Session, name: str = "env") -> DigitalTwinEnvironment:
    env = DigitalTwinEnvironment(
        environment_id=uuid.uuid4(),
        name=name,
        description="test",
        schema_version="v1",
        simulation_only=True,
        provenance="synthetic",
        config={"simulated": True},
    )
    db.add(env)
    db.commit()
    db.refresh(env)
    return env


def test_env_isolation_guard(db_session: Session) -> None:
    svc = TwinStateService(db_session)
    env = _make_env(db_session)
    try:
        svc.ensure_same_environment(str(env.environment_id), str(uuid.uuid4()))
    except CrossEnvironmentError:
        pass
    else:
        assert False
