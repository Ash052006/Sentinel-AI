from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.models.digital_twin import (
    DigitalTwinEnvironment,
    ScenarioDefinition,
    SimulatedAsset,
)
from app.schemas.digital_twin import ScenarioStep
from app.services.twin.simulation_orchestrator import (
    OrchestrationError,
    SimulationOrchestrator,
)
from app.schemas.digital_twin import SimulationLifecycle


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


def _make_scenario(env: DigitalTwinEnvironment) -> ScenarioDefinition:
    step = ScenarioStep(
        step_id=uuid.uuid4(),
        step_number=1,
        name="step1",
        description="test",
        preconditions={},
        expected_observations={},
        actions=[],
        termination_condition=None,
    )
    return ScenarioDefinition(
        scenario_id=uuid.uuid4(),
        scenario_version="v1",
        name="scen",
        description="test",
        objective="test",
        required_environment_id=env.environment_id,
        steps=[step],
        evaluation_criteria={},
        execution_limits={},
        deterministic_seed=42,
        provenance="synthetic",
    )


def test_orchestrator_runs_bounded(db_session: Session) -> None:
    env = _make_env_with_asset(db_session)
    scen = _make_scenario(env)
    orch = SimulationOrchestrator(db=db_session)
    run = orch.run_scenario(scenario=scen, environment_id=str(env.environment_id), deterministic_seed=42)
    assert run.lifecycle == SimulationLifecycle.COMPLETED
