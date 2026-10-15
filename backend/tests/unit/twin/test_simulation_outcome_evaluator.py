from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.models.digital_twin import (
    DigitalTwinEnvironment,
    ScenarioDefinition,
    SimulatedAsset,
    SimulatedActionOutcome,
)
from app.schemas.digital_twin import ScenarioStep
from app.services.twin.simulation_outcome_evaluator import (
    EvaluationError,
    SimulationOutcomeEvaluator,
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


def test_evaluator_read_only_deterministic(db_session: Session) -> None:
    env = _make_env_with_asset(db_session)
    scen = _make_scenario(env)
    # create minimal run via orchestrator not required; build directly
    from app.models.digital_twin import SimulationRun
    from app.schemas.digital_twin import SimulationLifecycle

    run = SimulationRun(
        run_id=uuid.uuid4(),
        scenario_id=scen.scenario_id,
        scenario_version=scen.scenario_version,
        environment_id=env.environment_id,
        lifecycle=SimulationLifecycle.COMPLETED,
        provenance="synthetic",
    )
    db_session.add(run)
    db_session.commit()
    db_session.refresh(run)

    out = SimulatedActionOutcome(
        outcome_id=uuid.uuid4(),
        run_id=run.id,
        simulated_target_id=env.assets[0].asset_id,
        outcome="successful",
        preconditions={},
        verification_evidence={},
        reason="ok",
        limitations=[],
        simulated=True,
        provenance="synthetic",
    )
    db_session.add(out)
    db_session.commit()

    evalr = SimulationOutcomeEvaluator(db_session)
    res1 = evalr.evaluate(run, scen, [out])
    res2 = evalr.evaluate(run, scen, [out])
    assert res1 == res2
    assert res1["aggregate_status"] == "pass"
