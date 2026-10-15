"""Digital Twin domain contract tests — V3.26.

Focused contract validation covering environment/assets/snapshots/scenarios/
runs/action outcomes, strictness, safety rules, and compatibility.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.schemas.digital_twin import (
    ActionOutcome,
    AssetCategory,
    EnvironmentSnapshot,
    ScenarioDefinition,
    ScenarioStep,
    SimulatedActionOutcome,
    SimulatedAsset,
    SimulationLifecycle,
    SimulationRun,
    SimulationProvenance,
    TwinEnvironment,
)
from app.schemas.playbook import PlaybookInputs, ResolvableTarget


class TestEnvironmentAndAssets:
    def test_valid_environment_and_asset(self) -> None:
        env_id = uuid.uuid4()
        asset_id = uuid.uuid4()
        env = TwinEnvironment(
            environment_id=env_id,
            name="lab1",
            description="sim lab",
            schema_version="v1",
            simulation_only=True,
            assets=[asset_id],
        )
        assert env.provenance == SimulationProvenance.SYNTHETIC
        assert env.simulation_only is True

        asset = SimulatedAsset(
            asset_id=asset_id,
            environment_id=env_id,
            asset_category=AssetCategory.ENDPOINT,
            label="host-01",
            attributes={"os": "linux"},
        )
        assert asset.provenance == SimulationProvenance.SYNTHETIC
        assert asset.asset_id != env_id  # distinct identities

    def test_rejects_unknown_fields(self) -> None:
        with pytest.raises(ValidationError):
            TwinEnvironment(
                environment_id=uuid.uuid4(),
                name="lab",
                schema_version="v1",
                simulation_only=True,
                unknown_field="x",
            )

    def test_rejects_invalid_asset_category(self) -> None:
        with pytest.raises(ValidationError):
            SimulatedAsset(
                asset_id=uuid.uuid4(),
                environment_id=uuid.uuid4(),
                asset_category="invalid",  # type: ignore[arg-type]
                label="x",
            )

    def test_rejects_self_reference(self) -> None:
        asset_id = uuid.uuid4()
        with pytest.raises(ValidationError):
            SimulatedAsset(
                asset_id=asset_id,
                environment_id=uuid.uuid4(),
                asset_category=AssetCategory.SERVER,
                label="s",
                relationship_refs=[asset_id],
            )

    def test_rejects_duplicate_asset_ids_in_env(self) -> None:
        aid = uuid.uuid4()
        with pytest.raises(ValidationError):
            TwinEnvironment(
                environment_id=uuid.uuid4(),
                name="lab",
                schema_version="v1",
                simulation_only=True,
                assets=[aid, aid],
            )

    def test_rejects_non_simulation_only_env(self) -> None:
        with pytest.raises(ValidationError):
            TwinEnvironment(
                environment_id=uuid.uuid4(),
                name="lab",
                schema_version="v1",
                simulation_only=False,
            )


class TestSnapshot:
    def test_valid_snapshot_immutable_and_digest(self) -> None:
        snap = EnvironmentSnapshot(
            snapshot_id=uuid.uuid4(),
            environment_id=uuid.uuid4(),
            snapshot_version="v1",
            state_digest="a" * 64,
            asset_ids=[],
            relationship_refs=[],
            created_at=datetime.now(timezone.utc),
            immutable=True,
        )
        assert snap.immutable is True
        assert snap.provenance == SimulationProvenance.SYNTHETIC

    def test_rejects_bad_digest(self) -> None:
        with pytest.raises(ValidationError):
            EnvironmentSnapshot(
                snapshot_id=uuid.uuid4(),
                environment_id=uuid.uuid4(),
                snapshot_version="v1",
                state_digest="not-a-hex-digest",
                created_at=datetime.now(timezone.utc),
            )

    def test_rejects_non_immutable_snapshot(self) -> None:
        with pytest.raises(ValidationError):
            EnvironmentSnapshot(
                snapshot_id=uuid.uuid4(),
                environment_id=uuid.uuid4(),
                snapshot_version="v1",
                state_digest="b" * 64,
                created_at=datetime.now(timezone.utc),
                immutable=False,
            )


class TestScenario:
    def test_valid_scenario(self) -> None:
        step = ScenarioStep(
            step_id=uuid.uuid4(),
            step_number=1,
            name="init",
            description="init step",
            preconditions={"ready": True},
            expected_observations={"count": 1},
        )
        sc = ScenarioDefinition(
            scenario_id=uuid.uuid4(),
            scenario_version="v1",
            name="test-scenario",
            objective="verify",
            steps=[step],
            evaluation_criteria={"min_success": 1},
            deterministic_seed=123,
        )
        assert sc.provenance == SimulationProvenance.SYNTHETIC
        assert sc.steps[0].step_number == 1

    def test_rejects_duplicate_step_numbers(self) -> None:
        s1 = ScenarioStep(step_id=uuid.uuid4(), step_number=1, name="s1")
        s2 = ScenarioStep(step_id=uuid.uuid4(), step_number=1, name="s2")
        with pytest.raises(ValidationError):
            ScenarioDefinition(
                scenario_id=uuid.uuid4(),
                scenario_version="v1",
                name="sc",
                steps=[s1, s2],
            )

    def test_rejects_out_of_order_steps(self) -> None:
        s2 = ScenarioStep(step_id=uuid.uuid4(), step_number=2, name="s2")
        s1 = ScenarioStep(step_id=uuid.uuid4(), step_number=1, name="s1")
        with pytest.raises(ValidationError):
            ScenarioDefinition(
                scenario_id=uuid.uuid4(),
                scenario_version="v1",
                name="sc",
                steps=[s2, s1],  # not sorted
            )

    def test_rejects_executable_tokens_in_content(self) -> None:
        step = ScenarioStep(
            step_id=uuid.uuid4(),
            step_number=1,
            name="bad",
            preconditions={"cmd": "ls && rm -rf /"},
        )
        with pytest.raises(ValidationError):
            ScenarioDefinition(
                scenario_id=uuid.uuid4(),
                scenario_version="v1",
                name="sc",
                steps=[step],
            )


class TestSimulationRun:
    def test_valid_run_lifecycles(self) -> None:
        run = SimulationRun(
            run_id=uuid.uuid4(),
            scenario_id=uuid.uuid4(),
            scenario_version="v1",
            lifecycle=SimulationLifecycle.CREATED,
            configuration_digest="c" * 64,
        )
        assert run.provenance == SimulationProvenance.SYNTHETIC

        for lc in SimulationLifecycle:
            r = SimulationRun(
                run_id=uuid.uuid4(),
                scenario_id=uuid.uuid4(),
                scenario_version="v1",
                lifecycle=lc,
            )
            assert r.lifecycle == lc

    def test_rejects_bad_config_digest(self) -> None:
        with pytest.raises(ValidationError):
            SimulationRun(
                run_id=uuid.uuid4(),
                scenario_id=uuid.uuid4(),
                scenario_version="v1",
                configuration_digest="bad",
            )

    def test_does_not_reuse_playbook_lifecycles(self) -> None:
        # Simulation has its own enum; verify no collision in semantics
        sim_lcs = {lc.value for lc in SimulationLifecycle}
        # V3.25 playbook generated lifecycles are proposed/approval_required
        assert "proposed" not in sim_lcs
        assert "approval_required" not in sim_lcs
        assert "approved" not in sim_lcs
        assert "executed" not in sim_lcs


class TestActionOutcome:
    def test_outcomes_cover_unsupported_and_indeterminate(self) -> None:
        run_id = uuid.uuid4()
        tgt = uuid.uuid4()
        for oc in [ActionOutcome.SUCCESSFUL, ActionOutcome.FAILED, ActionOutcome.UNSUPPORTED, ActionOutcome.INDETERMINATE]:
            out = SimulatedActionOutcome(
                outcome_id=uuid.uuid4(),
                run_id=run_id,
                simulated_target_id=tgt,
                outcome=oc,
                simulated=True,
            )
            assert out.simulated is True
            assert out.provenance == SimulationProvenance.SYNTHETIC

    def test_rejects_non_simulated_outcome(self) -> None:
        with pytest.raises(ValidationError):
            SimulatedActionOutcome(
                outcome_id=uuid.uuid4(),
                run_id=uuid.uuid4(),
                simulated_target_id=uuid.uuid4(),
                outcome=ActionOutcome.FAILED,
                simulated=False,
            )

    def test_action_id_optional_and_bounded(self) -> None:
        out = SimulatedActionOutcome(
            outcome_id=uuid.uuid4(),
            run_id=uuid.uuid4(),
            simulated_target_id=uuid.uuid4(),
            outcome=ActionOutcome.UNSUPPORTED,
            action_id=None,
        )
        assert out.action_id is None


class TestCompatibility:
    def test_playbook_schemas_still_valid(self) -> None:
        # Ensure existing playbook schema classes still construct
        target = ResolvableTarget(
            target_type="ip",
            value="192.0.2.1",
            reference="detection:abc",
        )
        inputs = PlaybookInputs(
            correlation_id=uuid.uuid4(),
            graph_snapshot_digest="d" * 64,
            graph_node_count=0,
            graph_edge_count=0,
        )
        assert target.value == "192.0.2.1"
        assert inputs.graph_snapshot_digest == "d" * 64
