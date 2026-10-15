from __future__ import annotations

from typing import Any, Mapping, Optional, Sequence

from sqlalchemy.orm import Session

from app.models.digital_twin import (
    ScenarioDefinition,
    SimulationRun,
)
from app.schemas.digital_twin import SimulationLifecycle

from .simulated_action_adapter import SimulatedActionAdapter
from .snapshot_service import SnapshotService
from .synthetic_event_generator import SyntheticEventGenerator
from .twin_state_service import TwinStateService

__all__ = [
    "SimulationOrchestrator",
    "OrchestrationError",
]


class OrchestrationError(Exception):
    """Simulation orchestration error."""


class SimulationOrchestrator:
    def __init__(
        self,
        db: Session,
        twin_state: Optional[TwinStateService] = None,
        snapshot_service: Optional[SnapshotService] = None,
        event_generator: Optional[SyntheticEventGenerator] = None,
        action_adapter: Optional[SimulatedActionAdapter] = None,
        max_steps: int = 100,
        max_events_total: int = 1000,
    ) -> None:
        self.db = db
        self.twin_state = twin_state or TwinStateService(db)
        self.snapshot_service = snapshot_service or SnapshotService(db)
        self.event_generator = event_generator or SyntheticEventGenerator(db=db)
        self.action_adapter = action_adapter or SimulatedActionAdapter(db=db)
        self.max_steps = max(1, min(max_steps, 500))
        self.max_events_total = max(1, min(max_events_total, 5000))

    def run_scenario(
        self,
        scenario: ScenarioDefinition,
        environment_id: str,
        run_id: Optional[str] = None,
        snapshot_id: Optional[str] = None,
        deterministic_seed: Optional[Any] = None,
    ) -> SimulationRun:
        env = self.twin_state.get_environment(environment_id=environment_id)
        if not env.simulation_only:
            raise OrchestrationError("environment not simulation-only")
        if env.provenance != "synthetic":
            raise OrchestrationError("environment not synthetic provenance")

        if snapshot_id:
            snap = self.snapshot_service.get_snapshot(snapshot_id)
            if str(snap.environment_id) != str(env.id):
                raise OrchestrationError("snapshot environment mismatch")

        steps = list(scenario.steps)
        if len(steps) > self.max_steps:
            raise OrchestrationError("too many steps")

        import uuid

        run = SimulationRun(
            run_id=uuid.UUID(run_id) if run_id else uuid.uuid4(),
            scenario_id=scenario.scenario_id,
            scenario_version=scenario.scenario_version,
            environment_id=env.environment_id,
            snapshot_id=uuid.UUID(snapshot_id) if snapshot_id else None,
            lifecycle=SimulationLifecycle.CREATED,
            deterministic_seed=deterministic_seed if deterministic_seed is not None else scenario.deterministic_seed,
            provenance="synthetic",
            limitations=[],
            result_references=[],
        )
        self.db.add(run)
        self.db.commit()
        self.db.refresh(run)

        try:
            run.lifecycle = SimulationLifecycle.RUNNING
            self.db.add(run)
            self.db.commit()

            events_total = 0
            for i, step in enumerate(steps):
                if events_total > self.max_events_total:
                    raise OrchestrationError("event limit exceeded")
                # generate events if actions specify
                for action in step.actions or []:
                    if isinstance(action, dict) and action.get("generate_events"):
                        cnt = int(action.get("count", 1))
                        events_total += cnt
                        if events_total > self.max_events_total:
                            raise OrchestrationError("event limit exceeded")
                        self.event_generator.generate_events(
                            environment_id=environment_id,
                            seed=int(run.deterministic_seed) if isinstance(run.deterministic_seed, (int, str)) and str(run.deterministic_seed).lstrip("-").isdigit() else hash(str(run.deterministic_seed)) & 0x7FFFFFFF,
                            count=cnt,
                        )
                    if isinstance(action, dict) and action.get("apply_action"):
                        self.action_adapter.apply_action(
                            environment_id=environment_id,
                            run_id=str(run.run_id),
                            action_type=action.get("action_type", "unsupported"),
                            target_asset_id=action.get("target_asset_id"),
                        )
            run.lifecycle = SimulationLifecycle.COMPLETED
            self.db.add(run)
            self.db.commit()
            self.db.refresh(run)
        except Exception:
            run.lifecycle = SimulationLifecycle.FAILED
            self.db.add(run)
            self.db.commit()
            raise

        return run
