from __future__ import annotations

from typing import Any, Mapping, Optional

from sqlalchemy.orm import Session

from app.models.digital_twin import (
    SimulatedActionOutcome,
    SimulatedAsset,
)
from app.schemas.digital_twin import ActionOutcome

from .twin_state_service import (
    CrossEnvironmentError,
    EnvironmentNotFoundError,
    TwinStateService,
)

__all__ = [
    "SimulatedActionAdapter",
    "ActionAdaptationError",
]


class ActionAdaptationError(Exception):
    """Error adapting or applying simulated action."""


class SimulatedActionAdapter:
    def __init__(self, db: Session, twin_state: Optional[TwinStateService] = None) -> None:
        self.db = db
        self.twin_state = twin_state or TwinStateService(db)

    def apply_action(
        self,
        environment_id: str,
        run_id: Optional[str] = None,
        action_id: Optional[str] = None,
        action_type: str = "isolate",
        target_asset_id: Optional[str] = None,
        parameters: Optional[Mapping[str, Any]] = None,
    ) -> SimulatedActionOutcome:
        env = self.twin_state.get_environment(environment_id=environment_id)
        asset: Optional[SimulatedAsset] = None
        if target_asset_id:
            asset = self.twin_state.get_asset(target_asset_id)
            if str(asset.environment_id) != str(env.id):
                raise CrossEnvironmentError("asset environment mismatch")

        if action_type == "isolate" and asset is not None:
            attrs = dict(asset.attributes or {})
            attrs["isolated"] = True
            attrs["isolation_reason"] = "simulated_action"
            asset.attributes = attrs
            self.db.add(asset)
            outcome = SimulatedActionOutcome(
                outcome_id=asset.asset_id,
                run_id=asset.asset_id if run_id is None else __import__("uuid").UUID(run_id) if False else asset.asset_id,
                simulated_target_id=asset.asset_id,
                action_id=action_id,
                outcome="successful",
                preconditions={"action": action_type},
                verification_evidence={"simulated": True},
                reason="simulated isolation applied",
                limitations=["simulation-only"],
                simulated=True,
                provenance="synthetic",
            )
            # fix run_id properly
            import uuid

            outcome.run_id = uuid.UUID(run_id) if run_id else asset.id
            outcome.outcome_id = uuid.uuid4()
            outcome.simulated_target_id = asset.asset_id
            self.db.add(outcome)
            self.db.commit()
            self.db.refresh(outcome)
            return outcome

        if action_type == "block" and asset is not None:
            attrs = dict(asset.attributes or {})
            attrs["blocked"] = True
            asset.attributes = attrs
            self.db.add(asset)
            import uuid

            outcome = SimulatedActionOutcome(
                outcome_id=uuid.uuid4(),
                run_id=uuid.UUID(run_id) if run_id else asset.id,
                simulated_target_id=asset.asset_id,
                action_id=action_id,
                outcome="successful",
                preconditions={"action": action_type},
                verification_evidence={"simulated": True},
                reason="simulated block applied",
                limitations=["simulation-only"],
                simulated=True,
                provenance="synthetic",
            )
            self.db.add(outcome)
            self.db.commit()
            self.db.refresh(outcome)
            return outcome

        # unsupported
        import uuid

        outcome = SimulatedActionOutcome(
            outcome_id=uuid.uuid4(),
            run_id=uuid.UUID(run_id) if run_id else (asset.id if asset else uuid.uuid4()),
            simulated_target_id=asset.asset_id if asset else uuid.uuid4(),
            action_id=action_id,
            outcome="unsupported",
            preconditions={"action": action_type},
            verification_evidence={"simulated": True},
            reason="action not supported in simulation",
            limitations=["simulation-only", "unsupported-action"],
            simulated=True,
            provenance="synthetic",
        )
        self.db.add(outcome)
        self.db.commit()
        self.db.refresh(outcome)
        return outcome
