from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional

from sqlalchemy.orm import Session

from app.models.digital_twin import (
    ScenarioDefinition,
    SimulationRun,
    SimulatedActionOutcome,
)

__all__ = [
    "SimulationOutcomeEvaluator",
    "EvaluationError",
]


class EvaluationError(Exception):
    """Evaluation error."""


class SimulationOutcomeEvaluator:
    def __init__(self, db: Session) -> None:
        self.db = db

    def evaluate(
        self,
        run: SimulationRun,
        scenario: ScenarioDefinition,
        action_outcomes: Optional[List[SimulatedActionOutcome]] = None,
    ) -> Mapping[str, Any]:
        results: List[Dict[str, Any]] = []
        evidence_refs: List[Dict[str, Any]] = []

        outcomes = action_outcomes or []
        for out in sorted(outcomes, key=lambda o: str(o.outcome_id)):
            evidence_refs.append(
                {
                    "run_id": str(run.run_id),
                    "outcome_id": str(out.outcome_id),
                    "simulated_target_id": str(out.simulated_target_id),
                }
            )
            results.append(
                {
                    "criterion": f"action_{out.action_id or 'unknown'}",
                    "status": "pass" if out.outcome == "successful" else ("indeterminate" if out.outcome == "indeterminate" else ("indeterminate" if out.outcome == "unsupported" else "fail")),
                    "evidence": [str(out.outcome_id)],
                    "explanation": out.reason or "",
                }
            )

        aggregate = "pass"
        if any(r["status"] == "fail" for r in results):
            aggregate = "fail"
        elif any(r["status"] == "indeterminate" for r in results):
            aggregate = "indeterminate"

        return {
            "run_id": str(run.run_id),
            "scenario_id": str(scenario.scenario_id),
            "aggregate_status": aggregate,
            "criteria": results,
            "evidence_refs": evidence_refs,
            "read_only": True,
            "deterministic": True,
        }
