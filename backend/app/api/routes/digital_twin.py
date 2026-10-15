from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api import dependencies
from app.services.twin import (
    SimulationOrchestrator,
    SimulationOutcomeEvaluator,
    SnapshotService,
    SyntheticEventGenerator,
    TwinStateService,
)

router = APIRouter()


@router.get("/health")
def digital_twin_health() -> Dict[str, Any]:
    return {"status": "ok", "module": "digital_twin"}
