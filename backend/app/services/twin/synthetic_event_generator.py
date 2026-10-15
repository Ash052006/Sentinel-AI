from __future__ import annotations

import random
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional

from .twin_state_service import (
    CrossEnvironmentError,
    EnvironmentNotFoundError,
    TwinStateService,
)
from .snapshot_service import SnapshotService

__all__ = [
    "SyntheticEventGenerator",
    "EventGenerationError",
]


class EventGenerationError(Exception):
    """Error generating synthetic events."""


class SyntheticEventGenerator:
    def __init__(
        self,
        db: Optional[Any] = None,
        twin_state: Optional[TwinStateService] = None,
        snapshot_service: Optional[SnapshotService] = None,
        max_events: int = 100,
    ) -> None:
        self.db = db
        self.twin_state = twin_state or (TwinStateService(db) if db else None)
        self.snapshot_service = snapshot_service or (SnapshotService(db) if db else None)
        self.max_events = max(1, min(max_events, 1000))

    def generate_events(
        self,
        environment_id: str,
        seed: int,
        count: int = 10,
        scenario_time: Optional[datetime] = None,
        specification: Optional[Mapping[str, Any]] = None,
    ) -> List[Mapping[str, Any]]:
        if self.twin_state is None:
            raise EventGenerationError("db or twin_state required")
        if count < 0 or count > self.max_events:
            raise EventGenerationError("invalid event count")
        env = self.twin_state.get_environment(environment_id=environment_id)
        rng = random.Random(seed)
        base_time = scenario_time or datetime(2025, 1, 1, tzinfo=timezone.utc)
        events: List[Mapping[str, Any]] = []
        assets = sorted(env.assets, key=lambda a: str(a.asset_id))
        for i in range(count):
            asset = assets[i % len(assets)] if assets else None
            offset_sec = rng.randint(0, 60)
            event_time = base_time.replace(tzinfo=timezone.utc)
            # deterministic offset
            event_time = datetime(
                event_time.year,
                event_time.month,
                event_time.day,
                event_time.hour,
                event_time.minute,
                (event_time.second + offset_sec) % 60,
                tzinfo=timezone.utc,
            )
            event = {
                "id": f"sim-{seed}-{i}",
                "event_type": "synthetic.security.event",
                "timestamp": event_time.isoformat().replace("+00:00", "Z"),
                "provenance": "synthetic",
                "simulation_only": True,
                "environment_id": str(env.environment_id),
                "simulated_asset_id": str(asset.asset_id) if asset else None,
                "deterministic_key": (seed, i),
                "severity": rng.choice(["low", "medium", "high"]),
                "message": f"simulated event for {env.name}",
                "raw_data": {"simulated": True},
            }
            events.append(event)
        return events

    def generate_from_snapshot(
        self,
        snapshot_id: str,
        seed: int,
        count: int = 10,
        scenario_time: Optional[datetime] = None,
    ) -> List[Mapping[str, Any]]:
        if self.snapshot_service is None:
            raise EventGenerationError("snapshot service required")
        snap = self.snapshot_service.get_snapshot(snapshot_id)
        # get env via twin state
        env = self.twin_state.get_environment(environment_id=str(snap.environment_id)) if self.twin_state else None
        if env is None:
            raise EnvironmentNotFoundError(str(snap.environment_id))
        return self.generate_events(
            environment_id=str(env.environment_id),
            seed=seed,
            count=count,
            scenario_time=scenario_time,
        )
