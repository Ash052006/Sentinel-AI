from __future__ import annotations

from typing import Optional, Sequence

from sqlalchemy.orm import Session

from app.models.digital_twin import (
    DigitalTwinEnvironment,
    SimulatedAsset,
)

__all__ = [
    "TwinStateService",
    "EnvironmentNotFoundError",
    "AssetNotFoundError",
    "CrossEnvironmentError",
]


class EnvironmentNotFoundError(Exception):
    """Environment not found."""


class AssetNotFoundError(Exception):
    """Simulated asset not found."""


class CrossEnvironmentError(Exception):
    """Cross-environment reference or access error."""


class TwinStateService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create_environment(self, env: DigitalTwinEnvironment) -> DigitalTwinEnvironment:
        self.db.add(env)
        self.db.commit()
        self.db.refresh(env)
        return env

    def get_environment(self, env_id: str | None = None, environment_id: str | None = None) -> DigitalTwinEnvironment:
        eid = env_id or environment_id
        if not eid:
            raise EnvironmentNotFoundError("environment id required")
        env = (
            self.db.query(DigitalTwinEnvironment)
            .filter(DigitalTwinEnvironment.environment_id == eid)
            .one_or_none()
        )
        if env is None:
            raise EnvironmentNotFoundError(eid)
        return env

    def create_asset(self, asset: SimulatedAsset) -> SimulatedAsset:
        # ensure environment exists and is simulation-only
        env = self.get_environment(environment_id=str(asset.environment.environment_id)) if asset.environment else None
        if env is None:
            self.get_environment(environment_id=str(asset.environment_id))
        self.db.add(asset)
        self.db.commit()
        self.db.refresh(asset)
        return asset

    def get_asset(self, asset_id: str) -> SimulatedAsset:
        asset = (
            self.db.query(SimulatedAsset)
            .filter(SimulatedAsset.asset_id == asset_id)
            .one_or_none()
        )
        if asset is None:
            raise AssetNotFoundError(asset_id)
        return asset

    def list_assets(self, environment_id: str) -> Sequence[SimulatedAsset]:
        env = self.get_environment(environment_id=environment_id)
        return list(env.assets)

    def update_asset(self, asset: SimulatedAsset) -> SimulatedAsset:
        # ensure it belongs to a valid env
        self.db.add(asset)
        self.db.commit()
        self.db.refresh(asset)
        return asset

    def delete_asset(self, asset_id: str) -> None:
        asset = self.get_asset(asset_id)
        self.db.delete(asset)
        self.db.commit()

    @staticmethod
    def ensure_same_environment(environment_id_a: str | object, environment_id_b: str | object) -> None:
        a = str(environment_id_a)
        b = str(environment_id_b)
        if a != b:
            raise CrossEnvironmentError(f"{a} != {b}")
