"""SQLAlchemy persistence models for Digital Twin Cyber Range — V3.26.

These models persist simulation-only artifacts in a way that maintains
separation from production evidence. They follow the same conventions as
other models (UUID PKs, timestamp mixin, CHECK constraints, naming via Base).
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.postgres.base import Base, UUIDTimestampMixin

_NAME_LEN = 200
_DESC_LEN = 2000
_LABEL_LEN = 200
_REASON_LEN = 500
_LIMIT_LEN = 500
_DIGEST_LEN = 128
_STR_SM = 128

# Provenance: simulation-only
_SIM_PROV = "synthetic"

# Asset categories
_ASSET_CATS = ("endpoint", "server", "user", "service", "process", "file", "network_segment")

# Simulation lifecycle
_SIM_LC = (
    "created",
    "initialized",
    "running",
    "completed",
    "failed",
    "terminated",
    "cancelled",
)

# Action outcomes
_ACT_OUT = ("successful", "failed", "unsupported", "indeterminate")


class DigitalTwinEnvironment(UUIDTimestampMixin, Base):
    """Persisted twin environment (simulation-only)."""

    __tablename__ = "digital_twin_environments"

    __table_args__ = (
        Index("ix_digital_twin_env_name", "name"),
        CheckConstraint("simulation_only = true", name="env_simulation_only_true"),
        CheckConstraint(f"provenance = '{_SIM_PROV}'", name="env_prov_synthetic"),
    )

    environment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        unique=True,
        index=True,
        comment="Stable simulation environment identifier.",
    )
    name: Mapped[str] = mapped_column(String(_NAME_LEN), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    schema_version: Mapped[str] = mapped_column(String(_STR_SM), nullable=False)
    simulation_only: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    provenance: Mapped[str] = mapped_column(String(32), nullable=False, default=_SIM_PROV)
    config: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    assets: Mapped[list["SimulatedAsset"]] = relationship(
        back_populates="environment",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    snapshots: Mapped[list["EnvironmentSnapshot"]] = relationship(
        back_populates="environment",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    runs: Mapped[list["SimulationRun"]] = relationship(
        back_populates="environment",
        passive_deletes=True,
    )


class SimulatedAsset(UUIDTimestampMixin, Base):
    """Persisted simulated asset scoped to a twin environment."""

    __tablename__ = "simulated_assets"

    __table_args__ = (
        Index("ix_sim_asset_env", "environment_id"),
        Index("ix_sim_asset_category", "asset_category"),
        CheckConstraint(
            f"asset_category IN {_ASSET_CATS!r}".replace("'", ""),
            name="sim_asset_category_valid",
        ),
        CheckConstraint(f"provenance = '{_SIM_PROV}'", name="sim_asset_prov_synthetic"),
        UniqueConstraint(
            "environment_id",
            "asset_id",
            name="uq_sim_asset_env_asset",
        ),
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment="Stable simulated asset identifier (not production).",
    )
    environment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("digital_twin_environments.id", ondelete="CASCADE"),
        nullable=False,
    )
    asset_category: Mapped[str] = mapped_column(String(32), nullable=False)
    label: Mapped[str] = mapped_column(String(_LABEL_LEN), nullable=False)
    attributes: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    provenance: Mapped[str] = mapped_column(String(32), nullable=False, default=_SIM_PROV)
    relationship_refs: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
        comment="Serialized list of asset UUIDs (validated at contract/service layer).",
    )
    meta: Mapped[dict[str, Any] | None] = mapped_column("metadata", JSON, nullable=True)

    environment: Mapped[DigitalTwinEnvironment] = relationship(back_populates="assets")


class EnvironmentSnapshot(UUIDTimestampMixin, Base):
    """Immutable snapshot of twin environment state."""

    __tablename__ = "digital_twin_snapshots"

    __table_args__ = (
        Index("ix_dtsnap_env", "environment_id"),
        CheckConstraint("immutable = true", name="dtsnap_immutable_true"),
        CheckConstraint(f"provenance = '{_SIM_PROV}'", name="dtsnap_prov_synthetic"),
        UniqueConstraint(
            "environment_id",
            "snapshot_id",
            name="uq_dtsnap_env_snap",
        ),
    )

    snapshot_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
    )
    environment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("digital_twin_environments.id", ondelete="CASCADE"),
        nullable=False,
    )
    snapshot_version: Mapped[str] = mapped_column(String(_STR_SM), nullable=False)
    state_digest: Mapped[str] = mapped_column(String(_DIGEST_LEN), nullable=False)
    asset_ids: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
        comment="Serialized asset IDs in snapshot.",
    )
    relationship_refs: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
        comment="Serialized relationship refs.",
    )
    state_representation: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
        comment="Canonical immutable state representation.",
    )
    immutable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    provenance: Mapped[str] = mapped_column(String(32), nullable=False, default=_SIM_PROV)

    environment: Mapped[DigitalTwinEnvironment] = relationship(back_populates="snapshots")


class ScenarioDefinition(UUIDTimestampMixin, Base):
    """Versioned simulation scenario definition."""

    __tablename__ = "digital_twin_scenarios"

    __table_args__ = (
        Index("ix_dtscen_name_ver", "name", "scenario_version"),
        CheckConstraint(f"provenance = '{_SIM_PROV}'", name="dtscen_prov_synthetic"),
        UniqueConstraint(
            "scenario_id",
            "scenario_version",
            name="uq_dtscen_id_version",
        ),
    )

    scenario_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
    )
    scenario_version: Mapped[str] = mapped_column(String(_STR_SM), nullable=False)
    name: Mapped[str] = mapped_column(String(_NAME_LEN), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    objective: Mapped[str | None] = mapped_column(Text, nullable=True)
    required_environment_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    initial_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    initial_state: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    steps: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
        comment="Serialized scenario steps.",
    )
    evaluation_criteria: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    execution_limits: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    deterministic_seed: Mapped[str | None] = mapped_column(String(_STR_SM), nullable=True)
    provenance: Mapped[str] = mapped_column(String(32), nullable=False, default=_SIM_PROV)

    runs: Mapped[list["SimulationRun"]] = relationship(
        back_populates="scenario",
        passive_deletes=True,
    )


class SimulationRun(UUIDTimestampMixin, Base):
    """Simulation execution run record."""

    __tablename__ = "digital_twin_runs"

    __table_args__ = (
        Index("ix_dtrun_scenario", "scenario_id"),
        Index("ix_dtrun_env", "environment_id"),
        Index("ix_dtrun_snap", "snapshot_id"),
        Index("ix_dtrun_lifecycle", "lifecycle"),
        CheckConstraint(
            f"lifecycle IN {_SIM_LC!r}".replace("'", ""),
            name="dtrun_lifecycle_valid",
        ),
        CheckConstraint(f"provenance = '{_SIM_PROV}'", name="dtrun_prov_synthetic"),
        UniqueConstraint("run_id", name="uq_dtrun_run_id"),
    )

    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        unique=True,
        index=True,
    )
    scenario_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("digital_twin_scenarios.id", ondelete="CASCADE"),
        nullable=False,
    )
    scenario_version: Mapped[str] = mapped_column(String(_STR_SM), nullable=False)
    environment_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("digital_twin_environments.id", ondelete="SET NULL"),
        nullable=True,
    )
    snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("digital_twin_snapshots.id", ondelete="SET NULL"),
        nullable=True,
    )
    lifecycle: Mapped[str] = mapped_column(String(32), nullable=False, default="created")
    started_at: Mapped[Any | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Any | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deterministic_seed: Mapped[str | None] = mapped_column(String(_STR_SM), nullable=True)
    configuration_digest: Mapped[str | None] = mapped_column(String(_DIGEST_LEN), nullable=True)
    failure: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    limitations: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    result_references: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    provenance: Mapped[str] = mapped_column(String(32), nullable=False, default=_SIM_PROV)

    environment: Mapped[DigitalTwinEnvironment | None] = relationship(back_populates="runs")
    scenario: Mapped[ScenarioDefinition] = relationship(back_populates="runs")
    outcomes: Mapped[list["SimulatedActionOutcome"]] = relationship(
        back_populates="run",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class SimulatedActionOutcome(UUIDTimestampMixin, Base):
    """Outcome of a simulated action within a run."""

    __tablename__ = "digital_twin_action_outcomes"

    __table_args__ = (
        Index("ix_dtao_run", "run_id"),
        Index("ix_dtao_target", "simulated_target_id"),
        CheckConstraint(
            f"outcome IN {_ACT_OUT!r}".replace("'", ""),
            name="dtao_outcome_valid",
        ),
        CheckConstraint(f"provenance = '{_SIM_PROV}'", name="dtao_prov_synthetic"),
        CheckConstraint("simulated = true", name="dtao_simulated_true"),
        UniqueConstraint("outcome_id", name="uq_dtao_outcome_id"),
    )

    outcome_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        unique=True,
        index=True,
    )
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("digital_twin_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    simulated_target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
    )
    action_id: Mapped[str | None] = mapped_column(String(_STR_SM), nullable=True)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    preconditions: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    verification_evidence: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    reason: Mapped[str | None] = mapped_column(String(_REASON_LEN), nullable=True)
    limitations: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    simulated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    provenance: Mapped[str] = mapped_column(String(32), nullable=False, default=_SIM_PROV)

    run: Mapped[SimulationRun] = relationship(back_populates="outcomes")
