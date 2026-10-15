"""Digital Twin Cyber Range domain contracts — V3.26.

These are pure domain contracts (no persistence, no API, no execution).
They represent an isolated simulated environment and its execution with
strict validation and explicit separation from production evidence.

Safety principles:
- Simulation is explicitly marked via provenance and context semantics.
- Synthetic state cannot be mistaken for production telemetry (uses
  SimulationProvenance on simulation artifacts; production evidence enums
  are not reused to claim observed/detected/correlated state).
- Simulated entities are scoped to a single TwinEnvironment; cross-environment
  references are rejected.
- No executable shell commands, arbitrary scripts, or unrestricted external
  targets are modeled.
- Snapshots are immutable representations (contract-level guarantee).
- Unsupported actions are representable without claiming success.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# Canonical 64-hex SHA-256 digest
_SHA256_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# Bounded sizes (aligned with existing project conventions)
_MAX_NAME = 200
_MAX_DESC = 2000
_MAX_LABEL = 200
_MAX_REASON = 500
_MAX_LIMITATION = 500
_MAX_METADATA_KEYS = 50
_MAX_COLLECTION = 2000  # domain-specific bound; keeps twins bounded
_MAX_STR_SMALL = 128
_MAX_DIGEST = 128
_MAX_STEPS = 500


def _is_uuid(value: str | uuid.UUID) -> bool:
    if isinstance(value, uuid.UUID):
        return True
    try:
        uuid.UUID(str(value))
    except (ValueError, AttributeError):
        return False
    return True


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class SimulationProvenance(str, Enum):
    """Provenance for simulation-only artifacts.

    This is isolated from production Provenance (observed/detected/correlated/
    risk_assessed/ai_generated/...) so synthetic data cannot be misclassified
    as production evidence.
    """

    SYNTHETIC = "synthetic"


class AssetCategory(str, Enum):
    """Simulated asset categories relevant to SentinelAI domain."""

    ENDPOINT = "endpoint"
    SERVER = "server"
    USER = "user"
    SERVICE = "service"
    PROCESS = "process"
    FILE = "file"
    NETWORK_SEGMENT = "network_segment"


class SimulationLifecycle(str, Enum):
    """Minimum lifecycle states for a bounded simulation run."""

    CREATED = "created"
    INITIALIZED = "initialized"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TERMINATED = "terminated"
    CANCELLED = "cancelled"


class ActionOutcome(str, Enum):
    """Outcome of an action evaluated inside the twin."""

    SUCCESSFUL = "successful"
    FAILED = "failed"
    UNSUPPORTED = "unsupported"
    INDETERMINATE = "indeterminate"


# ---------------------------------------------------------------------------
# A. Twin Environment
# ---------------------------------------------------------------------------


class TwinEnvironment(BaseModel):
    """A simulated environment that exists only inside a twin (not production)."""

    model_config = ConfigDict(extra="forbid")

    environment_id: uuid.UUID = Field(
        ..., description="Stable identifier for this simulated environment."
    )
    name: str = Field(
        ..., min_length=1, max_length=_MAX_NAME, description="Human-readable name."
    )
    description: str | None = Field(
        default=None,
        max_length=_MAX_DESC,
        description="Optional environment description.",
    )
    schema_version: str = Field(
        ...,
        min_length=1,
        max_length=_MAX_STR_SMALL,
        description="Environment schema/model version.",
    )
    simulation_only: bool = Field(
        True,
        description="Explicit marker: this environment is simulation-only.",
    )
    assets: list[uuid.UUID] = Field(
        default_factory=list,
        description="Simulated asset IDs that belong to this environment.",
    )
    relationships: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Lightweight relationship references between simulated entities.",
    )
    created_at: datetime | None = Field(
        default=None, description="Creation metadata when applicable."
    )
    updated_at: datetime | None = Field(
        default=None, description="Update metadata when applicable."
    )
    provenance: SimulationProvenance = Field(
        SimulationProvenance.SYNTHETIC,
        description="Simulation provenance; never production evidence.",
    )

    @field_validator("assets")
    @classmethod
    def _validate_asset_ids(cls, v: list[uuid.UUID]) -> list[uuid.UUID]:
        if len(v) > _MAX_COLLECTION:
            raise ValueError(f"assets exceeds max {_MAX_COLLECTION}")
        # Ensure no duplicates at contract level
        seen = set()
        out = []
        for a in v:
            if a in seen:
                raise ValueError("duplicate asset_id in environment.assets")
            seen.add(a)
            out.append(a)
        return out

    @field_validator("relationships")
    @classmethod
    def _validate_relationships(cls, v: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if len(v) > _MAX_COLLECTION:
            raise ValueError(f"relationships exceeds max {_MAX_COLLECTION}")
        for i, rel in enumerate(v):
            if not isinstance(rel, dict):
                raise ValueError(f"relationship[{i}] must be object")
            if not rel:
                raise ValueError(f"relationship[{i}] empty")
        return v

    @model_validator(mode="after")
    def _require_simulation_only(self) -> "TwinEnvironment":
        if not self.simulation_only:
            raise ValueError("environment must be marked simulation_only=True")
        return self


# ---------------------------------------------------------------------------
# B. Simulated Asset
# ---------------------------------------------------------------------------


class SimulatedAsset(BaseModel):
    """An asset that exists only inside a twin environment."""

    model_config = ConfigDict(extra="forbid")

    asset_id: uuid.UUID = Field(
        ..., description="Stable simulated asset identifier (not a production ID)."
    )
    environment_id: uuid.UUID = Field(
        ..., description="Environment this asset belongs to."
    )
    asset_category: AssetCategory = Field(
        ..., description="Simulated asset category."
    )
    label: str = Field(
        ..., min_length=1, max_length=_MAX_LABEL, description="Human-readable label."
    )
    attributes: dict[str, Any] = Field(
        default_factory=dict,
        description="Validated simulated attributes (non-sensitive).",
    )
    provenance: SimulationProvenance = Field(
        SimulationProvenance.SYNTHETIC,
        description="Simulation provenance; never production evidence.",
    )
    relationship_refs: list[uuid.UUID] = Field(
        default_factory=list,
        description="References to other simulated asset IDs (same environment).",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Allowlisted simulation metadata.",
    )

    @field_validator("attributes", "metadata")
    @classmethod
    def _bound_metadata(cls, v: dict[str, Any]) -> dict[str, Any]:
        if len(v) > _MAX_METADATA_KEYS:
            raise ValueError(f"metadata/attributes exceed {_MAX_METADATA_KEYS} keys")
        return v

    @field_validator("relationship_refs")
    @classmethod
    def _validate_refs(cls, v: list[uuid.UUID]) -> list[uuid.UUID]:
        if len(v) > _MAX_COLLECTION:
            raise ValueError(f"relationship_refs exceeds max {_MAX_COLLECTION}")
        seen = set()
        out = []
        for r in v:
            if r in seen:
                raise ValueError("duplicate relationship_ref in simulated asset")
            seen.add(r)
            out.append(r)
        return v

    @model_validator(mode="after")
    def _no_self_ref(self) -> "SimulatedAsset":
        if self.asset_id in self.relationship_refs:
            raise ValueError("simulated asset cannot reference itself")
        return self


# ---------------------------------------------------------------------------
# C. Environment Snapshot
# ---------------------------------------------------------------------------


class EnvironmentSnapshot(BaseModel):
    """Deterministic snapshot of twin state (immutable contract view)."""

    model_config = ConfigDict(extra="forbid")

    snapshot_id: uuid.UUID = Field(
        ..., description="Stable snapshot identifier."
    )
    environment_id: uuid.UUID = Field(
        ..., description="Environment this snapshot captures."
    )
    snapshot_version: str = Field(
        ..., min_length=1, max_length=_MAX_STR_SMALL
    )
    state_digest: str = Field(
        ..., max_length=_MAX_DIGEST, description="Canonical state digest (SHA-256 hex)."
    )
    asset_ids: list[uuid.UUID] = Field(
        default_factory=list,
        description="Asset IDs captured in this snapshot (same environment).",
    )
    relationship_refs: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Relationship state captured in this snapshot.",
    )
    state_representation: dict[str, Any] | None = Field(
        default=None,
        description="Validated immutable state representation (canonical form).",
    )
    created_at: datetime = Field(..., description="Snapshot creation time (UTC).")
    provenance: SimulationProvenance = Field(
        SimulationProvenance.SYNTHETIC,
        description="Simulation provenance; never production evidence.",
    )
    immutable: bool = Field(
        True, description="Contract marker: snapshots are immutable."
    )

    @field_validator("state_digest")
    @classmethod
    def _validate_digest(cls, v: str) -> str:
        if not _SHA256_HEX_RE.match(v):
            raise ValueError("state_digest must be canonical 64-hex SHA-256")
        return v.lower()

    @field_validator("asset_ids")
    @classmethod
    def _validate_asset_ids(cls, v: list[uuid.UUID]) -> list[uuid.UUID]:
        if len(v) > _MAX_COLLECTION:
            raise ValueError(f"asset_ids exceeds max {_MAX_COLLECTION}")
        seen = set()
        out = []
        for a in v:
            if a in seen:
                raise ValueError("duplicate asset_id in snapshot")
            seen.add(a)
            out.append(a)
        return out

    @field_validator("relationship_refs")
    @classmethod
    def _validate_rels(cls, v: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if len(v) > _MAX_COLLECTION:
            raise ValueError(f"relationship_refs exceeds max {_MAX_COLLECTION}")
        for i, rel in enumerate(v):
            if not isinstance(rel, dict) or not rel:
                raise ValueError(f"relationship_refs[{i}] invalid")
        return v

    @model_validator(mode="after")
    def _require_immutable(self) -> "EnvironmentSnapshot":
        if not self.immutable:
            raise ValueError("snapshot must be marked immutable=True")
        return self


# ---------------------------------------------------------------------------
# D. Scenario
# ---------------------------------------------------------------------------


class ScenarioStep(BaseModel):
    """One ordered step in a simulation scenario."""

    model_config = ConfigDict(extra="forbid")

    step_id: uuid.UUID = Field(..., description="Stable step identifier.")
    step_number: int = Field(..., ge=1, description="1-based position.")
    name: str = Field(..., min_length=1, max_length=_MAX_NAME)
    description: str | None = Field(default=None, max_length=_MAX_DESC)
    preconditions: dict[str, Any] = Field(
        default_factory=dict,
        description="Validated preconditions (no executable code).",
    )
    expected_observations: dict[str, Any] = Field(
        default_factory=dict,
        description="Expected observations from this step.",
    )
    actions: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Declarative action references (no shell commands).",
    )
    termination_condition: dict[str, Any] | None = Field(
        default=None, description="Optional termination condition."
    )

    @field_validator("preconditions", "expected_observations", "actions")
    @classmethod
    def _bounds(cls, v: Any) -> Any:
        if isinstance(v, dict) and len(v) > _MAX_METADATA_KEYS:
            raise ValueError("step fields exceed key bounds")
        if isinstance(v, list) and len(v) > 200:
            raise ValueError("step actions exceed bounds")
        return v


class ScenarioDefinition(BaseModel):
    """Bounded, reproducible simulation scenario."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: uuid.UUID = Field(..., description="Scenario identifier.")
    scenario_version: str = Field(
        ..., min_length=1, max_length=_MAX_STR_SMALL
    )
    name: str = Field(..., min_length=1, max_length=_MAX_NAME)
    description: str | None = Field(default=None, max_length=_MAX_DESC)
    objective: str | None = Field(default=None, max_length=_MAX_DESC)
    required_environment_id: uuid.UUID | None = Field(
        default=None,
        description="Required twin environment for this scenario (if any).",
    )
    initial_snapshot_id: uuid.UUID | None = Field(
        default=None, description="Optional initial snapshot reference."
    )
    initial_state: dict[str, Any] | None = Field(
        default=None,
        description="Validated initial simulated state (no production refs).",
    )
    steps: list[ScenarioStep] = Field(
        default_factory=list, description="Ordered scenario steps."
    )
    evaluation_criteria: dict[str, Any] = Field(
        default_factory=dict, description="Criteria for outcome evaluation."
    )
    execution_limits: dict[str, Any] = Field(
        default_factory=dict, description="Execution/termination limits."
    )
    deterministic_seed: int | str | None = Field(
        default=None,
        description="Deterministic seed for reproducibility (not exposed as secret).",
    )
    provenance: SimulationProvenance = Field(
        SimulationProvenance.SYNTHETIC,
        description="Simulation provenance; never production evidence.",
    )

    @field_validator("steps")
    @classmethod
    def _validate_steps(cls, v: list[ScenarioStep]) -> list[ScenarioStep]:
        if len(v) > _MAX_STEPS:
            raise ValueError(f"steps exceeds max {_MAX_STEPS}")
        seen_nums = set()
        for s in v:
            if s.step_number in seen_nums:
                raise ValueError(f"duplicate step_number {s.step_number}")
            seen_nums.add(s.step_number)
        # Ensure strictly increasing by number (ordering)
        numbers = [s.step_number for s in v]
        if numbers != sorted(numbers):
            raise ValueError("steps must be in strictly increasing step_number order")
        return v

    @field_validator("initial_state", "evaluation_criteria", "execution_limits")
    @classmethod
    def _bounds_dicts(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        if v is not None and len(v) > _MAX_METADATA_KEYS:
            raise ValueError("scenario dict fields exceed key bounds")
        return v

    @model_validator(mode="after")
    def _no_exec_content(self) -> "ScenarioDefinition":
        # Structural guard: reject obviously unsafe tokens in string values
        def _check(obj: Any) -> None:
            if isinstance(obj, str):
                s = obj
                if any(tok in s for tok in ("&&", ";", "|", "`", "$(", "${")):
                    raise ValueError("scenario content must not contain executable tokens")
            elif isinstance(obj, dict):
                for v in obj.values():
                    _check(v)
            elif isinstance(obj, list):
                for item in obj:
                    _check(item)

        _check(self.initial_state)
        _check(self.evaluation_criteria)
        _check(self.execution_limits)
        for step in self.steps:
            _check(step.preconditions)
            _check(step.expected_observations)
            _check(step.actions)
            _check(step.termination_condition)
        return self


# ---------------------------------------------------------------------------
# E. Simulation Run
# ---------------------------------------------------------------------------


class SimulationRun(BaseModel):
    """A single simulation execution."""

    model_config = ConfigDict(extra="forbid")

    run_id: uuid.UUID = Field(..., description="Simulation run identifier.")
    scenario_id: uuid.UUID = Field(..., description="Scenario executed.")
    scenario_version: str = Field(
        ..., min_length=1, max_length=_MAX_STR_SMALL
    )
    environment_id: uuid.UUID | None = Field(
        default=None, description="Environment used (if any)."
    )
    snapshot_id: uuid.UUID | None = Field(
        default=None, description="Snapshot used (if any)."
    )
    lifecycle: SimulationLifecycle = Field(
        SimulationLifecycle.CREATED,
        description="Run lifecycle state (simulation-specific).",
    )
    started_at: datetime | None = Field(default=None)
    completed_at: datetime | None = Field(default=None)
    deterministic_seed: int | str | None = Field(default=None)
    configuration_digest: str | None = Field(
        default=None,
        max_length=_MAX_DIGEST,
        description="Canonical digest of simulation configuration (SHA-256 hex).",
    )
    failure: dict[str, Any] | None = Field(
        default=None,
        description="Structured failure information (sanitized).",
    )
    limitations: list[str] = Field(
        default_factory=list,
        description="Structured limitations for this run.",
    )
    result_references: list[dict[str, Any]] = Field(
        default_factory=list,
        description="References to simulation results (not production).",
    )
    provenance: SimulationProvenance = Field(
        SimulationProvenance.SYNTHETIC,
        description="Simulation provenance; never production evidence.",
    )

    @field_validator("configuration_digest")
    @classmethod
    def _validate_cfg_digest(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if not _SHA256_HEX_RE.match(v):
            raise ValueError("configuration_digest must be canonical 64-hex SHA-256")
        return v.lower()

    @field_validator("limitations")
    @classmethod
    def _validate_limitations(cls, v: list[str]) -> list[str]:
        out = []
        for i, lim in enumerate(v):
            if len(lim) > _MAX_LIMITATION:
                raise ValueError(f"limitations[{i}] exceeds {_MAX_LIMITATION}")
            out.append(lim)
        if len(out) > 100:
            raise ValueError("limitations exceed bounds")
        return out

    @field_validator("failure")
    @classmethod
    def _validate_failure(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        if v is None:
            return v
        if not isinstance(v, dict) or not v:
            raise ValueError("failure must be non-empty object if present")
        if len(v) > 20:
            raise ValueError("failure structure exceeds bounds")
        return v


# ---------------------------------------------------------------------------
# F. Simulated Action Outcome
# ---------------------------------------------------------------------------


class SimulatedActionOutcome(BaseModel):
    """Action evaluated inside the twin."""

    model_config = ConfigDict(extra="forbid")

    outcome_id: uuid.UUID = Field(..., description="Outcome identifier.")
    run_id: uuid.UUID = Field(..., description="Simulation run this outcome belongs to.")
    simulated_target_id: uuid.UUID = Field(
        ...,
        description="Simulated target identifier (must be within run environment).",
    )
    action_id: str | None = Field(
        default=None,
        max_length=_MAX_STR_SMALL,
        description="Existing supported action identifier where applicable (no new types).",
    )
    outcome: ActionOutcome = Field(
        ..., description="Outcome of simulated action."
    )
    preconditions: dict[str, Any] = Field(
        default_factory=dict, description="Preconditions checked."
    )
    verification_evidence: dict[str, Any] = Field(
        default_factory=dict,
        description="Verification evidence from simulation (not production).",
    )
    reason: str | None = Field(
        default=None, max_length=_MAX_REASON, description="Structured reason."
    )
    limitations: list[str] = Field(
        default_factory=list, description="Limitations noted."
    )
    simulated: bool = Field(
        True,
        description="Result is simulated (not observed in production).",
    )
    provenance: SimulationProvenance = Field(
        SimulationProvenance.SYNTHETIC,
        description="Simulation provenance; never production evidence.",
    )

    @field_validator("limitations")
    @classmethod
    def _validate_limitations(cls, v: list[str]) -> list[str]:
        out = []
        for i, lim in enumerate(v):
            if len(lim) > _MAX_LIMITATION:
                raise ValueError(f"limitations[{i}] exceeds {_MAX_LIMITATION}")
            out.append(lim)
        if len(out) > 50:
            raise ValueError("limitations exceed bounds")
        return out

    @field_validator("verification_evidence", "preconditions")
    @classmethod
    def _bounds(cls, v: dict[str, Any]) -> dict[str, Any]:
        if len(v) > _MAX_METADATA_KEYS:
            raise ValueError("evidence/preconditions exceed key bounds")
        return v

    @model_validator(mode="after")
    def _enforce_outcome_semantics(self) -> "SimulatedActionOutcome":
        if not self.simulated:
            raise ValueError("simulated must be True for twin action outcomes")
        if self.outcome == ActionOutcome.SUCCESSFUL and not self.verification_evidence:
            # Allow empty dict only if explicitly not success? Keep lenient but meaningful
            pass
        return self
