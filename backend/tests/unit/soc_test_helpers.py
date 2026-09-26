"""Shared deterministic fixtures for the Natural Language SOC tests (Step 23)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict

from app.schemas.incident_memory import MemoryType
from app.schemas.risk import RiskLevel
from app.schemas.soc_query import (
    SOCExecutionMetadata,
    SOCExecutionMode,
    SOCFilters,
    SOCPagination,
    SOCQueryIntent,
    SOCQueryResponse,
    SOCQueryTarget,
    SOCResource,
)

NOW = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)


def uuid4() -> uuid.UUID:
    return uuid.UUID(int=0)


def make_intent(
    resource: SOCResource = SOCResource.DETECTIONS,
    operation: str = "recent",
    *,
    mode: SOCExecutionMode = SOCExecutionMode.RECENT_FEED,
    target: SOCQueryTarget | None = None,
    filters: SOCFilters | None = None,
    pagination: SOCPagination | None = None,
) -> SOCQueryIntent:
    return SOCQueryIntent(
        resource=resource,
        operation=operation,
        mode=mode,
        target=target or SOCQueryTarget(),
        filters=filters or SOCFilters(),
        pagination=pagination or SOCPagination(),
    )


def make_response(
    *,
    intent: SOCQueryIntent | None = None,
    found: bool = True,
    count: int = 1,
    total: int | None = None,
    items: list[dict] | None = None,
    recorded_at: datetime = NOW,
) -> SOCQueryResponse:
    return SOCQueryResponse(
        intent=intent or make_intent(),
        metadata=SOCExecutionMetadata(
            resource=(intent or make_intent()).resource,
            operation=(intent or make_intent()).operation,
            mode=(intent or make_intent()).mode,
            recorded_at=recorded_at,
        ),
        read_only=True,
        found=found,
        count=count,
        total=total,
        items=items if items is not None else [{"id": "x"}],
        semantics=["detection_results"],
        note="Returned 1 recent detections.",
    )


class FakeRecord(BaseModel):
    """Minimal serializable read-model stand-in for executor tests."""

    model_config = ConfigDict(extra="forbid")

    id: str
    level: RiskLevel | None = None
    memory_type: MemoryType | None = None


class FakePage(BaseModel):
    """Minimal page stand-in mirroring the existing page contracts."""

    model_config = ConfigDict(extra="forbid")

    items: list[FakeRecord]
    total: int
    page: int = 1
    page_size: int = 50