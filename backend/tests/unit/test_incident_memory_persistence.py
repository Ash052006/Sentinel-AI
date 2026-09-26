"""Step 17 incident memory persistence behavior.

Mirrors the Step 10C :mod:`test_correlation_persistence` unit suite for
the Step 16 :class:`~app.schemas.incident_memory.IncidentMemory` envelope
persisted through the Step 17 service/repository/model layers.

No live PostgreSQL server is involved.  The PostgreSQL-specific ``JSONB``
column type is rendered as JSON for SQLite by installing a ``visit_JSONB``
visitor on the SQLite type compiler; all other column types work through
SQLAlchemy's generic type system, exactly like the correlation suite.
"""

from __future__ import annotations
from pydantic import ValidationError

import copy
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.dialects.sqlite.base import SQLiteTypeCompiler
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

# Make PostgreSQL JSONB columns work on SQLite for these unit tests.
if not hasattr(SQLiteTypeCompiler, "visit_JSONB"):
    SQLiteTypeCompiler.visit_JSONB = lambda self, type_, **kw: "JSON"  # noqa: E731

from app.database.postgres.base import Base
from app.models.incident_memory import IncidentMemoryRow
from app.repositories.incident_memory import (
    IncidentMemoryRepository,
    IncidentMemoryRepositoryError,
    IncidentMemoryValidationError,
)
from app.schemas.incident_memory import (
    IncidentMemory,
    MemoryAction,
    MemoryEntity,
    MemoryFinding,
    MemoryIndicator,
    MemoryOutcome,
    MemorySource,
    MemoryTechnique,
    MemoryType,
)
from app.schemas.security_event import Provenance
from app.services.incident_memory_persistence import (
    IncidentMemoryPersistenceError,
    IncidentMemoryPersistenceSummary,
    IncidentMemoryPersistenceValidationError,
)
from app.services.incident_memory_persistence import (
    IncidentMemoryPersistenceService,
)
from app.database.postgres.base import Base as _Base  # noqa: F401 (schema guard)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

BASE_TS = datetime(2026, 9, 21, 12, 0, 0, tzinfo=timezone.utc)

def _ts(hours: float = 0.0) -> datetime:
    """Deterministic timezone-aware timestamp offset from BASE_TS."""
    return BASE_TS + timedelta(hours=hours)

def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)

@pytest.fixture()
def db_session():
    """Fresh in-memory SQLite database with the full model schema."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    SessionMaker = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = SessionMaker()
    from sqlalchemy import text

    session.execute(text("PRAGMA foreign_keys=ON"))
    try:
        yield session
    finally:
        session.close()
        engine.dispose()

# ---------------------------------------------------------------------------
# Deterministic fixture data
# ---------------------------------------------------------------------------

def _source(
    *,
    provenance: Provenance = Provenance.OBSERVED,
    hours: float = 0.0,
) -> MemorySource:
    return MemorySource(
        source_id=uuid.uuid4(),
        provenance=provenance,
        label="fixture source",
        event_id=uuid.uuid4(),
        metadata={},
    )

def _indicator(*, source_id: uuid.UUID | None = None, hours: float = 0.0) -> MemoryIndicator:
    source_ids = [source_id] if source_id is not None else []
    return MemoryIndicator(
        indicator_id=uuid.uuid4(),
        indicator_type="ipv4",
        value="198.51.100.7",
        source_ids=source_ids,
        metadata={},
    )

def _entity(*, source_id: uuid.UUID | None = None, hours: float = 0.0) -> MemoryEntity:
    source_ids = [source_id] if source_id is not None else []
    return MemoryEntity(
        entity_id=uuid.uuid4(),
        entity_type="host",
        identifier="db-01.example.internal",
        source_ids=source_ids,
        metadata={},
    )

def _technique(*, source_id: uuid.UUID | None = None, hours: float = 0.0) -> MemoryTechnique:
    source_ids = [source_id] if source_id is not None else []
    return MemoryTechnique(
        technique_id=uuid.uuid4(),
        technique_code="T1059",
        name="Command and Scripting Interpreter",
        source_ids=source_ids,
        metadata={},
    )

def _indicator_finding(*, source_id: uuid.UUID | None = None, hours: float = 0.0) -> MemoryFinding:
    source_ids = [source_id] if source_id is not None else []
    return MemoryFinding(
        finding_id=uuid.uuid4(),
        finding_type="behaviour",
        title="fixture finding",
        summary=None,
        confidence=0.8,
        source_ids=source_ids,
        metadata={},
    )

def _action(*, source_id: uuid.UUID | None = None, hours: float = 0.0) -> MemoryAction:
    source_ids = [source_id] if source_id is not None else []
    return MemoryAction(
        action_id=uuid.uuid4(),
        action_type="contain",
        description="fixture action",
        source_ids=source_ids,
        metadata={},
    )

def _outcome(*, source_id: uuid.UUID | None = None, hours: float = 0.0) -> MemoryOutcome:
    source_ids = [source_id] if source_id is not None else []
    return MemoryOutcome(
        outcome_status="contained",
        summary="fixture outcome",
        source_ids=source_ids,
        metadata={},
    )

def _memory(
    *,
    memory_id: uuid.UUID | None = None,
    memory_type: MemoryType = MemoryType.INCIDENT_SUMMARY,
    title: str | None = None,
    summary: str | None = None,
    correlation_id: uuid.UUID | None = None,
    sources: list[MemorySource] | None = None,
    indicators: list[MemoryIndicator] | None = None,
    entities: list[MemoryEntity] | None = None,
    techniques: list[MemoryTechnique] | None = None,
    findings: list[MemoryFinding] | None = None,
    actions: list[MemoryAction] | None = None,
    outcome: MemoryOutcome | None = None,
    confidence: float | None = None,
    metadata: dict | None = None,
    provenance: Provenance = Provenance.RECALLED,
    hours: float = 0.0,
) -> IncidentMemory:
    """Build a Step 16 :class:`IncidentMemory` with resolution-safe content.

    A single canonical source is created first and its ``source_id`` is
    threaded into every content item's ``source_ids`` (and the outcome's),
    so Step 16's "every content reference resolves to the memory's own
    sources" rule holds by construction.
    """
    source_list = sources or [_source()]
    canonical_source_id = source_list[0].source_id
    return IncidentMemory(
        memory_id=memory_id or uuid.uuid4(),
        memory_type=memory_type,
        title=title or "fixture incident memory",
        summary=summary,
        correlation_id=correlation_id,
        sources=source_list,
        indicators=indicators or [_indicator(source_id=canonical_source_id)],
        entities=entities or [_entity(source_id=canonical_source_id)],
        techniques=techniques or [_technique(source_id=canonical_source_id)],
        findings=findings or [_indicator_finding(source_id=canonical_source_id)],
        actions=actions or [_action(source_id=canonical_source_id)],
        outcome=outcome or _outcome(source_id=canonical_source_id),
        confidence=confidence,
        metadata=metadata or {},
        provenance=provenance,
        created_at=_ts(hours),
    )

def _persist(db: Session, memories: list[IncidentMemory]) -> IncidentMemoryPersistenceSummary:
    service = IncidentMemoryPersistenceService()
    return service.persist_memories(db, memories)

def _all(db: Session) -> list[IncidentMemoryRow]:
    return list(db.scalars(select(IncidentMemoryRow)))

def _count(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(IncidentMemoryRow)) or 0

# ---------------------------------------------------------------------------
# 1. Envelope persistence & mapping
# ---------------------------------------------------------------------------

def test_memory_persisted_with_all_attributes(db_session):
    memory = _memory()
    summary = _persist(db_session, [memory])

    assert summary.memories_created == 1
    assert summary.memory_ids == (memory.memory_id,)
    assert not summary.is_empty

    rows = _all(db_session)
    assert len(rows) == 1
    row = rows[0]
    assert row.memory_id == memory.memory_id
    assert row.memory_type == memory.memory_type.value
    assert row.title == memory.title
    assert row.correlation_id == memory.correlation_id
    assert row.confidence == memory.confidence
    assert row.provenance == Provenance.RECALLED.value

def test_content_jsonb_round_trips(db_session):
    memory = _memory()
    _persist(db_session, [memory])
    row = _all(db_session)[0]

    assert row.sources == [s.model_dump(mode="json") for s in memory.sources]
    assert row.indicators == [i.model_dump(mode="json") for i in memory.indicators]
    assert row.entities == [e.model_dump(mode="json") for e in memory.entities]
    assert row.techniques == [t.model_dump(mode="json") for t in memory.techniques]
    assert row.findings == [f.model_dump(mode="json") for f in memory.findings]
    assert row.actions == [a.model_dump(mode="json") for a in memory.actions]
    assert row.outcomes == memory.outcome.model_dump(mode="json")
    assert row.memory_metadata == memory.metadata

# ---------------------------------------------------------------------------
# 2. Idempotency
# ---------------------------------------------------------------------------

def test_repeated_persist_is_idempotent(db_session):
    memory = _memory()
    first = _persist(db_session, [memory])
    second = _persist(db_session, [memory])

    assert first.memories_created == 1
    assert second.memories_created == 0
    assert second.memories_skipped == 1
    assert _count(db_session) == 1

def test_distinct_memory_ids_create_separate_rows(db_session):
    a = _memory(hours=1.0)
    b = _memory(hours=2.0)
    _persist(db_session, [a, b])
    assert _count(db_session) == 2

# ---------------------------------------------------------------------------
# 3. Provenance & integrity guards
# ---------------------------------------------------------------------------

def test_provenance_pinned_to_recalled(db_session):
    memory = _memory(provenance=Provenance.RECALLED)
    _persist(db_session, [memory])
    assert _all(db_session)[0].provenance == Provenance.RECALLED.value

def test_provenance_check_rejects_non_recalled(db_session):
    row = IncidentMemoryRow(
        memory_id=uuid.uuid4(),
        memory_type=MemoryType.INCIDENT_SUMMARY.value,
        title="x",
        summary=None,
        correlation_id=None,
        sources=[],
        indicators=[],
        entities=[],
        techniques=[],
        findings=[],
        actions=[],
        outcomes=[],
        memory_metadata={},
        confidence=None,
        provenance=Provenance.OBSERVED.value,
    )
    db_session.add(row)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

def test_confidence_check_rejects_out_of_range(db_session):
    row = IncidentMemoryRow(
        memory_id=uuid.uuid4(),
        memory_type=MemoryType.INCIDENT_SUMMARY.value,
        title="x",
        summary=None,
        correlation_id=None,
        sources=[],
        indicators=[],
        entities=[],
        techniques=[],
        findings=[],
        actions=[],
        outcomes=[],
        memory_metadata={},
        confidence=1.5,
        provenance=Provenance.RECALLED.value,
    )
    db_session.add(row)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

# ---------------------------------------------------------------------------
# 4. Validation, redaction & transaction safety
# ---------------------------------------------------------------------------

def test_non_memory_item_raises_and_rolls_back(db_session):
    with pytest.raises(IncidentMemoryPersistenceError):
        _persist(db_session, ["not-a-memory"])  # type: ignore[arg-type]
    assert _count(db_session) == 0

def test_malformed_metadata_raises_and_rolls_back(db_session):
    memory = _memory()
    memory.metadata = {"x": b"bytes"}  # type: ignore[assignment]
    with pytest.raises(IncidentMemoryPersistenceError):
        _persist(db_session, [memory])
    assert _count(db_session) == 0

def test_secret_source_metadata_rejected(db_session):
    """Secret-shaped source metadata is rejected at the envelope boundary; nothing persists."""
    source = _source()
    source.metadata = {  # type: ignore[assignment]
        "apiKey": "sk-abc123def456",
        "set_cookie": "sid=abc",
        "region": "eu",
    }
    with pytest.raises(ValidationError):
        _memory(sources=[source])

    assert _count(db_session) == 0


def test_nested_indicator_metadata_secret_redacted(db_session):
    """Nested credential values inside indicator metadata are redacted."""
    memory = _memory()
    memory.indicators[0].metadata = {  # type: ignore[assignment]
        "nested": {"token": "tok_xyz789", "reputation": 87}
    }
    _persist(db_session, [memory])

    metadata = _all(db_session)[0].indicators[0]["metadata"]["nested"]
    assert metadata["token"] == "<redacted>"
    assert metadata["reputation"] == 87

def test_error_message_never_leaks_payload(db_session):
    memory = _memory()
    memory.metadata = {"blob": "x" * 300_000}  # type: ignore[assignment]
    with pytest.raises(IncidentMemoryPersistenceError) as exc_info:
        _persist(db_session, [memory])
    message = str(exc_info.value)
    assert len(message) < 200
    assert "x" * 30 not in message

# ---------------------------------------------------------------------------
# 5. Repository
# ---------------------------------------------------------------------------

def test_repository_add_and_get_by_memory_id(db_session):
    repository = IncidentMemoryRepository(db_session)
    memory = _memory()
    _persist(db_session, [memory])
    found = repository.get_by_memory_id(memory.memory_id)
    assert found is not None
    assert found.memory_id == memory.memory_id
    assert repository.get_by_memory_id(uuid.uuid4()) is None

def test_repository_count_memories(db_session):
    repository = IncidentMemoryRepository(db_session)
    _persist(db_session, [_memory(), _memory()])
    count = repository.count_memories()
    assert count == 2

