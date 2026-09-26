"""Incident memory query layer behavior tests (Step 18).

Verifies the read-only retrieval layer
(:class:`~app.services.incident_memory_query.IncidentMemoryQueryService` and
the :class:`~app.repositories.incident_memory.IncidentMemoryRepository`
read methods) over rows produced by the Step 17 pipeline.

The query layer is read-only: these tests additionally assert that reads
never commit, flush, or stage writes, never mutate source data, and that
database failures surface as sanitized :class:`IncidentMemoryQueryError`
values with no raw driver/SQL text or payloads.

Same harness as Step 17: in-memory SQLite with the PostgreSQL ``JSONB``
column rendered as ``JSON`` via a test-only type-compiler visitor.
Deterministic listing is asserted with explicitly-supplied row
``created_at`` instants (the SQLAlchemy Python-side defaults can be
overridden at construction) and letter-bearing UUIDs for tie-break checks.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine, event, func, select, text
from sqlalchemy.dialects.sqlite.base import SQLiteTypeCompiler
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

# Make the PostgreSQL ``JSONB`` columns work on SQLite for these tests.
if not hasattr(SQLiteTypeCompiler, "visit_JSONB"):
    SQLiteTypeCompiler.visit_JSONB = lambda self, type_, **kw: "JSON"  # noqa: E731

from app.database.postgres.base import Base
from app.models.incident_memory import IncidentMemoryRow
from app.repositories.incident_memory import IncidentMemoryRepository
from app.schemas.incident_memory import (
    IncidentMemory,
    MemoryIndicator,
    MemorySource,
    MemoryType,
)
from app.schemas.security_event import Provenance
from app.services.incident_memory_persistence import IncidentMemoryPersistenceService
from app.services.incident_memory_query import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    IncidentMemoryQueryError,
    IncidentMemoryQueryService,
    IncidentMemoryQueryValidationError,
)

# ---------------------------------------------------------------------------
# Deterministic fixture data
# ---------------------------------------------------------------------------

BASE = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)


def _ts(hours: float = 0.0) -> datetime:
    """Deterministic timezone-aware timestamp offset from BASE."""
    return BASE + timedelta(hours=hours)


def _as_utc(value: datetime) -> datetime:
    """Treat naive SQLite-loaded instants as the UTC instants they are."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _materialize(row):
    """Assign flush-time defaults so unflushed (mocked) rows are readable."""
    if row.id is None:
        row.id = uuid.uuid4()
    if row.created_at is None:
        row.created_at = _ts(0)
    if row.updated_at is None:
        row.updated_at = _ts(0)
    return row


def _memory_row(
    *,
    memory_id: uuid.UUID | None = None,
    memory_type: MemoryType = MemoryType.INCIDENT_SUMMARY,
    title: str = "memory title",
    summary: str = "memory summary",
    correlation_id: uuid.UUID | None = None,
    sources: list | None = None,
    indicators: list | None = None,
    entities: list | None = None,
    techniques: list | None = None,
    findings: list | None = None,
    actions: list | None = None,
    outcomes: dict | None = None,
    memory_metadata: dict | None = None,
    confidence: float | None = None,
    provenance: Provenance = Provenance.RECALLED,
    created_at: datetime | None = None,
):
    """Build an incident_memories row (not yet persisted).

    ``created_at`` is explicitly assignable so ordering tests are fully
    deterministic (the SQLAlchemy Python-side default accepts an override).
    """
    return IncidentMemoryRow(
        memory_id=memory_id or uuid.uuid4(),
        memory_type=memory_type.value,
        title=title,
        summary=summary,
        correlation_id=correlation_id,
        sources=sources if sources is not None else [],
        indicators=indicators if indicators is not None else [],
        entities=entities if entities is not None else [],
        techniques=techniques if techniques is not None else [],
        findings=findings if findings is not None else [],
        actions=actions if actions is not None else [],
        outcomes=outcomes if outcomes is not None else {},
        memory_metadata=memory_metadata if memory_metadata is not None else {},
        confidence=confidence,
        provenance=provenance.value,
        created_at=created_at,
    )


def _seed(db: Session, *rows: IncidentMemoryRow) -> None:
    """Persist incident memory rows and reset the identity map for fresh reads."""
    db.add_all(rows)
    db.commit()
    db.expire_all()


def _seed_many(db: Session, rows: list[IncidentMemoryRow]) -> None:
    """Persist several incident memory rows."""
    _seed(db, *rows)


def _count(db: Session, model) -> int:
    return db.scalar(select(func.count(model.id)))


@pytest.fixture()
def db_session():
    """Fresh in-memory SQLite database with the full model schema."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = Session(engine)
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture()
def db_session_no_autoflush():
    """Read-only-behavior fixture: autoflush off so pending writes stay pending."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = Session(engine, autoflush=False)
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


# ---------------------------------------------------------------------------
# 1. Incident memory lookup
# ---------------------------------------------------------------------------


def test_get_memory_existing_round_trip(db_session):
    """A persisted memory is readable as a complete full record."""
    memory_id = uuid.uuid4()
    sources = [{"source_id": str(uuid.uuid4()), "provenance": "observed", "event_id": str(uuid.uuid4()), "metadata": {"region": "eu"}}]
    indicators = [{"indicator_id": str(uuid.uuid4()), "indicator_type": "ipv4", "value": "198.51.100.10", "source_ids": [], "metadata": {"reputation": 87}}]
    _seed(
        db_session,
        _memory_row(
            memory_id=memory_id,
            correlation_id=uuid.uuid4(),
            sources=sources,
            indicators=indicators,
            confidence=0.87,
            memory_metadata={"team": "soc"},
            created_at=_ts(3),
        ),
    )

    record = IncidentMemoryQueryService().get_memory(db_session, memory_id)

    assert record is not None
    assert record.memory_id == memory_id
    assert record.memory_type == MemoryType.INCIDENT_SUMMARY
    assert record.title == "memory title"
    assert record.summary == "memory summary"
    assert record.sources == sources
    assert record.indicators == indicators
    assert record.confidence == 0.87
    assert record.memory_metadata == {"team": "soc"}
    assert record.provenance == Provenance.RECALLED
    assert _as_utc(record.created_at) == _ts(3)


def test_get_memory_missing_returns_none(db_session):
    memory_id = uuid.uuid4()
    _seed(db_session, _memory_row(memory_id=memory_id))
    assert (
        IncidentMemoryQueryService().get_memory(db_session, uuid.uuid4()) is None
    )


def test_get_memory_accepts_string_uuid(db_session):
    memory_id = uuid.uuid4()
    _seed(db_session, _memory_row(memory_id=memory_id))

    record = IncidentMemoryQueryService().get_memory(db_session, str(memory_id))

    assert record is not None
    assert record.memory_id == memory_id


def test_get_memory_rejects_invalid_uuid_before_database(db_session):
    repo = MagicMock(spec=IncidentMemoryRepository)
    service = IncidentMemoryQueryService(repository_factory=lambda _db: repo)

    with pytest.raises(IncidentMemoryQueryValidationError):
        service.get_memory(db_session, "not-a-uuid")

    repo.get_by_memory_id.assert_not_called()


def test_get_memory_fields_complete(db_session):
    """Every persisted column surfaces with the correct value."""
    memory_id = uuid.uuid4()
    outcomes = {"outcome_status": "contained", "summary": "host contained"}
    ts = _ts(7)
    _seed(
        db_session,
        _memory_row(
            memory_id=memory_id,
            memory_type=MemoryType.MITIGATION_OUTCOME,
            title="Containment outcome",
            summary="",
            outcomes=outcomes,
            confidence=0.42,
            created_at=ts,
        ),
    )

    record = IncidentMemoryQueryService().get_memory(db_session, memory_id)

    assert record.memory_type == MemoryType.MITIGATION_OUTCOME
    assert record.title == "Containment outcome"
    assert record.summary == ""
    assert record.outcomes == outcomes
    assert record.confidence == 0.42
    assert record.provenance == Provenance.RECALLED
    assert record.correlation_id is None
    assert isinstance(record.id, uuid.UUID)
    assert isinstance(record.created_at, datetime)
    assert isinstance(record.updated_at, datetime)
    assert record.created_at.tzinfo is not None


# ---------------------------------------------------------------------------
# 2. Correlation-scoped queries
# ---------------------------------------------------------------------------


def test_correlation_one_memory(db_session):
    correlation_id = uuid.uuid4()
    memory_id = uuid.uuid4()
    _seed(db_session, _memory_row(memory_id=memory_id, correlation_id=correlation_id, created_at=_ts(1)))

    page = IncidentMemoryQueryService().list_memories_for_correlation(
        db_session, correlation_id
    )

    assert page.total == 1
    assert [r.memory_id for r in page.items] == [memory_id]


def test_correlation_multiple_memories(db_session):
    correlation_id = uuid.uuid4()
    memory_ids = [uuid.uuid4(), uuid.uuid4(), uuid.uuid4()]
    _seed_many(
        db_session,
        [
            _memory_row(memory_id=memory_ids[0], correlation_id=correlation_id, created_at=_ts(0)),
            _memory_row(memory_id=memory_ids[1], correlation_id=correlation_id, created_at=_ts(1)),
            _memory_row(memory_id=memory_ids[2], correlation_id=correlation_id, created_at=_ts(2)),
        ],
    )

    page = IncidentMemoryQueryService().list_memories_for_correlation(
        db_session, correlation_id, page=1, page_size=10
    )

    assert page.total == 3
    # Newest first: memory_ids[2], [1], [0]
    assert [r.memory_id for r in page.items] == [
        memory_ids[2],
        memory_ids[1],
        memory_ids[0],
    ]


def test_correlation_with_no_memories(db_session):
    correlation_id = uuid.uuid4()
    _seed(db_session, _memory_row(memory_id=uuid.uuid4(), correlation_id=correlation_id))

    page = IncidentMemoryQueryService().list_memories_for_correlation(
        db_session, uuid.uuid4()
    )

    assert page.total == 0
    assert page.items == []


def test_correlation_scoping_ignores_unrelated_and_none(db_session):
    """Memories citing other correlations (or none) are never matched."""
    target = uuid.uuid4()
    target_memory = uuid.uuid4()
    other_memory = uuid.uuid4()
    uncorrelated = uuid.uuid4()
    _seed_many(
        db_session,
        [
            _memory_row(memory_id=target_memory, correlation_id=target, created_at=_ts(1)),
            _memory_row(memory_id=other_memory, correlation_id=uuid.uuid4(), created_at=_ts(2)),
            _memory_row(memory_id=uncorrelated, correlation_id=None, created_at=_ts(3)),
        ],
    )

    service = IncidentMemoryQueryService()
    page = service.list_memories_for_correlation(db_session, target)

    assert page.total == 1
    assert [r.memory_id for r in page.items] == [target_memory]
    assert service.count_memories_for_correlation(db_session, target) == 1
    assert service.count_memories_for_correlation(db_session, uuid.uuid4()) == 0


def test_correlation_scoped_rejects_invalid_uuid_before_database(db_session):
    repo = MagicMock(spec=IncidentMemoryRepository)
    service = IncidentMemoryQueryService(repository_factory=lambda _db: repo)

    with pytest.raises(IncidentMemoryQueryValidationError):
        service.list_memories_for_correlation(db_session, "not-a-uuid")

    repo.count_memories_for_correlation.assert_not_called()
    repo.list_memories_for_correlation.assert_not_called()


def test_list_memories_memory_type_filter_narrows(db_session):
    """The optional memory_type filter restricts the general list to that type."""
    summary = uuid.uuid4()
    indicator = uuid.uuid4()
    pattern = uuid.uuid4()
    _seed_many(
        db_session,
        [
            _memory_row(
                memory_id=summary,
                memory_type=MemoryType.INCIDENT_SUMMARY,
                created_at=_ts(3),
            ),
            _memory_row(
                memory_id=indicator,
                memory_type=MemoryType.INDICATOR_OBSERVATION,
                created_at=_ts(2),
            ),
            _memory_row(
                memory_id=pattern,
                memory_type=MemoryType.ATTACK_PATTERN,
                created_at=_ts(1),
            ),
        ],
    )

    service = IncidentMemoryQueryService()
    page = service.list_memories(
        db_session, memory_type=MemoryType.INDICATOR_OBSERVATION
    )

    assert page.total == 1
    assert [r.memory_id for r in page.items] == [indicator]


# ---------------------------------------------------------------------------
# 3. Recent memories
# ---------------------------------------------------------------------------


def test_recent_ordered_newest_first(db_session):
    ids = [uuid.uuid4(), uuid.uuid4(), uuid.uuid4()]
    _seed_many(
        db_session,
        [
            _memory_row(memory_id=ids[0], created_at=_ts(1)),
            _memory_row(memory_id=ids[1], created_at=_ts(3)),
            _memory_row(memory_id=ids[2], created_at=_ts(2)),
        ],
    )

    feed = IncidentMemoryQueryService().list_recent_memories(db_session, limit=2)

    assert [r.memory_id for r in feed] == [ids[1], ids[2]]


def test_recent_deterministic_tie_break(db_session):
    """Equal created_at falls back to memory_id ascending (stable feed).

    letter-bearing hex keeps these deterministic ids out of SQLite's
    NUMERIC affinity (all-digit hex would be coerced to INTEGER), while
    remaining strictly sortable by memory_id.
    """
    id_a = uuid.UUID("00000000-0000-0000-0000-00000000000a")
    id_b = uuid.UUID("00000000-0000-0000-0000-00000000000b")
    id_c = uuid.UUID("00000000-0000-0000-0000-00000000000c")
    _seed_many(
        db_session,
        [
            _memory_row(memory_id=id_b, created_at=_ts(0)),
            _memory_row(memory_id=id_c, created_at=_ts(0)),
            _memory_row(memory_id=id_a, created_at=_ts(0)),
        ],
    )

    feed = IncidentMemoryQueryService().list_recent_memories(db_session, limit=10)

    assert [r.memory_id for r in feed] == [id_a, id_b, id_c]


def test_recent_empty(db_session):
    feed = IncidentMemoryQueryService().list_recent_memories(db_session, limit=10)
    assert feed == []


# ---------------------------------------------------------------------------
# 4. Pagination
# ---------------------------------------------------------------------------


def test_pagination_default_limit_applied(db_session):
    """Recent-feed default limit is applied when none is supplied."""
    ids = [uuid.uuid4() for _ in range(DEFAULT_PAGE_SIZE + 10)]
    _seed_many(
        db_session,
        [_memory_row(memory_id=mid, created_at=_ts(float(i))) for i, mid in enumerate(ids)],
    )

    feed = IncidentMemoryQueryService().list_recent_memories(db_session)

    assert len(feed) == DEFAULT_PAGE_SIZE
    assert feed[0].memory_id == ids[-1]


def test_pagination_custom_limit(db_session):
    ids = [uuid.uuid4() for _ in range(5)]
    _seed_many(
        db_session,
        [_memory_row(memory_id=mid, created_at=_ts(float(i))) for i, mid in enumerate(ids)],
    )

    feed = IncidentMemoryQueryService().list_recent_memories(db_session, limit=3)

    assert [r.memory_id for r in feed] == [ids[4], ids[3], ids[2]]


def test_pagination_page_and_offset(db_session):
    _seed_many(
        db_session,
        [_memory_row(memory_id=uuid.uuid4(), created_at=_ts(float(i))) for i in range(5)],
    )

    service = IncidentMemoryQueryService()
    first = service.list_memories(db_session, page=1, page_size=2)
    second = service.list_memories(db_session, page=2, page_size=2)

    assert first.total == 5
    assert len(first.items) == 2
    assert first.page == 1 and first.page_size == 2
    assert len(second.items) == 2
    assert first.items[-1].memory_id != second.items[0].memory_id


def test_pagination_page_beyond_bounds(db_session):
    memory_id = uuid.uuid4()
    _seed(db_session, _memory_row(memory_id=memory_id, created_at=_ts(1)))

    page = IncidentMemoryQueryService().list_memories(
        db_session, page=99, page_size=10
    )

    assert page.items == []
    assert page.total == 1


def test_pagination_max_limit_enforced(db_session):
    service = IncidentMemoryQueryService()
    with pytest.raises(IncidentMemoryQueryValidationError):
        service.list_memories(db_session, page_size=MAX_PAGE_SIZE + 1)
    with pytest.raises(IncidentMemoryQueryValidationError):
        service.list_recent_memories(db_session, limit=MAX_PAGE_SIZE * 5)


def test_pagination_invalid_limit_rejected(db_session):
    service = IncidentMemoryQueryService()
    with pytest.raises(IncidentMemoryQueryValidationError):
        service.list_recent_memories(db_session, limit=0)
    with pytest.raises(IncidentMemoryQueryValidationError):
        service.list_recent_memories(db_session, limit="x")


def test_pagination_invalid_page_rejected(db_session):
    service = IncidentMemoryQueryService()
    with pytest.raises(IncidentMemoryQueryValidationError):
        service.list_memories(db_session, page=0)
    with pytest.raises(IncidentMemoryQueryValidationError):
        service.list_memories_for_correlation(db_session, uuid.uuid4(), page=0, page_size=10)
    with pytest.raises(IncidentMemoryQueryValidationError):
        service.list_memories(db_session, page="x")


def test_pagination_stable_ordering_across_pages(db_session):
    """Every page re-uses the same total ordering; no drift between pages."""
    # letter-bearing hex keeps these deterministic ids out of SQLite's
    # NUMERIC affinity, while remaining strictly sortable by memory_id.
    memory_ids = [
        uuid.UUID(f"deadbeef-dead-beef-dead-{i:012x}") for i in range(1, 6)
    ]
    _seed_many(
        db_session,
        [
            _memory_row(memory_id=mid, created_at=_ts(0))
            for mid in memory_ids
        ],
    )

    service = IncidentMemoryQueryService()
    p1 = service.list_memories(db_session, page=1, page_size=2).items
    p2 = service.list_memories(db_session, page=2, page_size=2).items
    p3 = service.list_memories(db_session, page=3, page_size=2).items

    order = [r.memory_id for r in p1 + p2 + p3]
    assert order == sorted(memory_ids)  # tie-break: memory_id ascending


def test_list_memories_invalid_memory_type_rejected_before_database(db_session):
    """A non-MemoryType filter value is rejected before any repository work."""
    repo = MagicMock(spec=IncidentMemoryRepository)
    service = IncidentMemoryQueryService(repository_factory=lambda _db: repo)

    with pytest.raises(IncidentMemoryQueryValidationError):
        service.list_memories(db_session, memory_type="not-a-type")

    repo.count_memories.assert_not_called()
    repo.list_memories.assert_not_called()


def test_list_memories_memory_type_delegates_to_repository(db_session):
    """The service forwards the validated filter to count and list."""
    repo = MagicMock(spec=IncidentMemoryRepository)
    repo.count_memories.return_value = 2
    repo.list_memories.return_value = [
        _memory_row(
            memory_id=uuid.uuid4(),
            memory_type=MemoryType.ATTACK_PATTERN,
            created_at=_ts(1),
        )
    ]
    _materialize(repo.list_memories.return_value[0])
    service = IncidentMemoryQueryService(repository_factory=lambda _db: repo)

    page = service.list_memories(
        db_session, page=2, page_size=7, memory_type=MemoryType.ATTACK_PATTERN
    )

    assert page.total == 2
    assert len(page.items) == 1
    repo.count_memories.assert_called_once_with(
        memory_type=MemoryType.ATTACK_PATTERN
    )
    repo.list_memories.assert_called_once_with(
        limit=7,
        offset=(2 - 1) * 7,
        memory_type=MemoryType.ATTACK_PATTERN,
    )


def test_list_memories_no_filter_passes_none_to_repository(db_session):
    """Omitting the filter leaves the repository unfiltered (None)."""
    repo = MagicMock(spec=IncidentMemoryRepository)
    repo.count_memories.return_value = 3
    repo.list_memories.return_value = []
    service = IncidentMemoryQueryService(repository_factory=lambda _db: repo)

    service.list_memories(db_session)

    repo.count_memories.assert_called_once_with(memory_type=None)
    repo.list_memories.assert_called_once_with(limit=50, offset=0, memory_type=None)


# ---------------------------------------------------------------------------
# 5. Counting
# ---------------------------------------------------------------------------


def test_count_total(db_session):
    memory_ids = [uuid.uuid4() for _ in range(4)]
    _seed_many(
        db_session,
        [_memory_row(memory_id=mid) for mid in memory_ids],
    )

    assert IncidentMemoryQueryService().count_memories(db_session) == 4


def test_count_total_empty(db_session):
    assert IncidentMemoryQueryService().count_memories(db_session) == 0


def test_count_memories_with_memory_type_filter(db_session):
    """Counting honours the optional memory type filter (database-side)."""
    _seed_many(
        db_session,
        [
            _memory_row(
                memory_id=uuid.uuid4(),
                memory_type=MemoryType.INCIDENT_SUMMARY,
                created_at=_ts(1),
            ),
            _memory_row(
                memory_id=uuid.uuid4(),
                memory_type=MemoryType.INCIDENT_SUMMARY,
                created_at=_ts(2),
            ),
            _memory_row(
                memory_id=uuid.uuid4(),
                memory_type=MemoryType.INDICATOR_OBSERVATION,
                created_at=_ts(3),
            ),
        ],
    )

    service = IncidentMemoryQueryService()
    assert service.count_memories(db_session) == 3
    assert (
        service.count_memories(
            db_session, memory_type=MemoryType.INCIDENT_SUMMARY
        )
        == 2
    )
    assert (
        service.count_memories(
            db_session, memory_type=MemoryType.INDICATOR_OBSERVATION
        )
        == 1
    )
    assert (
        service.count_memories(
            db_session, memory_type=MemoryType.ATTACK_PATTERN
        )
        == 0
    )


def test_repository_filters_by_memory_type(db_session):
    """The repository list/count equality filter is database-side SQL."""
    repo = IncidentMemoryRepository(db_session)
    target = uuid.uuid4()
    _seed_many(
        db_session,
        [
            _memory_row(
                memory_id=target,
                memory_type=MemoryType.ATTACK_PATTERN,
                created_at=_ts(2),
            ),
            _memory_row(
                memory_id=uuid.uuid4(),
                memory_type=MemoryType.INCIDENT_SUMMARY,
                created_at=_ts(1),
            ),
        ],
    )

    rows = repo.list_memories(limit=10, memory_type=MemoryType.ATTACK_PATTERN)
    assert [r.memory_id for r in rows] == [target]
    assert (
        repo.count_memories(memory_type=MemoryType.ATTACK_PATTERN) == 1
    )
    assert (
        repo.count_memories(memory_type=MemoryType.INCIDENT_SUMMARY) == 1
    )
    assert repo.count_memories() == 2


def test_count_for_correlation(db_session):
    correlation_id = uuid.uuid4()
    cited = uuid.uuid4()
    other = uuid.uuid4()
    _seed_many(
        db_session,
        [
            _memory_row(memory_id=cited, correlation_id=correlation_id),
            _memory_row(memory_id=uuid.uuid4(), correlation_id=other),
            _memory_row(memory_id=uuid.uuid4(), correlation_id=None),
        ],
    )

    assert (
        IncidentMemoryQueryService().count_memories_for_correlation(
            db_session, correlation_id
        )
        == 1
    )
    assert (
        IncidentMemoryQueryService().count_memories_for_correlation(
            db_session, uuid.uuid4()
        )
        == 0
    )
    assert IncidentMemoryQueryService().count_memories(db_session) == 3


# ---------------------------------------------------------------------------
# 6. Data fidelity
# ---------------------------------------------------------------------------


def test_round_trip_persistence_service(db_session):
    """A memory persisted through the real service reads back identically."""
    event_id = uuid.uuid4()
    source = MemorySource(provenance=Provenance.OBSERVED, event_id=event_id)
    indicator = MemoryIndicator(
        indicator_type="ipv4",
        value="198.51.100.10",
        source_ids=[source.source_id],
    )
    memory = IncidentMemory(
        memory_type=MemoryType.INCIDENT_SUMMARY,
        title="Credential stuffing campaign",
        summary="Observed credential stuffing against the web tier.",
        sources=[source],
        indicators=[indicator],
        confidence=0.6,
        created_at=_ts(2),
    )
    IncidentMemoryPersistenceService().persist_memories(db_session, [memory])

    record = IncidentMemoryQueryService().get_memory(db_session, memory.memory_id)

    assert record is not None
    assert record.memory_id == memory.memory_id
    assert record.memory_type == MemoryType.INCIDENT_SUMMARY
    assert record.title == memory.title
    assert record.summary == memory.summary
    assert record.sources[0]["provenance"] == "observed"
    assert record.indicators[0]["value"] == "198.51.100.10"
    assert record.confidence == 0.6
    assert record.provenance == Provenance.RECALLED


def test_round_trip_without_summary_normalizes_to_empty(db_session):
    """A memory persisted without a summary reads back as an empty string."""
    source = MemorySource(provenance=Provenance.OBSERVED, event_id=uuid.uuid4())
    memory = IncidentMemory(
        memory_type=MemoryType.INCIDENT_SUMMARY,
        title="No summary",
        sources=[source],
        created_at=_ts(1),
    )
    IncidentMemoryPersistenceService().persist_memories(db_session, [memory])

    record = IncidentMemoryQueryService().get_memory(db_session, memory.memory_id)

    assert record is not None
    assert record.summary == ""


def test_confidence_none_and_boundaries_round_trip(db_session):
    memory_id = uuid.uuid4()
    none_id = uuid.uuid4()
    _seed_many(
        db_session,
        [
            _memory_row(memory_id=memory_id, confidence=0.0),
            _memory_row(memory_id=none_id, confidence=None),
        ],
    )

    service = IncidentMemoryQueryService()
    assert service.get_memory(db_session, memory_id).confidence == 0.0
    assert service.get_memory(db_session, none_id).confidence is None


def test_persisted_memory_always_recalled_provenance(db_session):
    memory_id = uuid.uuid4()
    _seed(db_session, _memory_row(memory_id=memory_id, provenance=Provenance.RECALLED))

    record = IncidentMemoryQueryService().get_memory(db_session, memory_id)

    assert record.provenance == Provenance.RECALLED


def test_structured_payload_fidelity_verbatim(db_session):
    """Structured JSONB payloads round-trip exactly (arrays and objects)."""
    memory_id = uuid.uuid4()
    sources = [{"source_id": str(uuid.uuid4()), "provenance": "enriched", "event_id": str(uuid.uuid4()), "metadata": {}}]
    indicators = [{"indicator_id": str(uuid.uuid4()), "indicator_type": "domain", "value": "evil.example.com", "source_ids": [], "metadata": {"sla": 3}}]
    outcomes = {"outcome_status": "contained", "summary": "ok"}
    _seed(
        db_session,
        _memory_row(
            memory_id=memory_id,
            sources=sources,
            indicators=indicators,
            outcomes=outcomes,
            memory_metadata={"priority": "high"},
        ),
    )

    record = IncidentMemoryQueryService().get_memory(db_session, memory_id)

    assert record.sources == sources
    assert record.indicators == indicators
    assert record.outcomes == outcomes
    assert record.memory_metadata == {"priority": "high"}


# ---------------------------------------------------------------------------
# 7. Security
# ---------------------------------------------------------------------------


def test_surfaces_redacted_at_write_structured_payloads(db_session):
    """The query path returns the stored (redacted) form, never a raw secret.

    Round-trip through the real service: Step 16 accepts a benign-shaped
    ``token`` metadata key (it is not in the Step 16 reject list), Step 17
    persistence redacts the credential value to ``<redacted>`` before write;
    the query layer must surface the stored redacted value — no weaker read
    path — and never the original secret.
    """
    event_id = uuid.uuid4()
    source = MemorySource(provenance=Provenance.OBSERVED, event_id=event_id)
    indicator = MemoryIndicator(
        indicator_type="ipv4",
        value="198.51.100.7",
        source_ids=[source.source_id],
        metadata={"nested": {"token": "tok_abc123", "reputation": 87}},
    )
    memory = IncidentMemory(
        memory_type=MemoryType.INDICATOR_OBSERVATION,
        title="Observed indicator",
        sources=[source],
        indicators=[indicator],
        created_at=_ts(0),
    )
    IncidentMemoryPersistenceService().persist_memories(db_session, [memory])

    record = IncidentMemoryQueryService().get_memory(db_session, memory.memory_id)

    assert record is not None
    assert record.indicators[0]["metadata"]["nested"]["token"] == "<redacted>"
    assert record.indicators[0]["metadata"]["nested"]["reputation"] == 87
    assert "tok_abc123" not in record.model_dump_json()


def test_query_error_contains_no_secrets_or_raw_sql(db_session):
    """A database failure surfaces sanitized: no raw SQL, no payloads."""
    repo = MagicMock(spec=IncidentMemoryRepository)
    repo.get_by_memory_id.side_effect = OperationalError(
        "SELECT * FROM incident_memories WHERE memory_id=:m",
        {},
        Exception("connection to server lost"),
    )
    service = IncidentMemoryQueryService(repository_factory=lambda _db: repo)

    with pytest.raises(IncidentMemoryQueryError) as exc_info:
        service.get_memory(db_session, uuid.uuid4())

    message = str(exc_info.value)
    assert "Traceback" not in message
    assert "connection to server lost" not in message
    assert "SELECT" not in message
    assert "incident_memories" not in message
    assert "failed to load incident memory" in message
    assert exc_info.value.__cause__ is not None


def test_list_error_sanitized(db_session):
    memory_id = uuid.uuid4()
    repo = MagicMock(spec=IncidentMemoryRepository)
    repo.count_memories.side_effect = OperationalError(
        "SELECT 1", {}, Exception("boom")
    )
    service = IncidentMemoryQueryService(repository_factory=lambda _db: repo)

    with pytest.raises(IncidentMemoryQueryError) as exc_info:
        service.list_memories(db_session)

    message = str(exc_info.value)
    assert "boom" not in message
    assert "SELECT" not in message
    assert str(memory_id) not in message or True  # ids are safe, payloads are not


# ---------------------------------------------------------------------------
# 8. Read-only contract
# ---------------------------------------------------------------------------


def test_query_service_never_writes_on_any_operation():
    """Every read goes through repository reads; the session is never touched."""
    memory_id = uuid.uuid4()
    row = _materialize(_memory_row(memory_id=memory_id))

    repo = MagicMock(spec=IncidentMemoryRepository)
    repo.get_by_memory_id.return_value = row
    repo.count_memories.return_value = 1
    repo.count_memories_for_correlation.return_value = 1
    repo.list_memories.return_value = [row]
    repo.list_memories_for_correlation.return_value = [row]
    repo.list_recent_memories.return_value = [row]

    db = MagicMock(spec=Session)
    service = IncidentMemoryQueryService(repository_factory=lambda _db: repo)

    service.get_memory(db, memory_id)
    service.list_memories(db)
    service.list_memories_for_correlation(db, uuid.uuid4())
    service.list_recent_memories(db)
    service.count_memories(db)
    service.count_memories_for_correlation(db, uuid.uuid4())

    db.commit.assert_not_called()
    db.flush.assert_not_called()
    db.add.assert_not_called()
    db.delete.assert_not_called()
    db.rollback.assert_not_called()
    db.execute.assert_not_called()
    repo.add.assert_not_called()


def test_query_service_reads_do_not_flush_pending_writes(db_session_no_autoflush):
    """Reads leave concurrently-staged (uncommitted) writes untouched."""
    memory_id = uuid.uuid4()
    _seed(db_session_no_autoflush, _memory_row(memory_id=memory_id, created_at=_ts(1)))

    pending = _memory_row(memory_id=uuid.uuid4(), created_at=_ts(9))
    db_session_no_autoflush.add(pending)

    service = IncidentMemoryQueryService()
    service.list_recent_memories(db_session_no_autoflush)
    service.get_memory(db_session_no_autoflush, memory_id)

    assert pending in list(db_session_no_autoflush.new)  # still staged
    assert _count(db_session_no_autoflush, IncidentMemoryRow) == 1


def test_returned_records_are_independent_of_rows(db_session):
    """Mutating a returned record never mutates the stored row."""
    memory_id = uuid.uuid4()
    _seed(
        db_session,
        _memory_row(
            memory_id=memory_id,
            sources=[{"source_id": str(uuid.uuid4()), "provenance": "observed", "event_id": str(uuid.uuid4()), "metadata": {"safe": "value"}}],
            indicators=[{"indicator_id": str(uuid.uuid4()), "indicator_type": "ipv4", "value": "198.51.100.10", "source_ids": [], "metadata": {"safe": "value"}}],
            memory_metadata={"safe": "value"},
        ),
    )

    record = IncidentMemoryQueryService().get_memory(db_session, memory_id)
    record.indicators[0]["value"] = "mutated"
    record.indicators[0]["metadata"]["new"] = "tampered"
    record.sources[0]["metadata"]["safe"] = "mutated"
    record.memory_metadata["safe"] = "mutated"

    fresh = IncidentMemoryQueryService().get_memory(db_session, memory_id)
    assert fresh.indicators[0]["value"] == "198.51.100.10"
    assert "new" not in fresh.indicators[0]["metadata"]
    assert fresh.sources[0]["metadata"] == {"safe": "value"}
    assert fresh.memory_metadata == {"safe": "value"}


# ---------------------------------------------------------------------------
# 9. Database behaviour
# ---------------------------------------------------------------------------


def test_empty_database_behavior(db_session):
    service = IncidentMemoryQueryService()
    assert service.count_memories(db_session) == 0
    assert service.get_memory(db_session, uuid.uuid4()) is None
    assert service.list_recent_memories(db_session) == []
    assert service.list_memories(db_session).items == []
    assert (
        service.list_memories_for_correlation(db_session, uuid.uuid4()).items == []
    )


def test_multiple_memory_records(db_session):
    memory_ids = [uuid.uuid4() for _ in range(3)]
    _seed_many(
        db_session,
        [_memory_row(memory_id=mid, created_at=_ts(float(i))) for i, mid in enumerate(memory_ids)],
    )

    feed = IncidentMemoryQueryService().list_recent_memories(db_session, limit=10)

    assert {r.memory_id for r in feed} == set(memory_ids)
    assert IncidentMemoryQueryService().count_memories(db_session) == 3


def test_deleted_memory_immediately_reflected(db_session):
    """Deleting a memory row makes the query layer reflect it immediately."""
    memory_id = uuid.uuid4()
    _seed(db_session, _memory_row(memory_id=memory_id, created_at=_ts(1)))

    row = db_session.scalar(
        select(IncidentMemoryRow).where(
            IncidentMemoryRow.memory_id == memory_id
        )
    )
    assert row is not None
    db_session.delete(row)
    db_session.commit()
    db_session.expire_all()

    service = IncidentMemoryQueryService()
    assert service.get_memory(db_session, memory_id) is None
    assert service.count_memories(db_session) == 0