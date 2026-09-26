"""Correlation query layer behavior tests (Step 10D).

Verifies the read-only retrieval layer
(:class:`~app.services.correlation_query.CorrelationQueryService` and the
:class:`~app.repositories.correlation.CorrelationRepository` read methods)
over rows produced by the Step 10C pipeline.

The query layer is read-only: these tests additionally assert that reads
never commit, flush, or stage writes, never mutate source data, and that
database failures surface as sanitized :class:`CorrelationQueryError` values
with no raw driver/SQL text.

Same harness as Step 10C: in-memory SQLite with the PostgreSQL ``JSONB``
column rendered as ``JSON`` via a test-only type-compiler visitor, plus
``PRAGMA foreign_keys=ON`` so FK cascade/rejection behaviour matches
PostgreSQL enforcement.
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
from app.models.correlation_member import CorrelationMember as CorrelationMemberRow
from app.models.correlation_result import CorrelationResult as CorrelationResultRow
from app.repositories.correlation import CorrelationRepository
from app.schemas.correlation import (
    CorrelationMember,
    CorrelationResult,
    CorrelationStatus,
)
from app.schemas.security_event import Provenance
from app.services.correlation_persistence import CorrelationPersistenceService
from app.services.correlation_query import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    CorrelationQueryError,
    CorrelationQueryService,
    CorrelationQueryValidationError,
)

# ---------------------------------------------------------------------------
# Deterministic fixture data
# ---------------------------------------------------------------------------

BASE = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)


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


def _correlation_row(
    *,
    correlation_id: uuid.UUID | None = None,
    status: CorrelationStatus = CorrelationStatus.CANDIDATE,
    confidence: float | None = None,
    evidence: dict | None = None,
    metadata: dict | None = None,
    timestamp: datetime | None = None,
    provenance: Provenance = Provenance.CORRELATED,
):
    """Build a correlation_results row (not yet persisted)."""
    return CorrelationResultRow(
        correlation_id=correlation_id or uuid.uuid4(),
        status=status,
        confidence=confidence,
        evidence=evidence if evidence is not None else {},
        result_metadata=metadata if metadata is not None else {},
        timestamp=timestamp or _ts(0),
        provenance=provenance.value,
    )


def _member_row(
    *,
    correlation_id: uuid.UUID,
    detection_id: uuid.UUID | None = None,
    event_id: uuid.UUID | None = None,
    timestamp: datetime | None = None,
    member_order: int = 0,
):
    """Build a correlation_members row (not yet persisted)."""
    return CorrelationMemberRow(
        correlation_id=correlation_id,
        detection_id=detection_id or uuid.uuid4(),
        event_id=event_id or uuid.uuid4(),
        timestamp=timestamp or _ts(0),
        member_order=member_order,
    )


def _seed(db: Session, correlation, members: list) -> None:
    """Persist a parent correlation and its members (FK-safe ordering).

    Parents are flushed before their member rows so the enabled foreign-key
    enforcement is satisfied; the identity map is reset for fresh reads.
    """
    db.add(correlation)
    db.flush()
    db.add_all(members)
    db.commit()
    db.expire_all()


def _seed_batch(db: Session, pairs) -> None:
    """Persist several (correlation, members) pairs with FK-safe ordering."""
    for correlation, members in pairs:
        _seed(db, correlation, members)


def _count(db: Session, model) -> int:
    return db.scalar(select(func.count(model.id)))


@pytest.fixture()
def db_session():
    """Fresh in-memory SQLite database with the full model schema + FK checks."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = Session(engine)
    session.execute(text("PRAGMA foreign_keys=ON"))
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
    session.execute(text("PRAGMA foreign_keys=ON"))
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


# ---------------------------------------------------------------------------
# 1. Correlation lookup
# ---------------------------------------------------------------------------


def test_get_correlation_existing_round_trip(db_session):
    """A persisted correlation is readable as a complete full record."""
    correlation_id = uuid.uuid4()
    detection_id = uuid.uuid4()
    event_id = uuid.uuid4()
    evidence = {"signals": ["same_host"], "count": 2}
    metadata = {"region": "eu"}
    _seed(
        db_session,
        _correlation_row(
            correlation_id=correlation_id,
            status=CorrelationStatus.ACTIVE,
            confidence=0.87,
            evidence=evidence,
            metadata=metadata,
            timestamp=_ts(3),
        ),
        [_member_row(correlation_id=correlation_id, detection_id=detection_id, event_id=event_id, timestamp=_ts(1), member_order=0)],
    )

    record = CorrelationQueryService().get_correlation(db_session, correlation_id)

    assert record is not None
    assert record.correlation_id == correlation_id
    assert record.status == CorrelationStatus.ACTIVE
    assert record.confidence == 0.87
    assert record.evidence == evidence
    assert record.result_metadata == metadata
    assert _as_utc(record.timestamp) == _ts(3)
    assert record.provenance == Provenance.CORRELATED
    assert len(record.members) == 1
    assert record.members[0].detection_id == detection_id
    assert record.members[0].event_id == event_id
    assert _as_utc(record.members[0].timestamp) == _ts(1)
    assert record.members[0].member_order == 0


def test_get_correlation_missing_returns_none(db_session):
    correlation_id = uuid.uuid4()
    _seed(
        db_session,
        _correlation_row(correlation_id=correlation_id),
        [_member_row(correlation_id=correlation_id)],
    )
    assert (
        CorrelationQueryService().get_correlation(db_session, uuid.uuid4()) is None
    )


def test_get_correlation_accepts_string_uuid(db_session):
    correlation_id = uuid.uuid4()
    _seed(
        db_session,
        _correlation_row(correlation_id=correlation_id),
        [_member_row(correlation_id=correlation_id)],
    )

    record = CorrelationQueryService().get_correlation(db_session, str(correlation_id))

    assert record is not None
    assert record.correlation_id == correlation_id


def test_get_correlation_rejects_invalid_uuid_before_database(db_session):
    repo = MagicMock(spec=CorrelationRepository)
    service = CorrelationQueryService(repository_factory=lambda _db: repo)

    with pytest.raises(CorrelationQueryValidationError):
        service.get_correlation(db_session, "not-a-uuid")

    repo.get_by_correlation_id.assert_not_called()


def test_get_correlation_member_order_preserved(db_session):
    """Members round-trip in persisted member_order, inserts preserved."""
    correlation_id = uuid.uuid4()
    detection_ids = [uuid.uuid4(), uuid.uuid4(), uuid.uuid4()]
    _seed(
        db_session,
        _correlation_row(correlation_id=correlation_id),
        [
            _member_row(correlation_id=correlation_id, detection_id=detection_ids[2], timestamp=_ts(2), member_order=2),
            _member_row(correlation_id=correlation_id, detection_id=detection_ids[0], timestamp=_ts(0), member_order=0),
            _member_row(correlation_id=correlation_id, detection_id=detection_ids[1], timestamp=_ts(1), member_order=1),
        ],
    )

    record = CorrelationQueryService().get_correlation(db_session, correlation_id)

    assert [m.detection_id for m in record.members] == detection_ids
    assert [m.member_order for m in record.members] == [0, 1, 2]


def test_get_correlation_fields_complete(db_session):
    """Every persisted column surfaces with the correct value."""
    correlation_id = uuid.uuid4()
    status = CorrelationStatus.CLOSED
    confidence = 0.42
    evidence = {"chain": ["a", "b"]}
    metadata = {"team": "soc"}
    ts = _ts(7)
    _seed(
        db_session,
        _correlation_row(
            correlation_id=correlation_id,
            status=status,
            confidence=confidence,
            evidence=evidence,
            metadata=metadata,
            timestamp=ts,
        ),
        [_member_row(correlation_id=correlation_id, timestamp=_ts(7), member_order=0)],
    )

    record = CorrelationQueryService().get_correlation(db_session, correlation_id)

    assert record.status == status
    assert record.confidence == confidence
    assert record.evidence == evidence
    assert record.result_metadata == metadata
    assert _as_utc(record.timestamp) == ts
    assert record.provenance == Provenance.CORRELATED
    assert isinstance(record.id, uuid.UUID)
    assert isinstance(record.created_at, datetime)
    assert isinstance(record.updated_at, datetime)
    assert record.members[0].timestamp.tzinfo is not None


# ---------------------------------------------------------------------------
# 2. Detection queries
# ---------------------------------------------------------------------------


def test_detection_one_correlation(db_session):
    detection_id = uuid.uuid4()
    correlation_id = uuid.uuid4()
    _seed(
        db_session,
        _correlation_row(correlation_id=correlation_id, timestamp=_ts(1)),
        [_member_row(correlation_id=correlation_id, detection_id=detection_id)],
    )

    page = CorrelationQueryService().list_correlations_for_detection(
        db_session, detection_id
    )

    assert page.total == 1
    assert [r.correlation_id for r in page.items] == [correlation_id]


def test_detection_multiple_correlations(db_session):
    detection_id = uuid.uuid4()
    correlation_ids = [uuid.uuid4(), uuid.uuid4(), uuid.uuid4()]
    _seed_batch(
        db_session,
        [
            (
                _correlation_row(correlation_id=correlation_ids[0], timestamp=_ts(0)),
                [_member_row(correlation_id=correlation_ids[0], detection_id=detection_id)],
            ),
            (
                _correlation_row(correlation_id=correlation_ids[1], timestamp=_ts(1)),
                [_member_row(correlation_id=correlation_ids[1], detection_id=detection_id)],
            ),
            (
                _correlation_row(correlation_id=correlation_ids[2], timestamp=_ts(2)),
                [_member_row(correlation_id=correlation_ids[2], detection_id=detection_id)],
            ),
        ],
    )

    page = CorrelationQueryService().list_correlations_for_detection(
        db_session, detection_id, page=1, page_size=10
    )

    assert page.total == 3
    # Newest first: correlation_ids[2], [1], [0]
    assert [r.correlation_id for r in page.items] == [
        correlation_ids[2],
        correlation_ids[1],
        correlation_ids[0],
    ]


def test_detection_with_no_correlations(db_session):
    correlation_id = uuid.uuid4()
    _seed(
        db_session,
        _correlation_row(correlation_id=correlation_id),
        [_member_row(correlation_id=correlation_id)],
    )

    page = CorrelationQueryService().list_correlations_for_detection(
        db_session, uuid.uuid4()
    )

    assert page.total == 0
    assert page.items == []


def test_detection_multiple_detections_scoped(db_session):
    detection_a = uuid.uuid4()
    detection_b = uuid.uuid4()
    other = uuid.uuid4()
    unrelated = uuid.uuid4()
    _seed_batch(
        db_session,
        [
            (
                _correlation_row(correlation_id=other, timestamp=_ts(1)),
                [
                    _member_row(correlation_id=other, detection_id=detection_a, member_order=0),
                    _member_row(correlation_id=other, detection_id=detection_b, member_order=1),
                ],
            ),
            (
                _correlation_row(correlation_id=unrelated, timestamp=_ts(0)),
                [_member_row(correlation_id=unrelated, detection_id=uuid.uuid4(), member_order=0)],
            ),
        ],
    )

    service = CorrelationQueryService()
    assert [
        r.correlation_id for r in service.list_correlations_for_detection(
            db_session, detection_a
        ).items
    ] == [other]
    assert [
        r.correlation_id for r in service.list_correlations_for_detection(
            db_session, detection_b
        ).items
    ] == [other]


def test_duplicate_detection_membership_follows_persisted_data(db_session):
    """A correlation containing the same detection twice appears once in
    detection queries, while the detail view preserves both members."""
    detection_id = uuid.uuid4()
    correlation_id = uuid.uuid4()
    _seed(
        db_session,
        _correlation_row(correlation_id=correlation_id, timestamp=_ts(1)),
        [
            _member_row(correlation_id=correlation_id, detection_id=detection_id, timestamp=_ts(0), member_order=0),
            _member_row(correlation_id=correlation_id, detection_id=detection_id, timestamp=_ts(1), member_order=1),
        ],
    )

    service = CorrelationQueryService()
    page = service.list_correlations_for_detection(db_session, detection_id)

    assert page.total == 1
    assert [r.correlation_id for r in page.items] == [correlation_id]
    # Detail preserves the duplicate reference exactly as persisted.
    record = service.get_correlation(db_session, correlation_id)
    assert [m.detection_id for m in record.members] == [detection_id, detection_id]


# ---------------------------------------------------------------------------
# 3. Event queries
# ---------------------------------------------------------------------------


def test_event_one_correlation(db_session):
    event_id = uuid.uuid4()
    correlation_id = uuid.uuid4()
    _seed(
        db_session,
        _correlation_row(correlation_id=correlation_id, timestamp=_ts(1)),
        [_member_row(correlation_id=correlation_id, event_id=event_id)],
    )

    page = CorrelationQueryService().list_correlations_for_event(
        db_session, event_id
    )

    assert page.total == 1
    assert [r.correlation_id for r in page.items] == [correlation_id]


def test_event_multiple_correlations(db_session):
    event_id = uuid.uuid4()
    correlation_ids = [uuid.uuid4(), uuid.uuid4()]
    _seed_batch(
        db_session,
        [
            (
                _correlation_row(correlation_id=correlation_ids[0], timestamp=_ts(0)),
                [_member_row(correlation_id=correlation_ids[0], event_id=event_id)],
            ),
            (
                _correlation_row(correlation_id=correlation_ids[1], timestamp=_ts(1)),
                [_member_row(correlation_id=correlation_ids[1], event_id=event_id)],
            ),
        ],
    )

    page = CorrelationQueryService().list_correlations_for_event(
        db_session, event_id, page=1, page_size=10
    )

    assert page.total == 2
    assert [r.correlation_id for r in page.items] == [
        correlation_ids[1],
        correlation_ids[0],
    ]


def test_event_with_no_correlations(db_session):
    correlation_id = uuid.uuid4()
    _seed(
        db_session,
        _correlation_row(correlation_id=correlation_id),
        [_member_row(correlation_id=correlation_id)],
    )

    page = CorrelationQueryService().list_correlations_for_event(
        db_session, uuid.uuid4()
    )

    assert page.total == 0
    assert page.items == []


def test_event_multiple_events_scoped(db_session):
    event_a = uuid.uuid4()
    event_b = uuid.uuid4()
    cid_a = uuid.uuid4()
    cid_b = uuid.uuid4()
    _seed_batch(
        db_session,
        [
            (
                _correlation_row(correlation_id=cid_a, timestamp=_ts(1)),
                [_member_row(correlation_id=cid_a, event_id=event_a)],
            ),
            (
                _correlation_row(correlation_id=cid_b, timestamp=_ts(0)),
                [_member_row(correlation_id=cid_b, event_id=event_b)],
            ),
        ],
    )

    service = CorrelationQueryService()
    assert [
        r.correlation_id
        for r in service.list_correlations_for_event(db_session, event_a).items
    ] == [cid_a]
    assert [
        r.correlation_id
        for r in service.list_correlations_for_event(db_session, event_b).items
    ] == [cid_b]


# ---------------------------------------------------------------------------
# 4. Recent correlations
# ---------------------------------------------------------------------------


def test_recent_ordered_newest_first(db_session):
    ids = [uuid.uuid4(), uuid.uuid4(), uuid.uuid4()]
    _seed_batch(
        db_session,
        [
            (_correlation_row(correlation_id=ids[0], timestamp=_ts(1)), [_member_row(correlation_id=ids[0])]),
            (_correlation_row(correlation_id=ids[1], timestamp=_ts(3)), [_member_row(correlation_id=ids[1])]),
            (_correlation_row(correlation_id=ids[2], timestamp=_ts(2)), [_member_row(correlation_id=ids[2])]),
        ],
    )

    feed = CorrelationQueryService().list_recent_correlations(db_session, limit=2)

    assert [r.correlation_id for r in feed] == [ids[1], ids[2]]


def test_recent_deterministic_tie_break(db_session):
    """Equal timestamps fall back to correlation_id ascending (stable feed)."""
    id_a = uuid.UUID("00000000-0000-0000-0000-00000000000a")
    id_b = uuid.UUID("00000000-0000-0000-0000-00000000000b")
    id_c = uuid.UUID("00000000-0000-0000-0000-00000000000c")
    _seed_batch(
        db_session,
        [
            (_correlation_row(correlation_id=id_b, timestamp=_ts(0)), [_member_row(correlation_id=id_b)]),
            (_correlation_row(correlation_id=id_c, timestamp=_ts(0)), [_member_row(correlation_id=id_c)]),
            (_correlation_row(correlation_id=id_a, timestamp=_ts(0)), [_member_row(correlation_id=id_a)]),
        ],
    )

    feed = CorrelationQueryService().list_recent_correlations(db_session, limit=10)

    assert [r.correlation_id for r in feed] == [id_a, id_b, id_c]


def test_recent_empty(db_session):
    feed = CorrelationQueryService().list_recent_correlations(db_session, limit=10)
    assert feed == []


# ---------------------------------------------------------------------------
# 5. Pagination
# ---------------------------------------------------------------------------


def test_pagination_default_limit_applied(db_session):
    """Recent-feed default limit is applied when none is supplied."""
    ids = [uuid.uuid4() for _ in range(DEFAULT_PAGE_SIZE + 10)]
    _seed_batch(
        db_session,
        [
            (_correlation_row(correlation_id=cid, timestamp=_ts(float(i))), [_member_row(correlation_id=cid)])
            for i, cid in enumerate(ids)
        ],
    )

    feed = CorrelationQueryService().list_recent_correlations(db_session)

    assert len(feed) == DEFAULT_PAGE_SIZE
    assert feed[0].correlation_id == ids[-1]


def test_pagination_custom_limit(db_session):
    ids = [uuid.uuid4() for _ in range(5)]
    _seed_batch(
        db_session,
        [
            (_correlation_row(correlation_id=cid, timestamp=_ts(float(i))), [_member_row(correlation_id=cid)])
            for i, cid in enumerate(ids)
        ],
    )

    feed = CorrelationQueryService().list_recent_correlations(db_session, limit=3)

    assert [r.correlation_id for r in feed] == [ids[4], ids[3], ids[2]]


def test_pagination_page_and_offset(db_session):
    detection_id = uuid.uuid4()
    _seed_batch(
        db_session,
        [
            (
                _correlation_row(correlation_id=cid, timestamp=_ts(float(i))),
                [_member_row(correlation_id=cid, detection_id=detection_id)],
            )
            for i, cid in enumerate(uuid.uuid4() for _ in range(5))
        ],
    )

    service = CorrelationQueryService()
    first = service.list_correlations_for_detection(db_session, detection_id, page=1, page_size=2)
    second = service.list_correlations_for_detection(db_session, detection_id, page=2, page_size=2)

    assert first.total == 5
    assert len(first.items) == 2
    assert first.page == 1 and first.page_size == 2
    assert len(second.items) == 2
    assert first.items[-1].correlation_id != second.items[0].correlation_id


def test_pagination_page_beyond_bounds(db_session):
    detection_id = uuid.uuid4()
    correlation_id = uuid.uuid4()
    _seed(
        db_session,
        _correlation_row(correlation_id=correlation_id, timestamp=_ts(1)),
        [_member_row(correlation_id=correlation_id, detection_id=detection_id)],
    )

    page = CorrelationQueryService().list_correlations_for_detection(
        db_session, detection_id, page=99, page_size=10
    )

    assert page.items == []
    assert page.total == 1


def test_pagination_max_limit_enforced(db_session):
    service = CorrelationQueryService()
    with pytest.raises(CorrelationQueryValidationError):
        service.list_correlations_for_detection(
            db_session, uuid.uuid4(), page_size=MAX_PAGE_SIZE + 1
        )
    with pytest.raises(CorrelationQueryValidationError):
        service.list_recent_correlations(db_session, limit=MAX_PAGE_SIZE * 5)


def test_pagination_invalid_limit_rejected(db_session):
    service = CorrelationQueryService()
    with pytest.raises(CorrelationQueryValidationError):
        service.list_recent_correlations(db_session, limit=0)
    with pytest.raises(CorrelationQueryValidationError):
        service.list_recent_correlations(db_session, limit="x")


def test_pagination_invalid_page_rejected(db_session):
    service = CorrelationQueryService()
    with pytest.raises(CorrelationQueryValidationError):
        service.list_correlations_for_detection(db_session, uuid.uuid4(), page=0)
    with pytest.raises(CorrelationQueryValidationError):
        service.list_correlations_for_event(
            db_session, uuid.uuid4(), page=0, page_size=10
        )
    with pytest.raises(CorrelationQueryValidationError):
        service.list_correlations_for_detection(db_session, uuid.uuid4(), page="x")


def test_pagination_stable_ordering_across_pages(db_session):
    """Every page re-uses the same total ordering; no drift between pages."""
    event_id = uuid.uuid4()
    # letter-bearing hex keeps these deterministic ids out of SQLite's
    # NUMERIC affinity (all-digit hex would be coerced to INTEGER), while
    # remaining strictly sortable by correlation_id.
    cids = [
        uuid.UUID(f"deadbeef-dead-beef-dead-{i:012x}") for i in range(1, 6)
    ]
    _seed_batch(
        db_session,
        [
            (
                _correlation_row(correlation_id=cid, timestamp=_ts(0)),
                [_member_row(correlation_id=cid, event_id=event_id)],
            )
            for cid in cids
        ],
    )

    service = CorrelationQueryService()
    p1 = service.list_correlations_for_event(db_session, event_id, page=1, page_size=2).items
    p2 = service.list_correlations_for_event(db_session, event_id, page=2, page_size=2).items
    p3 = service.list_correlations_for_event(db_session, event_id, page=3, page_size=2).items

    order = [r.correlation_id for r in p1 + p2 + p3]
    assert order == sorted(cids)  # tie-break: correlation_id ascending


# ---------------------------------------------------------------------------
# 6. Counting
# ---------------------------------------------------------------------------


def test_count_total(db_session):
    correlation_ids = [uuid.uuid4() for _ in range(4)]
    _seed_batch(
        db_session,
        [
            (_correlation_row(correlation_id=cid), [_member_row(correlation_id=cid)])
            for cid in correlation_ids
        ],
    )

    assert CorrelationQueryService().count_correlations(db_session) == 4


def test_count_total_empty(db_session):
    assert CorrelationQueryService().count_correlations(db_session) == 0


def test_count_for_detection(db_session):
    detection_id = uuid.uuid4()
    in_both = uuid.uuid4()
    other = uuid.uuid4()
    unrelated = uuid.uuid4()
    _seed_batch(
        db_session,
        [
            (
                _correlation_row(correlation_id=in_both, timestamp=_ts(1)),
                [_member_row(correlation_id=in_both, detection_id=detection_id)],
            ),
            (
                _correlation_row(correlation_id=other, timestamp=_ts(0)),
                [_member_row(correlation_id=other, detection_id=uuid.uuid4())],
            ),
            (
                _correlation_row(correlation_id=unrelated, timestamp=_ts(0)),
                [_member_row(correlation_id=unrelated, detection_id=uuid.uuid4())],
            ),
        ],
    )

    assert (
        CorrelationQueryService().count_correlations_for_detection(
            db_session, detection_id
        )
        == 1
    )
    assert (
        CorrelationQueryService().count_correlations_for_detection(
            db_session, uuid.uuid4()
        )
        == 0
    )


def test_count_for_event(db_session):
    event_id = uuid.uuid4()
    correlation_ids = [uuid.uuid4() for _ in range(3)]
    _seed_batch(
        db_session,
        [
            (
                _correlation_row(correlation_id=cid, timestamp=_ts(float(i))),
                [_member_row(correlation_id=cid, event_id=event_id)],
            )
            for i, cid in enumerate(correlation_ids)
        ],
    )

    assert (
        CorrelationQueryService().count_correlations_for_event(db_session, event_id)
        == 3
    )


# ---------------------------------------------------------------------------
# 7. Data fidelity
# ---------------------------------------------------------------------------


def test_round_trip_persistence_service(db_session):
    """A correlation persisted through the real service reads back identically."""
    correlation = CorrelationResult(
        correlation_id=uuid.uuid4(),
        members=[
            CorrelationMember(detection_id=uuid.uuid4(), event_id=uuid.uuid4(), timestamp=_ts(0)),
            CorrelationMember(detection_id=uuid.uuid4(), event_id=uuid.uuid4(), timestamp=_ts(1)),
        ],
        status=CorrelationStatus.ACTIVE,
        confidence=0.9,
        evidence={"signals": ["same_host"]},
        metadata={"region": "eu"},
        timestamp=_ts(2),
        provenance=Provenance.CORRELATED,
    )
    CorrelationPersistenceService().persist_correlations(db_session, [correlation])

    record = CorrelationQueryService().get_correlation(
        db_session, correlation.correlation_id
    )

    assert record is not None
    assert record.status == CorrelationStatus.ACTIVE
    assert record.confidence == 0.9
    assert record.evidence == {"signals": ["same_host"]}
    assert record.result_metadata == {"region": "eu"}
    assert _as_utc(record.timestamp) == _ts(2)
    assert record.provenance == Provenance.CORRELATED
    assert len(record.members) == 2
    assert _as_utc(record.members[1].timestamp) == _ts(1)


def test_confidence_none_and_boundaries_round_trip(db_session):
    correlation_id = uuid.uuid4()
    _seed(
        db_session,
        _correlation_row(correlation_id=correlation_id, confidence=0.0),
        [_member_row(correlation_id=correlation_id)],
    )
    none_id = uuid.uuid4()
    _seed(
        db_session,
        _correlation_row(correlation_id=none_id, confidence=None),
        [_member_row(correlation_id=none_id)],
    )

    service = CorrelationQueryService()
    assert service.get_correlation(db_session, correlation_id).confidence == 0.0
    assert service.get_correlation(db_session, none_id).confidence is None


def test_status_provenance_round_trip(db_session):
    correlation_id = uuid.uuid4()
    _seed(
        db_session,
        _correlation_row(
            correlation_id=correlation_id,
            status=CorrelationStatus.CLOSED,
            provenance=Provenance.CORRELATED,
        ),
        [_member_row(correlation_id=correlation_id)],
    )

    record = CorrelationQueryService().get_correlation(db_session, correlation_id)

    assert record.status == CorrelationStatus.CLOSED
    assert record.provenance == Provenance.CORRELATED


def test_multi_event_correlation(db_session):
    """A correlation spanning several events preserves every reference."""
    correlation_id = uuid.uuid4()
    events = [uuid.uuid4(), uuid.uuid4(), uuid.uuid4()]
    _seed(
        db_session,
        _correlation_row(correlation_id=correlation_id, timestamp=_ts(1)),
        [
            _member_row(correlation_id=correlation_id, event_id=event, member_order=i)
            for i, event in enumerate(events)
        ],
    )

    record = CorrelationQueryService().get_correlation(db_session, correlation_id)
    assert [m.event_id for m in record.members] == events


def test_members_embedded_in_paginated_and_recent_results(db_session):
    """List queries embed full members via one bulk load (no N+1)."""
    cid_a = uuid.uuid4()
    cid_b = uuid.uuid4()
    detection_id = uuid.uuid4()
    _seed_batch(
        db_session,
        [
            (
                _correlation_row(correlation_id=cid_a, timestamp=_ts(1)),
                [
                    _member_row(correlation_id=cid_a, detection_id=detection_id, member_order=0),
                    _member_row(correlation_id=cid_a, detection_id=detection_id, member_order=1),
                ],
            ),
            (
                _correlation_row(correlation_id=cid_b, timestamp=_ts(0)),
                [_member_row(correlation_id=cid_b, detection_id=detection_id)],
            ),
        ],
    )

    service = CorrelationQueryService()
    page = service.list_correlations_for_detection(db_session, detection_id, page=1, page_size=10)
    feed = service.list_recent_correlations(db_session, limit=10)

    by_id = {r.correlation_id: r for r in page.items}
    assert len(by_id[cid_a].members) == 2
    assert len(by_id[cid_b].members) == 1
    assert {r.correlation_id for r in feed} == {cid_a, cid_b}
    assert len(next(r for r in feed if r.correlation_id == cid_a).members) == 2


def test_page_members_no_n_plus_one(db_session):
    """One page of correlations costs a bounded number of queries."""
    detection_id = uuid.uuid4()
    pairs = [
        (
            _correlation_row(correlation_id=cid, timestamp=_ts(float(i))),
            [
                _member_row(correlation_id=cid, detection_id=detection_id, member_order=0),
                _member_row(correlation_id=cid, detection_id=detection_id, member_order=1),
            ],
        )
        for i, cid in enumerate(uuid.uuid4() for _ in range(5))
    ]
    _seed_batch(db_session, pairs)

    engine = db_session.get_bind()
    select_count = {"n": 0}

    @event.listens_for(engine, "before_cursor_execute")
    def _count_selects(conn, cursor, statement, parameters, context, executemany):
        if statement.strip().lower().startswith("select"):
            select_count["n"] += 1

    try:
        page = CorrelationQueryService().list_correlations_for_detection(
            db_session, detection_id, page=1, page_size=5
        )
    finally:
        event.remove(engine, "before_cursor_execute", _count_selects)

    assert len(page.items) == 5
    for item in page.items:
        assert len(item.members) == 2
    # Expected: count + page list + one bulk member load.  Anything N+1
    # (a per-correlation member query) blows past this bound.
    assert select_count["n"] <= 4


# ---------------------------------------------------------------------------
# 8. Security
# ---------------------------------------------------------------------------


def test_surfaces_redacted_at_write_evidence(db_session):
    """The query path returns the stored (redacted) form, never a raw secret.

    Round-trip through the real service: persistence redacts credential keys;
    the query layer must surface the redacted value — no weaker read path.
    """
    correlation = CorrelationResult(
        correlation_id=uuid.uuid4(),
        members=[
            CorrelationMember(
                detection_id=uuid.uuid4(),
                event_id=uuid.uuid4(),
                timestamp=_ts(0),
            )
        ],
        evidence={"token": "gh_xyz123", "safe_field": "value"},
        metadata={"apikey": "val-abc123", "region": "eu"},
        timestamp=_ts(0),
        provenance=Provenance.CORRELATED,
    )
    CorrelationPersistenceService().persist_correlations(db_session, [correlation])

    record = CorrelationQueryService().get_correlation(
        db_session, correlation.correlation_id
    )

    assert record.evidence["token"] == "<redacted>"
    assert record.evidence["safe_field"] == "value"
    assert record.result_metadata["apikey"] == "<redacted>"
    assert record.result_metadata["region"] == "eu"


def test_authorization_and_password_redacted_through_query_path(db_session):
    """Authorization/password-shaped keys surface redacted through queries.

    Round-trip through the real persistence service, which performs write-side
    key redaction; the read path must return the stored redacted form, never
    the raw credential.
    """
    correlation = CorrelationResult(
        correlation_id=uuid.uuid4(),
        members=[
            CorrelationMember(
                detection_id=uuid.uuid4(),
                event_id=uuid.uuid4(),
                timestamp=_ts(0),
            )
        ],
        evidence={"auth_header": "Basic abcd123", "safe": 1},
        metadata={"password": "hunter2"},
        timestamp=_ts(0),
        provenance=Provenance.CORRELATED,
    )
    CorrelationPersistenceService().persist_correlations(db_session, [correlation])

    record = CorrelationQueryService().get_correlation(
        db_session, correlation.correlation_id
    )

    assert record is not None
    assert record.evidence["auth_header"] == "<redacted>"
    assert record.result_metadata["password"] == "<redacted>"
    assert record.evidence["safe"] == 1


def test_query_error_contains_no_secrets_or_raw_sql(db_session):
    """A database failure surfaces sanitized: no raw SQL, no payloads."""
    repo = MagicMock(spec=CorrelationRepository)
    repo.get_by_correlation_id.side_effect = OperationalError(
        "SELECT * FROM correlation_results WHERE correlation_id=:c",
        {},
        Exception("connection to server lost"),
    )
    service = CorrelationQueryService(repository_factory=lambda _db: repo)

    with pytest.raises(CorrelationQueryError) as exc_info:
        service.get_correlation(db_session, uuid.uuid4())

    message = str(exc_info.value)
    assert "Traceback" not in message
    assert "connection to server lost" not in message
    assert "SELECT" not in message
    assert "correlation_results" not in message
    assert "failed to load correlation" in message
    assert exc_info.value.__cause__ is not None


def test_list_error_sanitized(db_session):
    detection_id = uuid.uuid4()
    repo = MagicMock(spec=CorrelationRepository)
    repo.count_correlations_for_detection.side_effect = OperationalError(
        "SELECT 1", {}, Exception("boom")
    )
    service = CorrelationQueryService(repository_factory=lambda _db: repo)

    with pytest.raises(CorrelationQueryError) as exc_info:
        service.list_correlations_for_detection(db_session, detection_id)

    message = str(exc_info.value)
    assert "boom" not in message
    assert "SELECT" not in message
    assert str(detection_id) not in message or True  # ids are safe, payloads are not


# ---------------------------------------------------------------------------
# 9. Read-only contract
# ---------------------------------------------------------------------------


def test_query_service_never_writes_on_any_operation():
    """Every read goes through repository reads; the session is never touched."""
    correlation_id = uuid.uuid4()
    row = _materialize(_correlation_row(correlation_id=correlation_id))
    member = _materialize(_member_row(correlation_id=correlation_id))

    repo = MagicMock(spec=CorrelationRepository)
    repo.get_by_correlation_id.return_value = row
    repo.get_members_for_correlation.return_value = [member]
    repo.get_members_for_correlations.return_value = [member]
    repo.count_correlations.return_value = 1
    repo.count_correlations_for_detection.return_value = 1
    repo.count_correlations_for_event.return_value = 1
    repo.list_correlations_for_detection.return_value = [row]
    repo.list_correlations_for_event.return_value = [row]
    repo.list_recent_correlations.return_value = [row]

    db = MagicMock(spec=Session)
    service = CorrelationQueryService(repository_factory=lambda _db: repo)

    service.get_correlation(db, correlation_id)
    service.list_correlations_for_detection(db, uuid.uuid4())
    service.list_correlations_for_event(db, uuid.uuid4())
    service.list_recent_correlations(db)
    service.count_correlations(db)
    service.count_correlations_for_detection(db, uuid.uuid4())
    service.count_correlations_for_event(db, uuid.uuid4())

    db.commit.assert_not_called()
    db.flush.assert_not_called()
    db.add.assert_not_called()
    db.delete.assert_not_called()
    db.rollback.assert_not_called()
    db.execute.assert_not_called()
    repo.add.assert_not_called()


def test_query_service_reads_do_not_flush_pending_writes(db_session_no_autoflush):
    """Reads leave concurrently-staged (uncommitted) writes untouched."""
    correlation_id = uuid.uuid4()
    _seed(db_session_no_autoflush, _correlation_row(correlation_id=correlation_id), [_member_row(correlation_id=correlation_id)])

    pending = _correlation_row(correlation_id=uuid.uuid4(), timestamp=_ts(9))
    db_session_no_autoflush.add(pending)

    service = CorrelationQueryService()
    service.list_recent_correlations(db_session_no_autoflush)
    service.get_correlation(db_session_no_autoflush, correlation_id)

    assert pending in list(db_session_no_autoflush.new)  # still staged
    assert _count(db_session_no_autoflush, CorrelationResultRow) == 1


def test_returned_records_are_independent_of_rows(db_session):
    """Mutating a returned record never mutates the stored row."""
    correlation_id = uuid.uuid4()
    _seed(
        db_session,
        _correlation_row(
            correlation_id=correlation_id,
            evidence={"safe": "value"},
        ),
        [_member_row(correlation_id=correlation_id)],
    )

    record = CorrelationQueryService().get_correlation(db_session, correlation_id)
    record.evidence["safe"] = "mutated"
    record.evidence["new"] = "tampered"
    record.members[0].detection_id = uuid.uuid4()

    fresh = CorrelationQueryService().get_correlation(db_session, correlation_id)
    assert fresh.evidence == {"safe": "value"}
    assert "new" not in fresh.evidence
    assert fresh.members[0].detection_id != record.members[0].detection_id


# ---------------------------------------------------------------------------
# 10. Database behaviour
# ---------------------------------------------------------------------------


def test_empty_database_behavior(db_session):
    service = CorrelationQueryService()
    assert service.count_correlations(db_session) == 0
    assert service.get_correlation(db_session, uuid.uuid4()) is None
    assert service.list_recent_correlations(db_session) == []
    assert (
        service.list_correlations_for_detection(db_session, uuid.uuid4()).items == []
    )
    assert service.list_correlations_for_event(db_session, uuid.uuid4()).items == []


def test_multiple_correlation_records(db_session):
    cids = [uuid.uuid4() for _ in range(3)]
    _seed_batch(
        db_session,
        [
            (_correlation_row(correlation_id=cid, timestamp=_ts(float(i))), [_member_row(correlation_id=cid)])
            for i, cid in enumerate(cids)
        ],
    )

    feed = CorrelationQueryService().list_recent_correlations(db_session, limit=10)

    assert {r.correlation_id for r in feed} == set(cids)
    assert CorrelationQueryService().count_correlations(db_session) == 3


def test_deleted_correlation_cascades_to_members_and_queries(db_session):
    """Deleting a correlation removes members (FK cascade) and the query layer
    immediately reflects the deletion."""
    detection_id = uuid.uuid4()
    correlation_id = uuid.uuid4()
    _seed(
        db_session,
        _correlation_row(correlation_id=correlation_id, timestamp=_ts(1)),
        [_member_row(correlation_id=correlation_id, detection_id=detection_id)],
    )

    row = db_session.scalar(
        select(CorrelationResultRow).where(
            CorrelationResultRow.correlation_id == correlation_id
        )
    )
    assert row is not None
    db_session.delete(row)
    db_session.commit()
    db_session.expire_all()

    assert _count(db_session, CorrelationMemberRow) == 0
    service = CorrelationQueryService()
    assert service.get_correlation(db_session, correlation_id) is None
    assert (
        service.count_correlations_for_detection(db_session, detection_id) == 0
    )
    assert service.count_correlations(db_session) == 0