"""Detection query layer behavior tests (Step 9G).

Verifies the read-only retrieval layer
(:class:`~app.services.detection_query.DetectionQueryService` and the
:class:`~app.repositories.detection.DetectionRepository` read methods) over
rows produced by the Step 9F pipeline.

The query layer is read-only: these tests additionally assert that reads
never commit, flush, or stage writes, and that database failures surface as
sanitized :class:`DetectionQueryError` values with no raw driver/SQL text.

Same harness as Step 9F: in-memory SQLite with the PostgreSQL ``JSONB``
column rendered as ``JSON`` via a test-only type-compiler visitor.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.dialects.sqlite.base import SQLiteTypeCompiler
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

# Make the PostgreSQL ``JSONB`` columns work on SQLite for these tests.
if not hasattr(SQLiteTypeCompiler, "visit_JSONB"):
    SQLiteTypeCompiler.visit_JSONB = lambda self, type_, **kw: "JSON"  # noqa: E731

from app.database.postgres.base import Base
from app.models.detection_result import DetectionResult as DetectionResultRow
from app.models.detection_rule_failure import (
    DetectionRuleFailure as DetectionRuleFailureRow,
)
from app.repositories.detection import (
    DetectionRepository,
    FailuresOverview,
    ResultsOverview,
)
from app.schemas.detection import (
    DetectionEvidence,
    DetectionMetadata,
    DetectionSeverity,
    RuleType,
)
from app.schemas.detection_agent import (
    DetectionAnalysis,
    DetectionFailure,
    DetectionResult as DetectionResultContract,
)
from app.schemas.security_event import Provenance
from app.services.detection_persistence import DetectionPersistenceService
from app.services.detection_query import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    DetectionQueryError,
    DetectionQueryService,
    DetectionQueryValidationError,
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


def _result_row(
    *,
    event_id: uuid.UUID,
    detection_id: uuid.UUID | None = None,
    rule_id: str = "sigma-a",
    rule_type: RuleType = RuleType.SIGMA,
    rule_version: str = "1.0.0",
    severity: DetectionSeverity = DetectionSeverity.HIGH,
    confidence: float = 0.8,
    evidence: dict | None = None,
    result_metadata: dict | None = None,
    detected_at: datetime | None = None,
):
    """Build a detection_results row (not yet persisted)."""
    return DetectionResultRow(
        event_id=event_id,
        detection_id=detection_id or uuid.uuid4(),
        rule_id=rule_id,
        rule_type=rule_type,
        rule_version=rule_version,
        severity=severity,
        matched=True,
        confidence=confidence,
        evidence=evidence if evidence is not None else {},
        result_metadata=result_metadata if result_metadata is not None else {},
        detected_at=detected_at or _ts(0),
        provenance=Provenance.DETECTED.value,
    )


def _failure_row(
    *,
    event_id: uuid.UUID,
    engine: str = "sigma",
    rule_id: str = "sigma-bad",
    error_type: str = "malformed_rule",
    error_message: str = "boom",
    failed_at: datetime | None = None,
):
    """Build a detection_rule_failures row (not yet persisted)."""
    return DetectionRuleFailureRow(
        event_id=event_id,
        engine=engine,
        rule_id=rule_id,
        error_type=error_type,
        error_message=error_message,
        failed_at=failed_at or _ts(0),
        provenance=Provenance.DETECTED.value,
    )


def _seed(db: Session, *rows) -> None:
    """Persist rows and reset the identity map (fresh reads afterwards)."""
    db.add_all(rows)
    db.commit()
    db.expire_all()


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
# 1. Single-result retrieval
# ---------------------------------------------------------------------------


def test_get_result_round_trip_through_persistence_service(db_session):
    """A persisted analysis is readable back as a complete record."""
    event_id = uuid.uuid4()
    result = DetectionResultContract(
        event_id=event_id,
        rule_id="sigma-alert",
        rule_type=RuleType.SIGMA,
        matched=True,
        severity=DetectionSeverity.CRITICAL,
        confidence=0.95,
        evidence=DetectionEvidence(
            matched_fields={"family": "emotet"},
            matched_conditions=["family == emotet"],
        ),
        timestamp=_ts(1.0),
        metadata=DetectionMetadata(rule_version="1.2.3"),
    )
    analysis = DetectionAnalysis(
        event_id=event_id, results=[result], timestamp=_ts(1.0)
    )
    DetectionPersistenceService().persist_analysis(db_session, analysis)

    record = DetectionQueryService().get_result(db_session, result.detection_id)

    assert record is not None
    assert record.detection_id == result.detection_id
    assert record.event_id == event_id
    assert record.rule_id == "sigma-alert"
    assert record.rule_type == RuleType.SIGMA
    assert record.rule_version == "1.2.3"
    assert record.severity == DetectionSeverity.CRITICAL
    assert record.matched is True
    assert record.confidence == 0.95
    assert record.evidence["matched_fields"]["family"] == "emotet"
    assert record.evidence["matched_conditions"] == ["family == emotet"]
    # The persisted result_metadata column mirrors the analysis metadata.
    assert record.result_metadata["rule_version"] == "1.2.3"
    assert _as_utc(record.detected_at) == _ts(1.0)
    assert record.provenance == Provenance.DETECTED


def test_get_result_unknown_detection_id_returns_none(db_session):
    _seed(db_session, _result_row(event_id=uuid.uuid4()))
    assert DetectionQueryService().get_result(db_session, uuid.uuid4()) is None


def test_get_result_accepts_string_uuid(db_session):
    row = _result_row(event_id=uuid.uuid4())
    _seed(db_session, row)
    record = DetectionQueryService().get_result(db_session, str(row.detection_id))
    assert record is not None
    assert record.detection_id == row.detection_id


def test_get_result_rejects_invalid_uuid_before_database(db_session):
    repo = MagicMock(spec=DetectionRepository)
    service = DetectionQueryService(repository_factory=lambda _db: repo)

    with pytest.raises(DetectionQueryValidationError):
        service.get_result(db_session, "not-a-uuid")

    repo.get_result_by_detection_id.assert_not_called()


# ---------------------------------------------------------------------------
# 2. Event-scoped result pages
# ---------------------------------------------------------------------------


def test_list_results_for_event_paginates_with_totals(db_session):
    event_id = uuid.uuid4()
    _seed(
        db_session,
        _result_row(event_id=event_id, rule_id="r1", detected_at=_ts(1)),
        _result_row(event_id=event_id, rule_id="r2", detected_at=_ts(2)),
        _result_row(event_id=event_id, rule_id="r3", detected_at=_ts(3)),
        _result_row(event_id=uuid.uuid4(), rule_id="other", detected_at=_ts(9)),
    )

    service = DetectionQueryService()
    first = service.list_results_for_event(db_session, event_id, page=1, page_size=2)
    second = service.list_results_for_event(db_session, event_id, page=2, page_size=2)

    assert first.total == 3
    assert first.page == 1 and first.page_size == 2
    assert [r.rule_id for r in first.items] == ["r3", "r2"]
    assert second.total == 3
    assert [r.rule_id for r in second.items] == ["r1"]


def test_list_results_for_event_deterministic_tie_break(db_session):
    """Equal detected_at falls back to detection_id ascending (stable pages)."""
    event_id = uuid.uuid4()
    detection_id_a = uuid.UUID("00000000-0000-0000-0000-00000000000a")
    detection_id_b = uuid.UUID("00000000-0000-0000-0000-00000000000b")
    detection_id_c = uuid.UUID("00000000-0000-0000-0000-00000000000c")
    _seed(
        db_session,
        _result_row(
            event_id=event_id, rule_id="r-a",
            detection_id=detection_id_b, detected_at=_ts(0),
        ),
        _result_row(
            event_id=event_id, rule_id="r-b",
            detection_id=detection_id_c, detected_at=_ts(0),
        ),
        _result_row(
            event_id=event_id, rule_id="r-c",
            detection_id=detection_id_a, detected_at=_ts(0),
        ),
    )

    page = DetectionQueryService().list_results_for_event(
        db_session, event_id, page=1, page_size=10
    )
    assert [r.rule_id for r in page.items] == ["r-c", "r-a", "r-b"]


def test_list_results_for_event_page_beyond_bounds(db_session):
    event_id = uuid.uuid4()
    _seed(db_session, _result_row(event_id=event_id, rule_id="r1", detected_at=_ts(1)))

    page = DetectionQueryService().list_results_for_event(
        db_session, event_id, page=99, page_size=10
    )
    assert page.items == []
    assert page.total == 1


def test_list_results_for_event_empty(db_session):
    page = DetectionQueryService().list_results_for_event(
        db_session, uuid.uuid4(), page=1, page_size=10
    )
    assert page.items == []
    assert page.total == 0


def test_pagination_parameters_validated(db_session):
    event_id = uuid.uuid4()
    service = DetectionQueryService()
    with pytest.raises(DetectionQueryValidationError):
        service.list_results_for_event(db_session, event_id, page=0)
    with pytest.raises(DetectionQueryValidationError):
        service.list_results_for_event(db_session, event_id, page_size=0)
    with pytest.raises(DetectionQueryValidationError):
        service.list_results_for_event(
            db_session, event_id, page_size=MAX_PAGE_SIZE + 1
        )
    with pytest.raises(DetectionQueryValidationError):
        service.list_results_for_event(db_session, event_id, page="x")
# ---------------------------------------------------------------------------
# 3. Rule-scoped pages and the recent feed
# ---------------------------------------------------------------------------


def test_list_results_for_rule_filters_and_totals(db_session):
    _seed(
        db_session,
        _result_row(event_id=uuid.uuid4(), rule_id="sigma-a", detected_at=_ts(1)),
        _result_row(event_id=uuid.uuid4(), rule_id="sigma-a", detected_at=_ts(2)),
        _result_row(event_id=uuid.uuid4(), rule_id="other", detected_at=_ts(3)),
    )

    page = DetectionQueryService().list_results_for_rule(
        db_session, "sigma-a", page=1, page_size=1
    )
    assert page.total == 2
    assert [r.rule_id for r in page.items] == ["sigma-a"]


def test_list_results_for_rule_validates_rule_id(db_session):
    service = DetectionQueryService()
    with pytest.raises(DetectionQueryValidationError):
        service.list_results_for_rule(db_session, "")
    with pytest.raises(DetectionQueryValidationError):
        service.list_results_for_rule(db_session, "   ")
    with pytest.raises(DetectionQueryValidationError):
        service.list_results_for_rule(db_session, "x" * 256)


def test_list_recent_results_bounded_newest_first(db_session):
    _seed(
        db_session,
        _result_row(event_id=uuid.uuid4(), rule_id="old", detected_at=_ts(1)),
        _result_row(event_id=uuid.uuid4(), rule_id="mid", detected_at=_ts(2)),
        _result_row(event_id=uuid.uuid4(), rule_id="new", detected_at=_ts(3)),
    )

    feed = DetectionQueryService().list_recent_results(db_session, limit=2)
    assert [r.rule_id for r in feed] == ["new", "mid"]


def test_list_recent_results_default_limit(db_session):
    rows = [
        _result_row(
            event_id=uuid.uuid4(),
            rule_id=f"r{i}",
            detected_at=_ts(float(i)),
        )
        for i in range(DEFAULT_PAGE_SIZE + 10)
    ]
    db_session.add_all(rows)
    db_session.commit()
    db_session.expire_all()

    feed = DetectionQueryService().list_recent_results(db_session)
    assert len(feed) == DEFAULT_PAGE_SIZE
    assert feed[0].rule_id == f"r{DEFAULT_PAGE_SIZE + 9}"


def test_list_recent_results_validates_limit(db_session):
    service = DetectionQueryService()
    with pytest.raises(DetectionQueryValidationError):
        service.list_recent_results(db_session, limit=0)
    with pytest.raises(DetectionQueryValidationError):
        service.list_recent_results(db_session, limit=DEFAULT_PAGE_SIZE * 5)


# ---------------------------------------------------------------------------
# 4. Failures for an event's analysis
# ---------------------------------------------------------------------------


def test_list_failures_for_analysis_paginates(db_session):
    event_id = uuid.uuid4()
    _seed(
        db_session,
        _failure_row(event_id=event_id, rule_id="f1", failed_at=_ts(1)),
        _failure_row(event_id=event_id, rule_id="f2", failed_at=_ts(2)),
        _failure_row(event_id=event_id, rule_id="f3", failed_at=_ts(3)),
    )

    page = DetectionQueryService().list_failures_for_analysis(
        db_session, event_id, page=1, page_size=2
    )
    assert page.total == 3
    assert [r.rule_id for r in page.items] == ["f3", "f2"]
    assert page.items[0].error_type == "malformed_rule"


def test_list_failures_for_analysis_empty(db_session):
    page = DetectionQueryService().list_failures_for_analysis(
        db_session, uuid.uuid4()
    )
    assert page.items == []
    assert page.total == 0
# ---------------------------------------------------------------------------
# 5. Event analysis views (summary + with children)
# ---------------------------------------------------------------------------


def test_get_analysis_summary_counts_and_windows(db_session):
    event_id = uuid.uuid4()
    _seed(
        db_session,
        _result_row(event_id=event_id, rule_id="r1", detected_at=_ts(1)),
        _result_row(event_id=event_id, rule_id="r2", detected_at=_ts(3)),
        _failure_row(event_id=event_id, rule_id="f1", failed_at=_ts(2)),
    )

    summary = DetectionQueryService().get_analysis(db_session, event_id)

    assert summary is not None
    assert summary.event_id == event_id
    assert summary.result_count == 2
    assert summary.failure_count == 1
    assert _as_utc(summary.first_detected_at) == _ts(1)
    assert _as_utc(summary.last_detected_at) == _ts(3)
    assert _as_utc(summary.first_failed_at) == _ts(2)
    assert _as_utc(summary.last_failed_at) == _ts(2)
    assert summary.provenance == Provenance.DETECTED


def test_get_analysis_returns_none_when_no_rows(db_session):
    assert DetectionQueryService().get_analysis(db_session, uuid.uuid4()) is None


def test_get_analysis_with_children_populates_records(db_session):
    event_id = uuid.uuid4()
    _seed(
        db_session,
        _result_row(event_id=event_id, rule_id="r1", detected_at=_ts(2)),
        _result_row(event_id=event_id, rule_id="r2", detected_at=_ts(1)),
        _failure_row(event_id=event_id, rule_id="f1"),
        # A different event must never leak into this event's view.
        _result_row(event_id=uuid.uuid4(), rule_id="other"),
    )

    view = DetectionQueryService().get_analysis_with_children(
        db_session, event_id
    )

    assert view is not None
    assert view.result_count == 2
    assert view.failure_count == 1
    assert [r.rule_id for r in view.results] == ["r1", "r2"]  # newest first
    assert [f.rule_id for f in view.failures] == ["f1"]
    assert _as_utc(view.last_detected_at) == _ts(2)


def test_get_analysis_with_children_returns_none_when_empty(db_session):
    assert (
        DetectionQueryService().get_analysis_with_children(db_session, uuid.uuid4())
        is None
    )


def test_get_analysis_with_children_no_n_plus_one(db_session):
    """Children are eager-loaded: two bulk queries, never one per child."""
    event_id = uuid.uuid4()
    results = [
        _result_row(
            event_id=event_id, rule_id=f"r{i}", detected_at=_ts(float(i))
        )
        for i in range(5)
    ]
    failures = [
        _failure_row(
            event_id=event_id, rule_id=f"f{i}", failed_at=_ts(float(i))
        )
        for i in range(5)
    ]
    _seed(db_session, *results, *failures)

    engine = db_session.get_bind()
    select_count = {"n": 0}

    @event.listens_for(engine, "before_cursor_execute")
    def _count_selects(conn, cursor, statement, parameters, context, executemany):
        if statement.strip().lower().startswith("select"):
            select_count["n"] += 1

    try:
        view = DetectionQueryService().get_analysis_with_children(
            db_session, event_id
        )
    finally:
        event.remove(engine, "before_cursor_execute", _count_selects)

    assert view is not None
    assert len(view.results) == 5
    assert len(view.failures) == 5
    # Expected statements: result overview + failure overview + result list +
    # failure list.  Anything N+1 (per-child query) blows past this bound.
    assert select_count["n"] <= 4
# ---------------------------------------------------------------------------
# 6. Read-only contract
# ---------------------------------------------------------------------------


def test_query_service_never_writes_on_any_operation():
    """Every read goes through repository reads; the session is never touched."""
    event_id = uuid.uuid4()
    row = _materialize(_result_row(event_id=event_id, rule_id="r1"))
    repo = MagicMock(spec=DetectionRepository)
    repo.get_result_by_detection_id.return_value = row
    repo.count_results_for_event.return_value = 1
    repo.get_results_for_event.return_value = [row]
    repo.count_results_for_rule.return_value = 1
    repo.get_results_for_rule.return_value = [row]
    repo.list_recent_results.return_value = [row]
    repo.count_failures_for_event.return_value = 0
    repo.get_failures_for_event.return_value = []
    repo.get_results_overview.return_value = ResultsOverview(
        count=1, first_detected_at=_ts(0), last_detected_at=_ts(0)
    )
    repo.get_failures_overview.return_value = FailuresOverview(count=0)

    db = MagicMock(spec=Session)
    service = DetectionQueryService(repository_factory=lambda _db: repo)

    service.get_result(db, uuid.uuid4())
    service.list_results_for_event(db, event_id)
    service.list_results_for_rule(db, "sigma-a")
    service.list_recent_results(db)
    service.list_failures_for_analysis(db, event_id)
    service.get_analysis(db, event_id)
    service.get_analysis_with_children(db, event_id)

    db.commit.assert_not_called()
    db.flush.assert_not_called()
    db.add.assert_not_called()
    db.rollback.assert_not_called()
    db.execute.assert_not_called()
    repo.add.assert_not_called()


def test_query_service_reads_do_not_flush_pending_writes(db_session_no_autoflush):
    """Reads leave concurrently-staged (uncommitted) writes untouched."""
    event_id = uuid.uuid4()
    _seed(db_session_no_autoflush, _result_row(event_id=event_id, rule_id="r1"))

    pending = _result_row(event_id=uuid.uuid4(), rule_id="pending")
    db_session_no_autoflush.add(pending)

    DetectionQueryService().list_results_for_event(
        db_session_no_autoflush, event_id, page=1, page_size=10
    )
    DetectionQueryService().get_analysis(db_session_no_autoflush, event_id)

    assert pending in list(db_session_no_autoflush.new)  # still staged
    assert _count(db_session_no_autoflush, DetectionResultRow) == 1


# ---------------------------------------------------------------------------
# 7. Sanitized failures
# ---------------------------------------------------------------------------


def test_database_error_sanitized(db_session):
    """Raw driver/SQL text never reaches the consumer-facing error."""
    repo = MagicMock(spec=DetectionRepository)
    repo.get_result_by_detection_id.side_effect = OperationalError(
        "SELECT * FROM detection_results", {}, Exception("connection to server lost")
    )
    service = DetectionQueryService(repository_factory=lambda _db: repo)

    with pytest.raises(DetectionQueryError) as exc_info:
        service.get_result(db_session, uuid.uuid4())

    message = str(exc_info.value)
    assert "Traceback" not in message
    assert "connection to server lost" not in message
    assert "SELECT" not in message
    assert "failed to load detection result" in message
    assert exc_info.value.__cause__ is not None


def test_analysis_query_error_carries_event_id(db_session):
    event_id = uuid.uuid4()
    repo = MagicMock(spec=DetectionRepository)
    repo.get_results_overview.side_effect = OperationalError(
        "x", {}, Exception("boom")
    )
    service = DetectionQueryService(repository_factory=lambda _db: repo)

    with pytest.raises(DetectionQueryError) as exc_info:
        service.get_analysis(db_session, event_id)

    assert exc_info.value.event_id == event_id
    assert str(event_id) in str(exc_info.value)
    assert "boom" not in str(exc_info.value)