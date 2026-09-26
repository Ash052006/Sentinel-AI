"""Correlation persistence behavior tests (Step 10C).

Verifies that Step 10A :class:`~app.schemas.correlation.CorrelationResult`
objects are persisted through the service/repository layer into the Step
10C-A contract models
(:class:`~app.models.correlation_result.CorrelationResult`,
:class:`~app.models.correlation_member.CorrelationMember`).

No live PostgreSQL server is involved.  The PostgreSQL-specific ``JSONB``
column type is rendered as JSON for SQLite by installing a ``visit_JSONB``
visitor on the SQLite type compiler; all other column types work through
SQLAlchemy's generic type system.  Behavior is therefore tested end-to-end
against the same models and mapping code used in production.
"""

from __future__ import annotations

import copy
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.dialects.sqlite.base import SQLiteTypeCompiler
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

# Make the PostgreSQL ``JSONB`` columns work on SQLite for these unit tests.
# This is a test-only type-compiler adapter; production DDL keeps JSONB.
if not hasattr(SQLiteTypeCompiler, "visit_JSONB"):
    SQLiteTypeCompiler.visit_JSONB = lambda self, type_, **kw: "JSON"  # noqa: E731

from app.database.postgres.base import Base
from app.models.correlation_member import (
    CorrelationMember as CorrelationMemberRow,
)
from app.models.correlation_result import (
    CorrelationResult as CorrelationResultRow,
)
from app.repositories.correlation import CorrelationRepository
from app.schemas.correlation import (
    CorrelationMember,
    CorrelationResult,
    CorrelationStatus,
)
from app.schemas.security_event import Provenance
from app.services.correlation_persistence import (
    CorrelationPersistenceError,
    CorrelationPersistenceService,
    CorrelationPersistenceValidationError,
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
    # SQLite enforces foreign keys only when explicitly enabled.  This lets
    # the tests exercise FK cascade/rejection behavior that PostgreSQL
    # enforces natively.
    from sqlalchemy import text

    session.execute(text("PRAGMA foreign_keys=ON"))
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _member(
    *,
    detection_id: uuid.UUID | None = None,
    event_id: uuid.UUID | None = None,
    hours: float = 0.0,
) -> CorrelationMember:
    """Build one Step 10A member reference with deterministic scaffolding."""
    return CorrelationMember(
        detection_id=detection_id or uuid.uuid4(),
        event_id=event_id or uuid.uuid4(),
        timestamp=_ts(hours),
    )


def _correlation(
    *,
    correlation_id: uuid.UUID | None = None,
    members: list[CorrelationMember] | None = None,
    status: CorrelationStatus | None = None,
    confidence: float | None = None,
    evidence: dict | None = None,
    metadata: dict | None = None,
    hours: float = 0.0,
) -> CorrelationResult:
    """Build a :class:`CorrelationResult` schema object."""
    return CorrelationResult(
        correlation_id=correlation_id or uuid.uuid4(),
        members=members or [
            _member(hours=0),
            _member(hours=1),
        ],
        status=status or CorrelationStatus.CANDIDATE,
        confidence=confidence,
        evidence=evidence or {},
        metadata=metadata or {},
        timestamp=_ts(hours),
    )


def _persist(
    db: Session,
    results: list[CorrelationResult],
    *,
    service: CorrelationPersistenceService | None = None,
):
    """Persist *results* through the real service with a fixed clock."""
    sink = service or CorrelationPersistenceService(clock=lambda: _ts(1))
    return sink.persist_correlations(db, results)


def _all_correlations(db: Session) -> list[CorrelationResultRow]:
    return list(db.scalars(select(CorrelationResultRow)))


def _all_members(db: Session) -> list[CorrelationMemberRow]:
    return list(db.scalars(select(CorrelationMemberRow)))


def _count(db: Session, model) -> int:
    return db.scalar(select(func.count()).select_from(model))


# ---------------------------------------------------------------------------
# 1. Correlation persistence
# ---------------------------------------------------------------------------


def test_correlation_row_persisted_with_all_attributes(db_session):
    """A result maps to a fully-populated correlation_results row."""
    correlation_id = uuid.uuid4()
    event_id = uuid.uuid4()
    result = _correlation(
        correlation_id=correlation_id,
        members=[
            _member(hours=0),
            _member(event_id=event_id, hours=2),
        ],
        status="active",
        confidence=0.87,
        evidence={"signals": ["same_host"], "detection_ids": []},
        metadata={"region": "eu"},
        hours=3,
    )
    summary = _persist(db_session, [result])

    assert summary.correlations_created == 1
    assert summary.member_counts == (2,)
    assert not summary.is_empty

    rows = _all_correlations(db_session)
    assert len(rows) == 1
    row = rows[0]
    assert row.correlation_id == correlation_id
    assert row.status.value == "active"
    assert row.confidence == 0.87
    assert row.evidence["signals"] == ["same_host"]
    assert row.result_metadata["region"] == "eu"
    assert _as_utc(row.timestamp) == _ts(3)
    assert row.provenance == "correlated"


def test_members_persisted_as_references_in_order(db_session):
    """Every member persists in Step 10A member order as a reference."""
    correlation_id = uuid.uuid4()
    detection_ids = [uuid.uuid4(), uuid.uuid4()]
    event_id = uuid.uuid4()
    result = _correlation(
        correlation_id=correlation_id,
        members=[
            _member(detection_id=detection_ids[0], event_id=event_id, hours=0),
            _member(detection_id=detection_ids[1], event_id=event_id, hours=1),
        ],
    )
    _persist(db_session, [result])

    members = CorrelationRepository(db_session).get_members_for_correlation(
        correlation_id
    )
    assert len(members) == 2
    assert [m.member_order for m in members] == [0, 1]
    assert [m.detection_id for m in members] == detection_ids
    assert all(m.event_id == event_id for m in members)
    assert [m.correlation_id for m in members] == [correlation_id] * 2
    assert _as_utc(members[0].timestamp) == _ts(0)
    assert _as_utc(members[1].timestamp) == _ts(1)


def test_empty_result_list_persists_nothing(db_session):
    """An empty result set is a no-op that returns an empty summary."""
    summary = _persist(db_session, [])

    assert summary.is_empty
    assert summary.correlations_created == 0
    assert summary.correlations_skipped == 0
    assert summary.correlation_ids == ()
    assert _count(db_session, CorrelationResultRow) == 0
    assert _count(db_session, CorrelationMemberRow) == 0


def test_confidence_null_allowed(db_session):
    """A correlation without numeric confidence persists as NULL."""
    result = _correlation(confidence=None)
    _persist(db_session, [result])

    assert _all_correlations(db_session)[0].confidence is None


# ---------------------------------------------------------------------------
# 2. Provenance and database constraints (defense-in-depth)
# ---------------------------------------------------------------------------


def test_provenance_defaults_to_correlated(db_session):
    """Every persisted correlation row carries provenance 'correlated'."""
    _persist(db_session, [_correlation()])

    assert _all_correlations(db_session)[0].provenance == "correlated"


def test_provenance_check_blocks_non_correlated(db_session):
    """The DB CHECK constraint rejects any non-'correlated' provenance."""
    row = CorrelationResultRow(
        correlation_id=uuid.uuid4(),
        status="candidate",
        confidence=None,
        evidence={},
        result_metadata={},
        timestamp=_ts(0),
        provenance=Provenance.OBSERVED.value,
    )
    db_session.add(row)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_confidence_check_blocks_out_of_range(db_session):
    """The DB CHECK constraint rejects confidence outside [0.0, 1.0]."""
    row = CorrelationResultRow(
        correlation_id=uuid.uuid4(),
        status="candidate",
        confidence=1.5,
        evidence={},
        result_metadata={},
        timestamp=_ts(0),
        provenance=Provenance.CORRELATED.value,
    )
    db_session.add(row)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


# ---------------------------------------------------------------------------
# 3. Idempotency
# ---------------------------------------------------------------------------


def test_repersist_same_correlation_skips(db_session):
    """Re-persisting the same correlation_id is a no-op."""
    result = _correlation()
    first = _persist(db_session, [result])
    second = _persist(db_session, [result])

    assert first.correlations_created == 1
    assert second.correlations_created == 0
    assert second.correlations_skipped == 1
    assert second.correlation_ids == ()
    assert len(_all_correlations(db_session)) == 1
    assert len(_all_members(db_session)) == 2


def test_new_correlation_id_creates_new_historical_row(db_session):
    """A re-correlation with a fresh correlation_id is a new, kept row."""
    shared = uuid.uuid4()
    first = _persist(db_session, [_correlation(correlation_id=shared, hours=1)])
    second = _persist(db_session, [_correlation(hours=2)])

    assert first.correlations_created == 1
    assert second.correlations_created == 1
    rows = _all_correlations(db_session)
    assert len(rows) == 2
    assert {_as_utc(r.timestamp) for r in rows} == {
        _as_utc(_ts(1)),
        _as_utc(_ts(2)),
    }


def test_mixed_batch_persists_new_and_skips_existing(db_session):
    """A batch mixing known and unknown correlations works per-item."""
    known = _correlation()
    _persist(db_session, [known])
    fresh = _correlation()

    summary = _persist(db_session, [known, fresh])

    assert summary.correlations_created == 1
    assert summary.correlations_skipped == 1
    assert summary.correlation_ids == (fresh.correlation_id,)
    assert len(_all_correlations(db_session)) == 2


# ---------------------------------------------------------------------------
# 4. Structured-evidence secret filtering (defense-in-depth)
# ---------------------------------------------------------------------------


def test_evidence_sensitive_key_redacted(db_session):
    """Credential keys inside evidence are redacted before persistence."""
    result = _correlation(
        evidence={
            "signals": ["same_host"],
            "apiKey": "sk-abc123def456",
            "nested": {"token": "tok_xyz789", "reputation": 87},
        }
    )
    _persist(db_session, [result])

    evidence = _all_correlations(db_session)[0].evidence
    assert evidence["apiKey"] == "<redacted>"
    assert evidence["nested"]["token"] == "<redacted>"
    assert evidence["nested"]["reputation"] == 87
    assert evidence["signals"] == ["same_host"]


def test_metadata_sensitive_key_redacted(db_session):
    """Credential keys inside result_metadata are redacted too."""
    result = _correlation(
        metadata={
            "apikey": "val-abc123",
            "set_cookie": "sid=abc",
            "region": "eu",
        }
    )
    _persist(db_session, [result])

    metadata = _all_correlations(db_session)[0].result_metadata
    assert metadata["apikey"] == "<redacted>"
    assert metadata["set_cookie"] == "<redacted>"
    assert metadata["region"] == "eu"


def test_evidence_list_values_recursively_redacted(db_session):
    """Redaction recurses through lists inside evidence."""
    result = _correlation(
        evidence={"detections": [{"token": "gh_xyz123", "family": "emotet"}]}
    )
    _persist(db_session, [result])

    entry = _all_correlations(db_session)[0].evidence["detections"][0]
    assert entry["token"] == "<redacted>"
    assert entry["family"] == "emotet"


# ---------------------------------------------------------------------------
# 5. Validation and transaction ownership
# ---------------------------------------------------------------------------


def test_evidence_size_bound_raises_and_rolls_back(db_session):
    """Oversized evidence aborts the whole unit with no partial rows."""
    result = _correlation(evidence={"blob": "x" * 300_000})

    with pytest.raises(CorrelationPersistenceError) as exc_info:
        _persist(db_session, [result])

    assert isinstance(exc_info.value, CorrelationPersistenceValidationError)
    assert "evidence" in str(exc_info.value)
    assert exc_info.value.correlation_id == result.correlation_id
    # Transaction rolled back: nothing persisted by the failing unit.
    assert _count(db_session, CorrelationResultRow) == 0
    assert _count(db_session, CorrelationMemberRow) == 0


def test_non_result_item_raises_and_rolls_back(db_session):
    """A non-CorrelationResult item aborts the whole unit."""
    with pytest.raises(CorrelationPersistenceError) as exc_info:
        _persist(db_session, ["not-a-correlation"])  # type: ignore[arg-type]

    assert isinstance(exc_info.value, CorrelationPersistenceValidationError)
    assert "CorrelationResult" in str(exc_info.value)
    assert _count(db_session, CorrelationResultRow) == 0
    assert _count(db_session, CorrelationMemberRow) == 0


def test_database_error_rolls_back_and_raises_safe_error(db_session):
    """A real DB failure surfaces as a sanitized persistence error."""
    from sqlalchemy import text

    # Drop the table behind the session to force a deterministic DB error.
    db_session.execute(text("DROP TABLE correlation_results"))
    db_session.commit()

    result = _correlation()
    with pytest.raises(CorrelationPersistenceError) as exc_info:
        _persist(db_session, [result])

    assert "Traceback" not in str(exc_info.value)
    assert "correlation" in str(exc_info.value)


# ---------------------------------------------------------------------------
# 6. Repository query methods
# ---------------------------------------------------------------------------


def test_repository_does_not_commit(db_session):
    """The repository stages rows only; the caller owns the transaction."""
    repo = CorrelationRepository(db_session)
    repo.add(
        CorrelationResultRow(
            correlation_id=uuid.uuid4(),
            status="candidate",
            confidence=None,
            evidence={},
            result_metadata={},
            timestamp=_ts(0),
            provenance=Provenance.CORRELATED.value,
        )
    )
    db_session.rollback()
    assert _count(db_session, CorrelationResultRow) == 0


def test_get_by_correlation_id(db_session):
    """Repository looks up correlations by their unique correlation_id."""
    correlation_id = uuid.uuid4()
    _persist(db_session, [_correlation(correlation_id=correlation_id)])

    repo = CorrelationRepository(db_session)
    found = repo.get_by_correlation_id(correlation_id)
    assert found is not None
    assert found.correlation_id == correlation_id
    assert repo.get_by_correlation_id(uuid.uuid4()) is None


def test_get_members_for_correlation_returns_empty_for_unknown(db_session):
    """Unknown correlations return an empty member list."""
    repo = CorrelationRepository(db_session)
    assert repo.get_members_for_correlation(uuid.uuid4()) == []


# ---------------------------------------------------------------------------
# 7. Model & database constraints (defense-in-depth)
# ---------------------------------------------------------------------------


def test_correlation_id_null_rejected(db_session):
    """The correlation identity is a required, non-nullable column."""
    row = CorrelationResultRow(
        correlation_id=None,  # type: ignore[arg-type]
        status="candidate",
        confidence=None,
        evidence={},
        result_metadata={},
        timestamp=_ts(0),
        provenance=Provenance.CORRELATED.value,
    )
    db_session.add(row)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_invalid_status_rejected_by_persistence_service(db_session):
    """Status values outside candidate/active/closed are rejected at the
    persistence boundary — the schema's enum alone must not be the only
    gate (defense in depth against model_construct-style bypasses).
    """
    from types import SimpleNamespace

    result = CorrelationResult.model_construct(
        correlation_id=uuid.uuid4(),
        members=[
            SimpleNamespace(
                detection_id=uuid.uuid4(),
                event_id=uuid.uuid4(),
                timestamp=_ts(0),
            )
        ],
        status="malicious",
        confidence=None,
        evidence={},
        metadata={},
        timestamp=_ts(0),
        provenance=Provenance.CORRELATED,
    )

    with pytest.raises(CorrelationPersistenceError) as exc_info:
        _persist(db_session, [result])

    assert isinstance(exc_info.value, CorrelationPersistenceValidationError)
    assert "status" in str(exc_info.value)
    assert exc_info.value.correlation_id == result.correlation_id
    assert _count(db_session, CorrelationResultRow) == 0
    assert _count(db_session, CorrelationMemberRow) == 0


def test_duplicate_correlation_id_rejected_at_database(db_session):
    """The unique correlation_id constraint prevents duplicate records."""
    cid = uuid.uuid4()
    _persist(db_session, [_correlation(correlation_id=cid)])

    row = CorrelationResultRow(
        correlation_id=cid,
        status="candidate",
        confidence=None,
        evidence={},
        result_metadata={},
        timestamp=_ts(1),
        provenance=Provenance.CORRELATED.value,
    )
    db_session.add(row)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_duplicate_member_order_rejected_at_database(db_session):
    """Members of one correlation cannot share a member_order."""
    cid = uuid.uuid4()
    _persist(db_session, [_correlation(correlation_id=cid)])

    dup = CorrelationMemberRow(
        correlation_id=cid,
        detection_id=uuid.uuid4(),
        event_id=uuid.uuid4(),
        timestamp=_ts(0),
        member_order=0,
    )
    db_session.add(dup)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_members_cascade_with_parent_correlation(db_session):
    """Deleting a correlation removes its member rows (ON DELETE CASCADE)."""
    cid = uuid.uuid4()
    _persist(db_session, [_correlation(correlation_id=cid)])

    assert _count(db_session, CorrelationMemberRow) == 2
    repo = CorrelationRepository(db_session)
    db_session.delete(repo.get_by_correlation_id(cid))
    db_session.commit()

    assert _count(db_session, CorrelationResultRow) == 0
    assert _count(db_session, CorrelationMemberRow) == 0


def test_evidence_and_metadata_json_round_trip(db_session):
    """Structured evidence/metadata survive a JSON round-trip exactly."""
    evidence = {
        "signals": ["same_host"],
        "count": 3,
        "ratio": 0.5,
        "flag": True,
        "nothing": None,
        "nested": {"list": [1, 2], "text": "x"},
    }
    metadata = {"region": "eu", "tags": ["lambda"], "score": 1.25}
    result = _correlation(evidence=evidence, metadata=metadata)
    _persist(db_session, [result])

    row = _all_correlations(db_session)[0]
    assert row.evidence == evidence
    assert row.result_metadata == metadata


def test_timestamps_round_trip_timezone_aware(db_session):
    """Persisted timestamps keep their exact UTC instant.

    SQLite's DATETIME column type is naive; the documented ``_as_utc``
    helper treats those instants as UTC for comparison (production
    PostgreSQL stores tz-aware timestamptz).
    """
    correlation_ts = _ts(6)
    member_ts = _ts(5)
    cid = uuid.uuid4()
    result = _correlation(
        correlation_id=cid,
        members=[_member(hours=5)],
        hours=6,
    )
    _persist(db_session, [result])

    row = _all_correlations(db_session)[0]
    assert _as_utc(row.timestamp) == correlation_ts
    members = CorrelationRepository(db_session).get_members_for_correlation(cid)
    assert _as_utc(members[0].timestamp) == member_ts


# ---------------------------------------------------------------------------
# 8. Membership breadth
# ---------------------------------------------------------------------------


def test_single_member_correlation(db_session):
    """A correlation with one member persists fully."""
    result = _correlation(members=[_member()])
    summary = _persist(db_session, [result])

    assert summary.member_counts == (1,)
    assert len(_all_members(db_session)) == 1


def test_members_span_multiple_events(db_session):
    """Event references across several events are all preserved."""
    events = {uuid.uuid4(), uuid.uuid4(), uuid.uuid4()}
    result = _correlation(members=[_member(event_id=e) for e in events])
    _persist(db_session, [result])

    stored = {m.event_id for m in _all_members(db_session)}
    assert stored == events


def test_duplicate_detection_membership_preserved(db_session):
    """Duplicate detection references are preserved, not silently deduped.

    The Step 10A contract explicitly preserves duplicate membership; the
    persistence layer must faithfully store both references.
    """
    detection_id = uuid.uuid4()
    result = _correlation(
        members=[
            _member(detection_id=detection_id, hours=0),
            _member(detection_id=detection_id, hours=1),
        ]
    )
    _persist(db_session, [result])

    members = _all_members(db_session)
    assert len(members) == 2
    assert [m.detection_id for m in members] == [detection_id, detection_id]
    assert [m.member_order for m in members] == [0, 1]


# ---------------------------------------------------------------------------
# 9. Confidence boundaries
# ---------------------------------------------------------------------------


def test_confidence_boundaries_zero_and_one(db_session):
    """Confidence 0.0 and 1.0 are both valid persistence states."""
    result_0 = _correlation(confidence=0.0)
    result_1 = _correlation(confidence=1.0)
    _persist(db_session, [result_0, result_1])

    confidences = {row.confidence for row in _all_correlations(db_session)}
    assert confidences == {0.0, 1.0}


# ---------------------------------------------------------------------------
# 10. Idempotency edge: duplicate identity within one batch
# ---------------------------------------------------------------------------


def test_same_batch_duplicate_correlation_skipped(db_session):
    """Two identical correlation_ids in one call persist only the first."""
    result = _correlation()
    summary = _persist(db_session, [result, result])

    assert summary.correlations_created == 1
    assert summary.correlations_skipped == 1
    assert len(_all_correlations(db_session)) == 1
    assert len(_all_members(db_session)) == 2


# ---------------------------------------------------------------------------
# 11. Security: redaction breadth + no secrets in errors
# ---------------------------------------------------------------------------


def test_authorization_and_password_keys_redacted(db_session):
    """Authorization headers and passwords are redacted like other secrets.

    The Step 10A schema itself rejects these keys, so the service-level
    redaction is exercised through ``model_construct`` (schema bypass) to
    prove the persistence-boundary defense in depth.)
    """
    from types import SimpleNamespace

    result = CorrelationResult.model_construct(
        correlation_id=uuid.uuid4(),
        members=[
            SimpleNamespace(
                detection_id=uuid.uuid4(),
                event_id=uuid.uuid4(),
                timestamp=_ts(0),
            )
        ],
        status=CorrelationStatus.CANDIDATE,
        confidence=None,
        evidence={
            "Authorization": "Bearer abc.def.ghi",
            "password": "hunter2",
            "safe_field": "value",
        },
        metadata={},
        timestamp=_ts(0),
        provenance=Provenance.CORRELATED,
    )
    _persist(db_session, [result])

    evidence = _all_correlations(db_session)[0].evidence
    assert evidence["Authorization"] == "<redacted>"
    assert evidence["password"] == "<redacted>"
    assert evidence["safe_field"] == "value"


def test_persistence_error_does_not_leak_payload(db_session):
    """Exception text never contains evidence/metadata payload content."""
    result = _correlation(evidence={"blob": "x" * 300_000})

    with pytest.raises(CorrelationPersistenceError) as exc_info:
        _persist(db_session, [result])

    message = str(exc_info.value)
    assert "x" * 20 not in message
    assert len(message) < 200


def test_non_json_evidence_raises_validation_error(db_session):
    """Non-JSON-serializable evidence is a controlled validation failure.

    The Step 10A schema normally guarantees JSON-compatible evidence; this
    exercises the persistence-boundary defense-in-depth gate directly by
    constructing a ``CorrelationResult`` through ``model_construct``
    (which bypasses schema validation).
    """
    from types import SimpleNamespace

    result = CorrelationResult.model_construct(
        correlation_id=uuid.uuid4(),
        members=[
            SimpleNamespace(
                detection_id=uuid.uuid4(),
                event_id=uuid.uuid4(),
                timestamp=_ts(0),
            )
        ],
        status=CorrelationStatus.CANDIDATE,
        confidence=None,
        evidence={datetime.now(timezone.utc): "not-key-json"},
        metadata={},
        timestamp=_ts(0),
        provenance=Provenance.CORRELATED,
    )

    with pytest.raises(CorrelationPersistenceError) as exc_info:
        _persist(db_session, [result])

    assert isinstance(exc_info.value, CorrelationPersistenceValidationError)
    assert "JSON" in str(exc_info.value)
    assert _count(db_session, CorrelationResultRow) == 0


# ---------------------------------------------------------------------------
# 12. Immutability of the input contract
# ---------------------------------------------------------------------------


def test_input_correlation_not_mutated(db_session):
    """Persisting must not mutate the caller's CorrelationResult objects.

    Evidence/metadata are cloned through the redaction layer and members
    are only read; the schema objects (as built) must be bit-for-bit
    unchanged after persistence.
    """
    evidence = {
        "apiKey": "sk-abc123def456",
        "nested": {"token": "tok_xyz789", "ok": 1},
    }
    metadata = {"apikey": "val-abc123", "region": "eu"}
    members = [_member(), _member()]
    result = _correlation(evidence=evidence, metadata=metadata, members=members)

    evidence_before = copy.deepcopy(result.evidence)
    metadata_before = copy.deepcopy(result.metadata)
    members_before = [
        (m.detection_id, m.event_id, m.timestamp) for m in result.members
    ]

    _persist(db_session, [result])

    # Redaction happened on a clone: the original object still carries the
    # raw (unredacted) values the caller supplied.
    assert result.evidence == evidence_before
    assert result.evidence["apiKey"] == "sk-abc123def456"
    assert result.evidence["nested"]["token"] == "tok_xyz789"
    assert result.metadata == metadata_before
    assert result.metadata["apikey"] == "val-abc123"
    assert [
        (m.detection_id, m.event_id, m.timestamp) for m in result.members
    ] == members_before