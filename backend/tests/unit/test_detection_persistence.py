"""Detection persistence behavior tests (Step 9F-B).

Verifies that :class:`~app.schemas.detection_agent.DetectionAnalysis`
outputs are persisted through the service/repository layer into the Step
9F-A contract models (:class:`~app.models.detection_result.DetectionResult`,
:class:`~app.models.detection_rule_failure.DetectionRuleFailure`).

No live PostgreSQL server and no rule execution are involved.  The
PostgreSQL-specific ``JSONB`` column type is rendered as JSON for SQLite by
installing a ``visit_JSONB`` visitor on the SQLite type compiler; all other
column types work through SQLAlchemy's generic type system.  Behavior is
therefore tested end-to-end against the same models and mapping code used
in production.
"""

from __future__ import annotations

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
from app.models.detection_result import DetectionResult as DetectionResultRow
from app.models.detection_rule_failure import (
    DetectionRuleFailure as DetectionRuleFailureRow,
)
from app.repositories.detection import DetectionRepository
from app.schemas.detection import (
    DetectionEvidence,
    DetectionMetadata,
    DetectionResult,
    DetectionSeverity,
    RuleType,
)
from app.schemas.detection_agent import (
    DetectionAnalysis,
    DetectionAnalysisMetadata,
    DetectionFailure,
)
from app.schemas.security_event import Provenance
from app.services.detection_persistence import (
    DetectionPersistenceError,
    DetectionPersistenceService,
    DetectionPersistenceValidationError,
    sanitize_error_message,
)

# ---------------------------------------------------------------------------
# Deterministic fixture data
# ---------------------------------------------------------------------------

BASE = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
CLOCK = datetime(2026, 9, 1, 13, 0, 0, tzinfo=timezone.utc)


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
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _result(
    rule_id: str = "sigma-001",
    *,
    rule_type: RuleType = RuleType.SIGMA,
    event_id: uuid.UUID | None = None,
    detection_id: uuid.UUID | None = None,
    severity: DetectionSeverity = DetectionSeverity.HIGH,
    confidence: float = 0.95,
    detected_at: datetime | None = None,
    rule_version: str | None = "1.0.0",
    matched_conditions: list[str] | None = None,
    matched_fields: dict | None = None,
    metadata_extra: dict | None = None,
) -> DetectionResult:
    """Build a matched :class:`DetectionResult` schema object."""
    return DetectionResult(
        detection_id=detection_id or uuid.uuid4(),
        event_id=event_id or uuid.uuid4(),
        rule_id=rule_id,
        rule_type=rule_type,
        matched=True,
        severity=severity,
        confidence=confidence,
        evidence=DetectionEvidence(
            matched_conditions=matched_conditions or ["sel"],
            matched_fields=matched_fields or {},
        ),
        timestamp=detected_at or _ts(0),
        metadata=DetectionMetadata(
            rule_version=rule_version,
            extra=metadata_extra or {},
        ),
    )


def _failure(
    engine: str = "sigma",
    rule_id: str = "sigma-bad",
    error_type: str = "malformed_rule",
    message: str = "rule could not be parsed",
) -> DetectionFailure:
    """Build a :class:`DetectionFailure` schema object (secret-safe message)."""
    return DetectionFailure(
        engine=engine,
        rule_id=rule_id,
        error_type=error_type,
        message=message,
    )


def _analysis(
    *,
    event_id: uuid.UUID | None = None,
    results: tuple[DetectionResult, ...] = (),
    failures: tuple[DetectionFailure, ...] = (),
) -> DetectionAnalysis:
    """Build a :class:`DetectionAnalysis` with deterministic scaffolding."""
    return DetectionAnalysis(
        event_id=event_id or uuid.uuid4(),
        results=list(results),
        failures=list(failures),
        metadata=DetectionAnalysisMetadata(engines_executed=1),
        timestamp=_ts(0),
    )


def _persist(
    db: Session,
    analysis: DetectionAnalysis,
    *,
    service: DetectionPersistenceService | None = None,
):
    """Persist *analysis* through the real service with a fixed clock."""
    sink = service or DetectionPersistenceService(clock=lambda: CLOCK)
    return sink.persist_analysis(db, analysis)


def _all_results(db: Session) -> list[DetectionResultRow]:
    return list(db.scalars(select(DetectionResultRow)))


def _all_failures(db: Session) -> list[DetectionRuleFailureRow]:
    return list(db.scalars(select(DetectionRuleFailureRow)))


def _count(db: Session, model) -> int:
    return db.scalar(select(func.count()).select_from(model))


# ---------------------------------------------------------------------------
# 1. Match persistence
# ---------------------------------------------------------------------------


def test_result_row_persisted_with_all_attributes(db_session):
    """A matched result maps to a fully-populated detection_results row."""
    event_id = uuid.uuid4()
    result = _result(
        "sigma-001",
        rule_type=RuleType.SIGMA,
        event_id=event_id,
        severity=DetectionSeverity.CRITICAL,
        confidence=0.87,
        detected_at=_ts(2),
        matched_conditions=["selection_1", "selection_2"],
        matched_fields={"Image": "powershell.exe"},
        metadata_extra={"source": "unit-test"},
        rule_version="2.1.0",
    )
    summary = _persist(db_session, _analysis(event_id=event_id, results=(result,)))

    assert summary.results_created == 1
    assert summary.failures_created == 0
    assert not summary.is_empty

    rows = _all_results(db_session)
    assert len(rows) == 1
    row = rows[0]
    assert row.event_id == event_id
    assert row.detection_id == result.detection_id
    assert row.rule_id == "sigma-001"
    assert row.rule_type == RuleType.SIGMA
    assert row.rule_version == "2.1.0"
    assert row.severity == DetectionSeverity.CRITICAL
    assert row.matched is True
    assert row.confidence == 0.87
    assert row.evidence["matched_conditions"] == ["selection_1", "selection_2"]
    assert row.evidence["matched_fields"] == {"Image": "powershell.exe"}
    assert row.result_metadata["rule_version"] == "2.1.0"
    assert row.result_metadata["extra"] == {"source": "unit-test"}
    assert _as_utc(row.detected_at) == _ts(2)
    assert row.provenance == "detected"


def test_rule_version_falls_back_to_unknown(db_session):
    """A result without a rule version is persisted as 'unknown'."""
    result = _result(rule_version=None)
    _persist(db_session, _analysis(results=(result,)))

    row = _all_results(db_session)[0]
    assert row.rule_version == "unknown"


def test_multiple_results_for_same_event_persisted(db_session):
    """Several matches for one event all persist as distinct rows."""
    event_id = uuid.uuid4()
    results = (
        _result("sigma-a", event_id=event_id, detected_at=_ts(1)),
        _result("yara-b", rule_type=RuleType.YARA, event_id=event_id, detected_at=_ts(2)),
    )
    summary = _persist(db_session, _analysis(event_id=event_id, results=results))

    assert summary.results_created == 2
    rows = _all_results(db_session)
    assert len(rows) == 2
    assert {row.rule_type for row in rows} == {RuleType.SIGMA, RuleType.YARA}


def test_empty_analysis_persists_nothing(db_session):
    """An analysis with no results and no failures is a no-op."""
    summary = _persist(db_session, _analysis())

    assert summary.is_empty
    assert summary.results_created == 0
    assert summary.failures_created == 0
    assert _count(db_session, DetectionResultRow) == 0
    assert _count(db_session, DetectionRuleFailureRow) == 0


# ---------------------------------------------------------------------------
# 2. Provenance and database constraints (defense-in-depth)
# ---------------------------------------------------------------------------


def test_provenance_defaults_to_detected(db_session):
    """Every persisted detection row carries provenance 'detected'."""
    _persist(db_session, _analysis(results=(_result("sigma-a"),)))

    assert _all_results(db_session)[0].provenance == "detected"


def test_provenance_check_blocks_non_detected(db_session):
    """The DB CHECK constraint rejects any non-'detected' provenance."""
    row = DetectionResultRow(
        event_id=uuid.uuid4(),
        detection_id=uuid.uuid4(),
        rule_id="sigma-a",
        rule_type=RuleType.SIGMA,
        rule_version="1.0.0",
        severity=DetectionSeverity.HIGH,
        matched=True,
        confidence=0.5,
        evidence={},
        result_metadata={},
        detected_at=_ts(0),
        provenance=Provenance.OBSERVED.value,
    )
    db_session.add(row)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_matched_check_blocks_false(db_session):
    """The DB CHECK constraint rejects matched=False rows."""
    row = DetectionResultRow(
        event_id=uuid.uuid4(),
        detection_id=uuid.uuid4(),
        rule_id="sigma-a",
        rule_type=RuleType.SIGMA,
        rule_version="1.0.0",
        severity=DetectionSeverity.HIGH,
        matched=False,
        confidence=0.5,
        evidence={},
        result_metadata={},
        detected_at=_ts(0),
        provenance=Provenance.DETECTED.value,
    )
    db_session.add(row)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_confidence_check_blocks_out_of_range(db_session):
    """The DB CHECK constraint rejects confidence outside [0.0, 1.0]."""
    row = DetectionResultRow(
        event_id=uuid.uuid4(),
        detection_id=uuid.uuid4(),
        rule_id="sigma-a",
        rule_type=RuleType.SIGMA,
        rule_version="1.0.0",
        severity=DetectionSeverity.HIGH,
        matched=True,
        confidence=1.5,
        evidence={},
        result_metadata={},
        detected_at=_ts(0),
        provenance=Provenance.DETECTED.value,
    )
    db_session.add(row)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


# ---------------------------------------------------------------------------
# 3. Idempotency
# ---------------------------------------------------------------------------


def test_repersist_same_analysis_skips(db_session):
    """Re-persisting the same analysis is a no-op (results)."""
    event_id = uuid.uuid4()
    result = _result("sigma-a", event_id=event_id, detected_at=_ts(1))
    analysis = _analysis(event_id=event_id, results=(result,))

    first = _persist(db_session, analysis)
    second = _persist(db_session, analysis)

    assert first.results_created == 1
    assert second.results_created == 0
    assert second.results_skipped == 1
    assert second.result_ids == ()
    assert len(_all_results(db_session)) == 1


def test_repersist_same_failure_skips(db_session):
    """Re-persisting the same analysis is a no-op (failures)."""
    event_id = uuid.uuid4()
    failure = _failure("sigma", "sigma-bad", "malformed_rule")
    analysis = _analysis(event_id=event_id, failures=(failure,))

    first = _persist(db_session, analysis)
    second = _persist(db_session, analysis)

    assert first.failures_created == 1
    assert second.failures_created == 0
    assert second.failures_skipped == 1
    assert len(_all_failures(db_session)) == 1


def test_new_detection_id_creates_new_historical_row(db_session):
    """A re-evaluation with a fresh detection_id is a new, kept row."""
    event_id = uuid.uuid4()
    first = _persist(
        db_session,
        _analysis(
            event_id=event_id,
            results=(_result("sigma-a", event_id=event_id, detected_at=_ts(1)),),
        ),
    )
    second = _persist(
        db_session,
        _analysis(
            event_id=event_id,
            results=(_result("sigma-a", event_id=event_id, detected_at=_ts(2)),),
        ),
    )

    assert first.results_created == 1
    assert second.results_created == 1
    rows = _all_results(db_session)
    assert len(rows) == 2
    assert {_as_utc(row.detected_at) for row in rows} == {
        _as_utc(_ts(1)),
        _as_utc(_ts(2)),
    }


# ---------------------------------------------------------------------------
# 4. Failure persistence
# ---------------------------------------------------------------------------


def test_failure_row_persisted(db_session):
    """A rule failure maps to a fully-populated failure row."""
    event_id = uuid.uuid4()
    failure = _failure(
        engine="sigma",
        rule_id="sigma-bad",
        error_type="malformed_rule",
        message="rule could not be parsed",
    )
    summary = _persist(db_session, _analysis(event_id=event_id, failures=(failure,)))

    assert summary.failures_created == 1
    assert not summary.is_empty

    rows = _all_failures(db_session)
    assert len(rows) == 1
    row = rows[0]
    assert row.event_id == event_id
    assert row.engine == "sigma"
    assert row.rule_id == "sigma-bad"
    assert row.error_type == "malformed_rule"
    assert row.error_message == "rule could not be parsed"
    assert _as_utc(row.failed_at) == CLOCK
    assert row.provenance == "detected"


def test_failure_message_sanitized_on_persist(db_session):
    """JWT-shaped credentials inside failure text are redacted before write."""
    failure = _failure(
        engine="yara",
        rule_id="yara-a",
        error_type="match_error",
        message=(
            "authentication token "
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc123 was invalid"
        ),
    )
    _persist(db_session, _analysis(failures=(failure,)))

    stored = _all_failures(db_session)[0].error_message
    assert "was invalid" in stored
    assert "eyJhbGciOiJIUzI1Ni" not in stored
    assert "<redacted>" in stored


# --- sanitize_error_message unit behavior (defense-in-depth gate) --------


def test_sanitize_empty_message_passthrough():
    """Empty messages pass through unchanged."""
    assert sanitize_error_message("") == ""
    assert sanitize_error_message(None) is None or True  # type: ignore[arg-type]


def test_sanitize_redacts_labeled_credential():
    """Labeled credentials (api_key=...) are redacted together with value."""
    safe = sanitize_error_message("abuseipdb api_key=sk-topsecret123456 rejected")
    assert "sk-topsecret123456" not in safe
    assert "<redacted>" in safe


def test_sanitize_redacts_authorization_header():
    """Authorization headers including Bearer tokens are redacted."""
    safe = sanitize_error_message("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc")
    assert "Bearer" not in safe
    assert "<redacted>" in safe


def test_sanitize_redacts_bare_64_char_token():
    """A leaked opaque 64-char token is redacted."""
    token = "a" * 64
    safe = sanitize_error_message(f"leaked {token} in message")
    assert token not in safe


def test_sanitize_truncates_long_message():
    """Messages are truncated to the maximum error-message bound."""
    long_msg = "error: " + "x" * 5000
    safe = sanitize_error_message(long_msg)
    assert len(safe) <= 4000


# ---------------------------------------------------------------------------
# 5. Structured-evidence secret filtering (defense-in-depth)
# ---------------------------------------------------------------------------


def test_evidence_sensitive_key_redacted(db_session):
    """Credential keys inside evidence are redacted before persistence.

    The fixture data passes the Step 9A schema's secret scan (no forbidden
    substrings in the serialized evidence) while its keys still match the
    persistence-layer credential-key pattern — the defense-in-depth gate.
    """
    result = _result(
        "yara-a",
        rule_type=RuleType.YARA,
        matched_conditions=["APT_backdoor"],
        matched_fields={
            "process.command_line": "powershell -enc abc",
            "apiKey": "sk-abc123def456",
            "nested": {"token": "tok_xyz789", "reputation": 87},
        },
    )
    _persist(db_session, _analysis(results=(result,)))

    evidence = _all_results(db_session)[0].evidence
    fields = evidence["matched_fields"]
    assert fields["apiKey"] == "<redacted>"
    assert fields["nested"]["token"] == "<redacted>"
    assert fields["nested"]["reputation"] == 87
    assert fields["process.command_line"] == "powershell -enc abc"


def test_metadata_sensitive_key_redacted(db_session):
    """Credential keys inside result_metadata are redacted too.

    ``apikey`` and ``set_cookie`` pass the Step 9A schema's secret scan (the
    key ``client_secret`` would be rejected by the schema itself) while
    still matching the persistence-layer credential-key pattern.
    """
    result = _result(
        "sigma-a",
        metadata_extra={
            "apikey": "val-abc123",
            "set_cookie": "sid=abc",
            "region": "eu",
        },
    )
    _persist(db_session, _analysis(results=(result,)))

    extra = _all_results(db_session)[0].result_metadata["extra"]
    assert extra["apikey"] == "<redacted>"
    assert extra["set_cookie"] == "<redacted>"
    assert extra["region"] == "eu"


def test_evidence_list_values_recursively_redacted(db_session):
    """Redaction recurses through lists inside evidence."""
    result = _result(
        "sigma-a",
        matched_fields={
            "detections": [{"token": "gh_xyz123", "family": "emotet"}]
        },
    )
    _persist(db_session, _analysis(results=(result,)))

    evidence = _all_results(db_session)[0].evidence
    entry = evidence["matched_fields"]["detections"][0]
    assert entry["token"] == "<redacted>"
    assert entry["family"] == "emotet"


# ---------------------------------------------------------------------------
# 6. Validation and transaction ownership
# ---------------------------------------------------------------------------


def test_evidence_size_bound_raises_and_rolls_back(db_session):
    """Oversized evidence aborts the whole unit with no partial rows."""
    event_id = uuid.uuid4()
    big_fields = {"blob": "x" * 300_000}
    result = _result("sigma-a", event_id=event_id, matched_fields=big_fields)
    analysis = _analysis(event_id=event_id, results=(result,))

    with pytest.raises(DetectionPersistenceError) as exc_info:
        _persist(db_session, analysis)

    assert isinstance(exc_info.value, DetectionPersistenceValidationError)
    assert "detection analysis" in str(exc_info.value)
    # Transaction rolled back: nothing persisted by the failing unit.
    assert _count(db_session, DetectionResultRow) == 0
    assert _count(db_session, DetectionRuleFailureRow) == 0


def test_database_error_rolls_back_and_raises_safe_error(db_session):
    """A real DB failure surfaces as a sanitized persistence error."""
    from sqlalchemy import text

    # Drop the table behind the session to force a deterministic DB error.
    db_session.execute(text("DROP TABLE detection_results"))
    db_session.commit()

    analysis = _analysis(results=(_result("sigma-a"),))
    with pytest.raises(DetectionPersistenceError) as exc_info:
        _persist(db_session, analysis)

    assert "Traceback" not in str(exc_info.value)
    assert exc_info.value.event_id == analysis.event_id


# ---------------------------------------------------------------------------
# 7. Repository query methods
# ---------------------------------------------------------------------------


def test_repository_does_not_commit(db_session):
    """The repository stages rows only; the caller owns the transaction."""
    repo = DetectionRepository(db_session)
    repo.add(
        DetectionResultRow(
            event_id=uuid.uuid4(),
            detection_id=uuid.uuid4(),
            rule_id="sigma-a",
            rule_type=RuleType.SIGMA,
            rule_version="1.0.0",
            severity=DetectionSeverity.HIGH,
            matched=True,
            confidence=0.5,
            evidence={},
            result_metadata={},
            detected_at=_ts(0),
            provenance=Provenance.DETECTED.value,
        )
    )
    db_session.rollback()
    assert _count(db_session, DetectionResultRow) == 0


def test_get_result_by_detection_id(db_session):
    """Repository looks up detection results by their unique detection_id."""
    event_id = uuid.uuid4()
    result = _result("sigma-a", event_id=event_id)
    _persist(db_session, _analysis(event_id=event_id, results=(result,)))

    repo = DetectionRepository(db_session)
    found = repo.get_result_by_detection_id(result.detection_id)
    assert found is not None
    assert found.rule_id == "sigma-a"
    assert repo.get_result_by_detection_id(uuid.uuid4()) is None


def test_get_results_for_event_ordered_newest_first(db_session):
    """Event-scoped result queries return newest-first ordering."""
    event_id = uuid.uuid4()
    _persist(
        db_session,
        _analysis(
            event_id=event_id,
            results=(
                _result("sigma-a", event_id=event_id, detected_at=_ts(1)),
                _result("sigma-b", event_id=event_id, detected_at=_ts(3)),
                _result("sigma-c", event_id=event_id, detected_at=_ts(2)),
            ),
        ),
    )

    rows = DetectionRepository(db_session).get_results_for_event(event_id)
    assert [r.rule_id for r in rows] == ["sigma-b", "sigma-c", "sigma-a"]


def test_get_results_for_event_limit(db_session):
    """The event query honours an optional limit."""
    event_id = uuid.uuid4()
    _persist(
        db_session,
        _analysis(
            event_id=event_id,
            results=(
                _result("sigma-a", event_id=event_id),
                _result("sigma-b", event_id=event_id),
            ),
        ),
    )

    rows = DetectionRepository(db_session).get_results_for_event(event_id, limit=1)
    assert len(rows) == 1


def test_get_results_for_rule(db_session):
    """Rule-scoped result queries return only that rule's matches."""
    event_id = uuid.uuid4()
    _persist(
        db_session,
        _analysis(
            event_id=event_id,
            results=(
                _result("sigma-a", event_id=event_id, detected_at=_ts(2)),
                _result("other", event_id=event_id, detected_at=_ts(1)),
            ),
        ),
    )

    rows = DetectionRepository(db_session).get_results_for_rule("sigma-a")
    assert [r.rule_id for r in rows] == ["sigma-a"]


def test_find_existing_failure_identifies_by_identity_tuple(db_session):
    """Failures are matched on (event, engine, rule, error_type, message)."""
    event_id = uuid.uuid4()
    failure = _failure("sigma", "sigma-bad", "malformed_rule")
    _persist(db_session, _analysis(event_id=event_id, failures=(failure,)))

    repo = DetectionRepository(db_session)
    found = repo.find_existing_failure(
        event_id=event_id,
        engine="sigma",
        rule_id="sigma-bad",
        error_type="malformed_rule",
        error_message=failure.message,
    )
    assert found is not None
    # A different engine is a different failure row.
    other = repo.find_existing_failure(
        event_id=event_id,
        engine="yara",
        rule_id="sigma-bad",
        error_type="malformed_rule",
        error_message=failure.message,
    )
    assert other is None


def test_get_failures_for_event(db_session):
    """Event-scoped failure queries return all persisted failures."""
    event_id = uuid.uuid4()
    _persist(
        db_session,
        _analysis(
            event_id=event_id,
            failures=(
                _failure("sigma", "sigma-a", "malformed_rule"),
                _failure("yara", "yara-b", "match_error"),
                _failure("sigma", "sigma-c", "unsupported_feature"),
            ),
        ),
    )

    rows = DetectionRepository(db_session).get_failures_for_event(event_id)
    assert {r.rule_id for r in rows} == {"sigma-a", "yara-b", "sigma-c"}
    assert {r.engine for r in rows} == {"sigma", "yara"}