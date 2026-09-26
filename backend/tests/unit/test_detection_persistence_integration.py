"""Detection pipeline integration tests (Step 9F-C).

Exercises the full Step 9E agent -> Step 9F persistence path:

    DetectionAgent.evaluate(event, persistence=...)
        -> DetectionAnalysis
        -> DetectionPersistenceService.persist_analysis(db, analysis)
            -> DetectionResult / DetectionRuleFailure (PostgreSQL)

The Sigma engine runs for real against a deterministic rule registry (no
network, no LLM).  The YARA engine is a deterministic fake (constructor
injection, exactly as the Step 9E suite does) so compilation state never
influences these tests.  Persistence runs through the *real*
:class:`DetectionPersistenceService` against an in-memory SQLite engine
with the PostgreSQL ``JSONB`` column rendered as ``JSON`` (the same
test-only type-compiler visitor the Step 8C-B suite uses).

These tests verify the new pipeline boundary introduced in Step 9F-C:

* a completed analysis is persisted through the injected sink,
* multiple results (Sigma and YARA) and rule/engine failures are all
  persisted with provenance ``detected``,
* a no-match analysis persists nothing,
* re-persisting the same analysis is a no-op,
* persistence failure is handled per the existing service conventions, and
* Step 9E behavior is unchanged when no persistence (or a mock) is supplied.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.dialects.sqlite.base import SQLiteTypeCompiler
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

# Make the PostgreSQL ``JSONB`` columns work on SQLite for these unit tests.
if not hasattr(SQLiteTypeCompiler, "visit_JSONB"):
    SQLiteTypeCompiler.visit_JSONB = lambda self, type_, **kw: "JSON"  # noqa: E731

from app.agents.detection import DetectionAgent, persist_analysis_bound
from app.database.postgres.base import Base
from app.models.detection_result import DetectionResult as DetectionResultRow
from app.models.detection_rule_failure import (
    DetectionRuleFailure as DetectionRuleFailureRow,
)
from app.schemas.detection import (
    DetectionEvidence,
    DetectionMetadata,
    DetectionResult,
    DetectionRule,
    DetectionSeverity,
    RuleType,
)
from app.schemas.detection_agent import DetectionAnalysis
from app.schemas.normalized_event import (
    EventCategory,
    EventOutcome,
    NormalizedSecurityEvent,
    ProcessInfo,
)
from app.schemas.security_event import Provenance, SourceType
from app.services.detection.registry import DetectionRuleRegistry
from app.services.detection.yara.engine import YaraDetectionReport
from app.services.detection_persistence import (
    DetectionPersistenceError,
    DetectionPersistenceService,
    DetectionPersistenceValidationError,
)

_FIXED_TS = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
_CLOCK_TS = datetime(2026, 9, 1, 13, 0, 0, tzinfo=timezone.utc)
_FIXED_EVENT_ID = uuid.UUID("bbbb2222-cccc-dddd-eeee-ffffffffffff")


# ---------------------------------------------------------------------------
# Deterministic fake YARA engine (no compilation, no network)
# ---------------------------------------------------------------------------


class FakeYaraEngine:
    """Deterministic YARA engine configured to succeed or explode."""

    def __init__(
        self,
        *,
        results: tuple[DetectionResult, ...] = (),
        failures: tuple = (),
        raise_error: Exception | None = None,
    ) -> None:
        self._results = list(results)
        self._failures = list(failures)
        self._raise_error = raise_error

    def evaluate(self, event, rules) -> YaraDetectionReport:
        if self._raise_error is not None:
            raise self._raise_error
        return YaraDetectionReport(
            results=self._results,
            failures=self._failures,
            rules_total=len(self._results) + len(self._failures),
            rules_evaluated=len(self._results),
            rules_ignored=0,
            evaluated_rule_ids=tuple(r.rule_id for r in self._results),
            target_event_id=event.event_id,
        )


# ---------------------------------------------------------------------------
# Deterministic fixtures
# ---------------------------------------------------------------------------


def _event(
    *,
    event_id: uuid.UUID | None = None,
    process: ProcessInfo | None = None,
) -> NormalizedSecurityEvent:
    """Create a normalised process event with optional process details."""
    return NormalizedSecurityEvent(
        event_id=event_id or _FIXED_EVENT_ID,
        timestamp=_FIXED_TS,
        event_category=EventCategory.PROCESS,
        action="process_create",
        outcome=EventOutcome.SUCCESS,
        source="windows-sysmon",
        source_type=SourceType.OPERATING_SYSTEM,
        process=process,
        normalized_data={},
        provenance=Provenance.OBSERVED,
    )


def _sigma_match_event() -> NormalizedSecurityEvent:
    """Event that matches a Sigma rule on Image == powershell.exe."""
    return _event(
        process=ProcessInfo(
            name="ps",
            executable="powershell.exe",
            command_line="powershell -enc AQ==",
            pid=123,
        ),
    )


def _sigma_content(*, detection: dict | None = None) -> dict:
    if detection is None:
        detection = {"sel": {"Image": "powershell.exe"}, "condition": "sel"}
    return {
        "title": "PowerShell exec",
        "id": str(uuid.uuid4()),
        "status": "test",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": detection,
        "level": "high",
    }


def _sigma_rule(
    rule_id: str = "sigma-match",
    *,
    severity: DetectionSeverity = DetectionSeverity.HIGH,
    content: dict | None = None,
) -> DetectionRule:
    if content is None:
        content = _sigma_content()
    return DetectionRule(
        rule_id=rule_id,
        name=f"Rule {rule_id}",
        description=f"Detects {rule_id}",
        rule_type=RuleType.SIGMA,
        severity=severity,
        enabled=True,
        version="1.0.0",
        content=content,
    )


def _yara_match_result(detection_id: uuid.UUID | None = None) -> DetectionResult:
    """Deterministic YARA result with a fixed detection_id by default."""
    return DetectionResult(
        detection_id=detection_id or uuid.UUID("cccc3333-dddd-eeee-ffff-000000000001"),
        event_id=_FIXED_EVENT_ID,
        rule_id="yara-apt-backdoor",
        rule_type=RuleType.YARA,
        matched=True,
        severity=DetectionSeverity.CRITICAL,
        confidence=0.8,
        evidence=DetectionEvidence(matched_conditions=["APT_backdoor"]),
        timestamp=_FIXED_TS,
        metadata=DetectionMetadata(rule_version="2.0.0"),
    )


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


def _count(db: Session, model) -> int:
    return db.scalar(select(func.count()).select_from(model))


def _all_results(db: Session) -> list[DetectionResultRow]:
    return list(db.scalars(select(DetectionResultRow)))


def _all_failures(db: Session) -> list[DetectionRuleFailureRow]:
    return list(db.scalars(select(DetectionRuleFailureRow)))


# ---------------------------------------------------------------------------
# A. Agent -> real Sigma engine -> persistence
# ---------------------------------------------------------------------------


def test_sigma_match_persisted_through_agent(db_session):
    """A real Sigma match flows from the agent into detection_results."""
    registry = DetectionRuleRegistry([_sigma_rule("sigma-match")])
    agent = DetectionAgent(registry=registry, yara_engine=FakeYaraEngine())
    service = DetectionPersistenceService(clock=lambda: _CLOCK_TS)
    persist = persist_analysis_bound(db_session, service=service)

    analysis = agent.evaluate(_sigma_match_event(), clock=_FIXED_TS, persistence=persist)

    assert isinstance(analysis, DetectionAnalysis)
    assert len(analysis.results) == 1
    assert len(analysis.failures) == 0
    assert analysis.results[0].rule_id == "sigma-match"

    rows = _all_results(db_session)
    assert len(rows) == 1
    row = rows[0]
    assert row.event_id == _FIXED_EVENT_ID
    assert row.rule_id == "sigma-match"
    assert row.rule_type.value == "sigma"
    assert row.severity.value == "high"
    assert row.matched is True
    assert row.provenance == "detected"
    assert row.evidence["matched_conditions"] == ["sel"]
    assert _count(db_session, DetectionRuleFailureRow) == 0


def test_sigma_and_yara_results_both_persisted(db_session):
    """Both engines' matches persist with their own rule types."""
    registry = DetectionRuleRegistry([_sigma_rule("sigma-match")])
    yara_result = _yara_match_result()
    agent = DetectionAgent(
        registry=registry,
        yara_engine=FakeYaraEngine(results=(yara_result,)),
    )
    persist = persist_analysis_bound(db_session, service=DetectionPersistenceService())

    analysis = agent.evaluate(_sigma_match_event(), clock=_FIXED_TS, persistence=persist)

    assert len(analysis.results) == 2
    rows = _all_results(db_session)
    assert len(rows) == 2
    assert {row.rule_id for row in rows} == {"sigma-match", "yara-apt-backdoor"}
    assert {row.rule_type.value for row in rows} == {"sigma", "yara"}
    yara_row = next(r for r in rows if r.rule_id == "yara-apt-backdoor")
    assert yara_row.rule_version == "2.0.0"
    assert yara_row.severity.value == "critical"


def test_no_match_persists_nothing(db_session):
    """A clean no-match evaluation persists no rows."""
    no_match_content = _sigma_content(
        detection={"sel": {"Image": "definitely_not_present.exe"}, "condition": "sel"}
    )
    registry = DetectionRuleRegistry(
        [_sigma_rule("sigma-nomatch", content=no_match_content)]
    )
    agent = DetectionAgent(registry=registry, yara_engine=FakeYaraEngine())
    persist = persist_analysis_bound(db_session, service=DetectionPersistenceService())

    analysis = agent.evaluate(_event(), clock=_FIXED_TS, persistence=persist)

    assert analysis.results == []
    assert analysis.failures == []
    assert _count(db_session, DetectionResultRow) == 0
    assert _count(db_session, DetectionRuleFailureRow) == 0


def test_repersist_same_analysis_is_noop(db_session):
    """Persisting the same completed analysis twice writes one row."""
    registry = DetectionRuleRegistry([_sigma_rule("sigma-match")])
    agent = DetectionAgent(registry=registry, yara_engine=FakeYaraEngine())
    service = DetectionPersistenceService(clock=lambda: _CLOCK_TS)
    persist = persist_analysis_bound(db_session, service=service)

    analysis = agent.evaluate(_sigma_match_event(), clock=_FIXED_TS, persistence=persist)
    again = persist(analysis)

    assert again.results_created == 0
    assert again.results_skipped == 1
    assert len(_all_results(db_session)) == 1


# ---------------------------------------------------------------------------
# B. Failures through the agent -> persistence
# ---------------------------------------------------------------------------


def test_rule_failure_persisted_through_agent(db_session):
    """A malformed Sigma rule persists as a detection_rule_failures row."""
    bad = _sigma_rule("sigma-bad", content={"not": "a valid sigma rule"})
    registry = DetectionRuleRegistry([bad])
    agent = DetectionAgent(registry=registry, yara_engine=FakeYaraEngine())
    persist = persist_analysis_bound(
        db_session, service=DetectionPersistenceService(clock=lambda: _CLOCK_TS)
    )

    analysis = agent.evaluate(_sigma_match_event(), clock=_FIXED_TS, persistence=persist)

    assert len(analysis.failures) == 1
    assert analysis.failures[0].engine == "sigma"
    assert analysis.failures[0].rule_id == "sigma-bad"

    rows = _all_failures(db_session)
    assert len(rows) == 1
    row = rows[0]
    assert row.event_id == _FIXED_EVENT_ID
    assert row.engine == "sigma"
    assert row.rule_id == "sigma-bad"
    assert row.error_type == "malformed_rule"
    assert row.provenance == "detected"
    assert _count(db_session, DetectionResultRow) == 0


def test_engine_failure_persisted_through_agent(db_session):
    """An exploding engine persists its <engine> sentinel failure row."""
    yara_error = NotImplementedError("yara boom")
    agent = DetectionAgent(
        registry=DetectionRuleRegistry([_sigma_rule("sigma-nomatch", content=_sigma_content(
            detection={"sel": {"Image": "never.exe"}, "condition": "sel"}
        ))]),
        yara_engine=FakeYaraEngine(raise_error=yara_error),
    )
    persist = persist_analysis_bound(
        db_session, service=DetectionPersistenceService(clock=lambda: _CLOCK_TS)
    )

    analysis = agent.evaluate(_sigma_match_event(), clock=_FIXED_TS, persistence=persist)

    engine_failures = [f for f in analysis.failures if f.engine == "yara"]
    assert len(engine_failures) == 1
    assert engine_failures[0].rule_id == "<engine>"
    assert engine_failures[0].error_type == "engine_error"

    rows = _all_failures(db_session)
    assert len(rows) == 1
    assert rows[0].engine == "yara"
    assert rows[0].rule_id == "<engine>"
    assert rows[0].error_type == "engine_error"
    assert rows[0].provenance == "detected"


# ---------------------------------------------------------------------------
# C. Persistence failure handling at the pipeline boundary
# ---------------------------------------------------------------------------


def test_persistence_failure_rolls_back_and_raises_safe(db_session):
    """A real persistence failure surfaces sanitized with no partial rows."""
    registry = DetectionRuleRegistry([_sigma_rule("sigma-match")])
    from app.schemas.detection import DetectionEvidence as Evidence

    oversized = _yara_match_result()
    oversized.evidence = Evidence(
        matched_conditions=["APT_backdoor"],
        matched_fields={"blob": "y" * 300_000},
    )
    agent = DetectionAgent(
        registry=registry,
        yara_engine=FakeYaraEngine(results=(oversized,)),
    )
    persist = persist_analysis_bound(
        db_session, service=DetectionPersistenceService(clock=lambda: _CLOCK_TS)
    )

    with pytest.raises(DetectionPersistenceError) as exc_info:
        agent.evaluate(_sigma_match_event(), clock=_FIXED_TS, persistence=persist)

    # Safe-type semantics: the service's pre-commit validation error, not raw
    # DB/SQL text.
    assert isinstance(exc_info.value, DetectionPersistenceValidationError)
    assert "Traceback" not in str(exc_info.value)
    # Transaction rolled back: nothing persisted by the failing unit.
    assert _count(db_session, DetectionResultRow) == 0
    assert _count(db_session, DetectionRuleFailureRow) == 0


def test_mock_persistence_failure_re_raised(db_session):
    """A failing injected sink is surfaced as-is by the agent."""

    def failing_persistence(analysis):
        raise DetectionPersistenceError(event_id=analysis.event_id)

    registry = DetectionRuleRegistry([_sigma_rule("sigma-match")])
    agent = DetectionAgent(registry=registry, yara_engine=FakeYaraEngine())

    with pytest.raises(DetectionPersistenceError) as exc_info:
        agent.evaluate(
            _sigma_match_event(),
            clock=_FIXED_TS,
            persistence=failing_persistence,
        )

    assert exc_info.value.event_id == _FIXED_EVENT_ID
    assert _count(db_session, DetectionResultRow) == 0
    assert _count(db_session, DetectionRuleFailureRow) == 0


# ---------------------------------------------------------------------------
# D. Step 9E behavior unchanged when persistence is not supplied / mocked
# ---------------------------------------------------------------------------


def test_no_persistence_supplied_unchanged(db_session):
    """Without a persistence sink, evaluate() behaves exactly as Step 9E."""
    registry = DetectionRuleRegistry([_sigma_rule("sigma-match")])
    agent = DetectionAgent(registry=registry, yara_engine=FakeYaraEngine())

    analysis = agent.evaluate(_sigma_match_event(), clock=_FIXED_TS)

    assert isinstance(analysis, DetectionAnalysis)
    assert len(analysis.results) == 1
    assert len(analysis.failures) == 0
    assert _count(db_session, DetectionResultRow) == 0
    assert _count(db_session, DetectionRuleFailureRow) == 0


def test_mocked_persistence_receives_analysis(db_session):
    """A mock sink receives exactly the completed analysis."""
    registry = DetectionRuleRegistry([_sigma_rule("sigma-match")])
    agent = DetectionAgent(registry=registry, yara_engine=FakeYaraEngine())

    captured: list[DetectionAnalysis] = []

    def mock_persistence(analysis):
        captured.append(analysis)
        return None

    analysis = agent.evaluate(_sigma_match_event(), clock=_FIXED_TS, persistence=mock_persistence)

    assert len(captured) == 1
    assert captured[0] is analysis
    assert captured[0].event_id == _FIXED_EVENT_ID