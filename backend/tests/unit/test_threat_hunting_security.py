"""Threat Hunting security tests (V2.19).

Adversarial perimeter of the bounded hunt engine:

* input validation rejects secret-bearing strings, control characters,
  oversized filter sets / values / names, out-of-range windows, and
  filter piles beyond the hard cap (max 8) before anything runs;
* values are bound parameters, never spliced SQL — crafted payloads that
  look like SQL conditions must be treated as inert literals;
* resource caps are hard failures (``LIMITS_EXCEEDED``) with an audited
  failed terminal state, never silent truncation of evidence;
* bounded projection keeps the findings page within the cap and reports
  every dropped group via the summary's ``omitted_findings``;
* running a hunt never mutates the persisted analytical history it reads;
* serialized hunt output never leaks connection/credential material.
"""

from __future__ import annotations

import json
import uuid
from datetime import timedelta

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database.postgres.base import Base
from app.models.audit_log import AuditLog
from app.models.detection_result import DetectionResult
from app.schemas.threat_hunting import (
    HUNT_MAX_EVIDENCE,
    HUNT_MAX_FINDINGS,
    HUNT_MAX_FILTERS,
    HUNT_MAX_FILTER_SET,
    HUNT_MAX_FILTER_VALUE_LENGTH,
    HUNT_MAX_NAME_LENGTH,
    HUNT_MAX_WINDOW_HOURS,
    HuntFilter,
    HuntFilterField,
    HuntOperator,
    HuntType,
    ThreatHuntCreate,
)
from app.services.threat_hunting import ThreatHuntService
from app.services.threat_hunting.errors import HuntLimitError
from tests.unit.threat_hunt_test_helpers import (
    NOW,
    a_detection,
    a_indicator,
    a_lookup,
    seed_actor,
)

START = NOW - timedelta(days=1)
END = NOW + timedelta(days=1)

_SECRET_PATTERNS = ("api_key", "authorization", "bearer", "secret", "password", "token")


@pytest.fixture()
def db():
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


def _payload(**overrides) -> ThreatHuntCreate:
    data: dict = {
        "name": "Perimeter validation hunt",
        "hunt_type": HuntType.DETECTION_REVIEW.value,
        "description": "Scope the adversarial perimeter.",
        "start_time": START,
        "end_time": END,
        "filters": [],
    }
    data.update(overrides)
    return ThreatHuntCreate(**data)


def _filter(field, operator, **extra) -> HuntFilter:
    kwargs = {"field": field, "operator": operator}
    kwargs.update(extra)
    return HuntFilter(**kwargs)


class TestAdversarialInput:
    def test_secret_substrings_rejected_everywhere(self) -> None:
        with pytest.raises(ValidationError, match="must not contain secrets"):
            _payload(name="hunt with api_key inside")

        with pytest.raises(ValidationError, match="must not contain secrets"):
            _payload(description="rotates the bearer token weekly")

        with pytest.raises(ValidationError, match="must not contain secrets"):
            _payload(
                name="inner-hunt",
                filters=[
                    _filter(
                        HuntFilterField.RULE_ID.value,
                        HuntOperator.EQUALS.value,
                        value="RULE-1 secret=abc",
                    )
                ],
            )

    def test_control_characters_rejected(self) -> None:
        with pytest.raises(ValidationError, match="control characters"):
            _payload(name="hunt\x00name")
        with pytest.raises(ValidationError, match="control characters"):
            _payload(
                name="h",
                filters=[
                    _filter(
                        HuntFilterField.SEVERITY.value,
                        HuntOperator.EQUALS.value,
                        value="high\n",
                    )
                ],
            )

    def test_filter_set_beyond_hard_cap_rejected(self) -> None:
        with pytest.raises(ValidationError, match="maximum"):
            _payload(
                filters=[
                    _filter(
                        HuntFilterField.SEVERITY.value,
                        HuntOperator.IN.value,
                        values=[f"s{i}" for i in range(HUNT_MAX_FILTER_SET + 1)],
                    )
                ]
            )

    def test_filter_value_beyond_2048_rejected(self) -> None:
        with pytest.raises(ValidationError, match="2048"):
            _payload(
                filters=[
                    _filter(
                        HuntFilterField.SEVERITY.value,
                        HuntOperator.EQUALS.value,
                        value="x" * (HUNT_MAX_FILTER_VALUE_LENGTH + 1),
                    )
                ]
            )

    def test_name_longer_than_120_rejected(self) -> None:
        with pytest.raises(ValidationError, match="120"):
            _payload(name="x" * (HUNT_MAX_NAME_LENGTH + 1))

    def test_window_beyond_720_hours_rejected(self) -> None:
        far = NOW + timedelta(hours=HUNT_MAX_WINDOW_HOURS + 1)
        with pytest.raises(ValidationError, match="720"):
            _payload(start_time=NOW, end_time=far)

    def test_reversed_window_rejected(self) -> None:
        with pytest.raises(ValidationError, match="after"):
            _payload(start_time=END, end_time=START)

    def test_filter_pile_beyond_8_rejected(self) -> None:
        filters = [
            _filter(
                HuntFilterField.SEVERITY.value,
                HuntOperator.EQUALS.value,
                value="high",
            )
            for _ in range(HUNT_MAX_FILTERS + 1)
        ]
        with pytest.raises(ValidationError, match="at most 8"):
            _payload(filters=filters)


class TestBindingNotSplicing:
    def test_crafted_value_is_inert_literal(self, db: Session) -> None:
        actor = seed_actor(db)
        a_detection(
            db,
            event_id=uuid.uuid4(),
            detection_id=uuid.uuid4(),
            rule_id="RULE-1",
            severity="high",
            at=NOW,
        )
        db.commit()

        crafted = ("'RULE-1' OR '1'='1", "RULE-1') OR 1=1 --", "RULE-1; DROP TABLE x")
        for value in crafted:
            payload = _payload(
                name="crafted",
                filters=[
                    _filter(
                        HuntFilterField.RULE_ID.value,
                        HuntOperator.EQUALS.value,
                        value=value,
                    )
                ],
            )
            detail = ThreatHuntService.create(db, actor=actor, payload=payload)
            completed = ThreatHuntService.run(
                db, actor=actor, hunt_id=detail.hunt_id
            )
            assert completed.status.value == "completed"
            assert completed.result_count == 0, value

    def test_sql_like_contains_binds_literally(self, db: Session) -> None:
        actor = seed_actor(db)
        a_indicator(db, value="203.0.113.5")
        db.commit()
        payload = _payload(
            name="contains-escape",
            hunt_type=HuntType.INDICATOR_HUNT.value,
            filters=[
                _filter(
                    HuntFilterField.INDICATOR_VALUE.value,
                    HuntOperator.CONTAINS.value,
                    value="203.0.113.' UNION SELECT * --",
                )
            ],
        )
        detail = ThreatHuntService.create(db, actor=actor, payload=payload)
        completed = ThreatHuntService.run(db, actor=actor, hunt_id=detail.hunt_id)
        assert completed.status.value == "completed"
        assert completed.result_count == 0


class TestBoundsHardFail:
    def test_findings_bounded_with_omitted_count(self, db: Session) -> None:
        actor = seed_actor(db)
        for i in range(200):
            a_detection(
                db,
                event_id=uuid.uuid4(),
                detection_id=uuid.uuid4(),
                rule_id=f"RULE-{i:03d}",
                severity="medium",
                at=NOW + timedelta(seconds=i),
            )
        db.commit()
        detail = ThreatHuntService.create(
            db, actor=actor, payload=_payload(name="200-groups")
        )
        completed = ThreatHuntService.run(db, actor=actor, hunt_id=detail.hunt_id)
        assert completed.status.value == "completed"

        page = ThreatHuntService.list_findings(
            db, actor=actor, hunt_id=detail.hunt_id, page_size=HUNT_MAX_FINDINGS
        )
        assert page.total == HUNT_MAX_FINDINGS  # never exceeds the cap
        summary = next(
            (f for f in page.items if "omitted_findings" in f.context), None
        )
        assert summary is not None
        assert summary.context["omitted_findings"] == 200 - (HUNT_MAX_FINDINGS - 1)

    def test_evidence_cap_is_a_hard_failure(self, db: Session) -> None:
        from app.schemas.threat_hunting import HUNT_SURFACE_CAP

        actor = seed_actor(db)
        for i in range(HUNT_SURFACE_CAP):
            indicator = a_indicator(db, value=f"203.0.113.{i + 1}")
            a_lookup(
                db,
                indicator_id=indicator.id,
                event_id=uuid.uuid4(),
                result_timestamp=NOW,
            )
        db.commit()

        detail = ThreatHuntService.create(
            db,
            actor=actor,
            payload=_payload(
                name="evidence-cap",
                hunt_type=HuntType.INDICATOR_HUNT.value,
                filters=[
                    _filter(
                        HuntFilterField.INDICATOR_VALUE.value,
                        HuntOperator.STARTS_WITH.value,
                        value="203.0.113.",
                    )
                ],
            ),
        )
        with pytest.raises(HuntLimitError):
            ThreatHuntService.run(db, actor=actor, hunt_id=detail.hunt_id)

        failed = ThreatHuntService.get(db, actor=actor, hunt_id=detail.hunt_id)
        assert failed.status.value == "failed"
        assert failed.error_code == "LIMITS_EXCEEDED"
        assert str(HUNT_MAX_EVIDENCE) in failed.error_message

    def test_failure_is_audited_and_terminal(self, db: Session) -> None:
        actor = seed_actor(db)
        from app.schemas.threat_hunting import HUNT_SURFACE_CAP

        for i in range(HUNT_SURFACE_CAP):
            indicator = a_indicator(db, value=f"198.51.100.{i + 1}")
            a_lookup(
                db,
                indicator_id=indicator.id,
                event_id=uuid.uuid4(),
                result_timestamp=NOW,
            )
        db.commit()
        detail = ThreatHuntService.create(
            db,
            actor=actor,
            payload=_payload(
                name="audit-fail",
                hunt_type=HuntType.INDICATOR_HUNT.value,
            ),
        )
        try:
            ThreatHuntService.run(db, actor=actor, hunt_id=detail.hunt_id)
        except HuntLimitError:
            pass
        else:  # pragma: no cover
            pytest.fail("expected HuntLimitError")

        failure = db.execute(
            select(AuditLog)
            .where(AuditLog.action == "threat_hunt.failed")
            .where(AuditLog.resource == "threat_hunts")
        ).scalar_one_or_none()
        assert failure is not None

        from app.services.threat_hunting.errors import HuntAlreadyFailedError

        with pytest.raises(HuntAlreadyFailedError):
            ThreatHuntService.run(db, actor=actor, hunt_id=detail.hunt_id)


class TestInvestigatesNeverMutates:
    def test_source_history_unchanged_after_runs(self, db: Session) -> None:
        actor = seed_actor(db)
        seeded = []
        for i in range(5):
            tree = a_detection(
                db,
                event_id=uuid.uuid4(),
                detection_id=uuid.uuid4(),
                rule_id=f"RULE-{i}",
                severity="high",
                at=NOW + timedelta(seconds=i),
            )
            seeded.append((str(tree.event_id), tree.rule_id, tree.severity))
        db.commit()

        before = set(
            db.execute(
                select(
                    DetectionResult.rule_id,
                    DetectionResult.severity,
                    DetectionResult.provenance,
                )
            ).all()
        )
        assert len(before) == 5

        detail = ThreatHuntService.create(
            db, actor=actor, payload=_payload(name="read-only-1")
        )
        ThreatHuntService.run(db, actor=actor, hunt_id=detail.hunt_id)
        other = ThreatHuntService.create(
            db, actor=actor, payload=_payload(name="read-only-2")
        )
        ThreatHuntService.cancel(db, actor=actor, hunt_id=other.hunt_id)
        db.commit()

        after = set(
            db.execute(
                select(
                    DetectionResult.rule_id,
                    DetectionResult.severity,
                    DetectionResult.provenance,
                )
            ).all()
        )
        assert after == before


class TestNoOutputLeaks:
    def test_serialized_pages_carry_no_credentials(self, db: Session) -> None:
        actor = seed_actor(db)
        a_detection(
            db,
            event_id=uuid.uuid4(),
            detection_id=uuid.uuid4(),
            rule_id="RULE-1",
            severity="critical",
            at=NOW,
        )
        db.commit()
        detail = ThreatHuntService.create(
            db, actor=actor, payload=_payload(name="leak-scan")
        )
        ThreatHuntService.run(db, actor=actor, hunt_id=detail.hunt_id)

        blobs = [
            ThreatHuntService.get(db, actor=actor, hunt_id=detail.hunt_id).model_dump_json(),
            ThreatHuntService.list_evidence(
                db, actor=actor, hunt_id=detail.hunt_id
            ).model_dump_json(),
            ThreatHuntService.list_findings(
                db, actor=actor, hunt_id=detail.hunt_id
            ).model_dump_json(),
            ThreatHuntService.list_timeline(
                db, actor=actor, hunt_id=detail.hunt_id
            ).model_dump_json(),
        ]
        lowered = " ".join(b.lower() for b in blobs)
        for pattern in _SECRET_PATTERNS:
            assert pattern not in lowered, pattern
        assert "postgres://" not in lowered
        assert "://" not in lowered
        for blob in blobs:
            assert json.loads(blob) is not None  # all serializable