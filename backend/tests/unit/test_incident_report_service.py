"""V2.20 incident-report service tests (category G).

``IncidentReportService`` ownership: one new row per generation, failed-row
persistence with sanitized errors on terminal failures, no row on a missing
correlation, the audit trail (requested/succeeded/failed), and the bounded,
deterministic list/get read models.  Runs fully on SQLite.
"""

from __future__ import annotations

import uuid
import warnings
from datetime import timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.models.incident_report import IncidentReportRow
from app.schemas.incident_report import ReportStatus
from app.services.reporting.errors import (
    ReportCorrelationNotFoundError,
    ReportProviderError,
    ReportUnexpectedError,
)
from app.services.reporting.generator import IncidentReportGenerator
from app.services.reporting.service import IncidentReportService
from tests.unit.incident_report_test_helpers import (
    FakeReportLLM,
    canonical_model_output,
    seed_actor,
)
from tests.unit.threat_hunt_test_helpers import a_correlation

CORR = uuid.UUID("20000000-0000-0000-0000-000000000001")

warnings.filterwarnings("ignore", category=DeprecationWarning)


@pytest.fixture()
def db():
    from sqlalchemy import create_engine
    from sqlalchemy.pool import StaticPool

    from app.database.postgres.base import Base

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


def _rows(db: Session):
    return db.query(IncidentReportRow).all()


def _audit_actions(db: Session, action: str):
    return (
        db.query(AuditLog)
        .filter(AuditLog.action == action)
        .all()
    )


def _service(**llm_kwargs) -> IncidentReportService:
    return IncidentReportService(
        generator_factory=lambda: IncidentReportGenerator(llm=FakeReportLLM(**llm_kwargs))
    )


class TestGeneratePersistence:
    def test_generate_persists_exactly_one_generated_row(self, db: Session):
        a_correlation(db, correlation_id=CORR)
        actor = seed_actor(db)
        svc = _service()

        record = svc.generate(db, actor=actor, correlation_id=CORR)

        rows = _rows(db)
        assert len(rows) == 1
        assert rows[0].status == ReportStatus.GENERATED.value
        assert rows[0].report_id == str(record.report_id)
        assert rows[0].correlation_id == str(CORR)
        assert rows[0].payload is not None
        assert rows[0].title == record.title
        assert rows[0].generated_by == actor.id

    def test_generate_writes_audit_trail(self, db: Session):
        a_correlation(db, correlation_id=CORR)
        actor = seed_actor(db)
        _service().generate(db, actor=actor, correlation_id=CORR)

        assert len(_audit_actions(db, "incident_report.generated_requested")) == 1
        assert len(_audit_actions(db, "incident_report.generated_succeeded")) == 1
        assert len(_audit_actions(db, "incident_report.generated_failed")) == 0

    def test_generate_only_one_row_per_call(self, db: Session):
        a_correlation(db, correlation_id=CORR)
        actor = seed_actor(db)
        svc = _service()
        svc.generate(db, actor=actor, correlation_id=CORR)
        svc.generate(db, actor=actor, correlation_id=CORR)
        assert len(_rows(db)) == 2

    def test_missing_correlation_no_row(self, db: Session):
        actor = seed_actor(db)
        with pytest.raises(ReportCorrelationNotFoundError):
            _service().generate(db, actor=actor, correlation_id=uuid.uuid4())
        assert _rows(db) == []
        assert len(_audit_actions(db, "incident_report.generated_failed")) == 1


class TestFailedRowPersistence:
    def test_provider_error_persists_failed_row(self, db: Session):
        a_correlation(db, correlation_id=CORR)
        actor = seed_actor(db)
        service = IncidentReportService(
            generator_factory=lambda: IncidentReportGenerator(
                llm=FakeReportLLM(callable=lambda prompt: (_ for _ in ()).throw(
                    ConnectionError("provider exploded")
                ))
            )
        )
        with pytest.raises(ReportProviderError):
            service.generate(db, actor=actor, correlation_id=CORR)

        rows = _rows(db)
        assert len(rows) == 1
        assert rows[0].status == ReportStatus.FAILED.value
        assert rows[0].payload is None
        assert rows[0].error_code == "REPORT_PROVIDER_UNAVAILABLE"
        assert rows[0].error_message  # sanitized
        assert len(_audit_actions(db, "incident_report.generated_failed")) == 1

    def test_unexpected_internal_error_maps_to_internal(self, db: Session):
        a_correlation(db, correlation_id=CORR)
        actor = seed_actor(db)

        def boom_parse(text):
            raise ValueError("parser bug")

        gen = IncidentReportGenerator(
            llm=FakeReportLLM(),
            parse=boom_parse,
        )
        service = IncidentReportService(generator_factory=lambda: gen)

        with pytest.raises(ReportUnexpectedError):
            service.generate(db, actor=actor, correlation_id=CORR)
        row = _rows(db)[0]
        assert row.status == ReportStatus.FAILED.value
        assert row.error_code == "REPORT_INTERNAL"

    def test_failed_row_never_carries_payload(self, db: Session):
        a_correlation(db, correlation_id=CORR)
        actor = seed_actor(db)
        bad = canonical_model_output(findings=[{"title": "t", "summary": "s", "evidence_references": [str(uuid.uuid4())]}])
        service = IncidentReportService(
            generator_factory=lambda: IncidentReportGenerator(llm=FakeReportLLM(text=bad))
        )
        from app.services.reporting.errors import ReportEvidenceError

        with pytest.raises(ReportEvidenceError):
            service.generate(db, actor=actor, correlation_id=CORR)
        row = _rows(db)[0]
        assert row.payload is None
        assert row.error_code == "REPORT_EVIDENCE_INVALID"


class TestReads:
    def test_get_returns_record_with_payload(self, db: Session):
        a_correlation(db, correlation_id=CORR)
        actor = seed_actor(db)
        created = _service().generate(db, actor=actor, correlation_id=CORR)
        got = _service().get(db, report_id=created.report_id)
        assert got.report_id == created.report_id
        assert got.payload is not None
        assert got.payload.ai.title == "Correlated network intrusion"

    def test_get_missing_raises(self, db: Session):
        with pytest.raises(Exception):
            _service().get(db, report_id=uuid.uuid4())

    def test_list_pages_deterministically(self, db: Session):
        a_correlation(db, correlation_id=CORR)
        actor = seed_actor(db)
        svc = _service()
        for _ in range(3):
            svc.generate(db, actor=actor, correlation_id=CORR)
        page = svc.list(db, page=1, page_size=2)
        assert page.total == 3
        assert len(page.items) == 2
        page2 = svc.list(db, page=2, page_size=2)
        assert len(page2.items) == 1
        ids = [r.report_id for r in page.items + page2.items]
        assert len(set(ids)) == 3

    def test_failed_row_listed_as_failed_summary(self, db: Session):
        a_correlation(db, correlation_id=CORR)
        actor = seed_actor(db)

        bad = canonical_model_output(
            findings=[{"title": "t", "summary": "s", "evidence_references": [str(uuid.uuid4())]}]
        )
        service = IncidentReportService(
            generator_factory=lambda: IncidentReportGenerator(llm=FakeReportLLM(text=bad))
        )
        from app.services.reporting.errors import ReportEvidenceError

        with pytest.raises(ReportEvidenceError):
            service.generate(db, actor=actor, correlation_id=CORR)
        page = service.list(db, page_size=50)
        assert page.items[0].status == ReportStatus.FAILED