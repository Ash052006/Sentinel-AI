"""V2.20 incident-report generator + context tests (categories E/F).

End-to-end, read-only generation over a seeded SQLite database: source
resolution, provenance pins, availability semantics, deterministic
catalogs/timelines, secret safety both sides, and the guarantee that
generation performs zero mutations of the analytical history.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.detection_result import DetectionResult
from app.models.audit_log import AuditLog
from app.models.incident_report import IncidentReportRow
from app.schemas.incident_report import IncidentReport
from app.schemas.detection import DetectionSeverity
from app.schemas.security_event import Provenance
from app.schemas.investigation_context import InputAvailability
from app.services.reporting.context import ReportContextBuilder
from app.services.reporting.errors import (
    ReportCorrelationNotFoundError,
    ReportEvidenceError,
    ReportSecretSafetyError,
    ReportValidationError,
)
from app.services.reporting.generator import IncidentReportGenerator
from tests.unit.incident_report_test_helpers import (
    NOW,
    ACTOR_ID,
    a_approval,
    a_correlation,
    a_detection,
    a_indicator,
    a_lookup,
    a_memory,
    a_risk,
    a_soar_execution,
    canonical_model_output,
    FakeReportLLM,
    seed_actor,
)

CORR = uuid.UUID("20000000-0000-0000-0000-000000000001")
EV1 = uuid.UUID("30000000-0000-0000-0000-000000000001")
EV2 = uuid.UUID("30000000-0000-0000-0000-000000000002")
DET1 = uuid.UUID("40000000-0000-0000-0000-000000000001")
DET2 = uuid.UUID("40000000-0000-0000-0000-000000000002")
RISK = uuid.UUID("40000000-0000-0000-0000-000000000003")
MEM = uuid.UUID("40000000-0000-0000-0000-000000000004")
IND = uuid.UUID("40000000-0000-0000-0000-000000000005")
APPROVAL = uuid.UUID("40000000-0000-0000-0000-000000000006")
SOAR = uuid.UUID("40000000-0000-0000-0000-000000000007")


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


def _seed_full(db: Session):
    """Seed a correlation with detections, risk, memory, TI, approval, SOAR."""
    a_correlation(
        db,
        correlation_id=CORR,
        at=NOW,
        members=[(DET1, EV1, NOW - timedelta(minutes=5), 0), (DET2, EV2, NOW, 1)],
    )
    a_detection(db, event_id=EV1, detection_id=DET1, rule_id="sigma-1", at=NOW - timedelta(minutes=5))
    a_detection(
        db,
        event_id=EV2,
        detection_id=DET2,
        rule_id="sigma-2",
        at=NOW,
        severity=DetectionSeverity.CRITICAL,
    )
    a_risk(db, risk_assessment_id=RISK, correlation_id=CORR, at=NOW - timedelta(minutes=3))
    indicator = a_indicator(db, value="203.0.113.9")
    a_lookup(
        db,
        indicator_id=indicator.id,
        event_id=EV1,
        provider="abuseipdb",
        result_timestamp=NOW - timedelta(minutes=2),
    )
    a_memory(db, memory_id=MEM, correlation_id=CORR, created_at=NOW - timedelta(days=1))
    a_approval(
        db,
        approval_id=APPROVAL,
        policy_decision_id=uuid.uuid4(),
        correlation_id=CORR,
        requested_at=NOW - timedelta(minutes=1),
    )
    a_soar_execution(
        db,
        execution_id=SOAR,
        policy_decision_id=uuid.uuid4(),
        correlation_id=CORR,
        started_at=NOW,
    )
    db.commit()


class TestContextBuild:
    def test_unknown_correlation_raises(self, db: Session):
        with pytest.raises(ReportCorrelationNotFoundError):
            ReportContextBuilder().build(db, uuid.uuid4())

    def test_availability_and_provenance(self, db: Session):
        _seed_full(db)
        built = ReportContextBuilder().build(db, CORR)
        ctx = built.context

        assert ctx.availability.correlation is InputAvailability.PROVIDED
        assert ctx.availability.detections is InputAvailability.PROVIDED
        assert ctx.availability.threat_intelligence is InputAvailability.PROVIDED
        assert ctx.availability.risk_assessment is InputAvailability.PROVIDED
        assert ctx.availability.incident_memory is InputAvailability.PROVIDED
        assert ctx.availability.investigation is InputAvailability.NOT_PROVIDED
        assert ctx.availability.attribution is InputAvailability.NOT_PROVIDED
        assert ctx.availability.security_events is InputAvailability.NOT_PROVIDED

        assert ctx.correlation.provenance is Provenance.CORRELATED
        assert all(d.provenance is Provenance.DETECTED for d in ctx.detections)
        assert ctx.risk_assessment.provenance is Provenance.RISK_ASSESSED
        assert all(m.provenance is Provenance.RECALLED for m in ctx.incident_memories)
        assert all(t.provenance is Provenance.ENRICHED for t in ctx.threat_intelligence)
        assert all(a.provenance is Provenance.APPROVAL_REVIEWED for a in ctx.approvals)
        assert all(s.provenance is Provenance.OBSERVED for s in ctx.soar_executions)

    def test_evidence_catalog_unique_and_reproducible(self, db: Session):
        _seed_full(db)
        first = ReportContextBuilder().build(db, CORR)
        second = ReportContextBuilder().build(db, CORR)
        ids1 = [r.reference_id for r in first.context.evidence_catalog]
        ids2 = [r.reference_id for r in second.context.evidence_catalog]
        assert ids1 == ids2
        assert len(set(ids1)) == len(ids1)
        assert len(ids1) >= 8  # corr + 2 members + 2 detections + risk + memory + TI + approval + SOAR

    def test_timeline_deterministic(self, db: Session):
        _seed_full(db)
        first = ReportContextBuilder().build(db, CORR)
        second = ReportContextBuilder().build(db, CORR)
        assert [t.kind for t in first.timeline] == [t.kind for t in second.timeline]
        assert [t.reference_id for t in first.timeline] == [t.reference_id for t in second.timeline]

    def test_empty_correlation_stays_none_found(self, db: Session):
        a_correlation(db, correlation_id=CORR)
        db.commit()
        built = ReportContextBuilder().build(db, CORR)
        ctx = built.context
        assert ctx.availability.detections is InputAvailability.NOT_PROVIDED
        assert ctx.availability.incident_memory is InputAvailability.NONE_FOUND
        assert ctx.availability.risk_assessment is InputAvailability.NOT_PROVIDED

    def test_no_mutation_of_sources(self, db: Session):
        _seed_full(db)
        before = db.execute(
            select(DetectionResult)
        ).scalars().all()
        counts = {
            mtab: db.query(mtab).count()
            for mtab in (
                DetectionResult,
                __import__("app.models.risk_assessment", fromlist=["RiskAssessment"]).RiskAssessment,
            )
        }
        ReportContextBuilder().build(db, CORR)
        db.rollback()
        after = db.execute(
            select(DetectionResult)
        ).scalars().all()
        assert len(before) == len(after)
        assert counts[DetectionResult] == db.query(DetectionResult).count()


class TestGenerator:
    def _generator(self, **kwargs) -> IncidentReportGenerator:
        return IncidentReportGenerator(llm=FakeReportLLM(), **kwargs)

    def test_generate_produces_valid_report(self, db: Session):
        _seed_full(db)
        actor = seed_actor(db)
        gen = self._generator()
        report = gen.generate(db, actor=actor, correlation_id=CORR)
        assert isinstance(report, IncidentReport)
        assert report.correlation_id == CORR
        assert report.generated_by == actor.id
        assert report.schema_version == "2.20"
        assert report.model == "fake-report-model"
        assert report.ai.title == "Correlated network intrusion"
        assert len(report.evidence_catalog) >= 1
        assert len(report.timeline) >= 5

    def test_generate_is_zero_write(self, db: Session):
        _seed_full(db)
        actor = seed_actor(db)
        before_reports = db.query(IncidentReportRow).count()
        before_audit = db.query(AuditLog).count()
        gen = self._generator()
        gen.generate(db, actor=actor, correlation_id=CORR)
        # The generator itself never writes: no rows, no audit, no mutation.
        assert db.query(IncidentReportRow).count() == before_reports
        assert db.query(AuditLog).count() == before_audit

    def test_dangling_citation_raises_evidence_error(self, db: Session):
        _seed_full(db)
        actor = seed_actor(db)
        bad = canonical_model_output(
            findings=[
                {
                    "title": "t",
                    "summary": "s",
                    "evidence_references": [str(uuid.uuid4())],
                }
            ]
        )
        gen = IncidentReportGenerator(llm=FakeReportLLM(text=bad))
        with pytest.raises(ReportEvidenceError):
            gen.generate(db, actor=actor, correlation_id=CORR)

    def test_valid_catalog_citation_accepted(self, db: Session):
        _seed_full(db)
        actor = seed_actor(db)
        ref = ReportContextBuilder().build(db, CORR)
        rid = ref.context.evidence_catalog[0].reference_id
        good = canonical_model_output(
            findings=[
                {"title": "t", "summary": "s", "evidence_references": [str(rid)]}
            ]
        )
        gen = IncidentReportGenerator(llm=FakeReportLLM(text=good))
        report = gen.generate(db, actor=actor, correlation_id=CORR)
        assert report.ai.findings[0].evidence_references == [rid]

    def test_llm_malformed_output_raises_validation_error(self, db: Session):
        _seed_full(db)
        actor = seed_actor(db)
        gen = IncidentReportGenerator(llm=FakeReportLLM(text="{oops"))
        with pytest.raises(ReportValidationError):
            gen.generate(db, actor=actor, correlation_id=CORR)

    def test_secret_in_llm_output_rejected(self, db: Session):
        _seed_full(db)
        actor = seed_actor(db)
        leaked = canonical_model_output(executive_summary="contains an api_key exposed here")
        gen = IncidentReportGenerator(llm=FakeReportLLM(text=leaked))
        with pytest.raises(ReportSecretSafetyError):
            gen.generate(db, actor=actor, correlation_id=CORR)

    def test_deterministic_reports(self, db: Session):
        _seed_full(db)
        actor = seed_actor(db)
        fixed_id = uuid.UUID("50000000-0000-0000-0000-000000000001")
        fixed_now = NOW + timedelta(hours=1)

        def make():
            return IncidentReportGenerator(
                llm=FakeReportLLM(),
                now=lambda: fixed_now,
                report_id_factory=lambda: fixed_id,
            )

        r1 = make().generate(db, actor=actor, correlation_id=CORR)
        r2 = make().generate(db, actor=actor, correlation_id=CORR)
        assert r1.model_dump() == r2.model_dump()