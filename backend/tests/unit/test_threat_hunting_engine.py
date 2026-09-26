"""Threat Hunting engine tests (V2.19).

The engine is the only place a run is driven and it is deterministic,
read-only and bounded.  These tests seed persisted analytical history on
the same SQLAlchemy models used in production (SQLite-rendered, see
:mod:`tests.unit.threat_hunt_test_helpers`) and pin:

* collection through the closed surfaces and their links (records-kind and
  reuse-kind), with window filtering and implicit template defaults;
* verbatim provenance/severity inheritance (never fabricated);
* deterministic grouping findings, the always-present summary finding, the
  explicit ``omitted_findings`` truncation of the finding projection;
* hard ``LIMITS_EXCEEDED`` failures for surface/evidence/timeline bounds —
  never a silent truncation;
* the reuse-read refusal path (HuntExecutionError, never a half-collected
  result);
* byte-identical artifact identities across two runs of the same hunt id.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database.postgres.base import Base
from app.schemas.threat_hunting import (
    HUNT_MAX_EVIDENCE,
    HUNT_SURFACE_CAP,
    HuntType,
)
from app.services.threat_hunting.engine import (
    EvidenceItem,
    ThreatHuntEngine,
)
from app.services.threat_hunting.errors import HuntExecutionError, HuntLimitError
from app.services.threat_hunting.grammar import TEMPLATES, compile_predicates
from tests.unit.threat_hunt_test_helpers import (
    NOW,
    a_audit,
    a_correlation,
    a_detection,
    a_indicator,
    a_lookup,
    a_memory,
    a_risk,
)

TZ_START = NOW - timedelta(days=1)
TZ_END = NOW + timedelta(days=1)

HUNT_ID = uuid.UUID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")


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


def _run(db: Session, hunt_type: HuntType, *, filters=(), **engine_kwargs) -> object:
    engine = ThreatHuntEngine(db, **engine_kwargs)
    predicates, _ = compile_predicates(hunt_type, list(filters))
    return engine.run(
        hunt_id=HUNT_ID,
        hunt_type=hunt_type,
        start_time=TZ_START,
        end_time=TZ_END,
        predicates=predicates,
    )


class TestDetectionReview:
    def test_collects_only_in_window_detections_with_verbatim_fields(
        self, db: Session
    ) -> None:
        inside = [
            a_detection(
                db,
                event_id=uuid.uuid4(),
                detection_id=uuid.uuid4(),
                rule_id="RULE-A",
                severity="high",
                at=NOW,
            ),
            a_detection(
                db,
                event_id=uuid.uuid4(),
                detection_id=uuid.uuid4(),
                rule_id="RULE-B",
                severity="critical",
                at=NOW + timedelta(minutes=5),
            ),
        ]
        a_detection(
            db,
            event_id=uuid.uuid4(),
            detection_id=uuid.uuid4(),
            rule_id="RULE-OLD",
            at=NOW - timedelta(days=3),
        )
        db.commit()

        result = _run(db, HuntType.DETECTION_REVIEW)

        assert len(result.evidence) == 2
        assert {e.reference_id for e in result.evidence} == {
            inside[0].detection_id, inside[1].detection_id
        }
        for item in result.evidence:
            assert item.surface == "detection"
            assert item.evidence_type == "detection"
            assert item.provenance == "detected"
        severities = {e.severity for e in result.evidence}
        assert severities == {"high", "critical"}

    def test_findings_group_by_rule_and_carry_summary(self, db: Session) -> None:
        a_detection(
            db, event_id=uuid.uuid4(), detection_id=uuid.uuid4(), rule_id="RULE-A",
            severity="high", at=NOW,
        )
        a_detection(
            db, event_id=uuid.uuid4(), detection_id=uuid.uuid4(), rule_id="RULE-A",
            severity="low", at=NOW + timedelta(minutes=2),
        )
        a_detection(
            db, event_id=uuid.uuid4(), detection_id=uuid.uuid4(), rule_id="RULE-B",
            severity="critical", at=NOW + timedelta(minutes=1),
        )
        db.commit()

        result = _run(db, HuntType.DETECTION_REVIEW)

        titles = [f.title for f in result.findings]
        # Sorted severity-first: RULE-B (critical), RULE-A (high), summary.
        assert titles[0].startswith("Rule 'RULE-B'")
        assert titles[1].startswith("Rule 'RULE-A'")
        assert result.findings[-1].title == TEMPLATES[
            HuntType.DETECTION_REVIEW
        ].title

        rule_a = next(f for f in result.findings if f.title.startswith("Rule 'RULE-A'"))
        assert rule_a.context["rule_id"] == "RULE-A"
        assert rule_a.context["count"] == 2
        assert rule_a.context["event_count"] == 2
        assert rule_a.context["severities"] == ["high", "low"]
        assert rule_a.severity == "high"  # inherited max, never invented
        assert len(rule_a.evidence_ids) == 2

        summary = result.findings[-1]
        assert summary.context["evidence_count"] == 3
        assert summary.context["surface_counts"] == {"detection": 3}
        assert "confidence" not in summary.context
        assert "omitted_findings" not in summary.context

    def test_timeline_is_chronological_and_bounded(self, db: Session) -> None:
        late = a_detection(
            db, event_id=uuid.uuid4(), detection_id=uuid.uuid4(),
            rule_id="RULE-L", at=NOW + timedelta(minutes=10),
        )
        early = a_detection(
            db, event_id=uuid.uuid4(), detection_id=uuid.uuid4(),
            rule_id="RULE-E", at=NOW,
        )
        db.commit()

        result = _run(db, HuntType.DETECTION_REVIEW)

        assert len(result.timeline) == 2
        assert result.timeline[0].reference_id == early.detection_id
        assert result.timeline[1].reference_id == late.detection_id
        assert all(t.provenance == "detected" for t in result.timeline)
        assert [t.timeline_item_id for t in result.timeline] == [
            t.timeline_item_id for t in _run(db, HuntType.DETECTION_REVIEW).timeline
        ]

    def test_deterministic_artifact_identity_for_same_hunt_id(
        self, db: Session
    ) -> None:
        a_detection(
            db, event_id=uuid.uuid4(), detection_id=uuid.uuid4(),
            rule_id="RULE-X", at=NOW,
        )
        db.commit()

        first = _run(db, HuntType.DETECTION_REVIEW)
        second = _run(db, HuntType.DETECTION_REVIEW)

        assert [e.key for e in first.evidence] == [e.key for e in second.evidence]
        assert [f.finding_id for f in first.findings] == [
            f.finding_id for f in second.findings
        ]
        assert [t.timeline_item_id for t in first.timeline] == [
            t.timeline_item_id for t in second.timeline
        ]
        # A different hunt id must produce different artifact identities.
        engine = ThreatHuntEngine(db)
        predicates, _ = compile_predicates(HuntType.DETECTION_REVIEW, [])
        other = engine.run(
            hunt_id=uuid.uuid4(),
            hunt_type=HuntType.DETECTION_REVIEW,
            start_time=TZ_START,
            end_time=TZ_END,
            predicates=predicates,
        )
        assert [e.key for e in other.evidence] == [e.key for e in first.evidence]
        assert other.findings[0].finding_id != first.findings[0].finding_id

    def test_empty_window_yields_only_summary_finding(self, db: Session) -> None:
        result = _run(db, HuntType.DETECTION_REVIEW)
        assert result.evidence == []
        assert result.timeline == []
        assert len(result.findings) == 1
        assert result.findings[0].context["evidence_count"] == 0
        assert result.findings[0].provenance == "observed"


class TestAuthenticationAnomaly:
    def test_default_filters_scope_to_auth_resources(self, db: Session) -> None:
        keep_a = a_audit(
            db, action="auth.login", resource="auth", ip_address="10.0.0.1", at=NOW,
        )
        keep_b = a_audit(
            db, action="auth.logout", resource="role_check",
            ip_address="10.0.0.1", at=NOW + timedelta(minutes=1),
        )
        a_audit(
            db, action="user.export", resource="auth",
            ip_address="10.0.0.9", at=NOW + timedelta(minutes=2),
        )  # not an auth.* action -> excluded by the implicit default
        a_audit(
            db, action="auth.login", resource="session",
            ip_address="10.0.0.9", at=NOW + timedelta(minutes=3),
        )  # resource outside (auth, role_check) -> excluded
        a_audit(
            db, action="auth.login", resource="auth",
            ip_address="10.0.0.1", at=NOW - timedelta(days=3),
        )  # out of window
        db.commit()

        result = _run(db, HuntType.AUTHENTICATION_ANOMALY)

        assert {e.reference_id for e in result.evidence} == {keep_a.id, keep_b.id}
        # exactly the two in-window auth.* (auth|role_check) rows remain
        ips = {e.subject for e in result.evidence}
        assert ips == {"10.0.0.1"}
        actions = [
            e.title.removeprefix("Audit ") for e in result.evidence
        ]
        assert sorted(actions) == ["auth.login", "auth.logout"]
        for item in result.evidence:
            assert item.evidence_type == "audit_log"
            assert item.provenance == "observed"
            assert item.severity is None

    def test_findings_group_by_actor_ip(self, db: Session) -> None:
        a_audit(db, action="auth.login", resource="auth", ip_address="10.0.0.1", at=NOW)
        a_audit(
            db, action="auth.login", resource="auth",
            ip_address="10.0.0.1", at=NOW + timedelta(minutes=1),
        )
        a_audit(
            db, action="auth.logout", resource="role_check",
            ip_address="10.0.0.7", at=NOW + timedelta(minutes=2),
        )
        db.commit()

        result = _run(db, HuntType.AUTHENTICATION_ANOMALY)

        grouped = [
            f for f in result.findings
            if f.context.get("subject_kind") == "actor_ip"
        ]
        assert {f.context["subject"] for f in grouped} == {"10.0.0.1", "10.0.0.7"}
        busy = next(f for f in grouped if f.context["subject"] == "10.0.0.1")
        assert busy.context["count"] == 2
        assert busy.context["action_counts"] == {"auth.login": 2}
        assert busy.provenance == "observed"


class TestIndicatorHunt:
    def test_collects_indicators_and_follows_lookups(self, db: Session) -> None:
        indicator = a_indicator(db, value="203.0.113.9", first_seen_at=NOW)
        outside_indicator = a_indicator(db, value="203.0.113.10", first_seen_at=NOW - timedelta(days=3))
        a_indicator(db, value="evil.example", indicator_type="domain", first_seen_at=NOW)
        a_lookup(
            db, indicator_id=indicator.id, event_id=uuid.uuid4(),
            result_timestamp=NOW,
        )
        a_lookup(
            db, indicator_id=outside_indicator.id, event_id=uuid.uuid4(),
            result_timestamp=NOW,
        )  # anchor outside window: indicator not collected -> lookup skipped
        db.commit()

        result = _run(db, HuntType.INDICATOR_HUNT)

        surfaces = {e.surface for e in result.evidence}
        assert surfaces == {"indicator", "lookup"}
        # 2 in-window indicators + 1 lookup for the in-window indicator
        assert len(result.evidence) == 3
        lookup_evidence = [e for e in result.evidence if e.surface == "lookup"]
        assert len(lookup_evidence) == 1
        assert lookup_evidence[0].provenance == "enriched"
        assert lookup_evidence[0].evidence_type == "indicator_lookup"

        ip_group = next(
            f for f in result.findings
            if f.context.get("indicator_type") == "ip"
        )
        assert ip_group.context["count"] == 1
        assert ip_group.context["values"] == ["203.0.113.9"]
        assert ip_group.provenance == "enriched"


class TestMultiStageActivity:
    def test_collects_members_risks_and_memory_links(self, db: Session) -> None:
        corr_id_1 = uuid.uuid4()
        corr_id_2 = uuid.uuid4()
        event_a, event_b = uuid.uuid4(), uuid.uuid4()
        det_a = uuid.uuid4()
        a_correlation(
            db, correlation_id=corr_id_1, at=NOW,
            members=[(det_a, event_a, NOW, 0), (uuid.uuid4(), event_b, NOW, 1)],
        )
        a_correlation(db, correlation_id=corr_id_2, at=NOW + timedelta(minutes=1))
        a_risk(db, risk_assessment_id=uuid.uuid4(), correlation_id=corr_id_1, at=NOW)
        a_memory(
            db, memory_id=uuid.uuid4(), correlation_id=corr_id_1,
            title="Prior similar intrusion",
            summary="Historical recall of a similar multi-stage intrusion.",
            created_at=NOW,
        )
        a_memory(
            db, memory_id=uuid.uuid4(), correlation_id=None,
            created_at=NOW,
        )  # not citing either correlation -> not linked
        db.commit()

        result = _run(db, HuntType.MULTI_STAGE_ACTIVITY)

        by_surface: dict[str, list] = {}
        for e in result.evidence:
            by_surface.setdefault(e.surface, []).append(e)
        assert len(by_surface["correlation"]) == 2
        assert len(by_surface["correlation_member"]) == 2
        assert len(by_surface["risk"]) == 1
        assert len(by_surface["memory"]) == 1
        assert len(result.evidence) == 6

        memory = by_surface["memory"][0]
        assert memory.provenance == "recalled"
        assert memory.title == "Prior similar intrusion"

        corr_finding = next(
            f for f in result.findings
            if f.context.get("correlation_id") == str(corr_id_1)
        )
        assert corr_finding.context["member_count"] == 2
        assert corr_finding.context["risk_levels"] == ["high"]
        assert corr_finding.context["risk_assessment_count"] == 1
        assert corr_finding.severity == "high"  # inherited from risk level

        empty_corr = next(
            f for f in result.findings
            if f.context.get("correlation_id") == str(corr_id_2)
        )
        assert empty_corr.context["member_count"] == 0
        assert "risk_levels" not in empty_corr.context


class TestPrivilegeActivity:
    def test_detection_event_links_correlations_then_risk(self, db: Session) -> None:
        event_id = uuid.uuid4()
        detection = a_detection(
            db, event_id=event_id, detection_id=uuid.uuid4(),
            rule_id="RULE-PRIV", severity="high", at=NOW,
        )
        a_detection(
            db, event_id=uuid.uuid4(), detection_id=uuid.uuid4(),
            rule_id="RULE-OTHER", at=NOW,
        )
        corr_id = uuid.uuid4()
        a_correlation(
            db, correlation_id=corr_id, at=NOW,
            members=[(detection.detection_id, event_id, NOW, 0)],
        )
        a_risk(
            db, risk_assessment_id=uuid.uuid4(), correlation_id=corr_id,
            level="high", at=NOW,
        )
        db.commit()

        result = _run(db, HuntType.PRIVILEGE_ACTIVITY)

        surfaces = [e.surface for e in result.evidence]
        assert surfaces.count("detection") == 2
        assert surfaces.count("correlation") == 1
        assert surfaces.count("risk") == 1

        rule_group = next(
            f for f in result.findings
            if f.context.get("rule_id") == "RULE-PRIV"
        )
        assert rule_group.context["count"] == 1
        assert rule_group.severity == "high"

        corr_group = next(
            f for f in result.findings
            if f.context.get("correlation_id") == str(corr_id)
        )
        assert corr_group.context["risk_levels"] == ["high"]

    def test_risk_level_filter_scopes_the_risk_link(self, db: Session) -> None:
        from app.schemas.threat_hunting import HuntFilter, HuntFilterField, HuntOperator

        event_id = uuid.uuid4()
        detection = a_detection(
            db, event_id=event_id, detection_id=uuid.uuid4(),
            rule_id="RULE-PRIV", at=NOW,
        )
        corr_id = uuid.uuid4()
        a_correlation(
            db, correlation_id=corr_id, at=NOW,
            members=[(detection.detection_id, event_id, NOW, 0)],
        )
        a_risk(
            db, risk_assessment_id=uuid.uuid4(), correlation_id=corr_id,
            level="high", at=NOW,
        )
        db.commit()

        filt = HuntFilter(
            field=HuntFilterField.RISK_LEVEL.value,
            operator=HuntOperator.EQUALS.value,
            value="critical",
        )
        result = _run(db, HuntType.PRIVILEGE_ACTIVITY, filters=[filt])

        assert all(e.surface != "risk" for e in result.evidence)
        assert {e.surface for e in result.evidence} == {"detection", "correlation"}
        corr_finding = next(
            f for f in result.findings
            if f.context.get("correlation_id") == str(corr_id)
        )
        assert "risk_levels" not in corr_finding.context


class TestBounds:
    def test_surface_count_over_cap_fails_the_hunt(self, db: Session) -> None:
        for i in range(6):
            a_detection(
                db, event_id=uuid.uuid4(), detection_id=uuid.uuid4(),
                rule_id=f"RULE-{i}", at=NOW + timedelta(seconds=i),
            )
        db.commit()

        with pytest.raises(HuntLimitError, match="matched 6 records"):
            _run(db, HuntType.DETECTION_REVIEW, surface_cap=5)

    def test_evidence_cap_fails_instead_of_truncating(self, db: Session) -> None:
        for i in range(3):
            a_detection(
                db, event_id=uuid.uuid4(), detection_id=uuid.uuid4(),
                rule_id=f"RULE-{i}", at=NOW + timedelta(seconds=i),
            )
        db.commit()

        with pytest.raises(HuntLimitError, match="evidence items"):
            _run(db, HuntType.DETECTION_REVIEW, max_evidence=2)

    def test_timeline_cap_fails(self, db: Session) -> None:
        for i in range(2):
            a_detection(
                db, event_id=uuid.uuid4(), detection_id=uuid.uuid4(),
                rule_id=f"RULE-{i}", at=NOW + timedelta(seconds=i),
            )
        db.commit()

        with pytest.raises(HuntLimitError, match="timeline"):
            _run(db, HuntType.DETECTION_REVIEW, max_timeline=1)

    def test_findings_projection_truncates_with_explicit_omission(
        self, db: Session
    ) -> None:
        severities = ["critical", "high", "medium", "low", "medium"]
        for i, severity in enumerate(severities):
            a_detection(
                db, event_id=uuid.uuid4(), detection_id=uuid.uuid4(),
                rule_id=f"RULE-{i}", severity=severity,
                at=NOW + timedelta(seconds=i),
            )
        db.commit()

        result = _run(db, HuntType.DETECTION_REVIEW, max_findings=3)

        assert len(result.findings) == 3
        assert result.findings[-1].title == TEMPLATES[
            HuntType.DETECTION_REVIEW
        ].title
        assert result.findings[-1].context["omitted_findings"] == 3
        assert result.findings[-1].context["evidence_count"] == 5

    def test_default_bounds_are_the_contract_values(self) -> None:
        engine = ThreatHuntEngine(db=None)  # type: ignore[arg-type]
        assert engine._surface_cap == HUNT_SURFACE_CAP
        assert engine._max_evidence == HUNT_MAX_EVIDENCE


class TestExecutionErrors:
    def test_reuse_service_refusal_raises_execution_error(
        self, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import app.services.risk_query as risk_query_module

        def _refuse(*args, **kwargs):
            raise RuntimeError("downstream unavailable")

        monkeypatch.setattr(
            risk_query_module.RiskQueryService,
            "list_assessments_for_correlation",
            _refuse,
        )

        event_id = uuid.uuid4()
        detection = a_detection(
            db, event_id=event_id, detection_id=uuid.uuid4(),
            rule_id="RULE-PRIV", at=NOW,
        )
        corr_id = uuid.uuid4()
        a_correlation(
            db, correlation_id=corr_id, at=NOW,
            members=[(detection.detection_id, event_id, NOW, 0)],
        )
        db.commit()

        engine = ThreatHuntEngine(db)
        predicates, _ = compile_predicates(HuntType.PRIVILEGE_ACTIVITY, [])
        with pytest.raises(HuntExecutionError, match="risk_for_correlations"):
            engine.run(
                hunt_id=HUNT_ID,
                hunt_type=HuntType.PRIVILEGE_ACTIVITY,
                start_time=TZ_START,
                end_time=TZ_END,
                predicates=predicates,
            )

    def test_unknown_link_kind_is_rejected(self, db: Session) -> None:
        from app.services.threat_hunting.grammar import LinkSpec

        engine = ThreatHuntEngine(db)
        parent = EvidenceItem(
            surface="correlation",
            key="correlation:x",
            evidence_type="correlation",
            provenance="correlated",
            reference_id=uuid.uuid4(),
            event_id=None,
            correlation_id=uuid.uuid4(),
            severity=None,
            subject=None,
            observed_at=NOW,
            title="Correlation x",
            summary="x",
        )
        bad = LinkSpec(
            name="execute",
            surface="risk",
            kind="execute",
            from_evidence_keys=("correlation",),
        )
        with pytest.raises(HuntExecutionError, match="unknown link kind"):
            engine._run_link(
                HUNT_ID, bad, TZ_START, TZ_END, [],
                {"correlation:x": parent},
            )

    def test_unsupported_evidence_source_rejected(self, db: Session) -> None:
        engine = ThreatHuntEngine(db)
        with pytest.raises(HuntExecutionError, match="unsupported evidence source"):
            engine._to_evidence("detection", object())


class TestReadOnlySurface:
    def test_run_does_not_write_hunt_tables(self, db: Session) -> None:
        from app.models.threat_hunt import (
            ThreatHuntEvidenceRow,
            ThreatHuntFindingRow,
            ThreatHuntTimelineItemRow,
        )
        from sqlalchemy import func, select

        a_detection(
            db, event_id=uuid.uuid4(), detection_id=uuid.uuid4(),
            rule_id="RULE-A", at=NOW,
        )
        db.commit()

        _run(db, HuntType.DETECTION_REVIEW)

        for model in (
            ThreatHuntEvidenceRow, ThreatHuntFindingRow, ThreatHuntTimelineItemRow
        ):
            count = db.scalar(select(func.count()).select_from(model)) or 0
            assert count == 0, model.__tablename__

    def test_every_evidence_item_has_closed_provenance(self, db: Session) -> None:
        from app.schemas.threat_hunting import HUNT_EVIDENCE_PROVENANCES

        a_detection(
            db, event_id=uuid.uuid4(), detection_id=uuid.uuid4(),
            rule_id="RULE-A", at=NOW,
        )
        a_correlation(db, correlation_id=uuid.uuid4(), at=NOW, members=[])
        db.commit()

        result = _run(db, HuntType.MULTI_STAGE_ACTIVITY)
        # no windowed detections surface for multi-stage; correlation only
        for item in result.evidence:
            assert item.provenance in HUNT_EVIDENCE_PROVENANCES
            assert item.provenance != "ai_generated"
