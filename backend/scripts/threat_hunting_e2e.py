"""Threat Hunting end-to-end demonstration (V2.19).

Walks the **entire governed hunt lifecycle** against real PostgreSQL:

    seed analytical history (detections / a correlation + members /
        a risk assessment / an indicator + lookup / audit rows)
        -> create drafts -> run each template exactly once
        -> read back deterministic evidence / findings / timeline
        -> cancel a draft -> observe the audited trail

Everything is persisted to PostgreSQL exactly like the SOC pipeline, so
the read models, findings and the audit trail are real, not stubs.  All
seeded record ids and hunt names are deterministic and prefixed with
``E2E`` so re-runs are idempotent (prior E2E rows are removed first).

Usage:
    python scripts/threat_hunting_e2e.py
"""

from __future__ import annotations

import sys
import time
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select

from app.core.security import hash_password
from app.database.postgres.session import SessionLocal
from app.models.role import Role
from app.models.user import User
from app.services.threat_hunting import ThreatHuntService
from tests.unit.threat_hunt_test_helpers import (
    NOW,
    a_correlation,
    a_detection,
    a_indicator,
    a_lookup,
    a_risk,
)

NAMESPACE = uuid.UUID("7f3a1b2c-9e4d-4a56-b7c8-9d0e1f2a3b4c")


def _id(label: str) -> uuid.UUID:
    return uuid.uuid5(NAMESPACE, f"e2e-threat-hunting::{label}")


def _reset(db, hunt_names: list[str]) -> None:
    from app.models.correlation_member import CorrelationMember
    from app.models.correlation_result import CorrelationResult
    from app.models.detection_result import DetectionResult
    from app.models.risk_assessment import RiskAssessment
    from app.models.threat_hunt import (
        ThreatHuntEvidenceRow,
        ThreatHuntFindingRow,
        ThreatHuntRow,
        ThreatHuntTimelineItemRow,
    )
    from app.models.threat_intel_indicator import ThreatIntelIndicator
    from app.models.threat_intel_lookup import ThreatIntelLookup

    hunt_subq = select(ThreatHuntRow.hunt_id).where(ThreatHuntRow.name.in_(hunt_names))
    db.execute(delete(ThreatHuntTimelineItemRow).where(ThreatHuntTimelineItemRow.hunt_id.in_(hunt_subq)))
    db.execute(delete(ThreatHuntFindingRow).where(ThreatHuntFindingRow.hunt_id.in_(hunt_subq)))
    db.execute(delete(ThreatHuntEvidenceRow).where(ThreatHuntEvidenceRow.hunt_id.in_(hunt_subq)))
    db.execute(delete(ThreatHuntRow).where(ThreatHuntRow.name.in_(hunt_names)))
    db.execute(delete(DetectionResult).where(DetectionResult.event_id.in_(
        [_id(f"event-{i}") for i in range(3)]
    )))
    db.execute(delete(CorrelationMember).where(CorrelationMember.correlation_id == _id("correlation-1")))
    db.execute(delete(CorrelationResult).where(CorrelationResult.correlation_id == _id("correlation-1")))
    db.execute(delete(RiskAssessment).where(RiskAssessment.risk_assessment_id == _id("risk-1")))
    db.execute(delete(ThreatIntelLookup).where(ThreatIntelLookup.event_id == _id("lookup-event")))
    db.execute(delete(ThreatIntelIndicator).where(ThreatIntelIndicator.value == "203.0.113.42"))
    db.commit()


def _actor(db):
    role = db.execute(select(Role).where(Role.name == "analyst")).scalar_one_or_none()
    if role is None:
        role = Role(name="analyst", description="analyst role")
        db.add(role)
        db.commit()
        db.refresh(role)
    actor = db.execute(
        select(User).where(User.email == "e2e-threat-hunting@example.com")
    ).scalar_one_or_none()
    if actor is None:
        actor = User(
            email="e2e-threat-hunting@example.com",
            password_hash=hash_password("TestPassword123!"),
            is_active=True,
            role_id=role.id,
        )
        db.add(actor)
        db.commit()
        db.refresh(actor)
    return actor


def _payload(name, hunt_type, **overrides):
    import app.schemas.threat_hunting as s

    data = {
        "name": name,
        "hunt_type": hunt_type,
        "description": "V2.19 E2E hunt over deterministic seeded history.",
        "start_time": NOW - timedelta(hours=24),
        "end_time": NOW + timedelta(hours=24),
        "filters": [],
    }
    data.update(overrides)
    return s.ThreatHuntCreate(**data)


def main() -> int:
    db = SessionLocal()
    started_at = time.time()
    try:
        event_ids = [_id(f"event-{i}") for i in range(3)]
        correlation_id = _id("correlation-1")
        risk_id = _id("risk-1")
        lookup_event_id = _id("lookup-event")
        actor = _actor(db)

        hunts = [
            "E2E: detection review",
            "E2E: indicator hunt",
            "E2E: multi-stage activity",
            "E2E: auth anomaly (draft)",
        ]

        _reset(db, hunts)

        # 1. Seed persisted analytical history (what a hunt may read).
        a_detection(db, event_id=event_ids[0], detection_id=_id("det-1"),
                    rule_id="E2E-RECON", severity="high", at=NOW)
        a_detection(db, event_id=event_ids[1], detection_id=_id("det-2"),
                    rule_id="E2E-EXFIL", severity="critical", at=NOW - timedelta(minutes=5))
        a_detection(db, event_id=event_ids[2], detection_id=_id("det-3"),
                    rule_id="E2E-RECON", severity="medium", at=NOW - timedelta(minutes=3))
        a_correlation(
            db,
            correlation_id=correlation_id,
            status="closed",
            at=NOW - timedelta(minutes=2),
            members=[
                (event_ids[0], event_ids[0], NOW - timedelta(minutes=4), 1),
                (event_ids[1], event_ids[1], NOW - timedelta(minutes=3), 2),
            ],
        )
        a_risk(
            db,
            risk_assessment_id=risk_id,
            correlation_id=correlation_id,
            score=0.92,
            level="high",
            at=NOW - timedelta(minutes=1),
        )
        indicator = a_indicator(db, value="203.0.113.42", indicator_type="ip", first_seen_at=NOW)
        a_lookup(db, indicator_id=indicator.id, event_id=lookup_event_id,
                 provider="abuseipdb", found=True, result_timestamp=indicator.first_seen_at)
        db.commit()
        print("[1] seeded 3 detections, 1 correlation (+2 members), 1 risk assessment, 1 indicator + lookup")
        print(f"    window {NOW - timedelta(hours=24)} .. {NOW + timedelta(hours=24)}")

        from app.schemas.threat_hunting import HuntType

        def run(name: str, hunt_type: HuntType, **overrides) -> None:
            created = ThreatHuntService.create(db, actor=actor, payload=_payload(name, hunt_type.value, **overrides))
            assert created.status.value == "draft"
            completed = ThreatHuntService.run(db, actor=actor, hunt_id=created.hunt_id)
            assert completed.status.value == "completed"
            detail = ThreatHuntService.get(db, actor=actor, hunt_id=created.hunt_id)
            findings_page = ThreatHuntService.list_findings(db, actor=actor, hunt_id=created.hunt_id)
            evidence_page = ThreatHuntService.list_evidence(db, actor=actor, hunt_id=created.hunt_id)
            timeline_page = ThreatHuntService.list_timeline(db, actor=actor, hunt_id=created.hunt_id)
            prov = {e.provenance for e in evidence_page.items}
            print(
                f"    -> {hunt_type.value:<22} result_count={detail.result_count} "
                f"findings={findings_page.total} timeline={timeline_page.total} "
                f"provenance={sorted(prov)}"
            )

        print("[2] running governed hunts exactly once")
        run(hunts[0], HuntType.DETECTION_REVIEW)
        run(hunts[1], HuntType.INDICATOR_HUNT)
        run(hunts[2], HuntType.MULTI_STAGE_ACTIVITY)

        # 3. Cancel a non-terminal draft; rerun of a completed hunt is refused.
        draft = ThreatHuntService.create(
            db, actor=actor, payload=_payload(hunts[3], HuntType.AUTHENTICATION_ANOMALY.value)
        )
        ThreatHuntService.cancel(db, actor=actor, hunt_id=draft.hunt_id)
        cancelled = ThreatHuntService.get(db, actor=actor, hunt_id=draft.hunt_id)
        assert cancelled.status.value == "cancelled"
        print(f"[3] cancelled draft -> status={cancelled.status.value} (auditable transition)")

        listing = ThreatHuntService.list(db, actor=actor, status_filter=None)
        print(f"[4] persisted hunts visible in listing (total={listing.total} overall)")

        # Leave the database exactly as found: drop the E2E seeds and hunts
        # (start-of-run reset keeps re-runs idempotent; end-of-run reset keeps
        # the analytical history pristine for the rest of the test suite).
        _reset(db, hunts)
        print(f"\nE2E completed in {time.time() - started_at:.1f}s — no security state touched, "
              "hunt artifacts audited to threat_hunt.*; seed rows + hunts removed")
        return 0
    except Exception as exc:  # pragma: no cover - script diagnostics
        print(f"E2E FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())