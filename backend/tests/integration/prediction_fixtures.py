"""Shared fixtures for the V3.24 attack-prediction test suite.

Two correlations are built into the *real* V3.22 graph rather than mocked, because
the entire claim under test is that a prediction is grounded in persisted state:
if the graph were a stub, "every prediction cites resolvable evidence" would be
vacuous.

* ``prediction_correlation`` carries persisted ATT&CK mappings on some of its
  detections, so a predicted stage can legitimately carry a technique id.
* ``unmapped_correlation`` carries none, so the only honest outcome is
  ``INSUFFICIENT_EVIDENCE`` with no technique id anywhere.

Both keep secrets in the detection ``evidence``/``result_metadata`` payloads,
because a prediction must never echo them: several tests assert exactly that.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete, or_
from sqlalchemy.orm import Session

from app.agents.debate.engine import DebateEngine
from app.models.correlation_member import CorrelationMember
from app.models.correlation_result import CorrelationResult
from app.models.debate import (
    DebateAgentAssessmentRecord,
    DebateArgumentRecord,
    DebateConsensusRecord,
    DebateRoundRecord,
    DebateSessionRecord,
)
from app.models.detection_result import DetectionResult
from app.models.knowledge_graph import KnowledgeGraphEdge, KnowledgeGraphNode
from app.models.risk_assessment import RiskAssessment
from app.schemas.correlation import CorrelationStatus
from app.schemas.detection import DetectionSeverity, RuleType
from app.schemas.risk import RiskLevel
from app.services.debate.persistence import DebateService
from app.services.knowledge_graph.builder import KnowledgeGraphBuilder
from app.services.knowledge_graph.queries import KnowledgeGraphQueries
from app.services.knowledge_graph.vocabulary import DEFAULT_BOUNDS
from tests.helpers.debate_runtime import ScriptedDebateRuntime
from tests.integration.debate_fixtures import ROLES

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)

#: Strings planted in detection payloads.  No prediction artifact may contain
#: any of them; tests assert on their absence rather than trusting the code.
LEAKED_SECRET = "must-never-reach-a-prediction"
LEAKED_API_KEY = "sk-must-never-appear-in-a-prediction"


def _ts(minutes: int = 0) -> datetime:
    return BASE + timedelta(minutes=minutes)


def _build_correlation(db: Session, *, attack_mappings: dict[int, dict]):
    """Persist one 7-detection / 1-event correlation and build its graph.

    ``attack_mappings`` maps a detection index to the ``rule_references`` mapping
    that detection should persist.  Detections absent from it persist no ATT&CK
    mapping at all, which is the realistic case for most rules.
    """
    correlation_id = uuid.uuid4()
    event_id = uuid.uuid4()
    risk_id = uuid.uuid4()
    detection_ids = [uuid.uuid4() for _ in range(7)]

    db.add(
        CorrelationResult(
            correlation_id=correlation_id,
            status=CorrelationStatus.ACTIVE,
            confidence=0.91,
            evidence={"note": LEAKED_SECRET},
            result_metadata={},
            timestamp=_ts(60),
            provenance="correlated",
        )
    )
    db.flush()
    for order, detection_id in enumerate(detection_ids):
        evidence: dict = {"secret": LEAKED_SECRET}
        if order in attack_mappings:
            evidence["rule_references"] = attack_mappings[order]
        db.add(
            DetectionResult(
                event_id=event_id,
                detection_id=detection_id,
                rule_id=f"prediction-rule-{order:02d}",
                rule_type=RuleType.SIGMA,
                rule_version="1.0.0",
                severity=DetectionSeverity.HIGH,
                matched=True,
                confidence=0.8,
                evidence=evidence,
                result_metadata={"api_key": LEAKED_API_KEY},
                detected_at=_ts(order),
                provenance="detected",
            )
        )
    db.flush()
    for order, detection_id in enumerate(detection_ids):
        db.add(
            CorrelationMember(
                correlation_id=correlation_id,
                detection_id=detection_id,
                event_id=event_id,
                timestamp=_ts(order),
                member_order=order,
            )
        )
    db.flush()
    db.add(
        RiskAssessment(
            risk_assessment_id=risk_id,
            correlation_id=correlation_id,
            score=0.785,
            level=RiskLevel.HIGH,
            confidence=0.7,
            factors=[{"name": "exploit"}],
            evidence=[{"detail": LEAKED_SECRET}],
            assessment_metadata={},
            timestamp=_ts(70),
            provenance="risk_assessed",
        )
    )
    db.commit()

    KnowledgeGraphBuilder().build_for_correlation(db, correlation_id)

    queries = KnowledgeGraphQueries(DEFAULT_BOUNDS)
    graph = queries.get_correlation_graph(db, correlation_id)
    detection_refs = sorted(
        node["source_reference"]
        for node in graph.nodes
        if node["node_type"] == "DETECTION"
    )
    return {
        "correlation_id": correlation_id,
        "event_id": event_id,
        "risk_id": risk_id,
        "graph": graph,
        "queries": queries,
        "detection_refs": detection_refs,
        "detection_ref": detection_refs[0],
        "correlation_ref": sorted(
            node["source_reference"]
            for node in graph.nodes
            if node["node_type"] == "CORRELATION"
        )[0],
    }


def _teardown_correlation(db: Session, built: dict) -> None:
    node_ids = [node["id"] for node in built["graph"].nodes]
    db.rollback()
    for model in (
        DebateConsensusRecord,
        DebateArgumentRecord,
        DebateAgentAssessmentRecord,
        DebateRoundRecord,
        DebateSessionRecord,
    ):
        db.execute(delete(model))
    if node_ids:
        db.execute(
            delete(KnowledgeGraphEdge).where(
                or_(
                    KnowledgeGraphEdge.source_node_id.in_(node_ids),
                    KnowledgeGraphEdge.target_node_id.in_(node_ids),
                )
            )
        )
        db.execute(delete(KnowledgeGraphNode).where(KnowledgeGraphNode.id.in_(node_ids)))
    db.execute(
        delete(RiskAssessment).where(
            RiskAssessment.risk_assessment_id == built["risk_id"]
        )
    )
    db.execute(
        delete(CorrelationMember).where(
            CorrelationMember.correlation_id == built["correlation_id"]
        )
    )
    db.execute(delete(DetectionResult).where(DetectionResult.event_id == built["event_id"]))
    db.execute(
        delete(CorrelationResult).where(
            CorrelationResult.correlation_id == built["correlation_id"]
        )
    )
    db.commit()


@pytest.fixture(scope="module")
def prediction_correlation(db_session: Session):
    """A correlation whose detections persist real ATT&CK mappings.

    Three detections map to ``T1003`` (OS Credential Dumping) and one to
    ``T1021`` (Remote Services).  Both names match closed stage tokens, so a
    prediction over this correlation may legitimately name a technique id — the
    case a stricter reading of "never invent ATT&CK ids" must still allow.
    """
    built = _build_correlation(
        db_session,
        attack_mappings={
            0: {"attack": "T1003", "attack_name": "OS Credential Dumping"},
            1: {"attack": "T1003", "attack_name": "OS Credential Dumping"},
            2: {"attack_id": "T1003", "attack_tactic": "credential access"},
            3: {"mitre_attack": "t1021", "attack_name": "Remote Services"},
        },
    )
    yield built
    _teardown_correlation(db_session, built)


@pytest.fixture(scope="module")
def unmapped_correlation(db_session: Session):
    """A correlation with no persisted ATT&CK mapping on any detection."""
    built = _build_correlation(db_session, attack_mappings={})
    yield built
    _teardown_correlation(db_session, built)


def _debate_script(
    detection_refs: list[str],
    correlation_ref: str,
    *,
    hypothesis: str,
) -> dict:
    """A five-agent script whose hypotheses name a predictable stage."""
    script: dict = {}
    for role in ROLES:
        script[f"{role}:1"] = {
            "observations": [
                {
                    "observation_kind": "observation",
                    "statement": "Seven detections reference one persisted event.",
                    "evidence_references": [detection_refs[0], correlation_ref],
                    "confidence": 0.9,
                }
            ],
            "hypotheses": [
                {
                    "observation_kind": "hypothesis",
                    "statement": hypothesis,
                    "evidence_references": list(detection_refs),
                    "confidence": 0.75,
                }
            ],
            "limitations": {"limitations": [LEAKED_SECRET]},
            "confidence": 0.75,
        }
        script[f"{role}:2"] = {"arguments": [], "unresolved_questions": []}
        script[f"{role}:3"] = {"counterarguments": []}
    return script


def persist_debate_naming(
    db: Session,
    built: dict,
    *,
    hypothesis: str = "The activity may represent credential-access behavior",
) -> str:
    """Run the real V3.23 engine offline and persist its debate.

    The real engine and the real persistence service are used — only the model
    provider is a deterministic script — so the prediction layer consumes a
    genuine ``DebateSession`` document rather than a hand-written lookalike.
    """
    runtime = ScriptedDebateRuntime(
        _debate_script(built["detection_refs"], built["correlation_ref"], hypothesis=hypothesis)
    )
    engine = DebateEngine(runtime=runtime)
    graph = built["queries"].get_correlation_graph(
        db, built["correlation_id"]
    )
    session = engine.run(
        graph,
        correlation_id=built["correlation_id"],
        unavailable_entity_types=built["queries"].unavailable_entity_types(),
    )
    DebateService(db).persist_session(session)
    return str(session.debate_id)


@pytest.fixture(scope="module")
def correlated_prediction_correlation(db_session: Session):
    """Its own correlation, with persisted mappings *and* a persisted debate.

    Deliberately separate from :func:`prediction_correlation`: a shared row would
    make the no-debate case untestable the moment any test persisted a debate
    for it, and "what happens without a debate" is a claim worth asserting.
    """
    built = _build_correlation(
        db_session,
        attack_mappings={
            0: {"attack": "T1003", "attack_name": "OS Credential Dumping"},
            1: {"attack": "T1003", "attack_name": "OS Credential Dumping"},
        },
    )
    debate_id = persist_debate_naming(db_session, built)
    yield {**built, "debate_id": debate_id}
    _teardown_correlation(db_session, built)


@pytest.fixture
def debate_free_correlation(db_session: Session):
    """A private correlation that starts with no persisted debate.

    Function-scoped so a test may freely persist one without disturbing any other
    test's upstream state.
    """
    built = _build_correlation(
        db_session,
        attack_mappings={
            0: {"attack": "T1003", "attack_name": "OS Credential Dumping"},
        },
    )
    yield built
    _teardown_correlation(db_session, built)


__all__ = [
    "LEAKED_API_KEY",
    "LEAKED_SECRET",
    "correlated_prediction_correlation",
    "debate_free_correlation",
    "persist_debate_naming",
    "prediction_correlation",
    "unmapped_correlation",
]