"""Shared fixtures for the V3.23 debate test suite.

Builds a real 7-detection / 1-event correlation in the V3.22 graph, then exposes
the evidence references a debate is allowed to cite.  Using the real graph
(mrather than a hand-built stub) is deliberate: the whole point of V3.23 is
that a model can only cite evidence the bounded graph actually contains, so the
tests must exercise that same real path.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete, or_
from sqlalchemy.orm import Session

from app.agents.debate.evidence import EvidenceCatalog
from app.agents.debate.vocabulary import (
    AgentRole,
    RoundKind,
    deterministic_argument_id,
    deterministic_hypothesis_id,
)
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
from app.services.knowledge_graph.builder import KnowledgeGraphBuilder
from app.services.knowledge_graph.queries import KnowledgeGraphQueries
from app.services.knowledge_graph.vocabulary import DEFAULT_BOUNDS
from tests.helpers.debate_runtime import ScriptedDebateRuntime

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)

#: The one hypothesis every scripted agent raises.  Identical normalized text
#: across agents is what agreement detection keys on, so this is the canonical
#: "the roster agrees" scenario.
AGREED_HYPOTHESIS = "The activity may represent credential-access behavior"
AGREED_HYPOTHESIS_ID = str(deterministic_hypothesis_id(AGREED_HYPOTHESIS))

ROLES = (
    "detection_analyst",
    "threat_intelligence_analyst",
    "behavioral_analyst",
    "incident_investigator",
    "skeptic",
)


def _ts(minutes: int = 0) -> datetime:
    return BASE + timedelta(minutes=minutes)


@pytest.fixture(scope="module")
def debate_correlation(db_session: Session):
    """A persisted 7-detection / 1-event correlation, built into the V3.22 graph."""
    correlation_id = uuid.uuid4()
    event_id = uuid.uuid4()
    risk_id = uuid.uuid4()
    detection_ids = [uuid.uuid4() for _ in range(7)]

    db_session.add(
        CorrelationResult(
            correlation_id=correlation_id,
            status=CorrelationStatus.ACTIVE,
            confidence=0.91,
            evidence={"note": "must never reach a debate prompt"},
            result_metadata={},
            timestamp=_ts(60),
            provenance="correlated",
        )
    )
    db_session.flush()
    for order, detection_id in enumerate(detection_ids):
        db_session.add(
            DetectionResult(
                event_id=event_id,
                detection_id=detection_id,
                rule_id=f"debate-rule-{order:02d}",
                rule_type=RuleType.SIGMA,
                rule_version="1.0.0",
                severity=DetectionSeverity.HIGH,
                matched=True,
                confidence=0.8,
                evidence={"secret": "must never reach a debate prompt"},
                result_metadata={"api_key": "sk-must-never-appear"},
                detected_at=_ts(order),
                provenance="detected",
            )
        )
    db_session.flush()
    for order, detection_id in enumerate(detection_ids):
        db_session.add(
            CorrelationMember(
                correlation_id=correlation_id,
                detection_id=detection_id,
                event_id=event_id,
                timestamp=_ts(order),
                member_order=order,
            )
        )
    db_session.flush()
    db_session.add(
        RiskAssessment(
            risk_assessment_id=risk_id,
            correlation_id=correlation_id,
            score=0.785,
            level=RiskLevel.HIGH,
            confidence=0.7,
            factors=[{"name": "exploit"}],
            evidence=[{"detail": "ignored"}],
            assessment_metadata={},
            timestamp=_ts(70),
            provenance="risk_assessed",
        )
    )
    db_session.commit()

    KnowledgeGraphBuilder().build_for_correlation(db_session, correlation_id)

    queries = KnowledgeGraphQueries(DEFAULT_BOUNDS)
    graph = queries.get_correlation_graph(db_session, correlation_id)
    catalog = EvidenceCatalog.from_graph(graph)

    yield {
        "correlation_id": correlation_id,
        "event_id": event_id,
        "graph": graph,
        "catalog": catalog,
        "queries": queries,
        "detection_ref": catalog.by_kind("DETECTION")[0].reference,
        "correlation_ref": catalog.by_kind("CORRELATION")[0].reference,
        "risk_ref": catalog.by_kind("RISK_ASSESSMENT")[0].reference,
    }

    db_session.rollback()
    for model in (
        DebateConsensusRecord,
        DebateArgumentRecord,
        DebateAgentAssessmentRecord,
        DebateRoundRecord,
        DebateSessionRecord,
    ):
        db_session.execute(delete(model))
    # Remove only the graph nodes this fixture caused to be built.
    # `KnowledgeGraphBuilder.build_all` builds every correlation in the
    # database, and the graph tables are shared with the V3.22 graph tests, so
    # a blanket DELETE here would wipe state other test modules depend on.
    node_ids = [node["id"] for node in graph.nodes]
    if node_ids:
        db_session.execute(
            delete(KnowledgeGraphEdge).where(
                or_(
                    KnowledgeGraphEdge.source_node_id.in_(node_ids),
                    KnowledgeGraphEdge.target_node_id.in_(node_ids),
                )
            )
        )
        db_session.execute(
            delete(KnowledgeGraphNode).where(KnowledgeGraphNode.id.in_(node_ids))
        )
    db_session.execute(
        delete(RiskAssessment).where(RiskAssessment.risk_assessment_id == risk_id)
    )
    db_session.execute(
        delete(CorrelationMember).where(
            CorrelationMember.correlation_id == correlation_id
        )
    )
    db_session.execute(delete(DetectionResult).where(DetectionResult.event_id == event_id))
    db_session.execute(
        delete(CorrelationResult).where(
            CorrelationResult.correlation_id == correlation_id
        )
    )
    db_session.commit()


def agreement_script(
    detection_ref: str,
    correlation_ref: str,
    *,
    hypothesis: str = AGREED_HYPOTHESIS,
    confidence: float = 0.75,
    unresolved_questions: tuple[str, ...] = (),
) -> dict:
    """All five agents reach the same hypothesis from real evidence.

    Round 2 and round 3 are left empty here; a caller that needs argument ids
    can probe a first run, which keeps each test focused on one behaviour.
    """
    script: dict = {}
    for role in ROLES:
        script[f"{role}:1"] = {
            "observations": [
                {
                    "observation_kind": "observation",
                    "statement": "Seven detections reference one persisted event.",
                    "evidence_references": [detection_ref, correlation_ref],
                    "confidence": 0.9,
                }
            ],
            "hypotheses": [
                {
                    "observation_kind": "hypothesis",
                    "statement": hypothesis,
                    "evidence_references": [correlation_ref],
                    "confidence": confidence,
                }
            ],
            "limitations": {"limitations": ["No threat intelligence feed was available."]},
            "confidence": confidence,
        }
        script[f"{role}:2"] = {
            "arguments": [],
            "unresolved_questions": list(unresolved_questions),
        }
        script[f"{role}:3"] = {"counterarguments": []}
    return script


#: The two round-2 statements every agent raises, with the agent each one
#: targets. Argument ids are a pure function of these, so a test can target them
#: without running a probe first.
_ARGUMENT_TEMPLATES = (
    (
        "agent:skeptic",
        "supports",
        "Seven detections of one event support a single access pattern.",
    ),
    (
        "agent:detection_analyst",
        "opposes",
        "Detection counts alone do not establish malicious intent.",
    ),
)


def _argument_id(author_role: str, target_role: str, statement: str) -> str:
    """The id the engine will assign to this round-2 argument."""
    return str(
        deterministic_argument_id(
            round_kind=RoundKind.ROUND_TWO,
            author_role=AgentRole(author_role),
            target_role=target_role,
            target_hypothesis_id=AGREED_HYPOTHESIS_ID,
            statement=statement,
        )
    )


def argument_script(detection_ref: str, correlation_ref: str) -> dict:
    """A script whose agents argue in round 2 and counterargue in round 3.

    Round-3 counterarguments must target argument ids actually raised in round
    2. Those ids are deterministic, so they are computed here from the same
    inputs the engine uses rather than hard-coded.
    """
    script = agreement_script(detection_ref, correlation_ref)
    argument_ids: list[str] = []
    for role in ROLES:
        arguments = []
        for target_agent, stance, statement in _ARGUMENT_TEMPLATES:
            target_role = target_agent.removeprefix("agent:")
            arguments.append(
                {
                    "target_agent_id": target_agent,
                    "target_hypothesis_id": AGREED_HYPOTHESIS_ID,
                    "stance": stance,
                    "statement": statement,
                    "evidence_references": [correlation_ref],
                }
            )
            argument_ids.append(_argument_id(role, target_role, statement))
        script[f"{role}:2"] = {
            "arguments": arguments,
            "unresolved_questions": ["Was the account privileged at the time?"],
        }
    for index, role in enumerate(ROLES):
        script[f"{role}:3"] = {
            "counterarguments": [
                {
                    "target_argument_id": argument_ids[index % len(argument_ids)],
                    "weakness": "missing_evidence",
                    "statement": "That position overstates what correlation structure alone can establish.",
                    "evidence_references": [correlation_ref],
                }
            ]
        }
    return script


__all__ = [
    "AGREED_HYPOTHESIS",
    "AGREED_HYPOTHESIS_ID",
    "ROLES",
    "ScriptedDebateRuntime",
    "agreement_script",
    "argument_script",
]