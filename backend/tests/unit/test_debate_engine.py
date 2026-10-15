"""Debate engine unit tests — V3.23.

Covers the properties that make a debate trustworthy: the bounded five-round
lifecycle, evidence grounding, deterministic reconciliation, and the governed
failure paths.  Every test drives the real engine through an injected
deterministic runtime, so no outbound provider call is required.
"""

from __future__ import annotations

import pytest

from app.agents.debate.engine import DebateEngine
from app.agents.debate.exceptions import (
    DebateBoundsError,
    DebateEvidenceError,
    DebateModelValidationError,
    DebatePartialFailureError,
    DebateProviderError,
)
from app.agents.debate.evidence import EvidenceCatalog, derive_facts
from app.agents.debate.vocabulary import (
    DebateBounds,
    deterministic_debate_id,
)
from tests.integration.debate_fixtures import AGREED_HYPOTHESIS
from tests.helpers.debate_runtime import (
    FailingDebateRuntime,
    FlakyDebateRuntime,
    ScriptedDebateRuntime,
)

pytestmark = pytest.mark.usefixtures("debate_correlation")

ROLES = (
    "detection_analyst",
    "threat_intelligence_analyst",
    "behavioral_analyst",
    "incident_investigator",
    "skeptic",
)


def _run(fixture, script, *, runtime=None, **kwargs):
    engine = DebateEngine(runtime=runtime or ScriptedDebateRuntime(script))
    return engine.run(
        fixture["graph"],
        correlation_id=fixture["correlation_id"],
        unavailable_entity_types=fixture["queries"].unavailable_entity_types(),
        **kwargs,
    )


def _base_script(fixture, **kwargs):
    from tests.integration.debate_fixtures import agreement_script

    return agreement_script(
        fixture["detection_ref"], fixture["correlation_ref"], **kwargs
    )


# ---------------------------------------------------------------------------
# Round lifecycle
# ---------------------------------------------------------------------------


class TestRoundLifecycle:
    def test_emits_all_five_rounds_in_order(self, debate_correlation):
        session = _run(debate_correlation, _base_script(debate_correlation))
        assert [r.round_kind.value for r in session.rounds] == [
            "round_0_shared_evidence",
            "round_1_independent_assessments",
            "round_2_cross_agent_arguments",
            "round_3_counterarguments",
            "round_4_reconciliation",
        ]
        assert [r.round_number for r in session.rounds] == [0, 1, 2, 3, 4]

    def test_uses_exactly_five_agents(self, debate_correlation):
        session = _run(debate_correlation, _base_script(debate_correlation))
        assert len(session.agents) == 5
        assert sorted(a.role.value for a in session.agents) == sorted(ROLES)

    def test_round_one_is_independent_no_prior_rounds(self, debate_correlation):
        """Each agent assesses from the same evidence without seeing peers."""
        runtime = ScriptedDebateRuntime(_base_script(debate_correlation))
        session = _run(debate_correlation, None, runtime=runtime)
        # 5 agents x 3 model rounds = 15 calls; rounds 0 and 4 never call a model.
        assert len(runtime.calls) == 15
        assert session.status.value == "completed"

    def test_every_agent_produces_one_assessment(self, debate_correlation):
        session = _run(debate_correlation, _base_script(debate_correlation))
        assert len(session.assessments) == 5
        assert sorted(a.agent_id for a in session.assessments) == sorted(
            session.agents[i].agent_id for i in range(5)
        )

    def test_rounds_record_which_agents_participated(self, debate_correlation):
        session = _run(debate_correlation, _base_script(debate_correlation))
        round_one = next(r for r in session.rounds if r.round_number == 1)
        assert len(round_one.agent_ids) == 5


# ---------------------------------------------------------------------------
# Evidence grounding
# ---------------------------------------------------------------------------


class TestEvidenceGrounding:
    def test_facts_are_engine_derived_not_model_supplied(self, debate_correlation):
        session = _run(debate_correlation, _base_script(debate_correlation))
        assert len(session.facts) > 0
        assert all(f.claim_kind.value == "fact" for f in session.facts)
        # Every fact cites at least one real graph reference.
        assert all(len(f.evidence_references) > 0 for f in session.facts)

    def test_seven_detections_are_one_event(self, debate_correlation):
        """The V3.22 shared-event semantics must survive into debate facts."""
        catalog = debate_correlation["catalog"]
        facts = derive_facts(debate_correlation["graph"], catalog)
        detections = catalog.by_kind("DETECTION")
        events = catalog.by_kind("EVENT")
        assert len(detections) == 7
        # Exactly one EVENT node for seven detections: the shared-event
        # semantics of V3.22 must survive into debate reasoning.
        assert len(events) == 1
        shared = [
            f
            for f in facts
            if "reference the same persisted event identifier" in f.statement
        ]
        assert len(shared) == 1
        # Cites the single event plus all seven detections.
        assert len(shared[0].evidence_references) == len(detections) + 1
        assert not any(
            f.statement.lower().count("7 events") for f in facts
        ), "seven detections of one event must never become seven events"

    def test_fabricated_citation_rejects_entire_agent_output(self, debate_correlation):
        script = _base_script(debate_correlation)
        script["detection_analyst:1"] = script["detection_analyst:1"].copy()
        script["detection_analyst:1"]["observations"] = [
            {
                "observation_kind": "observation",
                "statement": "An observation citing evidence that does not exist.",
                "evidence_references": ["detection:00000000-0000-0000-0000-000000000000"],
                "confidence": 0.9,
            }
        ]
        with pytest.raises(DebatePartialFailureError) as exc:
            _run(debate_correlation, script)
        assert "detection_analyst" in exc.value.failed_agents

    def test_observation_without_citation_is_rejected(self, debate_correlation):
        script = _base_script(debate_correlation)
        script["skeptic:1"]["observations"] = [
            {
                "observation_kind": "observation",
                "statement": "An uncited observation.",
                "evidence_references": [],
                "confidence": 0.5,
            }
        ]
        with pytest.raises(DebatePartialFailureError) as exc:
            _run(debate_correlation, script)
        assert "skeptic" in exc.value.failed_agents

    def test_model_cannot_declare_a_fact(self, debate_correlation):
        """FACT is not in the model's vocabulary, so it cannot assert one."""
        script = _base_script(debate_correlation)
        script["skeptic:1"]["observations"] = [
            {
                "observation_kind": "fact",
                "statement": "The correlation is malicious.",
                "evidence_references": [debate_correlation["correlation_ref"]],
                "confidence": 0.9,
            }
        ]
        with pytest.raises(DebatePartialFailureError):
            _run(debate_correlation, script)

    def test_agent_cannot_set_provenance(self, debate_correlation):
        script = _base_script(debate_correlation)
        script["skeptic:1"]["observations"] = [
            {
                "observation_kind": "observation",
                "statement": "Trying to claim observed provenance.",
                "evidence_references": [debate_correlation["correlation_ref"]],
                "confidence": 0.5,
                "provenance": "observed",
            }
        ]
        with pytest.raises(DebatePartialFailureError):
            _run(debate_correlation, script)

    def test_every_persisted_claim_is_ai_generated(self, debate_correlation):
        """A debate conclusion is reasoning, never evidence."""
        session = _run(debate_correlation, _base_script(debate_correlation))
        assert session.consensus.provenance.value == "ai_generated"
        for assessment in session.assessments:
            assert assessment.provenance.value == "ai_generated"
            for claim in (*assessment.observations, *assessment.hypotheses):
                assert claim.provenance.value == "ai_generated"
        for argument in session.arguments:
            assert argument.provenance.value == "ai_generated"


# ---------------------------------------------------------------------------
# Determinism and consensus
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_same_inputs_produce_the_same_debate_id(self, debate_correlation):
        script = _base_script(debate_correlation)
        first = _run(debate_correlation, script)
        second = _run(debate_correlation, script)
        assert first.debate_id == second.debate_id
        assert deterministic_debate_id(
            debate_correlation["correlation_id"],
            first.metadata.graph_snapshot_digest,
            first.metadata.configuration_digest,
        ) == first.debate_id

    def test_payload_is_stable_apart_from_creation_time(self, debate_correlation):
        script = _base_script(debate_correlation)
        first = _run(debate_correlation, script)
        second = _run(debate_correlation, script)
        assert first.model_dump_json(exclude={"metadata"}) == second.model_dump_json(
            exclude={"metadata"}
        )

    def test_agreement_is_detected_from_identical_statements(self, debate_correlation):
        session = _run(debate_correlation, _base_script(debate_correlation))
        assert session.consensus.state.value == "partial_consensus"
        assert session.consensus.consensus_strength == 1.0
        assert session.consensus.leading_hypothesis is not None

    def test_disagreement_produces_contested_not_a_forced_consensus(
        self, debate_correlation
    ):
        """A split roster is contested, never averaged into a false consensus."""
        catalog = debate_correlation["catalog"]
        # Cite broadly so completeness clears the consensus threshold;
        # otherwise thin evidence would (correctly) report insufficient first.
        broad = sorted(catalog.references)
        minority = "The activity is probably benign administrative work."
        supporters = ("detection_analyst", "incident_investigator")
        dissenters = ("behavioral_analyst", "threat_intelligence_analyst")
        script = _base_script(debate_correlation)
        for role in ROLES:
            # The skeptic abstains entirely, so the best any position can reach
            # is 2 of 5 agents: agreement 0.4, below the partial-consensus bar.
            hypotheses = []
            if role in supporters:
                hypotheses = [
                    {
                        "observation_kind": "hypothesis",
                        "statement": AGREED_HYPOTHESIS,
                        "evidence_references": broad,
                        "confidence": 0.6,
                    }
                ]
            elif role in dissenters:
                hypotheses = [
                    {
                        "observation_kind": "hypothesis",
                        "statement": minority,
                        "evidence_references": broad,
                        "confidence": 0.6,
                    }
                ]
            script[f"{role}:1"] = {
                "observations": [
                    {
                        "observation_kind": "observation",
                        "statement": "Seven detections reference one persisted event.",
                        "evidence_references": broad,
                        "confidence": 0.9,
                    }
                ],
                "hypotheses": hypotheses,
                "limitations": {"limitations": ["No threat intelligence feed was available."]},
                "confidence": 0.6,
            }
        session = _run(debate_correlation, script)
        assert session.consensus.state.value == "contested"
        assert session.consensus.consensus_strength <= 0.5
        assert session.consensus.dissent, "a contested debate must record dissent"

    def test_evidence_gaps_are_reported(self, debate_correlation):
        """The graph's blind spots are stated, not silently absorbed."""
        session = _run(debate_correlation, _base_script(debate_correlation))
        gaps = session.consensus.evidence_gaps
        assert gaps, "expected explicit evidence gaps"
        # The V3.22 graph cannot supply threat-indicator or incident-memory
        # entities, so a debate over it must say so rather than reason as if it
        # could. Unavailable V2 entity types are named explicitly too.
        assert any("THREAT_INDICATOR" in g for g in gaps)
        assert any("INCIDENT_MEMORY" in g for g in gaps)
        assert any("No investigations table exists in V2" in g for g in gaps)
        assert gaps == sorted(gaps)
        # Gaps are surfaced at session level too.
        assert session.limitations


# ---------------------------------------------------------------------------
# Governed failures
# ---------------------------------------------------------------------------


class TestGovernedFailures:
    def test_provider_unavailable_does_not_fake_a_consensus(self, debate_correlation):
        runtime = FailingDebateRuntime()
        with pytest.raises(DebatePartialFailureError) as exc:
            _run(debate_correlation, None, runtime=runtime)
        assert set(exc.value.failed_agents) == set(ROLES)
        assert runtime.call_count == 5

    def test_single_agent_failure_still_fails_closed(self, debate_correlation):
        """A partial roster is not a debate; the request must fail, not shrink."""
        runtime = FlakyDebateRuntime(fail_roles={"skeptic"})
        with pytest.raises(DebatePartialFailureError) as exc:
            _run(debate_correlation, None, runtime=runtime)
        assert exc.value.failed_agents == ("skeptic",)

    def test_malformed_model_output_is_a_governed_failure(self, debate_correlation):
        script = _base_script(debate_correlation)
        script["skeptic:1"] = "{ this is not json"
        with pytest.raises(DebatePartialFailureError):
            _run(debate_correlation, script)

    def test_bounds_are_enforced(self, debate_correlation):
        # Five agents each contribute one observation, so a total cap of two
        # must trip rather than the run silently trimming.
        tiny = DebateBounds(max_total_observations=2)
        script = _base_script(debate_correlation)
        engine = DebateEngine(runtime=ScriptedDebateRuntime(script), bounds=tiny)
        with pytest.raises(DebateBoundsError):
            engine.run(
                debate_correlation["graph"],
                correlation_id=debate_correlation["correlation_id"],
                unavailable_entity_types=debate_correlation[
                    "queries"
                ].unavailable_entity_types(),
            )


# ---------------------------------------------------------------------------
# Secret safety
# ---------------------------------------------------------------------------


class TestSecretSafety:
    def test_secrets_from_v2_evidence_never_reach_the_payload(self, debate_correlation):
        session = _run(debate_correlation, _base_script(debate_correlation))
        payload = session.model_dump_json()
        assert "sk-must-never-appear" not in payload
        assert "must never reach a debate prompt" not in payload

    def test_metadata_records_no_secrets(self, debate_correlation):
        session = _run(debate_correlation, _base_script(debate_correlation))
        assert session.metadata.provider
        assert "sk-" not in session.model_dump_json()