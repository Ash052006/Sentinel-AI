"""Step 16 — Incident Memory deterministic extraction tests.

Scope: this module verifies the memory **extraction layer**: the policy
(sufficiency, canonical ordering, assembly) and the extractor entry point
(input guard, injected clock/UUID, memory-type filters, service-boundary
secret re-scan).  It exercises no persistence, no API, no Kafka, no LLM,
no RAG/vector/graph retrieval, and no response/mitigation behaviour.

Covered explicitly:

1.  policy sufficiency            — per-type rules, zero-result never raises
2.  canonical order               — enum-declaration emission order
3.  content restriction           — type carries only its own content
4.  provenance                     — RECALLED output, original sources
5.  identity preservation          — supplied ids/order carried intact
6.  determinism                    — injected clock+UUID ⇒ byte-identical
7.  immutability                   — input↔memory never share mutable state
8.  confidence                     — carried as supplied, never derived
9.  memory-type filter             — restrict / unsupported / empty
10. input guard                    — non-input, naive clock, bad factory
11. safety                         — post-construction secret re-scan
12. sufficiency absence            — never fabricated, no metaphors
13. policy metadata                — deterministic, secret-free, id-free
14. performance/bounds smoke       — within-cap inputs stay tractable
"""

import copy
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.schemas.incident_memory import MemoryIndicator, MemoryType
from app.schemas.security_event import Provenance
from app.services.incident_memory import (
    IncidentMemoryError,
    IncidentMemoryExtractor,
    IncidentMemoryInput,
    IncidentMemorySafetyError,
    InvalidIncidentMemoryInputError,
    UnsupportedMemorySignalError,
    policy,
)

_TIMESTAMP = datetime(2026, 9, 21, 12, 0, 0, tzinfo=timezone.utc)
_ALT_TIMESTAMP = _TIMESTAMP + timedelta(hours=3)

_ALL_TYPES = tuple(MemoryType)


def _source_dict(provenance=Provenance.OBSERVED, **extra):
    payload = {
        "source_id": uuid.uuid4(),
        "provenance": provenance,
        "label": None,
        "event_id": None,
        "detection_id": None,
        "correlation_id": None,
        "risk_assessment_id": None,
        "investigation_id": None,
        "attribution_assessment_id": None,
        "finding_id": None,
        "metadata": {},
    }
    payload.update(extra)
    if provenance is Provenance.OBSERVED and "event_id" not in extra:
        payload["event_id"] = uuid.uuid4()
    if provenance is Provenance.AI_GENERATED and "investigation_id" not in extra:
        payload["investigation_id"] = uuid.uuid4()
    return payload


def _input(**overrides):
    """Fully-grounded, all-content input used across the module."""
    source = _source_dict()
    source_ids = [source["source_id"]]
    payload = {
        "correlation_id": uuid.uuid4(),
        "title": "phishing campaign incident",
        "summary": "Two waves of phishing bypassed the filter.",
        "confidence": 0.5,
        "sources": [source],
        "indicators": [
            {
                "indicator_id": uuid.uuid4(),
                "indicator_type": "ipv4",
                "value": "203.0.113.9",
                "source_ids": source_ids,
                "metadata": {},
            }
        ],
        "entities": [
            {
                "entity_id": uuid.uuid4(),
                "entity_type": "actor",
                "identifier": "group-x",
                "source_ids": source_ids,
                "metadata": {},
            }
        ],
        "techniques": [
            {
                "technique_id": uuid.uuid4(),
                "technique_code": "T1566",
                "name": "Phishing",
                "source_ids": source_ids,
                "metadata": {},
            }
        ],
        "findings": [
            {
                "finding_id": uuid.uuid4(),
                "finding_type": "root-cause",
                "title": "Filter miss",
                "confidence": 0.6,
                "source_ids": source_ids,
                "metadata": {},
            }
        ],
        "actions": [
            {
                "action_id": uuid.uuid4(),
                "action_type": "tuning",
                "description": "Tuned filter rules",
                "source_ids": source_ids,
                "metadata": {},
            }
        ],
        "outcome": {
            "outcome_status": "resolved",
            "summary": "Campaign mitigated",
            "source_ids": source_ids,
            "metadata": {},
        },
    }
    payload.update(overrides)
    return IncidentMemoryInput(**payload)


# ---------------------------------------------------------------------------
# 1. Policy sufficiency
# ---------------------------------------------------------------------------


class TestSufficiency:
    def test_empty_input_satisfies_nothing(self):
        data = IncidentMemoryInput(title="bare")
        assert policy.satisfied_memory_types(data) == ()

    def test_incident_summary_requires_title_and_summary_and_sources(self):
        with_summary = IncidentMemoryInput(
            title="t", summary="s", sources=[_source_dict()]
        )
        assert policy.memory_satisfied(MemoryType.INCIDENT_SUMMARY, with_summary)

        no_summary = IncidentMemoryInput(title="t", sources=[_source_dict()])
        assert not policy.memory_satisfied(MemoryType.INCIDENT_SUMMARY, no_summary)

        no_sources = IncidentMemoryInput(title="t", summary="s", sources=[])
        assert not policy.memory_satisfied(MemoryType.INCIDENT_SUMMARY, no_sources)

    def test_requiring_grounded_items_per_type(self):
        grounded = _input()
        for memory_type in (
            MemoryType.INDICATOR_OBSERVATION,
            MemoryType.ATTACK_PATTERN,
            MemoryType.INVESTIGATION_FINDING,
        ):
            assert policy.memory_satisfied(memory_type, grounded)

        referenceless = IncidentMemoryInput(
            title="t",
            sources=grounded.sources,
            indicators=[
                MemoryIndicator(
                    indicator_id=uuid.uuid4(),
                    indicator_type="ipv4",
                    value="1.2.3.4",
                    source_ids=[],
                )
            ],
        )
        assert not policy.memory_satisfied(MemoryType.INDICATOR_OBSERVATION, referenceless)

        # A single referenceless item vetoes the whole type (no silent drop)
        sid = grounded.sources[0].source_id
        mixed = IncidentMemoryInput(
            title="t",
            sources=grounded.sources,
            indicators=[
                MemoryIndicator(
                    indicator_id=uuid.uuid4(),
                    indicator_type="ipv4",
                    value="1.2.3.4",
                    source_ids=[sid],
                ),
                MemoryIndicator(
                    indicator_id=uuid.uuid4(),
                    indicator_type="domain",
                    value="evil.example",
                    source_ids=[],
                ),
            ],
        )
        assert not policy.memory_satisfied(MemoryType.INDICATOR_OBSERVATION, mixed)

    def test_mitigation_outcome_actions_or_outcome(self):
        actions_only = _input(outcome=None)
        assert policy.memory_satisfied(MemoryType.MITIGATION_OUTCOME, actions_only)

        outcome_only = _input(actions=[])
        assert policy.memory_satisfied(MemoryType.MITIGATION_OUTCOME, outcome_only)

        none_at_all = _input(actions=[], outcome=None)
        assert not policy.memory_satisfied(MemoryType.MITIGATION_OUTCOME, none_at_all)

        ungrounded_outcome = _input(actions=[], outcome={"outcome_status": "resolved", "source_ids": []})
        assert not policy.memory_satisfied(MemoryType.MITIGATION_OUTCOME, ungrounded_outcome)


# ---------------------------------------------------------------------------
# 2. Canonical ordering
# ---------------------------------------------------------------------------


class TestCanonicalOrdering:
    def test_satisfied_types_in_enum_order(self):
        data = _input()
        got = policy.satisfied_memory_types(data)
        assert got == tuple(MemoryType)

    def test_incident_summary_precedes_indicator_observation(self):
        data = _input()
        got = [t.value for t in policy.satisfied_memory_types(data)]
        assert got.index("incident_summary") < got.index("indicator_observation")

    def test_extractor_emits_in_canonical_order(self):
        extractor = IncidentMemoryExtractor()
        memories = extractor.extract(_input(), clock=_TIMESTAMP)
        assert [m.memory_type for m in memories] == list(MemoryType)


class TestAssembly:
    def _extract_one(self, data, memory_type):
        extractor = IncidentMemoryExtractor()
        out = extractor.extract(
            data, clock=_TIMESTAMP, memory_types=[memory_type]
        )
        assert len(out) == 1
        return out[0]

    def test_incident_summary_carries_summary(self):
        m = self._extract_one(_input(), MemoryType.INCIDENT_SUMMARY)
        assert m.summary == "Two waves of phishing bypassed the filter."
        assert m.indicators == []
        assert m.findings == []

    def test_other_types_drop_summary(self):
        for memory_type in (
            MemoryType.INDICATOR_OBSERVATION,
            MemoryType.ATTACK_PATTERN,
            MemoryType.INVESTIGATION_FINDING,
            MemoryType.MITIGATION_OUTCOME,
        ):
            m = self._extract_one(_input(), memory_type)
            assert m.summary is None

    def test_title_carried_on_every_memory(self):
        for memory_type in _ALL_TYPES:
            m = self._extract_one(_input(), memory_type)
            assert m.title == "phishing campaign incident"

    def test_type_carries_only_its_own_content(self):
        data = _input()
        indicator_mem = self._extract_one(data, MemoryType.INDICATOR_OBSERVATION)
        assert len(indicator_mem.indicators) == 1
        assert indicator_mem.techniques == []
        assert indicator_mem.actions == []

        technique_mem = self._extract_one(data, MemoryType.ATTACK_PATTERN)
        assert len(technique_mem.techniques) == 1
        assert technique_mem.indicators == []

        finding_mem = self._extract_one(data, MemoryType.INVESTIGATION_FINDING)
        assert len(finding_mem.findings) == 1
        assert finding_mem.actions == []

        mitigation_mem = self._extract_one(data, MemoryType.MITIGATION_OUTCOME)
        assert len(mitigation_mem.actions) == 1
        assert mitigation_mem.outcome.outcome_status == "resolved"
        assert mitigation_mem.findings == []

    def test_source_ids_preserved_on_items(self):
        data = _input()
        source_id = data.sources[0].source_id
        indicator_id = data.indicators[0].indicator_id
        m = self._extract_one(data, MemoryType.INDICATOR_OBSERVATION)
        assert m.indicators[0].indicator_id == indicator_id
        assert m.indicators[0].source_ids == [source_id]
        assert m.sources[0].source_id == source_id

    def test_ai_source_keeps_investigation_reference(self):
        investigation_id = uuid.uuid4()
        source = _source_dict(
            provenance=Provenance.AI_GENERATED,
            investigation_id=investigation_id,
        )
        data = _input(
            sources=[source],
            indicators=[{
                "indicator_type": "domain",
                "value": "evil.example",
                "source_ids": [source["source_id"]],
            }],
            entities=[],
            techniques=[],
            findings=[{
                "finding_type": "conclusion",
                "title": "Coordinated campaign",
                "source_ids": [source["source_id"]],
            }],
            actions=[],
            outcome=None,
        )
        m = self._extract_one(data, MemoryType.INVESTIGATION_FINDING)
        assert m.sources[0].provenance is Provenance.AI_GENERATED
        assert m.sources[0].investigation_id == investigation_id


# ---------------------------------------------------------------------------
# 4. Provenance
# ---------------------------------------------------------------------------


class TestOutputProvenance:
    def test_memory_pinned_to_recalled(self):
        for memory in IncidentMemoryExtractor().extract(_input(), clock=_TIMESTAMP):
            assert memory.provenance is Provenance.RECALLED

    def test_sources_keep_original_provenance(self):
        data = _input()
        assert data.sources[0].provenance is Provenance.OBSERVED
        for memory in IncidentMemoryExtractor().extract(data, clock=_TIMESTAMP):
            assert memory.sources[0].provenance is Provenance.OBSERVED
            assert memory.sources[0].provenance is not Provenance.RECALLED


# ---------------------------------------------------------------------------
# 6. Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def _sequential_ids(self):
        counter = iter(range(1, 1000))
        return lambda: uuid.UUID(int=next(counter))

    def test_identical_input_with_clock_and_factory_byte_identical(self):
        data = _input()
        extractor = IncidentMemoryExtractor()
        first = extractor.extract(data, clock=_TIMESTAMP, uuid_factory=self._sequential_ids())
        second = extractor.extract(data, clock=_TIMESTAMP, uuid_factory=self._sequential_ids())
        assert first == second
        assert [m.model_dump_json() for m in first] == [m.model_dump_json() for m in second]

    def test_two_extractions_no_shared_state(self):
        data = _input()
        extractor = IncidentMemoryExtractor()
        first = extractor.extract(data, clock=_TIMESTAMP, uuid_factory=self._sequential_ids())
        second = extractor.extract(data, clock=_TIMESTAMP, uuid_factory=self._sequential_ids())
        first[0].metadata["note"] = "changed"
        assert "note" not in second[0].metadata
        assert first[0] != second[0]

    def test_created_at_stamped_from_clock(self):
        m = IncidentMemoryExtractor().extract(
            _input(), clock=_ALT_TIMESTAMP
        )[0]
        assert m.created_at == _ALT_TIMESTAMP
        assert m.created_at.tzinfo is not None

    def test_default_clock_is_timezone_aware(self):
        m = IncidentMemoryExtractor().extract(_input())[0]
        assert m.created_at.tzinfo is not None
        assert m.created_at.utcoffset() is not None

    def test_correlation_id_carried_everywhere(self):
        data = _input()
        for memory in IncidentMemoryExtractor().extract(data, clock=_TIMESTAMP):
            assert memory.correlation_id == data.correlation_id


# ---------------------------------------------------------------------------
# 7. Immutability
# ---------------------------------------------------------------------------


class TestImmutability:
    def test_mutating_input_after_extraction_does_not_change_memory(self):
        data = _input()
        memory = IncidentMemoryExtractor().extract(
            data, clock=_TIMESTAMP, memory_types=[MemoryType.INDICATOR_OBSERVATION]
        )[0]
        data.indicators[0].value = "1.1.1.1"
        assert memory.indicators[0].value == "203.0.113.9"

    def test_mutating_memory_does_not_change_input(self):
        data = _input()
        memory = IncidentMemoryExtractor().extract(
            data, clock=_TIMESTAMP, memory_types=[MemoryType.INDICATOR_OBSERVATION]
        )[0]
        memory.indicators[0].value = "2.2.2.2"
        assert data.indicators[0].value == "203.0.113.9"

    def test_input_never_mutated_per_field(self):
        data = _input()
        copy_before = copy.deepcopy(data.model_dump(mode="json"))
        IncidentMemoryExtractor().extract(data, clock=_TIMESTAMP)
        assert data.model_dump(mode="json") == copy_before


# ---------------------------------------------------------------------------
# 8. Confidence
# ---------------------------------------------------------------------------


class TestConfidenceCarried:
    def test_carried_as_supplied(self):
        for memory in IncidentMemoryExtractor().extract(
            _input(confidence=0.3), clock=_TIMESTAMP
        ):
            assert memory.confidence == 0.3

    def test_none_when_not_supplied(self):
        for memory in IncidentMemoryExtractor().extract(
            _input(confidence=None), clock=_TIMESTAMP
        ):
            assert memory.confidence is None

    def test_independent_of_finding_confidence(self):
        # Memory-level confidence is supplied independently of any finding's
        # own confidence; neither overwrites the other.
        data = _input(confidence=0.3)
        finding_mem = IncidentMemoryExtractor().extract(
            data, clock=_TIMESTAMP, memory_types=[MemoryType.INVESTIGATION_FINDING]
        )[0]
        assert finding_mem.confidence == 0.3
        assert finding_mem.findings[0].confidence == 0.6


# ---------------------------------------------------------------------------
# 9. Memory-type filter
# ---------------------------------------------------------------------------


class TestMemoryTypeFilter:
    def test_restricts_to_requested(self):
        out = IncidentMemoryExtractor().extract(
            _input(), clock=_TIMESTAMP,
            memory_types=[MemoryType.ATTACK_PATTERN],
        )
        assert [m.memory_type for m in out] == [MemoryType.ATTACK_PATTERN]

    def test_empty_filter_extracts_nothing(self):
        out = IncidentMemoryExtractor().extract(
            _input(), clock=_TIMESTAMP, memory_types=[]
        )
        assert out == []

    def test_duplicate_requests_deduplicated(self):
        out = IncidentMemoryExtractor().extract(
            _input(), clock=_TIMESTAMP,
            memory_types=[MemoryType.INCIDENT_SUMMARY, MemoryType.INCIDENT_SUMMARY],
        )
        assert len(out) == 1

    def test_unsupported_memory_type_raises(self):
        with pytest.raises(UnsupportedMemorySignalError):
            IncidentMemoryExtractor().extract(
                _input(), clock=_TIMESTAMP, memory_types=["crime_prediction"]
            )

    def test_unsupported_never_leaks_value(self):
        with pytest.raises(UnsupportedMemorySignalError) as exc:
            IncidentMemoryExtractor().extract(
                _input(), clock=_TIMESTAMP, memory_types=["pure_eval_shell"]
            )
        assert "pure_eval_shell" not in str(exc.value)


# ---------------------------------------------------------------------------
# 10. Input guard
# ---------------------------------------------------------------------------


class TestInputGuard:
    def test_non_input_object_rejected(self):
        with pytest.raises(InvalidIncidentMemoryInputError):
            IncidentMemoryExtractor().extract(
                {"title": "nope"}, clock=_TIMESTAMP
            )

    def test_naive_clock_rejected(self):
        with pytest.raises(InvalidIncidentMemoryInputError):
            IncidentMemoryExtractor().extract(
                _input(), clock=datetime(2026, 9, 21, 12, 0, 0)
            )

    def test_non_datetime_clock_rejected(self):
        with pytest.raises(InvalidIncidentMemoryInputError):
            IncidentMemoryExtractor().extract(_input(), clock="2026-09-21T12:00:00Z")

    def test_non_callable_factory_rejected(self):
        with pytest.raises(InvalidIncidentMemoryInputError):
            IncidentMemoryExtractor().extract(_input(), clock=_TIMESTAMP, uuid_factory="uuid4")

    def test_error_is_member_of_hierarchy(self):
        assert issubclass(InvalidIncidentMemoryInputError, IncidentMemoryError)
        assert issubclass(UnsupportedMemorySignalError, IncidentMemoryError)
        assert issubclass(IncidentMemorySafetyError, IncidentMemoryError)


# ---------------------------------------------------------------------------
# 11. Safety: post-construction secret re-scan
# ---------------------------------------------------------------------------


class TestSafetyRescan:
    def test_direct_construction_rejects_secret(self):
        with pytest.raises(Exception):
            _input(summary="keep the password safe")

    def test_post_construction_secret_rejected_at_extraction(self):
        data = _input()
        data.summary = "the password is hunter2"
        with pytest.raises(IncidentMemorySafetyError):
            IncidentMemoryExtractor().extract(data, clock=_TIMESTAMP)

    def test_safety_error_leaks_no_content(self):
        data = _input()
        data.summary = "api_key=sk_live_9f8e7e1a2b3c"
        with pytest.raises(IncidentMemorySafetyError) as exc:
            IncidentMemoryExtractor().extract(data, clock=_TIMESTAMP)
        assert "sk_live_9f8e7e1a2b3c" not in str(exc.value)
        assert "api_key" in str(exc.value)

    def test_cross_boundary_secret_value_rejected(self):
        data = _input()
        data.indicators[0].value = "bearer token mid-stream"
        with pytest.raises(IncidentMemorySafetyError):
            IncidentMemoryExtractor().extract(data, clock=_TIMESTAMP)


# ---------------------------------------------------------------------------
# 12. Absence is never fabricated
# ---------------------------------------------------------------------------


class TestNeverFabricated:
    def test_no_summary_never_invented(self):
        data = _input()
        data.summary = None
        out = IncidentMemoryExtractor().extract(data, clock=_TIMESTAMP)
        assert MemoryType.INCIDENT_SUMMARY not in [m.memory_type for m in out]
        assert all(m.summary is None for m in out)

    def test_empty_input_never_yields_placeholder(self):
        out = IncidentMemoryExtractor().extract(
            IncidentMemoryInput(title="empty"), clock=_TIMESTAMP
        )
        assert out == []

    def test_no_metadata_invention(self):
        memory = IncidentMemoryExtractor().extract(
            _input(), clock=_TIMESTAMP, memory_types=[MemoryType.ATTACK_PATTERN]
        )[0]
        # Policy metadata is counts + decision only; no content absorbed.
        assert "indicator_count" in memory.metadata
        assert memory.metadata["decision"] == "all_techniques_source_grounded"


# ---------------------------------------------------------------------------
# 13. Policy metadata
# ---------------------------------------------------------------------------


class TestPolicyMetadata:
    def test_deterministic_and_secret_free(self):
        m1 = policy.build_policy_metadata(MemoryType.ATTACK_PATTERN, _input())
        m2 = policy.build_policy_metadata(MemoryType.ATTACK_PATTERN, _input())
        assert m1 == m2
        assert all(isinstance(v, (str, int, bool)) for v in m1.values())
        assert "policy" in m1
        assert "memory_type" in m1
        assert "timestamp" not in m1
        assert "memory_id" not in m1

    def test_decision_reason_names(self):
        assert policy.decision_reason(MemoryType.INCIDENT_SUMMARY, _input()) == "incident_summary_with_source_grounding"
        assert policy.decision_reason(MemoryType.ATTACK_PATTERN, _input()) == "all_techniques_source_grounded"


# ---------------------------------------------------------------------------
# 14. Bounds/perf smoke
# ---------------------------------------------------------------------------


class TestPerformanceSmoke:
    def test_max_content_bounds_tractable(self):
        source_ids = [uuid.uuid4(), uuid.uuid4()]
        sources = [
            _source_dict(source_id=s, event_id=uuid.uuid4()) for s in source_ids
        ]
        data = IncidentMemoryInput(
            correlation_id=uuid.uuid4(),
            title="large-but-bounded",
            summary="within the hard contract caps",
            confidence=0.9,
            sources=sources,
            indicators=[
                {
                    "indicator_type": "ipv4",
                    "value": f"203.0.113.{i % 250}",
                    "source_ids": source_ids,
                }
                for i in range(128)
            ],
        )
        extractor = IncidentMemoryExtractor()
        out = extractor.extract(data, clock=_TIMESTAMP)
        assert len(out) > 0
        indicator_mem = [m for m in out if m.memory_type is MemoryType.INDICATOR_OBSERVATION][0]
        assert len(indicator_mem.indicators) == 128