"""Step 16 — Incident Memory domain contract tests.

Scope: this test module verifies the *contract only*.  It exercises no
extraction decision, no memory assembly, no persistence, no API, no LLM
call, no RAG/vector/graph behaviour, and no response/mitigation — the
contract defines the structured, bounded, secret-safe, deterministic,
provenance-aware shape that the deterministic extraction layer (see
``test_incident_memory_extraction.py``) fills.

Covered explicitly:

1.  memory types                 — five values, serialize as value
2.  provenance                   — RECALLED pinned; prior values intact
3.  memory is historical         — never current evidence, no masquerade
4.  source provenance            — provenance→reference map coherence
5.  source RECALLED              — forbidden; finding_id AI_GENERATED-only
6.  content models               — bounded, blank/oversized rejected
7.  confidence                   — bounds, finiteness, bool rejected,
                                  independence from other pipelines
8.  boundaries                   — list caps, metadata depth/size, ref caps
9.  cross-references             — dangling rejected, resolved accepted,
                                  duplicates preserved
10. secret safety                — all eight patterns rejected
11. JSON safety                  — sets/bytes/objects/NaN/depth/cycles
12. immutability                 — nested inputs never aliased
13. determinism                  — identical input ⇒ identical JSON
14. timestamps                   — tz-aware required, naive rejected
15. unknown fields               — ignored (SentinelAI default)
16. security isolation           — no framework imports (AST)
"""

import ast
import json
import math
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.schemas import (
    IncidentMemory,
    MAX_MEMORY_ACTIONS,
    MAX_MEMORY_ENTITIES,
    MAX_MEMORY_FINDINGS,
    MAX_MEMORY_IDENTIFIER_LENGTH,
    MAX_MEMORY_INDICATORS,
    MAX_MEMORY_LABEL_LENGTH,
    MAX_MEMORY_METADATA_DEPTH,
    MAX_MEMORY_METADATA_SERIALIZED_BYTES,
    MAX_MEMORY_SOURCE_REFERENCES_PER_ITEM,
    MAX_MEMORY_SOURCES,
    MAX_MEMORY_SUMMARY_LENGTH,
    MAX_MEMORY_TECHNIQUES,
    MAX_MEMORY_TECHNIQUE_CODE_LENGTH,
    MAX_MEMORY_TITLE_LENGTH,
    MAX_MEMORY_VALUE_LENGTH,
    MemoryAction,
    MemoryEntity,
    MemoryFinding,
    MemoryIndicator,
    MemoryOutcome,
    MemorySource,
    MemoryTechnique,
    MemoryType,
)
from app.schemas.security_event import Provenance

BACKEND = Path(__file__).resolve().parent.parent.parent

_TIMESTAMP = datetime(2026, 9, 21, 12, 0, 0, tzinfo=timezone.utc)
_UTC_OFFSET = timedelta(hours=5, minutes=30)

_SECRET_PATTERN_SAMPLES = (
    "api_key_default",
    "authorization_bearer",
    "bearer_credential",
    "super_secret",
    "user_password",
    "session_cookie",
    "session_token_value",
    "auth_jwt",
)


def _source(**overrides):
    """Default source-backed memory source (OBSERVED event)."""
    defaults = {
        "source_id": uuid.uuid4(),
        "provenance": Provenance.OBSERVED,
        "label": "telemetry-event",
        "event_id": uuid.uuid4(),
    }
    defaults.update(overrides)
    return MemorySource(**defaults)


def _indicator(source_ids=None, **overrides):
    defaults = {
        "indicator_id": uuid.uuid4(),
        "indicator_type": "ipv4",
        "value": "203.0.113.9",
        "source_ids": source_ids or [],
    }
    defaults.update(overrides)
    return MemoryIndicator(**defaults)


def _memory(source_ids_map=None, **overrides):
    """Default fully-grounded memory record (INCIDENT_SUMMARY)."""
    source = _source()
    defaults = {
        "memory_id": uuid.uuid4(),
        "memory_type": MemoryType.INCIDENT_SUMMARY,
        "title": "mail-filter bypass incident",
        "summary": "Two phishing waves bypassed the filter before tuning.",
        "correlation_id": uuid.uuid4(),
        "sources": [source],
        "created_at": _TIMESTAMP,
    }
    defaults.update(overrides)
    return IncidentMemory(**defaults)


# ---------------------------------------------------------------------------
# 1. Memory types
# ---------------------------------------------------------------------------


class TestMemoryTypes:
    def test_values(self):
        assert MemoryType.INCIDENT_SUMMARY.value == "incident_summary"
        assert MemoryType.INDICATOR_OBSERVATION.value == "indicator_observation"
        assert MemoryType.ATTACK_PATTERN.value == "attack_pattern"
        assert MemoryType.INVESTIGATION_FINDING.value == "investigation_finding"
        assert MemoryType.MITIGATION_OUTCOME.value == "mitigation_outcome"
        assert len(MemoryType) == 5

    def test_serializes_as_value(self):
        m = _memory(memory_type=MemoryType.ATTACK_PATTERN)
        assert '"attack_pattern"' in m.model_dump_json()

    def test_unknown_value_rejected(self):
        with pytest.raises((ValidationError, ValueError)):
            MemoryType("crime_prediction")


# ---------------------------------------------------------------------------
# 2. Provenance: additive RECALLED, prior values intact
# ---------------------------------------------------------------------------


class TestProvenance:
    def test_recalled_added_additively(self):
        assert Provenance.RECALLED.value == "recalled"
        assert len(Provenance) == 13

    def test_learned_added_additively(self):
        assert Provenance.LEARNED.value == "learned"
        assert Provenance.LEARNED is not Provenance.RECALLED

    def test_prior_values_intact(self):
        for expected, actual in (
            ("observed", Provenance.OBSERVED),
            ("enriched", Provenance.ENRICHED),
            ("reconstructed", Provenance.RECONSTRUCTED),
            ("detected", Provenance.DETECTED),
            ("correlated", Provenance.CORRELATED),
            ("risk_assessed", Provenance.RISK_ASSESSED),
            ("ai_generated", Provenance.AI_GENERATED),
            ("attribution_assessed", Provenance.ATTRIBUTION_ASSESSED),
        ):
            assert actual.value == expected


# ---------------------------------------------------------------------------
# 3. Memory is historical memory, never current evidence
# ---------------------------------------------------------------------------


class TestMemoryIsHistorical:
    def test_recalled_is_default(self):
        m = _memory()
        assert m.provenance is Provenance.RECALLED

    def test_other_provenance_rejected(self):
        for provenance in (
            Provenance.OBSERVED,
            Provenance.ENRICHED,
            Provenance.RECONSTRUCTED,
            Provenance.DETECTED,
            Provenance.CORRELATED,
            Provenance.RISK_ASSESSED,
            Provenance.AI_GENERATED,
            Provenance.ATTRIBUTION_ASSESSED,
        ):
            with pytest.raises(ValidationError):
                _memory(provenance=provenance)

    def test_recalled_memory_cannot_claim_current_evidence_fields(self):
        m = _memory()
        # The memory record carries no current-evidence identity fields; it
        # references its origins only through provenance-aware *sources*.
        assert not hasattr(m, "event_id")
        assert not hasattr(m, "detection_id")
        assert not hasattr(m, "risk_assessment_id")
        assert not hasattr(m, "attribution_assessment_id")


# ---------------------------------------------------------------------------
# 4. Source provenance coherence
# ---------------------------------------------------------------------------


class TestSourceProvenance:
    def test_reference_map_coherent(self):
        cases = (
            (Provenance.OBSERVED, "event_id"),
            (Provenance.ENRICHED, "event_id"),
            (Provenance.RECONSTRUCTED, "event_id"),
            (Provenance.DETECTED, "detection_id"),
            (Provenance.CORRELATED, "correlation_id"),
            (Provenance.RISK_ASSESSED, "risk_assessment_id"),
            (Provenance.AI_GENERATED, "investigation_id"),
            (Provenance.ATTRIBUTION_ASSESSED, "attribution_assessment_id"),
        )
        for provenance, field in cases:
            source = _source(provenance=provenance, **{field: uuid.uuid4()})
            assert getattr(source, field) is not None
            assert source.provenance is provenance

    def test_matching_reference_required(self):
        for provenance in (
            Provenance.DETECTED,
            Provenance.CORRELATED,
            Provenance.RISK_ASSESSED,
            Provenance.AI_GENERATED,
            Provenance.ATTRIBUTION_ASSESSED,
        ):
            with pytest.raises(ValidationError):
                _source(provenance=provenance)

    def test_extra_references_allowed_lock_step_with_attribution_step14(self):
        # An OBSERVED event source may also legitimately carry a
        # detection-derived reference; the contract enforces the *matching*
        # reference, exactly like Step 14 evidence validation.
        source = _source(
            provenance=Provenance.OBSERVED,
            event_id=uuid.uuid4(),
            detection_id=uuid.uuid4(),
        )
        assert source.detection_id is not None

    def test_ai_generated_retains_investigation_reference(self):
        investigation_id = uuid.uuid4()
        finding_id = uuid.uuid4()
        source = _source(
            provenance=Provenance.AI_GENERATED,
            investigation_id=investigation_id,
            finding_id=finding_id,
        )
        assert source.investigation_id == investigation_id
        assert source.finding_id == finding_id

    def test_finding_id_ai_generated_only(self):
        with pytest.raises(ValidationError):
            _source(provenance=Provenance.OBSERVED, finding_id=uuid.uuid4())

    def test_provenance_never_converted(self):
        # A memory assembled from an AI finding keeps AI_GENERATED on the
        # source; the *memory* itself is RECALLED history.
        source = _source(
            provenance=Provenance.AI_GENERATED,
            investigation_id=uuid.uuid4(),
        )
        m = _memory(sources=[source])
        assert m.provenance is Provenance.RECALLED
        assert m.sources[0].provenance is Provenance.AI_GENERATED
        assert m.sources[0].provenance is not Provenance.RECALLED


# ---------------------------------------------------------------------------
# 5. Source RECALLED forbidden
# ---------------------------------------------------------------------------


class TestSourceRecalledForbidden:
    def test_recalled_source_rejected(self):
        with pytest.raises(ValidationError):
            _source(provenance=Provenance.RECALLED, event_id=uuid.uuid4())

    def test_recalled_value_rejected_in_payload(self):
        with pytest.raises(ValidationError):
            MemorySource(
                source_id=uuid.uuid4(),
                provenance="recalled",
                event_id=uuid.uuid4(),
            )


# ---------------------------------------------------------------------------
# 6. Content models: bounded, blank/oversized rejected
# ---------------------------------------------------------------------------


class TestContentBounds:
    def test_blank_strings_rejected(self):
        with pytest.raises(ValidationError):
            _indicator(indicator_type="   ")
        with pytest.raises(ValidationError):
            _indicator(value="")
        with pytest.raises(ValidationError):
            _memory(title=" \t ")

    def test_oversized_strings_rejected(self):
        with pytest.raises(ValidationError):
            _memory(title="x" * (MAX_MEMORY_TITLE_LENGTH + 1))
        with pytest.raises(ValidationError):
            _memory(summary="x" * (MAX_MEMORY_SUMMARY_LENGTH + 1))
        with pytest.raises(ValidationError):
            _indicator(value="x" * (MAX_MEMORY_VALUE_LENGTH + 1))
        with pytest.raises(ValidationError):
            _source(label="x" * (MAX_MEMORY_LABEL_LENGTH + 1))
        with pytest.raises(ValidationError):
            MemoryEntity(
                entity_id=uuid.uuid4(),
                entity_type="actor",
                identifier="x" * (MAX_MEMORY_IDENTIFIER_LENGTH + 1),
            )
        with pytest.raises(ValidationError):
            MemoryTechnique(
                technique_id=uuid.uuid4(),
                technique_code="x" * (MAX_MEMORY_TECHNIQUE_CODE_LENGTH + 1),
            )

    def test_max_length_value_accepted(self):
        m = _memory(title="x" * MAX_MEMORY_TITLE_LENGTH)
        assert len(m.title) == MAX_MEMORY_TITLE_LENGTH

    def test_whitespace_stripped_at_bound(self):
        m = _memory(title="  padded title  ")
        assert m.title == "padded title"

    def test_content_round_trip(self):
        source_ids = [uuid.uuid4() for _ in range(2)]
        sources = [MemorySource(source_id=s, provenance=Provenance.OBSERVED, event_id=uuid.uuid4()) for s in source_ids]
        indicator = _indicator(source_ids)
        entity = MemoryEntity(entity_type="host", identifier="web-01", source_ids=source_ids)
        technique = MemoryTechnique(technique_code="T1566", name="Phishing", source_ids=source_ids)
        finding = MemoryFinding(finding_type="root-cause", title="Filter miss", source_ids=source_ids)
        action = MemoryAction(action_type="tuning", description="Tuned filter", source_ids=source_ids)
        outcome = MemoryOutcome(outcome_status="resolved", summary="Filter now catches", source_ids=source_ids)
        m = IncidentMemory(
            memory_id=uuid.uuid4(),
            memory_type=MemoryType.INCIDENT_SUMMARY,
            title="round trip",
            sources=sources,
            indicators=[indicator],
            entities=[entity],
            techniques=[technique],
            findings=[finding],
            actions=[action],
            outcome=outcome,
            created_at=_TIMESTAMP,
        )
        dumped = json.loads(m.model_dump_json())
        assert len(dumped["sources"]) == 2
        assert dumped["indicators"][0]["value"] == "203.0.113.9"
        assert dumped["outcome"]["outcome_status"] == "resolved"


# ---------------------------------------------------------------------------
# 7. Confidence
# ---------------------------------------------------------------------------


class TestConfidence:
    def test_bounds(self):
        m = _memory(confidence=0.0)
        assert m.confidence == 0.0
        m2 = _memory(confidence=1.0)
        assert m2.confidence == 1.0

    def test_out_of_bounds_rejected(self):
        with pytest.raises(ValidationError):
            _memory(confidence=-0.01)
        with pytest.raises(ValidationError):
            _memory(confidence=1.01)

    def test_non_finite_rejected(self):
        with pytest.raises(ValidationError):
            _memory(confidence=float("nan"))
        with pytest.raises(ValidationError):
            _memory(confidence=float("inf"))
        with pytest.raises(ValidationError):
            _memory(confidence=float("-inf"))

    def test_boolean_coercion_rejected(self):
        with pytest.raises(ValidationError):
            _memory(confidence=True)

    def test_finding_confidence_independent(self):
        with pytest.raises(ValidationError):
            _memory(
                findings=[
                    MemoryFinding(
                        finding_id=uuid.uuid4(),
                        finding_type="root-cause",
                        title="t",
                        confidence=float("nan"),
                    )
                ]
            )
        with pytest.raises(ValidationError):
            MemoryFinding(
                finding_id=uuid.uuid4(),
                finding_type="root-cause",
                title="t",
                confidence=True,
            )

    def test_not_derived_from_other_pipelines(self):
        # Confidence is carried as supplied: it is never recomputed from
        # risk severity, detection severity, or attribution confidence, and
        # those signals are simply absent from the memory contract.
        m = _memory(confidence=0.4)
        assert m.confidence == 0.4
        assert "severity" not in IncidentMemory.model_fields
        assert "risk_level" not in IncidentMemory.model_fields
        assert "attribution" not in IncidentMemory.model_fields


# ---------------------------------------------------------------------------
# 8. Boundaries: list caps and metadata
# ---------------------------------------------------------------------------


class TestBoundaries:
    def test_source_list_cap(self):
        sources = [_source() for _ in range(MAX_MEMORY_SOURCES)]
        _memory(sources=sources)
        with pytest.raises(ValidationError):
            _memory(sources=sources + [_source()])

    def test_content_list_caps(self):
        with pytest.raises(ValidationError):
            _memory(indicators=[_indicator() for _ in range(MAX_MEMORY_INDICATORS + 1)])
        with pytest.raises(ValidationError):
            _memory(entities=[MemoryEntity(entity_type="host", identifier=f"h{i}") for i in range(MAX_MEMORY_ENTITIES + 1)])
        with pytest.raises(ValidationError):
            _memory(techniques=[MemoryTechnique(technique_code=f"T{i}") for i in range(MAX_MEMORY_TECHNIQUES + 1)])
        with pytest.raises(ValidationError):
            _memory(findings=[MemoryFinding(finding_type="f", title="t") for _ in range(MAX_MEMORY_FINDINGS + 1)])
        with pytest.raises(ValidationError):
            _memory(actions=[MemoryAction(action_type="a") for _ in range(MAX_MEMORY_ACTIONS + 1)])

    def test_source_references_per_item_cap(self):
        with pytest.raises(ValidationError):
            _indicator(source_ids=[uuid.uuid4() for _ in range(MAX_MEMORY_SOURCE_REFERENCES_PER_ITEM + 1)])

    def test_metadata_depth_cap(self):
        deep = {}
        cursor = deep
        for _ in range(MAX_MEMORY_METADATA_DEPTH):
            nxt = {}
            cursor["n"] = nxt
            cursor = nxt
        with pytest.raises(ValidationError):
            _memory(metadata=deep)

    def test_metadata_serialized_size_cap(self):
        big = {"blob": "x" * (MAX_MEMORY_METADATA_SERIALIZED_BYTES + 1)}
        with pytest.raises(ValidationError):
            _memory(metadata=big)

    def test_metadata_at_cap_accepted(self):
        blob = "x" * (MAX_MEMORY_METADATA_SERIALIZED_BYTES - 16)
        m = _memory(metadata={"blob": blob})
        assert m.metadata["blob"] == blob


# ---------------------------------------------------------------------------
# 9. Cross-references
# ---------------------------------------------------------------------------


class TestCrossReferences:
    def test_dangling_reference_rejected(self):
        with pytest.raises(ValidationError):
            _memory(indicators=[_indicator(source_ids=[uuid.uuid4()])])

    def test_resolved_reference_accepted(self):
        source = _source()
        m = _memory(sources=[source], indicators=[_indicator(source_ids=[source.source_id])])
        assert m.indicators[0].source_ids == [source.source_id]

    def test_duplicate_references_preserved(self):
        source = _source()
        m = _memory(
            sources=[source],
            indicators=[_indicator(source_ids=[source.source_id, source.source_id])],
        )
        assert m.indicators[0].source_ids == [source.source_id, source.source_id]

    def test_outcome_reference_must_resolve(self):
        source = _source()
        good = MemoryOutcome(outcome_status="resolved", source_ids=[source.source_id])
        _memory(sources=[source], outcome=good)
        dangling = MemoryOutcome(
            outcome_status="resolved", source_ids=[uuid.uuid4()]
        )
        with pytest.raises(ValidationError):
            _memory(sources=[source], outcome=dangling)

    def test_unreferential_content_allowed_when_no_content_claims(self):
        # A bare memory with an empty indicator list is valid; nothing
        # claims a dangling source.
        _memory(indicators=[])


# ---------------------------------------------------------------------------
# 10. Secret safety
# ---------------------------------------------------------------------------


class TestSecretSafety:
    @pytest.mark.parametrize("sample", _SECRET_PATTERN_SAMPLES)
    def test_all_patterns_rejected(self, sample):
        with pytest.raises(ValidationError):
            _memory(title=sample)
        with pytest.raises(ValidationError):
            _memory(summary=sample)
        with pytest.raises(ValidationError):
            _source(label=sample)
        with pytest.raises(ValidationError):
            _indicator(value=sample)

    def test_secret_in_metadata_rejected(self):
        with pytest.raises(ValidationError):
            _memory(metadata={"note": "keep the api_key safe"})

    def test_secret_in_content_item_rejected(self):
        with pytest.raises(ValidationError):
            _memory(entities=[MemoryEntity(entity_type="host", identifier="secret_password")])

    def test_error_message_leaks_no_content(self):
        with pytest.raises(ValidationError) as exc:
            _memory(title="my api_key_eyJhbGci ate it")
        text = str(exc.value)
        assert "api_key" in text
        assert "eyJhbGci" not in text

    def test_sources_list_secret_free(self):
        with pytest.raises(ValidationError):
            _memory(sources=[_source(label="bearer token")])


# ---------------------------------------------------------------------------
# 11. JSON safety
# ---------------------------------------------------------------------------


class TestJsonSafety:
    def _non_json(self):
        return {"a": {1, 2}}

    def test_set_rejected(self):
        with pytest.raises(ValidationError):
            _memory(metadata=self._non_json())

    def test_bytes_rejected(self):
        with pytest.raises(ValidationError):
            _memory(metadata={"b": b"bytes"})

    def test_arbitrary_object_rejected(self):
        with pytest.raises(ValidationError):
            _memory(metadata={"o": object()})

    def test_nan_rejected(self):
        with pytest.raises(ValidationError):
            _memory(metadata={"n": float("nan")})

    def test_infinity_rejected(self):
        with pytest.raises(ValidationError):
            _memory(metadata={"n": float("inf")})

    def test_cycle_rejected(self):
        lst: list = []
        lst.append(lst)
        with pytest.raises(ValidationError):
            _memory(metadata={"cycle": lst})


# ---------------------------------------------------------------------------
# 12. Immutability — inputs never aliased
# ---------------------------------------------------------------------------


class TestImmutability:
    def test_metadata_dict_not_aliased_from_payload(self):
        payload = {"k": ["v"]}
        m = _memory(metadata=payload)
        payload["k"].append("mutated")
        assert m.metadata["k"] == ["v"]

    def test_source_metadata_not_aliased_from_payload(self):
        payload = {"note": ["keep"]}
        source = _source(metadata=payload)
        m = _memory(sources=[source])
        payload["note"].append("mutated")
        assert m.sources[0].metadata["note"] == ["keep"]


# ---------------------------------------------------------------------------
# 13. Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_identical_input_yields_identical_json(self):
        # Identical INPUT (one authoritative JSON payload) must yield
        # byte-identical output: no hidden nondeterminism in the
        # canonical re-serialization.
        first = _memory()
        payload = json.loads(first.model_dump_json())
        second = IncidentMemory(**payload)
        assert first.model_dump_json() == second.model_dump_json()
# 14. Timestamps
# ---------------------------------------------------------------------------


class TestTimestamps:
    def test_naive_rejected(self):
        with pytest.raises(ValidationError):
            _memory(created_at=datetime(2026, 9, 21, 12, 0, 0))

    def test_aware_accepted(self):
        m = _memory(created_at=_TIMESTAMP)
        assert m.created_at is not None
        m2 = _memory(created_at=_TIMESTAMP.astimezone(timezone(_UTC_OFFSET)))
        assert m2.created_at == _TIMESTAMP

    def test_default_requires_explicit_clock(self):
        # created_at has no hidden default in the contract; the extraction
        # layer injects it explicitly.
        assert "created_at" in IncidentMemory.model_fields
        assert IncidentMemory.model_fields["created_at"].is_required()


# ---------------------------------------------------------------------------
# 15. Unknown fields
# ---------------------------------------------------------------------------


class TestUnknownFields:
    def test_unknown_fields_ignored(self):
        m = _memory(severity="critical", brand_new_field=42)
        assert "brand_new_field" not in m.model_dump()
        assert m.provenance is Provenance.RECALLED


# ---------------------------------------------------------------------------
# 16. Security isolation (no framework imports)
# ---------------------------------------------------------------------------


class TestSecurityIsolation:
    def test_no_forbidden_imports(self):
        files = [BACKEND / "app/schemas/incident_memory.py"]
        files += sorted((BACKEND / "app/services/incident_memory").glob("*.py"))
        for path in files:
            source = path.read_text()
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    module = node.names[0].name
                    assert not _starts_forbidden(module), (
                        f"forbidden import '{module}' in {path.name}"
                    )
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    assert not _starts_forbidden(module), (
                        f"forbidden import '{module}' in {path.name}"
                    )
                elif isinstance(node, ast.Call):
                    target = node.func
                    if isinstance(target, ast.Name) and target.id in (
                        "eval",
                        "exec",
                        "compile",
                    ):
                        raise AssertionError(
                            f"Forbidden call '{target.id}(' in {path.name}"
                        )


def _starts_forbidden(module: str) -> bool:
    # substring-import check: 'google.cloud' and 'sqlalchemy.ext' are as
    # forbidden as their roots; only exact module names are matched.
    root = module.split(".")[0]
    return root in {"fastapi", "sqlalchemy", "alembic", "kafka", "qdrant", "neo4j", "httpx", "google", "ollama", "langgraph", "subprocess"}
