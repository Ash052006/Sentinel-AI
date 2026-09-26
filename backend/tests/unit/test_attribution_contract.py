"""Step 14 — Threat Attribution domain contract tests.

Scope: this test module verifies the *contract only*.  It exercises no
attribution determinination, no confidence calculation, no LLM call, no
RAG query, no persistence, no API, and no response/mitigation behaviour —
the contract defines the structured, bounded, secret-safe, deterministic
shape a future attribution engine may fill.

Covered explicitly:

1.  enums                         — status & target-type values, rejection
2.  valid assessment              — full round-trip, all provenance types
3.  target validation             — blank / whitespace / oversized
4.  confidence                    — bounds, finiteness, no derivation
5.  status                        — all six values, never derived
6.  evidence references           — provenance→reference map coherence
7.  conflicting evidence          — preserved, never auto-resolved
8.  provenance                    — additive member, prior values intact
9.  secret safety                 — all eight patterns rejected
10. JSON safety                   — sets/bytes/objects/NaN/depth/cycles
11. immutability                  — nested inputs never aliased
12. determinism                   — identical input ⇒ identical JSON
13. timestamps                    — tz-aware required, naive rejected
14. unknown fields                — ignored (SentinelAI default)
15. boundaries                    — hard limits, never truncated
16. security isolation            — no framework imports, 12A hardened
"""

import ast
import math
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.schemas import (
    AttributionAssessment,
    AttributionEvidence,
    AttributionHypothesis,
    AttributionStatus,
    AttributionTargetType,
    MAX_ATTRIBUTION_EVIDENCE_ITEMS,
    MAX_ATTRIBUTION_HYPOTHESES,
    MAX_ATTRIBUTION_LABEL_LENGTH,
    MAX_ATTRIBUTION_METADATA_DEPTH,
    MAX_ATTRIBUTION_METADATA_SERIALIZED_BYTES,
    MAX_ATTRIBUTION_TARGET_IDENTIFIER_LENGTH,
)
from app.schemas.security_event import Provenance
from app.schemas.investigation import InvestigationEvidence

BACKEND = Path(__file__).resolve().parent.parent.parent

_TIMESTAMP = datetime(2026, 9, 21, 12, 0, 0, tzinfo=timezone.utc)

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


def _evidence(**overrides):
    """Default source-backed evidence (OBSERVED event)."""
    defaults = {
        "evidence_type": "network-flow",
        "provenance": Provenance.OBSERVED,
        "event_id": uuid.uuid4(),
    }
    defaults.update(overrides)
    return AttributionEvidence(**defaults)


def _hypothesis(evidence_ids=None, **overrides):
    defaults = {
        "target_type": AttributionTargetType.THREAT_GROUP,
        "target_identifier": "APT29",
        "confidence": 0.8,
        "supporting_evidence_ids": evidence_ids or [],
    }
    defaults.update(overrides)
    return AttributionHypothesis(**defaults)


def _assessment(hypotheses=None, evidence=None, **overrides):
    defaults = {
        "correlation_id": uuid.uuid4(),
        "status": AttributionStatus.UNCERTAIN,
        "hypotheses": hypotheses or [],
        "evidence": evidence or [],
        "timestamp": _TIMESTAMP,
    }
    defaults.update(overrides)
    return AttributionAssessment(**defaults)


def _assessment_with_one_hypothesis():
    ev = _evidence()
    h = _hypothesis([ev.evidence_id])
    return _assessment(hypotheses=[h], evidence=[ev])


# ---------------------------------------------------------------------------
# 1. Enums
# ---------------------------------------------------------------------------


class TestEnums:
    def test_status_values(self):
        assert AttributionStatus.ATTRIBUTED.value == "attributed"
        assert AttributionStatus.PARTIALLY_SUPPORTED.value == "partially_supported"
        assert AttributionStatus.UNCERTAIN.value == "uncertain"
        assert AttributionStatus.INSUFFICIENT_EVIDENCE.value == "insufficient_evidence"
        assert AttributionStatus.CONFLICTING.value == "conflicting"
        assert AttributionStatus.UNATTRIBUTED.value == "unattributed"
        assert len(AttributionStatus) == 6

    def test_status_serializes_as_value(self):
        a = _assessment(status=AttributionStatus.ATTRIBUTED, hypotheses=[], evidence=[])
        assert '"attributed"' in a.model_dump_json()

    def test_invalid_status_rejected(self):
        with pytest.raises(ValidationError):
            _assessment(status="probably_them")

    def test_target_type_values(self):
        assert AttributionTargetType.THREAT_ACTOR.value == "threat_actor"
        assert AttributionTargetType.THREAT_GROUP.value == "threat_group"
        assert AttributionTargetType.MALWARE_FAMILY.value == "malware_family"
        assert AttributionTargetType.CAMPAIGN.value == "campaign"
        assert AttributionTargetType.INFRASTRUCTURE.value == "infrastructure"
        assert AttributionTargetType.TECHNIQUE_CLUSTER.value == "technique_cluster"
        assert AttributionTargetType.UNKNOWN.value == "unknown"

    def test_invalid_target_type_rejected(self):
        with pytest.raises(ValidationError):
            _hypothesis(target_type="nation_state")


# ---------------------------------------------------------------------------
# 2. Valid assessment
# ---------------------------------------------------------------------------


class TestValidAssessment:
    def test_minimal_assessment_builds(self):
        a = _assessment()
        assert isinstance(a.attribution_assessment_id, uuid.UUID)
        assert a.status is AttributionStatus.UNCERTAIN
        assert a.timestamp == _TIMESTAMP
        assert a.provenance is Provenance.ATTRIBUTION_ASSESSED

    def test_full_round_trip_all_provenance_types(self):
        eid = uuid.uuid4()
        did = uuid.uuid4()
        cid = uuid.uuid4()
        rid = uuid.uuid4()
        iid = uuid.uuid4()
        evidence = [
            _evidence(provenance=Provenance.OBSERVED, event_id=eid),
            _evidence(provenance=Provenance.ENRICHED, event_id=eid),
            _evidence(provenance=Provenance.RECONSTRUCTED, event_id=eid),
            AttributionEvidence(
                evidence_type="detection-hit",
                provenance=Provenance.DETECTED,
                detection_id=did,
            ),
            AttributionEvidence(
                evidence_type="correlation-member",
                provenance=Provenance.CORRELATED,
                correlation_id=cid,
            ),
            AttributionEvidence(
                evidence_type="risk-finding",
                provenance=Provenance.RISK_ASSESSED,
                risk_assessment_id=rid,
            ),
            AttributionEvidence(
                evidence_type="investigation-reasoning",
                provenance=Provenance.AI_GENERATED,
                investigation_id=iid,
            ),
        ]
        h = _hypothesis(
            target_type=AttributionTargetType.MALWARE_FAMILY,
            target_identifier="Cobalt Strike",
            confidence=0.6,
            supporting_evidence_ids=[e.evidence_id for e in evidence],
            conflicting_evidence_ids=[],
        )
        a = _assessment(
            correlation_id=cid,
            status=AttributionStatus.PARTIALLY_SUPPORTED,
            hypotheses=[h],
            evidence=evidence,
            metadata={"pipeline": {"run": 7}},
        )
        restored = AttributionAssessment.model_validate_json(a.model_dump_json())
        assert restored.status is AttributionStatus.PARTIALLY_SUPPORTED
        assert len(restored.evidence) == 7
        assert restored.hypotheses[0].target_identifier == "Cobalt Strike"
        assert str(restored.correlation_id) == str(cid)


# ---------------------------------------------------------------------------
# 3. Target validation
# ---------------------------------------------------------------------------


class TestTargetValidation:
    def test_blank_target_rejected(self):
        with pytest.raises(ValidationError):
            _hypothesis(target_identifier="")

    def test_whitespace_target_rejected(self):
        with pytest.raises(ValidationError):
            _hypothesis(target_identifier="   ")

    def test_non_string_target_rejected(self):
        with pytest.raises(ValidationError):
            _hypothesis(target_identifier=1234)

    def test_oversized_target_rejected(self):
        with pytest.raises(ValidationError):
            _hypothesis(target_identifier="A" * (MAX_ATTRIBUTION_TARGET_IDENTIFIER_LENGTH + 1))

    def test_boundary_length_accepted(self):
        h = _hypothesis(target_identifier="A" * MAX_ATTRIBUTION_TARGET_IDENTIFIER_LENGTH)
        assert len(h.target_identifier) == MAX_ATTRIBUTION_TARGET_IDENTIFIER_LENGTH

    def test_target_never_truncated(self):
        with pytest.raises(ValidationError):
            _hypothesis(target_identifier="long" * (MAX_ATTRIBUTION_TARGET_IDENTIFIER_LENGTH + 1))

    def test_stripping_is_deterministic(self):
        h = _hypothesis(target_identifier="  Sandworm  ")
        assert h.target_identifier == "Sandworm"


# ---------------------------------------------------------------------------
# 4. Confidence
# ---------------------------------------------------------------------------


class TestConfidence:
    def test_bounds_accepted(self):
        assert _hypothesis(confidence=0.0).confidence == 0.0
        assert _hypothesis(confidence=1.0).confidence == 1.0
        assert _hypothesis(confidence=0.5).confidence == 0.5

    def test_negative_rejected(self):
        with pytest.raises(ValidationError):
            _hypothesis(confidence=-0.01)

    def test_above_one_rejected(self):
        with pytest.raises(ValidationError):
            _hypothesis(confidence=1.01)

    def test_infinity_rejected(self):
        with pytest.raises(ValidationError):
            _hypothesis(confidence=math.inf)

    def test_nan_rejected(self):
        with pytest.raises(ValidationError):
            _hypothesis(confidence=float("nan"))

    def test_bool_rejected(self):
        with pytest.raises(ValidationError):
            _hypothesis(confidence=True)
        with pytest.raises(ValidationError):
            _hypothesis(confidence=False)

    def test_confidence_never_derived_from_status(self):
        # Confidence is purely per-hypothesis; it must never influence the
        # assessment status (and nothing computes status from it).
        a_high = _assessment_with_one_hypothesis()
        a_low = _assessment_with_one_hypothesis()
        a_high.hypotheses[0].confidence = 1.0
        a_low.hypotheses[0].confidence = 0.1
        assert a_high.status is AttributionStatus.UNCERTAIN
        assert a_low.status is AttributionStatus.UNCERTAIN

    def test_status_not_derived_from_hypothesis_count(self):
        # Zero-hypothesis assessment with a *positive* status is permitted:
        # status is caller-supplied, never inferred from the lists.
        a = _assessment(status=AttributionStatus.ATTRIBUTED, hypotheses=[], evidence=[])
        assert a.status is AttributionStatus.ATTRIBUTED


# ---------------------------------------------------------------------------
# 5. Status
# ---------------------------------------------------------------------------


class TestStatus:
    @pytest.mark.parametrize(
        "status",
        [
            AttributionStatus.ATTRIBUTED,
            AttributionStatus.PARTIALLY_SUPPORTED,
            AttributionStatus.UNCERTAIN,
            AttributionStatus.INSUFFICIENT_EVIDENCE,
            AttributionStatus.CONFLICTING,
            AttributionStatus.UNATTRIBUTED,
        ],
    )
    def test_all_statuses_accepted(self, status):
        assert _assessment(status=status, hypotheses=[], evidence=[]).status is status

    def test_high_confidence_not_auto_attributed(self):
        ev = _evidence()
        h = _hypothesis([ev.evidence_id], confidence=0.95)
        a = _assessment(
            hypotheses=[h],
            evidence=[ev],
            status=AttributionStatus.INSUFFICIENT_EVIDENCE,
        )
        assert a.status is AttributionStatus.INSUFFICIENT_EVIDENCE


# ---------------------------------------------------------------------------
# 6. Evidence references
# ---------------------------------------------------------------------------


class TestEvidenceReferences:
    def test_missing_required_reference_rejected(self):
        with pytest.raises(ValidationError):
            AttributionEvidence(  # DETECTED without detection_id
                evidence_type="detection-hit", provenance=Provenance.DETECTED
            )

    @pytest.mark.parametrize(
        "provenance,wrong_ref_kwargs",
        [
            (Provenance.DETECTED, {"event_id": uuid.uuid4()}),
            (Provenance.CORRELATED, {"detection_id": uuid.uuid4()}),
            (Provenance.RISK_ASSESSED, {"correlation_id": uuid.uuid4()}),
            (Provenance.AI_GENERATED, {"event_id": uuid.uuid4()}),
        ],
    )
    def test_provenance_reference_mismatch_rejected(self, provenance, wrong_ref_kwargs):
        # The provenance declares a category backed only by the *wrong* kind
        # of reference — the required reference is absent.
        with pytest.raises(ValidationError):
            AttributionEvidence(
                evidence_type="mismatch", provenance=provenance, **wrong_ref_kwargs
            )

    def test_ai_generated_uses_investigation_id(self):
        ev = AttributionEvidence(
            evidence_type="investigation-reasoning",
            provenance=Provenance.AI_GENERATED,
            investigation_id=uuid.uuid4(),
        )
        assert ev.investigation_id is not None

    def test_attribution_assessed_forbidden_on_evidence(self):
        with pytest.raises(ValidationError):
            _evidence(provenance=Provenance.ATTRIBUTION_ASSESSED, event_id=uuid.uuid4())

    def test_hypothesis_must_reference_present_evidence(self):
        ev = _evidence()
        h = _hypothesis([uuid.uuid4()])  # references a UUID nowhere in assessment
        with pytest.raises(ValidationError):
            _assessment(hypotheses=[h], evidence=[ev])

    def test_resolution_spans_supporting_and_conflicting(self):
        ev1 = _evidence()
        ev2 = _evidence()
        h = _hypothesis([ev1.evidence_id], conflicting_evidence_ids=[ev2.evidence_id])
        a = _assessment(hypotheses=[h], evidence=[ev1, ev2])
        assert len(a.hypotheses[0].conflicting_evidence_ids) == 1


# ---------------------------------------------------------------------------
# 7. Conflicting evidence
# ---------------------------------------------------------------------------


class TestConflictingEvidence:
    def test_both_lists_preserved(self):
        ev1 = _evidence()
        ev2 = _evidence()
        h = _hypothesis([ev1.evidence_id], conflicting_evidence_ids=[ev2.evidence_id])
        a = _assessment(hypotheses=[h], evidence=[ev1, ev2])
        restored = AttributionAssessment.model_validate_json(a.model_dump_json())
        hh = restored.hypotheses[0]
        assert [str(x) for x in hh.supporting_evidence_ids] == [str(ev1.evidence_id)]
        assert [str(x) for x in hh.conflicting_evidence_ids] == [str(ev2.evidence_id)]

    def test_same_reference_both_sides_rejected(self):
        ev = _evidence()
        with pytest.raises(ValidationError):
            _hypothesis([ev.evidence_id], conflicting_evidence_ids=[ev.evidence_id])

    def test_duplicate_ids_preserved(self):
        ev = _evidence()
        h = _hypothesis([ev.evidence_id, ev.evidence_id])
        a = _assessment(hypotheses=[h], evidence=[ev])
        assert len(a.hypotheses[0].supporting_evidence_ids) == 2


# ---------------------------------------------------------------------------
# 8. Provenance
# ---------------------------------------------------------------------------


class TestProvenance:
    def test_attribution_assessed_value(self):
        assert Provenance.ATTRIBUTION_ASSESSED.value == "attribution_assessed"
        assert Provenance.ATTRIBUTION_ASSESSED in Provenance

    def test_prior_provenance_values_unchanged(self):
        assert Provenance.OBSERVED.value == "observed"
        assert Provenance.ENRICHED.value == "enriched"
        assert Provenance.RECONSTRUCTED.value == "reconstructed"
        assert Provenance.DETECTED.value == "detected"
        assert Provenance.CORRELATED.value == "correlated"
        assert Provenance.RISK_ASSESSED.value == "risk_assessed"
        assert Provenance.AI_GENERATED.value == "ai_generated"

    @pytest.mark.parametrize(
        "provenance,ref_kwargs",
        [
            (Provenance.OBSERVED, {"event_id": uuid.uuid4()}),
            (Provenance.ENRICHED, {"event_id": uuid.uuid4()}),
            (Provenance.RECONSTRUCTED, {"event_id": uuid.uuid4()}),
            (Provenance.DETECTED, {"detection_id": uuid.uuid4()}),
            (Provenance.CORRELATED, {"correlation_id": uuid.uuid4()}),
            (Provenance.RISK_ASSESSED, {"risk_assessment_id": uuid.uuid4()}),
        ],
    )
    def test_prior_source_provenances_still_valid_on_evidence(self, provenance, ref_kwargs):
        ev = AttributionEvidence(
            evidence_type="source", provenance=provenance, **ref_kwargs
        )
        assert ev.provenance is provenance

    def test_hypothesis_pinned_to_attribution_assessed(self):
        with pytest.raises(ValidationError):
            _hypothesis(provenance=Provenance.AI_GENERATED)

    def test_assessment_pinned_to_attribution_assessed(self):
        with pytest.raises(ValidationError):
            _assessment(provenance=Provenance.OBSERVED)
        assert _assessment().provenance is Provenance.ATTRIBUTION_ASSESSED

    def test_12a_investigation_evidence_still_valid_for_prior_values(self):
        # Regression: 12A source-backed evidence remains valid.
        ev = InvestigationEvidence(
            evidence_type="flow",
            provenance=Provenance.OBSERVED,
            event_id=uuid.uuid4(),
        )
        assert ev.provenance is Provenance.OBSERVED

    def test_12a_investigation_evidence_rejects_attribution_assessed(self):
        # Hardening: attribution hypotheses are conclusions, not evidence,
        # so 12A must reject them as source evidence.
        with pytest.raises(ValidationError):
            InvestigationEvidence(
                evidence_type="flow",
                provenance=Provenance.ATTRIBUTION_ASSESSED,
                event_id=uuid.uuid4(),
            )

    def test_12a_banned_ai_generated_still_rejected(self):
        with pytest.raises(ValidationError):
            InvestigationEvidence(
                evidence_type="flow",
                provenance=Provenance.AI_GENERATED,
                event_id=uuid.uuid4(),
            )


# ---------------------------------------------------------------------------
# 9. Secret safety
# ---------------------------------------------------------------------------


class TestSecretSafety:
    @pytest.mark.parametrize("sample", _SECRET_PATTERN_SAMPLES)
    def test_target_identifier_rejects_secrets(self, sample):
        with pytest.raises(ValidationError):
            _hypothesis(target_identifier=f"actor-{sample}")

    @pytest.mark.parametrize("sample", _SECRET_PATTERN_SAMPLES)
    def test_evidence_type_rejects_secrets(self, sample):
        with pytest.raises(ValidationError):
            _evidence(evidence_type=f"label-{sample}")

    @pytest.mark.parametrize("sample", _SECRET_PATTERN_SAMPLES)
    def test_evidence_metadata_rejects_secrets(self, sample):
        with pytest.raises(ValidationError):
            _evidence(metadata={sample: "not really a secret"})

    @pytest.mark.parametrize("sample", _SECRET_PATTERN_SAMPLES)
    def test_hypothesis_metadata_rejects_secrets(self, sample):
        with pytest.raises(ValidationError):
            _hypothesis(metadata={sample: "x"})

    @pytest.mark.parametrize("sample", _SECRET_PATTERN_SAMPLES)
    def test_assessment_metadata_rejects_secrets(self, sample):
        with pytest.raises(ValidationError):
            _assessment(metadata={"nested": {"deep": {sample: "x"}}})

    @pytest.mark.parametrize("sample", _SECRET_PATTERN_SAMPLES)
    def test_assessment_depth_rejects_secrets(self, sample):
        with pytest.raises(ValidationError):
            ev = _evidence(metadata={"sub": {sample: "x"}})
            h = _hypothesis([ev.evidence_id])
            _assessment(hypotheses=[h], evidence=[ev])


# ---------------------------------------------------------------------------
# 10. JSON safety
# ---------------------------------------------------------------------------


class TestJsonSafety:
    def test_set_rejected(self):
        with pytest.raises(ValidationError):
            _assessment(metadata={"tags": {1, 2}})

    def test_bytes_rejected(self):
        with pytest.raises(ValidationError):
            _evidence(metadata={"raw": b"\x00\x01"})

    def test_arbitrary_object_rejected(self):
        with pytest.raises(ValidationError):
            _hypothesis(metadata={"obj": object()})

    def test_nan_rejected_in_metadata(self):
        with pytest.raises(ValidationError):
            _assessment(metadata={"score": float("nan")})

    def test_infinity_rejected_in_metadata(self):
        with pytest.raises(ValidationError):
            _evidence(metadata={"score": math.inf})

    def test_cycle_rejected(self):
        meta = {}
        meta["self"] = meta
        with pytest.raises(ValidationError):
            _assessment(metadata=meta)

    def test_list_cycle_rejected(self):
        meta = {"v": []}
        meta["v"].append(meta["v"])
        with pytest.raises(ValidationError):
            _hypothesis(metadata=meta)

    def test_non_string_key_rejected(self):
        with pytest.raises(ValidationError):
            _evidence(metadata={1: "int-key"})

    def test_string_keys_accepted(self):
        a = _assessment(metadata={"str-key": {"sub": "ok"}})
        assert a.metadata == {"str-key": {"sub": "ok"}}


# ---------------------------------------------------------------------------
# 11. Immutability
# ---------------------------------------------------------------------------


class TestImmutability:
    def test_evidence_metadata_not_aliased(self):
        meta = {"note": ["a", "b"]}
        ev = _evidence(metadata=meta)
        meta["note"].append("c")
        meta["extra"] = "mutated"
        assert ev.metadata == {"note": ["a", "b"]}

    def test_hypothesis_metadata_not_aliased(self):
        meta = {"chains": ["x"]}
        h = _hypothesis(metadata=meta)
        meta["chains"].append("y")
        assert h.metadata == {"chains": ["x"]}

    def test_assessment_list_inputs_not_aliased(self):
        ev_list = [_evidence()]
        h_list = [_hypothesis([ev_list[0].evidence_id])]
        a = _assessment(hypotheses=h_list, evidence=ev_list)
        h_list.clear()
        ev_list.clear()
        assert len(a.hypotheses) == 1
        assert len(a.evidence) == 1


# ---------------------------------------------------------------------------
# 12. Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_identical_inputs_identical_serialization(self):
        eid = uuid.uuid4()
        cid = uuid.uuid4()
        hid = uuid.uuid4()
        kwargs = {
            "attribution_assessment_id": hid,
            "correlation_id": cid,
            "status": AttributionStatus.UNCERTAIN,
            "hypotheses": [
                AttributionHypothesis(
                    hypothesis_id=hid,
                    target_type=AttributionTargetType.INFRASTRUCTURE,
                    target_identifier="evil.example.net",
                    confidence=0.7,
                    supporting_evidence_ids=[eid],
                )
            ],
            "evidence": [
                AttributionEvidence(
                    evidence_id=eid,
                    evidence_type="dns-query",
                    provenance=Provenance.OBSERVED,
                    event_id=uuid.uuid4(),
                )
            ],
            "timestamp": _TIMESTAMP,
        }
        a1 = AttributionAssessment(**kwargs)
        a2 = AttributionAssessment(**kwargs)
        assert a1.model_dump_json() == a2.model_dump_json()

    def test_no_hidden_clock_timestamp_required(self):
        with pytest.raises(ValidationError):
            AttributionAssessment(
                correlation_id=uuid.uuid4(), status=AttributionStatus.UNATTRIBUTED
            )

    def test_list_order_preserved(self):
        ev1 = _evidence()
        ev2 = _evidence()
        a = _assessment(evidence=[ev1, ev2])
        assert [str(e.evidence_id) for e in a.evidence] == [
            str(ev1.evidence_id),
            str(ev2.evidence_id),
        ]


# ---------------------------------------------------------------------------
# 13. Timestamps
# ---------------------------------------------------------------------------


class TestTimestamps:
    def test_naive_timestamp_rejected(self):
        with pytest.raises(ValidationError):
            _assessment(timestamp=datetime(2026, 9, 21, 12, 0, 0))

    def test_aware_utc_accepted(self):
        a = _assessment()
        assert a.timestamp == _TIMESTAMP

    def test_non_utc_aware_accepted(self):
        ts = datetime(2026, 9, 21, 12, 0, 0, tzinfo=timezone(timedelta(hours=2)))
        assert _assessment(timestamp=ts).timestamp == ts

    def test_deterministic_serialization(self):
        a1 = _assessment()
        a2 = _assessment()
        assert a1.timestamp == a2.timestamp == _TIMESTAMP

    def test_numeric_timestamp_rejected(self):
        with pytest.raises(ValidationError):
            _assessment(timestamp=1781000000.0)


# ---------------------------------------------------------------------------
# 14. Unknown fields
# ---------------------------------------------------------------------------


class TestUnknownFields:
    def test_unknown_fields_ignored_everywhere(self):
        a = AttributionAssessment(
            correlation_id=uuid.uuid4(),
            status=AttributionStatus.UNATTRIBUTED,
            timestamp=_TIMESTAMP,
            unexpected_top_level="ignored",
            hypotheses=[
                AttributionHypothesis(
                    target_type=AttributionTargetType.UNKNOWN,
                    target_identifier="unknown-actor",
                    confidence=0.0,
                    unexpected_hypothesis_field=True,
                )
            ],
            evidence=[
                AttributionEvidence(
                    evidence_type="none",
                    provenance=Provenance.OBSERVED,
                    event_id=uuid.uuid4(),
                    unexpected_evidence_field="ignored",
                )
            ],
        )
        assert a.status is AttributionStatus.UNATTRIBUTED
        serialized = a.model_dump_json()
        assert "unexpected_top_level" not in serialized
        assert "unexpected_hypothesis_field" not in serialized
        assert "unexpected_evidence_field" not in serialized


# ---------------------------------------------------------------------------
# 15. Boundaries
# ---------------------------------------------------------------------------


class TestBoundaries:
    def test_hypothesis_limit_enforced(self):
        ev = _evidence()
        many = [_hypothesis([ev.evidence_id]) for _ in range(MAX_ATTRIBUTION_HYPOTHESES + 1)]
        with pytest.raises(ValidationError):
            _assessment(hypotheses=many, evidence=[ev])

    def test_evidence_limit_enforced(self):
        many = [_evidence() for _ in range(MAX_ATTRIBUTION_EVIDENCE_ITEMS + 1)]
        with pytest.raises(ValidationError):
            _assessment(evidence=many, hypotheses=[])

    def test_metadata_depth_enforced(self):
        deep = {}
        node = deep
        for _ in range(MAX_ATTRIBUTION_METADATA_DEPTH + 1):
            node["child"] = {}
            node = node["child"]
        with pytest.raises(ValidationError):
            _assessment(metadata=deep)

    def test_metadata_size_enforced(self):
        blob = {"pad": "x" * (MAX_ATTRIBUTION_METADATA_SERIALIZED_BYTES + 1)}
        with pytest.raises(ValidationError):
            _evidence(metadata=blob)

    def test_evidence_label_bound_enforced(self):
        with pytest.raises(ValidationError):
            _evidence(evidence_type="e" * (MAX_ATTRIBUTION_LABEL_LENGTH + 1))

    def test_expected_ids_are_uuids(self):
        assert isinstance(_evidence().evidence_id, uuid.UUID)
        assert isinstance(_hypothesis().hypothesis_id, uuid.UUID)
        assert isinstance(_assessment().attribution_assessment_id, uuid.UUID)

    def test_correlation_id_required(self):
        with pytest.raises(ValidationError):
            _assessment(correlation_id=None)


# ---------------------------------------------------------------------------
# 16. Security isolation
# ---------------------------------------------------------------------------


class TestSecurityIsolation:
    FORBIDDEN = {
        "fastapi",
        "sqlalchemy",
        "qdrant_client",
        "neo4j",
        "kafka",
        "httpx",
        "google",
        "anthropic",
        "openai",
    }

    def test_attribution_schema_has_no_forbidden_imports(self):
        path = BACKEND / "app" / "schemas" / "threat_attribution.py"
        tree = ast.parse(path.read_text())
        violations: list[str] = []
        for node in tree.body:
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module.split(".")[0] in self.FORBIDDEN:
                    violations.append(f"from {module}")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in self.FORBIDDEN:
                        violations.append(f"import {alias.name}")
        assert violations == []

    def test_schema_imports_without_frameworks(self):
        script = (
            "import app.schemas.threat_attribution, sys; "
            "print('qdrant_client' in sys.modules)"
        )
        out = subprocess.run(
            [sys.executable, "-c", script],
            cwd=str(BACKEND),
            capture_output=True,
            text=True,
            check=True,
        )
        assert out.stdout.strip() == "False"

    def test_attribution_module_random_stdlib_only(self):
        path = BACKEND / "app" / "schemas" / "threat_attribution.py"
        tree = ast.parse(path.read_text())
        allowed = {
            "__future__",
            "json",
            "uuid",
            "enum",
            "datetime",
            "math",
            "typing",
            "pydantic",
            "app",
        }
        imports = set()
        for node in tree.body:
            if isinstance(node, ast.Import):
                imports.update(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add((node.module or "").split(".")[0])
        extra = imports - allowed
        assert extra == set(), f"unexpected imports in attribution contract: {sorted(extra)}"


class TestAssessmentAssemblesClean:
    def test_exemplar_e2e_shape(self):
        a = _assessment_with_one_hypothesis()
        assert a.status.value in {"attributed", "partially_supported", "uncertain",
                                  "insufficient_evidence", "conflicting", "unattributed"}
        assert a.hypotheses[0].target_type is AttributionTargetType.THREAT_GROUP
        assert 0.0 <= a.hypotheses[0].confidence <= 1.0