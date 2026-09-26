"""Threat Hunting contract tests (V2.19) — closed grammar & boundaries.

Pins the single source of truth for the hunt vocabulary: the closed
surface/operator/field matrices, the bounded window/filter/value caps, the
type→field allowlist, the set-vs-scalar filter shape rules and the secret /
control-character rejections.  Everything here is pure schema validation —
no database is touched.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from app.schemas.threat_hunting import (
    FIELD_OPERATORS,
    FIELD_VALUE_KIND,
    HUNT_MAX_FILTERS,
    HUNT_MAX_FILTER_SET,
    HUNT_MAX_FILTER_VALUE_LENGTH,
    HUNT_MAX_NAME_LENGTH,
    HUNT_MAX_WINDOW_HOURS,
    HUNT_NAMESPACE,
    HUNT_SURFACE_CAP,
    HUNT_TYPE_FIELDS,
    HuntFilter,
    HuntFilterField,
    HuntOperator,
    HuntType,
    ThreatHuntCreate,
    ThreatHuntStatus,
)
from app.services.threat_hunting.grammar import (
    SURFACES,
    SURFACE_FOR_FIELD,
    TEMPLATES,
    compile_predicates,
    evidence_key,
    udid,
)

TZ = timezone.utc
START = datetime(2026, 9, 1, 0, 0, 0, tzinfo=TZ)
END = datetime(2026, 9, 8, 0, 0, 0, tzinfo=TZ)


def _create(**overrides) -> ThreatHuntCreate:
    payload: dict = {
        "name": "Baseline hunt",
        "hunt_type": HuntType.DETECTION_REVIEW.value,
        "start_time": START,
        "end_time": END,
        "filters": [],
    }
    payload.update(overrides)
    return ThreatHuntCreate(**payload)


def _extra(base: dict, key: str, value: object = "anything") -> dict:
    """Return a copy of a valid payload plus one extra field (forbid test)."""
    copy = dict(base)
    copy[key] = value
    return copy


class TestClosedVocabulary:
    def test_no_generic_query_string_surface(self) -> None:
        # The contract accepts only HuntType / structure — never a raw query.
        base = _create().model_dump()
        for field in ("query", "dsl", "where", "expression", "raw"):
            with pytest.raises(ValidationError):
                ThreatHuntCreate(**_extra(base, field))

    def test_every_hunt_filter_field_is_mapped_to_a_surface(self) -> None:
        assert set(SURFACE_FOR_FIELD) == set(HuntFilterField)

    def test_every_field_operator_pair_is_valid_in_grammar(self) -> None:
        for field in HuntFilterField:
            operators = FIELD_OPERATORS[field]
            assert operators, field
            for operator in operators:
                assert operator in HuntOperator

    def test_value_kind_is_closed(self) -> None:
        assert set(FIELD_VALUE_KIND) == set(HuntFilterField)

    def test_surface_column_targets_are_closed(self) -> None:
        for surface in SURFACES.values():
            for column in surface.exposed_field_targets.values():
                assert column, surface.key

    def test_each_hunt_type_has_exactly_one_template(self) -> None:
        assert set(TEMPLATES) == set(HuntType)
        for hunt_type in HuntType:
            template = TEMPLATES[hunt_type]
            assert template.hunt_type == hunt_type
            assert template.primary_surfaces
            for key in template.primary_surfaces:
                assert key in SURFACES
            for link in template.links:
                assert link.surface in SURFACES
                assert link.kind
                for key in link.from_evidence_keys:
                    assert key in template.primary_surfaces or key in {
                        l.surface for l in template.links
                    }

    def test_hunt_type_field_allowlist_matches_templates(self) -> None:
        for hunt_type in HuntType:
            allowed = HUNT_TYPE_FIELDS[hunt_type]
            assert allowed, hunt_type
            for field in allowed:
                assert field in SURFACE_FOR_FIELD


class TestWindowBounds:
    def test_naive_timestamp_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _create(
                start_time=datetime(2026, 9, 1),
                end_time=datetime(2026, 9, 8),
            )

    def test_reversed_window_rejected(self) -> None:
        with pytest.raises(ValidationError, match="after start_time"):
            _create(start_time=END, end_time=START)

    def test_equal_timestamps_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _create(start_time=START, end_time=START)

    def test_window_beyond_max_rejected(self) -> None:
        with pytest.raises(ValidationError, match="window exceeds"):
            _create(start_time=START, end_time=START + timedelta(hours=HUNT_MAX_WINDOW_HOURS + 1))

    def test_max_window_accepted(self) -> None:
        _create(start_time=START, end_time=START + timedelta(hours=HUNT_MAX_WINDOW_HOURS))


class TestFilters:
    def test_field_not_allowed_for_type_rejected(self) -> None:
        with pytest.raises(ValidationError, match="not supported by hunt type"):
            _create(
                hunt_type=HuntType.DETECTION_REVIEW.value,
                filters=[
                    {
                        "field": HuntFilterField.INDICATOR_VALUE.value,
                        "operator": HuntOperator.EQUALS.value,
                        "value": "1.2.3.4",
                    }
                ],
            )

    def test_duplicate_field_rejected(self) -> None:
        with pytest.raises(ValidationError, match="at most once"):
            _create(
                filters=[
                    {
                        "field": HuntFilterField.RULE_ID.value,
                        "operator": HuntOperator.EQUALS.value,
                        "value": "R-1",
                    },
                    {
                        "field": HuntFilterField.RULE_ID.value,
                        "operator": HuntOperator.EQUALS.value,
                        "value": "R-2",
                    },
                ]
            )

    def test_operator_not_valid_for_field_rejected(self) -> None:
        with pytest.raises(ValidationError, match="not valid for field"):
            HuntFilter(
                field=HuntFilterField.EVENT_ID.value,
                operator=HuntOperator.CONTAINS.value,
                value="x",
            )

    def test_set_operator_requires_values_list(self) -> None:
        with pytest.raises(ValidationError, match="requires a non-empty 'values'"):
            HuntFilter(
                field=HuntFilterField.RULE_ID.value,
                operator=HuntOperator.IN.value,
                value="R-1",
            )

    def test_scalar_operator_requires_single_value(self) -> None:
        with pytest.raises(ValidationError, match="requires a single 'value'"):
            HuntFilter(
                field=HuntFilterField.RULE_ID.value,
                operator=HuntOperator.EQUALS.value,
                values=["R-1"],
            )

    def test_in_set_size_is_bounded(self) -> None:
        with pytest.raises(ValidationError, match="exceeds the maximum"):
            HuntFilter(
                field=HuntFilterField.RULE_ID.value,
                operator=HuntOperator.IN.value,
                values=[f"R-{i}" for i in range(HUNT_MAX_FILTER_SET + 1)],
            )

    def test_uuid_fields_coerce_valid_uuid(self) -> None:
        filt = HuntFilter(
            field=HuntFilterField.EVENT_ID.value,
            operator=HuntOperator.EQUALS.value,
            value=str(uuid.uuid4()),
        )
        assert filt.scalar_value == str(uuid.UUID(filt.scalar_value))

    def test_uuid_field_rejects_garbage(self) -> None:
        with pytest.raises(ValidationError, match="valid UUID"):
            HuntFilter(
                field=HuntFilterField.DETECTION_ID.value,
                operator=HuntOperator.EQUALS.value,
                value="not-a-uuid",
            )

    def test_enum_field_rejects_out_of_set(self) -> None:
        with pytest.raises(ValidationError, match="closed set"):
            HuntFilter(
                field=HuntFilterField.SEVERITY.value,
                operator=HuntOperator.EQUALS.value,
                value="banana",
            )

    def test_filter_value_length_is_bounded(self) -> None:
        with pytest.raises(ValidationError, match="exceeds"):
            HuntFilter(
                field=HuntFilterField.INDICATOR_VALUE.value,
                operator=HuntOperator.CONTAINS.value,
                value="x" * (HUNT_MAX_FILTER_VALUE_LENGTH + 1),
            )

    def test_control_characters_rejected(self) -> None:
        with pytest.raises(ValidationError, match="control characters"):
            HuntFilter(
                field=HuntFilterField.RULE_ID.value,
                operator=HuntOperator.EQUALS.value,
                value="rule\u0007meta",
            )

    def test_secret_shaped_values_rejected(self) -> None:
        with pytest.raises(ValidationError, match="secrets"):
            HuntFilter(
                field=HuntFilterField.INDICATOR_VALUE.value,
                operator=HuntOperator.EQUALS.value,
                value="api_key=sk-0123456789",
            )

    def test_blank_value_rejected(self) -> None:
        with pytest.raises(ValidationError, match="must not be blank"):
            HuntFilter(
                field=HuntFilterField.RULE_ID.value,
                operator=HuntOperator.EQUALS.value,
                value="   ",
            )


class TestCreateShape:
    def test_blank_name_rejected(self) -> None:
        with pytest.raises(ValidationError, match="must not be blank"):
            _create(name="   ")

    def test_name_length_capped(self) -> None:
        with pytest.raises(ValidationError, match="String should have at most"):
            _create(name="x" * (HUNT_MAX_NAME_LENGTH + 1))

    def test_name_secret_shaped_rejected(self) -> None:
        with pytest.raises(ValidationError, match="secrets"):
            _create(name="password-dump-hunt")

    def test_too_many_filters_rejected(self) -> None:
        # The count check runs before the per-field loop, so duplicate
        # fields still exercise the 8-filter cap.
        with pytest.raises(ValidationError, match="at most 8 items"):
            _create(
                filters=[
                    {
                        "field": HuntFilterField.SEVERITY.value,
                        "operator": HuntOperator.IN.value,
                        "values": ["high"],
                    }
                    for _ in range(HUNT_MAX_FILTERS + 1)
                ]
            )

    def test_unknown_extra_field_rejected(self) -> None:
        base = _create().model_dump()
        base["filters"] = [
            {"field": "made_up", "operator": "equals", "value": "x"}
        ]
        with pytest.raises(ValidationError):
            ThreatHuntCreate(**base)


class TestCompilePredicates:
    def test_auth_template_adds_implicit_defaults(self) -> None:
        predicates, surfaces = compile_predicates(HuntType.AUTHENTICATION_ANOMALY, [])
        assert len(predicates) == 2
        assert any(p.column == "action" and p.operator == "starts_with" and p.value == "auth." for p in predicates)
        assert any(p.column == "resource" and p.operator == "in" and p.value == ["auth", "role_check"] for p in predicates)
        assert surfaces == ("audit",)

    def test_indicator_template_surfaces(self) -> None:
        predicates, surfaces = compile_predicates(HuntType.INDICATOR_HUNT, [])
        assert surfaces == ("indicator", "lookup")

    def test_user_filter_maps_to_column(self) -> None:
        flt = HuntFilter(
            field=HuntFilterField.RULE_ID.value,
            operator=HuntOperator.EQUALS.value,
            value="R-42",
        )
        predicates, _ = compile_predicates(HuntType.DETECTION_REVIEW, [flt])
        assert any(p.column == "rule_id" and p.operator == "equals" and p.value == "R-42" for p in predicates)

    def test_in_user_filter_carries_bounded_list(self) -> None:
        flt = HuntFilter(
            field=HuntFilterField.SEVERITY.value,
            operator=HuntOperator.IN.value,
            values=["low", "high"],
        )
        predicates, _ = compile_predicates(HuntType.DETECTION_REVIEW, [flt])
        assert any(p.operator == "in" and p.value == ["low", "high"] for p in predicates)


class TestDeterministicIdentity:
    def test_udid_is_uuid5_scoped_to_hunt(self) -> None:
        hunt_id = uuid.uuid4()
        a = udid(hunt_id, "evidence:detection:abc")
        b = udid(hunt_id, "evidence:detection:abc")
        other = udid(uuid.uuid4(), "evidence:detection:abc")
        assert a == b
        assert a != other
        assert a.hex == uuid.uuid5(HUNT_NAMESPACE, f"{hunt_id}::evidence:detection:abc").hex

    def test_evidence_key_is_deterministic(self) -> None:
        rid = uuid.uuid4()
        assert evidence_key("detection", rid) == f"detection:{rid}"


class TestLifecycleEnums:
    def test_status_set_closed(self) -> None:
        assert {s.value for s in ThreatHuntStatus} == {
            "draft", "running", "completed", "failed", "cancelled"
        }

    def test_no_auto_mitigation_surface(self) -> None:
        fields = " ".join(HuntType.__members__)
        tokens = ["block", "quarantine", "response", "soar", "approve", "mitigat"]
        for token in tokens:
            assert token not in fields.lower()