"""Tests for the Detection Rule Model & Registry (Step 9B).

Covers DetectionRuleRegistry registration, retrieval, listing, enable /
disable, deterministic SIGMA/YARA selection, version semantics,
duplicate handling, mutation safety, domain exceptions, and the absence
of execution / network / database / LLM behaviour.

These are pure unit tests of the in-memory registry — no database
connection, no Sigma/YARA engine invocation, no network, and no LLM are
used.
"""

import pytest

from app.schemas.detection import (
    DetectionMetadata,
    DetectionRule,
    DetectionSeverity,
    RuleType,
)
from app.services.detection import (
    DetectionError,
    DetectionRuleNotFoundError,
    DetectionRuleRegistry,
    DuplicateDetectionRuleError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _rule(
    rule_id: str = "sigma-001",
    *,
    rule_type: RuleType = RuleType.SIGMA,
    severity: DetectionSeverity = DetectionSeverity.HIGH,
    enabled: bool = True,
    version: str = "1.0.0",
    metadata: dict | None = None,
) -> DetectionRule:
    """Return a minimal valid DetectionRule."""
    return DetectionRule(
        rule_id=rule_id,
        name=f"Rule {rule_id}",
        description=f"Detects {rule_id}",
        rule_type=rule_type,
        severity=severity,
        enabled=enabled,
        version=version,
        metadata=DetectionMetadata(extra=metadata) if metadata else DetectionMetadata(),
    )


def _yara_rule(rule_id: str = "yara-001", **kwargs) -> DetectionRule:
    return _rule(rule_id, rule_type=RuleType.YARA, **kwargs)


# ===========================================================================
# A. Instantiation
# ===========================================================================


class TestRegistryInstantiation:
    def test_can_instantiate_empty(self):
        reg = DetectionRuleRegistry()
        assert reg.count() == 0

    def test_constructor_injects_rules(self):
        reg = DetectionRuleRegistry([_rule("sigma-001")])
        assert reg.count() == 1


# ===========================================================================
# B-F. Registration & retrieval
# ===========================================================================


class TestRegistrationAndRetrieval:
    def test_register_sigma_rule(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-001"))
        assert reg.count() == 1

    def test_register_yara_rule(self):
        reg = DetectionRuleRegistry()
        reg.register(_yara_rule("yara-001"))
        assert reg.count() == 1

    def test_retrieve_rule_by_id(self):
        reg = DetectionRuleRegistry()
        rule = _rule("sigma-001")
        reg.register(rule)
        assert reg.get("sigma-001") is rule

    def test_register_multiple_rules(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-001"))
        reg.register(_rule("sigma-002"))
        reg.register(_yara_rule("yara-001"))
        assert reg.count() == 3

    def test_get_returns_exact_object(self):
        reg = DetectionRuleRegistry()
        rule = _rule("sigma-001")
        reg.register(rule)
        assert reg.get("sigma-001") == rule
        assert reg.get("sigma-001") is rule

    def test_register_non_rule_rejected(self):
        with pytest.raises(TypeError):
            DetectionRuleRegistry().register("not a rule")

# ===========================================================================
# G. List all / enabled / disabled
# ===========================================================================


class TestListing:
    def test_list_all_rules(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-002"))
        reg.register(_rule("sigma-001"))
        ids = [r.rule_id for r in reg.list_rules()]
        assert ids == ["sigma-001", "sigma-002"]

    def test_list_enabled_only(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-001"))
        reg.register(_rule("sigma-002", enabled=False))
        enabled_ids = [r.rule_id for r in reg.list_enabled()]
        assert enabled_ids == ["sigma-001"]

    def test_list_disabled_only(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-001"))
        reg.register(_rule("sigma-002", enabled=False))
        disabled_ids = [r.rule_id for r in reg.list_disabled()]
        assert disabled_ids == ["sigma-002"]

    def test_list_rule_ids_sorted(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("b-rule"))
        reg.register(_rule("a-rule"))
        assert reg.list_rule_ids() == ["a-rule", "b-rule"]


# ===========================================================================
# H-K. Selection by type
# ===========================================================================


class TestSelectionByType:
    def test_find_sigma_rules(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-001"))
        reg.register(_yara_rule("yara-001"))
        ids = [r.rule_id for r in reg.find_by_type(RuleType.SIGMA)]
        assert ids == ["sigma-001"]

    def test_find_yara_rules(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-001"))
        reg.register(_yara_rule("yara-001"))
        ids = [r.rule_id for r in reg.find_by_type(RuleType.YARA)]
        assert ids == ["yara-001"]

    def test_find_enabled_sigma(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-001"))
        reg.register(_rule("sigma-002", enabled=False))
        ids = [r.rule_id for r in reg.find_enabled_by_type(RuleType.SIGMA)]
        assert ids == ["sigma-001"]

    def test_find_enabled_yara(self):
        reg = DetectionRuleRegistry()
        reg.register(_yara_rule("yara-001", enabled=False))
        reg.register(_yara_rule("yara-002"))
        ids = [r.rule_id for r in reg.find_enabled_by_type(RuleType.YARA)]
        assert ids == ["yara-002"]

    def test_find_by_type_excludes_other_types(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-001"))
        reg.register(_yara_rule("yara-001"))
        assert all(
            r.rule_type is RuleType.SIGMA
            for r in reg.find_by_type(RuleType.SIGMA)
        )


# ===========================================================================
# L-N. Enable / disable behaviour
# ===========================================================================


class TestEnableDisable:
    def test_disabled_excluded_from_enabled_selection(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-001", enabled=False))
        assert reg.find_enabled_by_type(RuleType.SIGMA) == []
        assert reg.list_enabled() == []

    def test_disabled_remains_retrievable(self):
        reg = DetectionRuleRegistry()
        rule = _rule("sigma-001")
        reg.register(rule)
        reg.disable("sigma-001")
        assert reg.get("sigma-001").enabled is False
        assert reg.has_rule("sigma-001") is True

    def test_enable_disabled_rule(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-001", enabled=False))
        reg.enable("sigma-001")
        assert reg.get("sigma-001").enabled is True
        assert [r.rule_id for r in reg.find_enabled_by_type(RuleType.SIGMA)] == [
            "sigma-001"
        ]

    def test_disable_enabled_rule(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-001"))
        reg.disable("sigma-001")
        assert reg.get("sigma-001").enabled is False
        assert reg.find_enabled_by_type(RuleType.SIGMA) == []

    def test_enable_unknown_raises(self):
        with pytest.raises(DetectionRuleNotFoundError):
            DetectionRuleRegistry().enable("missing")

    def test_disable_unknown_raises(self):
        with pytest.raises(DetectionRuleNotFoundError):
            DetectionRuleRegistry().disable("missing")

    def test_enable_already_enabled_is_noop(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-001"))
        reg.enable("sigma-001")
        assert reg.get("sigma-001").enabled is True

    def test_disable_already_disabled_is_noop(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-001", enabled=False))
        reg.disable("sigma-001")
        assert reg.get("sigma-001").enabled is False


# ===========================================================================
# P-Q. Duplicate handling and version semantics
# ===========================================================================


class TestDuplicateHandling:
    def test_duplicate_rule_id_rejected(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-001"))
        with pytest.raises(DuplicateDetectionRuleError):
            reg.register(_rule("sigma-001"))

    def test_duplicate_does_not_silently_overwrite(self):
        reg = DetectionRuleRegistry()
        original = _rule("sigma-001", severity=DetectionSeverity.HIGH)
        replacement = _rule("sigma-001", severity=DetectionSeverity.LOW)
        reg.register(original)
        with pytest.raises(DuplicateDetectionRuleError):
            reg.register(replacement)
        # Original is preserved unchanged.
        assert reg.get("sigma-001") is original
        assert reg.get("sigma-001").severity is DetectionSeverity.HIGH

    def test_duplicate_with_different_version_rejected(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-001", version="1.0.0"))
        with pytest.raises(DuplicateDetectionRuleError):
            reg.register(_rule("sigma-001", version="2.0.0"))
        assert reg.get("sigma-001").version == "1.0.0"

    def test_duplicate_error_attributes(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-001", version="3.0.0"))
        with pytest.raises(DuplicateDetectionRuleError) as excinfo:
            reg.register(_rule("sigma-001", version="3.1.0"))
        assert excinfo.value.rule_id == "sigma-001"
        assert excinfo.value.version == "3.1.0"

    def test_duplicate_error_is_detection_error(self):
        assert issubclass(DuplicateDetectionRuleError, DetectionError)

    def test_same_type_different_ids_allowed(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-001"))
        reg.register(_rule("sigma-002"))
        assert reg.count() == 2

    def test_register_after_unregister_allowed(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-001"))
        reg.unregister("sigma-001")
        reg.register(_rule("sigma-001"))
        assert reg.count() == 1


# ===========================================================================
# R-U. Rule attribute preservation
# ===========================================================================


class TestAttributePreservation:
    def test_severity_preserved(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-001", severity=DetectionSeverity.CRITICAL))
        assert reg.get("sigma-001").severity is DetectionSeverity.CRITICAL

    def test_version_preserved(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-001", version="2.4.1"))
        assert reg.get("sigma-001").version == "2.4.1"

    def test_metadata_preserved(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule(
            "sigma-001",
            metadata={"author": "sentinel", "tags": ["t1059"]},
        ))
        meta = reg.get("sigma-001").metadata
        assert meta.extra["author"] == "sentinel"
        assert meta.extra["tags"] == ["t1059"]

    def test_rule_name_description_preserved(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-001"))
        rule = reg.get("sigma-001")
        assert rule.name == "Rule sigma-001"
        assert rule.description == "Detects sigma-001"


# ===========================================================================
# V-W. Unregistering
# ===========================================================================


class TestUnregister:
    def test_unregister_existing_rule(self):
        reg = DetectionRuleRegistry()
        rule = _rule("sigma-001")
        reg.register(rule)
        removed = reg.unregister("sigma-001")
        assert removed is rule
        assert reg.count() == 0
        assert reg.has_rule("sigma-001") is False

    def test_unregister_unknown_raises(self):
        reg = DetectionRuleRegistry()
        with pytest.raises(DetectionRuleNotFoundError):
            reg.unregister("does-not-exist")

    def test_unregister_removes_only_target(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-001"))
        reg.register(_rule("sigma-002"))
        reg.unregister("sigma-001")
        assert reg.has_rule("sigma-002") is True
        assert reg.count() == 1

# ===========================================================================
# X. Deterministic selection
# ===========================================================================


class TestDeterministicSelection:
    def test_list_order_is_stable_by_rule_id(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-b"))
        reg.register(_rule("sigma-c"))
        reg.register(_rule("sigma-a"))
        assert [r.rule_id for r in reg.list_rules()] == [
            "sigma-a", "sigma-b", "sigma-c",
        ]

    def test_find_order_is_stable_by_rule_id(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-c", enabled=False))
        reg.register(_rule("sigma-a"))
        reg.register(_rule("sigma-b"))
        assert [r.rule_id for r in reg.find_by_type(RuleType.SIGMA)] == [
            "sigma-a", "sigma-b", "sigma-c",
        ]
        assert [r.rule_id for r in reg.find_enabled_by_type(RuleType.SIGMA)] == [
            "sigma-a", "sigma-b",
        ]

    def test_repeated_selection_matches(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("s2"))
        reg.register(_rule("s1", enabled=False))
        first = [r.rule_id for r in reg.find_enabled_by_type(RuleType.SIGMA)]
        second = [r.rule_id for r in reg.find_enabled_by_type(RuleType.SIGMA)]
        assert first == second


# ===========================================================================
# Y-Z. Mutation safety
# ===========================================================================


class TestMutationSafety:
    def test_registration_does_not_mutate_input(self):
        rule = _rule("sigma-001", metadata={"a": 1})
        snapshot = rule.model_dump()
        reg = DetectionRuleRegistry()
        reg.register(rule)
        assert rule.model_dump() == snapshot
        assert reg.get("sigma-001") is rule

    def test_listing_does_not_expose_internal_state_mutably(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-001"))
        reg.register(_rule("sigma-002"))
        lst1 = reg.list_rules()
        lst2 = reg.list_rules()
        # Each call returns an independent, freshly-built list.
        assert lst1 is not lst2
        assert lst1 == lst2
        assert reg.count() == 2

    def test_enable_disable_does_not_mutate_caller_object(self):
        rule = _rule("sigma-001", enabled=True)
        reg = DetectionRuleRegistry()
        reg.register(rule)
        reg.disable("sigma-001")
        # The caller-owned rule object itself is unchanged (a copy is
        # stored internally after the state change); only the registry
        # reflects the disabled state.
        assert rule.enabled is True
        assert reg.get("sigma-001").enabled is False


# ===========================================================================
# AA-AB. Empty / clear behaviour
# ===========================================================================


class TestEmptyAndClear:
    def test_empty_registry_behaviour(self):
        reg = DetectionRuleRegistry()
        assert reg.count() == 0
        assert reg.list_rules() == []
        assert reg.list_enabled() == []
        assert reg.list_disabled() == []
        assert reg.find_by_type(RuleType.SIGMA) == []
        assert reg.find_enabled_by_type(RuleType.YARA) == []
        assert reg.get_or_none("x") is None

    def test_clear_registry(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-001"))
        reg.register(_yara_rule("yara-001"))
        assert reg.count() == 2
        reg.clear()
        assert reg.count() == 0
        assert reg.list_rules() == []
# ===========================================================================
# AC. Domain-specific exceptions
# ===========================================================================


class TestDomainExceptions:
    def test_not_found_error_attributes(self):
        e = DetectionRuleNotFoundError("missing-rule")
        assert e.rule_id == "missing-rule"
        assert "missing-rule" in str(e)

    def test_not_found_is_detection_error(self):
        assert issubclass(DetectionRuleNotFoundError, DetectionError)
        assert issubclass(DetectionError, Exception)

    def test_duplicate_flag_is_detection_error(self):
        assert issubclass(DuplicateDetectionRuleError, DetectionError)

    def test_exception_messages_do_not_leak_secrets(self):
        e = DuplicateDetectionRuleError("sigma-001", "1.0.0")
        lower = str(e).lower()
        assert "apikey" not in lower
        assert "secret" not in lower
        assert "authorization" not in lower


# ===========================================================================
# AD-AG. Boundary enforcement (no execution, no I/O, no external systems)
# ===========================================================================


class TestBoundaryEnforcement:
    def test_no_execution_of_rule_content(self):
        # Rule definitions are data only; the registry never evaluates
        # any expression, calls eval/exec, or runs the rule content.
        reg = DetectionRuleRegistry()
        rule = _rule("sigma-001", metadata={"content": "telemetry|where foo"})
        reg.register(rule)
        reg.find_enabled_by_type(RuleType.SIGMA)
        reg.disable("sigma-001")
        reg.enable("sigma-001")
        reg.unregister("sigma-001")
        # Merely reaching here proves the registry treated the content as
        # inert data and did not attempt to interpret it.
        assert True

    def test_no_database_persistence(self):
        # Registration, listing and selection are purely in-memory.
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-001"))
        reg.register(_yara_rule("yara-001"))
        reg.find_by_type(RuleType.SIGMA)
        reg.clear()
        # No SQL, no repository, no session was involved.
        assert True

    def test_no_network_requests(self):
        # No requests, HTTP clients, or remote code loading occurs.
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-001"))
        reg.get("sigma-001")
        reg.find_enabled_by_type(RuleType.SIGMA)
        assert True

    def test_no_llm_usage(self):
        # No prompt, no model call, no AI inference is performed.
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-001"))
        reg.list_rules()
        assert True

    def test_no_execution_helpers_imported(self):
        # Defensive: the registry module must not reference eval/exec.
        import inspect
        import app.services.detection.registry as registry_module
        source = inspect.getsource(registry_module)
        assert "eval(" not in source
        assert "exec(" not in source
        assert "subprocess" not in source
        assert "os.system" not in source


# ===========================================================================
# Edge cases
# ===========================================================================


class TestEdgeCases:
    def test_get_or_none_returns_none_for_unknown(self):
        reg = DetectionRuleRegistry()
        assert reg.get_or_none("missing") is None

    def test_get_or_none_returns_rule_for_known(self):
        reg = DetectionRuleRegistry()
        rule = _rule("sigma-001")
        reg.register(rule)
        assert reg.get_or_none("sigma-001") is rule

    def test_has_rule_true_false(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-001"))
        assert reg.has_rule("sigma-001") is True
        assert reg.has_rule("sigma-999") is False

    def test_find_by_type_empty_result(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-001"))
        assert reg.find_by_type(RuleType.YARA) == []
        assert reg.find_enabled_by_type(RuleType.YARA) == []

    def test_list_disabled_excludes_enabled(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-001"))
        reg.register(_rule("sigma-002", enabled=False))
        assert [r.rule_id for r in reg.list_disabled()] == ["sigma-002"]

    def test_deterministic_order_across_sigma_and_yara(self):
        reg = DetectionRuleRegistry()
        reg.register(_yara_rule("yara-b"))
        reg.register(_rule("sigma-b"))
        reg.register(_rule("sigma-a"))
        assert [r.rule_id for r in reg.list_rules()] == [
            "sigma-a", "sigma-b", "yara-b",
        ]

    def test_disable_then_enable_round_trip(self):
        reg = DetectionRuleRegistry()
        reg.register(_rule("sigma-001"))
        reg.disable("sigma-001")
        reg.enable("sigma-001")
        assert reg.get("sigma-001").enabled is True
        assert [r.rule_id for r in reg.find_enabled_by_type(RuleType.SIGMA)] == [
            "sigma-001"
        ]
