"""Declarative policy rule registry — Step 24.

Holds an immutable snapshot of :class:`~app.schemas.policy_decision.
PolicyRule` declarative data and answers one question deterministically:
for a given :class:`ResponseActionType`, which enabled rules apply, in
which order?

* Ordering is a total order: ``(priority, policy_rule_id)`` ascending.
  Priority is explicit; id breaks ties.  The order never depends on
  insertion order, so the same rule set always yields the same decision.
* ``POLICY-NO-COVERAGE`` is the documented sentinel identity reported
  when the engine finds no enabled rule governing an action (the engine
  denies — fail closed).
* The registry never evaluates rules and never stores executable code.

Validation happens eagerly at construction: a duplicated
``policy_rule_id`` (the "conflicting rule configuration" case) is
rejected with :class:`PolicyRuleConfigurationError`; non-``PolicyRule``
entries are rejected the same way.  Individual rule-field conflicts
(e.g. an escalation below the risk floor) are rejected by the
``PolicyRule`` contract itself at construction time.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from app.schemas.policy_decision import PolicyRule, ResponseActionType
from app.services.policy.errors import PolicyRuleConfigurationError
from app.services.policy.rules import DEFAULT_POLICY_RULES

#: Documented sentinel used when no enabled rule governs an action.
NO_COVERAGE_RULE_ID = "POLICY-NO-COVERAGE"


def _rule_sort_key(rule: PolicyRule) -> tuple[int, str]:
    return (rule.priority, rule.policy_rule_id)


class PolicyRuleRegistry:
    """Immutable, deterministic snapshot of a policy rule set."""

    def __init__(self, rules: Iterable[PolicyRule] = ()) -> None:
        provided = tuple(rules)
        for item in provided:
            if not isinstance(item, PolicyRule):
                raise PolicyRuleConfigurationError(
                    "policy rules must be PolicyRule instances"
                )
        # Deep-copy snapshot: the registry never aliases caller objects,
        # so a caller mutating its own rule afterwards cannot change the
        # rule set the engine evaluates (determinism by construction).
        snapshot = tuple(rule.model_copy(deep=True) for rule in provided)
        ids = [rule.policy_rule_id for rule in snapshot]
        seen: set[str] = set()
        for rule_id in ids:
            if rule_id in seen:
                raise PolicyRuleConfigurationError(
                    f"duplicate policy_rule_id {rule_id!r} in the rule set "
                    "(conflicting rule configuration)"
                )
            seen.add(rule_id)
        #: Deterministic total order (priority, then id) — insertion order
        #: never influences selection.
        self._rules: tuple[PolicyRule, ...] = tuple(sorted(snapshot, key=_rule_sort_key))
        self._by_id: dict[str, PolicyRule] = {r.policy_rule_id: r for r in self._rules}

    @property
    def rules(self) -> tuple[PolicyRule, ...]:
        """The rule snapshot in deterministic order (read-only view)."""
        return self._rules

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def get(self, rule_id: str) -> PolicyRule | None:
        """Return the rule with *rule_id*, or None."""
        return self._by_id.get(rule_id)

    def rule_ids(self) -> tuple[str, ...]:
        """All rule ids in deterministic order."""
        return tuple(rule.policy_rule_id for rule in self._rules)

    def rules_for(self, action: ResponseActionType) -> tuple[PolicyRule, ...]:
        """Enabled rules that govern *action* (specific or cross-cutting),
        in deterministic ``(priority, rule_id)`` order."""
        return tuple(
            rule
            for rule in self._rules
            if rule.enabled and (rule.action_type is None or rule.action_type == action)
        )

    def __len__(self) -> int:
        return len(self._rules)


def _default_registry() -> PolicyRuleRegistry:
    return PolicyRuleRegistry(DEFAULT_POLICY_RULES)


#: Lazily built canonical default registry (module-level singleton).
DEFAULT_REGISTRY: PolicyRuleRegistry = _default_registry()


#: Convenience helper kept out of public API docs.
def _serialized(rules: Iterable[Any]) -> list[dict[str, Any]]:
    return [rule.model_dump(mode="json") for rule in rules]


__all__ = [
    "DEFAULT_REGISTRY",
    "NO_COVERAGE_RULE_ID",
    "PolicyRuleRegistry",
]