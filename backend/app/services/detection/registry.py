"""DetectionRuleRegistry — in-memory registry of detection rules.

The registry manages a set of :class:`DetectionRule` instances using
explicit dependency injection (rules are passed into the registry
explicitly) rather than global hidden state.  This keeps the registry
independently testable and free of network, database, or LLM side
effects.

The registry is a **rule-management and selection layer only**.  It does
**not** execute Sigma or YARA rules, generate :class:`DetectionResult`
objects, correlate events, calculate risk, or contact external services.

Responsibilities:
    * Register validation rules (rejecting duplicate rule IDs).
    * Retrieve a rule by ``rule_id``.
    * List all / enabled / disabled rules deterministically.
    * Find rules by :class:`RuleType` (respecting enabled state).
    * Enable and disable rules without removing them.

Process-local nature:
    This registry holds rules **in memory** for the lifetime of the
    instance.  It is process-local, not cluster-wide, and not persisted.
    It makes no network requests and performs no I/O.
"""

from __future__ import annotations

from typing import Iterable

from app.schemas.detection import DetectionRule, RuleType
from app.services.detection.exceptions import (
    DetectionRuleNotFoundError,
    DuplicateDetectionRuleError,
)


class DetectionRuleRegistry:
    """Stores and retrieves detection rules by ``rule_id``.

    Rules are injected at construction time (or via :meth:`register`)
    and live only for the lifetime of this registry instance.  No global
    state is used.

    Rules are treated as **caller-owned, immutable read-only** data: the
    registry stores and returns the exact :class:`DetectionRule` object
    it is given and never mutates it.  It never creates its own copies.
    Selection and listing are deterministic (ordered by ``rule_id``) and
    never modify the underlying rules.
    """

    def __init__(
        self,
        rules: Iterable[DetectionRule] | None = None,
    ) -> None:
        self._rules: dict[str, DetectionRule] = {}
        if rules is not None:
            for rule in rules:
                self.register(rule)

    # -- Registration ---------------------------------------------------------

    def register(self, rule: DetectionRule) -> None:
        """Register a rule, keyed by its ``rule_id``.

        The exact :class:`DetectionRule` object is stored (no copy is
        made) and is never mutated by the registry.  Duplicate ``rule_id``
        values are rejected — an existing rule is never silently
        overwritten, even if the *version* differs.

        Raises:
            TypeError: If *rule* is not a :class:`DetectionRule`.
            DuplicateDetectionRuleError: If a rule with the same
                ``rule_id`` is already registered.
        """
        if not isinstance(rule, DetectionRule):
            raise TypeError(
                "Expected DetectionRule, "
                f"got {type(rule).__name__}"
            )
        rule_id = rule.rule_id
        if rule_id in self._rules:
            raise DuplicateDetectionRuleError(
                rule_id=rule_id,
                version=rule.version,
            )
        self._rules[rule_id] = rule

    def unregister(self, rule_id: str) -> DetectionRule:
        """Remove and return the rule registered under *rule_id*.

        Only the matching rule is removed — never any other rule.

        Raises:
            DetectionRuleNotFoundError: If no rule with that ``rule_id``
                is registered.
        """
        if rule_id not in self._rules:
            raise DetectionRuleNotFoundError(rule_id)
        return self._rules.pop(rule_id)

    # -- Retrieval ------------------------------------------------------------

    def get(self, rule_id: str) -> DetectionRule:
        """Return the rule registered under *rule_id*.

        Raises:
            DetectionRuleNotFoundError: If no rule with that ``rule_id``
                is registered.
        """
        try:
            return self._rules[rule_id]
        except KeyError:
            raise DetectionRuleNotFoundError(rule_id) from None

    def get_or_none(self, rule_id: str) -> DetectionRule | None:
        """Return the rule or ``None`` if not registered.

        An alternative to :meth:`get` for callers that prefer ``None``
        over an exception for unknown rule IDs.
        """
        return self._rules.get(rule_id)

    def has_rule(self, rule_id: str) -> bool:
        """Return True if a rule with *rule_id* is registered."""
        return rule_id in self._rules

    # -- Listing --------------------------------------------------------------

    def list_rules(self) -> list[DetectionRule]:
        """Return all registered rules, deterministically ordered by
        ``rule_id``.

        A fresh list is returned each call; the registry's internal
        state is never exposed directly.
        """
        return [self._rules[rid] for rid in sorted(self._rules)]

    def list_enabled(self) -> list[DetectionRule]:
        """Return all enabled rules, ordered by ``rule_id``."""
        return [r for r in self.list_rules() if r.enabled]

    def list_disabled(self) -> list[DetectionRule]:
        """Return all disabled rules, ordered by ``rule_id``.

        Disabled rules remain registered and retrievable; this list is
        provided for management visibility.
        """
        return [r for r in self.list_rules() if not r.enabled]

    def list_rule_ids(self) -> list[str]:
        """Return the sorted rule IDs of all registered rules."""
        return sorted(self._rules)

    # -- Selection ------------------------------------------------------------

    def find_by_type(self, rule_type: RuleType) -> list[DetectionRule]:
        """Return all rules of *rule_type*, ordered by ``rule_id``.

        *rule_type* may be a :class:`RuleType` member or its raw string
        value (e.g. ``RuleType.SIGMA`` or ``\"sigma\"``).  Enabled state
        is ignored.  Rules are never modified.
        """
        return [
            r for r in self.list_rules() if r.rule_type == rule_type
        ]

    def find_enabled_by_type(
        self, rule_type: RuleType,
    ) -> list[DetectionRule]:
        """Return all enabled rules of *rule_type*, ordered by
        ``rule_id``.

        *rule_type* may be a :class:`RuleType` member or its raw string
        value.  Disabled rules are excluded.  Rules are never modified.
        """
        return [
            r for r in self.list_rules()
            if r.rule_type == rule_type and r.enabled
        ]

    # -- Enable / Disable -----------------------------------------------------

    def enable(self, rule_id: str) -> None:
        """Enable a disabled rule.

        The stored rule's ``enabled`` field is updated to enabled.
        Enabling an already-enabled rule is a no-op.

        Raises:
            DetectionRuleNotFoundError: If no rule with that ``rule_id``
                is registered.
        """
        rule = self.get(rule_id)
        if not rule.enabled:
            self._rules[rule_id] = rule.model_copy(update={"enabled": True})

    def disable(self, rule_id: str) -> None:
        """Disable an enabled rule.

        Disabling does **not** remove the rule from the registry; the
        rule definition and metadata are preserved.  Disabling an
        already-disabled rule is a no-op.

        Raises:
            DetectionRuleNotFoundError: If no rule with that ``rule_id``
                is registered.
        """
        rule = self.get(rule_id)
        if rule.enabled:
            self._rules[rule_id] = rule.model_copy(update={"enabled": False})

    # -- Management -----------------------------------------------------------

    def clear(self) -> None:
        """Remove all registered rules, leaving the registry empty."""
        self._rules.clear()

    def count(self) -> int:
        """Return the number of registered rules."""
        return len(self._rules)

