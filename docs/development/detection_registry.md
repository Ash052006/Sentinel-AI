Detection Rule Model & Registry (Step 9B)
=========================================

Overview
--------

**Step 9B** adds the detection rule **registry** — an in-memory
rule-management and selection layer that answers:

* Which detection rules are available to SentinelAI?
* Which rules are enabled?
* What version is each rule?
* Which rules should be selected for a particular detection engine
  (Sigma vs YARA)?

The registry is built on top of the existing ``DetectionRule`` contract
from Step 9A.  It reuses that schema verbatim — **no modifications were
made** to ``DetectionRule``, because it already carries everything the
registry needs (``rule_id``, ``rule_type``, ``version``, ``name``,
``description``, ``severity``, ``enabled``, ``metadata``).

The registry is **strictly a rule-management and selection layer**.  It
is **not** a rule execution engine.

Architecture
------------

::

                    DetectionRule
                         │
                         ▼
              ┌────────────────────┐
              │ Detection Registry │
              └─────────┬──────────┘
                        │
             ┌──────────┴──────────┐
             ▼                     ▼
       Enabled Sigma          Enabled YARA
             │                     │
             └──────────┬──────────┘
                        ▼
               Future Detection
                   Engines

File locations
--------------

* Registry: ``backend/app/services/detection/registry.py``
* Exceptions: ``backend/app/services/detection/exceptions.py``
* Package exports: ``backend/app/services/detection/__init__.py``
* Tests: ``backend/tests/unit/test_detection_registry.py``
* This document: ``docs/development/detection_registry.md``

Purpose of DetectionRuleRegistry
--------------------------------

``DetectionRuleRegistry`` stores ``DetectionRule`` objects keyed by
``rule_id`` and supports:

* ``register(rule)`` — add a rule, rejecting duplicate IDs.
* ``unregister(rule_id)`` — remove a rule.
* ``get(rule_id)`` / ``get_or_none(rule_id)`` / ``has_rule(rule_id)`` —
  retrieval.
* ``list_rules()`` / ``list_enabled()`` / ``list_disabled()`` /
  ``list_rule_ids()`` — enumeration.
* ``find_by_type(rule_type)`` / ``find_enabled_by_type(rule_type)`` —
  deterministic selection.
* ``enable(rule_id)`` / ``disable(rule_id)`` — state changes.
* ``clear()`` / ``count()`` — management.

Registration
------------

A rule is registered by passing a ``DetectionRule`` instance::

    registry = DetectionRuleRegistry()
    registry.register(
        DetectionRule(
            rule_id="sigma-credential-access-001",
            name="Credential Access via PowerShell",
            description="Detects credential dumping via PowerShell",
            rule_type=RuleType.SIGMA,
            severity=DetectionSeverity.HIGH,
        )
    )

Rules may also be injected at construction time::

    registry = DetectionRuleRegistry([rule_a, rule_b])

Registration validates that the argument is a ``DetectionRule``
(rejecting anything else with ``TypeError``) and rejects duplicate
``rule_id`` values with ``DuplicateDetectionRuleError``.  The exact rule
object is stored; the registry never copies or mutates caller-owned
input.

Retrieval
---------

``get(rule_id)`` returns the stored rule and raises
``DetectionRuleNotFoundError`` if it is absent.  ``get_or_none`` returns
``None`` for unknown IDs, and ``has_rule`` returns a boolean.  These
mirror the conventions established by ``ProviderRegistry`` in the
threat-intelligence layer.

Enabling / disabling
--------------------

::

    registry.disable("sigma-001")
    registry.enable("sigma-001")

Disabled rules **remain registered** and retrievable; disabling only
excludes them from enabled-rule selection (``list_enabled`` and
``find_enabled_by_type``).  The rule definition and metadata are
preserved.  Enabling/disabling an already-enabled/disabled rule is a
no-op.  Unknown rule IDs raise ``DetectionRuleNotFoundError``.

Deterministic selection
-----------------------

Selection methods return rules ordered by ``rule_id`` (ascending), so the
result is stable and reproducible regardless of registration order:

* ``find_by_type(RuleType.SIGMA)`` / ``find_by_type(RuleType.YARA)`` —
  all rules of that type (ignoring enabled state).
* ``find_enabled_by_type(...)`` — only enabled rules of that type.

Selection never modifies rules and never selects randomly.

Duplicate handling
------------------

``rule_id`` is the uniqueness identity.  Registering a rule whose
``rule_id`` already exists raises ``DuplicateDetectionRuleError`` and the
original rule is preserved unchanged — registration **never** silently
overwrites an existing rule.

Version semantics
-----------------

A rule's version is stored as metadata on the ``DetectionRule``
(``version`` field).  Because uniqueness is keyed on ``rule_id`` (not on
``rule_id + version``), registering the *same* ``rule_id`` with a
*different* version is still rejected — version changes do **not**
implicitly replace an existing rule.  There is no version history,
rollback, or deployment database in this step.

Mutation safety
---------------

The registry stores and returns the exact ``DetectionRule`` object it is
given and never mutates it or caller-owned input.  Listing methods
return freshly-built lists (never the internal storage), so callers
cannot accidentally corrupt registry state through a returned collection.
Enabled/disabled state changes store an immutable ``model_copy`` with the
updated ``enabled`` flag, leaving the caller-owned rule object untouched.

Process-local nature
--------------------

This registry is **process-local and in-memory**.  It is not
cluster-wide, is not persisted to a database, and is not distributed.
It is safe for use within a single application process; no cross-process
synchronization, distributed locks, Redis, or Kafka are involved.
Because the registry is an application-layer component and rules are
registered before the registry is shared, no additional thread-safety
mechanism is required for this step.

Dependency injection
--------------------

The registry is designed to be injected into future detection
components::

    registry = DetectionRuleRegistry()
    detection_agent = DetectionAgent(rule_registry=registry)  # future step

The registry itself never instantiates detection engines and never
executes rules.


What the registry does NOT execute
----------------------------------

The registry has **no** execution capability.  It does **not**:

* execute Sigma rules,
* execute YARA rules,
* evaluate arbitrary Python (no ``eval`` / ``exec``),
* run shell or PowerShell commands,
* generate ``DetectionResult`` objects,
* calculate risk or correlate events,
* map MITRE ATT&CK techniques,
* call an LLM or AI model,
* persist to PostgreSQL,
* publish to Kafka,
* call external APIs, or
* take response actions.

Its only responsibilities are storing, validating, retrieving, enabling /
disabling, and deterministically selecting rules.

Exceptions
----------

* ``DetectionError`` — base class for all detection rule-management
  errors.
* ``DuplicateDetectionRuleError`` — raised when a ``rule_id`` is already
  registered.  Carries ``rule_id`` and ``version``.
* ``DetectionRuleNotFoundError`` — raised when a ``rule_id`` is not
  registered.  Carries ``rule_id``.

Exception messages contain only rule IDs and versions — never secrets,
credentials, or rule content.

Criteria
--------

Validation criteria covered by the registry tests:

1. Registry can be instantiated.
2. Register a valid SIGMA rule.
3. Register a valid YARA rule.
4. Retrieve a rule by ``rule_id``.
5. Register multiple rules.
6. List all rules.
7. List enabled rules.
8. Find rules by SIGMA type.
9. Find rules by YARA type.
10. Find enabled SIGMA rules.
11. Find enabled YARA rules.
12. Disabled rules excluded from enabled selection.
13. Disabled rules remain retrievable.
14. Enable a disabled rule.
15. Disable an enabled rule.
16. Duplicate ``rule_id`` rejected.
17. Duplicate registration does not silently overwrite.
18. Different rule IDs may share a rule type.
19. Rule severity preserved.
20. Rule version preserved.
21. Rule metadata preserved.
22. Unregister an existing rule.
23. Unregister behavior for an unknown rule ID.
24. Selection is deterministic (ordered by ``rule_id``).
25. Listing does not expose mutable internal state.
26. Caller-owned rule is not unexpectedly mutated.
27. Empty registry behavior.
28. Clear registry behavior.
29. Domain-specific exceptions behave correctly.
30. No execution of rule content.
31. Registry is independent of a database.
32. Registry is independent of external network services.
33. Registry is independent of LLMs.

