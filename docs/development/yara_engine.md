YARA Detection Engine (Step 9D)
===============================

Overview
--------

**Step 9D** adds the **YARA Detection Engine** — a focused, deterministic
rule-evaluation engine that matches YARA rules against explicitly supplied
content bytes and produces structured :class:`DetectionResult` objects using
the existing Step 9A detection contract.

The engine builds on the Step 9B ``DetectionRuleRegistry`` (for rule
selection), the Step 9A ``DetectionRule`` / ``DetectionResult`` /
``DetectionEvidence`` schemas, and follows the reporting pattern
established by the Step 9C Sigma engine (``YaraDetectionReport`` /
``YaraRuleFailure`` mirror ``SigmaDetectionReport`` / ``SigmaRuleFailure``).

The engine is **a detection engine only**:

* It does **not** calculate risk.
* It does **not** correlate events.
* It does **not** call an LLM or threat-intelligence providers.
* It does **not** map MITRE techniques.
* It does **not** persist results.
* It does **not** publish Kafka messages.
* It does **not** take response actions.
* It does **not** orchestrate Sigma rules.

Architecture
------------

::

    SecurityEvent / applicable normalized file-content data
                    ↓
           DetectionRuleRegistry
                    ↓
             Enabled YARA Rules
                    ↓
            YaraDetectionEngine
                    ↓
              DetectionResult

The engine compiles YARA source into in-memory rule objects, matches them
against the target bytes via the standard ``yara-python`` matching API,
and converts successful matches into Step 9A ``DetectionResult`` objects
with deterministic structured evidence.

File locations
--------------

* Engine: ``backend/app/services/detection/yara/engine.py``
* Exceptions: ``backend/app/services/detection/yara/exceptions.py``
* Target adapter: ``backend/app/services/detection/yara/target_adapter.py``
* Package exports: ``backend/app/services/detection/yara/__init__.py``
* Tests: ``backend/tests/unit/test_yara_engine.py``
* This document: ``docs/development/yara_engine.md``

YARA dependency
---------------

* **Package**: ``yara-python==4.5.4``
* **Rationale**: ``yara-python`` is the official Python binding for
  YARA, maintained by the YARA authors at VirusTotal under the Apache
  2.0 license.  It is the de-facto standard Python binding for YARA
  and provides the ``yara.compile(source=...)`` public API used by the
  engine.  A pre-compiled wheel is available for CPython 3.11 on
  Windows, which is the project's current environment (Python 3.11.9).
* **Installation**: ``pip install yara-python==4.5.4``.  On Linux, the
  wheel may require the system libyara (see the package documentation);
  on Windows a self-contained wheel is provided.
* **Version pinning**: the dependency is pinned exactly in
  ``backend/requirements.txt`` consistent with project conventions.

No rules are downloaded dynamically.  No remote rule repository is used.

Supported YARA target types
---------------------------

YARA is content-oriented and evaluates **bytes**.  The engine supports a
small, explicit target abstraction — :class:`YaraTarget`:

* ``bytes`` / ``bytearray`` content — the primary supported target;
* file content already present **in memory** inside a
  :class:`NormalizedSecurityEvent` event's ``normalized_data`` (keyed as
  ``file_content``, ``file.content_bytes``, ``file.raw_content``, or
  ``raw_file_content``); string values are treated as base64-encoded
  (decoded) or plain UTF-8 text (used directly).

The engine's event adapter ``to_yara_target(event)`` extracts
already-present in-memory content from the event — the engine **never**
reads arbitrary local filesystem paths.

Documented non-targets (never treated as file content):

* file name (``file.name``);
* file extension (``file.extension``);
* file path (``file.path``);
* file hash (``file.hash``);
* process name / command line.

A hash is **not** file content.  A filename is **not** file content.  If an
event carries none of the supported content fields, ``to_yara_target``
raises ``InvalidYaraTargetError`` and ``evaluate()`` returns a report with
Rule representation
-------------------

The engine reuses the existing Step 9A ``DetectionRule`` contract with
``rule_type == RuleType.YARA``.  The YARA source is stored in the
rule's ``content`` field as a **string** containing the YARA rule text,
for example::

    rule SuspiciousPayload
    {
        meta:
            description = "Example detection"

        strings:
            $a = "suspicious_payload"

        condition:
            $a
    }

No competing rule model is introduced.  ``content`` must be a non-empty
string; ``dict`` / ``None`` / other content types are recorded as explicit
``malformed_rule`` failures.  Rule metadata in ``meta:`` and rule tags are
carried through the evaluation contract unchanged (see Evidence below).

Rule selection
--------------

The engine integrates with the existing ``DetectionRuleRegistry`` using::

    registry.find_enabled_by_type(RuleType.YARA)

The engine itself does **not** hold a registry reference and does **not**
maintain enable/disable state.  Given a list of rules, the engine will:

* evaluate only rules with ``rule_type == RuleType.YARA``;
* skip disabled rules;
* never execute Sigma rules.

Selection/order of results is deterministic and ordered by ``rule_id``
(consistent with registry ordering semantics).

Compilation
-----------

Rules are compiled one at a time with the YARA library's safe public API
``yara.compile(source=...)``.  Compilation is **isolated per rule** — a
malformed rule is recorded as an explicit ``malformed_rule`` failure and
**never** causes unrelated valid rules to disappear.

A simple in-process compiled-rule cache is keyed by ``(rule_id, version)``
and bounded at 512 entries (evicted wholesale when full).  The cache is
process-local and deterministic; unchanged rules are not recompiled.

Matching
--------

Matching uses the YARA library's normal ``rules.match(data=...)`` API
against the target bytes.  The engine never reimplements YARA's matching
language, never parses YARA conditions itself, and never evaluates rule
conditions as Python.

Evidence
--------

Every match produces a ``DetectionEvidence`` object derived deterministically
from the actual YARA match.  The evidence contains:

* ``matched_conditions`` — matched string identifiers
  (e.g. ``"strings:$a"``);
* ``matched_fields`` — a small safe map (e.g. ``content`` and optionally
  ``file.name``); **never** the raw file content;
* ``rule_references`` — rule metadata values from ``meta:``;
* ``detection_context`` — matched string identifiers with byte offsets
  and matched lengths, plus rule tags.

Raw file content is **never** embedded in evidence.  Identifiers, offsets,
lengths, and safe metadata only.

Confidence policy
-----------------

YARA matching is deterministic.  Confidence is the **same deterministic
base value used by the Step 9C Sigma engine**, derived solely from
``DetectionRule.severity``:

* CRITICAL → 1.0
* HIGH → 0.9
* MEDIUM → 0.7
* LOW → 0.5

Confidence is **not** a probability of maliciousness and is **separate
from** severity.  Severity comes from ``DetectionRule.severity`` and is
never inferred or modified based on match count, offsets, file extension,
file size, or number of matched rules.

DetectionResult
---------------

For every matching YARA rule the engine produces a Step 9A
``DetectionResult`` with:

* ``detection_id`` — auto-generated UUID;
* ``event_id`` — preserved exactly from the target's originating event
  (or the fixed sentinel UUID ``00000000-0000-0000-0000-000000000000``
  for standalone byte targets with no originating event, which keeps
  results deterministic);
* ``rule_id`` — preserved exactly;
* ``rule_type`` = ``RuleType.YARA``;
* ``matched`` = ``True``;
* ``severity`` — from the rule;
* ``confidence`` — deterministic severity-derived value;
* ``evidence`` — structured evidence;
* ``timestamp`` — evaluation timestamp;
* ``metadata`` — engine name, YARA rule name, namespace;
* ``provenance`` = ``Provenance.DETECTED``.

Only actual matches produce results; valid non-matches produce no result
and no failure (consistent with the Sigma engine).  This decision is
documented in the engine module docstring: callers that need explicit
non-match records may derive them from ``evaluated_rule_ids``.

Failure isolation
-----------------

The engine distinguishes:

1. valid non-match — no result, no failure;
2. valid match — a ``DetectionResult``;
3. malformed YARA rule — a ``YaraRuleFailure`` with
   ``error_type == "malformed_rule"``;
4. unsupported YARA functionality — a ``YaraRuleFailure`` with
   ``error_type == "unsupported_feature"``;
5. invalid target / no applicable content — a ``YaraRuleFailure`` with
   ``error_type == "invalid_target"``;
6. unexpected internal match errors — a ``YaraRuleFailure`` with
   ``error_type == "match_error"``.

Rule failures are **isolated**:  Rule A matches, Rule B is malformed,
Rule C matches → results for A and C are preserved, B is reported as an
explicit structured failure.  Failures are never silently swallowed and
never converted into non-matches.

Security boundaries
-------------------

The engine **never**:

* dynamically executes Python code from rules or content (no ``eval`` /
  ``exec``);
* launches external processes (no shell, PowerShell, or subprocess
  execution for YARA);
* downloads rules or payloads;
* accesses a remote rule repository;
* reads arbitrary local filesystem paths supplied by event data;
* loads arbitrary plugins;
* loads pre-compiled YARA rule binaries via ``yara.load()``;
* compiles YARA from files via ``yara.compile(filepath=...)``.

YARA source and target content are treated as untrusted input.  YARA
rules run inside the YARA library's interpreter; module ``import``
statements and ``include`` directives are rejected explicitly.

Filesystem-access restrictions
------------------------------

The engine **never automatically reads arbitrary local filesystem paths**
from event data.  A ``file.path`` such as ``C:\\some\\file.exe`` is
metadata only.  YARA evaluation operates on:

* bytes supplied explicitly to ``YaraTarget``, or
* content already present in memory in an event's ``normalized_data``.

Unsupported functionality (documented)
--------------------------------------

* ``import`` module directives (``math``, ``pe``, ``elf``, etc.) —
  rejected explicitly.
* ``include`` directives — rejected explicitly.
* External variables (``externals``) — the engine does not supply them.
* ``yara.compile(filepath=...)`` — the engine compiles from in-memory
  source only.
* ``yara.load()`` — the engine never loads pre-compiled rule files.
* Filesystem access from event data — ``file.path`` is never opened.

The engine does **not** claim complete YARA compatibility.  It supports
the YARA rule language as implemented by ``yara-python`` compilation for
standard string, hex-string, regex, condition, metadata, and tag
constructs, minus the deliberately rejected items above.

Process-local behavior
----------------------

The compiled-rule cache is **process-local, in-memory, and bounded**.  It
does not involve Redis, Kafka, Celery, database caching, distributed
locks, or cross-process synchronization.  No global mutable state is
used; each engine instance holds its own cache.

Dependency injection
--------------------

Dependencies are injected at construction time where appropriate:

* ``DetectionRuleRegistry`` — injected by callers (the engine does not
  instantiate one);
* YARA backend — the engine calls ``yara.compile`` /
  ``rules.match`` from the installed ``yara-python`` module, which tests
  can exercise against the real library.

No PostgreSQL, Kafka, or external services are required.

Exceptions
----------

* ``YaraDetectionError`` — base class (derives from the existing
  ``DetectionError``).
* ``MalformedYaraRuleError`` — the rule could not be compiled; carries
  ``rule_id`` and ``reason``.
* ``UnsupportedYaraFeatureError`` — the rule uses a deliberately
  unsupported construct; carries ``rule_id`` and ``feature``.
* ``InvalidYaraTargetError`` — the target/event carries no applicable
  content; carries a descriptive message.

Exception messages never expose rule content, event payloads, or secrets.

Tests
-----

``backend/tests/unit/test_yara_engine.py`` contains **100 tests** covering
(among others):

* engine instantiation; simple string matching; non-matching content;
* multiple strings (and / or conditions); hex-string and ``nocase``
  matching; offset conditions;
* multiple rules; disabled-rule exclusion; Sigma-rule exclusion;
* Step 9A result contract (event_id, rule_id, rule_type, severity,
  provenance, confidence);
* structured evidence (matched strings, offsets, lengths, tags, meta)
  without content leakage;
* explicit handling of events with no applicable content;
* no filesystem access from ``file.path``;
* malformed-rule failures and failure isolation;
* invalid-target handling; input immutability (event and rule);
* deterministic selection and repeated-evaluation determinism;
* empty registry / no-enabled-YARA-rules behavior;
* multiple matching rules producing separate results;
* metadata/tags consistency; security boundaries (no subprocess, no
  ``eval``/``exec``); binary content; compiled-rule cache behavior;
* synthetic harmless test payloads only.

What Step 9D does not include
-----------------------------

This step deliberately does **not** implement the detection agent
(Step 9E), Sigma functionality, detection persistence, MITRE ATT&CK
mapping, correlation, risk scoring, AI investigation, threat attribution,
incident memory, SOAR, response actions, frontend changes, Kafka
integration, or LLM reasoning — those belong to later steps.