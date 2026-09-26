Incident Memory Extraction (Step 16)
====================================

Overview
--------

**IncidentMemoryExtractor** turns a completed, validated risk/investigation
*context* into a durable, deterministic **IncidentMemory** record.

It is the **extraction** half of Step 16 (the *shape* is defined separately
by ``incident_memory_contract.md``; this document is the *producer*).
It performs **time and id injection** (determinism), **provenance
propagation**, **bound/consistency policy application**, and a
**whole-record leak-free secret scan** just before emission — so the memory
that lands on disk is canonical, safe)Skip.

The extractor lives in ``backend/app/services/incident_memory/``
(``input.py`` → ``policy.py`` → ``extractor.py``).  It returns an
``IncidentMemory``; nothing here reaches for storage or external TTP
lookup (those are later steps).

Guarantees
----------

1. Determinism
   Instances take optional ``clock`` and ``uuid_factory`` callables
   (default: ``datetime.now`` / ``uuid.uuid4``).  All ids and timestamps
   flow through these, so identical context + identical injections ⇒
   byte-identical output.  The suite round-trips and byte-compares to
   prove there is no hidden nondeterminism.

2. Provenance propagation without degradation
   Sources keep their original ``OBSERVED``/``ENRICHED``/... provenance;
   nested memory never rewrites them.  The extracted envelope is
   ``RECALLED`` *only as its own label* — source provenance is untouched,
   so recall honesty is preserved by construction.

3. Bounded policy
   Validation enforces the contract's caps and reference coherence
   (memory/summary/finding length; metadata depth; per-item source
   references; indicator↔source linkage).  Caps clamp *never* — they
   reject with ``ValidationError`` / ``IncidentMemoryError``.

4. Leak-free whole-record secret safety
   The final scan serializes the *entire* candidate memory and rejects
   any secret-shaped content, naming **only the matched pattern**, never
   the content.  A rejected memory is thrown away — never stored, never
   redacted, never echoed.

5. Fail-fast, honest errors
   Unbearable or empty contexts produce *valid zero-result* memory (a
   memory with no indicators is still a coherent incident memory), while
   incoherent contexts (stale/invalid provenance or dangling refs) raise
   ``IncidentMemoryError`` instead of silently emitting a corrupt record.

Pipeline position
-----------------

::

    RiskContext / InvestigationContext       (validated input)
        → IncidentMemoryInput                 (input.py, tight shape)
            → policy.py  (bounds · coherence · metadata JSON-compat)
                → extractor.py (clock · uuid_factory · whole-record scan)
                    → IncidentMemory           (contract; deterministic JSON)

Determinism mechanics
---------------------

Instantiation::

    extractor = IncidentMemoryExtractor(
        clock=clock,          # callable → datetime (injectable, default now)
        uuid_factory=uuid_factory,  # callable → UUID (injectable, default uuid4)
    )

Every emitted id (memory id, source ids, indicator ids, …) and the
``created_at`` originate from these factories; the suite injects fixed
ones and asserts the produced JSON is **byte-identical across identical
input**.

Safety mechanics
----------------

``extractor._ensure_output_secret_free`` (or the shared schema-level
whole-record scan) rejects secret-shaped values exactly like keys, via a
**single** message naming the matched *pattern word* — verified leak-free
by ``TestSecretSafety`` in the contract suite (the matched *content* never
appears in the rejection text).

Testing
-------

Two fresh, dedicated files were added at Step 16:

* ``tests/unit/test_incident_memory_contract.py`` — the *contract*:
  whole-record leak-free secret rejects, provenance permanence,
  determinism (identical input ⇒ identical JSON), bounded caps,
  reference coherence, reference resolution.
* ``tests/unit/test_incident_memory_extraction.py`` — the *extraction*
  capability: deterministic output, provenance propagation, policy
  application, fail-fast/honest-error behaviour, zero-result memory.

Result at Step 16: **110 passed** across the two files (contract + 
extraction), each green in isolation and together; full-suite regression
green (3355 passed / 2 skipped) with ``compileall`` clean and the alembic
head unchanged (``4a6c8d0e1f2a``).
