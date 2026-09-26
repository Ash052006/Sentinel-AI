Incident Memory Contract (Step 16)
==================================

Overview
--------

**Incident Memory** is the durable, deterministic memory that Sentinel
keeps of past incidents and their reusable intelligence.  This document
defines the **contract** for that capability (Step 16): a leak-free typed
schema capable of recording *what happened*, *which observable produced
it*, *which techniques/actors/findings were involved*, and *which
mitigations/outcomes followed* — grounded in an explicit provenance for
every source.

It is **contract only**: it introduces the validated data models, but the
actual *extraction* of memory from a source incident is a separate,
downstream capability (documented in ``incident_memory_extraction.md``).

The models live in ``backend/app/schemas/incident_memory.py``.

Purpose
-------

The contract provides a stable, typed schema for incident memory so that:

1. Past incidents and their indicators/techniques/actors are recorded in a
   deterministic, auditable shape that later TTP-lookup, correlation and
   recall can consume without re-parsing prose.
2. Provenance is preserved at the source level: every memory source says
   *how* Sentinel came to know it (``OBSERVED``, ``ENRICHED``,
   ``ANALYZED``, ``SUMMARIZED``, ...) so a recalled memory can honestly
   relabel itself ``RECALLED`` **without ever rewriting** its sources.
3. Determinism is guaranteed: identical input yields byte-identical JSON,
   with no hidden nondeterminism (injected clock + id factory, canonical
   ordering, JSON-compatible values only).
4. Safety is guaranteed: **secret-shaped content is rejected, never
   redacted**, and rejection never echoes the matched content back
   (no leak-on-reject).  Secret detection runs over the *whole* record so
   secret-shaped *values* are rejected exactly like secret-shaped *keys*.
5. Everything a consumer can rely on is bounded and validated
   (length caps, metadata depth, per-item reference caps, provenance
   coherence).

Pipeline position
-----------------

::

    SecurityEvent → Normalized → Enriched                 (earlier steps)
        → IncidentMemoryExtractor (Step 16, extraction)
            → IncidentMemory   (this contract — the durable shape)
        → Recall / TTP-lookup / correlation               (future)

Contract guarantees (cited by design location)
----------------------------------------------

Leak-free whole-record secret scan
    ``_SecretScannedRecord`` (the base for every standalone content record)
    and ``IncidentMemory._ensure_record_secret_free`` scan the **entire
    serialized record** as text.  A seed-shaped value is rejected with a
    message that names only the matched *pattern* — never the content —
    so rejection itself cannot leak.  Proven by the contract test
    ``test_error_message_leaks_no_content`` (asserts ``api_key`` present,
    the JWT fragment *) absent*) and by ``test_all_patterns_rejected`` for
    every record type (source/indicator/entity/technique/finding/action/
    outcome as well as the envelope).

Provenance
    ``IncidentMemory.provenance`` is pinned to the single additive member
    ``Provenance.RECALLED`` for all recalled memory.  ``MemoryType`` is a
    closed 5-value enum.  Sources keep their own original provenance and
    are never downgraded when nested under a ``RECALLED`` envelope.

Determinism
    Deterministic canonical emission: identical input → identical JSON.
    ``IncidentMemory.model_dump_json()`` is canonical, byte-stable, with no
    nondeterministic ordering or timestamps.  The extractor (not this
    contract) injects clock + uuid factory; this schema's own ids
    (``memory_id`` etc.) serialize byte-identically once fixed.

Boundedness
    All constant caps live in code (``MAX_MEMORY_*``): title/summary/finding
    caps, ``MAX_MEMORY_METADATA_DEPTH``, per-item source-reference caps,
    and a bounded (well-formed) JSON-only metadata constraint.  Caps reject
    with ``ValidationError``; they never silently truncate.

Reference coherence
    Sources/indicators/entities/techniques/findings/actions/outcomes are
    held as reference models; every indicator must resolve to sources that
    actually exist in the record, and envelope-level validation rejects
    dangling references (see the contract's reference-coherence tests).

Full isolated-run evidence (Step 16, stand-alone echo-after cwd fix):
    ``110 passed`` across both ``test_incident_memory_contract.py`` and
    ``test_incident_memory_extraction.py``; full suite green
    (``3355 passed, 2 skipped``) with ``python -m compileall -q app tests``
    clean and alembic head unchanged (``4a6c8d0e1f2a``).  Details in the
    Step 16 report.
