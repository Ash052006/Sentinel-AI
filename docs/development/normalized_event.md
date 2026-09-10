Normalized Event Contract
========================

Overview
--------

The NormalizedSecurityEvent schema defines the common internal
representation for security events after normalization. It lives
alongside (not replacing) the raw SecurityEvent contract.


Data-layer separation
---------------------

::

    SecurityEvent (raw)
    ├── event_id
    ├── timestamp
    ├── source
    ├── source_type
    ├── event_type
    ├── raw_data          ← immutable, forensic-grade
    ├── metadata
    └── provenance

    NormalizedSecurityEvent (normalized)
    ├── event_id          ← same as SecurityEvent.event_id
    ├── timestamp         ← same as SecurityEvent.timestamp
    ├── event_category    ← derived during normalization
    ├── action            ← derived (free-form string)
    ├── outcome           ← derived
    ├── source            ← carried forward
    ├── source_type       ← carried forward
    ├── actor             ← derived (optional)
    ├── source_endpoint   ← derived (optional)
    ├── destination_endpoint ← derived (optional)
    ├── process           ← derived (optional)
    ├── file              ← derived (optional)
    ├── normalized_data   ← flexible derived fields
    └── provenance        ← event-level trust marker

Key design principle: ``raw_data`` lives **only** on SecurityEvent.
It is never duplicated into NormalizedSecurityEvent.


Field semantics
---------------

raw_data
~~~~~~~~

Original source representation as collected. Preserved verbatim for
forensic investigation, auditing, debugging, replay, and future AI
investigation.

normalized_data
~~~~~~~~~~~~~~~

Common representation derived from the original event during
normalization. Contains structured JSON-compatible data that does
not yet fit into the strongly-typed common fields (actor, endpoint,
process, file).

Do not use normalized_data as a mirror of raw_data.

enriched data
~~~~~~~~~~~~~

Additional information obtained from another source (e.g. threat
intelligence, asset inventory, identity store). Added by future
enrichment agents. Not part of the normalized contract.

reconstructed data
~~~~~~~~~~~~~~~~~~

Information inferred because source information was missing (e.g.
synthesizing a missing hostname from IP address). Created by future
synthetic-reconstruction agents. Not part of the normalized contract.

These four layers must remain conceptually distinct throughout the
SentinelAI pipeline.


Provenance
----------

NormalizedSecurityEvent reuses the existing Provenance enum:

* **observed** — the information was directly mapped from the raw
  event during normalization. A newly normalized event defaults to
  this value.
* **enriched** — additional context was obtained from an external
  source (applied by future enrichment agents).
* **reconstructed** — information was inferred to fill gaps (applied
  by future synthetic-reconstruction agents).

Do NOT classify normalized information as enriched simply because it
is normalized. Do NOT classify it as reconstructed unless inference
actually occurred.

The schema is designed to support future field-level provenance
without redesigning this contract.


Event ID preservation
---------------------

NormalizedSecurityEvent retains the original SecurityEvent event_id.
This ensures every stage in the pipeline (raw → normalized →
enriched → reconstructed) remains traceable to a single underlying
security event.


File location
-------------

* Schema: ``backend/app/schemas/normalized_event.py``
* Tests: ``backend/tests/unit/test_normalized_event.py``
