Enrichment Contract
===================

Overview
--------

The EnrichmentContract defines the schema for **enriched** security events
in SentinelAI.  Enrichment adds external or contextual information to a
NormalizedSecurityEvent without mutating it.

Enrichment sits between normalization and detection in the pipeline::

    SecurityEvent (raw)
        ↓
    NormalizedSecurityEvent (normalized)
        ↓
    EnrichedSecurityEvent (enriched)  ← this contract
        ↓
    Future Detection

Why enrichment exists
---------------------

Normalization interprets existing raw fields into a common representation.
Enrichment adds *new* information that was not in the original event:

* IP reputation scores from threat-intelligence providers
* Geolocation data from MaxMind or similar services
* Domain reputation from AlienVault OTX
* Hash reputation from VirusTotal
* User context from internal identity stores
* Asset context from CMDB

Enrichment does **not** replace or overwrite original fields.  It is
strictly additive.


Enrichment vs normalization
----------------------------

+---------------+-------------------------------------------+
| Aspect        | Normalization                             |
+===============+===========================================+
| Input         | SecurityEvent                             |
+---------------+-------------------------------------------+
| Output        | NormalizedSecurityEvent                   |
+---------------+-------------------------------------------+
| Purpose       | Map source-specific fields to common       |
|               | representation                             |
+---------------+-------------------------------------------+
| New data?     | No — rearranges existing fields            |
+---------------+-------------------------------------------+

+---------------+-------------------------------------------+
| Aspect        | Enrichment                                |
+===============+===========================================+
| Input         | NormalizedSecurityEvent                   |
+---------------+-------------------------------------------+
| Output        | EnrichedSecurityEvent                     |
+---------------+-------------------------------------------+
| Purpose       | Add external/contextual information       |
+---------------+-------------------------------------------+
| New data?     | Yes — new enrichment results              |
+---------------+-------------------------------------------+


Enrichment vs reconstruction
-----------------------------

Reconstruction (a future stage) **infers** missing fields.  Enrichment
**adds** new information from external sources.

Reconstructed data uses ``Provenance.RECONSTRUCTED``.  Enriched data
uses ``Provenance.ENRICHED``.

These must never be confused.


EnrichedSecurityEvent structure
-------------------------------

::

    EnrichedSecurityEvent
    ├── event_id              ← preserved from NormalizedSecurityEvent
    ├── timestamp             ← preserved from NormalizedSecurityEvent
    ├── normalized_event      ← the full NormalizedSecurityEvent (never mutated)
    ├── enrichments[]         ← list of EnrichmentResult
    │   ├── EnrichmentResult 1
    │   ├── EnrichmentResult 2
    │   └── EnrichmentResult 3
    └── provenance            ← defaults to ENRICHED


EnrichmentResult structure
--------------------------

::

    EnrichmentResult
    ├── enrichment_id         ← unique ID for this enrichment (UUID)
    ├── enrichment_type       ← category (e.g. "ip_reputation")
    ├── source                ← origin (e.g. "VirusTotal")
    ├── value                 ← structured JSON payload
    ├── confidence            ← optional [0.0, 1.0]
    ├── timestamp             ← when the enrichment was produced
    └── metadata              ← optional JSON-compatible metadata


Provenance semantics
--------------------

The existing ``Provenance`` enum is reused — no new enum is created.

* **OBSERVED** — information directly present in the original event.
  The NormalizedSecurityEvent defaults to this.
* **ENRICHED** — information added by an enrichment source.
  The EnrichedSecurityEvent defaults to this.
* **RECONSTRUCTED** — information inferred to fill gaps.
  Applied by future reconstruction agents only.

Critical rule: the original NormalizedSecurityEvent's provenance is
**never** changed by enrichment.  If it was OBSERVED, it stays OBSERVED.


Event ID vs enrichment ID
-------------------------

* ``event_id`` — identity of the security event.  Carried through the
  entire pipeline: SecurityEvent → NormalizedSecurityEvent →
  EnrichedSecurityEvent.  Never regenerated.
* ``enrichment_id`` — identity of a particular enrichment result.
  Unique per EnrichmentResult.  Distinct from ``event_id``.


Multiple enrichment support
---------------------------

One event can have many enrichments from different sources::

    event_id = A
    enrichments:
      1. type: ip_reputation, source: VirusTotal
      2. type: geolocation,   source: MaxMind GeoIP
      3. type: domain_reputation, source: AlienVault OTX

All coexist independently.  No enrichment overwrites another.


Data-integrity rules
--------------------

1. The NormalizedSecurityEvent stored in ``normalized_event`` is never
   modified.
2. The ``event_id`` is preserved, not regenerated.
3. The ``timestamp`` is preserved.
4. The original provenance is preserved inside ``normalized_event``.
5. Enrichment results are additive only.


Example JSON
------------

Normalized event::

    {
        "event_id": "550e8400-e29b-41d4-a716-446655440000",
        "timestamp": "2025-06-15T12:00:00Z",
        "source_endpoint": {
            "ip": "185.220.101.42"
        },
        "source": "firewall",
        "source_type": "network",
        "event_category": "network",
        "provenance": "observed"
    }

Enrichment result::

    {
        "enrichment_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "enrichment_type": "ip_reputation",
        "source": "threat_intelligence_provider",
        "value": {
            "reputation": "malicious",
            "abuse_confidence": 87,
            "country": "RU"
        },
        "confidence": 0.94,
        "timestamp": "2025-06-15T12:05:00Z"
    }

The enrichment does **not** replace the original IP address.  It adds a
new enrichment result alongside it.


Step 7A scope
-------------

This step defines the **data contract only**.

Provider integrations (VirusTotal, AbuseIPDB, AlienVault OTX, etc.)
are **not** part of this step.  They belong to later implementation
steps.

No provider clients, HTTP requests, API keys, authentication, retry
logic, rate limiting, caching, threat-intelligence lookups, DNS
lookups, WHOIS lookups, geolocation APIs, reputation lookups, AI/LLM
logic, database tables, migrations, API endpoints, Kafka changes, or
frontend code are included.


File locations
--------------

* Schema: ``backend/app/schemas/enriched_event.py``
* Tests: ``backend/tests/unit/test_enriched_event.py``
* Documentation: ``docs/development/enrichment_contract.md``

