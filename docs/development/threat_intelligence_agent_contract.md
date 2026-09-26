Threat Intelligence Agent Contract (Step 8A)
=============================================

Overview
--------

The **Threat Intelligence Agent** is the future orchestration layer that
will coordinate external threat-intelligence providers, extract
indicators from security events, and structure their evidence into
enrichment results.

This document defines the **contract** for that agent (Step 8A).  It is
**contract only** - it introduces the data models that describe the
agent's inputs, intermediate representations, and outputs, but it does
**not** implement the orchestration itself.

Purpose
-------

The contract provides a stable, typed, immutable, and testable
specification of *what* a threat-intelligence analysis looks like, so
that:

1. The eventual agent can be implemented against a fixed shape.
2. Downstream consumers (detection, correlation, investigation) can rely
   on a consistent result structure.
3. Traceability and provenance are preserved from the original event
   through to each provider finding.
4. Provider failures are isolated and never crash the whole pipeline.

Responsibilities
----------------

The Threat Intelligence Agent (and its contract) is an **orchestration**
layer.  Its contract:

* Receives an ``EnrichedSecurityEvent`` (or the event identity/holdings
  needed for analysis).
* Extracts structurally identifiable indicators from the event.
* Deduplicates indicators deterministically.
* Selects providers through the existing
  :class:`ProviderRegistry` - never by hardcoding providers.
* Coordinates provider lookups.
* Isolates provider failures.
* Aggregates results and converted enrichments.
* Preserves the ``event → indicator → provider → result`` traceability.

Non-responsibilities
--------------------

The contract and the agent it describes are **not**:

* a provider,
* a detection engine,
* a risk scorer,
* an AI investigator, or
* a verdict engine.

The agent never decides "malicious", "benign", "compromised", or
"attack" unless a provider explicitly supplies such information.  The
contract therefore exposes **no** final risk score, **no** aggregated
confidence, and **no** verdict.

Input Contract
--------------

The primary input is an ``EnrichedSecurityEvent``.  The contract
preserves:

* ``event_id``
* ``timestamp``
* ``normalized_event``
* existing enrichments
* provenance

The agent **never mutates** the input event.  All analysis data is
additive.  Indicator values are only ever read from explicitly present,
structurally identifiable fields.

Indicator Extraction
--------------------

An extracted indicator is represented by :class:`ExtractedIndicator`:

.. code-block:: python

    {
        "indicator": "185.10.10.10",
        "indicator_type": "ip",
        "source_field": "source_endpoint.ip",
        "source_context": "source_endpoint",
    }

Fields:

* ``indicator`` - the raw indicator value.
* ``indicator_type`` - ``ip``, ``domain``, ``url``, or ``hash``
  (reusing :class:`IndicatorType`).
* ``source_field`` - dotted path to the field the value came from.
* ``source_context`` - coarse context of origin.

Supported source locations:

* **IP** - ``source_endpoint.ip``, ``destination_endpoint.ip``, and
  actor/source-related IP fields.
* **DOMAIN** - domain values present in ``normalized_data`` and
  relevant endpoint/application fields where explicitly available.
* **URL** - URL values present in ``normalized_data``.
* **HASH** - values from ``file.hash`` and ``normalized_data`` where
  explicitly structured as a hash.

No heuristic NLP extraction is performed, and no indicators are
invented.


Deduplication
-------------

Deduplication is **deterministic** via a canonical key on
:class:`ExtractedIndicator` (``canonical_key``):

.. code-block:: python

    canonical_key = "{indicator_type}:{normalized_value}"

Normalization is intentionally conservative and never changes indicator
meaning:

* **Domains** are lower-cased (``Example.COM`` ≡ ``example.com``).
* **Hashes** are lower-cased (hex hashes are case-insensitive).
* **IPs** are kept exactly as extracted.
* **URLs** are **not** normalized by default - URL normalization is only
  performed when explicitly requested so that the indicator meaning is
  never altered.

Rules:

* Same indicator + same type → deduplicates.
* Same indicator appearing in multiple fields → deduplicates (the
  ``canonical_key`` is identical), while the source context of each
  occurrence is preserved in the individual ``ExtractedIndicator``
  records.
* Different indicator types with the same literal value → do **not**
  deduplicate (``ip:185.10.10.10`` ≠ ``domain:185.10.10.10``).

This keeps source provenance while avoiding duplicate provider lookups.


Provider Selection
------------------

Provider selection must flow through the existing
:class:`ProviderRegistry`.  The agent does **not** hardcode:

.. code-block:: python

    if indicator_type is IndicatorType.IP:
        VirusTotal(); AbuseIPDB(); OTX()

Instead it uses ``ProviderRegistry.find_providers_for(indicator_type)``,
kept fully provider-agnostic:

.. code-block:: text

    IndicatorType.IP    -> Registry -> VirusTotal, AbuseIPDB, AlienVault OTX
    IndicatorType.DOMAIN-> Registry -> VirusTotal, AlienVault OTX
    IndicatorType.HASH  -> Registry -> VirusTotal, AlienVault OTX
    IndicatorType.URL   -> Registry -> providers supporting URL

New providers can be added to the registry without changing the agent.


Result Contract
---------------

The top-level result is :class:`ThreatIntelligenceAnalysis`:

.. code-block:: text

    ThreatIntelligenceAnalysis
    ├── event_id        (uuid.UUID, preserved, never regenerated)
    ├── indicators      (list[ExtractedIndicator])
    ├── results         (list[ProviderAssociation])
    ├── failures        (list[ProviderFailure])
    ├── enrichments     (list[EnrichmentResult])
    └── metadata        (ThreatIntelMetadata)

It deliberately defines **no** final risk score, **no** malicious/benign
verdict, and **no** aggregated confidence.  These are explicitly out of
scope for the contract.


Provider Result Association
---------------------------

Every provider result stays associated with its indicator, indicator
type, and provider via :class:`ProviderAssociation`:

.. code-block:: python

    ProviderAssociation(
        indicator=ExtractedIndicator(...),
        provider="virustotal",
        result=ThreatIntelResult(...),
    )

This preserves the mandatory traceability chain:

.. code-block:: text

    Event
      ↓
    Indicator
      ↓
    Provider
      ↓
    ThreatIntelResult

The relationship is never lost, so future explainability can walk from a
finding back to its origin.


Failure Isolation
-----------------

Provider failures are isolated.  A timeout from AbuseIPDB must never fail
the whole agent.  Failures are captured in :class:`ProviderFailure`:

.. code-block:: text

    ProviderFailure
    ├── provider        ("abuseipdb")
    ├── indicator       ("185.10.10.10")
    ├── indicator_type  (IndicatorType.IP)
    ├── error_type      ("timeout" | "rate_limit" | "http_error" | ...)
    ├── message         (human-readable, secret-safe)
    └── retryable       (bool)

Example:

.. code-block:: text

    results:
        VirusTotal result
        OTX result
    failures:
        AbuseIPDB timeout

:class:`ProviderFailure` deliberately contains **no** API keys,
authorization headers, or raw HTTP responses.


Provenance
----------

Threat intelligence is **external enrichment**.  The resulting
enrichment must use :data:`Provenance.ENRICHED`.  It is **never**
labelled ``OBSERVED`` or ``RECONSTRUCTED`` unless a future, explicitly
defined reconstruction process is involved.

The conversion helper
(:func:`threat_intel_result_to_enrichment`) produces
:class:`EnrichmentResult` objects intended to be attached with
``ENRICHED`` event-level provenance, and it never downgrades the
provenance of the external content.


Enrichment Conversion
---------------------

The contract defines how a :class:`ThreatIntelResult` is converted into
an :class:`EnrichmentResult` (and, in a later step, into an
:class:`EnrichedSecurityEvent`):

.. code-block:: text

    ThreatIntelResult
        ↓  threat_intel_result_to_enrichment
    EnrichmentResult
        ↓  (future orchestration)
    EnrichedSecurityEvent

The recommended enrichment type is ``"threat_intelligence"`` and the
``source`` identifies the provider:

.. code-block:: python

    enrichment_type = "threat_intelligence"
    source          = "virustotal"

The ``value`` carries structured, non-destructive provider evidence.
It **never** contains the API key or a raw HTTP response.  The original
normalized event remains unchanged.


Metadata
--------

Execution metadata is captured in :class:`ThreatIntelMetadata` for future
observability:

* ``providers_attempted``
* ``providers_succeeded``
* ``providers_failed``
* ``indicators_extracted``
* ``lookups_attempted``
* ``lookups_succeeded``
* ``lookups_failed``

It never contains secrets and never contains raw HTTP responses.


Traceability
------------

The contract preserves the full cause chain:

.. code-block:: text

    EnrichedSecurityEvent.event_id
        → ExtractedIndicator
            → ProviderAssociation
                → ThreatIntelResult

Every :class:`ProviderAssociation` keeps its extracted indicator and
provider, and every :class:`ThreatIntelResult` references back to the
indicator value and type.  This is mandatory for future explainability.


Testing Strategy
----------------

Contract tests live in
``backend/tests/unit/test_threat_intelligence_agent_contract.py`` and
contain **zero** real network calls.  Providers and the registry are
replaced with fakes/stubs.  The tests verify the contract, not the
providers.

The suite covers:

1. ExtractedIndicator validation
2. Valid IP indicator
3. Valid domain indicator
4. Valid URL indicator
5. Valid hash indicator
6. Invalid/empty indicator
7. Source field preservation
8. Indicator type preservation
9. Deterministic deduplication
10. Same indicator from multiple fields
11. Domain case handling
12. Hash handling
13. ThreatIntelligenceAnalysis validation
14. event_id preservation
15. Result association
16. ProviderFailure validation
17. Failure isolation representation
18. Enrichment representation
19. ENRICHED provenance
20. No final verdict field
21. No risk score field
22. Metadata validation
23. Input immutability expectations
24. Serialization/deserialization
25. Empty indicator list
26. Empty results
27. Provider failure-only result
28. Mixed success/failure representation
29. Traceability across event → indicator → provider → result
30. Secret-safety expectations


File Locations
--------------

* Contract models: ``backend/app/schemas/threat_intelligence_agent.py``
* Contract tests: ``backend/tests/unit/test_threat_intelligence_agent_contract.py``
* This document: ``docs/development/threat_intelligence_agent_contract.md``

Existing dependencies the contract reuses:

* :class:`~app.schemas.enriched_event.EnrichmentResult`
* :class:`~app.schemas.security_event.Provenance`
* :class:`~app.services.threat_intelligence.types.IndicatorType`
* :class:`~app.services.threat_intelligence.base.ThreatIntelResult`


Scope Boundaries
----------------

This step is **Step 8A only** - the contract.  The actual
Threat Intelligence Agent orchestration (indicator extraction, provider
selection, query dispatch, aggregation) is **not** implemented here and
will be a separate step.  No providers or the ``ProviderRegistry``
behaviour are modified, and application startup is unchanged.



