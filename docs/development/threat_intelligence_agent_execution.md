Threat Intelligence Agent Execution (Step 8B)
==============================================

Overview
--------

Step 8B implements the **execution layer** for the Threat Intelligence
Agent defined by the Step 8A contract:

* extracts structurally identifiable indicators from an
  ``EnrichedSecurityEvent``,
* deduplicates them deterministically via ``canonical_key``,
* selects compatible providers through the existing
  ``ProviderRegistry`` (never hardcoding provider lists),
* executes provider lookups while isolating every provider failure,
* converts successful ``ThreatIntelResult`` objects into
  ``EnrichmentResult`` objects via the pure Step 8A helper
  ``threat_intel_result_to_enrichment``, and
* returns a complete ``ThreatIntelligenceAnalysis`` with accurate
  execution metadata.

The agent is **stateless** and **deterministic**: the same input event
and registry always produce the same shape of analysis.  It performs no
network calls itself — providers are responsible for their own
credentials and HTTP access.

Architecture
------------

::

    EnrichedSecurityEvent
        |
        v
    ThreatIntelligenceAgent.analyze()
        |
        +-- Indicator extraction        (Step 8A ExtractedIndicator)
        |
        +-- Deterministic deduplication (canonical_key)
        |
        +-- ProviderRegistry.find_providers_for(indicator_type)
        |
        +-- ThreatIntelProvider.lookup(ThreatIndicator)
        |
        +-- ThreatIntelResult  /  ProviderFailure
        |
        +-- threat_intel_result_to_enrichment()
        |
        v
    ThreatIntelligenceAnalysis

Indicator Extraction
--------------------

Only **explicitly present, structurally identifiable** fields are read.
No heuristic NLP, no scanning of arbitrary strings, and no fabrication
of missing values.

Supported source locations:

* ``source_endpoint.ip`` → ``ip`` (context ``source_endpoint``)
* ``destination_endpoint.ip`` → ``ip`` (context ``destination_endpoint``)
* ``normalized_data`` keys that explicitly denote a value's type:

  * ``ip``-family keys (``ip``, ``ip_address``, ``source_ip``,
    ``src_ip``, ``destination_ip``, ``dst_ip``, ``remote_ip``,
    ``client_ip``) → ``ip``
  * domain-family keys (``domain``, ``domain_name``, ``host``,
    ``fqdn``) → ``domain``
  * URL-family keys (``url``, ``uri``, ``request_uri``, ``href``,
    ``url_full``) → ``url``
  * hash-family keys (``hash``, ``file_hash``, ``md5``, ``sha1``,
    ``sha256``, ``sha512``) → ``hash``

* ``file.hash`` → ``hash`` (context ``file``)

``normalized_data`` keys are iterated in **sorted order** so extraction
order is fully deterministic.


Deduplication
-------------

Deduplication reuses the Step 8A ``canonical_key``
(``"{type}:{normalized_value}"``):

* the same indicator value appearing in several fields produces **one**
  provider lookup,
* the **source context of every occurrence** is preserved in the
  individual ``ExtractedIndicator`` records kept on the analysis,
* different indicator types sharing a literal value are **never**
  collapsed (``ip:185.10.10.10`` ≠ ``domain:185.10.10.10``).

Provider Selection
------------------

Providers are obtained via ``ProviderRegistry.find_providers_for()``.
The agent contains **no** hardcoded provider list, so any provider
registered with the registry is automatically eligible.  Only providers
that support an indicator's type are invoked.

Lookup Execution & Failure Isolation
------------------------------------

For each unique indicator:

1. compatible providers are resolved from the registry,
2. each compatible provider is invoked with a validated
   ``ThreatIndicator``,
3. successful lookups become ``ProviderAssociation`` records pointing
   at the extracted indicator, provider name, and ``ThreatIntelResult``,
4. every failure is converted into a secret-safe ``ProviderFailure``
   and the loop continues — one failure never aborts the analysis.

Exceptions are classified with the existing provider hierarchy:

* ``RateLimitError`` → ``error_type="rate_limit"``, ``retryable=True``
* ``ProviderLookupError`` with timeout/server-error message →
  ``error_type="timeout"``, ``retryable=True``
* ``ProviderLookupError`` otherwise → ``error_type="provider_error"``,
  ``retryable=False``
* ``InvalidIndicatorError`` → ``error_type="invalid_indicator"``,
  ``retryable=False``
* other ``ThreatIntelError`` → ``error_type="provider_error"``,
  ``retryable=False``
* unexpected exceptions → ``error_type="unexpected"``,
  ``retryable=False``

Failures never contain API keys, authorization headers, or raw HTTP
responses.

Enrichment Conversion
---------------------

Every successful ``ThreatIntelResult`` is passed through the pure Step
8A helper ``threat_intel_result_to_enrichment``, producing an
``EnrichmentResult`` with:

* ``enrichment_type = "threat_intelligence"``,
* ``source`` = the provider name,
* structured provider evidence as the ``value``,
* ``Provenance.ENRICHED`` semantics (never observed/reconstructed).

No verdict or risk score is computed.  Provider reputation data (e.g.
VirusTotal votes, AbuseIPDB abuse confidence, OTX pulses) is recorded as
evidence only.


Metadata
--------

``ThreatIntelMetadata`` counts reflect actual execution:

* ``providers_attempted`` — distinct providers selected for lookups,
* ``providers_succeeded`` — distinct providers with ≥ 1 successful lookup,
* ``providers_failed`` — distinct providers with ≥ 1 failure,
* ``indicators_extracted`` — unique indicators (by canonical key),
* ``lookups_attempted`` / ``lookups_succeeded`` / ``lookups_failed`` —
  per-invocation counters.

Input Immutability
------------------

The agent never mutates the input event or its nested
``NormalizedSecurityEvent``.  All analysis data is new, additive
objects.

File Locations
--------------

* Agent: ``backend/app/agents/threat_intelligence.py``
* Tests: ``backend/tests/unit/test_threat_intelligence_agent.py``
* This document: ``docs/development/threat_intelligence_agent_execution.md``

Testing
-------

``backend/tests/unit/test_threat_intelligence_agent.py`` exercises the
agent with deterministic fake providers registered in a test-local
``ProviderRegistry`` — **zero** real network calls.  It covers the
required 32 scenarios: acceptance, empty analysis, per-source
extraction, deduplication, registry-based selection, compatible-only
providers, multi-provider execution, failure isolation, retryability,
enrichment conversion, traceability, metadata counters, secret-safety,
input immutability, and the absence of verdicts/risk scores.

Scope Boundaries
----------------

Step 8B implements orchestration only.  It performs **no inherent**
persistence, detection, correlation, risk scoring, MITRE mapping, or LLM
investigation, and it adds **no** concurrency — the existing provider
interfaces are synchronous and the loop is intentionally deterministic.
Persistence, when desired, is an **optional injected sink** (Step 8C-C):
`analyze(event, persistence=...)` hands the completed analysis to the
existing Step 8C `ThreatIntelligencePersistenceService`, which owns the
transaction.  Without that argument the agent performs no persistence.