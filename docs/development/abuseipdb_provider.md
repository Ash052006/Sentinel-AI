AbuseIPDB Threat-Intelligence Provider
=====================================

Purpose
-------

``AbuseIPDBProvider`` is SentinelAI's AbuseIPDB threat-intelligence
provider.  It implements the existing ``ThreatIntelProvider`` contract
and returns the existing ``ThreatIntelResult`` model.

The provider queries AbuseIPDB's v2 ``check`` endpoint for **IP-address
indicators only**, normalises the response into SentinelAI's
provider-neutral result model, and deliberately exposes only a small,
structured subset of the raw response.

Architecture::

    ThreatIndicator
        ↓
    AbuseIPDBProvider.lookup()
        ↓
    AbuseIPDB API v2  (via injectable httpx.Client)
        ↓
    ThreatIntelResult   (provider-neutral)
        ↓
    EnrichmentResult    (mapped by the future Threat Intelligence Agent)

The scope of this provider is limited to *retrieving and structuring
external intelligence*.  It does not detect, correlate, score, or
investigate.  Those duties belong to later SentinelAI components.


Supported indicator types
-------------------------

Only :class:`IndicatorType.IP` is supported.

If a ``DOMAIN``, ``URL``, or ``HASH`` indicator is passed to
``lookup()`` the provider raises the existing
:class:`UnsupportedIndicatorTypeError` **before** any HTTP request is
made (the guard runs first, so no network activity occurs).


AbuseIPDB API endpoint
----------------------

- Endpoint: ``GET https://api.abuseipdb.com/api/v2/check``
- Query parameters:

  * ``ipAddress`` — the IP address being queried (required)
  * ``maxAgeInDays`` — report review window in days (set to ``90``)

- Request headers:

  * ``Key`` — the AbuseIPDB API key (required)
  * ``Accept`` — ``application/json`` (required for JSON responses)

The endpoint is configured as a module constant (``_BASE_URL``) and is
not user-configurable at runtime.


Authentication mechanism
------------------------

AbuseIPDB API v2 authenticates via a custom ``Key`` request header
(``Key: <API_KEY>``).  The key is resolved in the following order, which
is consistent with the existing ``VirusTotalProvider``:

1. Explicit constructor argument: ``AbuseIPDBProvider(api_key=...)``
2. Application settings: ``Settings.abuseipdb_api_key`` (from the
   ``ABUSEIPDB_API_KEY`` environment variable / ``.env`` file)

If no key can be resolved the constructor raises ``ValueError``
immediately (fail-safe)::

    AbuseIPDB API key is required.

A missing key is the only supported failure mode for the constructor —
there is no anonymous mode.


Configuration
-------------

The following settings were added to ``app/core/config.py``:

+-------------------------+----------------+--------------------------------+
| Setting                 | Default        | Environment variable            |
+=========================+================+================================+
| ``abuseipdb_api_key``   | ``""``         | ``ABUSEIPDB_API_KEY``           |
+-------------------------+----------------+--------------------------------+
| ``abuseipdb_timeout_seconds`` | ``30.0`` | ``ABUSEIPDB_TIMEOUT_SECONDS``   |
+-------------------------+----------------+--------------------------------+

Both settings are added to ``backend/.env.example`` (the real ``.env``
file is never modified by the codebase or by tests).

Timeout resolution order (mirrors VirusTotal):

1. Constructor argument: ``timeout_seconds=...``
2. ``Settings.abuseipdb_timeout_seconds`` (default ``30.0``)


Request structure
-----------------

The provider performs a synchronous ``httpx.Client.get()`` call with the
following shape:

- URL: ``https://api.abuseipdb.com/api/v2/check``
- Params: ``{"ipAddress": <IP>, "maxAgeInDays": 90}``
- Headers: ``{"Key": <API_KEY>, "Accept": "application/json"}``

The ``httpx.Client`` is dependency-injectable so tests can supply an
``httpx.MockTransport`` and guarantee **zero real network traffic**.
When no client is supplied the provider constructs one internally using
the resolved timeout and owns it (``close()`` cleans it up).  An injected
client is never closed by the provider.

Response mapping
----------------

Per the official AbuseIPDB API v2 documentation, the ``check`` endpoint
returns the report fields **directly under a ``data`` object** — there is
no nested ``report`` key.  An IP with no abuse reports is still a
successful HTTP 200 response whose ``totalReports`` is ``0`` (and whose
``reports`` array is empty); that is a valid business outcome reported as
``ThreatIntelResult.found = False``, never a crash.

The provider maps the response into ``ThreatIntelResult``:

- ``indicator`` — the original :class:`ThreatIndicator` (preserved
  verbatim).
- ``provider`` — ``"abuseipdb"``.
- ``found`` — ``True`` when ``totalReports > 0``, otherwise ``False``.
- ``data`` — a deliberately selected, structured subset of the response
  (see below).  Nothing outside the allow-list is ever copied.
- ``confidence`` — always ``None`` (see *Confidence handling*).
- ``metadata`` — ``{"resource_type": "abuseipdb-ip"}``.
- ``timestamp`` — timezone-aware UTC lookup time (from the result model).

Deliberately selected report fields (present only when the API provides
them):

+------------------------+----------------------------------------------+
| Field                  | Meaning                                      |
+========================+==============================================+
| ``ipAddress``          | Queried IP address                           |
+------------------------+----------------------------------------------+
| ``ipVersion``          | IP version (``4`` / ``6``)                   |
+------------------------+----------------------------------------------+
| ``isPublic``           | Whether the address is public                |
+------------------------+----------------------------------------------+
| ``countryCode``        | ISO country code                             |
+------------------------+----------------------------------------------+
| ``usageType``          | Reported usage classification                |
+------------------------+----------------------------------------------+
| ``isp``                | Internet service provider                    |
+------------------------+----------------------------------------------+
| ``domain``             | Associated domain                            |
+------------------------+----------------------------------------------+
| ``hostnames``          | Associated hostnames                         |
+------------------------+----------------------------------------------+
| ``isTor``              | Whether it is a Tor exit node                |
+------------------------+----------------------------------------------+
| ``isCrawler``          | Whether it is flagged as a crawler           |
+------------------------+----------------------------------------------+
| ``totalReports``       | Total number of reports in the window        |
+------------------------+----------------------------------------------+
| ``numDistinctUsers``   | Distinct reporters                           |
+------------------------+----------------------------------------------+
| ``lastReportedAt``     | Timestamp of the most recent report          |
+------------------------+----------------------------------------------+
| ``isWhitelisted``      | Whether the address is whitelisted           |
+------------------------+----------------------------------------------+
| ``abuseConfidenceScore`` | AbuseIPDB's 0–100 confidence metric       |
+------------------------+----------------------------------------------+
| ``reports``            | Bounded list of individual reports           |
+------------------------+----------------------------------------------+

Per-report-item fields (for each entry in ``reports``):

+------------------------+----------------------------------------------+
| Field                  | Meaning                                      |
+========================+==============================================+
| ``reportedAt``         | When the report was submitted                |
+------------------------+----------------------------------------------+
| ``comment``            | Reporter comment                             |
+------------------------+----------------------------------------------+
| ``categories``         | Abuse category IDs                           |
+------------------------+----------------------------------------------+
| ``reporterId``         | Reporter ID (``0`` = anonymous)              |
+------------------------+----------------------------------------------+
| ``reporterCountryCode``| Reporter country code                        |
+------------------------+----------------------------------------------+
| ``reporterCountryName``| Reporter country name                        |
+------------------------+----------------------------------------------+

The ``reports`` array is trimmed to at most 10 entries so the result
payload stays bounded.  Only the fields above are extracted — any other
field in the raw response (e.g. ``countryName``, free-form or nested
objects) is intentionally dropped.  The raw response is never stored,
logged, or returned.

Error handling
--------------

HTTP status codes are mapped as follows (consistent with the VirusTotal
provider philosophy):

+--------+---------------------------------------------------------------+
| Status | Behaviour                                                    |
+========+===============================================================+
| 200    | Parse and normalise the JSON body.                           |
+--------+---------------------------------------------------------------+
| 400    | ``ProviderLookupError`` (input/usage error).  Not retried.   |
+--------+---------------------------------------------------------------+
| 401    | ``ProviderLookupError`` (authentication error).  Not retried.|
+--------+---------------------------------------------------------------+
| 403    | ``ProviderLookupError`` (permission error).  Not retried.    |
+--------+---------------------------------------------------------------+
| 404    | ``ProviderLookupError`` (resource unavailable).  Not retried.|
+--------+---------------------------------------------------------------+
| 429    | ``RateLimitError`` — see *Rate limiting*.                    |
+--------+---------------------------------------------------------------+
| 5xx    | Transient server failure — bounded retry, then                |
|        | ``ProviderLookupError``.                                     |
+--------+---------------------------------------------------------------+
| other  | ``ProviderLookupError`` (unexpected status).                 |
+--------+---------------------------------------------------------------+

Malformed JSON, a non-object body, or a missing ``data`` object are also
surfaced as ``ProviderLookupError``.  An ``errors`` block present in an
HTTP 200 body is detected defensively and reported as
``ProviderLookupError``.

The AbuseIPDB ``check`` endpoint does **not** use HTTP 404 / “no data” to
indicate an IP without reports — it returns 200 with ``totalReports: 0``.
The provider follows the real API semantics and returns ``found=False``
for that case instead of treating it as a crash.

Rate limiting
-------------

HTTP 429 from AbuseIPDB reuses the existing
:class:`RateLimitError`.  When a ``Retry-After`` header is present it is
captured as ``RateLimitError.retry_after`` (in seconds).  429 responses
are **never retried** — the caller observes the :class:`RateLimitError`
immediately and decides whether/how to throttle.


Retry behavior
--------------

Retries are strictly bounded and only target *transient* failures:

- HTTP 5xx server errors (500, 502, 503, …)
- Transport-level errors (connection refused, DNS failure)
- Timeouts (``httpx.TimeoutException``)

Configuration constants (module-level, test-overridable):

- ``_MAX_RETRIES = 2`` — maximum retry **attempts** after the initial
  request (so at most 3 HTTP calls total).
- ``_RETRY_BASE_DELAY = 1.0`` seconds — linear backoff
  (``delay = base * attempt``).

Client errors (400, 401, 403, 404, 429) are never retried.  After the
final retry the provider raises ``ProviderLookupError`` — the internal
retryable marker class never escapes to callers.


Timeout behavior
----------------

- Default timeout: ``30`` seconds (``Settings.abuseipdb_timeout_seconds``).
- A timeout is treated as a transient failure and retried under the same
  bounded-retry policy.
- If all attempts exhaust, a ``ProviderLookupError`` (“request timed out”)
  is raised.
- Every request is bounded — there is no unbounded HTTP call.


Security considerations
-----------------------

- The API key is **never** hardcoded, printed, logged, stored in test
  fixtures, or committed.
- The key is sent only in the ``Key`` request header; it is never placed
  in the query string.
- The key is **not** included in:
  * log messages
  * exception messages
  * ``ThreatIntelResult.data``
  * ``ThreatIntelResult.metadata``
  * test output
- The raw HTTP response is never stored or returned — only the
  deliberately selected fields in *Response mapping* are exposed.
- The ``httpx.Client`` is injectable; tests use ``httpx.MockTransport``
  so no real network traffic ever occurs.
- Tests use a fake key (``test-abuseipdb-key``) and assert it never leaks
  into results, exceptions, or logs.


Confidence handling
-------------------

``ThreatIntelResult.confidence`` is always ``None`` for this provider.

AbuseIPDB's ``abuseConfidenceScore`` is a 0–100 metric describing abuse
reports against an address within the query window.  It is **not** a
SentinelAI confidence score:

- SentinelAI's ``confidence`` field is documented as a score in
  ``[0.0, 1.0]``.
- Converting ``abuseConfidenceScore`` (0–100) into that field would
  require an arbitrary mapping that the SentinelAI architecture does not
  define.
- The raw value is preserved as evidence in ``data["abuseConfidenceScore"]``
  for downstream components to interpret.

No confidence value is fabricated.  If a future SentinelAI component
defines an explicit mapping, it belongs there — not in the provider.


Why the provider does not make final security decisions
-------------------------------------------------------

This provider is intentionally *non-verdict*.

A high ``abuseConfidenceScore`` does **not** become ``malicious = true``.
The provider only retrieves and structures external intelligence —
evidence and context.  AbuseIPDB data is noisy by nature (shared hosting
IPs, dynamic NAT ranges), and a single provider's signal is not a
security decision.

Later SentinelAI components own:

- Detection
- Correlation
- Risk scoring
- AI investigation
- Policy decisions

The provider contract is deliberately limited to *lookup → normalise →
return*.


Testing strategy
----------------

``backend/tests/unit/test_abuseipdb.py`` covers:

- Provider basics (name, supported types, contract conformance)
- API-key resolution, precedence, and fail-safe missing-key behaviour
- Request construction: endpoint, query parameters (``ipAddress``,
  ``maxAgeInDays=90``), ``Key`` and ``Accept`` headers
- Successful IP lookups (IPv4 and IPv6), indicator preservation
- Field mapping, missing-optional-field handling, empty-reports handling
- Unsupported DOMAIN / URL / HASH indicators (rejected before any HTTP)
- HTTP error handling: 400 / 401 / 403 / 429 (with and without
  ``Retry-After``) / 5xx / unexpected status / malformed JSON
- Bounded retry behaviour (retry-then-fail, recover-on-retry, no retry
  for 4xx, max call count)
- Timeout & transport-error behaviour
- Timeout configuration (constructor override and settings default)
- Injected ``httpx.Client`` usage and ownership/cleanup semantics
- Result contract (JSON-compatible data, ``confidence=None``,
  timezone-aware timestamp, secret-free metadata)
- Secret safety: API key never appears in results, exceptions, or logs
- Raw-response safety: unselected fields never leak into result data
- No-network safety via ``httpx.MockTransport``
- Deterministic parsing (identical/reordered responses yield equivalent
  results)

All tests run against ``httpx.MockTransport`` — there are zero real
network calls.


File locations
--------------

- Provider: ``backend/app/services/threat_intelligence/abuseipdb.py``
- Tests: ``backend/tests/unit/test_abuseipdb.py``
- Documentation: ``docs/development/abuseipdb_provider.md``
- Configuration: ``backend/app/core/config.py`` + ``backend/.env.example``
- Exports: ``backend/app/services/threat_intelligence/__init__.py``