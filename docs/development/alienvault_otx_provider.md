AlienVault OTX Threat-Intelligence Provider
=========================================

Purpose
-------

``AlienVaultOTXProvider`` is SentinelAI's AlienVault OTX (Open Threat
eXchange, now hosted by LevelBlue) threat-intelligence provider.  It
implements the existing ``ThreatIntelProvider`` contract and returns the
existing ``ThreatIntelResult`` model.

The provider queries OTX's **API v1** ``general`` indicator endpoint for
IPv4, IPv6, domain, URL, and file-hash indicators, normalises the
response into SentinelAI's provider-neutral result model, and exposes
only a deliberately bounded subset of the raw response.

Architecture::

    ThreatIndicator
        ↓
    AlienVaultOTXProvider.lookup()
        ↓
    AlienVault OTX API v1   (via injectable httpx.Client)
        ↓
    ThreatIntelResult       (provider-neutral)
        ↓
    EnrichmentResult        (mapped by the future Threat Intelligence Agent)

The scope of this provider is limited to *retrieving and structuring
external intelligence*.  It does not detect, correlate, score, or
investigate.  Those duties belong to later SentinelAI components.


Supported indicator types
-------------------------

All four :class:`IndicatorType` values are supported:

* ``IP`` (IPv4 **and** IPv6)
* ``DOMAIN``
* ``URL``
* ``HASH`` (MD5 / SHA-1 / SHA-256, any OTX file-hash family)

Unsupported indicator types can never reach ``lookup()`` because the
enum is fixed, but the provider still guards with
:class:`UnsupportedIndicatorTypeError` (via ``assert_supports``) before
any HTTP call.

IP values are validated with the standard-library ``ipaddress`` module
up-front, so a malformed address raises :class:`InvalidIndicatorError`
**before** any network access.  URL values are fully percent-encoded
(``urllib.parse.quote(..., safe='')``) before being placed in the
request path, so URL delimiters (``:``, ``/``, ``?``, ``&``, ``#``, …)
can never escape their path component.

AlienVault OTX API endpoint
---------------------------

- Endpoint: ``GET https://otx.alienvault.com/api/v1/indicators/{type}/{value}/general``
- Path segments:

  +------------------------+------------------------------------------+
  | Indicator type         | OTX slug                                 |
  +========================+==========================================+
  | ``IPv4``               | ``IPv4``                                 |
  +------------------------+------------------------------------------+
  | ``IPv6``               | ``IPv6``                                 |
  +------------------------+------------------------------------------+
  | ``domain``             | ``domain``                               |
  +------------------------+------------------------------------------+
  | ``URL``                | ``url``                                  |
  +------------------------+------------------------------------------+
  | ``HASH``               | ``file`` (all hash families)             |
  +------------------------+------------------------------------------+

- Request headers:

  * ``X-OTX-API-KEY`` — the OTX API key (required)
  * ``Accept`` — ``application/json``

The base URL and slugs are module constants and are not
user-configurable at runtime.  ``_API_V1_BASE_URL`` is
``https://otx.alienvault.com/api/v1``.


Authentication mechanism
------------------------

OTX API v1 authenticates via the custom ``X-OTX-API-KEY`` request header.
The key is resolved in the following order, consistent with the existing
``VirusTotalProvider`` and ``AbuseIPDBProvider``:

1. Explicit constructor argument: ``AlienVaultOTXProvider(api_key=...)``
2. Application settings: ``Settings.otx_api_key`` (from the
   ``OTX_API_KEY`` environment variable / ``.env`` file)

If no key can be resolved the constructor raises ``ValueError``
immediately (fail-safe)::

    AlienVault OTX API key is required.  Set OTX_API_KEY in your
    environment or pass api_key explicitly.

A missing key is the only supported constructor failure mode — there is
no anonymous mode.


Configuration
-------------

The following settings were added to ``app/core/config.py``:

+-------------------------+----------------+-------------------------------+
| Setting                 | Default        | Environment variable         |
+=========================+================+===============================+
| ``otx_api_key``         | ``""``         | ``OTX_API_KEY``              |
+-------------------------+----------------+-------------------------------+
| ``otx_timeout_seconds`` | ``30.0``       | ``OTX_TIMEOUT_SECONDS``      |
+-------------------------+----------------+-------------------------------+

Both settings are added to ``backend/.env.example`` (the real ``.env``
file is never modified by the codebase or by tests).

Timeout resolution order (mirrors the other providers):

1. Constructor argument: ``timeout_seconds=...``
2. ``Settings.otx_timeout_seconds`` (default ``30.0``)


Request structure
-----------------

The provider performs a synchronous ``httpx.Client.get()`` call with the
following shape:

- URL: ``https://otx.alienvault.com/api/v1/indicators/{slug}/{value}/general``
- Headers: ``{"X-OTX-API-KEY": <API_KEY>, "Accept": "application/json"}``

The ``httpx.Client`` is dependency-injectable so tests can supply an
``httpx.MockTransport`` and guarantee **zero real network traffic**.
When no client is supplied the provider constructs one internally using
the resolved timeout and owns it (``close()`` cleans it up).  An
injected client is never closed by the provider.

Indicator values are percent-encoded with ``quote(value, safe='')``
before interpolation so an indicator value can never alter the request
path structure (path traversal / query-injection / fragment-injection
are impossible).  A literal ``%`` inside a URL value is also encoded
(``%25``), so a value containing ``%2F`` cannot resurface as a path
separator.


Response mapping
----------------

The provider maps the OTX ``general`` response into
``ThreatIntelResult``:

- ``indicator`` — the original :class:`ThreatIndicator` (preserved
  verbatim).
- ``provider`` — ``"AlienVault OTX"``.
- ``found`` — ``True`` when ``pulse_info.count > 0`` (the OTX signal
  that the indicator has associated intelligence), otherwise ``False``.
  A 200 with zero pulses is a valid business outcome, never a crash.
- ``data`` — a deliberately selected, bounded subset of the response
  (see below).  Nothing outside the allow-list is ever copied.
- ``confidence`` — always ``None`` (see *Confidence handling*).
- ``metadata`` — ``{"resource_type": "otx-indicator",
  "otx_api_version": "v1"}``.
- ``timestamp`` — timezone-aware UTC lookup time (from the result
  model).

Indicator-level fields (present only when the API provides them):

+--------------------------+--------------------------------------------+
| Field                    | Meaning                                    |
+==========================+============================================+
| ``indicator``            | Value echoed back by OTX                  |
+--------------------------+--------------------------------------------+
| ``otx_type``             | OTX type string (e.g. ``"IPv4"``)         |
+--------------------------+--------------------------------------------+
| ``reputation``           | Raw OTX reputation integer (evidence only)|
+--------------------------+--------------------------------------------+
| ``validation``           | Normalised validation entries (capped)    |
+--------------------------+--------------------------------------------+
| ``pulse_info``           | Normalised pulse info (count/pulses,      |
|                          | capped)                                   |
+--------------------------+--------------------------------------------+
| ``asn`` / ``city`` /     | IP-only geo/ASN fields                    |
| ``country_code`` /       |                                            |
| ``country_name`` /       |                                            |
| ``latitude`` /           |                                            |
| ``longitude``            |                                            |
+--------------------------+--------------------------------------------+
| ``whois`` / ``alexa``    | Domain-only fields                        |
+--------------------------+--------------------------------------------+

Each pulse is reduced to a scalar allow-list (``id``, ``name``,
``description``, ``created``, ``modified``, ``adversary``, ``TLP``,
``indicator_count``), trimmed list fields (``tags``, ``references``,
``targeted_countries``, ``malware_families``, ``attack_ids``,
``industries``, ``indicator_type_counts``), and the author reduced to
its ``username``.  Everything else in a pulse is dropped.

Pulse info ``references`` are trimmed to ``_MAX_PULSE_REFERENCES`` and
``related`` group lists are trimmed to ``_MAX_RELATED_ENTRIES`` per
category.

All list bounds are module constants (test-overridable):

+--------------------------------+-------+
| Constant                       | Cap   |
+================================+=======+
| ``_MAX_PULSES``                | ``10``|
+--------------------------------+-------+
| ``_MAX_PULSE_LIST_ENTRIES``    | ``20``|
+--------------------------------+-------+
| ``_MAX_PULSE_REFERENCES``      | ``10``|
+--------------------------------+-------+
| ``_MAX_RELATED_ENTRIES``       | ``10``|
+--------------------------------+-------+
| ``_MAX_VALIDATION_ENTRIES``    | ``10``|
+--------------------------------+-------+

These caps guarantee the result payload is bounded regardless of how
large the raw OTX response is.


Found semantics
---------------

- ``found = True`` ⇔ the OTX response contains a ``pulse_info`` object
  whose ``count`` is greater than ``0``.
- A ``pulse_info.count == 0`` (or a missing ``pulse_info``) yields
  ``found = False`` with the parsed data still populated.
- OTX does not use non-200 statuses for "no data"; an indicator without
  pulses is a successful 200 response.  The provider follows the real
  API semantics and returns ``found=False``, never an error.
- A missing ``pulse_info`` or malformed structure is normalised to an
  absent ``pulse_info`` key (never an uncaught ``KeyError``).


Error handling
--------------

Per the established provider philosophy, the provider maps HTTP/API
failures to the existing exception hierarchy:

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
| 5xx    | Transient server failure — bounded retry, then               |
|        | ``ProviderLookupError``.                                     |
+--------+---------------------------------------------------------------+
| other  | ``ProviderLookupError`` (unexpected status).                 |
+--------+---------------------------------------------------------------+

Malformed JSON and non-object bodies are surfaced as
``ProviderLookupError``.  Unsupported indicator types raise
:class:`UnsupportedIndicatorTypeError`; malformed indicator values raise
:class:`InvalidIndicatorError` — both **before** any HTTP request.


Rate limiting
-------------

HTTP 429 from OTX reuses the existing :class:`RateLimitError`.  When a
``Retry-After`` header is present it is captured as
``RateLimitError.retry_after`` (in seconds).  429 responses are **never
retried** — the caller observes the :class:`RateLimitError` immediately
and decides whether/how to throttle.


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

- Default timeout: ``30`` seconds (``Settings.otx_timeout_seconds``).
- A timeout is treated as a transient failure and retried under the same
  bounded-retry policy.
- If all attempts exhaust, a ``ProviderLookupError`` ("request timed
  out") is raised.
- Every request is bounded — there is no unbounded HTTP call.


Confidence handling
-------------------

``ThreatIntelResult.confidence`` is always ``None`` for this provider.

OTX exposes several signals (pulse counts, per-indicator reputation, …)
but none of them is a SentinelAI confidence score:

- SentinelAI's ``confidence`` field is documented as a score in
  ``[0.0, 1.0]``.
- OTX ``reputation`` is a -/0/+ integer describing OTX community flags —
  converting it would require an arbitrary mapping the architecture does
  not define.
- Pulse volume is not a confidence measure (large campaigns, duplicate
  subscriptions, and community noise all distort it).

The raw factual values are preserved as evidence in ``data`` for
downstream components to interpret.  No confidence value is fabricated.
If a future SentinelAI component defines an explicit mapping, it belongs
there — not in the provider.


Why the provider does not make final security decisions
-------------------------------------------------------

This provider is intentionally *non-verdict*.

A high pulse count or non-zero reputation does **not** become
``malicious = true``.  The provider only retrieves and structures
external intelligence — evidence and context.  OTX data is community
noisy by nature, and a single provider's signal is not a security
decision.

Later SentinelAI components own:

- Detection
- Correlation
- Risk scoring
- AI investigation
- Policy decisions

The provider contract is deliberately limited to *lookup → normalise →
return*.


Security considerations
-----------------------

- The API key is **never** hardcoded, printed, logged, stored in test
  fixtures, or committed.
- The key is sent only in the ``X-OTX-API-KEY`` request header; it is
  never placed in the query string or URL path.
- The key is **not** included in:

  * log messages
  * exception messages
  * ``ThreatIntelResult.data``
  * ``ThreatIntelResult.metadata``
  * test output

- The raw HTTP response is never stored or returned — only the
  deliberately selected, bounded fields in *Response mapping* are
  exposed.
- Indicator values are fully percent-encoded in the request path so they
  cannot alter the URL structure (verified by tests for ``:``, ``/``,
  ``?``, ``&``, ``#``, spaces, userinfo, and embedded ``%``).
- Unused or sensitive pulse fields (e.g. full author objects, internal
  flags) never reach the result.
- The ``httpx.Client`` is injectable; tests use ``httpx.MockTransport``
  so no real network traffic ever occurs.
- Tests use a fake key and assert it never leaks into results,
  exceptions, or logs.


Testing strategy
----------------

``backend/tests/unit/test_alienvault_otx.py`` contains **100 tests**
covering:

- Provider basics (name, supported types, contract conformance, bounded
  default timeout)
- API-key resolution, precedence, fail-safe missing-key behaviour, and
  secret safety (key never in logs, exceptions, results, or metadata)
- Request construction: IPv4 / IPv6 / domain / URL / hash endpoints,
  percent-encoding of URL values, double-encoding of embedded ``%``,
  ``X-OTX-API-KEY`` and ``Accept`` headers
- Successful lookups for all four indicator kinds, indicator
  preservation, ``found=True`` semantics
- Response mapping: field allow-list, pulse normalisation, author
  reduction, IP geo fields, domain fields, domain-specific extras
- Indicator-specific parsing (IPv6, URL, hash) and pulse/related
  caps with oversized fixtures
- Found semantics: ``count`` boundaries and missing ``pulse_info``
- Raw-response safety: unselected fields (``secretPulseField``,
  ``avatar_url``, …) never leak into results
- Input validation: malformed IPs / IPv6 / blank / empty values rejected
  before any HTTP call
- HTTP error handling: 400 / 401 / 403 / 404 / 429 (with and without
  ``Retry-After``) / 5xx / unexpected status / malformed JSON / raw-body
  bandit
- Bounded retry behaviour (retry-then-fail, recover-on-retry, no retry
  for 4xx, exact call counts)
- Timeout & transport-error behaviour (retried then fail / recover on
  retry)
- Timeout configuration (constructor override, settings default,
  explicit-over-settings precedence)
- Injected ``httpx.Client`` usage and ownership/cleanup semantics
- Result contract: ``confidence=None``, ``provider`` field, timezone-aware
  timestamp, metadata fixed values, no verdict fields
- Deterministic parsing: same input → same output (timestamp excluded),
  reduced author shape, bounded module constants

All tests run against ``httpx.MockTransport`` — there are zero real
network calls.


File locations
--------------

- Provider: ``backend/app/services/threat_intelligence/alienvault_otx.py``
- Tests: ``backend/tests/unit/test_alienvault_otx.py``
- Documentation: ``docs/development/alienvault_otx_provider.md``
- Configuration: ``backend/app/core/config.py`` + ``backend/.env.example``
- Exports: ``backend/app/services/threat_intelligence/__init__.py``

