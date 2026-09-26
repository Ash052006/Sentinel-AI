# VirusTotal Threat Intelligence Provider

## 1. Purpose

This document describes SentinelAI's first concrete threat-intelligence
provider: the **VirusTotalProvider**.  It implements the provider-agnostic
`ThreatIntelProvider` abstraction established in **Step 7C** and performs
real lookups against the **official VirusTotal API v3**.

> **Important:** VirusTotal is **one source of threat intelligence**.
> Its results are **evidence/context, not an automatic final verdict**
> from SentinelAI.  SentinelAI's detection, correlation, and response
> pipeline decides how to act on this evidence.

## 2. VirusTotal Provider Role

The provider sits in the threat-intelligence layer of the enrichment
pipeline:

```
ThreatIndicator
        ↓
VirusTotalProvider.lookup()
        ↓
VirusTotal API v3  (bounded timeout, injectable httpx.Client)
        ↓
ThreatIntelResult  (provider-neutral)
        ↓
EnrichmentResult  (mapped by the future Threat Intelligence Agent)
        ↓
EnrichedSecurityEvent  (provenance = ENRICHED)
```

The provider converts VirusTotal's JSON:API-style response into the
provider-neutral `ThreatIntelResult` contract so that downstream agents
can process all providers uniformly.

## 3. Supported Indicator Types

| IndicatorType | VirusTotal endpoint | Notes |
|---------------|---------------------|-------|
| `ip`          | `/api/v3/ip_addresses/{ip}` | IPv4/IPv6 string used directly |
| `domain`      | `/api/v3/domains/{domain}` | Domain used directly |
| `hash`        | `/api/v3/files/{hash}` | MD5, SHA-1, or SHA-256 accepted |
| `url`         | `/api/v3/urls/{url_id}` | URL encoded as base64url, no padding |

The provider declares all four types via `supported_indicator_types`.

## 4. API Architecture

* Base URL: `https://www.virustotal.com/api/v3`
* Authentication: `x-apikey` request header
* All lookups are synchronous HTTP GET requests.
* The HTTP client (`httpx.Client`) is **injectable** so tests can use
  `httpx.MockTransport` without any network access.
* No SDK is used — direct REST integration with the official API.

### URL identifier computation

VirusTotal represents URLs as base64url-encoded identifiers with the
trailing `=` padding removed:

```python
url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode().rstrip("=")
```

Example: `https://example.com` → `aHR0cHM6Ly9leGFtcGxlLmNvbQ`

## 5. Configuration

Configuration is added to the existing `app/core/config.py` settings
(`pydantic-settings`, read from `.env`):

| Setting | Description | Default |
|---------|-------------|---------|
| `VIRUSTOTAL_API_KEY` | The VirusTotal API key | empty string |
| `VIRUSTOTAL_TIMEOUT_SECONDS` | Per-request timeout in seconds | `30.0` |

Example `.env`:

```
VIRUSTOTAL_API_KEY=
VIRUSTOTAL_TIMEOUT_SECONDS=30.0
```

## 6. API-Key Security

* The key **never appears in source code** — it is injected from
  configuration/environment.
* If the provider is instantiated without a key it raises a clear
  `ValueError` immediately (fail-safe).
* The key is **never logged**.
* The key is **never included in exception messages**.
* The key is **never included in `ThreatIntelResult` data or metadata**.
* The key is **never included in API responses**.
* The provider reads it from `Settings.virustotal_api_key` or from the
  explicit constructor argument `api_key=`.

## 7. Timeout Behavior

* Every request has a bounded timeout (`VIRUSTOTAL_TIMEOUT_SECONDS`).
* **Infinite timeouts are not permitted.**
* On `httpx.TimeoutException` the request is retried a bounded number of
  times (2 retries) with linear backoff, then raises
  `ProviderLookupError("request timed out")`.

## 8. Error Handling

| Condition | Behaviour |
|-----------|-----------|
| HTTP 200 | Parse and return result |
| HTTP 404 | `found = False` (valid "not found" result) |
| HTTP 400 | `ProviderLookupError` (bad request) |
| HTTP 401 | `ProviderLookupError` (unauthorized — check key) |
| HTTP 403 | `ProviderLookupError` (forbidden) |
| HTTP 429 | `RateLimitError` (see §9) |
| HTTP 5xx | Retried (bounded), then `ProviderLookupError` |
| Timeout | `ProviderLookupError` (after bounded retries) |
| Connection error | `ProviderLookupError` (after bounded retries) |
| Malformed JSON | `ProviderLookupError` |
| Unexpected structure | `ProviderLookupError` |

Errors never include the API key, Authorization header, secrets, or
sensitive request data.

## 9. Rate-Limit Handling

* HTTP 429 raises `RateLimitError` (added to the exception hierarchy in
  Step 7D, inheriting `ThreatIntelError`).
* It carries the `Retry-After` header value when present.
* **429 is never retried** — the provider does not hammer the API.
* Callers decide whether/how to back off using the `retry_after`
  attribute.
## 10. Response Normalization

VirusTotal response → provider-specific parser → `ThreatIntelResult`.

Only safe, structured fields are extracted:

* `last_analysis_stats`: `harmless`, `malicious`, `suspicious`,
  `undetected`, `timeout` counts.
* `reputation`: the integer reputation score when present.
* `categories`: the engine-category mapping when present.
* `last_analysis_date`: the Unix timestamp of the last analysis.
* `resource_type`: the VirusTotal resource type (`ip_addresses`,
  `domain`, `file`, `urls`).
* IP-specific: `asn`, `as_owner`, `country`, `network`, `whois`.
* Domain-specific: `registrar`, `whois`, `popularity_ranks`.
* File-specific: `md5`, `sha1`, `sha256`, `type_description`, `type_tag`,
  `popular_threat_classification`, `names` (trimmed to 10 entries).
* URL-specific: `url`, `title`, `final_url`.

The raw response is never dumped into the result.

## 11. Found vs Not-Found

* **Found** — VirusTotal returned a `data` object → `found = True`.
* **Not found** — HTTP 404 → `found = False`, empty `data`, and a
  minimal metadata payload.  This is **not** a provider failure.
* **API failure** — 401/403/429/5xx/transport errors raise exceptions.

`NOT FOUND` is deliberately never confused with `API FAILURE`.

## 12. Provenance

VirusTotal data is external enrichment:

```
Provenance.ENRICHED
```

Never `Provenance.OBSERVED`, never `Provenance.RECONSTRUCTED`.

The original `NormalizedSecurityEvent` is never mutated — only additive
`EnrichmentResult` instances are attached.

## 13. EnrichmentResult Mapping

When the future Threat Intelligence Agent maps a result into the existing
schema it uses a generic enrichment type:

```python
EnrichmentResult(
    enrichment_type="threat_intelligence",   # generic, not provider-specific
    source="VirusTotal",                      # the provider is the source
    value={
        "indicator_type": result.indicator.indicator_type.value,
        "indicator": result.indicator.value,
        "found": result.found,
        **result.data,
    },
    confidence=None,
    timestamp=result.timestamp,
)
```

`confidence` is `None` because VirusTotal does not provide a metric that
maps cleanly to SentinelAI's `[0, 1]` confidence model — detection counts
are **not** converted into invented confidence scores.

## 14. Testing Strategy

All tests in `tests/unit/test_virustotal.py` use an injected
`httpx.Client` backed by `httpx.MockTransport`.  **No test makes a real
network request.**

Coverage:
* Provider basics (name, supported types, interface compliance).
* API-key loading, fail-safe on missing key, secret absence from logs/
  exceptions/results.
* IP / Domain / Hash / URL lookups (success, not-found, malformed
  response).
* URL base64url resource handling.
* HTTP errors: 400, 401, 403, 404, 429, 500, 502, 503, timeout,
  connection error, malformed JSON, unexpected status.
* Rate-limit (429 not retried).
* Bounded retry of transient 5xx/network errors.
* Response parsing (malicious/suspicious/harmless/undetected,
  reputation, categories, missing optional fields).
* Result contract (indicator preserved, provider name, found, JSON data,
  confidence `None`, timezone-aware timestamp).
* Provenance (ENRICHED, never RECONSTRUCTED).
* Input validation (unsupported type, empty/blank values, non-indicator).
* No-network safety (mock transport only).
* Deterministic parsing.
* Secret safety (key absence from exceptions, logs, metadata).
* Integration test: `ThreatIndicator → VirusTotalProvider → mock VT
  response → ThreatIntelResult → EnrichmentResult →
  EnrichedSecurityEvent`.

## 15. Security Considerations

* API key is configuration-only — never hardcoded, committed, or logged.
* Logs record provider name, indicator type, success/failure, HTTP
  status, and duration only.  The raw indicator value and headers are
  not logged.
* Exception messages never carry credentials.
* Result metadata contains only safe context (`resource_type`, `vt_id`).
* The HTTP client is per-provider and injectable — no hidden global
  clients.
* No web scraping, no unofficial endpoints, no third-party proxies.

## 16. Future Provider Comparison

| Aspect | VirusTotal (7D) | AbuseIPDB (future) | AlienVault OTX (future) |
|--------|-----------------|--------------------|--------------------------|
| Types | ip, domain, url, hash | ip | domain, url, hash (ip) |
| Auth | `x-apikey` header | `key` query param | `X-OTX-API-KEY` header |
| Rate limits | quota based | request/min | quota based |
| Forte | multi-engine detections | abuse reports | threat pulses/OTX |

All providers share the `ThreatIntelProvider` interface and produce
`ThreatIntelResult`, so the pipeline treats them uniformly.  VirusTotal
results remain **context/evidence**, never an automatic verdict.