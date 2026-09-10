# Threat Intelligence Provider Contract & Infrastructure

## 1. Purpose

This document describes the provider-agnostic abstraction layer that
future threat-intelligence integrations (VirusTotal, AbuseIPDB,
AlienVault OTX, etc.) will implement.  The contract was established in
**Step 7C** as infrastructure only — no actual API calls, HTTP clients,
or provider implementations are included.

## 2. Why Provider Abstraction Exists

SentinelAI's enrichment pipeline needs to query external threat
intelligence sources to enrich normalised security events with
reputation data, detection counts, and attribution context.  Different
organisations use different providers, and some environments may not
have access to all providers.  A provider-agnostic abstraction:

* Keeps SentinelAI's core logic decoupled from any specific API.
* Allows providers to be added, removed, or replaced without modifying
  the enrichment pipeline.
* Enables capability-based routing: the future Threat Intelligence
  Agent selects providers based on which indicator types they support.
* Supports testing with fake/mock providers.

## 3. Architecture

```
                    Threat Intelligence Layer
                              |
                              v
                    ThreatIntelProvider
                       (abstract interface)
                       /       |       \\
                      /        |        \\
             VirusTotal   AbuseIPDB   AlienVault OTX
               FUTURE        FUTURE       FUTURE
```

> **Step 7C provides the abstract interface only.  The three providers
> shown above are NOT implemented.**

## 4. Module Structure

```
app/services/threat_intelligence/
    __init__.py        Public exports
    types.py           IndicatorType enum, ThreatIndicator model
    exceptions.py      Exception hierarchy
    base.py            ThreatIntelProvider ABC, ThreatIntelResult model
    registry.py        ProviderRegistry
```

## 5. ThreatIndicator

`ThreatIndicator` is a validated Pydantic model representing an
Indicator of Compromise (IoC).

```python
from app.services.threat_intelligence import IndicatorType, ThreatIndicator

indicator = ThreatIndicator(
    indicator_type=IndicatorType.IP,
    value="8.8.8.8",
)
```

### Supported Indicator Types

| Enum Value | Description | Example Value |
|------------|-------------|---------------|
| `ip`       | IPv4/IPv6 address | `8.8.8.8` |
| `domain`   | Domain name | `example.com` |
| `url`      | Full URL | `https://example.com/path` |
| `hash`     | File hash (MD5, SHA-1, SHA-256) | `e3b0c442...` |

### Validation Rules

* `indicator_type` is required and must be a valid `IndicatorType` enum.
* `value` is required, non-empty (min 1 char), not blank/whitespace.

## 6. ThreatIntelProvider

`ThreatIntelProvider` is an abstract base class (ABC) that every
provider must implement.

```python
class MyProvider(ThreatIntelProvider):

    @property
    def provider_name(self) -> str:
        return "MyProvider"

    @property
    def supported_indicator_types(self) -> frozenset[IndicatorType]:
        return frozenset({IndicatorType.IP, IndicatorType.DOMAIN})

    def lookup(self, indicator: ThreatIndicator) -> ThreatIntelResult:
        self.assert_supports(indicator)
        # ... perform lookup ...
        return ThreatIntelResult(
            indicator=indicator,
            provider=self.provider_name,
            found=True, data={...},
        )
```

### Required Members

| Member | Type | Description |
|--------|------|-------------|
| `provider_name` | `@property` | Unique human-readable name |
| `supported_indicator_types` | `@property` | `frozenset[IndicatorType]` |
| `lookup(indicator)` | `@abstractmethod` | Perform the lookup |

## 7. ThreatIntelResult

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `indicator` | `ThreatIndicator` | Yes | Indicator looked up |
| `provider` | `str` | Yes | Provider name (non-empty) |
| `found` | `bool` | Yes | Whether the provider had info |
| `data` | `dict` | No | Provider-specific payload |
| `confidence` | `float \| None` | No | Confidence in \[0.0, 1.0\] |
| `timestamp` | `datetime` | Yes | Timezone-aware UTC timestamp |
| `metadata` | `dict \| None` | No | Optional metadata |

## 8. ProviderRegistry

| Method | Description |
|--------|-------------|
| `register(provider)` | Add provider (unique name required) |
| `get(name)` | Retrieve by name |
| `get_or_none(name)` | Retrieve or return None |
| `list_providers()` | All providers in insertion order |
| `has_provider(name)` | Check existence |
| `find_providers_for(type)` | Providers supporting this type |
| `count()` | Number of registered providers |

## 9. Provider Capabilities

Providers declare which indicator types they support via the
`supported_indicator_types` property.  The future Threat Intelligence
Agent routes queries based on these capabilities.

```python
registry = ProviderRegistry()
registry.register(VirusTotalProvider())    # ip, domain, url, hash
registry.register(AbuseIPDBProvider())     # ip
registry.register(AlienVaultOTXProvider()) # domain, url, hash

ip_providers = registry.find_providers_for(IndicatorType.IP)
# Returns: [VirusTotalProvider, AbuseIPDBProvider]
```

## 10. Error Handling

```
ThreatIntelError (base)
├── UnsupportedIndicatorTypeError
├── ProviderNotFoundError
├── DuplicateProviderError
├── ProviderLookupError
└── InvalidIndicatorError
```

All exceptions inherit from `ThreatIntelError`.  Exception messages
must never expose secrets, API keys, or credentials.

## 11. Provenance

Threat intelligence is enrichment.  Provider-derived results must use:

```
Provenance.ENRICHED
```

Never `Provenance.OBSERVED` or `Provenance.RECONSTRUCTED`.
The original normalised event must remain unchanged.

## 12. EnrichmentResult Integration

`ThreatIntelResult` maps into the existing `EnrichmentResult` schema:

```python
# Provider returns:
ThreatIntelResult(
    indicator=ThreatIndicator(indicator_type=IndicatorType.IP, value="185.x.x.x"),
    provider="VirusTotal",
    found=True,
    data={"malicious": True, "detections": 8},
    confidence=0.95,
)

# Maps to:
EnrichmentResult(
    enrichment_type="threat_intelligence",
    source="VirusTotal",
    value={
        "indicator_type": "ip",
        "indicator": "185.x.x.x",
        "found": True,
        "malicious": True,
        "detections": 8,
    },
    confidence=0.95,
    timestamp=...,
)
```

## 13. Future Provider Architecture

| Provider | Supported Types | Status |
|----------|----------------|--------|
| VirusTotal | ip, domain, url, hash | **FUTURE** |
| AbuseIPDB | ip | **FUTURE** |
| AlienVault OTX | domain, url, hash | **FUTURE** |

## 14. Future Timeout / Retry / Rate-Limit Requirements

* **Bounded timeouts** — every HTTP call must have a timeout.
* **Retries** — transient failures (429, 502, 503) retried with backoff.
* **Rate limiting** — respect provider rate limits.
* **Graceful failure** — provider errors must not crash the pipeline.
* **Circuit breaking** — short-circuit for sustained failures.

## 15. Step 7C Scope

Step 7C establishes **infrastructure only**:

- ✅ `ThreatIndicator` model
- ✅ `IndicatorType` enum
- ✅ `ThreatIntelProvider` ABC
- ✅ `ThreatIntelResult` model
- ✅ `ProviderRegistry`
- ✅ Exception hierarchy
- ✅ Package exports, tests, documentation
- ❌ Provider implementations (VirusTotal, AbuseIPDB, OTX)
- ❌ HTTP clients, API keys, network requests
- ❌ DNS / WHOIS / Geolocation
- ❌ Detection / Correlation / Risk scoring
- ❌ AI / LLM, Database / Kafka / API / Frontend changes
