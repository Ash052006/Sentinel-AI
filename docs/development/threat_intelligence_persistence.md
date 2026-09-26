# Threat Intelligence Persistence Layer (Step 8C-B)

## 1. Purpose

Step 8C-B implements the **persistence execution** for threat-intelligence
data: it translates a Step 8B
`ThreatIntelligenceAnalysis` into PostgreSQL rows using the Step 8C-A
contract models (`ThreatIntelIndicator`, `ThreatIntelLookup`).

The contract (what is persisted, the schema, provenance rules, security
rules) is defined in
[`threat_intelligence_persistence_contract.md`](threat_intelligence_persistence_contract.md).
This document describes the implementation of that contract.

```
ThreatIntelligenceAnalysis (Step 8B)
    -> ThreatIntelligencePersistenceService.persist_analysis()   <- this layer
        -> ThreatIntelRepository (CRUD / queries)
            -> ThreatIntelIndicator / ThreatIntelLookup (PostgreSQL)
```

## 2. Components

| Component | File | Responsibility |
|-----------|------|----------------|
| Repository | `backend/app/repositories/threat_intelligence.py` | Entity-level CRUD + queries; owns **no** transaction boundaries |
| Service | `backend/app/services/threat_intelligence_persistence.py` | Maps an analysis to rows; owns the transaction; sanitization |
| Models (8C-A) | `backend/app/models/threat_intel_indicator.py`, `backend/app/models/threat_intel_lookup.py` | Contract schema |
| Migration | `backend/app/database/postgres/migrations/versions/8c0b00d20101_create_threat_intel_tables.py` | DDL for the two tables |

## 3. Pipeline

`ThreatIntelligencePersistenceService.persist_analysis(db, analysis)`:

1. **Collect indicators** — a canonical-key-deduplicated union of every
   indicator referenced by `analysis.indicators`, `analysis.results[*].indicator`,
   and `analysis.failures[*]`, along with their occurrence timestamps.
2. **Persist indicators** — `get_or_create_indicator()` per canonical key
   (Step 8A semantics: domains/hashes lower-cased, IPs/URLs byte-for-byte).
   `first_seen_at` is set once on creation and never overwritten;
   `last_seen_at` only moves forward (monotonic).
3. **Persist lookups** — success outcomes first, then failures.  Each
   outcome is checked for idempotency; matching rows are skipped, new rows
   are staged.
4. **Commit** — a single `db.commit()` publishes the whole analysis; any
   failure rolls the unit back before a safe exception propagates.

### Idempotency keys

* Success lookup: `(event_id, indicator_id, provider, status=success,
  performed_at)` — re-persisting an identical analysis reuses the row;
  the same indicator/provider checked at a *different* time is a new,
  legitimate historical row.
* Failure lookup: `(event_id, indicator_id, provider, status=error,
  error_type, sanitized error_message, retryable)` — failures carry no
  lookup timestamp, so repeated failures of the same analysis are stable.

Only non-`None` attributes participate in the match.  The matching method
is `ThreatIntelRepository.find_existing_lookup()`.

## 4. Result type

`persist_analysis()` returns a frozen `ThreatIntelPersistenceResult`:

| Field | Meaning |
|-------|---------|
| `event_id` | The originating event |
| `indicator_ids` | Indicator rows **used by this invocation** (created or reused) |
| `lookup_ids` | Lookup rows **created by this invocation only** — empty when everything was skipped |
| `indicators_created` | New indicator rows |
| `indicators_updated` | Reused indicator rows (timestamps touched) |
| `lookups_created` | New lookup rows |
| `lookups_skipped` | Existing rows reused (idempotent match) |

`Result.is_empty` is true when nothing was persisted.

## 5. Provenance enforcement

Every persisted lookup carries `provenance = Provenance.ENRICHED.value`
(`"enriched"`).  The Step 8C-A contract **requires** ENRICHED and the DB
CHECK constraint enforces it; `observed` / `reconstructed` are never
written by this layer.

## 6. Secret-safe persistence

The Step 8B contract already requires secret-safe messages; this layer is a
second, defense-in-depth gate:

* **`sanitize_error_message()`** runs layered regex redaction on every
  failure message before persistence:
  * labeled credentials (`api_key=...`, `token: ...`, `x-api-key: ...`, …)
  * `Authorization: Bearer/Basic` headers (scheme + credential together)
  * bare `Bearer`/`Basic` credential tokens (≥16 chars)
  * JWT-shaped tokens (`eyJ...`, with or without dot-separated segments)
  * 64-char opaque hex tokens (SHA-256-like keys)
  * then truncates to a bounded length (4 000 chars).
* **`_redact_structured()`** recursively walks structured `evidence` /
  `result_metadata` dicts/lists and replaces values under credential key
  names (`api_key`, `authorization`, `cookie`, `password`, `secret`,
  `token`, `client_secret`, …) with `<redacted>`.
* **`_prepare_structured()`** enforces a hard size bound (262 144
  serialized chars) on JSONB payloads, raising
  `ThreatIntelPersistenceValidationError` when exceeded.

## 7. Transactionality and error sanitization

```
try:
    return self._persist(db, analysis)
except ThreatIntelPersistenceError:
    db.rollback(); raise
except Exception as exc:
    db.rollback()
    raise ThreatIntelPersistenceError(event_id=analysis.event_id) from exc
```

Exceptions in `app/services/threat_intelligence_persistence.py`:

* `ThreatIntelPersistenceError` — safe, generic; never contains connection
  strings, passwords, keys, or raw DB/SQL text.  Only the event UUID and a
  bounded reason.
* `ThreatIntelPersistenceValidationError` — pre-commit validation failures
  (e.g. oversized evidence) that abort the transaction.

## 8. Repository API

`ThreatIntelRepository(db)` — no commits; the service owns transactions.

| Method | Purpose |
|--------|---------|
| `add(entity)` | Stage an entity for insertion |
| `get_or_create_indicator(value, indicator_type, canonical_key, seen_at)` | Global dedup by `canonical_key`; monotonic `last_seen_at`; returns `(row, created)` |
| `get_indicator_by_canonical_key(key)` | Lookup by dedup key |
| `get_indicator_by_type_and_value(type, value)` | Lookup by the two contract fields |
| `find_existing_lookup(event_id, indicator_id, provider, status, performed_at=None, error_type=None, error_message=None, retryable=None)` | Idempotency match (non-None fields only) |
| `get_lookups_for_event(event_id, limit=None)` | Most recent first |
| `get_lookups_for_indicator(indicator_id, limit=None)` | Most recent first |
| `get_provider_lookups_for_indicator(indicator_id, provider, limit=None)` | Per provider, most recent first |
| `get_recent_lookups(limit=50)` | Across all events |

`_as_utc()` normalizes values to UTC so aware vs. naive comparisons never
occur on test/embedded stores (SQLite returns naive UTC instants).

## 9. Migration

`8c0b00d20101_create_threat_intel_tables.py` creates:

* `threat_intel_indicators` — `canonical_key` **unique**; enum
  `indicator_type`; `first_seen_at` / `last_seen_at` timestamp columns.
* `threat_intel_lookups` — indexed `event_id`, `indicator_id` (FK, cascade),
  `provider`, `performed_at`; enum `status`; CHECK constraint on
  `provenance = 'enriched'`; JSONB `evidence` / `result_metadata`.

## 10. Testing

`backend/tests/unit/test_threat_intelligence_persistence.py` runs end-to-end
against the same models/ORM using an in-memory SQLite engine with the
`StaticPool`.  The PostgreSQL `JSONB` type is rendered as `JSON` on SQLite
via a test-only `visit_JSONB` adapter on `SQLiteTypeCompiler`.

Coverage includes:

* indicator dedup, canonical keys, first/last-seen semantics
* success + failure lookup persistence, provider associations without
  results being skipped
* relationships and cascade delete
* provenance assertions (`Provenance.ENRICHED.value`)
* idempotency (noop re-persist, different-time-is-new-row, transactional
  rollback)
* empty-analysis no-op
* oversized-evidence validation
* error-message sanitization unit tests
* structured evidence / metadata key redaction
* repository query methods

Run:

```
cd backend
.venv\Scripts\python.exe -m pytest tests/unit/test_threat_intelligence_persistence.py -v
```

## 11. Non-goals

* No provider API calls — the layer performs zero network I/O.
* No events table is created (`event_id` is a logical FK).
* No detection, correlation, or risk scoring.
* No OpenSearch / Qdrant / Neo4j persistence (PostgreSQL only).
* `ThreatIntelMetadata` counters are not stored; they are derivable from
  the lookup rows.

## File locations

* `backend/app/repositories/threat_intelligence.py`
* `backend/app/services/threat_intelligence_persistence.py`
* `backend/app/database/postgres/migrations/versions/8c0b00d20101_create_threat_intel_tables.py`
* `backend/tests/unit/test_threat_intelligence_persistence.py`
* Contract (schema): `docs/development/threat_intelligence_persistence_contract.md`
* This document: `docs/development/threat_intelligence_persistence.md`