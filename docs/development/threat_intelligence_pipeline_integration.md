Threat Intelligence Persistence Integration (Step 8C-C)
=======================================================

Overview
--------

Step 8C-C wires the Step 8B Threat Intelligence Agent to the existing
Step 8C persistence layer.  When an analysis completes, it is handed to
the existing `ThreatIntelligencePersistenceService.persist_analysis()`,
which writes it to PostgreSQL through the Step 8C-B repository.

This step introduces **no new persistence mechanism** — it reuses
`persist_analysis()` exactly as documented in
[`threat_intelligence_persistence.md`](threat_intelligence_persistence.md).
It also introduces **no detection, risk scoring, verdict, or response**
logic.

Architecture
------------

::

    SecurityEvent
        |
        v
    Normalization
        |
        v
    Enrichment
        |
        v
    ThreatIntelligenceAgent.analyze(event, persistence=callback)
        |
        +-- indicator extraction / dedup / provider lookups
        |
        v
    ThreatIntelligenceAnalysis
        |
        v                                     (Step 8C-C boundary)
    ThreatIntelligencePersistenceService.persist_analysis(db, analysis)
        |
        v
    ThreatIntelRepository
        |
        v
    PostgreSQL  (threat_intel_indicators / threat_intel_lookups)

The integration boundary
------------------------

The only change to the agent is an **optional, injected persistence
callback** on `ThreatIntelligenceAgent.analyze()`:

```python
analysis = agent.analyze(event, persistence=persist_analysis_bound(session))
```

* The agent remains **stateless and deterministic**: it builds the full
  `ThreatIntelligenceAnalysis` first, and only then invokes the callback.
* When `persistence` is omitted (default `None`) the agent performs **no
  persistence** — its behavior is exactly the Step 8B behavior.
* The agent never commits or rolls back; the injected
  `ThreatIntelligencePersistenceService` owns the transaction boundary.

Wiring helper
-------------

`app.agents.threat_intelligence.persist_analysis_bound(db, service=None)`
returns a `PersistenceCallback` bound to a SQLAlchemy `Session`:

```python
from sqlalchemy.orm import Session
from app.agents.threat_intelligence import (
    ThreatIntelligenceAgent,
    persist_analysis_bound,
)

db: Session = ...  # owned by the caller / pipeline
agent = ThreatIntelligenceAgent(registry)
analysis = agent.analyze(event, persistence=persist_analysis_bound(db))
```

The service (via the repository) handles:

* **Indicator deduplication** — `canonical_key` (Step 8A semantics);
  repeated occurrences reuse the global row and never duplicate it.
* **Idempotent lookups** — re-persisting an identical analysis is a no-op;
  the same indicator/provider at a *different* time is a legitimate new row.
* **Transaction safety** — a single commit per analysis; any failure rolls
  the whole unit back and raises a safe `ThreatIntelPersistenceError`.
* **Secret safety** — error messages are sanitized and structured evidence
  is recursively key-redacted before persistence.
Outcome distinctions preserved
------------------------------

The existing persistence contract distinguishes:

* **successful provider lookup** → `LookupStatus.SUCCESS` with the
  result/evidence columns populated;
* **lookup returning no meaningful intelligence** → a success row with
  `found=False` (the provider answered, but with no finding);
* **provider failure** → `LookupStatus.ERROR` with `error_type` and a
  sanitized `error_message`;
* **retryable provider failure** → the same `LookupStatus.ERROR` row with
  `retryable=True` (e.g. rate limits) versus non-retryable
  (`retryable=False`).

Provider evidence is persisted as **evidence only** — never converted into
malicious/benign verdicts, severity, risk scores, or detection results.

Error handling
--------------

A persistence failure (e.g. a database error, or an analysis that exceeds
the evidence-size bound) is handled by the existing service conventions:

* the service rolls the transaction back,
* it raises a **safe** `ThreatIntelPersistenceError` (sanitized — no DB/SQL
  text, API keys, or credentials),
* the agent logs a warning (event UUID only) and re-raises the sanitized
  error unchanged so the caller can react.

Because the analysis is fully built before persistence runs, a persistence
failure never corrupts or partially produces the returned analysis contract —
the sink simply fails before any write is committed.

Dependency injection
--------------------

The callback is the dependency-injection seam.  Tests (and alternate
pipeline configurations) can supply:

* the **real** service — `persist_analysis_bound(session)` (or any callable
  wrapping `ThreatIntelligencePersistenceService().persist_analysis`), or
* a **fake/mock** persistence — any `Callable[[ThreatIntelligenceAnalysis], Any]`.

Files
-----

* `backend/app/agents/threat_intelligence.py` — modified: optional
  `persistence` parameter on `analyze()`, plus the `persist_analysis_bound()`
  helper.
* `backend/tests/unit/test_threat_intelligence_persistence_integration.py`
  — new: end-to-end agent → service → repository tests (see below).

Testing
-------

`test_threat_intelligence_persistence_integration.py` exercises the full
`ThreatIntelligenceAgent → ThreatIntelligencePersistenceService` path
against an in-memory SQLite engine with deterministic fake providers (no
network).  Coverage:

* successful analysis is persisted;
* multiple indicators are persisted;
* multiple provider results are persisted;
* provider failures are persisted (isolated — successes are not lost);
* retryable vs non-retryable failures retain their status;
* repeated indicator occurrence never duplicates indicator rows;
* event/provider association remains traceable;
* persistence failure is handled per the existing service conventions
  (safe error raised, transaction rolled back);
* Step 8B behavior is unchanged when persistence is not supplied or is
  mocked.

Run:

```
cd backend
.venv\Scripts\python.exe -m pytest tests/unit/test_threat_intelligence_persistence_integration.py -v
```

Non-goals
---------

* No changes to the Step 8A contract or Step 8B analysis semantics.
* No new persistence service/repository — the existing Step 8C layer is
  reused unchanged.
* No detection, correlation, risk scoring, verdicts, or response.
* No Kafka/Redis/Neo4j/OpenSearch/Qdrant/LangGraph changes.