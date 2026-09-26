Risk Assessment Query & Retrieval (Step 11D)
============================================

Purpose
-------

Step 11D adds the **read-only retrieval layer** over the Step 11C
persistence contract.  It answers one question: *given a persisted risk
assessment, how do we get it back intact?*  It is the risk analogue of the
detection (Step 9G) and correlation (Step 10D) query services: one read
model module, read-side repository methods, and one validated read-only
service.

This is an **internal application/service layer**.  No HTTP/FastAPI
endpoints are introduced — the layer exists so a future read API can call
``RiskQueryService`` directly.

Step 11D retrieves risk assessments; it does not calculate, modify, persist,
expose through HTTP, or act on risk.

Architecture
------------

The query path mirrors the established Detection/Correlation query
conventions exactly::

    risk_assessments                          (Step 11C-A model)
        -> RiskRepository (read methods)      (Step 11D, read-only)
            -> RiskQueryService                (validates, orders, paginates,
                                               converts rows, sanitizes errors)
                -> RiskAssessmentRecord / RiskAssessmentPage
                    [future API layer consumes these read models]

* **Read-only end to end** — the repository never writes; the service never
  calls ``add``/``delete``/``flush``/``commit``/``rollback``; callers own
  the session transaction.  A failed read leaves the session untouched.
* **No risk engine** — scores, levels, confidence, factors, evidence,
  metadata, and provenance are surfaced exactly as persisted.  Nothing is
  recalculated, re-derived, reinterpreted, or regenerated.
* Modules: ``app/schemas/risk_query.py`` (read models),
  ``app/services/risk_query.py`` (service + exceptions + bounds),
  ``app/repositories/risk.py`` (read methods added to the Step 11C repo).

Supported queries
-----------------

| Operation | Signature | Returns |
|-----------|-----------|---------|
| Assessment detail | ``get_assessment(db, risk_assessment_id)`` | ``RiskAssessmentRecord \| None`` |
| By correlation | ``list_assessments_for_correlation(db, correlation_id, *, page=1, page_size=50)`` | ``RiskAssessmentPage`` |
| Recent feed | ``list_recent_assessments(db, *, limit=50)`` | ``list[RiskAssessmentRecord]`` |
| Count (total) | ``count_assessments(db)`` | ``int`` |
| Count (correlation) | ``count_assessments_for_correlation(db, correlation_id)`` | ``int`` |

* Unknown IDs produce a controlled not-found result (``None`` / empty page),
  never an error.
* A correlation's assessments are **not** collapsed: because
  ``risk_assessment_id`` is the identity and ``correlation_id`` is **not**
  unique (Step 11C-A), every historical assessment of a correlation is
  returned.

Ordering
--------

Every list orders by ``timestamp`` **descending** with
``risk_assessment_id`` **ascending** as the deterministic tie-break — the
exact two-key convention used by Detection (``detected_at``/``detection_id``)
and Correlation (``timestamp``/``correlation_id``).  Because
``risk_assessment_id`` is unique, the ordering is total: equal timestamps
never produce unstable or duplicated page boundaries, and page content never
drifts between calls.

Pagination
----------

* 1-based pages, offset pagination, matching Detection/Correlation:
  page >= 1, page_size in ``[1, 200]`` (default ``50``);
  recent limit in ``[1, 200]`` (default ``50``).
* ``total`` is returned on every page and counts all rows matching the query
  independent of the page window.  Totals are computed with database-side
  ``COUNT`` queries — the table is never materialized in Python to count.
* Filtering, ordering, and pagination all happen in SQL at the database
  layer; rows are hydrated only for the requested page.

Data fidelity
-------------

A persisted assessment reads back **exactly** as stored::

    RiskAssessment[] (Step 11B)
        -> risk_assessments       (Step 11C, JSONB preserved)
            -> RiskAssessmentRecord (Step 11D)

* ``score``/``confidence`` are the persisted ``[0.0, 1.0]`` floats
  (0.0, 1.0, and middle values round-trip).
* ``level`` is the controlled ``RiskLevel`` enum persisted
  (low/medium/high/critical), never re-derived from score.
* ``factors``/``evidence`` come back as plain lists of dicts; nested JSON
  inside factor/evidence metadata survives untouched.
* ``assessment_metadata`` is the persisted form of the Step 11A ``metadata``
  (the read-record field names the persisted column, following the
  Detection/Correlation ``result_metadata`` convention).
* ``provenance`` is always ``RISK_ASSESSED``; ``timestamp`` is normalized to
  a tz-aware UTC instant at the read boundary (SQLite returns naive UTC,
  PostgreSQL returns tz-aware — both appear identical to consumers).

Error handling
--------------

* ``RiskQueryValidationError`` — malformed UUIDs and out-of-bounds
  page/limit arguments; raised **before** any database work.
* ``RiskQueryError`` — sanitized service-level failure bubbling a database
  error (the underlying exception is preserved as ``__cause__`` for
  server-side logging).
* Messages never contain SQL statements, connection strings, table names,
  stack traces, payloads, or credentials — only safe identifiers
  (``risk_assessment_id`` / ``correlation_id``) and a stable reason string.
* Not-found is a normal result (``None`` / empty page), never an exception.

Security
--------

The query layer never fabricates data and only surfaces what the persistence
contract already stored.  Step 11C redacts credential-shaped keys (API keys,
authorization headers, passwords, bearer/JWT tokens, cookies) **before**
write; 11D therefore returns the stored **redacted** form (``<redacted>``)
and is never a weaker read path.  Numbers, strings, and safe metadata pass
through unchanged.  Error messages contain no payloads or secrets, and the
service logs only operation, identifiers, result counts, and error category.

Read-only guarantees
--------------------

11D is write-free, verified by tests and on live PostgreSQL:

* Querying never calls ``add``/``delete``/``flush``/``commit``/``rollback``.
* A full query round-trip emits **zero** INSERT/UPDATE/DELETE statements
  (asserted via SQL-level statement capture).
* Reads do not flush concurrently-staged (uncommitted) writes and do not
  mutate the objects they return (returned read models are independent
  copies of the ORM rows).
* Row count, persisted values, timestamps, IDs, and metadata are byte-for-byte
  identical before and after a read.

PostgreSQL behavior
-------------------

Verified against the live PostgreSQL 17 (``sentinelai``) instance:

* real persistence (Step 11C) → query (Step 11D) round-trip returns the
  exact persisted ``score`` (0.625), ``level`` (high), ``confidence`` (0.8),
  structured factors/evidence/metadata;
* multiple historical assessments for one correlation all returned, in
  deterministic order;
* pagination (page/offset) totals unaffected by the requested page;
* recent feed newest-first across all rows;
* missing IDs return ``None``/empty pages;
* idempotent re-persist (11C) remains a no-op after reads;
* database-side counts;
* read-only guarantee measured (zero write statements, unchanged row count).

No new Alembic migration is introduced by 11D: the query layer reads the
Step 11C schema as-is (``alembic check`` reports no pending operations).

Testing
-------

``tests/unit/test_risk_query.py`` (in-memory SQLite with the same ``JSONB``-
on-SQLite compiler and ``PRAGMA foreign_keys=ON`` harness as 10C/10D/11C)
covers:

* get by ID: existing, missing (``None``), string UUIDs, invalid UUID
  (rejected before DB), complete field fidelity, structured JSON fidelity;
* get by correlation: one / many / none, multiple historical assessments
  per correlation, deterministic ordering + tie-break, pagination, fidelity;
* recent: empty, one, many, default/maximum/boundary limits, newest-first,
  equal-timestamp tie-break;
* pagination: first/middle/last page, beyond-range page, min/max page_size,
  invalid/oversized page and page_size, stable ordering across pages;
* data fidelity: score/confidence boundaries (0, 0.5, 1), all four levels,
  empty structures, nested JSON;
* security: secret-shaped values in metadata / factor metadata / evidence
  metadata surface redacted (round-trip through the real Step 11C service);
* read-only contract: no writes on any operation, no flush of pending
  writes, returned records independent of rows, values/IDs/timestamps/
  metadata unchanged, SELECT-only statements;
* database behavior: empty database, counts, sanitized errors (no raw SQL /
  payloads in messages).

Non-goals
---------

11D does **not** implement: risk query APIs / routes / HTTP handlers
(future), risk dashboards, incident creation, alert generation, MITRE
mapping, AI investigation, LLM reasoning, response/mitigation, SOAR, threat
hunting, incident memory, knowledge graphs, attack prediction or
visualization, frontend changes, Kafka/RabbitMQ events, scoring, recalculation,
or new scoring policies.  Step 11D is the internal read layer only.

Step 11D retrieves risk assessments; it does not calculate, modify, persist,
expose through HTTP, or act on risk.