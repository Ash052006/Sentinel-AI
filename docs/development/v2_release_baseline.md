V1/V2 Release Baseline
======================

Purpose
-------

This document records the **frozen, verified baseline** of SentinelAI V1 + V2
at the end of the H1–H3 hardening pass.  It exists so a future change can be
compared against a known-good state: what the release contains, which
security and integrity findings were fixed and how they are covered by
regression tests, and what the exact verification results were.

It is a *verification record*, not a design document.  Feature design lives in
the per-feature documents under `docs/development/`.

Release scope
-------------

**V1 + V2 are complete.**  Hardening H1–H3 is complete and verified.  The
release is frozen pending the owner's release commit and tag.

V2 features
-----------

| Version | Feature | Design document |
|---|---|---|
| V2.13 | Threat Attribution | `threat_attribution_engine.md` |
| V2.14 | Incident Memory | `incident_memory_contract.md` |
| V2.15 | Natural Language SOC | `natural_language_soc.md` |
| V2.16 | HITL Approval | `hitl_approval.md` |
| V2.17 | Detection-as-Code | `detection_rule_governance_v217.md` |
| V2.18 | SOAR Integration | `soar_v218.md` |
| V2.19 | Threat Hunting | `threat_hunting_v219.md` |
| V2.20 | AI Incident Report Generator | `ai_incident_report_generator_v220.md` |
| V2.21 | Attack Path Visualization | `attack_path_visualization_v221.md` |

Hardening findings fixed
------------------------

### 1. SOAR re-executed providers on duplicate submission (High)

* **Root cause.**  `SoarService.execute` ran the engine *before* consulting
  the idempotency store, and built a fresh `SoarEngine` per call — so the
  engine's in-memory dedup ledger (`_processed`) was always empty.  A replayed
  request re-ran the playbook and then discarded the new result in favour of
  the already-persisted record.  Providers therefore executed twice for one
  logical submission.
* **Fix.**  `SoarEngine` accepts a `persisted_lookup` callable which the
  service wires to the durable store.  The engine resolves the content-derived
  idempotency key *before* any step runs.  The post-execution lookup is
  retained as a persistence-collision guard.
* **Regression coverage.**
  `tests/unit/test_soar_service.py::TestExecuteLifecycle::test_duplicate_submission_never_reinvokes_provider`
  counts provider invocations at the service layer;
  `tests/integration/test_soar_e2e.py::TestSoarE2E::test_d_identical_submission_persists_once`
  does the same through the real HTTP route.  Both fail if the durable lookup
  is removed.

### 2. Validly signed non-UUID `sub` produced HTTP 500 (Medium)

* **Root cause.**  `get_current_user` passed the JWT subject straight into the
  `users.id` comparison.  A token minted with a non-UUID `sub` reached
  PostgreSQL as invalid `uuid` text and surfaced a driver `DataError` as a 500
  on **every** protected route.
* **Fix.**  The subject must be a `str` parseable by `uuid.UUID`; anything else
  is an authentication failure (401).  Genuine database faults are deliberately
  **not** caught, so an outage remains a 5xx rather than being laundered into a
  misleading 401.
* **Regression coverage.**  `tests/unit/test_auth_token_hardening.py` — 6 tests
  covering valid UUID forms, non-UUID and non-string subjects, unknown users,
  and the database-fault-is-not-401 rule.

### 3. Anonymous infrastructure disclosure (Low)

* **Root cause.**  `/api/health/database` returned the database name and
  connecting role to unauthenticated callers, and `/api/health/kafka` revealed
  broker reachability.
* **Fix.**  Both dependency probes require an authenticated active user.  The
  public `/health` **liveness** endpoint is unchanged.  No role was narrowed
  and no frontend change was needed (the System page already sends a bearer
  token).
* **Regression coverage.**  `tests/unit/test_hardening.py::TestHealthEndpoint` —
  anonymous denial for both probes plus `test_liveness_probe_stays_public`.

### 4. Nondeterministic pagination (Medium)

* **Root cause.**  `ORDER BY created_at DESC` is not a total order.  Rows
  sharing a timestamp may be returned in any order, so `LIMIT`/`OFFSET` can
  repeat or skip a row across pages.  Reproduced on live PostgreSQL: after one
  routine status update, page 1 changed from `(1,2,3)` to `(2,3,4)` and page 2
  from `(4,5,6)` to `(5,6,1)` — row 1 served twice, row 4 skipped.
* **Fix.**  Both affected lists now tie-break on the primary key:
  hunts `created_at DESC, hunt_id DESC`; evidence
  `observed_at ASC NULLS LAST, evidence_id ASC`.  These were the only two
  lists in the codebase not already following that convention.
* **Regression coverage.**  `tests/unit/test_threat_hunting_architecture.py`
  enforces the convention structurally.  A behavioural SQLite test was
  deliberately **not** used: SQLite's stable sort cannot reproduce the defect,
  so such a test would pass even with the bug present.

### 5. Alembic schema drift (Medium)

* **Root cause.**  Five separate metadata/live-schema disagreements:
  (a) FK `ondelete` was `NO ACTION` in the database although the models
  declared `CASCADE`/`RESTRICT`, so deleting a hunt raised an `IntegrityError`
  instead of cascading; (b) four columns were modelled as `JSON` against a
  `JSONB` schema; (c) three live indexes were undeclared, meaning the next
  autogenerate would have proposed **dropping** them; (d) `threat_hunt` and
  `incident_report` reached `target_metadata` only via a transitive import, so
  a harmless refactor could have made autogenerate propose deleting live
  tables.
* **Fix.**  New migration `c3d4e5f6a1b2_align_threat_hunt_fk_ondelete.py`
  (down_revision `9c2d4e6f8a1b`) realigns the four threat-hunt FKs
  (three child FKs to `CASCADE`, `threat_hunts.created_by` to `RESTRICT`);
  the four JSON columns were corrected to `JSONB`; the three indexes were
  declared in the models; and the migration environment now imports every
  model module explicitly.
* **Regression coverage.**  `tests/unit/test_migration_drift.py` — 13 tests
  covering table count, single-head chain, JSONB column types, declared
  indexes, and FK delete semantics.

### Also corrected (test hermeticity, not security)

* `tests/unit/test_approval_service.py` assumed its injected-clock record
  landed on page 1; the shared development database accumulates newer pending
  rows.  It now pages forward and still asserts the record is found.
* `tests/unit/test_threat_hunt_api.py` asserted `len(items) == total` on a
  paginated endpoint.  It now asserts the pagination invariant
  `len(items) == min(total, page_size)`.

Neither change weakens an assertion, and no test was skipped or deleted to
reach a green suite.

Verification
------------

All results below were produced from the final working tree.

### Backend

| Check | Result |
|---|---|
| `pytest` (full suite) | **4865 passed, 0 failed, 12 skipped, 4 warnings** (~16 s) |
| `python -m compileall -q app tests scripts` | exit 0 — no syntax/import errors |

The 12 skips are all environment-gated, not suppressed failures: 8 require a
reachable Kafka broker, 3 require `GEMINI_API_KEY`, 1 requires `QDRANT_URL`.

The 4 warnings are pre-existing and benign: 2 Pydantic serializer warnings
raised by a test that deliberately passes a raw string where an enum is
expected (`test_threat_attribution.py`), 1 Starlette `httpx` deprecation, and
1 `PytestConfigWarning` for the unused `asyncio_mode` option
(`pytest-asyncio` is not installed).

### Frontend

| Check | Result |
|---|---|
| `tsc -b --noEmit` | exit 0 — no TypeScript errors |
| `eslint .` | clean — no errors |
| `vitest` | **13 files, 79 tests, all passed** |
| production build | succeeded (`912.66 kB`, gzip `260.23 kB`) |

The build emits one pre-existing Vite advisory that a chunk exceeds 500 kB.
It is a bundle-size advisory, not an error.

### Database

| Check | Result |
|---|---|
| `alembic current` | `c3d4e5f6a1b2 (head)` |
| `alembic heads` | `c3d4e5f6a1b2 (head)` — single head, linear chain |
| `alembic check` | 102 × `modify_comment`, **0 structural operations** |

> **Note on the head revision.**  The head is `c3d4e5f6a1b2`, not
> `9c2d4e6f8a1b`.  `9c2d4e6f8a1b` was the head *before* the FK `ondelete`
> drift was fixed; `c3d4e5f6a1b2` is the migration that carries that fix, and
> it descends directly from `9c2d4e6f8a1b`.  `alembic current` and
> `alembic heads` agree, so the database and the repository are in sync.

Structural alignment was additionally confirmed **independently of**
`alembic check`, by comparing live database introspection against ORM
metadata:

* FK `ondelete`: **0 mismatches** (3 child FKs `CASCADE`, `created_by` `RESTRICT`)
* `JSON`/`JSONB`: **0 mismatches** across all 28 JSON columns
* declared indexes missing from the live database: **0**

### Migration safety

* `down_revision` is `9c2d4e6f8a1b`; the chain is linear with a single head.
* Both directions were generated offline and executed for real against the
  development database: `alembic downgrade -1` and `alembic upgrade head` both
  exited 0, row counts were **identical** before and after
  (`threat_hunts` 75, `threat_hunt_findings` 19), and FK delete semantics were
  correctly reverted to `NO ACTION` and then restored.
* The migration only alters FK delete rules.  It performs no data deletion and
  no destructive table operation.

### Route / OpenAPI surface

* 61 paths, 64 operations, **0 duplicate `(method, path)` pairs**.
* The operation table is **byte-identical to the pre-hardening commit**
  (verified by generating the schema from a clean `HEAD` worktree and diffing),
  so the hardening pass added and removed no routes.
* All V1/V2 feature groups are registered: detection, correlation, risk,
  incident memories, SOC query, approvals, detection-as-code, SOAR, threat
  hunting, incident reports, attack paths.
* No V3 path is present.

### Security regression

| Finding | Verified behaviour |
|---|---|
| SOAR idempotency | first submission invokes the provider; duplicate invokes it **zero** additional times (service + HTTP) |
| Auth subject | non-string and non-UUID `sub` → **401** (never 500), including SQL-injection-shaped values; tampered signature → 401; absent token → 401 |
| Auth DB outage | a real database fault remains **5xx** and is not reported as an auth failure |
| Health | anonymous database/kafka probes → **401** with no infrastructure detail; authenticated SOC user → 200/503; `/health` liveness stays public |
| Pagination | 61 tests pass; live PostgreSQL emits both sort keys; 20 repeated paginated reads were byte-identical |
| Alembic | structural drift remains resolved (0 FK, 0 JSON/JSONB, 0 index mismatches) |

### Provenance regression

1457 provenance/integrity contract tests pass.  At the enum level all four
laundering pairs are distinct members —
`RECONSTRUCTED ≠ OBSERVED`, `AI_GENERATED ≠ OBSERVED`, `RECALLED ≠ OBSERVED`,
`LEARNED ≠ OBSERVED`.

At the persistence layer, laundering is refused by CHECK constraints, not
merely by application code.  Active write attempts were blocked **5/5** on
populated tables (`detection_results`, `correlation_results`,
`risk_assessments`, `approval_requests`, plus `incident_memories`) and
**7/7** on direct inserts of `observed`, `enriched`, `detected`, `correlated`,
`ai_generated`, `learned` and `attribution_assessed` into `incident_memories`;
only the legal value `recalled` was accepted.  All probes were rolled back and
no rows were left behind.

`rejected ≠ executed`, `approved ≠ executed` and `failed ≠ successful` are
enforced behaviourally by the SOAR policy gate
(`tests/unit/test_soar_gate.py`, 9 tests: denied never passes, missing grant
stays pending, invalid or mismatched grant is rejected).

> **Probe-method note.**  An earlier provenance probe appeared to show
> `incident_memories` accepting a non-`recalled` value.  That was a flaw in the
> probe, not the schema: the table was empty, so the `UPDATE` matched zero rows
> and evaluated no constraint.  Re-tested with real inserts, all illegal values
> are refused.  This is recorded because the false positive is easy to
> reproduce and would otherwise be re-investigated.

### Read-only / autonomy audit

Read-only and analysis features were confirmed not to trigger execution:

* The incident-report package imports no execution service; its two
  `db.commit()` calls belong to `IncidentReportService`, which persists the
  report and its audit trail.  The generator itself is proven zero-write by
  `test_generate_is_zero_write`.
* Attack-path generation performs no LLM call, no graph database access, no
  network call, no prediction, and no persistence.  The only textual matches
  for "predict" are docstrings stating it does *not* predict.
* `SOCQueryExecutor` is the SOC's own read-only dispatcher, not
  `ResponseExecutor`; it performs no writes and references no SOAR, response or
  approval service.
* Threat hunting persists hunts, findings and evidence, and has **no** SOAR,
  response or approval execution path.
* SOAR `execute` and the response executor remain reachable only through the
  V2.16 approval workflow and the policy gate.  These legitimate execution
  paths were not modified.

### Secret scan

The repository has **no automated secret scanner configured** (no
`pre-commit`, `gitleaks`, `detect-secrets`, `trufflehog`, `bandit` or
`semgrep`, and none referenced in CI or the Makefile), so the diff and the new
files were scanned manually.

* No API keys, tokens, passwords, private keys or credentials appear in the
  diff or in the three new files.  All matches were the words "token" and
  "password" inside comments, test names and variable names.
* `test_auth_token_hardening.py` reads `settings.jwt_secret` to mint test
  tokens and uses a synthetic password; it hardcodes no secret.
* `.env` and `.env.*` are gitignored (with a `!.env.example` exception) and no
  credential file is tracked by git.

Adding a secret scanner is recommended as a follow-up; it was not added here
because this task is a release freeze.

Known Alembic state
-------------------

**The remaining `alembic check` differences are comment/prose-only.**

* Structural schema/index/FK/JSONB drift has been **resolved** and verified
  resolved (0 mismatches on each axis, confirmed both by `alembic check` and by
  direct live-schema introspection).
* The 102 outstanding `modify_comment` operations are documentation-string
  prose differences between the model metadata and the database comments.
  They have **no effect on runtime schema, data, or behaviour**.
* They were **intentionally not mass-edited.**  Rewriting 102 documentation
  strings purely to drive `alembic check` to exit zero would be churn with no
  data-integrity or security benefit, and would obscure the genuinely
  meaningful signal the check provides.  The documented position is that
  comment-only drift is a known, accepted condition.

V3 status
---------

**V3 implementation has NOT started.**

There is no executable V3 implementation anywhere in the repository.  Verified
absent: knowledge-graph engine, multi-agent debate engine, attack-prediction
engine, AI playbook generation, digital-twin cyber range, and autonomous
purple team.  Specifically there are no V3 routes, services, models,
migrations, frontend pages, agents, or database tables.  ORM metadata contains
exactly 24 tables, all of them V1/V2.  The only agent module in the tree is
the V1/V2 `investigation` agent.

Documentation may reference a V3 roadmap; that is intentional and is not
implementation.

Known limitations
-----------------

These are real, remaining limitations of the frozen baseline:

1. **Alembic comment-only drift.**  102 `modify_comment` operations, as
   described above.  Non-structural and accepted by decision.
2. **No automated secret scanning.**  The repository has no committed secret
   scanner, so secret detection depends on manual review.
3. **JWT stored in `localStorage`.**  The frontend stores the access token in
   `localStorage`, so any successful XSS could read it.  No XSS sink was found
   in the frontend, but this is a residual risk inherent to the storage choice.
4. **Role-level, not owner-level, authorization.**  Access is enforced by SOC
   role.  `created_by` records provenance; it is deliberately *not* an
   authorization boundary, and resources are not scoped to their creator.
5. **Shared, non-pristine development database.**  Tests run against a
   persistent shared database, which makes some order-sensitive assertions
   fragile (two were corrected in this pass).  No test isolation exists, and no
   data was deleted to make tests pass.
6. **Environment-gated coverage.**  12 tests never execute locally because
   Kafka, `GEMINI_API_KEY` and `QDRANT_URL` are absent.  Those paths are
   unverified in this baseline, as is the live Kafka broker path
   (`/api/health/kafka` correctly reported 503 during verification).
