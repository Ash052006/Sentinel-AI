# V3.24 — Attack Prediction Engine

Status: **implemented contract** for the prediction component of SentinelAI V3.
Scope: attack prediction only. V3.25–V3.27 remain out of scope, and the V2
evidence, V3.22 knowledge-graph and V3.23 debate contracts are unchanged and
still authoritative.

The prediction engine projects *plausible next stages* from what is already
persisted, and records why it believes each projection — or records that it
cannot.

---

## 1. The fundamental rule

> A prediction is analytical reasoning over evidence. It is never evidence itself.

Every prediction row is pinned by `CHECK` constraint to
`provenance = 'ai_generated'`. A prediction therefore cannot be stored as, or
read as, `observed`, `detected`, `correlated` or `risk_assessed` — those values
belong to the V2 entities that genuinely produced them.

Two consequences follow, and both are enforced in code:

- **A prediction never creates or modifies evidence, and never writes the V3.22
  graph or a V3.23 debate.** All three are read-only inputs here. Only the
  deterministic builder writes the graph; only the V3.23 engine writes a debate.
- **A prediction can never be cited back as a fact.** Prediction evidence rows
  are pointers to persisted V2 sources (`reference`, `entity_kind`, `node_id`),
  never a copy of source content, so a projection cannot launder itself into
  the evidence layer on the way back in.

## 2. The second rule: decline rather than speculate

> No persisted source names a next stage? Then the answer is
> `INSUFFICIENT_EVIDENCE` with zero predictions.

`INSUFFICIENT_EVIDENCE` is a **successful** outcome (HTTP 200), not an error.
A prediction with no resolvable basis would be speculation, and a speculative
prediction is worse than none because downstream consumers cannot tell the
difference. The engine therefore answers "the graph cannot say" whenever the
inputs do not support a stage, and says so through a closed
`LimitationKind` vocabulary rather than silence.

## 3. There is no model, and no ATT&CK catalog

Unlike V3.23, this engine has **no reasoning provider**. It is a pure function:
same inputs, same output, every time.

- No LLM is invoked. `metadata` carries no provider or model field for a call
  this engine made; it records the *consumed* V3.23 debate's provider for
  traceability only.
- No ATT&CK catalog is embedded and no technique-successor table exists. A
  `technique_id` is populated **only** when a persisted detection supplied one
  via `evidence["rule_references"]`. Malformed ids are rejected at the schema
  boundary rather than normalised into plausibility.
- An absent `technique_id` is always accompanied by `technique_id_reason`. A
  missing technique is explained, never silent.
- The stage vocabulary is a closed token set used for **labelling** what the
  inputs already name. It deliberately contains no successor rules, so the
  engine cannot "know" that persistence follows credential access — it can only
  report that a persisted mapping or a debate hypothesis pointed there.

## 4. Inputs

Context assembly (`app/services/prediction/context.py`) is read-only and
bounded:

| Input | Source | Unavailable is |
| --- | --- | --- |
| Correlation, detections, rule references | V2 query layer | governed failure |
| Bounded graph, relationships | V3.22 `KnowledgeGraphQueries` | `graph_truncated` limitation |
| Persisted ATT&CK mappings | V2 mapping rows | `no_persisted_attack_mapping` |
| Latest debate per correlation | V3.23 persistence | `no_debate_artifact` |

Missing *optional* inputs are recorded in `metadata.unavailable_inputs` and as
typed limitations; the run continues. A missing *required* input (an
unresolvable correlation) is a governed failure. Upstream strings are clamped
before use so an oversized field cannot push the context past
`max_context_bytes`, and debate citations are filtered to references that
actually resolve in the graph — a debate claim pointing at nothing is not
support.

## 5. Determinism and identity

Deterministic identity keys, so re-running over unchanged inputs returns the
stored answer rather than producing a second one:

```
session_id        = uuid5(NAMESPACE, sha256(
                      correlation_id | graph_snapshot_digest | debate_id
                      | prediction_configuration_digest))
prediction_id     = uuid5(NAMESPACE, sha256(session_id | kind | target | depth))
evidence/uncert.  = uuid5(NAMESPACE, sha256(prediction_id | ...))
```

`graph_snapshot_digest` is a SHA-256 over the canonical bounded graph that was
read. `prediction_configuration_digest` covers the engine version **and** the
bounds, so changing either produces a new identity instead of silently
overwriting a prior run.

The consequence for the UI and API: `POST` is *run or return*, never *retry*.
A replay performs no new reasoning and is deliberately **not** audited as a
completion, because counting it would overstate the analysis performed.

## 6. Confidence

Bounded by construction — the weights sum to exactly `1.0` and every component
is in `[0, 1]`, so the weighted sum is in `[0, 1]` before the penalty:

```
confidence = round(clamp01(
      0.35 * evidence_support      # saturates at 2 supporting citations
    + 0.20 * evidence_diversity     # saturates at 3 distinct entity kinds
    + 0.25 * debate_support         # consensus state -> contribution
    + 0.20 * target_specificity     # persisted mapping > debate > analytical
    - contradiction_penalty         # 0.25 per contradicting citation, cap 0.50
), 4)
```

- The penalty is **counted, not weighted**: one contradiction should not
  outvote a real evidence base, but several should.
- `confidence_basis` exposes every component, so a number can always be
  explained rather than trusted.
- A supported prediction at or below `LOW_CONFIDENCE_THRESHOLD` (`0.35`) is
  reported `LOW_CONFIDENCE`, not `PREDICTED`.
- Confidence is a claim about a *future projection's plausibility*. It is not a
  risk score, not debate confidence, and not agent confidence.

## 7. The horizon, and why it is capped

`max_depth` is architecturally `2` and the bounds validator rejects any other
value. Depth `1` is the plausible next stage; depth `2` is one stage beyond.
There is no depth `3`.

At most one `immediate` and one `subsequent` prediction is emitted, and
candidate discovery **truncates before materialization**. A candidate that is
grounded but beyond the cap is recorded as a `horizon_capped` limitation rather
than silently dropped, so the analyst can see that something was withheld and
why.

## 8. Provenance, immutability, and constraints

Four tables (migration `a7b8c9d0e1f2`, revising `f6a7b8c9d0e1`):

| Table | Holds |
| --- | --- |
| `attack_prediction_sessions` | run identity, counts, `session_payload` |
| `attack_predictions` | one projection, its `prediction_payload` |
| `attack_prediction_evidence` | citing pointers, `supporting`/`contradicting` |
| `attack_prediction_uncertainties` | one row per prediction: gaps, questions, limitations |

The database, not just the ORM, enforces the invariants:

- `provenance = 'ai_generated'` on all four tables.
- `confidence BETWEEN 0 AND 1` on predictions and uncertainties.
- `depth BETWEEN 1 AND 2` on predictions.
- `status IN (...)` and `stance IN ('supporting','contradicting')` closed sets.
- `UNIQUE (prediction_id, reference, stance)` on evidence — a citation is
  identified by what it points at, its owner and its stance. Without this a code
  path could inflate a prediction's evidence count by re-inserting the same
  citation, which would silently *raise its confidence*, since support is a
  count.
- `UNIQUE (prediction_id)` on uncertainties — one uncertainty per prediction, so
  the persisted contradicting count is never ambiguous about which record is
  authoritative.

`session_payload` and `prediction_payload` hold the canonical JSON document, so
`GET` returns exactly what `POST` produced. The normalized child tables are the
queryable and auditable projection of the same write. Neither column contains
prompt text, API keys or raw provider payloads — the engine has no provider.

## 9. API

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/attack-predictions/{correlation_id}` | run or return the prediction |
| `GET` | `/api/attack-predictions/{prediction_id}` | read a stored prediction |

Roles: `admin`, `analyst`, `ciso`.

**The client cannot define a prediction.** The POST takes no body: a client may
ask for a prediction but cannot submit a stage, a technique or a confidence and
have the server believe it. Every such value is derived server-side.

### Governed failures — no silent fallback

| Condition | Status | Code |
| --- | --- | --- |
| correlation unresolvable / inputs unavailable | 503 | `prediction_input_unavailable` |
| bounds or configuration invalid | 422 | `prediction_configuration_invalid` |
| stored prediction not found | 404 | `prediction_not_found` |
| persistence refused | 409 | `prediction_persistence_conflict` |

The backend never fabricates a projection to cover a gap. Note the deliberate
asymmetry: *unavailable inputs are a success*, while a missing correlation is a
failure — the first is an honest analytical answer, the second is a bad request.

## 10. Audit lifecycle

| Action | When |
| --- | --- |
| `attack_prediction.created` | a new session was actually written |
| `attack_prediction.completed` | after persistence, with evidence and debate counts |
| `attack_prediction.failed` | a governed failure |
| `attack_prediction.unauthorized_attempt` | authenticated, but role not permitted |

Success auditing happens **after** the database write, not before. The trail
must describe what the database actually holds: logging `created` first would
leave a permanent record of a session a failed write never produced, and would
log a `created` event on an idempotent replay that created nothing. Both cases
are locked by tests that fail if the ordering regresses.

## 11. Frontend

`/predictions`, `/predictions/correlation/:correlationId`,
`/predictions/:predictionId` — the route parameter decides POST vs GET,
mirroring the V3.22/V3.23 correlation-scoped pages.

The page renders the distinction the engine is built on:

- Outcome is `insufficient evidence` when nothing is projected, framed as a
  correct answer rather than a failure, with an explicit "no prediction made"
  panel.
- **Supporting and contradicting citations are rendered side by side**, and a
  non-zero contradiction penalty is shown as a badge. Suppressing opposition
  would turn a contested projection into a confident-looking one.
- The full `confidence_basis` breakdown is displayed, so the number is
  explainable.
- Every `technique_id` renders with its `technique_id_reason`; an absent id
  renders as an explicit "no persisted technique" badge, never a blank.
- Unavailable inputs are listed, not hidden.

Types type `provenance` as the literal `'ai_generated'`, so a predicted
artifact cannot be rendered as an observed finding at the type level.

## 12. Bounds

| Bound | Default | Ceiling |
| --- | --- | --- |
| `max_graph_nodes` | 200 | 500 |
| `max_graph_edges` | 600 | 2000 |
| `max_debate_claims` | 64 | 500 |
| `max_candidate_predictions` | 8 | 32 |
| `max_evidence_references_per_prediction` | 16 | 32 |
| `max_predictions_emitted` | 4 | 32 |
| `max_depth` | 2 | **2 (fixed)** |
| `max_context_bytes` | 65536 | 1048576 |
| `max_technique_observations` | 64 | 256 |

## 13. Testing and verification

- `tests/unit/test_prediction_engine.py` — pure engine, no I/O.
- `tests/unit/test_prediction_contract.py` — schemas, models, and a dynamic
  import of the migration file to assert the ORM and the migration agree.
- `tests/integration/test_attack_prediction_api.py` — real PostgreSQL, real
  graph/debate fixtures, RBAC, audit ordering and idempotency.

The suite is **fully offline**: no provider, no network, and no real ATT&CK
lookup. Fixtures are constructed in the database rather than mocked, so a
constraint or ORM mismatch surfaces as a test failure instead of a review
comment.

### 13.1 Migration drift

`alembic check` also compares **comments**, and this repository carries known
pre-existing comment-only drift in five unrelated frozen tables
(`approval_requests`, `detection_rule_changes`, `detection_rule_releases`,
`detection_rule_versions`, `incident_memories`). Those are intentionally not
touched. The V3.24 criterion is narrower and stated exactly:

> `alembic check` reports **no** `attack_prediction*` operations.

Column comments are duplicated verbatim in the migration rather than imported
from live ORM metadata: a migration is a snapshot of one moment, so a later
model edit must not silently rewrite history.

## 14. Configuration

None. V3.24 has no provider selection, no API key, no model id and no
temperature. `LLM_PROVIDER` and related variables configure V3.23 only, and
changing them does not change a single prediction.