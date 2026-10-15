# V3.23 — Multi-Agent Debate Engine

Status: **implemented contract** for the debate component of SentinelAI V3.
Scope: multi-agent debate only. V3.24–V3.27 remain out of scope, and the
V3.22 knowledge-graph contract is unchanged and still authoritative.

The debate engine lets five specialized agents reason *over* an incident's
persisted evidence, argue across roles, and be reconciled deterministically
into a recorded conclusion.

---

## 1. The fundamental rule

> A debate is analytical reasoning over evidence. It is never evidence itself.

Every debate object is pinned by `CHECK` constraint to
`provenance = 'ai_generated'`. A debate can therefore never be stored as, or
read as, `observed`, `detected`, `correlated`, or `risk_assessed` — those
values belong to the V2 entities that genuinely produced them.

Two consequences follow, and both are enforced in code:

- **A debate never creates or modifies V2 evidence, and never writes the V3.22
  graph.** The graph is a read-only projection for this component; only the
  deterministic builder writes it.
- **A debate conclusion can never be cited back as a fact.** `ClaimKind.FACT`
  is engine-derived only (`app/agents/debate/evidence.py`); no model may emit
  it. A model-declared fact is a contract violation, not a weaker claim.

## 2. The five agents

Fixed roster, `app/agents/debate/vocabulary.py`. A larger roster would add more
correlated opinions of the same evidence, not new information.

| Role | Display name | Evidence focus (V3.22 node types) |
|---|---|---|
| `detection_analyst` | Detection Analyst | `DETECTION`, `CORRELATION` |
| `threat_intelligence_analyst` | Threat Intelligence Analyst | `THREAT_INDICATOR` |
| `behavioral_analyst` | Behavioral Analyst | `EVENT`, `DETECTION`, `CORRELATION` |
| `incident_investigator` | Incident Investigator | `CORRELATION`, `RISK_ASSESSMENT`, `INCIDENT_REPORT`, `INCIDENT_MEMORY` |
| `skeptic` | Skeptic / Contrarian | none — it reads the whole catalog adversarially |

The `skeptic` is a full member of the roster, not a post-hoc critique pass. It
forms its own assessment in round 1 and its challenges are weighed in the
reconciliation, so a debate cannot conclude unanimously by simply never
disagreeing.

## 3. The bounded lifecycle

Five rounds, no unbounded loop, no configurable depth. Round 0 involves no
model call.

| Round | Kind | Model calls | What happens |
|---|---|---|---|
| 0 | `round_0_shared_evidence` | 0 | Bounded graph read; `EvidenceCatalog` and engine-derived facts built |
| 1 | `round_1_independent_assessments` | 5 | Each agent assesses the same evidence in isolation |
| 2 | `round_2_cross_agent_arguments` | 5 | Each agent argues on another agent's hypothesis |
| 3 | `round_3_counterarguments` | 5 | Each agent challenges the arguments it was shown |
| 4 | `round_4_reconciliation` | 0 | Deterministic selection, confidence, dissent, gaps |

A complete debate is therefore exactly **15 model calls** — one per agent per
model round.

Round 0 is deliberately model-free: the evidence surface is a deterministic
function of persisted V2 rows, so letting a model summarize it would add
unreproducible variation to the one part that must be reproducible.

## 4. Evidence grounding

The engine builds a closed `EvidenceCatalog` from the bounded V3.22 graph. A
model's citation must resolve against it. If a citation names an entity that
is not in the catalog, the **entire agent output is rejected** — not the single
claim, the whole response.

This is what stops a plausible-sounding hallucinated `detection:<uuid>` from
entering a record. `app/agents/debate/evidence.py` holds the catalog; the
rejection path raises `DebateEvidenceError`.

Grounding is also required structurally, not just semantically:

- An `observation` with no citations is rejected by the schema — a description
  of the evidence that cites nothing is an assertion, not an observation.
- A `hypothesis` with no citations is rejected for the same reason.
- A `DebateCounterargument` with no citations is rejected. This is what stops
  the skeptic from manufacturing doubt by asserting that something is missing
  without showing that it is.
- An `AgentAssessment` that cites nothing must state at least one
  `limitation`, so silence is never mistaken for a clean review.

## 5. Determinism

Three properties make a debate reproducible and auditable rather than a second
opaque model opinion.

**Stable identity.** The session id is a UUIDv5 over
`(correlation_id, graph_snapshot_digest, configuration_digest)`. Re-posting over
an unchanged graph returns the stored debate instead of starting a new one;
changed evidence produces a *new* debate rather than overwriting a conclusion.
`GET` is a strict read of the stored session — never a re-run, never a
recomputation against the current graph.

**Deterministic reconciliation.** In round 4 no model participates. The engine
selects `leading_hypothesis`, classifies each argument as supporting or
opposing, computes `consensus_strength` from the supporting/opposing split, and
computes `confidence` from a documented weighted formula over agreement
(0.45), evidence support (0.35), and completeness (0.20), minus a bounded
contradiction penalty. `confidence` is never a blind average of agent
self-reports.

**Agreement on text, not vibes.** Two agents agree only on exactly normalized
text (whitespace collapsed, trailing punctuation stripped). Near-matches do not
count, because "mostly agrees" is not agreement.

## 6. Consensus states, reported honestly

`consensus` is deliberately narrow. It is reserved for a leading hypothesis
independently supported by **every** agent, unopposed by any argument, with no
unresolved question and sufficient evidence completeness. Anything weaker is
reported as what it is.

| State | Meaning |
|---|---|
| `consensus` | Every agent supports the leading hypothesis; nothing opposes it |
| `partial_consensus` | A majority supports it, but opposition or dissent remains |
| `contested` | The roster is split and support did not carry |
| `insufficient_evidence` | The graph cannot answer the question posed |

`insufficient_evidence` is an honest outcome, not a failure. A debate that
correctly reports "the evidence cannot establish this" is more useful than one
that manufactures a finding.

**Dissent is retained, never discarded.** A debate that hides the losing
argument is not auditable, so dissent is a first-class persisted object with
its own role, position, reason, and citations.

## 7. Provenance and immutability

- Every table has `CHECK (provenance = 'ai_generated')`.
- A stored debate is immutable. Re-persisting never mutates a conclusion;
  concurrent writers race on the primary key, and the loser discards its own
  row rather than merging into the winner's.
- Child rows use deterministic UUIDv5 ids derived from the session id, so a
  re-persist can never duplicate or fork a round or argument.

## 8. Persistence

Five tables (`app/models/debate.py`, migration `f6a7b8c9d0e1`):

| Table | Holds |
|---|---|
| `debate_sessions` | Session identity, digests, counts, `failure_code`, and the canonical `session_payload` |
| `debate_rounds` | One row per round: kind, summary, participating ids |
| `debate_agent_assessments` | One row per agent: observations, hypotheses, confidence, limitations |
| `debate_arguments` | Arguments and counterarguments, discriminated by `kind` |
| `debate_consensus` | State, leading hypothesis, strength/confidence, dissent, questions, gaps |

**Why both normalized children and a payload column.** The child tables make
the debate queryable and constrainable in SQL — provenance, confidence ranges,
non-empty evidence arrays, and the closed state/kind vocabularies are all
enforced by the database, not only by the application. The
`session_payload` column is the byte-exact canonical record, so a read can
reconstruct the response the POST returned without re-deriving anything from
five projections. The child tables are projections *of* that payload, never an
alternative source of truth.

`DebateService` (`app/services/debate/persistence.py`) is idempotent: identical
input returns the stored session, and the rebuild path validates the payload
through the same `DebateSession` contract that produced it.

## 9. API

Authenticated, RBAC-protected (`admin`, `analyst`, `ciso` — the existing V2
read roles and the V3.22 knowledge-graph roles).

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/debates/{correlation_id}` | Run **or return** the deterministic debate for one correlation |
| `GET` | `/api/debates/{debate_id}` | Read one stored debate verbatim |

`POST` returns `200` with the completed debate whether or not this call
performed it; a client cannot tell and does not need to, because the stored
conclusion is identical either way.

### Governed failures — no silent fallback

| Status | Failure code | Cause |
|---|---|---|
| 503 | `debate_provider_unavailable` | Provider unreachable |
| 504 | `debate_provider_timeout` | Provider timed out |
| 502 | `debate_provider_error` / `debate_model_validation_error` | Provider error, or output failed structural validation |
| 422 | `debate_evidence_error` / `debate_bounds_error` | Citation did not resolve, or output exceeded a bound |
| 404 | — | No persisted graph for that correlation |

**There is no fallback runtime.** An unavailable provider surfaces as a
governed failure rather than a deterministic stand-in debate, because a
fabricated consensus is indistinguishable from a real one to every downstream
consumer. A partial failure — at least one agent failing — is also reported as
a failure: a consensus over a surviving subset would misrepresent a partial
roster as a full debate.

Every failure body is shaped by `DebateFailureResponse`, the same contract used
for success, so a client can never receive a consensus-looking response for a
failed debate.

## 10. Reasoning providers — Gemini and Groq

The debate engine does not know what a "provider" is. It talks to one seam:

```python
class DebateRuntime(Protocol):
    provider_name: str
    model_name: str | None
    def complete(self, prompt: DebatePrompt, response_schema: dict) -> str: ...
```

Two implementations sit behind it — `GeminiDebateRuntime` and
`GroqDebateRuntime` — and both are built from the same schema-bound base class,
so a second vendor cannot fork the engine's behaviour.

### Selection is server-side and closed

`LLM_PROVIDER` selects exactly one provider per deployment
(`gemini` | `groq`). Anything else is a configuration error at boot, not a
runtime surprise. Clients never choose a provider: a request cannot ask for
Groq while the deployment is configured for Gemini.

| Variable | Default | Purpose |
|---|---|---|
| `LLM_PROVIDER` | `gemini` | Which provider serves model-backed rounds |
| `GROQ_API_KEY` | *(empty)* | Groq credential |
| `GROQ_MODEL` | `openai/gpt-oss-120b` | Groq model id |
| `GROQ_TIMEOUT_SECONDS` | `60.0` | Per-request timeout |
| `GROQ_MAX_RETRIES` | `4` | Bounded retries on transient failure |
| `GROQ_ENDPOINT_BASE` | `https://api.groq.com` | API base URL |
| `GROQ_MAX_OUTPUT_TOKENS` | `8192` | Output ceiling |
| `GROQ_TEMPERATURE` | `0.0` | Sampling temperature |
| `GROQ_REASONING_EFFORT` | `low` | `low` \| `medium` \| `high` |

The equivalent `GEMINI_*` variables are unchanged from V3.23.

> **Model id.** Groq publishes this model as **`openai/gpt-oss-120b`**. The
> bare `gpt-oss-120b` is not a valid Groq model id and is not silently
> rewritten to one.

### One provider per debate, and no fallback

Every model-backed round in a debate uses the same provider and model; the
engine never switches vendors mid-debate. If the selected provider fails, the
debate fails with a governed error. It is **never** answered by the other
provider, and never by a deterministic stand-in — see
[Governed failures](#governed-failures--no-silent-fallback).

Rounds 0 (bounded graph) and 4 (reconciliation) remain model-free on both
providers, so a Groq debate issues exactly the same 15 model calls as a Gemini
debate: 5 agents x rounds 1–3.

### Structured output across two dialects

Both providers demand JSON conforming to a schema, but they disagree on the
dialect. `GroqClient` translates the engine's schemas into Groq's strict subset
and **fails closed** on anything it cannot represent faithfully:

- every object becomes `additionalProperties: false` with all properties
  required (a provider-optional field is a validation hole, so it is refused);
- unknown keys and unsupported constructs (`$ref`, `anyOf`, `patternProperties`,
  …) are refused rather than approximated;
- a Gemini-style dialect is never forwarded to Groq untranslated.

A schema that cannot be translated is a configuration error, not a silently
loosened contract.

### Failures are normalised, and never leak the credential

Provider-specific status codes are mapped onto one closed error vocabulary so
the API's failure contract does not fork per vendor:

| Provider condition | Normalised |
|---|---|
| `401` / `403` | Configuration / permission error (not retryable) |
| `404` | Unknown model or endpoint |
| `429` (honours `retry-after`) | Rate limited, bounded retry |
| `498` | Flex Tier capacity exhausted, bounded retry |
| `5xx`, transport, timeout | Provider error / timeout, bounded retry |
| `finish_reason != "stop"`, refusal, malformed body | Provider error |

Retries are bounded and exhaustion is reported honestly rather than spun on.
Error messages and logs are sanitised: API keys, `Authorization` headers, and
provider response bodies are never logged or returned. Keys travel only in the
`Authorization` header — never in the URL or query string.

### Provider and model are part of debate identity

`configuration_digest` covers the provider and model alongside the bounds and
roster. A Groq debate and a Gemini debate over identical evidence are therefore
distinct, correctly-attributed artifacts rather than one silently standing in
for the other.

This also means the digest differs from pre-provider V3.23 identities, so a
`POST` against a correlation that already has a pre-provider debate yields a new
session id rather than matching the old one.

No schema migration is required: `provider` and `model` already exist on the
debate metadata written to the `debate_*` tables.

---

## 11. Audit lifecycle

`debate.completed`, `debate.failed`, and `debate.rejected` are recorded through
the existing `log_action` audit service, alongside the inherited
`auth.authorization.denied` from `require_role`.

Audit `details` carry only non-secret identifiers — debate id, correlation id,
consensus state, confidence, agent and round counts, failure code. Prompt text,
the provider endpoint, and credentials are deliberately excluded, so a run can
be reproduced from the audit trail without a secret ever being persisted.

An idempotent replay is **not** audited as a second completion: it performs no
new reasoning, so recording it as one would overstate how much analysis
actually happened.

## 12. Frontend

| Route | View |
|---|---|
| `/debates/correlation/:correlationId` | Run or return the debate for a correlation |
| `/debates/:debateId` | Read a stored debate verbatim |
| `/debates` | Explains the scoping and links back to correlations |

Reachable from the correlation detail page ("Run agent debate") and the
sidebar ("Agent Debate").

The view renders consensus state as reported — `partial_consensus` is never
displayed as `consensus` — and surfaces dissent, unresolved questions, and
evidence gaps as first-class sections rather than footnotes. Every claim shows
its citations as verbatim V3.22 source references, so an analyst can see that
the reasoning points at real persisted records.

A provider failure renders as a failure with the backend's detail. The page
never substitutes a placeholder conclusion, matching the backend's refusal to
fabricate one.

## 13. Bounds

Every limit **rejects**, never truncates. Silently dropping claims would make a
debate look complete when it was not.

| Bound | Value |
|---|---|
| Model rounds | 4 |
| Observations / hypotheses per agent | 12 / 8 |
| Total observations / hypotheses | 60 / 40 |
| Arguments / counterarguments per agent | 8 / 8 |
| Total arguments / counterarguments | 64 / 64 |
| Evidence references per claim | 32 |
| Unresolved questions / evidence gaps / dissent entries | 32 each |
| Claim text length | 1024 |
| Model output bytes | 49152 |
| Evidence catalog bytes | 98304 |

Roster-wide totals are checked after round 1, so one verbose agent cannot
exhaust the budget for the others.

## 14. Testing and verification

| Suite | Location | Result |
|---|---|---|
| Engine unit tests | `backend/tests/unit/test_debate_engine.py` | 23 passed |
| API integration tests | `backend/tests/integration/test_debate_api.py` | 32 passed |
| Persistence integration tests | `backend/tests/integration/test_debate_persistence.py` | 25 passed |
| Groq client unit tests | `backend/tests/unit/test_groq_client.py` | 93 passed, 1 skipped |
| Shared provider contract | `backend/tests/unit/test_provider_contract.py` | 38 passed |
| Provider integration & isolation | `backend/tests/integration/test_debate_providers.py` | 34 passed |
| Full backend suite | `backend/` | 5592 passed, 4 skipped |
| Frontend suite | `frontend/` | 165 passed |

Deterministic scripted runtimes (`backend/tests/helpers/debate_runtime.py`)
serve the provider seam in tests, so the engine, API, and persistence paths are
exercised end-to-end with no network access.

Provider tests use `httpx.MockTransport` behind **real** provider clients
rather than runtime test doubles, so the whole provider path — HTTP, strict
structured-output request, error normalisation — runs without a network or a
credential. `test_debate_providers.py` recovers `(role, round)` from the prompt
the provider actually received, so the 15-model-call and model-free-round-4
claims are asserted against the wire, not against the engine's own bookkeeping.
It also asserts provider isolation directly: when `LLM_PROVIDER=groq`, a Groq
rate-limit must fail the debate and only `api.groq.com` may ever be addressed,
and vice versa.

### 14.1 Test database must be reset between runs

The isolated test database (`sentinelai_test`) is created and migrated once per
session but is **not truncated afterwards**. Rows therefore accumulate across
successive local runs, and the V3.22 knowledge-graph builder tests — which
assume a pristine graph — begin to fail spuriously:

| Run | Result |
|---|---|
| First run on a clean database | 5592 passed, 4 skipped |
| Second run, same database | 21 failed, 5571 passed, 4 skipped |

The failures are `test_knowledge_graph_builder.py` assertions about node counts
and pruning; nothing in the debate or provider path is involved. Reset before
trusting a result:

```bash
psql -d postgres -c 'DROP DATABASE IF EXISTS sentinelai_test'
```

This is a pre-existing test-infrastructure weakness, not a debate-provider
regression. The fix belongs in `tests/conftest.py` (truncate or recreate at
session teardown); it is recorded here rather than changed silently.

### 14.2 Live provider verification

Live tests are opt-in and marker-gated, because they require real credentials,
cost money, and are not reproducible in CI:

```bash
pytest -m groq_integration      # requires GROQ_API_KEY
pytest -m gemini_integration    # requires GEMINI_API_KEY
```

They are skipped by default. A skip is a **skip, not a pass** — no live provider
success is claimed anywhere in this document unless a run actually produced one.

Verified beyond the test suite:

- Migration round-trip on a scratch database: 17 migrations applied, all five
  `debate_*` tables created, `downgrade e5f6a7b8c9d0` removed all five.
- `alembic check` attributes **zero** drift to any `debate_*` table. The 102
  remaining `modify_comment` diffs are pre-existing on `approval_requests`,
  `detection_rule_*`, and `incident_memories`, and are explicitly out of scope.
  Adding a provider required no migration at all: `provider` and `model` were
  already columns on `debate_sessions`.
- Every `debate_*` table carries its `provenance = 'ai_generated'` `CHECK`.
- A debate POST leaves correlation, member, detection, and risk rows
  byte-identical, including the correlation's `confidence`.