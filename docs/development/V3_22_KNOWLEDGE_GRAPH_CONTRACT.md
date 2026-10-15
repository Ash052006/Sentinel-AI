# V3.22 — Knowledge Graph Engine: Graph Contract

Status: **frozen contract** for the first component of SentinelAI V3.
Scope: knowledge graph only. No V3.23–V3.27 functionality.

The graph is a **representation of existing persisted V2 evidence**. It is not
an inference engine. It never invents, guesses, or completes a relationship.

---

## 1. The fundamental rule

> If the graph cannot prove why an edge exists, the edge must not exist.

Every node maps to a real persisted V2 entity. Every edge maps to a real
persisted V2 relationship, and carries:

- `source_reference` — the exact persisted row/column that justifies the edge
- `evidence_references` — the persisted entity IDs that participate in it
- `relationship_type` — a value from the closed vocabulary in §4

A relationship is **never** created because an LLM believes it, two entities
look similar, timestamps are near, an IP is shared, MITRE ATT&CK implies it,
RAG retrieved a statement, or a human might logically connect them.

## 2. Node vocabulary (closed)

Ten node types. Each has stable persisted identity.

| Node type | Source-of-truth table | Stable ID column | Node reference |
|---|---|---|---|
| `EVENT` | *no table* — see §2.1 | `detection_results.event_id` / `correlation_members.event_id` | `event_reference:<uuid>` |
| `DETECTION` | `detection_results` | `detection_id` (unique) | `detection:<detection_id>` |
| `CORRELATION` | `correlation_results` | `correlation_id` (unique) | `correlation:<correlation_id>` |
| `RISK_ASSESSMENT` | `risk_assessments` | `risk_assessment_id` (unique) | `risk_assessment:<risk_assessment_id>` |
| `THREAT_INDICATOR` | `threat_intel_indicators` | `id` (PK) | `threat_intel_indicator:<id>` |
| `INCIDENT_MEMORY` | `incident_memories` | `memory_id` (unique) | `incident_memory:<memory_id>` |
| `THREAT_HUNT` | `threat_hunts` | `hunt_id` (unique) | `threat_hunt:<hunt_id>` |
| `APPROVAL` | `approval_requests` | `approval_id` (unique) | `approval:<approval_id>` |
| `SOAR_EXECUTION` | `soar_executions` | `execution_id` (unique) | `soar_execution:<execution_id>` |
| `INCIDENT_REPORT` | `incident_reports` | `report_id` (PK) | `incident_report:<report_id>` |

### 2.1 `EVENT` is a reference-only node type — read this before trusting it

**SentinelAI V2 does not persist an event table.** `SecurityEvent` and
`NormalizedSecurityEvent` exist only as Pydantic schemas
(`app/schemas/security_event.py`, `app/schemas/normalized_event.py`) and are
transient pipeline objects.

What *is* persisted is the event **identifier**: `detection_results.event_id`
and `correlation_members.event_id` are real UUID columns (81/81 non-null in
the current development dataset). So an `EVENT` node means:

> "an event identifier that appears in persisted V2 rows"

It does **not** mean "a retrievable event record", because no such row exists.
Consequences, enforced in code:

- `provenance` is `referenced_event_identifier`, never `persisted_event`.
- The node reference is `event_reference:<uuid>`, **not** `event:<uuid>` — the
  prefix deliberately avoids implying an `events` table.
- Node metadata carries **only** the identifier and observation window. No
  event payload is read, so none can leak.
- This is why the graph can answer *"which detections came from this event?"*
  while never becoming an event-content disclosure endpoint.

### 2.2 Deliberately excluded node types

Four candidates from the V3 brief are **not** implemented, because V2 persists
no identity for them and inventing one would violate §1:

| Candidate | Why excluded |
|---|---|
| `INVESTIGATION` | No `investigations` table exists. AI investigation output is not persisted as a queryable record; it appears only inside `incident_reports.payload` JSONB. A node would have to be mined from a JSON blob, which is not a persisted relationship. |
| `POLICY_DECISION` | No `policy_decisions` table. Only `approval_requests.policy_decision_id` — an unenforced soft UUID reference with no row to point at. |
| `ATTACK_PATH` | V2.21 attack paths are a **computed read-only projection** (`app/services/attack_path/service.py`), rebuilt per request with no persisted identity. The brief forbids replacing V2 attack paths or inferring new attack-path relationships, so no node is created. |
| `THREAT_INTEL_LOOKUP` | A lookup row is *evidence for* an indicator edge, not an independent graph entity. It is preserved as the edge's `source_reference` and in `evidence_references`, which is precisely what those fields exist for. |

Consequence: the brief's question *"which investigation analyzed this
correlation?"* has **no answer in the graph**, and that is the correct
outcome. The API reports investigations as unavailable rather than inventing
one. V2 itself cannot answer it from persistence either.

## 3. Why one event + seven detections stays one + seven

This is the verified V2 semantics the brief requires be preserved:

- `correlation_members` is a **member row per (correlation, detection)**. Seven
  rows each carry the **same** `event_id`.
- The builder derives nodes from *distinct persisted identifiers*, keyed by
  `(node_type, source_id)`.
- Therefore seven members sharing one event produce **1 EVENT + 7 DETECTION**
  nodes, never seven events and never one merged detection.

The deterministic node id is `uuid5(NAMESPACE, f"{node_type}:{source_id}")`, so
the same V2 state always yields byte-identical node ids.

## 4. Relationship vocabulary (closed)

Ten relationship types. Each names its exact V2 source-of-truth. Nothing else
may be constructed.

| Relationship | From → To | V2 source-of-truth |
|---|---|---|
| `produced_detection` | EVENT → DETECTION | `detection_results.event_id` + `.detection_id` |
| `member_of_correlation` | DETECTION → CORRELATION | `correlation_members.detection_id` + `.correlation_id` (FK → `correlation_results.correlation_id`) |
| `assessed_by` | CORRELATION → RISK_ASSESSMENT | `risk_assessments.correlation_id` (FK → `correlation_results.correlation_id`) |
| `associated_with_indicator` | EVENT → THREAT_INDICATOR | `threat_intel_lookups.event_id` + `.indicator_id` (FK → `threat_intel_indicators.id`) |
| `recalled_by` | CORRELATION → INCIDENT_MEMORY | `incident_memories.correlation_id` |
| `requires_approval` | CORRELATION → APPROVAL | `approval_requests.correlation_id` |
| `authorized_execution` | APPROVAL → SOAR_EXECUTION | `soar_executions.approval_id` → `approval_requests.approval_id` |
| `responded_by_execution` | CORRELATION → SOAR_EXECUTION | `soar_executions.correlation_id` |
| `reported_by` | CORRELATION → INCIDENT_REPORT | `incident_reports.correlation_id` |
| `investigated_by_hunt` | CORRELATION → THREAT_HUNT | `threat_hunt_evidence.correlation_id` + `.hunt_id` |

Notes on the deliberate absences:

- **No `EVENT → CORRELATION` edge.** `correlation_members.event_id` exists,
  but it is non-null only alongside a non-null `detection_id` (81/81), so every
  event is already reachable through its detections. Adding the direct edge
  would duplicate an existing relationship.
- **No `DETECTION → THREAT_INDICATOR` edge**, despite being suggested by the
  brief's examples. There is **no persisted detection→indicator column**.
  `detection_results.evidence` is JSONB, and mining JSON for relationships is
  exactly the inference §1 forbids. Indicator relationships exist only where
  `threat_intel_lookups` persists them, which is event-scoped.
- **No `POLICY_DECISION → APPROVAL` edge**, because no policy decision row
  exists (§2.2).

## 5. Provenance contract

```jsonc
// node
{
  "id": "<deterministic uuid5>",
  "node_type": "DETECTION",
  "label": "powershell-encoded-download",
  "source_reference": "detection:<detection_id>",
  "provenance": "persisted_detection_result",
  "metadata": { /* explicit allowlist of safe scalars only */ }
}

// edge
{
  "id": "<deterministic uuid5>",
  "relationship_type": "member_of_correlation",
  "source_node_id": "<uuid5>",
  "target_node_id": "<uuid5>",
  "source_reference": "correlation_member:<correlation_member.id>",
  "evidence_references": [
    "detection:<detection_id>",
    "correlation:<correlation_id>"
  ]
}
```

Guarantees:

- `source_reference` and `evidence_references` always use **real persisted
  IDs**. Fabricated evidence IDs are rejected at construction time.
- Every edge's `evidence_references` must contain the source node's reference,
  the target node's reference, and the `source_reference` itself. A relationship
  that cannot cite all three is not constructible.
- `provenance` is a closed enum; a value outside it is rejected.
- Relationship types outside the closed vocabulary are rejected before any DB
  write.

## 6. RAG boundary

RAG is contextual knowledge, **not** observed security evidence.

- No RAG chunk, retrieval result, embedding, or knowledge-base document ever
  becomes a node, an edge, or an `evidence_references` entry.
- The builder imports nothing from the RAG/knowledge subsystem and performs no
  retrieval.
- RAG-derived text is never promoted to `OBSERVED` provenance.

## 7. No LLM in construction

Graph construction requires **no** Gemini or other LLM call, no RAG, and no
network access. It is pure SQL over existing tables, so the graph is
constructible with every external dependency offline.

## 8. Secret safety

Two independent layers:

1. **Allowlist construction.** Node metadata is built from an explicit
   per-type list of scalar columns. JSONB columns that may carry raw event
   payloads, provider responses, or credentials are never read
   (`evidence`, `result_metadata`, `payload`, `memory_metadata`,
   `execution_metadata`, `filters`, `steps`, `sources`, `indicators`,
   `entities`, `techniques`, `findings`, `actions`, `outcomes`,
   `assessment_metadata`, `factors`, `definition`, `context`).
2. **Defensive serialization.** Every node passes through a redactor that
   drops any key matching the platform secret patterns
   (`app/agents/investigation/_safety.py::SECRET_PATTERNS`) and truncates
   oversized strings. A graph read fails closed by omission, never by raising
   a 500.

Prompt injection cannot alter graph semantics: injected text can only ever
land in a `label`/`metadata` string value, which is data. Node identity,
edge validity, and relationships are computed exclusively from persisted
foreign-key columns.

## 9. Persistence

Relational, in the existing PostgreSQL infrastructure. The graph is an
index layer; **no V2 record is duplicated**.

`knowledge_graph_nodes`
- `id` UUID PK — deterministic `uuid5(node_type, source_id)`
- `node_type` VARCHAR(32) — closed vocabulary
- `source_id` VARCHAR(64) — the V2 native identifier, verbatim
- `source_reference` VARCHAR(128)
- `provenance` VARCHAR(48) — closed vocabulary
- `label` VARCHAR(256), bounded
- `metadata` JSONB — minimal, redacted
- UNIQUE `(node_type, source_id)` → no duplicate nodes, idempotent rebuild
- INDEX on `(node_type)`, `(source_id)`, `(label)`

`knowledge_graph_edges`
- `id` UUID PK — deterministic `uuid5(source, target, relationship)`
- `source_node_id`, `target_node_id` UUID
- FK → `knowledge_graph_nodes.id` **ON DELETE CASCADE** → no orphan edges
- `relationship_type` VARCHAR(48) — closed vocabulary
- `source_reference` VARCHAR(128)
- `evidence_references` JSONB — non-empty, real IDs only
- UNIQUE `(source_node_id, target_node_id, relationship_type)` → no duplicate edges
- INDEX on `(source_node_id)`, `(target_node_id)`, `(relationship_type)`

### 9.1 Orphan policy

`ON DELETE CASCADE` means an edge cannot outlive its endpoint nodes, so the
graph cannot accumulate structurally orphaned edges.

Because V2 deliberately stores several links as **soft references with no FK**
(so a report or memory may outlive its correlation), the builder resolves each
edge through an inner join on real rows. An edge is written **only** when both
endpoint entities are resolvable in V2. A soft reference whose target no longer
exists therefore yields no edge — deterministically, and without leaving a
dangling edge. A full rebuild also prunes nodes and edges no longer derivable,
so graph state converges to V2 state.

### 9.2 Migration status

The V3.22 migration `e5f6a7b8c9d0` is the Alembic head, and `alembic upgrade
head` → `downgrade` → `upgrade` was verified clean. The graph tables are
fully covered by migration metadata and contribute **zero** operations to
`alembic check`.

`alembic check` nevertheless still fails, on **pre-existing V2 drift only**: 102
`modify_comment` operations across `approval_requests`,
`detection_rule_changes`, `detection_rule_releases`, `detection_rule_versions`,
and `incident_memories`. Those models' `comment=` strings were reworded after
their migrations were applied, so the live comments differ from the models. No
file backing these five tables was modified by V3.22.

This is deliberately **not** fixed here. Re-writing an applied migration is
forbidden, and a comment-only reconciliation migration would extend V3.22 into
tables it must not touch. It is recorded as a known V2 deviation instead.

## 10. Bounds

| Bound | Value |
|---|---|
| `max_nodes` | 500 |
| `max_edges` | 2000 |
| `max_depth` | 5 |
| `max_page_size` | 200 (default 100) |

Traversal is breadth-first and stops at `max_depth` or the first node/edge
limit hit. Truncation is **always explicit** in the response:

```json
{ "truncated": true, "truncated_reason": "max_nodes", "node_count": 120, "edge_count": 240 }
```

It is never silent, and no request can return an unbounded graph.

The response always echoes the bounds **actually applied** in a `bounds`
object, so a caller never has to guess which limits shaped the result:

```json
{ "bounds": { "max_nodes": 500, "max_edges": 2000, "max_depth": 5, "max_page_size": 200 } }
```

Bounds are validated at construction (`GraphBounds`), so an out-of-range value
cannot be constructed by a caller and then silently clamped downstream.
Traversal enforces the node/edge caps **before** mutating the result set, so
no intermediate state ever exceeds a limit, and `max_page_size` counts the root
node — a page of `max_page_size` returns exactly that many nodes, never
`max_page_size + 1`.

## 11. API

Read-only, authenticated, RBAC-protected via the existing V2
`require_role("admin", "analyst", "ciso")` convention — the same roles as V2
SOC read access. No anonymous endpoint.

| Endpoint | Purpose |
|---|---|
| `GET /api/knowledge-graph/correlations/{correlation_id}` | Bounded correlation-centered graph |
| `GET /api/knowledge-graph/{correlation_id}` | Same response, exact brief shape (compatibility alias) |
| `GET /api/knowledge-graph/nodes/{node_id}` | Single node with source information |
| `GET /api/knowledge-graph/nodes/{node_id}/neighbors` | Bounded neighbors of one node |
| `GET /api/knowledge-graph/vocabulary` | The closed node/relationship vocabulary |

No LLM, RAG, or outbound call. Invalid UUID → 422/404. Missing node →
404. Correlation with no derivable edges → 200 with an empty, explicitly
reported graph.

The brief writes `GET /api/knowledge-graph/{correlation_id}`, which collides
with the `/nodes/{node_id}` prefix and cannot disambiguate a non-UUID path
segment. Both shapes are therefore served from one shared response builder:

- `/correlations/{correlation_id}` is the canonical, schema-documented route.
- `/{correlation_id}` is registered with `include_in_schema=False` purely for
  compatibility, so it cannot muddy the OpenAPI surface. It is still
  authenticated and RBAC-protected, and it returns a byte-identical body.
- Route ordering is irrelevant because the first segment is literal — but the
  short form **must** validate the UUID itself, since FastAPI's default path
  converter is `str`. `/api/knowledge-graph/not-a-uuid` returns 422 rather than
  falling through to a lookup for a nonexistent node.

## 12. Determinism and idempotency

- Node id = `uuid5(NAMESPACE, f"{node_type}:{source_id}")`
- Edge id = `uuid5(NAMESPACE, f"{relationship}|{source_node_id}|{target_node_id}")`
- Builder iterates rows in sorted order and commits once per build.
- Rebuilding against identical V2 state yields identical ids, rows, and
  ordering — verified by test, not by assumption.
- Pruning removes only rows no longer derivable from V2.

### 12.1 Edge collision is a merge, not a last-write-wins

Edge ids are derived from `(relationship, source, target)`. When several V2
rows justify the same logical relationship, they therefore collide on one id.
The builder merges rather than overwrites, so a single upsert can never discard
the citations that make the edge defensible:

- `source_reference` becomes the deterministically **smallest** colliding value.
- `evidence_references` becomes the sorted **union** of every contributor.

This is what keeps a relationship honest when, for example, two correlation
members both prove the same `produced_detection` edge. Losing the second
citation would have produced an edge whose evidence list was arbitrarily
incomplete.

### 12.2 Pruning never runs on a truncated scope

`build_for_correlation(prune=True)` removes nodes no longer derivable from V2.
If `--max-correlations` limited the build, the candidate set is incomplete, so
"not derivable from what I looked at" is not evidence of staleness. Pruning in
that state would delete valid rows for correlations the build never visited.

The builder therefore **skips pruning** and says so explicitly rather than
reporting a silent partial run:

```json
{ "prune_skipped": true, "prune_skipped_reason": "max_correlations_limit" }
```

Pruning only runs when the full V2 scope was evaluated.

## 13. Frontend

A SOC evidence view, not a decorative animation. Renders node type, entity
identity, relationship type, source reference, evidence references, provenance,
and truncation state. Clicking a node shows its persisted source reference;
clicking an edge shows exactly which persisted relationship supports it. No
random nodes, no decorative attack paths, no invented "AI network" aesthetic.

Routes: `/knowledge-graph` lists the correlations that actually exist so the
view is reachable without hand-editing a URL, and `/knowledge-graph/:correlationId`
opens one graph. The sidebar links to the list, and the correlation detail page
links to that correlation's graph.

The client is read-only by construction — it exposes no mutation method — and
renders only the allowlisted attributes from the contract. Raw V2 payloads are
never spread into the view, so the redaction guarantees of §8 are enforced at
materialization time and do not depend on the browser hiding anything. Truncation
and unavailable entity types are surfaced as first-class UI state, never as a
silently shorter graph.