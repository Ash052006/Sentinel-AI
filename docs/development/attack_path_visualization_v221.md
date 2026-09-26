Attack Path Visualization (V2.21)
=================================

Purpose
-------

Step 30 adds **Attack Path Visualization**: a read-only, API-served,
browser-rendered graph projection of the **already-persisted**
relationships that touch one correlation.  The projection is built
deterministically over persisted rows only — correlation members,
detection results, threat-intelligence indicators (via lookups),
risk assessments, incident memories, threat-hunt evidence, approval
requests and SOAR executions — and is rendered as an SVG graph on a
dedicated page without any graph library.

> **Graph, not inference.**  V2.21 does not invent an attacker or an
> attack step: **an edge exists only when it is backed by a persisted
> relationship** (a row id or a deterministic relationship directly
> supported by persisted fields), and **V2.21 does not infer missing
> attack steps** — nothing asserts lateral movement, attacker intent,
> pivoting, or a predicted next move.  The projection only draws the
> evidence-grounded relationships that SentinelAI already stored.

Why only persisted relationships?
---------------------------------

The pipeline already persists every link the projection needs:

* ``correlation_members`` — the correlation's detections.
* ``detection_results`` — detection identity / event id / severity.
* ``threat_intel_lookups`` — lookup rows that tie an indicator to a
  detection's ``event_id``.
* ``threat_intel_indicators`` — the indicator records.
* ``risk_assessments`` — ``correlation_id`` anchored risk rows.
* ``incident_memories`` — ``correlation_id`` anchored memory rows.
* ``threat_hunt_evidence`` — evidence rows that cite the correlation.
* ``approval_requests`` — policy-decision identity + correlation + approval.
* ``soar_executions`` — correlation / policy-decision / approval ids.

The relationship vocabulary is a **closed edge set**; each edge type is
read out of one persisted row or field pair.  The node set is a **closed
set** of nine types, each backed by a persisted table.  ``ENTITY``,
``RESPONSE``, ``INVESTIGATION`` and ``ATTRIBUTION`` are deliberately
**absent**: the persisted store carries no separately-provenanced record
for those surfaces in V2.21.  A response outcome is represented by the
approved approval request's ``response_status`` fields and the SOAR
execution's ``response_id`` reference; it is not promoted to a node
because no persisted response record exists to anchor it.  Discovery/
prediction-style relationships (``attacked``, ``lateral_movement``,
``compromised``) never exist.

Read-only and safe
------------------

* **Zero writes.**  The build pipeline issues only ``SELECT`` queries
  (no ORM ``add``/``commit``), the service performs no execution and no
  mutation, and tests prove immutability with a ``MutationSpy`` against
  a SQLite mirror plus PG-row-count checks around the live API.
* **Bounds are exposed, never silent.**  Per-surface caps
  (``MAX_CORRELATION_DETECTIONS`` … ``MAX_CORRELATION_SOAR_EXECUTIONS``)
  and the global graph caps (120 nodes / 240 edges) stop the growth of
  the projection **deterministically** by ``surface_priority`` and set
  ``metadata.truncated=True`` with a ``limitation`` string.  The UI shows
  an explicit truncation banner.
* **Deterministic layout + payload.**  Nodes are ordered
  ``(surface_priority, node_id)``, edges by ``edge_id``; the runtime uses
  a breadth-first layered layout, so the same records render the same
  diagram every time.  ``generated_at`` is the only clock-dependent value
  and is injectable for byte-exact tests.
* **Secret-free.**  A node's ``fields`` is a whitelisted map of bounded
  scalar columns (allowed keys per node type); raw ``evidence`` /
  ``result_metadata`` payloads are never copied.  Labels strip control
  characters.  Provenance always comes from the shared ``Provenance``
  enum; availability mirrors the V2.20 ``InputAvailability`` contract
  (``PROVIDED`` / ``NONE_FOUND`` / ``NOT_PROVIDED``) so a missing surface
  is never fabricated as "none found".

API
---

``GET /api/attack-paths/{correlation_id}`` — 200 returns
``AttackPathResponse`` (``graph``, ``metadata``, ``availability``).

* 401 unauthenticated; 403 viewer (audited as
  ``attack_path.unauthorized_attempt``); admin/analyst/ciso allowed.
* 404 unknown correlation; 422 validation; 503 source failure.
* No mutation endpoints.

Frontend
--------

``/attack-paths/:correlationId`` renders a self-contained SVG graph
(deterministic layered layout, zoom/pan/reset, node selection) plus
availability chips and a side panel showing the selected node's type,
provenance, occurrence, source reference, field map, and evidence
references.  Sidebar entry **Attack Paths** under Analysis; correlation
detail offers **View attack path**.

Test mapping
------------

Backend ``tests/unit/test_attack_path_graph.py`` (38, SQLite):
contract vocabularies; correlation root node; detection/risk/indicator/
memory/hunt/policy-approval-soar relationship reads; edge referential
integrity; determinism; read-only immutability (``MutationSpy``); global
and per-surface bounds + truncation; secrets and prompt-injection safety.

Backend ``tests/unit/test_attack_path_api.py`` (5, live Postgres):
401 unauthenticated; 403 viewer + audit row; 200 deterministic envelope
with all node types; 404 unknown correlation; reads never create rows.

Frontend ``src/pages/attack-path-page.test.tsx`` (8): graph render with
nodes/edges; per-surface availability labels; node selection reveals
provenance + evidence references; truncation banner; empty state; API
failure + retry; loading; no-correlation prompt.

Verification state
------------------

* Backend full suite: **4785 passed / 3 skipped**.
* Frontend full suite: **79 passed**; `tsc -b --noEmit` and `eslint` clean.
* Alembic: head `8a1b2c3d4e5f` unchanged — **no migration added**
  (V2.21 is a pure read projection).
* No commit (per the change-freeze constraint).