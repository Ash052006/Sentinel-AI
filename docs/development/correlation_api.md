# Correlation API (Step 10E)

## 1. Purpose

Step 10E exposes the read-only correlation query surface built in Step 10D
(`CorrelationQueryService`) through the existing FastAPI application. It lets
authorized users (admin, analyst, ciso) retrieve persisted correlation results
and their members via HTTP without needing direct database access.

Step 10E exposes read-only correlation queries through the API. It does not
create correlations, calculate risk, create incidents, map MITRE ATT&CK, or
perform response.

## 2. Architecture

`backend/app/api/routes/correlations.py` is a thin transport layer. Every
handler performs the same flow:

1. Authentication via the existing JWT `HTTPBearer` scheme.
2. Authorization via the existing `require_role("admin", "analyst", "ciso")`
   dependency.
3. A caller-owned `Session` obtained from the existing `get_db` dependency.
4. A single call to `CorrelationQueryService` (`app/services/correlation_query.py`).
5. Serialization of the returned `CorrelationResultRecord` /
   `CorrelationPage` objects (from `app/schemas/correlation_query.py`).

Route handlers do not perform SQL, call repositories, or reference database
models directly. All persistence reads happen inside
`CorrelationQueryService`, which delegates to
`CorrelationPersistenceService`.

Routes are registered in `backend/app/api/router.py` under the
`/api/correlations` prefix with tag `Correlations`.

## 3. Endpoints

| Method | Path | Handler | Description |
| ------ | ---- | ------- | ----------- |
| GET | `/api/correlations/recent` | `recent_correlations` | Newest correlations across all detections. |
| GET | `/api/correlations/detection/{detection_id}` | `correlations_for_detection` | Correlations linked to one detection. |
| GET | `/api/correlations/event/{event_id}` | `correlations_for_event` | Correlations linked to one event. |
| GET | `/api/correlations/{correlation_id}` | `get_correlation` | Single correlation by its UUID. |

The static `/recent` route is registered before `/detection/{detection_id}`,
`/event/{event_id}`, and `/{correlation_id}` so FastAPI's path matching never
treats `recent` as a UUID parameter.

## 4. Authentication

All endpoints use the application's existing stateless JWT bearer
authentication. Requests must send:

```
Authorization: Bearer <access_token>
```

Requests without a valid token receive `401 Unauthorized`. The token subject is
resolved to a user by the standard `get_current_user` dependency
(`app/api/dependencies.py`).

## 5. RBAC

The endpoint set is restricted to the SOC roles:

```
admin, analyst, ciso
```

Authorization is enforced by `require_role("admin", "analyst", "ciso")`. Any
authenticated user outside these roles receives `403 Forbidden`. The denial is
recorded by the standard authorization-audit behavior of the dependency.

Successful read-only retrievals are intentionally not audit-logged. This
mirrors the existing Detection API convention: reads are not audited; only
authorization denials are.

## 6. Request Parameters

Path parameters are UUIDs (as strings in the URL):

- `correlation_id` — the correlation result UUID.
- `detection_id` — the detection UUID.
- `event_id` — the event UUID.

Invalid UUID strings are rejected by FastAPI path validation with `422
Unprocessable Entity`.

Pagination and limits are query parameters:

- `page` (default `1`) — one-based page number for collection endpoints.
- `page_size` (default `50`, max `200`) — items per page for `/detection/...`
  and `/event/...`.
- `limit` (default `50`, max `200`) — max items for `/recent`.

`page` must be a positive integer; `page_size`/`limit` must be integers in
`[1, 200]`. Out-of-range values produce `422`.

## 7. Response Schemas

- `GET /api/correlations/{correlation_id}` returns a single
  `CorrelationResultRecord`.
- `GET /api/correlations/recent` returns `list[CorrelationResultRecord]`.
- `GET /api/correlations/detection/{detection_id}` and
  `GET /api/correlations/event/{event_id}` return `CorrelationPage`
  (`{items, total, page, page_size}`).

Every correlation carries its invariant shape: `correlation_id`, `status`,
`confidence`, `evidence`, `result_metadata`, `timestamp`, `provenance`, and
`members` (each with `detection_id`, `event_id`, `timestamp`, `member_order`),
plus row identity and lifecycle timestamps.

## 8. Pagination

Collection endpoints accept `page`/`page_size` (and `/recent` accepts `limit`)
with bounds inherited from Step 10D: default page size `50`, maximum `200`,
recent default `50`, maximum `200`. When a requested page exceeds the available
data the response is an empty `items` list within a valid page object (total is
still returned); it is not an error.

## 9. Ordering

Ordering is deterministic and inherited from Step 10D:

- Collections and the recent feed are sorted by `timestamp DESC` then
  `correlation_id ASC`.
- Members within a correlation preserve persisted `member_order`.

## 10. Error Responses

All errors are consistent with the rest of the application:

| Status | Meaning | Body behavior |
| ------ | ------- | ------------- |
| 401 | Missing/invalid bearer token | Standard auth error. |
| 403 | Authenticated but not admin/analyst/ciso | Standard authorization error; denial audited. |
| 404 | Correlation UUID not found | `{"detail": "Correlation not found"}`. |
| 422 | Invalid UUID, page, page_size, or limit | FastAPI validation detail. |
| 503 | Correlation data temporarily unavailable | `{"detail": "Correlation data is unavailable"}`. |

`CorrelationQueryValidationError` maps to `422`, and
`CorrelationQueryError`/lower layer failures map to `503`. Unknown exceptions
fall through to the application's centralized handler, which returns a generic
`500 Internal Server Error` without leaking internals.

## 11. Security and Redaction

- The API is read-only and performs no mutation; nothing it returns can alter
  state.
- Secrets are filtered out during correlation persistence (Step 10C/10D), and
  this API reuses that safe layer verbatim. It introduces no serializer that
  weakens redaction.
- The exact-match schema contract (Step 10A) forbids secret keys from
  surviving correlation storage, so redacted output is the only possible
  response.
- Failure messages never include SQL, stack traces, or internal details.

## 12. Read-Only Contract

The router exposes only `GET` operations. There are no POST/PUT/PATCH/DELETE
correlation endpoints, and no endpoint mutates correlation state, creates
correlations, or triggers background work. The read-only contract is enforced
by a unit test that inspects the OpenAPI spec (all routes `GET` only).

## 13. Query-Service Delegation

Every handler delegates to `CorrelationQueryService`:

- `get_correlation(db, correlation_id)`
- `list_correlations_for_detection(db, detection_id, page, page_size)`
- `list_correlations_for_event(db, event_id, page, page_size)`
- `list_recent_correlations(db, limit)`

`CorrelationQueryService` handles all SQL/repository interaction internally and
is the single authority for validation, ordering, and limit bounds. A unit test
inspects the route module source and asserts it contains no direct SQL/database
access. A delegation test swaps the module service for a probe to verify
handlers call the service with the exact arguments the client supplied.

## 14. OpenAPI

The routes are registered in the existing `/api` router, so they appear in
`/openapi.json` under `/api/correlations/*` with tag `Correlations`, security
`HTTPBearer`, and unique operation ids. Tests in
`tests/unit/test_correlation_api.py` verify each route's presence, tag,
security requirement, and that no other HTTP methods are exposed.

## 15. Testing

- `tests/unit/test_correlation_api.py` — 47 tests covering authentication,
  RBAC, single lookup, detection/event collections, recent feed, pagination
  bounds, route ordering, error sanitization, secret redaction, the read-only
  contract, service delegation, source-level no-direct-DB checks, and OpenAPI
  registration.
- The tests run through `TestClient(app)` against the real local PostgreSQL
  database via the existing `tests/conftest.py` fixtures (real
  `SessionLocal`, real seeded users, real JWT tokens), so the API test suite
  doubles as the live PostgreSQL verification.
- Full suite: `1912 passed` (baseline `1865` + `47` new API tests).

## 16. Non-Goals

Step 10E exposes read-only correlation queries through the API. It does not
create correlations, calculate risk, create incidents, map MITRE ATT&CK, or
perform response. There are no correlation-creation/update/delete endpoints, no
frontend changes, no Kafka consumers/producers, no OpenSearch/Qdrant/Neo4j
integration, and no schema migration (the Alembic head is unchanged).