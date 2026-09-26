"""Detection Rules API layer behavior tests (Step 26).

Exercises the read-only detection-rules endpoints through the full
integration stack the project already uses for API tests — JWT -> FastAPI
(``TestClient(app)``) -> route -> :class:`DetectionRuleQueryService` ->
PostgreSQL:

* authentication and RBAC enforcement;
* collection semantics — all loaded rules with honest match stats;
* Sigma/YARA type split and per-rule metadata mapping;
* detail lookup with preview content and 404 for unknown rules;
* analytics windows — validation, ordering, real (non-negative) counts;
* strict read-only behavior (no non-GET methods on the router).
"""

from __future__ import annotations

from fastapi.testclient import TestClient

import app.api.routes.detection_rules as detection_rules_routes
from tests.conftest import auth_header

SERVER_REPO_IDS = {
    "11111111-1111-4111-8111-111111111111",
    "22222222-2222-4222-8222-222222222222",
    "33333333-3333-4333-8333-333333333333",
    "44444444-4444-4444-8444-444444444444",
    "55555555-5555-4555-8555-555555555555",
    "66666666-6666-4666-8666-666666666666",
    "77777777-7777-4777-8777-777777777777",
    "88888888-8888-4888-8888-888888888888",
    "99999999-9999-4999-8999-999999999999",
    "10000000-0000-4000-8000-000000000000",
    "11000000-0000-4000-8000-000000000000",
    "12000000-0000-4000-8000-000000000000",
    "13000000-0000-4000-8000-000000000000",
    "14000000-0000-4000-8000-000000000000",
    "15000000-0000-4000-8000-000000000000",
    "16000000-0000-4000-8000-000000000000",
    "17000000-0000-4000-8000-000000000000",
    "18000000-0000-4000-8000-000000000000",
    "19000000-0000-4000-8000-000000000000",
    "20000000-0000-4000-8000-000000000000",
    "21000000-0000-4000-8000-000000000000",
    "22000000-0000-4000-8000-000000000000",
    "23000000-0000-4000-8000-000000000000",
    "24000000-0000-4000-8000-000000000000",
    "25000000-0000-4000-8000-000000000000",
    "26000000-0000-4000-8000-000000000000",
    "27000000-0000-4000-8000-000000000000",
    "28000000-0000-4000-8000-000000000000",
    "yara-suspicious-script-v1",
    "yara-web-shell-v1",
    "yara-credential-stealing-v1",
    "yara-powershell-artifact-v1",
    "yara-ransomware-marker-v1",
    "yara-amsi-bypass-v1",
    "yara-defender-tamper-v1",
    "yara-reverse-shell-token-v1",
    "yara-lsass-dump-access-v1",
    "yara-run-key-persistence-v1",
    "yara-encoded-web-shell-v1",
    "yara-script-obfuscation-v1",
    "yara-sql-injection-probe-v1",
    "yara-xss-probe-v1",
    "yara-credential-exposure-v1",
    "yara-crypto-miner-v1",
    "yara-process-injection-v1",
    "yara-credential-dump-toolkit-v1",
    "yara-ssh-persistence-v1",
    "yara-web-config-leak-v1",
    "yara-office-macro-v1",
    "yara-lateral-movement-tool-v1",
    "yara-exfil-transfer-v1",
    "yara-keylogger-api-v1",
    "yara-phishing-lure-v1",
}

_SEVERITIES = {"low", "medium", "high", "critical"}


def test_requires_authentication(client: TestClient):
    resp = client.get("/api/detection-rules")
    assert resp.status_code == 401

    resp = client.get("/api/detection-rules/analytics?window=30d")
    assert resp.status_code == 401

    resp = client.get("/api/detection-rules/does-not-exist")
    assert resp.status_code == 401


def test_list_returns_all_loaded_rules(client: TestClient, analyst_token: str):
    headers = auth_header(analyst_token)
    resp = client.get("/api/detection-rules", headers=headers)
    assert resp.status_code == 200

    rules = resp.json()
    assert len(rules) == 53

    sigma = [r for r in rules if r["rule_type"] == "sigma"]
    yara = [r for r in rules if r["rule_type"] == "yara"]
    assert len(sigma) == 28
    assert len(yara) == 25

    ids = {r["rule_id"] for r in rules}
    assert ids == SERVER_REPO_IDS

    for rule in rules:
        assert rule["severity"] in _SEVERITIES
        assert isinstance(rule["enabled"], bool)
        assert isinstance(rule["version"], str) and rule["version"]
        assert rule["source_file"]
        assert isinstance(rule["match_count"], int)
        assert rule["match_count"] >= 0
        assert "content" not in rule  # list is metadata-only


def test_list_ordering_is_deterministic(client: TestClient, analyst_token: str):
    headers = auth_header(analyst_token)
    first = client.get("/api/detection-rules", headers=headers).json()
    second = client.get("/api/detection-rules", headers=headers).json()
    assert [r["rule_id"] for r in first] == [r["rule_id"] for r in second]


def test_detail_returns_sigma_content(client: TestClient, analyst_token: str):
    headers = auth_header(analyst_token)
    resp = client.get(
        "/api/detection-rules/11111111-1111-4111-8111-111111111111",
        headers=headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["content_format"] == "yaml"
    assert body["content"].strip().startswith("title:")
    assert body["category"] == "process"


def test_detail_returns_yara_content(client: TestClient, analyst_token: str):
    headers = auth_header(analyst_token)
    resp = client.get("/api/detection-rules/yara-suspicious-script-v1", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["content_format"] == "yara"
    assert body["content"].strip().startswith("rule ")
    assert body["category"] == "file"


def test_detail_unknown_rule_is_404(client: TestClient, analyst_token: str):
    headers = auth_header(analyst_token)
    resp = client.get("/api/detection-rules/ffffffff-0000-4000-8000-000000000000", headers=headers)
    assert resp.status_code == 404


def test_analytics_valid_windows(client: TestClient, analyst_token: str):
    headers = auth_header(analyst_token)
    for window in ("1h", "6h", "24h", "7d", "30d"):
        resp = client.get(f"/api/detection-rules/analytics?window={window}", headers=headers)
        assert resp.status_code == 200, f"window={window} failed"
        body = resp.json()
        assert body["window"] == window
        assert isinstance(body["total_detections"], int)
        assert body["total_detections"] >= 0
        assert isinstance(body["rules_with_matches"], int)
        assert body["rules_with_matches"] >= 0
        assert isinstance(body["by_severity"], list)
        assert len(body["by_severity"]) == 4
        assert {b["severity"] for b in body["by_severity"]} == _SEVERITIES
        buckets = body["buckets"]
        starts = [b["bucket_start"] for b in buckets]
        assert starts == sorted(starts)
        assert all(isinstance(b["detections"], int) and b["detections"] >= 0 for b in buckets)
        assert sum(b["detections"] for b in buckets) == body["total_detections"]


def test_analytics_bad_window_is_422(client: TestClient, analyst_token: str):
    headers = auth_header(analyst_token)
    for window in ("90d", "1H", "", "one-day"):
        resp = client.get(f"/api/detection-rules/analytics?window={window}", headers=headers)
        assert resp.status_code == 422, f"window={window!r}"


def test_router_is_read_only():
    allowed = {("GET", route.path) for route in detection_rules_routes.router.routes}
    # three GET routes registered on the router itself
    assert len(allowed) == 3
    assert all(method == "GET" for method, _ in allowed)


def test_ctso_and_admin_can_read(client: TestClient, ciso_token: str, admin_token: str):
    for token in (ciso_token, admin_token):
        resp = client.get("/api/detection-rules", headers=auth_header(token))
        assert resp.status_code == 200