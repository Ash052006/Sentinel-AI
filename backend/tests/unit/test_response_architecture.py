"""Response & Mitigation architecture and isolation tests (Step 25).

Static guarantees of the Step 25 design, enforced by AST/source
inspection and the app's OpenAPI contract:

* the response service package never executes arbitrary code (no
  ``eval``/``exec``/``compile``/``__import__``), never uses ``getattr``-
  style dynamic dispatch, never calls callables from data, and has no
  shell/OS/filesystem/network surface;
* the response package is a **policy-consequence layer**: it imports
  policy *schemas* (the shared vocabulary) but never the policy *service*
  — it can never re-judge or override a decision;
* real-system reach is structurally impossible: no ``subprocess``,
  ``os``, open(), shutil, pickle, socket, httpx, requests, urllib,
  gemini/genai, sqlalchemy, kafka, qdrant, or app.models anywhere in the
  package;
* the contract schema file is non-procedural and carries no instruction
  fields (no function/callable/code/script/command channels);
* **no response API route and no migration were added** — Step 25 is a
  schema/service layer only; the OpenAPI contract has no response paths
  and no route module imports the response service package.

V2.18 relaxes that only for the dedicated SOAR domain (``/api/soar``), so
the no-path guard here carves out that namespace while still pinning that
the Step 25 response surface itself has no endpoints.
"""

from __future__ import annotations

import ast
from pathlib import Path

from app.main import app

RESPONSE_DIR = Path(__file__).resolve().parent.parent.parent / "app" / "services" / "response"
RESPONSE_CORE_FILES = sorted(
    p for p in RESPONSE_DIR.glob("*.py") if p.name != "__init__.py"
)
SCHEMA_FILE = (
    Path(__file__).resolve().parent.parent.parent
    / "app" / "schemas" / "response.py"
)
ROUTES_DIR = (
    Path(__file__).resolve().parent.parent.parent / "app" / "api" / "routes"
)

#: Anything that could reach a host, account, file, device, model,
#: message bus, or the decision-making engine.  The response layer must
#: import none of these.
FORBIDDEN_MODULES = (
    "fastapi",
    "sqlalchemy",
    "kafka",
    "qdrant",
    "subprocess",
    "socket",
    "httpx",
    "requests",
    "urllib",
    "app.models",
    "app.agents",
    "app.main",
    "app.services.policy",
    "app.services.hitl",
    "app.services.soar",
    "os",
    "pickle",
    "gemini",
    "genai",
)

#: Root modules the response core may import at all (whitelist-style guard).
ALLOWED_ROOTS = {
    "abc",
    "collections",
    "dataclasses",
    "enum",
    "functools",
    "hashlib",
    "ipaddress",
    "json",
    "logging",
    "math",
    "re",
    "typing",
    "time",
    "datetime",
    "uuid",
    "__future__",
    "app",
    "pydantic",
}


def _call_name(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _sources() -> dict[str, str]:
    return {p.name: p.read_text(encoding="utf-8") for p in RESPONSE_CORE_FILES}


# ---------------------------------------------------------------------------
# 1. OpenAPI contract — no response endpoint in Step 25
# ---------------------------------------------------------------------------


class TestOpenApiContract:
    def test_no_response_path(self) -> None:
        spec = app.openapi()
        forbidden_terms = (
            "response",
            "mitigat",
            "block",
            "quarantine",
            "disable",
            "isolate",
            "terminate",
            "action",
            "execut",
            "hitl",
        )
        # V2.18 legitimately adds the dedicated, sandbox/mock SOAR domain
        # under /api/soar; the Step 25 Response *service* itself still has
        # no API surface, so its terms are checked on every other path.
        for path in spec["paths"]:
            if "/api/soar/" in path:
                continue
            lowered = path.lower()
            assert not any(term in lowered for term in forbidden_terms), path

    def test_no_route_module_imports_response_service(self) -> None:
        for route_file in ROUTES_DIR.glob("*.py"):
            source = route_file.read_text(encoding="utf-8")
            assert "app.services.response" not in source, route_file.name


# ---------------------------------------------------------------------------
# 2. No arbitrary execution / dynamic dispatch / system reach
# ---------------------------------------------------------------------------


class TestNoArbitraryExecution:
    def test_no_eval_exec_compile_import(self) -> None:
        for name, source in _sources().items():
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        assert node.func.id not in {
                            "eval",
                            "exec",
                            "compile",
                            "__import__",
                        }, f"{name} calls a forbidden exec primitive"
                if isinstance(node, ast.Name):
                    assert node.id not in {
                        "eval",
                        "exec",
                        "compile",
                        "globals",
                        "locals",
                        "vars",
                    }, f"{name} references a forbidden exec primitive"
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    module = getattr(node, "module", "") or ""
                    for alias in getattr(node, "names", ()) if isinstance(node, ast.Import) else ():
                        if not module:
                            module = alias.name
                    assert not any(
                        forbidden in module for forbidden in FORBIDDEN_MODULES
                    ), f"{name} imports forbidden module {module}"

    def test_no_dynamic_attribute_dispatch(self) -> None:
        for name, source in _sources().items():
            assert "getattr(" not in source, name
            assert "vars(" not in source, name
            assert "__getattribute__" not in source, name
            assert ".__call__" not in source, name
            # Model methods must stay serialization-only on this path.
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    fname = _call_name(node.func)
                    assert "model_" not in fname or fname in {
                        "model_dump",
                        "model_validate",
                        "model_copy",
                    }, f"{name} calls a non-serialization model method"

    def test_no_fs_shell_network_or_device_primitives(self) -> None:
        for name, source in _sources().items():
            for token in (
                "open(",
                "os.system",
                "os.popen",
                "os.remove",
                "os.unlink",
                "os.environ",
                "subprocess",
                "shutil.",
                "pickle.",
                "socket.",
                "httpx",
                "requests.",
                "urllib.",
                "gemini",
                "genai",
                "time.sleep",
                "iptables",
                "powershell",
                "kill(",
                "shutdown",
            ):
                assert token not in source, f"{name} must not contain {token}"

    def test_import_whitelist(self) -> None:
        for name, source in _sources().items():
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    root = (node.module or "").split(".")[0]
                    assert root in ALLOWED_ROOTS, f"{name} imports {root}"
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        root = alias.name.split(".")[0]
                        assert root in ALLOWED_ROOTS, f"{name} imports {root}"


# ---------------------------------------------------------------------------
# 3. Policy-consequence only: never re-judges, never reaches a host
# ---------------------------------------------------------------------------


class TestPolicyConsequenceOnly:
    def test_no_policy_service_import(self) -> None:
        for name, source in _sources().items():
            assert "app.services.policy" not in source, name
            assert "app.services.hitl" not in source, name
            assert "app.services.soar" not in source, name

    def test_shares_action_vocabulary_with_policy_schema(self) -> None:
        contracts = RESPONSE_DIR.joinpath("contracts.py").read_text(
            encoding="utf-8"
        )
        assert "from app.schemas.policy_decision import" in contracts
        assert "ResponseActionType" in contracts
        import app.schemas.response
        import app.schemas.policy_decision

        assert (
            app.schemas.response.ResponseActionType
            is app.schemas.policy_decision.ResponseActionType
        )

    def test_executor_provides_no_user_dispatch(self) -> None:
        executor = RESPONSE_DIR.joinpath("executor.py").read_text(
            encoding="utf-8"
        )
        assert "provider_for" in executor  # deterministic registry lookup
        assert "getattr(" not in executor
        assert "import_module" not in executor

    def test_registry_is_explicit_and_deterministic(self) -> None:
        registry = RESPONSE_DIR.joinpath("registry.py").read_text(
            encoding="utf-8"
        )
        assert "duplicate registration" in registry
        assert "sorted(" in registry

    def test_service_has_no_decision_authority(self) -> None:
        service = RESPONSE_DIR.joinpath("service.py").read_text(
            encoding="utf-8"
        )
        assert "PolicyDecisionEngine(" not in service
        assert "from app.services.policy" not in service
        assert "decide(" not in service
        assert service.count("execute(") >= 1  # facade forwards only

    def test_no_persistence_surface(self) -> None:
        for name, source in _sources().items():
            low = source.lower()
            assert "sqlalchemy" not in low, name
            assert "asyncpg" not in low, name
            assert "psycopg" not in low, name
            assert "kafka" not in low, name
            assert "qdrant" not in low, name


# ---------------------------------------------------------------------------
# 4. Contract schema file — non-procedural, isolated
# ---------------------------------------------------------------------------


class TestSchemaIsolation:
    def test_schema_no_exec_or_http(self) -> None:
        source = SCHEMA_FILE.read_text(encoding="utf-8")
        for token in (
            "__import__",
            "getattr(",
            "httpx",
            "requests.",
            "socket.",
            "subprocess",
            "eval(",
            "exec(",
            "os.",
        ):
            assert token not in source, token
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    assert node.func.id not in {"eval", "exec", "compile"}, (
                        f"response.py calls {node.func.id}"
                    )
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                module = getattr(node, "module", "") or ""
                assert not any(
                    forbidden in module for forbidden in FORBIDDEN_MODULES
                ), f"response.py imports forbidden module {module}"

    def test_schema_helper_functions_are_limited(self) -> None:
        source = SCHEMA_FILE.read_text(encoding="utf-8")
        declared = {
            "def _assert_json_compatible(value: Any, field: str) -> None:",
            "def _assert_no_secrets(value: Any, field: str) -> None:",
            "def _json_clone(value: dict[str, Any]) -> dict[str, Any]:",
            "def _require_non_blank(value: str, field: str) -> str:",
            "def _ensure_tz_aware(value: datetime, field: str) -> datetime:",
            "def _ensure_metadata_bounded(value: dict[str, Any], field: str) -> dict[str, Any]:",
            "def _reject_control_characters(value: str, field: str) -> str:",
        }
        for line in source.splitlines():
            if line.startswith("def ") and not line.startswith("def depth"):
                assert line in declared, f"unexpected function: {line}"

    def test_contract_rejects_instruction_carrier_fields(self) -> None:
        from app.schemas.response import ResponseRequest

        for field in ("function", "callable", "code", "script", "command",
                      "prompt", "instructions"):
            assert field not in ResponseRequest.model_fields, field


# ---------------------------------------------------------------------------
# 5. No migration was added by Step 25
# ---------------------------------------------------------------------------


class TestNoMigration:
    def test_no_response_migration_file(self) -> None:
        backend_root = (
            Path(__file__).resolve().parent.parent.parent
        )
        migrations_dir = (
            backend_root
            / "app" / "database" / "postgres" / "migrations" / "versions"
        )
        migration_files = (
            sorted(migrations_dir.glob("*.py"))
            if migrations_dir.is_dir()
            else []
        )
        assert migration_files, "expected the pre-existing migrations dir"
        # No migration may introduce any response-execution persistence
        # (table/model names for the Step 25 layer).  The pre-existing
        # incident-memory migration legitimately mentions "mitigation"
        # as a MemoryOutcome vocabulary word, so the scan is scoped to
        # response layer identifiers only.
        scoped_tokens = (
            "response_result",
            "response_request",
            "response_attempt",
            "response_execution",
            "responseresult",
            "responserequest",
        )
        for p in migration_files:
            body = p.read_text(encoding="utf-8", errors="ignore").lower()
            assert not any(token in body for token in scoped_tokens), p.name