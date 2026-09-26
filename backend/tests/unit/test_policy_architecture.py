"""Policy Decision architecture and dependency-isolation tests (Step 24).

Static guarantees of the Step 24 design, enforced by AST/source inspection
and the app's OpenAPI contract:

* the policy service package never executes arbitrary code (no
  ``eval``/``exec``/``compile``/``__import__``), never uses ``getattr``-
  style dynamic dispatch, and never names functions/callables from data;
* the policy package is a **decision layer only**: it imports no LLM
  SDK, no transport (fastapi/network/clients), no SQL/DB layer, no
  ``app.models`` ORM, no Kafka, no subprocess/OS execution, and no
  response/execution surface — the engine can never reach a host,
  account, file, or device and therefore *cannot* execute an action;
* the contract schema file is likewise non-procedural (no exec tokens,
  no forbidden imports, no free-form instruction fields);
* **no public API route was added** — Step 24 is a schema/service layer
  only; the OpenAPI contract contains no policy paths.
"""

from __future__ import annotations

import ast
from pathlib import Path

from app.main import app

POLICY_DIR = Path(__file__).resolve().parent.parent.parent / "app" / "services" / "policy"
POLICY_CORE_FILES = sorted(
    p for p in POLICY_DIR.glob("*.py") if p.name != "__init__.py"
)
SCHEMA_FILE = (
    Path(__file__).resolve().parent.parent.parent
    / "app" / "schemas" / "policy_decision.py"
)

#: Anything that could reach a host, account, file, device, model, or
#: message bus.  The policy engine must never import any of these.
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
    "os.path",
    "pickle",
    "gemini",
    "genai",
)

#: Root modules the policy core may import at all (whitelist-style guard).
ALLOWED_ROOTS = {
    "abc",
    "collections",
    "dataclasses",
    "enum",
    "functools",
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
    return {p.name: p.read_text(encoding="utf-8") for p in POLICY_CORE_FILES}


# ---------------------------------------------------------------------------
# 1. OpenAPI contract — no policy endpoint in Step 24
# ---------------------------------------------------------------------------


class TestOpenApiContract:
    def test_no_policy_path(self) -> None:
        spec = app.openapi()
        policy_paths = [p for p in spec["paths"] if "policy" in p]
        assert policy_paths == []

    def test_no_decision_endpoint(self) -> None:
        spec = app.openapi()
        for path in spec["paths"]:
            # The policy engine has no API surface ("decision" is guarded);
            # the V2.16 approval workflow owns "/approvals*" paths instead.
            assert "decision" not in path


# ---------------------------------------------------------------------------
# 2. No arbitrary execution / dynamic dispatch in the policy core
# ---------------------------------------------------------------------------


class TestNoArbitraryExecution:
    def test_no_eval_exec_compile_import(self) -> None:
        for name, source in _sources().items():
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    assert _call_name(node.func) not in {
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
                    assert not any(
                        forbidden in module for forbidden in FORBIDDEN_MODULES
                    ), f"{name} imports forbidden module {module}"

    def test_no_dynamic_attribute_dispatch(self) -> None:
        for name, source in _sources().items():
            assert "getattr(" not in source, name
            assert "__getattribute__" not in source, name

    def test_no_data_to_callable_bridge(self) -> None:
        # Rule data / input fields must never be turned into a call.
        for name, source in _sources().items():
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    fname = _call_name(node.func)
                    assert "model_" not in fname or fname in {
                        "model_dump",
                        "model_validate",
                        "model_copy",
                    }, f"{name} calls a non-serialization model method from the engine path"
                if isinstance(node, ast.Attribute):
                    assert node.attr not in {"__call__"}, name

    def test_contract_rejects_instruction_carrier_fields(self) -> None:
        from app.schemas.policy_decision import PolicyInput

        assert "function" not in PolicyInput.model_fields
        assert "callable" not in PolicyInput.model_fields
        assert "code" not in PolicyInput.model_fields
        assert "script" not in PolicyInput.model_fields


# ---------------------------------------------------------------------------
# 3. Decision-only: no transport, no DB, no model, no response surface
# ---------------------------------------------------------------------------


class TestDecisionOnly:
    def test_no_fs_or_shell_primitives(self) -> None:
        for name, source in _sources().items():
            for token in (
                "open(",
                "os.system",
                "os.popen",
                "subprocess",
                "shutil.",
                "pickle.load",
                "socket.",
                "httpx",
                "requests.",
                "urllib.",
                "gemini",
                "genai",
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

    def test_no_response_surface_imported(self) -> None:
        for name, source in _sources().items():
            assert "app.services.response" not in source, name
            assert "app.services.hitl" not in source, name
            assert "app.services.soar" not in source, name

    def test_engine_has_no_action_runners(self) -> None:
        engine_src = POLICY_DIR.joinpath("engine.py").read_text(encoding="utf-8")
        for token in ("def _block", "def _quarantine", "def _isolate",
                      "def _disable", "def _execute", "def execute(action"):
            assert token not in engine_src, token

    def test_no_decision_fabrication_without_evaluation(self) -> None:
        engine_src = POLICY_DIR.joinpath("engine.py").read_text(encoding="utf-8")
        identity_src = POLICY_DIR.joinpath("identity.py").read_text(encoding="utf-8")
        # The UUIDv5 derivation lives in exactly one place — the shared
        # identity module (the engine's single source of truth, also used
        # by the approval workflow to re-verify submitted decisions,
        # H2.F-01).  The engine always routes decision assembly through
        # this derivation, so an identity is never fabricated inline.
        assert "uuid5" in identity_src
        assert "derive_policy_decision_id" in identity_src
        assert "derive_policy_decision_id" in engine_src
        assert "policy_decision_id_content" in engine_src
        assert "decide" in engine_src

    def test_registry_is_declarative_only(self) -> None:
        registry_src = POLICY_DIR.joinpath("registry.py").read_text(encoding="utf-8")
        assert "sorted(" in registry_src
        assert "model_copy(deep=True)" in registry_src


# ---------------------------------------------------------------------------
# 4. Contract schema file — non-procedural, isolated
# ---------------------------------------------------------------------------


class TestSchemaIsolation:
    def test_schema_no_exec_or_http(self) -> None:
        source = SCHEMA_FILE.read_text(encoding="utf-8")
        for token in ("__import__", "getattr(", "httpx", "requests.",
                      "socket.", "subprocess", "eval(", "exec("):
            assert token not in source, token
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Only a bare `compile(...)` is the exec primitive;
                # `re.compile(...)` (ast.Attribute) is fine.
                if isinstance(node.func, ast.Name):
                    assert node.func.id not in {"eval", "exec", "compile"}, (
                        f"policy_decision.py calls {node.func.id}"
                    )
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                module = getattr(node, "module", "") or ""
                assert not any(
                    forbidden in module for forbidden in FORBIDDEN_MODULES
                ), f"policy_decision.py imports forbidden module {module}"

    def test_schema_is_contract_only(self) -> None:
        source = SCHEMA_FILE.read_text(encoding="utf-8")
        assert "class PolicyInput(BaseModel)" in source
        assert "class PolicyRule(BaseModel)" in source
        assert "class PolicyDecision(BaseModel)" in source
        # Only declared validation helpers and the ranking helper are
        # permitted; anything else is evaluation logic leaking into the
        # contract.
        declared = {
            "def _assert_json_compatible(value: Any, field: str) -> None:",
            "def _assert_no_secrets(value: Any, field: str) -> None:",
            "def _json_clone(value: dict[str, Any]) -> dict[str, Any]:",
            "def _require_non_blank(value: str, field: str) -> str:",
            "def _ensure_tz_aware(value: datetime, field: str) -> datetime:",
            #: Metadata depth/size bound is a declaration-only validation
            #: helper (same class as the others above), not evaluation logic.
            "def _ensure_metadata_bounded(value: dict[str, Any], field: str) -> dict[str, Any]:",
            "def risk_rank(level: RiskLevel) -> int:",
        }
        for line in source.splitlines():
            if line.startswith("def "):
                assert line in declared, f"unexpected function: {line}"

    def test_no_policy_service_imported_by_routes(self) -> None:
        # No HTTP route may reach the policy engine.  The V2.16 approval
        # route legitimately references the words "policy" (reason copy) and
        # "decision" (the decision it routes), so the guarantee is scoped to
        # imports: the policy *service* stays out of the API surface while
        # the policy *schema* remains a shared vocabulary everywhere.
        routes_dir = (
            Path(__file__).resolve().parent.parent.parent / "app" / "api" / "routes"
        )
        for route_file in routes_dir.glob("*.py"):
            source = route_file.read_text(encoding="utf-8")
            assert "from app.services.policy" not in source, route_file.name
            assert "app.services.policy" not in source, route_file.name