"""Natural Language SOC architecture and dependency-isolation tests (Step 23).

Static guarantees of the Step 23 design, enforced by AST/source inspection
and the app's OpenAPI contract:

* exactly one Natural Language SOC endpoint (``POST /api/soc/query``), with
  no path collisions and no non-POST method;
* the SOC core package never executes arbitrary code (no ``eval``/``exec``/
  ``compile``/``__import__``), never uses ``getattr``-style dynamic dispatch
  in the parse/execute chain, and dispatch happens only through the
  allowlist registry dict;
* the SOC core files never import ``fastapi`` (transport lives only in the
  thin API route), nor directly import ``sqlalchemy``, Kafka, Qdrant,
  ``app.models``, OS/shell facility — the LLM can never express a
  database, transport, or filesystem primitive;
* the executor pins ``read_only=True`` and every validated intent passes
  through the shared registry before execution;
* the LLM is constrained via the ``SOC_INTENT_MODEL_JSON_SCHEMA`` and its
  output is never allowed to name functions/callables.
"""

from __future__ import annotations

import ast
from pathlib import Path

from app.main import app
from app.schemas.soc_query import (
    SOC_INTENT_MODEL_JSON_SCHEMA,
    SOCQueryResponse,
)

SOC_DIR = Path(__file__).resolve().parent.parent.parent / "app" / "services" / "soc"
SOC_CORE_FILES = sorted(
    p for p in SOC_DIR.glob("*.py") if p.name != "__init__.py"
)

FORBIDDEN_MODULES = (
    "fastapi",
    "sqlalchemy",
    "kafka",
    "qdrant",
    "subprocess",
    "app.models",
    "os.path",
    "pickle",
)

#: Root modules the SOC core may import at all (whitelist-style guard).
ALLOWED_ROOTS = {
    "abc",
    "dataclasses",
    "json",
    "logging",
    "typing",
    "time",
    "datetime",
    "__future__",
    "app",
    "pydantic",
    "httpx",
}


def _call_name(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _sources() -> dict[str, str]:
    return {p.name: p.read_text(encoding="utf-8") for p in SOC_CORE_FILES}


# ---------------------------------------------------------------------------
# 1. OpenAPI contract — exactly one SOC endpoint, POST only
# ---------------------------------------------------------------------------


class TestOpenApiContract:
    def test_single_endpoint_no_collisions(self) -> None:
        spec = app.openapi()
        soc_paths = [p for p in spec["paths"] if "soc" in p]
        assert soc_paths == ["/api/soc/query"]

    def test_post_only(self) -> None:
        spec = app.openapi()
        methods = set(spec["paths"]["/api/soc/query"])
        assert methods == {"post"}


# ---------------------------------------------------------------------------
# 2. No arbitrary execution / dynamic dispatch in the SOC core
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
        # The parse/execute chain never resolves members by name from any
        # model-derived string (that would be the LLM-to-callable bridge).
        for filename in (
            "executor.py",
            "engine.py",
            "gemini.py",
            "parser.py",
            "formatter.py",
        ):
            source = SOC_DIR.joinpath(filename).read_text(encoding="utf-8")
            assert "getattr(" not in source, filename
            assert "__getattribute__" not in source, filename

    def test_executor_dispatch_is_registry_dict_only(self) -> None:
        executor_src = SOC_DIR.joinpath("executor.py").read_text(encoding="utf-8")
        assert "_handlers.get((" in executor_src
        assert "handler.call(db" in executor_src

    def test_no_function_name_surfaces_from_llm(self) -> None:
        from app.schemas.soc_query import SOCModelIntent

        assert "function" not in SOCModelIntent.model_fields
        assert "callable" not in SOCModelIntent.model_fields
        schema_keys = " ".join(SOC_INTENT_MODEL_JSON_SCHEMA["properties"])
        assert "function" not in schema_keys

    def test_no_shell_code_strings_in_prompt_contract(self) -> None:
        from app.services.soc.prompt import SYSTEM_INSTRUCTION

        for forbidden in ("SELECT ", "sh -c", "os.system", "subprocess", "DELETE"):
            assert forbidden not in SYSTEM_INSTRUCTION

    def test_read_only_pinned_by_executor(self) -> None:
        executor_src = SOC_DIR.joinpath("executor.py").read_text(encoding="utf-8")
        assert "read_only=True" in executor_src
        annotation = SOCQueryResponse.model_fields["read_only"].annotation
        assert str(annotation).startswith("typing.Literal[True]")

    def test_results_are_serialized_not_raw_objects(self) -> None:
        executor_src = SOC_DIR.joinpath("executor.py").read_text(encoding="utf-8")
        assert 'model_dump(mode="json")' in executor_src


# ---------------------------------------------------------------------------
# 3. Filesystem / OS isolation and import whitelist
# ---------------------------------------------------------------------------


class TestOsIsolation:
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

    def test_only_gemini_uses_http_transport(self) -> None:
        for name, source in _sources().items():
            if "httpx" in source:
                assert name == "gemini.py"


# ---------------------------------------------------------------------------
# 4. Grammar consistency between prompt, registry, and schema
# ---------------------------------------------------------------------------


class TestGrammarConsistency:
    def test_prompt_grammar_covers_registry(self) -> None:
        from app.services.soc.prompt import SYSTEM_INSTRUCTION
        from app.services.soc.registry import specs

        resources = {spec.resource.value for spec in specs()}
        for spec in specs():
            assert spec.resource.value in resources
            assert spec.operation.value in SYSTEM_INSTRUCTION
            assert spec.resource.value in SYSTEM_INSTRUCTION

    def test_registry_is_single_source_for_specs(self) -> None:
        from app.services.soc import validator
        from app.services.soc.registry import HANDLERS, specs

        assert len(specs()) == len(HANDLERS)
        by_key = {(s.resource, s.operation) for s in specs()}
        assert by_key == set(HANDLERS)
        assert hasattr(validator, "registry")

    def test_executor_binds_registry_handlers_by_default(self) -> None:
        from app.services.soc.executor import SOCQueryExecutor
        from app.services.soc.registry import HANDLERS

        executor = SOCQueryExecutor()
        assert executor._handlers is HANDLERS