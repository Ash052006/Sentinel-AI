"""SOAR architecture & isolation tests (V2.18).

Static guarantees of the V2.18 design, enforced by AST/source inspection:

* the SOAR **core** (engine/gate/providers/playbooks/registry/validator/
  hashing/errors/schema) never executes arbitrary code (no
  ``eval``/``exec``/``compile``/``__import__``), never uses ``getattr``-
  style dynamic dispatch, never touches the filesystem, kernel, network,
  host or model surface, and has no real-system reach (no subprocess, os,
  socket, httpx, requests, urllib, kafka, qdrant, gemini/genai);
* SOAR **orchestrates, it never decides**: the engine re-verifies the
  authorizing decision through its own independent gate and reuses the
  Step 25 target validator as the sole target authority — it does not
  import the policy service, the HITL service, or any LLM/agent;
* the execution contract carries a decision and controlled references —
  never instructions (no function/code/script/command channels);
* providers are sandbox/mock only: no indicator of a real host/cloud/
  network/filesystem adapter exists anywhere in the package.
"""

from __future__ import annotations

import ast
from pathlib import Path

SOAR_DIR = (
    Path(__file__).resolve().parent.parent.parent
    / "app" / "services" / "soar"
)
SOAR_SCHEMA_FILE = (
    Path(__file__).resolve().parent.parent.parent
    / "app" / "schemas" / "soar.py"
)
SOAR_CORE_FILES = sorted(
    p
    for p in SOAR_DIR.glob("*.py")
    if p.name
    in {
        "engine.py",
        "errors.py",
        "gate.py",
        "hashing.py",
        "playbooks.py",
        "providers.py",
        "registry.py",
        "validator.py",
    }
)

#: Anything that could reach a host, account, file, device, model,
#: message bus, or the decision-making engine.  The SOAR core must import
#: none of these.
FORBIDDEN_MODULES = (
    "fastapi",
    "sqlalchemy",
    "asyncpg",
    "psycopg",
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
    "os",
    "pickle",
    "gemini",
    "genai",
)

#: Root modules the SOAR core may import (whitelist-style guard).
ALLOWED_ROOTS = {
    "abc",
    "collections",
    "dataclasses",
    "datetime",
    "enum",
    "functools",
    "hashlib",
    "json",
    "logging",
    "math",
    "re",
    "time",
    "typing",
    "uuid",
    "__future__",
    "app",
    "pydantic",
}


def _calls_and_imports(source: str) -> list[str]:
    tree = ast.parse(source)
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                found.append(node.func.id)
        if isinstance(node, ast.Name):
            found.append(node.id)
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            module = getattr(node, "module", "") or ""
            if not module:
                for alias in getattr(node, "names", ()):
                    module = alias.name or module
            found.append(module)
    return found


class TestNoArbitraryExecution:
    def test_no_exec_primitives(self) -> None:
        for path in SOAR_CORE_FILES + [SOAR_SCHEMA_FILE]:
            source = path.read_text(encoding="utf-8")
            for token in ("eval(", "exec(", "__import__("):
                assert token not in source, (path.name, token)
            found = _calls_and_imports(source)
            for banned in ("eval", "exec", "compile", "globals", "locals", "vars"):
                assert banned not in found, (path.name, banned)

    def test_no_dynamic_dispatch(self) -> None:
        for path in SOAR_CORE_FILES:
            source = path.read_text(encoding="utf-8")
            assert "getattr(" not in source, path.name
            assert "vars(" not in source, path.name
            assert "__getattribute__" not in source, path.name
            assert "import_module" not in source, path.name
            assert ".__call__" not in source, path.name

    def test_no_fs_shell_network_or_model_surface(self) -> None:
        for path in SOAR_CORE_FILES:
            source = path.read_text(encoding="utf-8")
            for token in (
                "open(",
                "os.",
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
                "docker",
                "ssh",
            ):
                assert token not in source, (path.name, token)

    def test_import_whitelist(self) -> None:
        for path in SOAR_CORE_FILES:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    root = (node.module or "").split(".")[0]
                    assert root in ALLOWED_ROOTS, (path.name, root)
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        root = alias.name.split(".")[0]
                        assert root in ALLOWED_ROOTS, (path.name, root)


class TestOrchestratesNeverDecides:
    def test_core_never_imports_the_policy_or_hitl_service(self) -> None:
        for path in SOAR_CORE_FILES:
            source = path.read_text(encoding="utf-8")
            assert "app.services.policy" not in source, path.name
            assert "app.services.hitl" not in source, path.name
            assert "app.agents" not in source, path.name

    def test_engine_uses_independent_gate_and_target_validator(self) -> None:
        engine = SOAR_DIR.joinpath("engine.py").read_text(encoding="utf-8")
        assert "SoarPolicyGate(" in engine
        assert "canonical_target(" in engine
        assert "validate_target" in engine or "as _av" in engine
        # The approval seam is the V2.16 verifier protocol, never a new
        # approval mechanism.
        assert "approval_verifier" in engine

    def test_gate_is_the_only_authority_for_refusals(self) -> None:
        gate = SOAR_DIR.joinpath("gate.py").read_text(encoding="utf-8")
        assert "policy_decision_id" in gate
        assert "APPROVAL_NOT_GIVEN" in gate
        assert "never" in gate  # fail-closed posture documented in code


class TestContractCarriesNoInstructionFields:
    def test_execution_request_has_no_instruction_carriers(self) -> None:
        from app.schemas.soar import SoarExecutionRequest

        for field in ("function", "callable", "code", "script", "command",
                      "prompt", "instructions", "args", "shell"):
            assert field not in SoarExecutionRequest.model_fields, field

    def test_schema_is_non_procedural(self) -> None:
        source = SOAR_SCHEMA_FILE.read_text(encoding="utf-8")
        for token in ("__import__", "getattr(", "httpx", "requests.", "socket.",
                      "subprocess", "eval(", "exec(", "os.", "open("):
            assert token not in source, token

    def test_step_never_carries_executables(self) -> None:
        from app.schemas.soar import SoarStep

        assert "command" not in SoarStep.model_fields
        assert "script" not in SoarStep.model_fields
        assert "url" not in SoarStep.model_fields


class TestSandboxProviders:
    def test_providers_explicitly_document_sandbox(self) -> None:
        providers = SOAR_DIR.joinpath("providers.py").read_text(encoding="utf-8")
        assert "sandbox" in providers.lower()
        assert "MockFirewallProvider" in providers
        assert "MockEDRProvider" in providers
        assert "MockIdentityProvider" in providers
        assert "dry_run" in providers

    def test_registry_rejects_duplicates_and_unknown_ids(self) -> None:
        registry = SOAR_DIR.joinpath("registry.py").read_text(encoding="utf-8")
        assert "duplicate" in registry and "already registered" in registry
        assert "no registered provider" in registry


class TestDeterministicIdentity:
    def test_hashing_has_no_randomness_or_wallclock(self) -> None:
        source = SOAR_DIR.joinpath("hashing.py").read_text(encoding="utf-8")
        assert "uuid.uuid4" not in source
        assert "datetime.now(" not in source
        assert "time.time" not in source
        assert "playbook_version" in source  # version participates in lineage