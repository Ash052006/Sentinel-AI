"""Step 13 — RAG layer dependency-isolation tests.

The Knowledge & RAG layer must stay dependency-light and offline-capable:

* no RAG service module may statically import Qdrant, Neo4j, Kafka,
  FastAPI, SQLAlchemy, or HTTP/AI SDKs at module scope;
* importing the ``app.services.knowledge`` package must not pull in
  ``qdrant_client`` (the Qdrant store imports it lazily);
* the schema contracts carry no framework dependencies at all.
"""

import ast
import subprocess
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent.parent
KNOWLEDGE_PKG = BACKEND / "app" / "services" / "knowledge"

FORBIDDEN_MODULES = {
    "qdrant_client",
    "neo4j",
    "kafka",
    "fastapi",
    "sqlalchemy",
    "httpx",
    "google",
    "anthropic",
    "openai",
}


def _module_paths():
    root = KNOWLEDGE_PKG
    return [
        p
        for p in root.glob("**/*.py")
        if p.name != "__init__.py"
    ]


def test_no_forbidden_top_level_imports():
    violations: list[str] = []
    for path in _module_paths():
        tree = ast.parse(path.read_text())
        for node in tree.body:
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module.split(".")[0] in FORBIDDEN_MODULES:
                    violations.append(f"{path.name}: from {module}")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in FORBIDDEN_MODULES:
                        violations.append(f"{path.name}: import {alias.name}")
    assert violations == []


def test_importing_package_does_not_import_qdrant():
    # Run in a fresh interpreter so module state is honest.
    script = (
        "import app.services.knowledge, sys; "
        "print('qdrant_client' in sys.modules)"
    )
    out = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(BACKEND),
        capture_output=True,
        text=True,
        check=True,
    )
    assert out.stdout.strip() == "False"


def test_schema_contracts_import_without_frameworks():
    script = (
        "import app.schemas.knowledge, app.schemas.knowledge_context, sys; "
        "print('qdrant_client' in sys.modules)"
    )
    out = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(BACKEND),
        capture_output=True,
        text=True,
        check=True,
    )
    assert out.stdout.strip() == "False"