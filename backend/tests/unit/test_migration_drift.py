"""Alembic drift-gate guards.

``alembic check`` is only meaningful when ``env.py`` registers *every*
model: a table missing from ``target_metadata`` is not reported as drift at
all — autogenerate simply never sees it, and the next
``revision --autogenerate`` would happily propose dropping live tables.

These tests pin that invariant and pin the model/schema alignment that was
fixed during hardening, so the drift gate cannot rot back into a no-op.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parent.parent.parent
MODELS_DIR = BACKEND / "app" / "models"
ENV_FILE = (
    BACKEND / "app" / "database" / "postgres" / "migrations" / "env.py"
)
VERSIONS_DIR = (
    BACKEND / "app" / "database" / "postgres" / "migrations" / "versions"
)


def _model_modules() -> set[str]:
    return {
        path.stem
        for path in MODELS_DIR.glob("*.py")
        if not path.stem.startswith("__")
    }


def _env_imported_modules() -> set[str]:
    tree = ast.parse(ENV_FILE.read_text(encoding="utf-8"))
    return {
        node.module.split(".")[-1]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        and node.module
        and node.module.startswith("app.models")
    }


class TestMetadataCoverage:
    def test_every_model_module_is_imported_by_env(self) -> None:
        missing = _model_modules() - _env_imported_modules()
        assert not missing, (
            "model modules absent from migrations/env.py: "
            f"{sorted(missing)}. Their tables would be invisible to autogenerate."
        )

    def test_env_imports_reference_real_modules(self) -> None:
        unknown = _env_imported_modules() - _model_modules()
        assert not unknown, f"env.py imports missing model modules: {sorted(unknown)}"

    def test_all_model_tables_registered_in_metadata(self) -> None:
        """Boot the app's model layer the way Alembic does and assert every
        module actually contributed its table(s)."""
        from app.database.postgres.base import Base

        for module in sorted(_env_imported_modules()):
            __import__(f"app.models.{module}")
        assert len(Base.metadata.tables) >= 24, (
            f"only {len(Base.metadata.tables)} tables registered; expected the "
            "full schema"
        )
        for expected in (
            "threat_hunts",
            "threat_hunt_evidence",
            "threat_hunt_findings",
            "threat_hunt_timeline_items",
            "incident_reports",
            "incident_memories",
            "approval_requests",
        ):
            assert expected in Base.metadata.tables, expected


class TestMigrationChain:
    def test_single_head(self) -> None:
        from alembic.config import Config
        from alembic.script import ScriptDirectory

        config = Config(str(BACKEND / "alembic.ini"))
        script = ScriptDirectory.from_config(config)
        assert len(script.get_heads()) == 1, (
            f"multiple migration heads: {script.get_heads()}"
        )

    def test_revisions_are_unique_and_linear(self) -> None:
        from alembic.config import Config
        from alembic.script import ScriptDirectory

        config = Config(str(BACKEND / "alembic.ini"))
        script = ScriptDirectory.from_config(config)
        revisions = [rev.revision for rev in script.walk_revisions()]
        assert len(revisions) == len(set(revisions)), "duplicate revision id"
        for rev in script.walk_revisions():
            assert rev.revision, f"{rev.path} has no revision id"

    def test_ondelete_migration_covers_every_hunt_foreign_key(self) -> None:
        """The migration that realigned the hunt FKs must stay exhaustive."""
        target = VERSIONS_DIR / (
            "c3d4e5f6a1b2_align_threat_hunt_fk_ondelete.py"
        )
        assert target.exists(), "FK ondelete migration is missing"
        source = target.read_text(encoding="utf-8")
        for constraint in (
            "fk_threat_hunts_created_by_users",
            "fk_threat_hunt_evidence_hunt_id_threat_hunts",
            "fk_threat_hunt_findings_hunt_id_threat_hunts",
            "fk_threat_hunt_timeline_items_hunt_id_threat_hunts",
        ):
            assert constraint in source, constraint
        assert "CASCADE" in source and "RESTRICT" in source

    @pytest.mark.parametrize(
        "model,column",
        [
            ("threat_hunt", "filters"),
            ("threat_hunt", "evidence_ids"),
            ("threat_hunt", "context"),
            ("incident_report", "payload"),
        ],
    )
    def test_structured_columns_stay_jsonb(self, model: str, column: str) -> None:
        """These columns are JSONB in the live schema; the model must agree or
        autogenerate proposes a lossy JSONB -> JSON downgrade."""
        from app.database.postgres.base import Base

        module = __import__(f"app.models.{model}", fromlist=["*"])
        for obj in vars(module).values():
            table = getattr(obj, "__table__", None)
            if table is None or column not in table.c:
                continue
            assert "JSONB" in type(table.c[column].type).__name__, (
                f"{model}.{column} is "
                f"{type(table.c[column].type).__name__}, expected JSONB"
            )
            return
        pytest.fail(f"{model}.{column} not found on any table in {model}")

    @pytest.mark.parametrize(
        "model,column,index",
        [
            ("incident_memory", "correlation_id", "ix_incident_memories_correlation_id"),
            ("incident_memory", "provenance", "ix_incident_memories_provenance"),
            ("approval_request", "provenance", "ix_approval_requests_provenance"),
        ],
    )
    def test_existing_indexes_stay_declared(
        self, model: str, column: str, index: str
    ) -> None:
        """These indexes exist in the live schema.  If the model stops
        declaring them, autogenerate proposes dropping them."""
        module = __import__(f"app.models.{model}", fromlist=["*"])
        for obj in vars(module).values():
            table = getattr(obj, "__table__", None)
            if table is None or column not in table.c:
                continue
            declared = {ix.name for ix in table.indexes} | {
                c.name for c in (table.primary_key.columns if table.primary_key else ())
            }
            assert index in declared, (
                f"{index} exists in the database but is not declared on "
                f"{model}.{column}; autogenerate would drop it"
            )
            return
        pytest.fail(f"{model}.{column} not found on any table in {model}")
