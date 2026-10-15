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
import re
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


#: The five frozen V2 tables that carry intentional comment-only drift.
#:
#: Established in ``docs/development/v2_release_baseline.md`` and restated in the
#: V3.22/V3.23/V3.24 documents: the comments in the live database differ from the
#: ORM metadata for these tables, the difference is documentation prose only, and
#: it is deliberately *not* reconciled.  Mass-rewriting documentation strings to
#: drive ``alembic check`` to zero would be churn that hides the signal the check
#: exists to provide.
KNOWN_V2_COMMENT_DRIFT_TABLES: frozenset[str] = frozenset(
    {
        "approval_requests",
        "detection_rule_changes",
        "detection_rule_releases",
        "detection_rule_versions",
        "incident_memories",
    }
)


#: Tables V3.25 does not govern, whose comments may legitimately diverge in the
#: test database.
#:
#: The four frozen V3.24 ``attack_prediction*`` tables drift in the *test*
#: database only.  Their migration was revised to duplicate the ORM comments
#: after the test database had already been migrated, and ``alembic upgrade
#: head`` is a no-op against a database already at head, so the revision can
#: never take effect there.  The development database, migrated with the revised
#: file, has no such drift.  Comments carry no behaviour and V3.24 is frozen, so
#: this is an environment condition to report and rebuild away -- not a V3.25
#: invariant, and not something to assert on either way.
UNGOVERNED_BY_V325: frozenset[str] = frozenset(
    {
        "attack_prediction_sessions",
        "attack_prediction_uncertainties",
        "attack_predictions",
        "attack_prediction_evidence",
    }
)


class TestFrozenV2CommentDrift:
    """Guards the *known* drift instead of quietly resolving it.

    An autogenerated migration once swept these comment differences into the
    V3.25 revision and was applied before the unrelated operations were removed
    from the file.  That mutated the development database to match ORM metadata,
    which silently deleted the documented condition: ``alembic check`` went green
    for the wrong reason.  These tests make the condition visible again so it
    cannot be lost a second time.
    """

    def test_the_drift_tables_are_still_the_documented_five(self) -> None:
        """If this fails, either the schema changed or the list was edited to
        match reality — which would hide the drift instead of describing it."""
        assert KNOWN_V2_COMMENT_DRIFT_TABLES == frozenset(
            {
                "approval_requests",
                "detection_rule_changes",
                "detection_rule_releases",
                "detection_rule_versions",
                "incident_memories",
            }
        )

    def test_the_v325_migration_touches_no_frozen_v2_table(self) -> None:
        """V3.25 must create only its own four tables.

        This is the regression that matters: had the swept-in ``alter_column``
        calls stayed, this migration would rewrite frozen V2 comments on every
        fresh deployment.
        """
        source = (
            VERSIONS_DIR / "b8c9d0e1f2a3_create_playbook_tables.py"
        ).read_text(encoding="utf-8")
        created = set(re.findall(r"create_table\(\s*[\"']([a-z_]+)[\"']", source))
        assert created == {
            "playbook_sessions",
            "playbook_steps",
            "playbook_actions",
            "playbook_action_evidence",
        }
        assert "alter_column" not in source
        assert "modify_comment" not in source

    def test_v325_models_are_visible_to_autogenerate(self) -> None:
        """A table missing from ``target_metadata`` is never reported as drift."""
        from app.database.postgres.base import Base

        for module in sorted(_env_imported_modules()):
            __import__(f"app.models.{module}")
        for table in (
            "playbook_sessions",
            "playbook_steps",
            "playbook_actions",
            "playbook_action_evidence",
        ):
            assert table in Base.metadata.tables, table

    def test_live_schema_matches_the_migration_history(self, db_session) -> None:
        """The live database must equal what the migrations produce.

        This is the assertion whose absence let the accidental mutation go
        unnoticed: ``alembic check`` reported zero drift because the database had
        been rewritten to match the models, not because the two had always agreed.
        Reported per-table so a failure names the table that diverged.
        """
        from sqlalchemy import inspect

        from app.database.postgres.base import Base

        for module in sorted(_env_imported_modules()):
            __import__(f"app.models.{module}")

        inspector = inspect(db_session.get_bind())
        live_tables = set(inspector.get_table_names())
        for table in Base.metadata.tables:
            assert table in live_tables, table

        drift: dict[str, list[str]] = {}
        for name in sorted(Base.metadata.tables):
            table = Base.metadata.tables[name]
            live_comments = {
                column["name"]: column.get("comment")
                for column in inspector.get_columns(name)
            }
            mismatched = sorted(
                column.name
                for column in table.columns
                if (live_comments.get(column.name) or None) != (column.comment or None)
            )
            if mismatched:
                drift[name] = mismatched

        # V3.25 governs its own four tables plus the frozen V2 tables it must not
        # touch.  Drift belongs in the five frozen tables and nowhere else that
        # V3.25 is responsible for.
        unexpected = set(drift) - KNOWN_V2_COMMENT_DRIFT_TABLES - UNGOVERNED_BY_V325
        assert not unexpected, (
            f"comment drift in tables V3.25 governs unexpectedly: {unexpected}"
        )
        # The V3.25 migration duplicates its comments verbatim, so its tables
        # agree with the models by construction.  This is the assertion that
        # would break if someone swept comment edits into the V3.25 revision.
        assert not [t for t in drift if t.startswith("playbook")], (
            f"V3.25 tables must not drift: {drift}"
        )
        # The documented condition must still be present, not silently resolved.
        # If this ever drops to empty that is a deliberate decision to reconcile
        # the drift, not an accident — and the documentation must change with it.
        missing = KNOWN_V2_COMMENT_DRIFT_TABLES - set(drift)
        assert not missing, (
            "the known V2 comment drift has been resolved; if that was "
            f"intentional, update the documentation. Missing: {missing}"
        )
