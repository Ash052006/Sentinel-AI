"""Threat Hunting architecture tests (V2.19).

Static guarantees of the V2.19 design, enforced by AST/source inspection:

* the hunt core (grammar/query/engine) never executes arbitrary code, never
  takes a query string / SQL fragment / expression tree, and has no reach
  to a host, network, model, message bus, filesystem, shell or decision
  engine (no os/socket/httpx/requests/urllib/subprocess/pickle/gemini/
  genai/kafka/qdrant);
* the write surface is closed: only the four hunt tables + the sanctioned
  audit trail, versus every source of evidence being read-only;
* the hunt core never imports the response/soar/policy/approval/hitl/
  agent surfaces — it investigates, it never executes;
* the grammar's runtime column dispatch is pinned to a module-level
  allowlist (``_ALLOWED_COLUMNS``) that mirrors the exposed surface
  vocabulary — no client-influenced attribute/column ever reaches a query;
* the migration introduces exactly the four hunt tables and stays free of
  the ``approval`` token (the architecture scan carve-out).
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from app.main import app

BACKEND = Path(__file__).resolve().parent.parent.parent
HUNT_DIR = BACKEND / "app" / "services" / "threat_hunting"
SCHEMA_FILE = BACKEND / "app" / "schemas" / "threat_hunting.py"
MODEL_FILE = BACKEND / "app" / "models" / "threat_hunt.py"
REPO_FILE = BACKEND / "app" / "repositories" / "threat_hunting.py"
ROUTE_FILE = BACKEND / "app" / "api" / "routes" / "threat_hunts.py"
MIGRATIONS_DIR = (
    BACKEND / "app" / "database" / "postgres" / "migrations" / "versions"
)
HUNT_MIGRATION_NAME = "7a1b2c3d4e5f_create_threat_hunt_tables.py"

HUNT_CORE_FILES = sorted(
    p
    for p in HUNT_DIR.glob("*.py")
    if p.name in {"grammar.py", "query.py", "engine.py", "service.py", "errors.py"}
)

#: Surfaces a hunt must NEVER reach: they execute, decide or act.
NEVER_IMPORTED = (
    "app.services.soar",
    "app.services.response",
    "app.services.policy",
    "app.services.approval",
    "app.services.hitl",
    "app.agents",
    "app.schemas.soar",
    "app.schemas.policy_decision",
)

#: Anything that could reach a host, bus, model or the outside world.
FORBIDDEN_TOKENS = (
    "os.",
    "socket.",
    "subprocess",
    "httpx",
    "requests.",
    "urllib.",
    "pickle.",
    "gemini",
    "genai",
    "kafka",
    "qdrant",
    "open(",
    "time.sleep",
    "import_module",
)


class TestNoArbitraryExecution:
    def test_no_exec_primitives_or_dynamic_dispatch(self) -> None:
        for path in HUNT_CORE_FILES + [SCHEMA_FILE]:
            source = path.read_text(encoding="utf-8")
            for token in ("eval(", "exec(", "__import__(", "compile(", "vars("):
                assert token not in source, (path.name, token)

    def test_no_import_module(self) -> None:
        for path in HUNT_CORE_FILES:
            source = path.read_text(encoding="utf-8")
            assert "import_module" not in source, path.name

    def test_no_function_value_dispatch(self) -> None:
        for path in HUNT_CORE_FILES:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    attr = node.func.attr
                    assert attr not in ("__call__", "__getattribute__"), (path.name, attr)

    def test_core_has_no_reach_to_network_filesystem_model_or_bus(self) -> None:
        for path in HUNT_CORE_FILES:
            source = path.read_text(encoding="utf-8")
            for token in FORBIDDEN_TOKENS:
                assert token not in source, (path.name, token)


class TestInvestigatesNeverExecutes:
    def test_core_never_imports_the_executing_surfaces(self) -> None:
        for path in HUNT_CORE_FILES + [ROUTE_FILE]:
            source = path.read_text(encoding="utf-8")
            for module in NEVER_IMPORTED:
                assert module not in source, (path.name, module)

    def test_schema_contract_has_no_action_capability(self) -> None:
        from app.schemas.threat_hunting import (
            HuntFilter,
            ThreatHuntCreate,
            ThreatHuntDetail,
        )

        action_words = (
            "block", "quarantine", "approve", "response_action",
            "command", "script", "provider", "playbook", "policy", "decision",
        )
        for schema in (ThreatHuntCreate, ThreatHuntDetail, HuntFilter):
            for word in action_words:
                assert word not in schema.model_fields, (schema.__name__, word)

    def test_operator_vocabulary_is_read_only(self) -> None:
        from app.schemas.threat_hunting import (
            FIELD_OPERATORS,
            HuntFilter,
            HuntOperator,
        )

        assert set(HuntOperator) == {
            HuntOperator.EQUALS,
            HuntOperator.NOT_EQUALS,
            HuntOperator.IN,
            HuntOperator.NOT_IN,
            HuntOperator.CONTAINS,
            HuntOperator.STARTS_WITH,
            HuntOperator.ENDS_WITH,
        }
        assert "execute" not in {op.value for op in HuntOperator}
        for field, operators in FIELD_OPERATORS.items():
            assert operators, field
            assert set(operators) <= set(HuntOperator)
        # No operator may reference a dynamic expression or execution builtin.
        for op in HuntOperator:
            assert op.value not in ("regex", "glob", "sql", "eval", "exec")

    def test_engine_writes_nothing_but_its_own_artifacts(self) -> None:
        import re

        source = (HUNT_DIR / "engine.py").read_text(encoding="utf-8")
        # The engine returns dataclasses; it must not import a persistence
        # service or another table model.
        assert "app.repositories" not in source
        assert "app.services.audit_service" not in source
        # Evidence schemas it imports are read-only query records (or the
        # hunting schema) — never write/response schemas.
        for match in re.findall(r"from\s+app\.schemas\.([\w.]+)\s+import", source):
            assert match == "threat_hunting" or match.endswith("_query"), match

    def test_repository_writes_only_the_four_hunt_tables(self) -> None:
        source = REPO_FILE.read_text(encoding="utf-8")
        for model in ("ThreatHuntRow", "ThreatHuntEvidenceRow",
                      "ThreatHuntFindingRow", "ThreatHuntTimelineItemRow"):
            assert model in source
        assert "from app.models.threat_hunt import" in source
        # No writes to source-of-truth tables outside the hunt surface.
        for other_tables in (
            "DetectionResult", "CorrelationResult", "RiskAssessment",
            "ThreatIntelIndicator", "IncidentMemory",
        ):
            assert other_tables not in source.replace("ThreatHuntRow", "")

    def test_service_writes_via_repository_and_audit_only(self) -> None:
        source = (HUNT_DIR / "service.py").read_text(encoding="utf-8")
        assert "from app.repositories import threat_hunting as repo" in source
        assert "from app.services.audit_service import log_action" in source
        for module in ("app.models.detection", "app.models.correlation",
                       "app.models.risk", "app.models.threat_intel"):
            assert module not in source


class TestClosedColumnDispatch:
    def test_query_allowlist_is_a_module_level_frozenset(self) -> None:
        source = (HUNT_DIR / "query.py").read_text(encoding="utf-8")
        assert "_ALLOWED_COLUMNS: dict[str, frozenset[str]]" in source

    def test_no_raw_sql_or_string_interpolation_in_statements(self) -> None:
        source = (HUNT_DIR / "query.py").read_text(encoding="utf-8")
        for token in ("text(", "SELECT ", "INSERT ", "UPDATE ", "DELETE ",
                      "execute(", "{column}", "%s"):
            assert token not in source, token

    def test_every_runtime_column_is_allowlisted(self) -> None:
        from app.services.threat_hunting.query import _ALLOWED_COLUMNS
        from app.services.threat_hunting.grammar import SURFACES

        assert set(_ALLOWED_COLUMNS) == set(SURFACES)
        for key, columns in _ALLOWED_COLUMNS.items():
            assert columns, key

    def test_link_kinds_are_a_closed_set(self) -> None:
        source = (HUNT_DIR / "engine.py").read_text(encoding="utf-8")
        kinds = (
            '"members"', '"lookups_by_indicator"',
            '"reuse_correlations_by_event"', '"reuse_risk_by_correlation"',
            '"reuse_memory_by_correlation"',
        )
        for kind in kinds:
            assert kind in source
        assert '"execute"' not in source


class TestApiIsThinTransport:
    def test_hunt_paths_exposed_with_expected_methods(self) -> None:
        spec = app.openapi()
        paths = set(spec["paths"])
        assert "/api/threat-hunts" in paths
        assert "/api/threat-hunts/{hunt_id}" in paths
        assert "/api/threat-hunts/{hunt_id}/run" in paths
        assert "/api/threat-hunts/{hunt_id}/cancel" in paths
        assert "/api/threat-hunts/{hunt_id}/evidence" in paths
        assert "/api/threat-hunts/{hunt_id}/findings" in paths
        assert "/api/threat-hunts/{hunt_id}/timeline" in paths
        assert set(spec["paths"]["/api/threat-hunts"]) == {"get", "post"}
        assert set(spec["paths"]["/api/threat-hunts/{hunt_id}/run"]) == {"post"}
        assert set(spec["paths"]["/api/threat-hunts/{hunt_id}/cancel"]) == {"post"}

    def test_hunt_paths_stay_in_hunt_vocabulary(self) -> None:
        spec = app.openapi()
        for path in spec["paths"]:
            if "/threat-hunts" not in path:
                continue
            assert "response" not in path
            assert "policy" not in path
            assert "soar" not in path
            assert "decision" not in path
            assert "approval" not in path

    def test_route_file_imports_service_and_schemas_only(self) -> None:
        source = ROUTE_FILE.read_text(encoding="utf-8")
        assert "from app.services.threat_hunting import ThreatHuntService" in source
        assert "app.services.audit_service" in source
        for module in NEVER_IMPORTED:
            assert module not in source


class TestPaginationIsDeterministic:
    """``ORDER BY created_at DESC`` alone is **not a total order**.

    Rows that share a ``created_at`` (fixed-clock runs, bulk inserts,
    same-microsecond commits) are returned in an arbitrary, plan-dependent
    order, so ``LIMIT``/``OFFSET`` can serve a row twice and skip another
    across pages.  Reproduced on PostgreSQL: with six tied hunts a routine
    status transition rewrote page 1 from ``(1,2,3)`` to ``(2,3,4)`` and
    page 2 from ``(4,5,6)`` to ``(5,6,1)`` — row 1 served twice, row 4
    never served.  The list must break the tie on the primary key, which is
    what every other paginated repository in the codebase already does.

    The tie-break is asserted structurally because SQLite's sort happens to
    be stable, so a behavioural test on the unit-test engine cannot observe
    the defect; PostgreSQL is the engine that actually misbehaves.
    """

    def test_list_orders_by_created_at_with_primary_key_tiebreak(self) -> None:
        tree = ast.parse(REPO_FILE.read_text(encoding="utf-8"))

        def _sort_keys(call: ast.Call) -> set[str]:
            keys: set[str] = set()
            for arg in call.args:
                for sub in ast.walk(arg):
                    if (
                        isinstance(sub, ast.Attribute)
                        and isinstance(sub.value, ast.Name)
                        and sub.value.id == "ThreatHuntRow"
                    ):
                        keys.add(sub.attr)
            return keys

        order_by_calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "order_by"
        ]
        created_at_orders = [
            call for call in order_by_calls if "created_at" in _sort_keys(call)
        ]
        assert created_at_orders, "the hunt list no longer orders by created_at"

        for call in created_at_orders:
            keys = _sort_keys(call)
            assert "hunt_id" in keys, (
                "the paginated hunt list orders by created_at without a "
                "primary-key tiebreak; tied timestamps make LIMIT/OFFSET "
                "duplicate and skip rows"
            )

    def test_every_paginated_ordering_has_a_unique_tiebreak(self) -> None:
        """Guard *all* hunt sub-resources, not just the hunt list.

        Evidence was paginated by ``observed_at`` alone — the same defect.
        Every ``order_by`` that feeds a ``LIMIT``/``OFFSET`` must carry a
        second, unique sort key.
        """
        tree = ast.parse(REPO_FILE.read_text(encoding="utf-8"))

        def _keys(call: ast.Call) -> set[str]:
            found: set[str] = set()
            for arg in call.args:
                for sub in ast.walk(arg):
                    if (
                        isinstance(sub, ast.Attribute)
                        and isinstance(sub.value, ast.Name)
                        and sub.value.id.startswith("ThreatHunt")
                    ):
                        found.add(sub.attr)
            return found

        offenders: list[str] = []
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "order_by"
            ):
                continue
            keys = _keys(node)
            if len(keys) < 2 and keys:
                # Single-key ordering: only a problem if the key is not
                # already the primary key.
                only = next(iter(keys))
                if not only.endswith("_id"):
                    offenders.append(only)

        assert not offenders, (
            "paginated ordering on a non-unique key without a tiebreak: "
            + ", ".join(sorted(offenders))
        )

    def test_paginated_ordering_matches_repository_convention(self) -> None:
        """Every paginated repository must break timestamp ties on a unique
        key.  ``threat_hunting`` was the only one that did not."""
        repos = sorted((BACKEND / "app" / "repositories").glob("*.py"))
        offenders: list[str] = []
        for path in repos:
            source = path.read_text(encoding="utf-8")
            if "order_by" not in source:
                continue
            for lineno, line in enumerate(source.splitlines(), start=1):
                stripped = line.strip()
                if not stripped.startswith("order_by("):
                    continue
                window = "\n".join(
                    source.splitlines()[lineno - 1 : lineno + 4]
                )
                if not re.search(r"\.limit\(|\.offset\(", window):
                    continue
                if not re.search(
                    r"created_at|requested_at|detected_at|timestamp|updated_at",
                    window,
                ):
                    continue
                # A timestamp sort with no second key in the same clause.
                if not re.search(
                    r"(_id|log_id|memory_id|\bid)\s*\.?(asc|desc)?\(\)?",
                    window,
                ) or not re.search(r"\.asc\(\)|\.desc\(\)|\bid\b", window):
                    offenders.append(f"{path.name}:{lineno}")
        assert not offenders, (
            "paginated timestamp ordering without a unique tiebreak: "
            + ", ".join(offenders)
        )


class TestMigration:
    def test_hunt_migration_registered(self) -> None:
        migration = MIGRATIONS_DIR / HUNT_MIGRATION_NAME
        assert migration.exists()
        source = migration.read_text(encoding="utf-8")
        assert "7a1b2c3d4e5f" in source
        assert "down_revision" in source and "6a1b2c3d4e5f" in source
        assert "threat_hunts" in source

    def test_hunt_migration_creates_exactly_the_four_tables(self) -> None:
        migration = MIGRATIONS_DIR / HUNT_MIGRATION_NAME
        source = migration.read_text(encoding="utf-8")
        for table in (
            "'threat_hunts'",
            "'threat_hunt_evidence'",
            "'threat_hunt_findings'",
            "'threat_hunt_timeline_items'",
        ):
            assert table in source
        assert source.count("create_table") == 4
        assert source.count("drop_table") == 4

    def test_hunt_migration_carries_no_approval_token(self) -> None:
        # The global architecture scan (test_approval_architecture) treats
        # this migration as the V2.19 carve-out: it must stay free of the
        # forbidden substring everywhere.
        migration = MIGRATIONS_DIR / HUNT_MIGRATION_NAME
        source = migration.read_text(encoding="utf-8")
        assert "approval" not in source

    def test_hunt_migration_matches_model_fk_naming(self) -> None:
        from app.models.threat_hunt import ThreatHuntEvidenceRow

        for fk in ThreatHuntEvidenceRow.__table__.foreign_keys:
            assert fk.target_fullname, fk.target_fullname