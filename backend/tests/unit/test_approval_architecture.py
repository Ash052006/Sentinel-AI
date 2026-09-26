"""Approval Workflow architecture tests (V2.16).

Static guarantees that keep the workflow's layering honest:

* the approval API surface exists under ``/api/approvals*`` while the
  policy engine keeps no ``/decision`` surface;
* no HTTP route reaches the Step 25 response service or the policy
  service (approvals.py operates through the approval service only);
* the approval package imports the response service (allowed layering:
  the approval *grants* and the response layer *executes*), while the
  response package never imports the approval package (no cycle);
* the migration introduces exactly the approval table and stays free of
  response tokens.
"""

from __future__ import annotations

from pathlib import Path

from app.main import app

BACKEND = Path(__file__).resolve().parent.parent.parent
ROUTES_DIR = BACKEND / "app" / "api" / "routes"
RESPONSE_DIR = BACKEND / "app" / "services" / "response"
APPROVAL_DIR = BACKEND / "app" / "services" / "approval"
MIGRATIONS_DIR = (
    BACKEND / "app" / "database" / "postgres" / "migrations" / "versions"
)


class TestApprovalApiSurface:
    def test_approval_paths_are_exposed(self) -> None:
        spec = app.openapi()
        paths = set(spec["paths"])
        assert "/api/approvals" in paths
        assert "/api/approvals/recent" in paths
        assert "/api/approvals/{approval_id}" in paths
        assert "/api/approvals/{approval_id}/approve" in paths
        assert "/api/approvals/{approval_id}/reject" in paths
        assert "/api/approvals/{approval_id}/cancel" in paths

    def test_no_decision_surface(self) -> None:
        spec = app.openapi()
        for path in spec["paths"]:
            assert "decision" not in path

    def test_approval_path_tokens_stay_in_approval_vocabulary(self) -> None:
        spec = app.openapi()
        for path in spec["paths"]:
            if "/approvals" not in path:
                continue
            assert "response" not in path
            assert "policy" not in path


class TestRouteIsolation:
    def test_approval_route_imports_only_approval_service(self) -> None:
        source = (ROUTES_DIR / "approvals.py").read_text(encoding="utf-8")
        assert "from app.services.approval" in source
        assert "app.services.response" not in source
        assert "app.services.policy" not in source

    def test_no_route_imports_approval_internals(self) -> None:
        for route_file in ROUTES_DIR.glob("*.py"):
            if route_file.name == "approvals.py":
                continue
            source = route_file.read_text(encoding="utf-8")
            assert "from app.services.approval" not in source, route_file.name

    def test_approval_service_may_import_response_service(self) -> None:
        source = (APPROVAL_DIR / "service.py").read_text(encoding="utf-8")
        assert "from app.services.response" in source

    def test_response_service_never_imports_approval_package(self) -> None:
        for py in RESPONSE_DIR.glob("*.py"):
            source = py.read_text(encoding="utf-8")
            assert "app.services.approval" not in source, py.name


class TestMigration:
    def test_approval_migration_table_registered(self) -> None:
        migration = MIGRATIONS_DIR / "a1b2c3d4e5f6_create_approval_request_tables.py"
        assert migration.exists()
        source = migration.read_text(encoding="utf-8")
        assert "create_table" in source
        assert "'approval_requests'" in source
        assert "a1b2c3d4e5f6" in source

    def test_approval_migration_creates_exactly_the_approval_table(self) -> None:
        migration = MIGRATIONS_DIR / "a1b2c3d4e5f6_create_approval_request_tables.py"
        source = migration.read_text(encoding="utf-8")
        assert source.count("create_table") == 1
        assert source.count("drop_table") == 1

    def test_no_other_migration_touches_approvals(self) -> None:
        for py in MIGRATIONS_DIR.glob("*.py"):
            if "a1b2c3d4e5f6" in py.name:
                continue
            source = py.read_text(encoding="utf-8")
            if "6a1b2c3d4e5f" in py.name:
                # V2.18: the SOAR migration records the *existing* V2.16
                # human-in-the-loop grant it consults
                # (soar_executions.approval_id is a controlled reference).
                # It introduces no approval mechanism and must never create
                # or alter an approval table — only the reference is allowed.
                assert "approval_requests" not in source, py.name
                assert "approval.request" not in source, py.name
                assert "create_table('approval" not in source, py.name
                assert "alter_table('approval" not in source, py.name
                continue
            assert "approval" not in source.lower(), py.name


class TestNoAutoApproval:
    def test_no_auto_approval_or_scheduler_vocabulary(self) -> None:
        for py in APPROVAL_DIR.glob("*.py"):
            source = py.read_text(encoding="utf-8")
            assert "autoapprove" not in source.lower()
            assert "auto_approve" not in source.lower()
            assert "cron" not in source.lower()
            assert "apscheduler" not in source.lower()
            assert "threading" not in source.lower()

    def test_service_approval_means_permission_not_verdict(self) -> None:
        source = (APPROVAL_DIR / "service.py").read_text(encoding="utf-8")
        assert "approval is authorization, not execution" in source.lower()