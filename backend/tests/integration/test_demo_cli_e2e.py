"""End-to-end verification of ``python -m app.cli demo``.

Runs the real demo command against the real application and the real
PostgreSQL database, then proves the properties the demo promises:

A. The run completes — every checklist row reports a verdict, a skipped check
   states a reason, and any failure means a non-zero exit code.
B. What the checklist claims is what the database contains: the recorded
   detection, correlation, risk, approval, hunt and SOAR execution ids are
   readable through the *existing* HTTP APIs the frontend calls, and every
   printed link is a route the frontend router actually declares.
C. One incident, not a pile of copies — the demo adds exactly one set of
   detections and correlations, and every stage that names a correlation names
   the same one.
D. A denied or approval-gated decision executed nothing: the response stage
   reports zero provider calls for those scenarios while an allowed decision
   still executes.
E. Cleanup restores the database — after ``--clean`` every table is back at
   its pre-demo row count.

The demo leaves its results behind on purpose, so the fixture always runs the
matching ``--clean``, including when a test fails.
"""

from __future__ import annotations

import contextlib
import json
import os
import warnings
from pathlib import Path
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import cli
from app.core.security import create_access_token
from app.main import app
from app.models.audit_log import AuditLog
from app.models.correlation_member import CorrelationMember
from app.models.detection_result import DetectionResult
from app.models.role import Role
from app.models.user import User
from scripts import run_demo_dataset as runner

warnings.filterwarnings("ignore", category=DeprecationWarning)

#: No live provider call may be made from the test suite.
#:
#: ``--no-gemini`` is deliberately NOT passed.  The demo bypasses the report
#: service only when the operator disabled Gemini *and* a key is genuinely
#: available to call, so with this machine's real ``.env`` key that flag would
#: make the stage report ``skipped`` and never exercise the governed-failure
#: path these tests exist to pin.  Instead the key is made unresolvable for the
#: duration of the run (see :func:`no_resolvable_gemini_key`): the demo still
#: calls the real report service, which cannot reach a provider and therefore
#: persists the honest governed ``failed`` row -- with no network call at all.
DEMO_ARGS = ["demo", "--scenario", "full", "--offline", "--json"]

FRONTEND_ROUTES = (
    Path(__file__).resolve().parents[3] / "frontend" / "src" / "routes" / "index.tsx"
)


@contextlib.contextmanager
def no_resolvable_gemini_key():
    """Make the environment and the settings singleton resolve to *no* key.

    ``GEMINI_API_KEY`` is loaded from ``.env`` into the pydantic settings
    object at import time, so clearing ``os.environ`` alone still leaves a real
    key resolvable.  Both sources are neutralised for the duration of the block
    and restored afterwards, so no provider call can leave the test suite.
    """
    from app.core.config import settings

    original_env = os.environ.pop("GEMINI_API_KEY", None)
    original_setting = settings.gemini_api_key
    settings.gemini_api_key = ""
    try:
        yield
    finally:
        settings.gemini_api_key = original_setting
        if original_env is not None:
            os.environ["GEMINI_API_KEY"] = original_env


@pytest.fixture(scope="module")
def state_file(tmp_path_factory):
    """Keep the demo's cleanup snapshots out of the developer's own file."""
    path = tmp_path_factory.mktemp("demo-cli") / ".demo_state.json"
    original = cli.STATE_FILE
    cli.STATE_FILE = path
    yield path
    cli.STATE_FILE = original


@pytest.fixture(scope="module")
def admin_headers(db_session: Session) -> dict[str, str]:
    user = db_session.execute(
        select(User).join(Role, User.role_id == Role.id).where(Role.name == "admin")
    ).scalars().first()
    assert user is not None, "conftest seeds the admin role and user"
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


@pytest.fixture(scope="module")
def demo_run(state_file):
    """Run the demo once, then always remove what it left behind.

    The cleanup is in a ``finally`` so a failing run cannot leave rows behind
    for the next run — including the next run of this very module.
    """
    baseline = runner.table_counts()
    try:
        with no_resolvable_gemini_key():
            assert cli.main(DEMO_ARGS) == 0, "a clean demo run must exit 0"
        payload = json.loads(state_file.read_text(encoding="utf-8"))["runs"][-1]
        during = runner.table_counts()
        yield payload, baseline, during
    finally:
        cli.main(["demo", "--clean", "--json"])


# ---------------------------------------------------------------------------
# A. The run itself
# ---------------------------------------------------------------------------


def test_the_checklist_has_twenty_rows_and_none_failed(demo_run):
    payload, _, _ = demo_run
    assert payload["status"] == "PASS"
    assert payload["summary"] == {"passed": 20, "skipped": 0, "failed": 0}
    assert len(payload["stages"]) == 20


def _stage(payload: dict, name: str) -> dict:
    return next(stage for stage in payload["stages"] if stage["name"] == name)


def _items(stage: dict) -> list[dict]:
    return stage.get("items") or []


def _generate_item(payload: dict) -> dict:
    """The report stage's ``generate`` outcome for the demo's incident."""
    return next(
        item
        for item in _items(_stage(payload, "incident_reports"))
        if item["check"] == "generate"
    )


def test_every_stage_observed_something(demo_run):
    payload, _, _ = demo_run
    for stage in payload["stages"]:
        assert stage["status"] in ("PASS", "SKIP"), stage["name"]
        # A stage is either backed by checks, or by the note the demo's own
        # pipeline wrote for it; an unexplained one would be a silent pass.
        assert _items(stage) or stage.get("note", "").strip(), stage["name"]
        for item in _items(stage):
            assert item["status"] in ("ok", "skipped", "failed"), item["check"]
            if item["status"] == "skipped":
                assert item["note"].strip(), f"{item['check']} skipped without a reason"


def test_the_run_reports_the_identities_it_created(demo_run):
    payload, _, _ = demo_run
    for key in ("correlation_id", "detection_id", "risk_assessment_id",
                "approval_id", "soar_execution_id", "hunt_id"):
        assert payload["entities"].get(key), f"no {key} was reported"


def test_gemini_is_never_faked_and_the_governed_failure_is_recorded(demo_run):
    """A report must exist as a *persisted decision row*, never as invented text.

    The report service owns report persistence: with no provider available it
    commits one ``failed`` row carrying a sanitised error and audits it.  The
    demo therefore must reach the real service rather than short-circuiting in
    front of it — otherwise ``GET /api/incident-reports`` serves nothing and the
    Incident Reports page is empty even though the run "passed".
    """
    payload, _, _ = demo_run
    generation = [i for i in _items(_stage(payload, "incident_reports"))
                  if i["check"] == "generate"]
    assert generation, "the report stage must record a generate outcome"
    item = generation[0]
    assert item["status"] == "ok", item
    observed = item["observed"]
    assert observed["report_id"], "a report row id must be reported"
    assert observed["status"] == "failed", (
        "without a Gemini key the only honest persisted outcome is a governed "
        f"failed row, got {observed['status']!r}"
    )
    assert observed["error_code"], "the governed failure carries an error code"
    assert observed["error_message"], "and a sanitized reason"
    assert "No report text was invented" in item["note"]


def test_the_persisted_report_row_is_served_by_the_existing_api(
    demo_run, admin_headers
):
    """DB row -> read service -> ``GET /api/incident-reports`` -> the demo row."""
    payload, _, _ = demo_run
    correlation = payload["entities"]["correlation_id"]
    report_id = _generate_item(payload)["observed"]["report_id"]
    client = TestClient(app)

    listing = client.get(
        "/api/incident-reports",
        params={"page": 1, "page_size": 50, "correlation_id": correlation},
        headers=admin_headers,
    )
    assert listing.status_code == 200
    page = listing.json()
    assert page["correlation_id"] == correlation
    assert [item["report_id"] for item in page["items"]] == [report_id]
    assert page["items"][0]["status"] == "failed"
    assert page["items"][0]["error_code"]

    detail = client.get(f"/api/incident-reports/{report_id}", headers=admin_headers)
    assert detail.status_code == 200
    assert detail.json()["correlation_id"] == correlation


def test_the_failed_generation_is_audited(demo_run, db_session):
    payload, _, _ = demo_run
    actions = set(
        db_session.execute(
            select(AuditLog.action).where(
                AuditLog.action.in_(
                    [
                        "incident_report.generated_requested",
                        "incident_report.generated_failed",
                    ]
                ),
                AuditLog.resource == "incident_reports",
            )
        ).scalars().all()
    )
    assert actions == {
        "incident_report.generated_requested",
        "incident_report.generated_failed",
    }, f"the refused generation must stay auditable, saw {actions}"


def test_the_report_row_is_tracked_for_cleanup(demo_run, state_file):
    """A persisted row the demo does not track could never be removed again."""
    payload, _, _ = demo_run
    report_id = _generate_item(payload)["observed"]["report_id"]
    runs = json.loads(state_file.read_text(encoding="utf-8"))["runs"]
    tracked = [
        row_id
        for run in runs
        for cleanup in run["cleanups"]
        for row_id in (cleanup.get("ids", {}).get("incident_reports") or [])
    ]
    assert report_id in tracked, (
        "the persisted report row must be registered with the cleanup ledger"
    )


def test_mitre_never_invents_a_technique_id(demo_run):
    payload, _, _ = demo_run
    stage = _stage(payload, "mitre")
    assert "no ATT&CK id is invented" in stage["note"]
    for item in _items(stage):
        techniques = (item.get("observed") or {}).get("techniques") or []
        assert techniques == [], "V2 ships no technique mapper, so none may appear"


# ---------------------------------------------------------------------------
# B. The database agrees with the report
# ---------------------------------------------------------------------------


def test_the_recorded_ids_are_served_by_the_existing_apis(demo_run, admin_headers):
    payload, _, _ = demo_run
    entities = payload["entities"]
    correlation = entities["correlation_id"]
    report_id = _generate_item(payload)["observed"].get("report_id")
    client = TestClient(app)
    for path, needle in [
        ("/api/detections/recent", entities["detection_id"]),
        (f"/api/correlations/{correlation}", correlation),
        ("/api/risk-assessments/recent", entities["risk_assessment_id"]),
        ("/api/approvals/recent", entities["approval_id"]),
        (f"/api/attack-paths/{correlation}", correlation),
        ("/api/threat-hunts", entities["hunt_id"]),
        ("/api/soar/executions", entities["soar_execution_id"]),
        ("/api/audit/logs?skip=0&limit=100", "threat_hunt.created"),
    ] + ([(f"/api/incident-reports/{report_id}", report_id)] if report_id else []):
        response = client.get(path, headers=admin_headers)
        assert response.status_code == 200, f"{path} -> {response.status_code}"
        assert needle in response.text, f"{path} does not return the demo's {needle}"


def test_every_printed_link_is_a_route_the_frontend_declares(demo_run):
    payload, _, _ = demo_run
    routes = FRONTEND_ROUTES.read_text(encoding="utf-8")
    for link in payload["frontend_urls"]:
        assert urlparse(link["url"]).port == 5173, link
        # Detail links are parameterised in the router (``/incidents/:id``),
        # so the route they resolve to is the parent path.
        parent = link["path"].rsplit("/", 1)[0]
        assert link["path"] in routes or parent in routes, (
            f"{link['path']} resolves to {parent!r}, which the frontend does "
            "not declare"
        )


# ---------------------------------------------------------------------------
# C. One coherent incident
# ---------------------------------------------------------------------------


def test_every_stage_names_the_same_correlation(demo_run):
    payload, _, _ = demo_run
    expected = payload["entities"]["correlation_id"]
    named = 0
    for stage in payload["stages"]:
        for item in _items(stage):
            reported = (item.get("observed") or {}).get("correlation_id")
            if reported:
                named += 1
                assert reported == expected, (
                    f"{stage['name']}/{item['check']} reported {reported}, "
                    f"but the demo's incident is {expected}"
                )
    assert named >= 3, "several stages must quote the incident's id"


def test_the_scenario_is_persisted_exactly_once(demo_run):
    payload, baseline, during = demo_run
    added = {table: during[table] - baseline[table] for table in during}
    # Ten events produce nine matched detections; a second copy of the
    # incident would show up as eighteen.
    assert added["detection_results"] == 9, added
    assert added["correlations"] == 3, added
    assert added["correlation_members"] == 9, added
    assert added["detection_rule_failures"] >= 1, "rule failures are tracked too"
    # The report stage must leave a persisted decision row, not nothing: that
    # row is the only thing the Incident Reports page can serve.
    assert added["incident_reports"] == 1, added
    # The whole run is small: no stage may fan out into hundreds of rows.
    assert sum(added.values()) < 200, added


def test_the_primary_correlation_owns_the_detections(demo_run, db_session):
    payload, _, _ = demo_run
    correlation_id = payload["entities"]["correlation_id"]
    members = db_session.execute(
        select(CorrelationMember).where(
            CorrelationMember.correlation_id == correlation_id
        )
    ).scalars().all()
    assert len(members) == 7, "the primary group holds the seven linked detections"

    detections = db_session.execute(
        select(DetectionResult).where(
            DetectionResult.detection_id.in_([str(m.detection_id) for m in members])
        )
    ).scalars().all()
    assert len(detections) == 7
    assert all(d.matched for d in detections)


# ---------------------------------------------------------------------------
# D. A blocked decision executed nothing
# ---------------------------------------------------------------------------


def test_a_denied_or_gated_decision_never_reached_a_provider(demo_run):
    payload, _, _ = demo_run
    response_items = _items(_stage(payload, "response"))
    executed = [item for item in response_items if (item.get("observed") or {}).get("provider_calls")]
    rejected = [
        item
        for item in response_items
        if (item.get("observed") or {}).get("execution_status", "").endswith("REJECTED")
    ]
    assert executed, "an allowed decision must still be able to execute"
    assert len(rejected) >= 2, "the denied and the approval-gated scenarios"
    for item in rejected:
        assert item["status"] == "ok", item["check"]
        assert item["observed"]["provider_calls"] == 0, (
            f"{item['check']} was rejected yet reached the provider"
        )


# ---------------------------------------------------------------------------
# E. Cleanup restores the database
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def cleaned_run(state_file, demo_run):
    """A second, self-contained run used to prove ``--clean`` end to end.

    It depends on ``demo_run`` only to sequence: that fixture's teardown runs
    at the end of the module, so the pending attempt is cleaned explicitly
    first.  Otherwise this baseline would include the other run's rows while
    the cleanup legitimately removes both.
    """
    cli.main(["demo", "--clean", "--json"])
    baseline = runner.table_counts()
    during = None
    try:
        assert cli.main(DEMO_ARGS) == 0
        during = runner.table_counts()
    finally:
        assert cli.main(["demo", "--clean", "--json"]) == 0
    return baseline, during, runner.table_counts(), state_file


def test_cleanup_removes_everything_the_run_added(cleaned_run):
    baseline, during, after, _ = cleaned_run
    assert during != baseline, "the run must actually have written something"
    assert after == baseline, {
        table: (before, after[table])
        for table, before in baseline.items()
        if after[table] != before
    }


def test_cleanup_forgets_the_run_only_after_proving_it(cleaned_run):
    _, _, _, state_file = cleaned_run
    assert json.loads(state_file.read_text(encoding="utf-8"))["runs"] == []


def test_a_second_clean_is_a_no_op_that_reports_no_drift(cleaned_run):
    _, _, _, state_file = cleaned_run
    before = runner.table_counts()
    assert cli.main(["demo", "--clean", "--json"]) == 0
    assert runner.table_counts() == before
    assert json.loads(state_file.read_text(encoding="utf-8"))["runs"] == []
