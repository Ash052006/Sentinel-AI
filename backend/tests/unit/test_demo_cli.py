"""Unit tests for ``python -m app.cli demo`` (the developer demo command).

Covers the guarantees the demo makes about *itself* rather than about the
pipeline it drives:

* stage-status derivation (a skipped stage is not a silent pass, a failed
  check is never hidden by passing neighbours);
* entity extraction refuses to invent an answer when two stages report
  different identities for the same entity;
* cleanup snapshots round-trip, so ``--clean`` can restore exactly the rows
  a run created;
* repeated runs accumulate per-attempt state instead of overwriting each
  other, and a failed restore keeps its snapshots for a retry;
* the demo's mode snapshot carries no credential material;
* the demo user identity is derived deterministically, and a reused identity
  is never scheduled for deletion;
* the response spy counts provider invocations, which is what makes the
  "a blocked decision executed nothing" claim verifiable.

No test here runs the pipeline, so none of them writes to the database.
"""

from __future__ import annotations

import contextlib
import json
import os
from types import SimpleNamespace

import pytest

from app import cli
from scripts import run_demo_dataset as runner


@contextlib.contextmanager
def monkeypatch_key(name: str, value: str | None):
    """Temporarily set or clear an environment variable.

    ``GEMINI_API_KEY`` needs care: the demo resolves the key from the
    environment *or* from the pydantic settings singleton, and that singleton
    was populated from ``.env`` at import time.  Clearing only ``os.environ``
    would still leave a real key resolvable, so a test that believes Gemini is
    unavailable would in fact reach the live provider.  Both sources are set or
    cleared together and restored afterwards.
    """
    from app.core.config import settings

    original = os.environ.get(name)
    original_setting = settings.gemini_api_key
    if name == "GEMINI_API_KEY":
        settings.gemini_api_key = value or ""
    if value is None:
        os.environ.pop(name, None)
    else:
        os.environ[name] = value
    try:
        yield
    finally:
        settings.gemini_api_key = original_setting
        if original is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = original


# ---------------------------------------------------------------------------
# Stage status
# ---------------------------------------------------------------------------


def test_all_ok_is_pass():
    assert cli._stage_status([{"status": "ok"}, {"status": "ok"}]) == "PASS"


def test_a_failure_is_never_hidden_by_passing_neighbours():
    assert cli._stage_status([{"status": "ok"}, {"status": "failed"}]) == "FAIL"


def test_only_skipped_work_reports_skipped_not_passed():
    assert cli._stage_status([{"status": "skipped"}]) == "SKIP"
    assert cli._stage_status([{"status": "ok"}, {"status": "skipped"}]) == "PASS"


def test_an_empty_stage_is_a_failure_not_a_pass():
    assert cli._stage_status([]) == "FAIL"


# ---------------------------------------------------------------------------
# Entity extraction
# ---------------------------------------------------------------------------


def _report_item(check: str, observed: dict) -> dict:
    return {"check": check, "status": "ok", "note": "", "observed": observed}


def test_entities_prefer_the_persisted_identity():
    persisted = _report_item("ingest", {"correlation_id": "a" * 8})
    entities = cli._entities_from([persisted], {"correlation_id": "a" * 8})
    assert entities["correlation_id"] == "a" * 8


def test_a_stage_contradicting_the_demo_identity_is_refused():
    """A disagreement about the incident's id is a defect, not a detail."""
    items = [_report_item("ingest", {"correlation_id": "b" * 8})]
    with pytest.raises(RuntimeError, match="correlation_id conflict"):
        cli._entities_from(items, {"correlation_id": "a" * 8})


def test_the_prelude_fills_a_key_no_stage_reported():
    entities = cli._entities_from([_report_item("a", {})], {"detection_id": "d" * 8})
    assert entities["detection_id"] == "d" * 8


def test_no_observed_identity_yields_no_claim():
    assert cli._entities_from([_report_item("a", {})], {}) == {}


def test_frontend_links_use_real_routes():
    links = cli._frontend_links({"correlation_id": "c" * 8})
    assert links, "at least the correlation detail page must be linkable"
    for link in links:
        assert link["url"] == f"{link['url'].rsplit(link['path'], 1)[0]}{link['path']}"
        assert link["url"].startswith("http")
    paths = {link["path"] for link in links}
    assert f"/correlations/{'c' * 8}" in paths
    assert f"/attack-paths/{'c' * 8}" in paths
    # Without a correlation there is nothing to deep-link into.
    assert not any("/correlations/" in path for path in
                   {link["path"] for link in cli._frontend_links({})})


# ---------------------------------------------------------------------------
# Cleanup snapshots
# ---------------------------------------------------------------------------


def test_cleanup_snapshot_round_trips():
    cleanup = runner.Cleanup()
    cleanup.track("detection_results", "11111111-1111-1111-1111-111111111111")
    cleanup.track_user("22222222-2222-2222-2222-222222222222")
    restored = runner.Cleanup.restore(cleanup.snapshot())
    assert restored._ids["detection_results"] == set(cleanup._ids["detection_results"])
    assert restored._user_ids == cleanup._user_ids
    assert bool(restored) is True


def test_an_empty_cleanup_is_falsy():
    assert not runner.Cleanup()


def test_restore_of_an_empty_snapshot_is_an_empty_cleanup():
    restored = runner.Cleanup.restore(runner.Cleanup().snapshot())
    assert not restored


def test_demo_mode_snapshot_round_trips():
    mode = runner.DemoMode(
        leave_results=True,
        skip_gemini=True,
        force_offline=True,
        reject_hitl=True,
        label="full",
    )
    snapshot = mode.snapshot()
    assert snapshot == {
        "leave_results": True,
        "skip_gemini": True,
        "force_offline": True,
        "reject_hitl": True,
        "label": "full",
    }
    # The snapshot is written to a file on disk, so it must be JSON-clean and
    # free of any credential material.
    json.dumps(snapshot)
    assert not any("key" in field or "token" in field for field in snapshot)


# ---------------------------------------------------------------------------
# Repeated-run state handling
# ---------------------------------------------------------------------------


@pytest.fixture()
def state_file(tmp_path, monkeypatch):
    path = tmp_path / ".demo_state.json"
    monkeypatch.setattr(cli, "STATE_FILE", path)
    return path


def _payload(attempt: str, baseline: dict[str, int] | None = None) -> dict:
    cleanup = runner.Cleanup()
    cleanup.track("detection_results", f"{attempt}-0000-0000-0000-000000000000")
    return {
        "run_id": "fixed-run",
        "attempt_id": attempt,
        "created_at": f"2026-01-0{attempt[-1]}T00:00:00+00:00",
        "baseline": baseline or {"detection_results": 10},
        "cleanups": [cleanup.snapshot()],
    }


def test_two_runs_of_one_scenario_keep_both_attempts(state_file):
    """The regression that orphaned the first run's users and audit rows."""
    cli._save_run(_payload("aaaaaaa1"))
    cli._save_run(_payload("aaaaaaa2"))
    stored = json.loads(state_file.read_text())["runs"]
    assert len(stored) == 2
    assert {run["attempt_id"] for run in stored} == {"aaaaaaa1", "aaaaaaa2"}


def test_re_saving_the_same_attempt_is_idempotent(state_file):
    cli._save_run(_payload("aaaaaaa1"))
    cli._save_run(_payload("aaaaaaa1"))
    assert len(json.loads(state_file.read_text())["runs"]) == 1


def test_state_with_unreadable_json_is_treated_as_empty(monkeypatch, state_file):
    state_file.write_text("{not json")
    assert cli._load_state() == {"schema": 1, "runs": []}


# ---------------------------------------------------------------------------
# Cleanup reporting
# ---------------------------------------------------------------------------


class _Args:
    run = None


def test_cleanup_of_nothing_is_a_pass(state_file):
    result = cli._clean(_Args())
    assert result["status"] == "PASS"
    assert result["run_ids"] == []


def test_drift_is_measured_against_the_oldest_attempt(
    state_file, monkeypatch
):
    """Two attempts: the second one's baseline already contains the first.

    Comparing the post-cleanup totals to *either* attempt's own baseline
    reports a phantom drift unless the oldest (true pre-demo) baseline is used.
    """
    cli._save_run(_payload("aaaaaaa1", {"detection_results": 10}))
    cli._save_run(_payload("aaaaaaa2", {"detection_results": 19}))
    monkeypatch.setattr(runner, "table_counts", lambda: {"detection_results": 10})
    monkeypatch.setattr(runner, "run_cleanups", lambda db, cleanups: [])

    result = cli._clean(_Args())
    assert result["status"] == "PASS"
    assert result["drift"] == {}
    assert json.loads(state_file.read_text())["runs"] == []


def test_drift_is_reported_and_the_snapshots_are_kept(
    state_file, monkeypatch
):
    cli._save_run(_payload("aaaaaaa1", {"detection_results": 10}))
    monkeypatch.setattr(runner, "table_counts", lambda: {"detection_results": 11})
    monkeypatch.setattr(runner, "run_cleanups", lambda db, cleanups: [])

    result = cli._clean(_Args())
    assert result["status"] == "FAIL"
    assert result["drift"]["detection_results"] == {"after": 11, "baseline": 10}
    # A failed restore must stay on disk so the next --clean can retry it.
    assert len(json.loads(state_file.read_text())["runs"]) == 1


def test_a_cleanup_error_fails_the_command_even_when_counts_match(
    state_file, monkeypatch
):
    cli._save_run(_payload("aaaaaaa1", {"detection_results": 10}))
    monkeypatch.setattr(runner, "table_counts", lambda: {"detection_results": 10})
    monkeypatch.setattr(
        runner,
        "run_cleanups",
        lambda db, cleanups: ["cleanup-failed:IntegrityError"],
    )

    result = cli._clean(_Args())
    assert result["status"] == "FAIL"
    assert result["cleanup_errors"] == ["cleanup-failed:IntegrityError"]
    assert len(json.loads(state_file.read_text())["runs"]) == 1


# ---------------------------------------------------------------------------
# Interdependent cleanups
# ---------------------------------------------------------------------------


def test_several_attempts_are_deleted_in_one_dependency_ordered_pass():
    """Attempts share the deterministic demo users, so they are interdependent.

    An approval carries a real ``users`` foreign key, which means deleting one
    attempt's user before another attempt's approval would abort the whole
    transaction and leave the database half-cleaned.
    """
    first = runner.Cleanup()
    first.track_user("11111111-1111-1111-1111-111111111111")
    second = runner.Cleanup()
    second.track("approval_requests", "22222222-2222-2222-2222-222222222222")

    merged = runner.Cleanup.merge([first, second])

    assert merged._user_ids == first._user_ids
    assert merged._ids["approval_requests"] == second._ids["approval_requests"]


def test_merging_keeps_the_oldest_audit_baseline():
    """A row missing from the oldest baseline is new to every attempt."""
    first = runner.Cleanup()
    first._audit_baseline = {"a"}
    second = runner.Cleanup()
    second._audit_baseline = {"a", "b"}

    merged = runner.Cleanup.merge([first, second])

    assert merged._audit_baseline == {"a"}


# ---------------------------------------------------------------------------
# Determinism helpers
# ---------------------------------------------------------------------------


def test_demo_user_token_is_stable_and_role_scoped():
    assert runner._demo_user_token("analyst") == runner._demo_user_token("analyst")
    assert runner._demo_user_token("analyst") != runner._demo_user_token("admin")


def test_demo_user_token_carries_no_clock():
    """A clock-derived address would make every run create a new user row."""
    assert runner._demo_user_token("analyst") == "22b9a24f-6326-55d6-b4b3-b0235401b37d"


def test_response_spy_counts_only_provider_resolutions():
    from app.schemas.policy_decision import ResponseActionType
    from app.services.response.registry import DEFAULT_RESPONSE_REGISTRY

    spy = runner._CountingResponseRegistry(DEFAULT_RESPONSE_REGISTRY)
    assert spy.calls == 0
    spy.provider_for(ResponseActionType.BLOCK_IP)
    assert spy.calls == 1
    spy.get("mock")
    assert spy.calls == 1, "looking a provider up by name is not an invocation"


def test_demo_hunt_window_defaults_to_the_dataset_window():
    assert runner.DEMO_HUNT_WINDOW is None or isinstance(
        runner.DEMO_HUNT_WINDOW, tuple
    )


def test_a_new_run_does_not_adopt_the_previous_run_identities():
    """A second run in one process must not reuse cached row identities.

    The cached context names rows that the previous attempt's ``--clean`` has
    already deleted, so adopting it makes every later stage fail with
    "correlation does not exist".
    """
    class _Stale:
        detections = ["detection-from-the-first-run"]
        _shared = True

    runner._SHARED_SCENARIO_CONTEXT = _Stale()  # type: ignore[assignment]
    runner.DEMO_HUNT_WINDOW = (1, 2)  # type: ignore[assignment]
    runner._DEFERRED_CLEANUPS.append(runner.Cleanup())

    runner.reset_demo_run_state()

    assert runner._SHARED_SCENARIO_CONTEXT is None
    assert runner.DEMO_HUNT_WINDOW is None
    assert runner._DEFERRED_CLEANUPS == []


def test_the_report_stage_bypasses_the_service_only_when_gemini_is_forbidden():
    """``--no-gemini`` must not be mistaken for "no provider exists".

    The V2.20 report service is the only writer of ``incident_reports``.  When
    the operator forbids the model call *and* a key is available, the demo
    leaves the service alone.  When there is no key at all the service can only
    persist its governed ``failed`` row, so skipping it would leave the Incident
    Reports page empty while the run still reported PASS.
    """
    from dataclasses import replace

    original = runner.demo_mode
    try:
        runner.demo_mode = replace(original, skip_gemini=True)
        with monkeypatch_key("GEMINI_API_KEY", "test-key"):
            assert not runner._resolved_gemini_key(), "the flag suppresses the key"
            assert runner._environment_gemini_key() == "test-key", (
                "the environment key is still observable"
            )

        runner.demo_mode = replace(original, skip_gemini=False)
        with monkeypatch_key("GEMINI_API_KEY", None):
            assert not runner._resolved_gemini_key()
            assert not runner._environment_gemini_key()
    finally:
        runner.demo_mode = original


def test_the_latest_report_reads_through_the_service_read_model(monkeypatch):
    """The demo must report the row the API will serve, not a re-derivation."""
    import uuid

    from app.services.reporting.service import IncidentReportService

    seen: dict[str, object] = {}

    class _Summary:
        def __init__(self, report_id: str) -> None:
            self.report_id = uuid.UUID(report_id)
            self.status = "failed"

    class _Page:
        def __init__(self, items: list[_Summary]) -> None:
            self.items = items

    def _fake_list(self, db, *, page=1, page_size=50, correlation_id=None):
        seen.update(page=page, page_size=page_size, correlation_id=correlation_id)
        return _Page([_Summary("11111111-1111-4111-8111-111111111111")])

    monkeypatch.setattr(IncidentReportService, "list", _fake_list)
    latest = runner._latest_report_for(object(), uuid.uuid4())

    assert latest is not None
    assert str(latest.report_id) == "11111111-1111-4111-8111-111111111111"
    assert seen["page"] == 1 and seen["page_size"] == 1, "newest row only"


def test_incident_memory_counts_only_its_own_correlation_members():
    """The memory title must agree with the correlation it is anchored to.

    A scenario can hold several correlations, so ``context.detection_ids`` spans
    the whole scenario.  Using it here made the memory advertise more matched
    detections than its own correlation contains (9 vs 7), which broke
    auditability between the memory and the correlation row.
    """
    import uuid as _uuid

    event_shared = str(_uuid.uuid4())
    event_other = str(_uuid.uuid4())
    rule = _uuid.uuid4()
    rule_other = _uuid.uuid4()

    def _member(detection_id, event_id, rule_id):
        return SimpleNamespace(
            detection_id=_uuid.UUID(detection_id), event_id=_uuid.UUID(event_id),
            rule_id=rule_id,
        )

    # Seven members on one shared event (the primary correlation) ...
    primary_members = [
        _member(str(_uuid.uuid4()), event_shared, rule) for _ in range(7)
    ]
    # ... and detections elsewhere in the scenario that this memory must ignore.
    stray_detections = [_member(str(_uuid.uuid4()), event_other, rule_other)]

    primary_id = str(_uuid.uuid4())
    context = SimpleNamespace(
        correlation_id=primary_id,
        risk_assessment_id=str(_uuid.uuid4()),
        detections=primary_members + stray_detections,
        detection_ids=[str(d.detection_id) for d in primary_members + stray_detections],
        correlations=[
            SimpleNamespace(correlation_id=_uuid.UUID(primary_id), members=primary_members)
        ],
        risks=[SimpleNamespace(
            correlation_id=_uuid.UUID(primary_id), confidence=None, level=None,
        )],
    )

    payload = runner._current_incident_memory_payload(context, iter(range(1000)))

    assert "7 matched detection(s)" in payload["title"]
    assert "one event" in payload["title"]
    assert "8 matched detection(s)" not in payload["title"]
    finding = payload["findings"][0]
    assert finding.metadata["member_detection_count"] == 7
    assert finding.metadata["distinct_event_count"] == 1
    assert finding.metadata["event_ids"] == [event_shared]
    # Every member detection must be cited as a source, in full.  The previous
    # implementation truncated this list to the first five entries, which made
    # the memory cite fewer detections than the count in its own title and left
    # a reader unable to enumerate the evidence behind that count.
    source_detection_ids = sorted(
        str(s.detection_id) for s in payload["sources"] if s.detection_id
    )
    assert source_detection_ids == sorted(
        str(m.detection_id) for m in primary_members
    )
    assert len(source_detection_ids) == 7
    assert str(stray_detections[0].detection_id) not in source_detection_ids
    # The cross-check that keeps the title's count and the cited provenance
    # from ever drifting apart again.
    assert (
        finding.metadata["cited_member_detection_count"]
        == finding.metadata["member_detection_count"]
    )


def test_incident_memory_fails_loudly_rather_than_truncating_sources():
    """An over-large correlation must not be silently under-cited.

    Truncating the source list is a provenance defect, so exceeding the memory
    source bound is an explicit failure instead of a quiet loss of evidence.
    """
    import uuid as _uuid

    from app.schemas.incident_memory import MAX_MEMORY_SOURCES

    primary_id = str(_uuid.uuid4())
    # More members than a memory may cite, once the correlation source is
    # counted.
    members = [
        SimpleNamespace(
            detection_id=_uuid.uuid4(),
            event_id=_uuid.uuid4(),
            rule_id=_uuid.uuid4(),
        )
        for _ in range(MAX_MEMORY_SOURCES + 1)
    ]
    context = SimpleNamespace(
        correlation_id=primary_id,
        risk_assessment_id=None,
        detections=members,
        detection_ids=[str(d.detection_id) for d in members],
        correlations=[
            SimpleNamespace(
                correlation_id=_uuid.UUID(primary_id), members=members
            )
        ],
        risks=[],
    )

    with pytest.raises(ValueError, match="exceeds the memory source bound"):
        runner._current_incident_memory_payload(context, iter(range(1000)))
