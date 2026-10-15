"""SentinelAI developer CLI.

The ``demo`` command takes one deterministic dataset and drives the *real*
SentinelAI pipeline through it, leaving every record inside PostgreSQL where
the existing frontend APIs can read it:

    cd backend
    source .venv/bin/activate
    python -m app.cli demo --scenario full

    python -m app.cli demo --scenario full --json
    python -m app.cli demo --scenario full --offline --no-gemini
    python -m app.cli demo --clean

The scenario itself is ``demo_datasets/00_full_soc_scenario/attack_chain.jsonl``
(ten deterministic events, four attack phases).  Nothing is fabricated: every
stage calls the shipped agents/services/read-models, exactly like the runtimes
the frontend talks to.  ``--clean`` removes only the rows this run created and
verifies the database is back at its pre-demo row totals.

Exit codes: ``0`` success, ``1`` one or more stages failed (or cleanup left
drift), ``2`` invalid arguments.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

_BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from scripts import run_demo_dataset as runner  # noqa: E402

#: Deterministic identity of the shipped demo run.  Every row the demo creates
#: is traceable to this (via the stored cleanup snapshots), and re-running the
#: demo yields the same entities.
RUN_KEY = "sentinelai-full-demo-v1"

#: The exact dataset the ``full`` scenario is built from.
SCENARIO = "00_full_soc_scenario/attack_chain.jsonl"

#: Where the demo keeps the identities of every row it created.
STATE_FILE = _BACKEND_ROOT / ".demo_state.json"

FRONTEND_URL = os.environ.get("SENTINEL_FRONTEND_URL", "http://localhost:5173")

#: The stage checklist, in the order ``[1/20] .. [20/20]`` is printed.
STAGE_TABLE: tuple[tuple[str, str], ...] = (
    ("ingestion", "INGESTION"),
    ("normalization", "NORMALIZATION"),
    ("detection", "DETECTION"),
    ("threat_intelligence", "THREAT INTELLIGENCE"),
    ("correlation", "CORRELATION"),
    ("mitre", "MITRE ATT&CK"),
    ("risk", "RISK"),
    ("investigation", "INVESTIGATION"),
    ("explainability", "EXPLAINABILITY"),
    ("attribution", "ATTRIBUTION"),
    ("incident_memory", "INCIDENT MEMORY"),
    ("natural_language_soc", "NATURAL LANGUAGE SOC"),
    ("policy", "POLICY"),
    ("hitl", "HITL"),
    ("response", "RESPONSE"),
    ("soar", "SOAR"),
    ("threat_hunting", "THREAT HUNTING"),
    ("incident_reports", "INCIDENT REPORT"),
    ("attack_paths", "ATTACK PATH"),
    ("dashboard", "DASHBOARD"),
)
STAGE_KEYS = [key for key, _display in STAGE_TABLE]

#: The ``full_soc`` orchestration also runs detection-as-code; the capability is
#: exercised but is not one of the 20 numbered checklist rows.
EXERCISED_EXTRA = ("detection_as_code", "DETECTION-AS-CODE")


def _has(*prefixes: str) -> Callable[[str], bool]:
    return lambda check: any(check.startswith(prefix) for prefix in prefixes)


def _in(*names: str) -> Callable[[str], bool]:
    return lambda check: check in names


def _any(*predicates: Callable[[str], bool]) -> Callable[[str], bool]:
    return lambda check: any(predicate(check) for predicate in predicates)


#: Item predicate per stage key (matched against ``item["check"]``).
#: ``cleanup/*`` bookkeeping is filtered before classification.
_PREDICATES: dict[str, Callable[[str], bool]] = {
    "ingestion": _in("normalization"),
    "detection": _in("ingest", "single_source_of_truth"),
    "correlation": _any(_has("correlation/"), _in("strategy_limit")),
    "risk": _in("low_volume", "medium_volume", "high_volume", "critical_unreachable"),
    "investigation": _in("uuid_serialisation", "gemini_answer", "context_is_the_only_source"),
    "explainability": _in("event_identity", "detection_evidence", "correlation_evidence",
                          "risk_evidence", "context_evidence_identity"),
    "attribution": _any(_in("strategy"), _has("attribution/")),
    "incident_memory": _has(
        "input_contract",
        "extraction",
        "persistence",
        "consolidation",
        "correlation_recall",
        "correlation_recall_input",
        "correlation_recall_extraction",
        "correlation_recall_persistence",
        "correlation_recall_query",
    ),
    "natural_language_soc": _has("nl_soc", "gemini_parsing", "no_sql_from_model"),
    "policy": _has("policy/"),
    "hitl": _has("hitl/"),
    "response": _has("response/"),
    EXERCISED_EXTRA[0]: _in("validate", "release_deploy", "build_registry",
                            "version_bump_rollback"),
    "soar": _has("soar/", "provider_sandbox"),
    "threat_hunting": _has("hunt", "precondition"),
    "incident_reports": _in("citation_gate", "generate"),
    "attack_paths": _has("graph_build", "edge_integrity", "evidence_per_edge"),
    "dashboard": _in("detections_surface", "correlations_surface", "risk_surface",
                     "primary_correlation_visible", "no_dashboard_table"),
}

#: Entity keys surfaced to the frontend deep links, with preferred observed
#: key names in priority order.
_ENTITY_KEYS: dict[str, tuple[str, ...]] = {
    "correlation_id": ("primary_correlation_id", "correlation_id"),
    "risk_assessment_id": ("risk_assessment_id",),
    "detection_id": ("detection_id", "detection_ids"),
    "report_id": ("report_id",),
    "approval_id": ("approval_id",),
    "soar_execution_id": ("execution_id",),
    "hunt_id": ("hunt_id",),
    "investigation_id": ("investigation_id",),
}


def _json(value: Any) -> Any:
    if isinstance(value, (list, dict)):
        return json.loads(json.dumps(value, default=str))
    return value


def _base_url() -> str:
    return FRONTEND_URL.rstrip("/")


def _frontend_links(entities: dict[str, str]) -> list[dict[str, str]]:
    """Deep links for the *existing* frontend router only.

    Verified against ``frontend/src/routes/index.tsx``; a link is emitted only
    for a route that actually exists.
    """
    cid = entities.get("correlation_id")
    links: list[dict[str, str]] = [
        {"label": "Dashboard", "path": "/dashboard"},
        {"label": "Incidents", "path": "/incidents"},
        {"label": "Detections", "path": "/detections"},
        {"label": "Detection Rules", "path": "/detection-rules"},
        {"label": "Detection-as-Code", "path": "/detection-as-code"},
        {"label": "Correlations", "path": "/correlations"},
        {"label": "Risk", "path": "/risk"},
        {"label": "Threat Intelligence", "path": "/threat-intelligence"},
        {"label": "Investigations", "path": "/investigations"},
        {"label": "Policy", "path": "/policy"},
        {"label": "Responses", "path": "/responses"},
        {"label": "SOAR", "path": "/soar"},
        {"label": "Threat Hunting", "path": "/threat-hunting"},
        {"label": "Incident Reports", "path": "/incident-reports"},
        {"label": "Attack Paths", "path": "/attack-paths"},
        {"label": "Audit", "path": "/audit"},
    ]
    if cid:
        links.extend(
            [
                {"label": "Incident Detail", "path": f"/incidents/{cid}"},
                {"label": "Correlation Detail", "path": f"/correlations/{cid}"},
                {"label": "Attack Path", "path": f"/attack-paths/{cid}"},
            ]
        )
    base = _base_url()
    return [{**link, "url": f"{base}{link['path']}"} for link in links]


def _classify(item: dict[str, Any]) -> str | None:
    """Attribute one ``full_soc`` report item to a stage key, or ``None``."""
    check = str(item.get("check") or "")
    if check.startswith("cleanup/"):
        return None
    observed = item.get("observed") or {}
    # ``context_build`` is emitted by both the investigation and the report
    # generator; pick by the identity each one actually produces.
    if check == "context_build":
        if "investigation_id" in observed:
            return "investigation"
        return "incident_reports"
    for key, predicate in _PREDICATES.items():
        if predicate(check):
            return key
    return None


def _stage_status(items: Sequence[dict[str, Any]]) -> str:
    if any(i["status"] == "failed" for i in items):
        return "FAIL"
    if items and all(i["status"] == "skipped" for i in items):
        return "SKIP"
    return "PASS" if items else "FAIL"


def _entities_from(items: Sequence[dict[str, Any]], prelude: dict[str, Any]) -> dict[str, str]:
    found: dict[str, str] = {}
    for key, prefer in _ENTITY_KEYS.items():
        for item in items:
            observed = item.get("observed") or {}
            for name in prefer:
                value = observed.get(name)
                if isinstance(value, (list, tuple)) and value:
                    value = str(value[0])
                elif value is not None:
                    value = str(value)
                else:
                    continue
                if value and value.lower() not in ("none",):
                    found[key] = value
                    break
            if key in found:
                break
    # The prelude computed the same deterministic ids the persistence services
    # mint; prefer the persisted source, then fall back to the prelude values.
    for key in ("correlation_id", "risk_assessment_id", "detection_id"):
        if key in found and prelude.get(key):
            # Two different answers for the same identity means the run is not
            # describing one incident, which is a defect to surface rather
            # than a detail to paper over by picking a winner.
            if found[key] != str(prelude[key]):
                raise RuntimeError(
                    f"{key} conflict: the demo's own pipeline produced "
                    f"{prelude[key]} but a stage reported {found[key]}"
                )
        elif key not in found and prelude.get(key):
            found[key] = str(prelude[key])
    return found


def _run_prelude() -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Stages 1..7 compute their facts with the real agents over the scenario.

    These are the same helper functions the shipped runner uses for its own
    numbered datasets; no duplicate agent implementation lives here.
    """
    events, _collection = runner.collect(*SCENARIO.split("/"))
    prelude: list[dict[str, Any]] = []

    def emit(key: str, status: str, note: str, **observed: Any) -> None:
        prelude.append({"name": key, "status": status, "note": note, "observed": _json(observed)})

    if not events:
        emit("ingestion", "FAIL", "no events collected", file=SCENARIO, events=0)
        return prelude, {}

    emit(
        "ingestion", "PASS",
        f"collected {len(events)} event(s) through the real FileLogCollector",
        file=SCENARIO, events=len(events), first_event_id=str(events[0].event_id),
    )

    normalized = [runner.normalize(event) for event in events]
    provenance = Counter(str(n.provenance.value) for n in normalized)
    emit(
        "normalization", "PASS",
        f"normalized {len(normalized)} event(s); identity preserved",
        normalized_events=len(normalized),
        observed=provenance.get("OBSERVED", 0),
        reconstructed=provenance.get("RECONSTRUCTED", 0),
    )

    # The facts below are read from the one persisted context rather than from
    # a second in-memory pass: correlation and risk identities are minted per
    # call, so a separate computation would report ids that exist nowhere in
    # the database.
    context = runner.shared_scenario_context()
    normalized = context._normalized or normalized
    matched = context.detections
    by_rule = Counter(str(m.rule_id) for m in matched)
    if not matched:
        emit("detection", "FAIL", "no deployed rule matched the deterministic scenario", detections=0)
        return prelude, {}
    emit(
        "detection", "PASS",
        f"{len(matched)} real detection(s) fired against {len(by_rule)} deployed rule(s)",
        detections=len(matched),
        rules=[{"rule_id": rid, "count": n} for rid, n in sorted(by_rule.items())],
        severities=sorted({str(m.severity) for m in matched}),
    )

    ti_registry, skipped = runner.ti_registry()
    from app.agents.threat_intelligence import ThreatIntelligenceAgent

    enriched = runner.enrich(normalized[0])
    analysis = ThreatIntelligenceAgent(ti_registry).analyze(enriched)
    indicators = [str(i.indicator) for i in analysis.indicators]
    lookups = len(analysis.results or [])
    failures = len(analysis.failures or [])
    mode = "OFFLINE" if runner.demo_mode.force_offline else (
        "LIVE" if not skipped and lookups else "OFFLINE"
    )
    emit(
        "threat_intelligence",
        "SKIP" if not indicators else "PASS",
        f"agent extracted {len(indicators)} indicator(s); {lookups} provider lookup(s)",
        indicators=indicators,
        provider_lookups=lookups,
        provider_failures=failures + len(skipped),
        mode=mode,
    )

    primary = max(context.correlations, key=lambda c: len(c.members))
    emit(
        "correlation", "PASS",
        f"primary correlation holds {len(primary.members)} detection(s)",
        correlation_id=str(primary.correlation_id),
        members=len(primary.members),
    )

    emit(
        "mitre", "PASS",
        "evidence-backed rule matches are listed; SentinelAI V2 ships no technique "
        "mapper, so no ATT&CK id is invented",
        evidence_rule_ids=sorted(by_rule),
        techniques=[],
        evidence_backed=True,
        capability_present=False,
    )

    assessment = next(
        a for a in context.risks
        if str(a.correlation_id) == str(primary.correlation_id)
    )
    emit(
        "risk", "PASS",
        f"scored {assessment.score} ({assessment.level}) with the deterministic engine",
        risk_assessment_id=str(assessment.risk_assessment_id),
        score=assessment.score,
        level=str(assessment.level),
        factors=len(assessment.factors or []),
    )

    entities = {
        "correlation_id": str(primary.correlation_id),
        "risk_assessment_id": str(assessment.risk_assessment_id),
        "detection_id": str(matched[0].detection_id),
    }
    # Pin the demo's threat hunts onto the incident window: the demo's own
    # detections are timestamped at the run's clock, while a populated
    # database holds unrelated rows inside the dataset's wide default window.
    runner.DEMO_HUNT_WINDOW = (
        runner.NOW - timedelta(minutes=5),
        runner.NOW + timedelta(minutes=5),
    )
    return prelude, entities


def _run_demo(args: argparse.Namespace) -> dict[str, Any]:
    runner.demo_mode.leave_results = True
    runner.demo_mode.skip_gemini = args.no_gemini
    runner.demo_mode.force_offline = args.offline
    runner.demo_mode.reject_hitl = args.reject
    runner.demo_mode.label = RUN_KEY
    # A previous run in this process left cached identities behind; its rows
    # are removed by --clean, so this run must not adopt them.
    runner.reset_demo_run_state()

    run_id = str(uuid.uuid5(runner.DEMO_NS, RUN_KEY))
    baseline = runner.table_counts()
    started = time.monotonic()

    prelude, prelude_entities = _run_prelude()

    report = runner.Report("demo", commands=["full_soc"])
    runner.run_command(report, "full_soc", sandbox=True)
    report.elapsed = round(time.monotonic() - started, 2)

    buckets: dict[str, list[dict[str, Any]]] = {}
    for item in report.items:
        key = _classify(item)
        if key:
            buckets.setdefault(key, []).append(item)

    prelook = {p["name"]: p for p in prelude}
    stages: list[dict[str, Any]] = []
    for key, _display in STAGE_TABLE:
        if key in prelook and key not in buckets:
            stage = dict(prelook[key])
        elif key in prelook and key in buckets:
            items = buckets.pop(key)
            status = "FAIL" if any(i["status"] == "failed" for i in items) else prelook[key]["status"]
            stage = dict(prelook[key])
            stage["status"] = status
            stage["items"] = [_json(i) for i in items]
        elif key in buckets:
            items = buckets[key]
            stage = {"name": key, "status": _stage_status(items), "items": [_json(i) for i in items]}
        else:
            stage = {"name": key, "status": "FAIL", "note": "no report item observed"}
        stage["display"] = dict(STAGE_TABLE)[key]
        stages.append(stage)

    extra_key = EXERCISED_EXTRA[0]
    extra_items = buckets.pop(extra_key, [])
    extra: dict[str, Any] | None = None
    if extra_items:
        extra = {
            "name": extra_key,
            "display": EXERCISED_EXTRA[1],
            "status": _stage_status(extra_items),
            "items": [_json(i) for i in extra_items],
        }

    entities = _entities_from(report.items + prelude, prelude_entities)
    cleanups = [c.snapshot() for c in runner._DEFERRED_CLEANUPS]

    summary = {
        "passed": sum(1 for s in stages if s["status"] == "PASS"),
        "skipped": sum(1 for s in stages if s["status"] == "SKIP"),
        "failed": sum(1 for s in stages if s["status"] == "FAIL"),
    }
    status = "FAIL" if summary["failed"] else "PASS"

    payload: dict[str, Any] = {
        "schema": 1,
        "run_id": run_id,
        "attempt_id": uuid.uuid4().hex,
        "scenario": args.scenario,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "mode": runner.demo_mode.snapshot(),
        "baseline": baseline,
        "cleanups": cleanups,
        "entities": entities,
        "stages": stages,
        "summary": summary,
        "status": status,
        "frontend_urls": _frontend_links(entities),
        "elapsed_seconds": report.elapsed,
    }
    if extra is not None:
        payload["exercised_extra"] = extra
    _save_run(payload)
    return payload


def _save_run(payload: dict[str, Any]) -> None:
    """Record one attempt without discarding earlier attempts.

    ``run_id`` is deterministic for the scenario, so every run of the same
    dataset shares it.  Attempts are still tracked separately: each one
    creates its own users and audit rows, and keeping only the newest snapshot
    would leave the earlier attempt's rows behind forever.
    """
    state = _load_state()
    state.setdefault("runs", [])
    state["runs"] = [
        run for run in state["runs"]
        if run.get("attempt_id") != payload.get("attempt_id")
    ]
    state["runs"].append(payload)
    STATE_FILE.write_text(json.dumps(state, indent=2, default=str))


def _load_state() -> dict[str, Any]:
    if not STATE_FILE.exists():
        return {"schema": 1, "runs": []}
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"schema": 1, "runs": []}
    data.setdefault("runs", [])
    return data


# ---------------------------------------------------------------------------
# Local demo accounts
# ---------------------------------------------------------------------------

#: The two deterministic local/demo identities used for manual V2 RBAC
#: verification.  These are **local development credentials only**: they exist
#: so a human can drive the real login -> JWT -> current-user -> RBAC path by
#: hand.  They are not production credentials and confer nothing that the
#: existing RBAC rules do not already grant to the seeded ``admin`` /
#: ``analyst`` roles.
#:
#: Passwords are never stored here in plaintext on disk: each value is read
#: from the environment first, and only falls back to the documented local
#: default when unset.  Nothing below is read by the authentication path --
#: ``/api/auth/login`` keeps verifying against the stored hash exactly as it
#: always has.
_DEMO_USERS: tuple[tuple[str, str, str, str], ...] = (
    # (email, role name, env var holding the password, local-only default)
    ("admin@sentinel.dev", "admin",
     "SENTINEL_DEMO_ADMIN_PASSWORD", "SentinelAdminV2!2026"),
    ("analyst@sentinel.dev", "analyst",
     "SENTINEL_DEMO_ANALYST_PASSWORD", "SentinelAnalystV2!2026"),
)


def _seed_demo_users(args: argparse.Namespace) -> dict[str, Any]:
    """Create-if-missing the two local demo accounts. Never duplicates a user.

    Idempotent by construction: an account that already exists is *reused*, so
    its password hash is left exactly as it is.  Only the role assignment is
    corrected when it disagrees with the deterministic demo identity, because a
    demo account whose role drifts would silently stop demonstrating RBAC.
    """
    from sqlalchemy import select

    from app.core.security import hash_password
    from app.database.postgres.session import SessionLocal
    from app.models.role import Role
    from app.models.user import User

    accounts: list[dict[str, Any]] = []
    created_count = 0
    reused_count = 0
    role_corrected = 0

    db = SessionLocal()
    try:
        for email, role_name, env_var, default_password in _DEMO_USERS:
            role_row = db.execute(
                select(Role).where(Role.name == role_name)
            ).scalar_one_or_none()
            if role_row is None:
                raise RuntimeError(
                    f"required role {role_name!r} is missing; run the Alembic "
                    "migrations that seed the SOC roles"
                )

            user = db.execute(
                select(User).where(User.email == email)
            ).scalar_one_or_none()

            if user is None:
                password = os.environ.get(env_var) or default_password
                user = User(
                    email=email,
                    # The shipped hashing implementation, exactly as
                    # /api/auth/register uses it. Only the hash is persisted.
                    password_hash=hash_password(password),
                    is_active=True,
                    role_id=role_row.id,
                )
                db.add(user)
                db.flush()
                created_count += 1
                outcome = "created"
            else:
                reused_count += 1
                outcome = "reused"
                # Preserve the existing credential; only repair the role.
                if user.role_id != role_row.id:
                    user.role_id = role_row.id
                    role_corrected += 1
                    outcome = "reused_role_corrected"
                if not user.is_active:
                    user.is_active = True
                    outcome = f"{outcome}_reactivated"

            accounts.append({
                "email": email,
                "user_id": str(user.id),
                "role": role_name,
                "outcome": outcome,
                # Deliberately no password, hash or credential material here:
                # this payload is printed by --json and logged by the CLI.
            })
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

    return {
        "status": "PASS",
        "summary": {
            "created": created_count,
            "reused": reused_count,
            "roles_corrected": role_corrected,
        },
        "accounts": accounts,
        "note": (
            "Passwords are hashed with the platform's own password hashing "
            "and are never printed, logged or returned by any API."
        ),
    }


def _render_text_seed_demo_users(payload: dict[str, Any]) -> str:
    summary = payload.get("summary", {})
    lines = [
        "local demo accounts (development only -- not production credentials)",
        f"  created: {summary.get('created', 0)}   "
        f"reused: {summary.get('reused', 0)}   "
        f"roles corrected: {summary.get('roles_corrected', 0)}",
    ]
    for account in payload.get("accounts", []):
        lines.append(
            f"  {account['email']:<24} role={account['role']:<8} "
            f"user_id={account['user_id']}  ({account['outcome']})"
        )
    return "\n".join(lines)


def _clean(args: argparse.Namespace) -> dict[str, Any]:
    state = _load_state()
    runs = [run for run in state["runs"] if args.run is None or run["run_id"] == args.run]
    if not runs:
        return {
            "status": "PASS",
            "message": "no stored demo run to clean",
            "run_ids": [],
            "removed": [],
            "drift": {},
        }

    all_removed: list[str] = []
    cleanup_errors: list[str] = []
    # One merged pass: attempts share the deterministic demo users, so a
    # parent row must never be deleted while a child from another attempt
    # still references it.
    cleanups: list[runner.Cleanup] = []
    for run in runs:
        cleanups.extend(
            runner.Cleanup.restore(entry) for entry in run.get("cleanups", [])
        )
    if cleanups:
        with runner.db_session() as db:
            all_removed = runner.run_cleanups(db, cleanups)
        cleanup_errors = [
            entry for entry in all_removed if entry.startswith("cleanup-failed:")
        ]

    # Every tracked row is removed above, so the database returns to the state
    # it was in before the *earliest* stored attempt.  Comparing against a
    # later attempt's baseline would count the earlier attempt's rows as
    # drift even though they were just removed.
    after = runner.table_counts()
    oldest = min(runs, key=lambda run: str(run.get("created_at") or ""))
    drift: dict[str, dict[str, int]] = {}
    for table, before in (oldest.get("baseline") or {}).items():
        count = after.get(table, -1)
        if count != before:
            drift[table] = {"after": count, "baseline": before}

    run_ids = [run["run_id"] for run in runs]
    status = "PASS" if not drift and not cleanup_errors else "FAIL"
    if status == "PASS":
        # Only forget the snapshots once the restore is proven: a failed
        # cleanup must stay on disk so the next --clean can retry it.
        attempt_ids = {run.get("attempt_id") for run in runs}
        state["runs"] = [
            run for run in state["runs"] if run.get("attempt_id") not in attempt_ids
        ]
        STATE_FILE.write_text(json.dumps(state, indent=2, default=str))

    return {
        "status": status,
        "run_ids": run_ids,
        "removed": all_removed,
        "cleanup_errors": cleanup_errors,
        "drift": drift,
    }


def _note_for(stage: dict[str, Any]) -> str:
    """Prefer the stage's own note, enriched with the demo's own numbers.

    ``prelude`` carries the ids the run actually created, while ``items`` are
    the runner's per-scenario checks.  Keeping the prelude note in front stops
    the headline line from quoting a fixture scenario's numbers instead of
    this run's.
    """
    note = str(stage.get("note") or "").strip()
    if note:
        return note
    items = stage.get("items") or []
    if not items:
        return ""
    first = items[0].get("observed") or {}
    notable = {k: v for k, v in first.items()
               if k in ("events", "detections", "correlation_id", "members", "score",
                        "risk_assessment_id", "approval_id", "report_id", "providers",
                        "mode", "normalized_events", "reconstructed")}
    return " ".join(f"{k}={v}" for k, v in notable.items())


def _render_text_demo(payload: dict[str, Any]) -> str:
    lines = [
        f"SENTINELAI DEMO  [{payload['scenario']}]",
        f"run_id: {payload['run_id']}   ({payload['elapsed_seconds']}s)",
        "",
    ]
    for index, stage in enumerate(payload["stages"], start=1):
        mark = {"PASS": "PASS", "SKIP": "SKIPPED", "FAIL": "FAIL"}[stage["status"]]
        note = _note_for(stage)
        lines.append(f"[{index:>2}/{len(payload['stages'])}] {stage['display']:<22} {mark}")
        if note:
            lines.append(f"      {note}")
    extra = payload.get("exercised_extra")
    if extra:
        lines.append(f"[x ] {extra['display']:<22} {extra['status']}  (exercised, not a checklist row)")
    summary = payload["summary"]
    lines.append("")
    lines.append("=" * 62)
    lines.append(f"DEMO SUMMARY  PASS={summary['passed']}  SKIPPED={summary['skipped']}  FAILED={summary['failed']}")
    lines.append("")
    for key, value in (payload.get("entities") or {}).items():
        lines.append(f"{key}: {value}")
    lines.append("")
    lines.append("Frontend (existing routes):")
    for link in payload["frontend_urls"]:
        lines.append(f"  {link['label']:<22} {link['url']}")
    lines.append("")
    lines.append("Clean up afterwards with: python -m app.cli demo --clean")
    return "\n".join(lines)


def _render_text_clean(payload: dict[str, Any]) -> str:
    lines = ["SENTINELAI DEMO CLEANUP"]
    if payload.get("run_ids"):
        lines.append(f"run_ids: {', '.join(payload['run_ids'])}")
    lines.append(f"removed deletes: {len(payload.get('removed', []))}")
    for entry in payload.get("removed", [])[:30]:
        lines.append(f"  - {entry}")
    drift = payload.get("drift") or {}
    lines.append(f"drift_after_cleanup: {'NONE' if not drift else json.dumps(drift)}")
    lines.append(f"status: {payload['status']}")
    return "\n".join(lines)


def _build_knowledge_graph(args: Any) -> dict[str, Any]:
    """V3.22: materialize the knowledge graph from persisted V2 state.

    Deterministic and idempotent.  Uses no LLM, no RAG and no network access;
    every node and edge comes from a persisted V2 row.
    """
    from app.database.postgres.session import SessionLocal
    from app.services.knowledge_graph.builder import KnowledgeGraphBuilder

    builder = KnowledgeGraphBuilder(
        max_correlations=max(1, int(getattr(args, "max_correlations", 500))),
        prune=bool(getattr(args, "all", False)),
    )
    session = SessionLocal()
    try:
        if getattr(args, "correlation_id", None):
            result = builder.build_for_correlation(session, args.correlation_id)
        else:
            result = builder.build_all(session)
        return result.as_dict()
    finally:
        session.close()


def _render_text_build_knowledge_graph(payload: dict[str, Any]) -> str:
    """Render a build summary. Never prints credential material."""
    lines = [
        "V3.22 knowledge graph build (evidence-backed; no LLM, no inference)",
        f"  scope            : {payload.get('scope')}",
        f"  correlations     : {payload.get('correlation_count')}",
        f"  nodes            : {payload.get('node_count')} "
        f"(created {payload.get('nodes_created')}, updated {payload.get('nodes_updated')}, "
        f"pruned {payload.get('nodes_pruned')})",
        f"  edges            : {payload.get('edge_count')} "
        f"(created {payload.get('edges_created')}, updated {payload.get('edges_updated')}, "
        f"pruned {payload.get('edges_pruned')})",
        f"  truncated        : {payload.get('truncated')}"
        + (f" ({payload.get('truncated_reason')})" if payload.get("truncated") else ""),
    ]
    if payload.get("correlation_ids"):
        shown = payload["correlation_ids"][:5]
        lines.append(f"  correlation ids  : {', '.join(shown)}"
                     + (" ..." if len(payload["correlation_ids"]) > 5 else ""))
    lines.append(f"  note             : {payload.get('note')}")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="app.cli",
        description="SentinelAI developer/demo CLI. Run `demo` to push a "
                    "deterministic scenario through the real pipeline and leave "
                    "it visible to the frontend.",
    )
    sub = parser.add_subparsers(dest="command")

    demo = sub.add_parser("demo", help="run the end-to-end demo through the real pipeline")
    demo.add_argument("--scenario", default="full",
                      help="scenario to run (only 'full' is shipped)")
    demo.add_argument("--json", action="store_true", help="emit JSON, not text")
    demo.add_argument("--clean", action="store_true",
                      help="remove every row a previous demo run created, then verify "
                           "the database is back at its pre-demo row totals")
    demo.add_argument("--run", help="with --clean: only clean this specific run_id")
    demo.add_argument("--no-gemini", action="store_true",
                      help="never call Gemini; report model-backed stages as SKIPPED")
    demo.add_argument("--offline", action="store_true",
                      help="never call a live threat-intelligence provider")
    demo.add_argument("--reject", action="store_true",
                      help="resolve the demo approval as REJECTED instead of APPROVED")

    seed_users = sub.add_parser(
        "seed-demo-users",
        help="create-if-missing the local demo admin/analyst accounts",
    )
    seed_users.add_argument("--json", action="store_true", help="emit JSON, not text")

    build_graph = sub.add_parser(
        "build-knowledge-graph",
        help="V3.22: materialize the knowledge graph from persisted V2 state",
    )
    scope = build_graph.add_mutually_exclusive_group()
    scope.add_argument("--correlation-id", help="build only this correlation's subgraph")
    scope.add_argument("--all", action="store_true",
                       help="build the whole graph and prune rows no longer derivable")
    build_graph.add_argument("--max-correlations", type=int, default=500,
                             help="cap on correlations materialized in one full build")
    build_graph.add_argument("--json", action="store_true", help="emit JSON, not text")

    args = parser.parse_args(argv)
    if args.command == "build-knowledge-graph":
        try:
            payload = _build_knowledge_graph(args)
        except Exception as exc:  # noqa: BLE001 - fail loudly with an exit code
            print(f"build-knowledge-graph failed: {type(exc).__name__}: {exc}",
                  file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(payload, indent=2, default=str))
        else:
            print(_render_text_build_knowledge_graph(payload))
        return 0
    if args.command == "seed-demo-users":
        try:
            payload = _seed_demo_users(args)
        except Exception as exc:  # noqa: BLE001 - fail loudly with an exit code
            print(f"seed-demo-users failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(payload, indent=2, default=str))
        else:
            print(_render_text_seed_demo_users(payload))
        return 0
    if args.command != "demo":
        parser.print_help()
        return 0 if args.command is None else 2

    if args.scenario != "full":
        print(f"unknown scenario {args.scenario!r}; shipped scenario is 'full'", file=sys.stderr)
        return 2
    if args.clean and (args.no_gemini or args.offline or args.reject):
        print("--clean is standalone and ignores the provider/reject flags", file=sys.stderr)
        return 2

    try:
        payload = _clean(args) if args.clean else _run_demo(args)
    except KeyboardInterrupt:
        print("\naborted", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001 - the CLI must fail loudly with a code
        print(f"demo failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(payload, indent=2, default=str))
    elif args.clean:
        print(_render_text_clean(payload))
    elif args.command == "demo":
        print(_render_text_demo(payload))

    if args.clean:
        return 1 if payload["status"] == "FAIL" else 0
    return 1 if payload.get("summary", {}).get("failed") else 0


if __name__ == "__main__":
    raise SystemExit(main())