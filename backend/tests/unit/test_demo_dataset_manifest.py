"""F-07 — demo-dataset manifest metadata no longer advertises a fixed defect.

F-06 corrected ``IncidentMemoryLearningService``'s default
``query_service_factory``.  ``scripts/run_demo_dataset.py`` used to describe
that defect as *current* in two places: an inline workaround comment and the
``known_gaps`` list the ``manifest`` command serialises into
``demo_datasets/manifest.json``.

These tests pin the correction at the source of truth (the runner module) so
the stale claim cannot silently reappear.  They are fixture-free — no
database, no Alembic, no external provider — and the generation test writes
only into a temporary directory, never the shipped ``manifest.json``.
"""

from __future__ import annotations

import ast
import json
import pathlib

from scripts import run_demo_dataset as runner

SOURCE_PATH = pathlib.Path(runner.__file__)
SHIPPED_MANIFEST = SOURCE_PATH.resolve().parents[1] / "demo_datasets" / "manifest.json"

#: The stale wording that must never again describe the shipped default as
#: broken / requiring a caller-side workaround.
STALE_MARKERS = (
    "broken default factory",
    "default factory cannot be used as",
    "needs no app change",
)

#: The known gaps unrelated to the resolved Incident Memory Learning defect.
#: They must survive the correction verbatim (order included).
EXPECTED_REMAINING_GAPS = [
    "06_mitre_mapping: SentinelAI V2 has no ATT&CK technique mapper; the command reports the capability gap honestly.",
    "Correlation groups by identical event_id only; multi-event chains do not correlate.",
    "Risk event_breadth is structurally capped at 1 for multi-member correlations (lower than the goal of 3).",
    "JSONL YARA ingestion is unreachable because no shipped source mapping forwards file content; YARA matches only explicit targets (evaluate_target).",
    "Investigation/report/NL-SOC answers require a GEMINI_API_KEY; without one the runner skips and never fabricates.",
    "Threat-intelligence lookups require the real provider keys in .env; failures are captured, never fabricated.",
]


def _source() -> str:
    return SOURCE_PATH.read_text(encoding="utf-8")


def _known_gaps_literal() -> list[str]:
    """Extract the ``known_gaps`` string list from the runner's AST."""
    tree = ast.parse(_source())
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for key, value in zip(node.keys, node.values):
            if (
                isinstance(key, ast.Constant)
                and key.value == "known_gaps"
                and isinstance(value, ast.List)
            ):
                return [
                    element.value
                    for element in value.elts
                    if isinstance(element, ast.Constant)
                    and isinstance(element.value, str)
                ]
    raise AssertionError("known_gaps list literal not found in run_demo_dataset.py")


def _generate_manifest(tmp_path, monkeypatch) -> tuple[dict, runner.Report]:
    """Run ``cmd_manifest`` against a throwaway pack rooted at *tmp_path*."""
    pack_dir = tmp_path / "01_log_collection"
    pack_dir.mkdir()
    (pack_dir / "application_events.jsonl").write_text("{}\n", encoding="utf-8")

    monkeypatch.setattr(runner, "DATASETS", tmp_path)
    monkeypatch.setattr(runner, "COMMANDS", {"log_collection": "01_log_collection"})

    report = runner.Report(command="manifest")
    runner.cmd_manifest(report, sandbox=False)

    written = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    return written, report


# ---------------------------------------------------------------------------
# Source metadata
# ---------------------------------------------------------------------------


def test_source_does_not_describe_the_resolved_defect_as_current():
    source = _source()
    for marker in STALE_MARKERS:
        assert marker not in source, (
            f"stale wording still present in run_demo_dataset.py: {marker!r}"
        )


def test_source_known_gaps_exactly_retain_the_unrelated_entries():
    assert _known_gaps_literal() == EXPECTED_REMAINING_GAPS


def test_source_known_gaps_do_not_mention_the_learning_service():
    gaps = _known_gaps_literal()
    assert not any("IncidentMemoryLearningService" in gap for gap in gaps)
    assert not any("default factory" in gap for gap in gaps)


# ---------------------------------------------------------------------------
# Manifest generation (controlled temporary output directory)
# ---------------------------------------------------------------------------


def test_manifest_generation_still_produces_the_expected_structure(
    tmp_path, monkeypatch
):
    manifest, _report = _generate_manifest(tmp_path, monkeypatch)
    assert manifest["pack"] == "sentinelai-demo-datasets"
    assert isinstance(manifest["known_gaps"], list)
    assert all(isinstance(gap, str) for gap in manifest["known_gaps"])
    assert isinstance(manifest["functions"], list) and manifest["functions"]
    entry = manifest["functions"][0]
    assert entry["id"] == "log_collection"
    assert {"file", "bytes", "sha256"} <= set(entry["files"][0])


def test_generated_manifest_known_gaps_drop_the_resolved_defect(
    tmp_path, monkeypatch
):
    manifest, _report = _generate_manifest(tmp_path, monkeypatch)
    gaps = manifest["known_gaps"]
    assert gaps == EXPECTED_REMAINING_GAPS
    assert not any("IncidentMemoryLearningService" in gap for gap in gaps)


def test_manifest_generation_reports_success(tmp_path, monkeypatch):
    _manifest, report = _generate_manifest(tmp_path, monkeypatch)
    assert not report.failed
    assert any(item["check"] == "manifest_written" for item in report.passed)


def test_shipped_manifest_is_never_touched(tmp_path, monkeypatch):
    before = SHIPPED_MANIFEST.read_bytes()
    _generate_manifest(tmp_path, monkeypatch)
    assert SHIPPED_MANIFEST.read_bytes() == before
