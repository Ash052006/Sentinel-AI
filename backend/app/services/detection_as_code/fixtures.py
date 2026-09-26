"""Detection-as-Code fixture loading (V2.17).

The controlled rules root carries per-rule positive/negative fixtures next
to the sources (never inside the engine dirs, never executed):

* Sigma:  ``sigma/fixtures/<rule_id>/positive.json`` and ``negative.json``,
  each a deterministic JSON serialization of the exact normalized event the
  fixture represents (parsed back through
  :class:`~app.schemas.normalized_event.NormalizedSecurityEvent`).
* YARA:   ``yara/fixtures/<rule_id>/positive.bin`` and ``negative.bin``,
  deterministic raw byte payloads.

Every reference is a manifest-relative path resolved against the rules root
via the path-safety guards (``app/services/detection_as_code/paths.py`).
Validation runs the fixture through the **real engine**; nothing here
compiles or executes any code.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.schemas.normalized_event import NormalizedSecurityEvent
from app.services.detection_as_code.paths import resolve_safe

#: Relative per-type fixture roots (posix layout inside the rules root).
SIGMA_FIXTURES_ROOT = "sigma/fixtures"
YARA_FIXTURES_ROOT = "yara/fixtures"


def fixture_ref(rule_id: str, fixture: str, rule_type: str) -> str:
    """Relative manifest reference for a fixture of *rule_id*."""
    root = (
        SIGMA_FIXTURES_ROOT if rule_type == "sigma" else YARA_FIXTURES_ROOT
    )
    return f"{root}/{rule_id}/{fixture}"


def sigma_positive_ref(rule_id: str) -> str:
    return fixture_ref(rule_id, "positive.json", "sigma")


def sigma_negative_ref(rule_id: str) -> str:
    return fixture_ref(rule_id, "negative.json", "sigma")


def yara_positive_ref(rule_id: str) -> str:
    return fixture_ref(rule_id, "positive.bin", "yara")


def yara_negative_ref(rule_id: str) -> str:
    return fixture_ref(rule_id, "negative.bin", "yara")


def default_fixture_refs(rule_id: str, rule_type: str) -> tuple[str, str]:
    """Return ``(positive_fixture, negative_fixture)`` refs for a rule."""
    if rule_type == "sigma":
        return sigma_positive_ref(rule_id), sigma_negative_ref(rule_id)
    return yara_positive_ref(rule_id), yara_negative_ref(rule_id)


def load_sigma_event(root: Path, relative: str) -> NormalizedSecurityEvent:
    """Load and re-validate a Sigma fixture JSON into a security event."""
    path = resolve_safe(root, relative)
    if not path.is_file():
        raise FileNotFoundError(f"sigma fixture missing: {relative}")
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return NormalizedSecurityEvent.model_validate(payload)


def load_yara_bytes(root: Path, relative: str) -> bytes:
    """Load a YARA fixture raw byte payload."""
    path = resolve_safe(root, relative)
    if not path.is_file():
        raise FileNotFoundError(f"yara fixture missing: {relative}")
    return path.read_bytes()


def dump_sigma_event(event: NormalizedSecurityEvent) -> str:
    """Deterministic JSON serialization of a normalized event."""
    return event.model_dump_json(indent=2) + "\n"


def write_sigma_fixture(root: Path, rule_id: str, fixture: str, payload: str) -> Path:
    """Write one Sigma fixture file (deterministic)."""
    directory = root / SIGMA_FIXTURES_ROOT / rule_id
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / fixture
    path.write_text(payload, encoding="utf-8")
    return path


def write_yara_fixture(root: Path, rule_id: str, fixture: str, payload: bytes) -> Path:
    """Write one YARA fixture file (deterministic)."""
    directory = root / YARA_FIXTURES_ROOT / rule_id
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / fixture
    path.write_bytes(payload)
    return path


__all__ = [
    "SIGMA_FIXTURES_ROOT",
    "YARA_FIXTURES_ROOT",
    "sigma_positive_ref",
    "sigma_negative_ref",
    "yara_positive_ref",
    "yara_negative_ref",
    "default_fixture_refs",
    "load_sigma_event",
    "load_yara_bytes",
    "dump_sigma_event",
    "write_sigma_fixture",
    "write_yara_fixture",
]