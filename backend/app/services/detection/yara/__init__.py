"""YARA Detection Engine — Step 9D.

Evaluates YARA rules against explicitly supplied content bytes and
produces deterministic, auditable :class:`DetectionResult` objects.

This module implements a **documented supported subset** of YARA
functionality.  Unsupported constructs are rejected explicitly — the
engine never silently ignores or misinterprets unsupported YARA features.

Supported constructs
--------------------
* String matching: literal strings, hex strings, regular expressions
  in YARA source.
* Condition expressions: ``any of them``, ``all of them``, boolean
  combinations, string counts, ``at``/``in`` offsets, ``filesize``,
  ``entrypoint``, ``for ... of``.
* Rule metadata (``meta:``) — captured into evidence.
* Rule tags — captured into evidence.
* Per-rule compilation — malformed rules do not discard valid results.

Unsupported constructs
----------------------
* ``import`` modules (math, pe, elf, etc.).
* ``include`` directives.
* External variables (``externals``).
* ``yara.compile(filepath=...)`` — the engine never reads files from
  disk.
* ``yara.load()`` — compiles from source only.
* Filesystem access from event data — ``file.path`` is never opened.

Relationship to the pipeline::

    NormalizedSecurityEvent / YaraTarget
        -> YaraDetectionEngine.evaluate() / evaluate_target()
            -> YaraDetectionReport
                -> DetectionResult (matches only)
"""

from app.services.detection.yara.engine import (
    YaraDetectionEngine,
    YaraDetectionReport,
    YaraRuleFailure,
)
from app.services.detection.yara.exceptions import (
    InvalidYaraTargetError,
    MalformedYaraRuleError,
    UnsupportedYaraFeatureError,
    YaraDetectionError,
)
from app.services.detection.yara.target_adapter import (
    YaraTarget,
    to_yara_target,
    to_yara_target_from_bytes,
)

__all__ = [
    "YaraDetectionEngine",
    "YaraDetectionReport",
    "YaraRuleFailure",
    "YaraDetectionError",
    "MalformedYaraRuleError",
    "UnsupportedYaraFeatureError",
    "InvalidYaraTargetError",
    "YaraTarget",
    "to_yara_target",
    "to_yara_target_from_bytes",
]
