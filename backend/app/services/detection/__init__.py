"""Detection rule registry — rule-management and selection layer.

Step 9B establishes the in-memory detection rule registry, which answers
"which detection rules are available, which are enabled, what version,
and which rules should be selected for a particular detection engine".
It is a rule-management layer only — it does **not** execute Sigma or
YARA rules, generate DetectionResult objects, or contact external
services.

Step 9C adds the :mod:`sigma` sub-package for real-time Sigma rule
matching against normalised events.

Step 9D adds the :mod:`yara` sub-package for YARA rule matching against
explicitly supplied content bytes.
"""

from app.services.detection.exceptions import (
    DetectionError,
    DetectionRuleNotFoundError,
    DuplicateDetectionRuleError,
)
from app.services.detection.registry import DetectionRuleRegistry
from app.services.detection.sigma.engine import (
    SigmaDetectionEngine,
    SigmaDetectionReport,
    SigmaRuleFailure,
)
from app.services.detection.sigma.exceptions import (
    InvalidEventDataError,
    MalformedSigmaRuleError,
    SigmaDetectionError,
    UnsupportedSigmaFeatureError,
)
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

__all__ = [
    # Exceptions
    "DetectionError",
    "DuplicateDetectionRuleError",
    "DetectionRuleNotFoundError",
    # Registry
    "DetectionRuleRegistry",
    # Sigma Engine
    "SigmaDetectionEngine",
    "SigmaDetectionReport",
    "SigmaRuleFailure",
    "SigmaDetectionError",
    "MalformedSigmaRuleError",
    "UnsupportedSigmaFeatureError",
    "InvalidEventDataError",
    # YARA Engine
    "YaraDetectionEngine",
    "YaraDetectionReport",
    "YaraRuleFailure",
    "YaraDetectionError",
    "MalformedYaraRuleError",
    "UnsupportedYaraFeatureError",
    "InvalidYaraTargetError",
]
