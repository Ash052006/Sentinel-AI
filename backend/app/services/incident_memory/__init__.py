"""Incident Memory & Learning — foundation layer (Step 16).

Deterministic, evidence-grounded memory extraction: an explicit structured
incident input is converted into zero or more ``IncidentMemory`` records.
There is no persistence, no API, no Kafka, no AI, no RAG retrieval, and no
autonomous modification in this layer.

Public surface:

* :class:`IncidentMemoryExtractor` — the deterministic extraction entry
  point (:func:`IncidentMemoryExtractor.extract`).
* :class:`IncidentMemoryInput` — the explicit structured input contract.
* :mod:`policy` — sufficiency rules, canonical ordering, assembly.
* The :mod:`exceptions` hierarchy.
"""

from app.services.incident_memory import (
    exceptions,
    extractor,
    input,
    policy,
)
from app.services.incident_memory.exceptions import (
    IncidentMemoryError,
    IncidentMemoryExtractionError,
    IncidentMemoryReferenceError,
    IncidentMemorySafetyError,
    IncidentMemoryValidationError,
    InvalidIncidentMemoryInputError,
    UnsupportedMemorySignalError,
)
from app.services.incident_memory.extractor import IncidentMemoryExtractor
from app.services.incident_memory.input import IncidentMemoryInput

__all__ = [
    "IncidentMemoryExtractor",
    "IncidentMemoryInput",
    "IncidentMemoryError",
    "InvalidIncidentMemoryInputError",
    "UnsupportedMemorySignalError",
    "IncidentMemoryExtractionError",
    "IncidentMemoryValidationError",
    "IncidentMemoryReferenceError",
    "IncidentMemorySafetyError",
    "input",
    "policy",
    "exceptions",
    "extractor",
]