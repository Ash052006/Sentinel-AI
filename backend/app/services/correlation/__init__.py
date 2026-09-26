"""Correlation engine — Step 10B.

Implements the deterministic correlation strategy abstraction consumed by
the Correlation Agent (see :mod:`app.agents.correlation`).

Step 10A defined the Correlation domain contract; Step 10B implements
the first **deterministic baseline correlation strategy** (same-event
correlation) together with the agent that consumes a Step 9I
``DetectionCorrelationBatch`` and produces Step 10A ``CorrelationResult``
objects.

No persistence, no API, and no storage/network/AI dependencies exist in
this step — the engine works entirely in memory.
"""

from app.services.correlation.exceptions import (
    CorrelationError,
    CorrelationInputError,
    CorrelationStrategyError,
)
from app.services.correlation.strategy import (
    SIGNAL_SHARED_EVENT,
    SIGNAL_STANDALONE,
    CorrelationGroup,
    CorrelationStrategy,
    DeterministicCorrelationStrategy,
)

__all__ = [
    "CorrelationError",
    "CorrelationInputError",
    "CorrelationStrategyError",
    "CorrelationGroup",
    "CorrelationStrategy",
    "DeterministicCorrelationStrategy",
    "SIGNAL_SHARED_EVENT",
    "SIGNAL_STANDALONE",
]