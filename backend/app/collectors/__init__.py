"""Log collectors for ingesting security events into SentinelAI.

Each collector reads from a specific source type and converts raw records
into validated :class:`SecurityEvent` objects.
"""

from app.collectors.base import BaseCollector, CollectionResult
from app.collectors.file_collector import FileLogCollector

__all__ = [
    "BaseCollector",
    "CollectionResult",
    "FileLogCollector",
]
