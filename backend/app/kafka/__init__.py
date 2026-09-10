"""Kafka transport layer for SentinelAI security events.

Provides the producer, consumer, and serialization components that
transport :class:`SecurityEvent` objects through Apache Kafka.

The flow::

    FileLogCollector → SecurityEvent → KafkaProducer → Kafka topic
    Kafka topic → KafkaConsumer → SecurityEvent → Future agents
"""

from app.kafka.consumer import KafkaEventConsumer
from app.kafka.producer import KafkaEventProducer
from app.kafka.serialization import (
    deserialize_event,
    event_to_dict,
    serialize_event,
)

__all__ = [
    "KafkaEventConsumer",
    "KafkaEventProducer",
    "deserialize_event",
    "event_to_dict",
    "serialize_event",
]