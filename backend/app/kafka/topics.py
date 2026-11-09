"""Explicit Kafka topic provisioning.

Broker auto-topic creation is disabled in the SentinelAI compose file
(``KAFKA_AUTO_CREATE_TOPICS_ENABLE=false``), so every topic the ingestion
worker depends on -- the security-events topic and its dead-letter topic --
must be created explicitly before the worker starts consuming.

:func:`ensure_topics` is idempotent: it lists existing topics and creates only
the missing ones.  A concurrent creator (race) is tolerated.
"""

from __future__ import annotations

import logging

from kafka import KafkaAdminClient
from kafka.admin import NewTopic
from kafka.errors import KafkaError, TopicAlreadyExistsError

logger = logging.getLogger(__name__)


def ensure_topics(
    bootstrap_servers: str,
    topics: list[str],
    *,
    num_partitions: int = 1,
    replication_factor: int = 1,
    request_timeout_ms: int = 10_000,
) -> list[str]:
    """Create any of *topics* that do not yet exist.

    Args:
        bootstrap_servers: Kafka broker address(es).
        topics: Topic names to provision.
        num_partitions: Partitions per created topic.
        replication_factor: Replication factor per created topic.
        request_timeout_ms: Admin request timeout.

    Returns:
        The list of topic names actually created (empty when all existed).
    """
    admin = KafkaAdminClient(
        bootstrap_servers=bootstrap_servers,
        request_timeout_ms=request_timeout_ms,
    )
    try:
        existing = set(admin.list_topics())
        missing = [name for name in topics if name not in existing]
        if not missing:
            logger.info("Kafka topics already present: %s", ", ".join(topics))
            return []

        new_topics = [
            NewTopic(
                name,
                num_partitions=num_partitions,
                replication_factor=replication_factor,
            )
            for name in missing
        ]
        try:
            admin.create_topics(new_topics)
        except TopicAlreadyExistsError:
            # Lost a race with another provisioner; treat as success.
            logger.info("Kafka topics created concurrently: %s", ", ".join(missing))
            return []
        logger.info("Kafka topics created: %s", ", ".join(missing))
        return missing
    except KafkaError:
        logger.error("Kafka topic provisioning failed")
        raise
    finally:
        admin.close()
