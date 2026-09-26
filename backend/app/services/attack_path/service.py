"""Attack Path Visualization service — V2.21.

Thin read-only orchestrator: builds the deterministic projection for one
correlation and wraps it in the ``AttackPathResponse`` envelope.  The
service performs no writes, triggers no SOAR execution and consults no
external provider; it only reads persisted records through the graph
builder.
"""

from __future__ import annotations

import logging
import uuid

from sqlalchemy.orm import Session

from app.schemas.attack_path import (
    AttackPathAvailability,
    AttackPathGraph,
    AttackPathMetadata,
    AttackPathResponse,
)
from app.schemas.investigation_context import InputAvailability
from app.services.attack_path.builder import AttackPathGraphBuilder
from app.services.attack_path.errors import (
    AttackPathCorrelationNotFoundError,
    AttackPathError,
    AttackPathSourceError,
    AttackPathUnexpectedError,
)

logger = logging.getLogger(__name__)


class AttackPathService:
    """Read-only V2.21 attack-path projection service."""

    def build_graph(
        self,
        db: Session,
        *,
        correlation_id: uuid.UUID | str,
    ) -> AttackPathResponse:
        """Return the evidence-grounded attack-path graph for *correlation_id*.

        Raises :class:`AttackPathCorrelationNotFoundError` when the
        correlation does not exist.  Never writes; never executes.
        """
        try:
            result = AttackPathGraphBuilder(db, correlation_id).build()
        except AttackPathCorrelationNotFoundError:
            raise
        except AttackPathSourceError:
            raise
        except AttackPathError as exc:
            logger.warning("Attack path projection rejected: %s", exc)
            raise AttackPathUnexpectedError(str(exc)) from exc
        except Exception as exc:
            logger.warning("Attack path projection failed internally: %s", exc)
            raise AttackPathUnexpectedError(str(exc)) from exc

        availability = AttackPathAvailability(
            **{
                key: InputAvailability(value)
                for key, value in result.availability.items()
            }
        )
        return AttackPathResponse(
            graph=AttackPathGraph(nodes=result.nodes, edges=result.edges),
            metadata=AttackPathMetadata(
                correlation_id=result.correlation_id,
                generated_at=result.generated_at,
                node_count=len(result.nodes),
                edge_count=len(result.edges),
                truncated=result.truncated,
                limitation=result.limitation,
                bounds=result.bounds,
            ),
            availability=availability,
        )


__all__ = ["AttackPathService"]