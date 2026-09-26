"""Response providers (Step 25).

The provider abstraction and the deterministic development provider used
by Version 1.

**This is a simulation layer.**  ``MockResponseProvider`` simulates an
action's execution and returns a structured result.  It does **not**
modify the host system, does not run process-spawning utilities, does not
call external systems, and does not touch OS or
filesystem APIs — it literally blocks/quarantines/disables nothing.

Real integrations (firewall, EDR, IAM, SOAR, cloud security APIs) belong
to the future SOAR/integration scope and MUST implement the same
``ResponseProvider`` interface: they receive a *validated structured
request*, never raw natural language, never shell commands, never
arbitrary Python.
"""

from __future__ import annotations

import abc
from datetime import datetime, timezone
from typing import Any

from app.schemas.policy_decision import ResponseActionType
from app.schemas.response import (
    ResponseExecutionStatus,
    ResponseRequest,
    ResponseResult,
)
from app.schemas.security_event import Provenance


def _default_now() -> datetime:
    return datetime.now(timezone.utc)


class ResponseProvider(abc.ABC):
    """Interface every realization of a response action must implement.

    Deterministic, side-effect-bearing only through documented adapters.
    ``execute`` returns a fully-formed :class:`ResponseResult` echoing the
    validated request.  A provider that cannot run raises
    :class:`~app.services.response.errors.ResponseProviderError` (never
    returns a fake success).
    """

    #: Stable, non-user-controlled identity recorded on results.
    name: str = ""

    #: The closed subset of actions this provider realizes.
    supported_actions: frozenset[ResponseActionType] = frozenset()

    @abc.abstractmethod
    def execute(
        self,
        request: ResponseRequest,
        *,
        clock: Any = None,
    ) -> ResponseResult:
        """Execute *request* (already policy-gated and target-validated)
        and return its :class:`ResponseResult`."""

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{self.__class__.__name__} name={self.name!r}>"


#: Blank messages are not allowed; Result.message validator rejects blanks.
def _simulated_message(action: ResponseActionType) -> str:
    return f"Simulated {action.value} execution"


class MockResponseProvider(ResponseProvider):
    """Deterministic development provider covering all six actions.

    Outcome semantics:

    * a properly gated request returns ``EXECUTED`` with a fixed template
      message and ``started_at == completed_at`` (instant, simulated);
    * it never blocks traffic, quarantines files, disables accounts,
      terminates sessions, or isolates endpoints — nothing on the host,
      filesystem, or network is touched;
    * it never sleeps, never randomizes, never contacts anything.
    """

    name = "mock"

    supported_actions = frozenset(ResponseActionType)

    def execute(
        self,
        request: ResponseRequest,
        *,
        clock: Any = None,
    ) -> ResponseResult:
        now = (clock() if clock is not None else _default_now())
        tz = now.tzinfo
        if tz is None or tz.utcoffset(now) is None:
            from app.services.response.errors import ResponseProviderError

            raise ResponseProviderError(
                "provider clock must return a timezone-aware timestamp"
            )
        return ResponseResult(
            response_id=request.response_id,
            policy_decision_id=request.policy_decision_id,
            correlation_id=request.correlation_id,
            action_type=request.action_type,
            execution_status=ResponseExecutionStatus.EXECUTED,
            target=request.target,
            provider=self.name,
            started_at=now,
            completed_at=now,
            message=_simulated_message(request.action_type),
            error_code=None,
            metadata={"simulated": True, "provider_class": self.__class__.__name__},
            timestamp=now,
        )


#: Canonical shared development provider (stateless, reusable).
MOCK_PROVIDER = MockResponseProvider()


__all__ = [
    "MOCK_PROVIDER",
    "MockResponseProvider",
    "ResponseProvider",
]