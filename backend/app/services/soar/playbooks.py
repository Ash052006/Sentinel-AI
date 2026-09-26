"""SOAR playbook registry (V2.18).

The closed, immutable, server-authoritative registry of declarative
playbooks.  V2.18 ships a fixed seed set:

* one single-step playbook per closed operation (``block_ip``,
  ``block_domain``, ``quarantine_file``, ``disable_account``,
  ``terminate_session``, ``isolate_endpoint``);
* one composite orchestration playbook (``endpoint_containment``)
  demonstrating multi-step, multi-provider orchestration where secondary
  steps bind explicit targets — still structurally validated, never client
  supplied at execution time.

Boundary: playbooks are **registered in code**; no client can create,
upload, import or mutate a playbook through the API.  The API exposes
read-only playbook surfaces plus governed execution/cancel/dry-run.
"""

from __future__ import annotations

from app.schemas.policy_decision import ResponseActionType
from app.schemas.soar import (
    SoarFailurePolicy,
    SoarPlaybookDefinition,
    SoarStep,
)
from app.services.soar.errors import SoarValidationError


def _single_step_playbook(
    *,
    playbook_id: str,
    name: str,
    description: str,
    action: ResponseActionType,
    provider_id: str,
) -> SoarPlaybookDefinition:
    """One declarative playbook whose single step performs *action* via
    *provider_id*, inheriting the decision's canonical target."""
    return SoarPlaybookDefinition(
        playbook_id=playbook_id,
        name=name,
        description=description,
        primary_action=action,
        failure_policy=SoarFailurePolicy.STOP_ON_FAILURE,
        steps=[
            SoarStep(
                step_number=1,
                label=name,
                provider_id=provider_id,
                operation=action,
                target=None,
                retries=0,
                timeout_seconds=30,
            )
        ],
    )


def _seed_definitions() -> list[SoarPlaybookDefinition]:
    """The fixed seed descriptors (deterministic, code-owned)."""
    return [
        _single_step_playbook(
            playbook_id="block_ip",
            name="Block source IP",
            description=(
                "Single-step workflow that blocks the authorized source IP "
                "via the firewall sandbox adapter."
            ),
            action=ResponseActionType.BLOCK_IP,
            provider_id="firewall",
        ),
        _single_step_playbook(
            playbook_id="block_domain",
            name="Block domain",
            description=(
                "Single-step workflow that blocks the authorized domain via "
                "the firewall sandbox adapter."
            ),
            action=ResponseActionType.BLOCK_DOMAIN,
            provider_id="firewall",
        ),
        _single_step_playbook(
            playbook_id="quarantine_file",
            name="Quarantine file",
            description=(
                "Single-step workflow that quarantines the authorized file "
                "via the EDR sandbox adapter."
            ),
            action=ResponseActionType.QUARANTINE_FILE,
            provider_id="edr",
        ),
        _single_step_playbook(
            playbook_id="disable_account",
            name="Disable account",
            description=(
                "Single-step workflow that disables the authorized account "
                "via the identity sandbox adapter."
            ),
            action=ResponseActionType.DISABLE_ACCOUNT,
            provider_id="identity",
        ),
        _single_step_playbook(
            playbook_id="terminate_session",
            name="Terminate session",
            description=(
                "Single-step workflow that terminates the authorized session "
                "via the EDR sandbox adapter."
            ),
            action=ResponseActionType.TERMINATE_SESSION,
            provider_id="edr",
        ),
        _single_step_playbook(
            playbook_id="isolate_endpoint",
            name="Isolate endpoint",
            description=(
                "Single-step workflow that isolates the authorized endpoint "
                "via the EDR sandbox adapter."
            ),
            action=ResponseActionType.ISOLATE_ENDPOINT,
            provider_id="edr",
        ),
        SoarPlaybookDefinition(
            playbook_id="endpoint_containment",
            name="Endpoint containment",
            description=(
                "Composite orchestration: isolate the authorized endpoint, "
                "then block the bound command-and-control IP at the firewall "
                "and disable the bound actor account at the identity adapter. "
                "Secondary targets are bound at registration and structurally "
                "validated — never supplied at execution time."
            ),
            primary_action=ResponseActionType.ISOLATE_ENDPOINT,
            failure_policy=SoarFailurePolicy.STOP_ON_FAILURE,
            steps=[
                SoarStep(
                    step_number=1,
                    label="Isolate endpoint",
                    provider_id="edr",
                    operation=ResponseActionType.ISOLATE_ENDPOINT,
                    target=None,
                    retries=0,
                    timeout_seconds=30,
                ),
                SoarStep(
                    step_number=2,
                    label="Block C2 IP",
                    provider_id="firewall",
                    operation=ResponseActionType.BLOCK_IP,
                    target="198.51.100.7",
                    retries=1,
                    timeout_seconds=30,
                ),
                SoarStep(
                    step_number=3,
                    label="Disable actor account",
                    provider_id="identity",
                    operation=ResponseActionType.DISABLE_ACCOUNT,
                    target="actor-198.51.100.7@example.com",
                    retries=0,
                    timeout_seconds=30,
                ),
            ],
        ),
    ]


class SoarPlaybookRegistry:
    """Closed, immutable registry of the code-owned declarative playbooks."""

    def __init__(self, definitions: list[SoarPlaybookDefinition] | None = None) -> None:
        self._codex: dict[str, SoarPlaybookDefinition] = {}
        for definition in definitions if definitions is not None else _seed_definitions():
            self._register(definition)

    def _register(self, definition: SoarPlaybookDefinition) -> None:
        if not isinstance(definition, SoarPlaybookDefinition):
            raise SoarValidationError("a playbook must be a SoarPlaybookDefinition")
        if definition.playbook_id in self._codex:
            raise SoarValidationError(
                f"duplicate registered playbook id {definition.playbook_id!r}"
            )
        if not definition.steps:
            raise SoarValidationError("a playbook must declare at least one step")
        if definition.steps[0].operation is not definition.primary_action:
            raise SoarValidationError(
                "a playbook's first step must perform its primary_action"
            )
        self._codex[definition.playbook_id] = definition

    def get(self, playbook_id: str) -> SoarPlaybookDefinition | None:
        return self._codex.get(playbook_id)

    def require(self, playbook_id: str) -> SoarPlaybookDefinition:
        """Resolve a registered playbook by id.

        Raises:
            SoarValidationError: unknown playbook id (fail closed).
        """
        definition = self._codex.get(playbook_id)
        if definition is None:
            raise SoarValidationError(
                f"no registered playbook for id '{playbook_id}'"
            )
        return definition

    def ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._codex))

    def all(self) -> list[SoarPlaybookDefinition]:
        return [self._codex[key] for key in sorted(self._codex)]


def default_playbook_registry() -> SoarPlaybookRegistry:
    return SoarPlaybookRegistry()


DEFAULT_SOAR_PLAYBOOK_REGISTRY = default_playbook_registry()

__all__ = [
    "DEFAULT_SOAR_PLAYBOOK_REGISTRY",
    "SoarPlaybookRegistry",
    "default_playbook_registry",
]