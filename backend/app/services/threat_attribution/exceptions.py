"""Threat Attribution Engine exception hierarchy — Step 15.

Schema-level validation errors live in ``app/schemas/threat_attribution.py``
(Step 14).  This module defines the operational errors raised by the Step 15
engine, its input contract, and its attribution strategy.

Every message is sanitized: it never carries raw input, target identifiers,
evidence payloads, credentials, or internal stack traces.  Causes are
chained via ``raise ... from`` so genuine failure details are preserved
without leaking them into the message.  A genuine engine failure is always
distinguishable from a deliberate "there is not enough evidence" result —
the latter is a normal, valid categorical ``AttributionStatus`` on the
returned assessment, never an exception.

The hierarchy mirrors the deterministic exception conventions established in
the earlier engine steps (correlation 10B, risk 11B): a subsystem base class
with distinct input / strategy / safety subclasses.
"""

from __future__ import annotations


class AttributionError(Exception):
    """Base exception for all threat attribution subsystem errors."""


class InvalidAttributionInputError(AttributionError):
    """The attribution input violates the Step 15 input contract.

    Raised when the engine receives something that is not a validated
    ``ThreatAttributionInput``, or when the input exceeds engine-level
    bounds (claim cap, supported-target cap, prepared evidence metadata
    size).
    """


class UnsupportedAttributionSignalError(AttributionError):
    """A claim targets a category the deterministic policy cannot support.

    The Step 15 policy only attributes to explicit, named candidates.  A
    claim whose ``target_type`` is ``unknown`` names nothing and is
    therefore an unsupported attribution signal, rejected fail-closed.
    """


class AttributionSafetyError(AttributionError, ValueError):
    """Credential-shaped content was detected in attribution input.

    Subclasses both ``AttributionError`` and ``ValueError`` (mirroring
    ``KnowledgeSafetyError``) so both the engine path and any schema-style
    validation path can catch and reclassify it deterministically.  Secrets
    are rejected, never redacted.
    """


class AttributionStrategyError(AttributionError):
    """The configured attribution strategy failed unexpectedly.

    The original cause is preserved through the ``__cause__`` chain; the
    message is deliberately generic and never repeats the underlying
    exception's content.
    """


class AttributionOutputValidationError(AttributionError):
    """A strategy returned an object that is not a valid Step 14 assessment.

    Raised when the strategy's result is not an ``AttributionAssessment``
    or fails Step 14 contract re-validation — the engine never silently
    downgrades a genuine failure to an "unattributed" result.
    """


class AttributionEvidenceReferenceError(AttributionError):
    """An attribution hypothesis references evidence that cannot be resolved.

    Raised when a strategy would produce a hypothesis whose evidence
    references do not resolve to the assessment's evidence records — the
    contract-equivalent of a fabricated citation.
    """