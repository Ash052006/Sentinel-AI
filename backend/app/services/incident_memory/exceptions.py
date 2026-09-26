"""Incident Memory operational error hierarchy — Step 16 foundation.

Schema-level validation errors live in ``app/schemas/incident_memory.py``
as ``ValueError`` (the staged-contract convention).  This module defines
the operational errors raised by the deterministic memory extraction layer.

Every message is sanitized: it never carries input content, indicator
values, identifiers, credentials, or internal stack traces.  Causes are
chained via ``raise ... from`` so genuine failure details are preserved
without leaking into the message.

A deliberate "not enough information to build memory" outcome is **not** an
exception: the extractor returns an empty list as a valid result.  An
exception in this hierarchy always indicates a genuine failure.
"""

from __future__ import annotations


class IncidentMemoryError(Exception):
    """Base exception for all incident-memory failures."""


class InvalidIncidentMemoryInputError(IncidentMemoryError):
    """The extraction input violates the Incident Memory input contract.

    Raised when the extractor receives something that is not a validated
    ``IncidentMemoryInput``, when the supplied clock is naive or not a
    datetime, or when an input cross-reference or bound cannot be satisfied.
    """


class UnsupportedMemorySignalError(IncidentMemoryError):
    """The extraction request references an unsupported memory category.

    Raised when a caller filters extraction to a memory type that is not
    part of the supported, deterministic taxonomy.
    """


class IncidentMemoryExtractionError(IncidentMemoryError):
    """The deterministic extraction pipeline failed unexpectedly.

    The original cause is preserved through the ``__cause__`` chain; the
    message is deliberately generic and never repeats the underlying
    exception's content.
    """


class IncidentMemoryValidationError(IncidentMemoryError):
    """An assembled memory failed Step 16 contract re-validation.

    Raised when a strategy/assembler produces something that is not a valid
    ``IncidentMemory`` — the extractor never downgrades a genuine failure
    into an empty memory result.
    """


class IncidentMemoryReferenceError(IncidentMemoryError):
    """An assembled memory references sources that cannot be resolved.

    The contract-level equivalent of a fabricated citation; the extractor
    rejects it rather than emitting broken output.
    """


class IncidentMemorySafetyError(IncidentMemoryError, ValueError):
    """Credential-shaped content was detected in extraction input (fail closed).

    Subclasses both ``IncidentMemoryError`` and ``ValueError`` (mirroring
    ``KnowledgeSafetyError``) so both schema paths and service paths can
    catch and reclassify it deterministically.  Secrets are rejected, never
    redacted.
    """