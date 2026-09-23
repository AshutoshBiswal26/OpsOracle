"""Typed error hierarchy for OpsOracle.

All errors derive from :class:`OpsOracleError`. Error messages must never include
credential material (access keys, session tokens, secrets); see RULES.md §5 and
requirement 9.3.
"""

from __future__ import annotations


class OpsOracleError(Exception):
    """Base class for all OpsOracle errors."""


class ConfigError(OpsOracleError):
    """Raised when configuration is missing or invalid."""


class ValidationError(OpsOracleError):
    """Raised when input fails validation (e.g., bad time window, bad model field)."""


class CollectionError(OpsOracleError):
    """Raised when evidence collection from an AWS source fails.

    Carries the source and operation to aid debugging without leaking credentials.
    """

    def __init__(
        self,
        message: str,
        *,
        source: str | None = None,
        operation: str | None = None,
    ) -> None:
        self.source = source
        self.operation = operation
        detail = message
        if source:
            detail = f"[{source}] {detail}"
        if operation:
            detail = f"{detail} (operation={operation})"
        super().__init__(detail)


class ThrottlingError(CollectionError):
    """Retryable collection error caused by AWS throttling / rate limiting."""


class AccessError(CollectionError):
    """Non-retryable collection error, e.g. AccessDenied / unauthorized."""


class NormalizationError(OpsOracleError):
    """Raised only for unrecoverable, batch-level normalization failures.

    Per-record problems are handled tolerantly by the normalizer and never raise.
    """


class ReasoningError(OpsOracleError):
    """Raised when the Bedrock invocation or output parsing fails.

    The orchestrator catches this and degrades gracefully to a report without the AI
    reasoning section (requirement 7.7).
    """
