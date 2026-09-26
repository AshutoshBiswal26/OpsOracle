"""Typed error hierarchy for OpsOracle.

All errors derive from :class:`OpsOracleError`. Error messages must never include
credential material (access keys, session tokens, secrets); see RULES.md §5 and
requirement 9.3. As a defense-in-depth safeguard, every error message is passed
through :func:`redact_secrets` before it reaches the base ``Exception``, so even a
caller that accidentally interpolates a credential into a message will not leak it.
"""

from __future__ import annotations

import re

_REDACTED = "***REDACTED***"

# Patterns for common AWS / generic credential material. These are intentionally
# conservative: they target well-known shapes so ordinary diagnostic text is left
# intact while secrets are scrubbed.
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    # AWS access key IDs: AKIA/ASIA/AROA/AIDA + 16 uppercase-alphanumeric chars.
    re.compile(r"\b(?:AKIA|ASIA|AROA|AIDA|AGPA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b"),
    # AWS secret access keys: 40-char base64-ish blobs.
    re.compile(r"\b[A-Za-z0-9/+=]{40}\b"),
    # Long session tokens (base64-ish, typically much longer than 40 chars).
    re.compile(r"\b[A-Za-z0-9/+=]{100,}\b"),
    # key=value / key: value pairs whose key names a secret.
    re.compile(
        r"(?i)\b(aws_secret_access_key|aws_session_token|secret_access_key|"
        r"session_token|access_key|secret_key|secret|token|password|passwd|pwd|"
        r"authorization|api[_-]?key)\b\s*[=:]\s*\S+"
    ),
)


def redact_secrets(message: str) -> str:
    """Return ``message`` with any credential-looking substrings replaced.

    Used to guarantee that error messages never surface AWS access keys, secret
    keys, session tokens, or ``key=value`` secret assignments (requirement 9.3).
    """
    if not message:
        return message
    redacted = message
    for pattern in _SECRET_PATTERNS:
        if pattern is _SECRET_PATTERNS[3]:
            # Preserve the key name, redact only the value.
            redacted = pattern.sub(
                lambda m: f"{m.group(1)}={_REDACTED}", redacted
            )
        else:
            redacted = pattern.sub(_REDACTED, redacted)
    return redacted


class OpsOracleError(Exception):
    """Base class for all OpsOracle errors.

    Any message passed to an OpsOracle error is scrubbed of credential material
    before being handed to :class:`Exception`, so error text is always safe to log
    or surface (requirement 9.3).
    """

    def __init__(self, message: str = "", *args: object) -> None:
        safe_message = redact_secrets(message) if isinstance(message, str) else message
        super().__init__(safe_message, *args)


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
