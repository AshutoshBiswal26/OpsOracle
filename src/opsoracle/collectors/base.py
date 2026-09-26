"""Collector protocol and shared retry / pagination helpers.

Collectors return *raw* AWS payloads only; normalization happens in a separate stage so
AWS integration stays independent from business logic (RULES.md §6).

This module holds the source-agnostic plumbing every collector reuses:

* :class:`Collector` — the protocol each source-specific collector implements.
* :func:`retry_with_backoff` — bounded exponential backoff for throttling/transient AWS
  errors, surfacing :class:`ThrottlingError` once the retry budget is exhausted
  (requirement 1.5). The ``sleep`` function is injectable so tests never actually wait.
* :func:`paginate` — token-based pagination that follows ``NextToken`` until the source
  is exhausted, accumulating raw records unmodified (requirement 1.2).
* :func:`client_error_code` / :func:`default_is_retryable` — shared botocore error-code
  classification so retryable-vs-typed-error handling is consistent across collectors
  (requirements 1.5, 1.6).
"""

from __future__ import annotations

import time
from typing import Any, Callable, Protocol, TypeVar

from ..errors import ThrottlingError
from ..models.investigation import TimeWindow

T = TypeVar("T")

# Botocore error codes that are safe to retry (throttling / transient).
RETRYABLE_ERROR_CODES = frozenset(
    {
        "Throttling",
        "ThrottlingException",
        "ThrottledException",
        "RequestLimitExceeded",
        "TooManyRequestsException",
        "ServiceUnavailable",
        "RequestThrottled",
    }
)


class Collector(Protocol):
    """A source-specific evidence collector."""

    def collect(self, window: TimeWindow, filters: dict | None = None) -> list[dict]:
        """Return raw AWS records within ``window``. No normalization here."""
        ...


def client_error_code(exc: Exception) -> str | None:
    """Extract a botocore ``ClientError`` code without importing botocore.

    Botocore ``ClientError`` instances carry a ``response`` mapping shaped like
    ``{"Error": {"Code": "..."}}``. Reading it reflectively keeps this module free of a
    hard botocore dependency and lets tests use a lightweight stand-in exception.
    Returns ``None`` when no recognizable code is present.
    """
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        error = response.get("Error")
        if isinstance(error, dict):
            code = error.get("Code")
            if isinstance(code, str):
                return code
    return None


def default_is_retryable(exc: Exception) -> bool:
    """Return ``True`` when ``exc`` is a known throttling/transient AWS error.

    Shared default predicate for :func:`retry_with_backoff`; collectors may pass a
    narrower predicate if a source needs source-specific rules.
    """
    return client_error_code(exc) in RETRYABLE_ERROR_CODES


def retry_with_backoff(
    func: Callable[[], T],
    *,
    max_retries: int,
    source: str,
    operation: str,
    base_delay: float = 0.1,
    max_delay: float = 5.0,
    sleep: Callable[[float], None] = time.sleep,
    is_retryable: Callable[[Exception], bool] | None = None,
) -> T:
    """Call ``func`` with bounded exponential backoff on retryable errors.

    ``func`` is retried up to ``max_retries`` times (so at most ``max_retries + 1``
    total invocations). Between attempts the wait is ``min(base_delay * 2**attempt,
    max_delay)`` seconds. Retryable errors are re-raised as :class:`ThrottlingError`
    once the retry budget is exhausted (requirement 1.5). Non-retryable errors
    propagate immediately so callers can classify them into typed errors
    (requirement 1.6).

    ``sleep`` is injectable so tests can pass a no-op and avoid real delays. When
    ``is_retryable`` is omitted, :func:`default_is_retryable` is used.
    """

    if max_retries < 0:
        from ..errors import ValidationError

        raise ValidationError("max_retries must be non-negative")

    predicate = is_retryable if is_retryable is not None else default_is_retryable

    attempt = 0
    while True:
        try:
            return func()
        except Exception as exc:  # noqa: BLE001 - re-raised/classified below
            retryable = predicate(exc)
            if not retryable or attempt >= max_retries:
                if retryable:
                    raise ThrottlingError(
                        f"exhausted {max_retries} retries: {exc}",
                        source=source,
                        operation=operation,
                    ) from exc
                raise
            delay = min(base_delay * (2**attempt), max_delay)
            sleep(delay)
            attempt += 1


def paginate(
    fetch: Callable[[str | None], dict],
    *,
    items_key: str = "Events",
    token_key: str = "NextToken",
) -> list[dict]:
    """Follow token-based pagination until exhausted, accumulating raw records.

    ``fetch`` receives the current continuation token (``None`` on the first call) and
    returns the raw response page. Records under ``items_key`` are accumulated
    unmodified (requirement 1.7); paging continues while ``token_key`` is present and
    truthy (requirement 1.2). ``fetch`` is responsible for the actual AWS call and may
    wrap it in :func:`retry_with_backoff`.
    """

    items: list[dict] = []
    token: str | None = None
    while True:
        page = fetch(token)
        chunk = page.get(items_key, [])
        if chunk:
            items.extend(chunk)
        token = page.get(token_key)
        if not token:
            break
    return items
