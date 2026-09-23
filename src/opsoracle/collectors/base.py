"""Collector protocol and shared retry helpers.

Collectors return *raw* AWS payloads only; normalization happens in a separate stage so
AWS integration stays independent from business logic (RULES.md §6).
"""

from __future__ import annotations

import time
from typing import Callable, Protocol, TypeVar

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

    Retryable errors are re-raised as :class:`ThrottlingError` once the retry budget is
    exhausted. Non-retryable errors propagate immediately so callers can classify them.
    """

    attempt = 0
    while True:
        try:
            return func()
        except Exception as exc:  # noqa: BLE001 - re-raised/classified below
            retryable = is_retryable(exc) if is_retryable else False
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
