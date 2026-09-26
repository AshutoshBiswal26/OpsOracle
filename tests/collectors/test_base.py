"""Unit tests for shared collector helpers (retry/backoff, pagination, classification).

Covers requirements 1.2 (pagination), 1.5 (bounded retry with backoff), and 1.6
(non-retryable errors surface for typed-error mapping). Backoff sleeps are injected as a
recorder so the suite never actually waits.
"""

import pytest

from opsoracle.collectors.base import (
    RETRYABLE_ERROR_CODES,
    client_error_code,
    default_is_retryable,
    paginate,
    retry_with_backoff,
)
from opsoracle.errors import ThrottlingError, ValidationError


class ClientError(Exception):
    """Minimal stand-in for botocore ClientError with a ``response`` payload."""

    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


# --------------------------------------------------------------------------- #
# client_error_code / default_is_retryable
# --------------------------------------------------------------------------- #


def test_client_error_code_extracts_code():
    assert client_error_code(ClientError("Throttling")) == "Throttling"


def test_client_error_code_none_for_plain_exception():
    assert client_error_code(ValueError("boom")) is None


def test_client_error_code_none_for_malformed_response():
    exc = Exception("x")
    exc.response = {"Error": "not-a-dict"}
    assert client_error_code(exc) is None


@pytest.mark.parametrize("code", sorted(RETRYABLE_ERROR_CODES))
def test_default_is_retryable_true_for_known_codes(code):
    assert default_is_retryable(ClientError(code)) is True


def test_default_is_retryable_false_for_access_denied():
    assert default_is_retryable(ClientError("AccessDenied")) is False


def test_default_is_retryable_false_for_non_client_error():
    assert default_is_retryable(RuntimeError("nope")) is False


# --------------------------------------------------------------------------- #
# retry_with_backoff
# --------------------------------------------------------------------------- #


def _recorder():
    delays: list[float] = []
    return delays, delays.append


def test_retry_returns_immediately_on_success():
    delays, sleep = _recorder()
    calls = {"n": 0}

    def func():
        calls["n"] += 1
        return "ok"

    result = retry_with_backoff(
        func, max_retries=3, source="s", operation="op", sleep=sleep
    )
    assert result == "ok"
    assert calls["n"] == 1
    assert delays == []  # never slept


def test_retry_recovers_after_transient_errors():
    delays, sleep = _recorder()
    outcomes = [ClientError("ThrottlingException"), ClientError("Throttling"), "ok"]

    def func():
        item = outcomes.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    result = retry_with_backoff(
        func, max_retries=5, source="s", operation="op", sleep=sleep
    )
    assert result == "ok"
    # Two retries -> two sleeps with exponential growth (0.1, 0.2 by default).
    assert delays == [0.1, 0.2]


def test_retry_exhaustion_raises_throttling_with_context():
    delays, sleep = _recorder()

    def func():
        raise ClientError("RequestLimitExceeded")

    with pytest.raises(ThrottlingError) as excinfo:
        retry_with_backoff(
            func, max_retries=2, source="cloudtrail", operation="lookup_events",
            sleep=sleep,
        )
    # initial attempt + 2 retries -> 2 sleeps
    assert len(delays) == 2
    msg = str(excinfo.value)
    assert "cloudtrail" in msg
    assert "lookup_events" in msg


def test_retry_does_not_retry_non_retryable_error():
    delays, sleep = _recorder()
    calls = {"n": 0}

    def func():
        calls["n"] += 1
        raise ClientError("AccessDenied")

    with pytest.raises(ClientError):
        retry_with_backoff(
            func, max_retries=5, source="s", operation="op", sleep=sleep
        )
    assert calls["n"] == 1  # attempted once, no retries
    assert delays == []


def test_retry_backoff_capped_at_max_delay():
    delays, sleep = _recorder()

    def func():
        raise ClientError("Throttling")

    with pytest.raises(ThrottlingError):
        retry_with_backoff(
            func,
            max_retries=5,
            source="s",
            operation="op",
            base_delay=1.0,
            max_delay=4.0,
            sleep=sleep,
        )
    # 1, 2, 4, 4, 4  -> capped at max_delay
    assert delays == [1.0, 2.0, 4.0, 4.0, 4.0]


def test_retry_zero_retries_raises_on_first_failure():
    delays, sleep = _recorder()

    def func():
        raise ClientError("Throttling")

    with pytest.raises(ThrottlingError):
        retry_with_backoff(
            func, max_retries=0, source="s", operation="op", sleep=sleep
        )
    assert delays == []


def test_retry_negative_retries_rejected():
    with pytest.raises(ValidationError):
        retry_with_backoff(
            lambda: None, max_retries=-1, source="s", operation="op"
        )


def test_retry_custom_predicate_used():
    delays, sleep = _recorder()
    outcomes = [ValueError("transient"), "ok"]

    def func():
        item = outcomes.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    result = retry_with_backoff(
        func,
        max_retries=3,
        source="s",
        operation="op",
        sleep=sleep,
        is_retryable=lambda e: isinstance(e, ValueError),
    )
    assert result == "ok"
    assert delays == [0.1]


# --------------------------------------------------------------------------- #
# paginate
# --------------------------------------------------------------------------- #


def test_paginate_single_page():
    pages = [{"Events": [{"EventId": "1"}, {"EventId": "2"}]}]
    result = paginate(lambda token: pages.pop(0))
    assert [e["EventId"] for e in result] == ["1", "2"]


def test_paginate_follows_next_token():
    pages = [
        {"Events": [{"EventId": "1"}], "NextToken": "t1"},
        {"Events": [{"EventId": "2"}], "NextToken": "t2"},
        {"Events": [{"EventId": "3"}]},
    ]
    seen_tokens = []

    def fetch(token):
        seen_tokens.append(token)
        return pages.pop(0)

    result = paginate(fetch)
    assert [e["EventId"] for e in result] == ["1", "2", "3"]
    assert seen_tokens == [None, "t1", "t2"]


def test_paginate_empty_pages():
    result = paginate(lambda token: {"Events": []})
    assert result == []


def test_paginate_preserves_records_unmodified():
    raw = {"EventId": "1", "extra": [1, 2, 3]}
    result = paginate(lambda token: {"Events": [raw]})
    assert result[0] is raw


def test_paginate_custom_keys():
    pages = [
        {"items": [1, 2], "cursor": "c1"},
        {"items": [3]},
    ]
    result = paginate(
        lambda token: pages.pop(0), items_key="items", token_key="cursor"
    )
    assert result == [1, 2, 3]
