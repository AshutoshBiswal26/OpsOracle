"""CloudTrail management-event collector (requirement 1).

Retrieves CloudTrail management events for an investigation window via Boto3
``lookup_events``, following pagination and retrying throttling errors. Returns the raw
event records unmodified so nothing is lost before normalization.

All source-agnostic plumbing (bounded retry/backoff, token pagination, botocore
error-code classification) lives in :mod:`opsoracle.collectors.base` and is reused here
rather than duplicated, so retry/pagination behavior stays consistent across collectors.
"""

from __future__ import annotations

from typing import Any

from ..errors import AccessError, CollectionError, ValidationError
from ..models.investigation import TimeWindow
from .base import (
    client_error_code,
    default_is_retryable,
    paginate,
    retry_with_backoff,
)

SOURCE = "cloudtrail"
_OPERATION = "lookup_events"
# CloudTrail caps ``lookup_events`` at 50 records per page; keep calls bounded (Req 10.1).
_MAX_RESULTS = 50

# CloudTrail lookup attribute keys accepted in the optional ``filters`` mapping.
_ATTRIBUTE_KEYS = {
    "EventName",
    "EventSource",
    "ResourceType",
    "ResourceName",
    "Username",
    "EventId",
    "ReadOnly",
    "AccessKeyId",
}

# Access-related botocore error codes → non-retryable AccessError (requirement 1.6).
_ACCESS_ERROR_CODES = frozenset(
    {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}
)


class CloudTrailCollector:
    """Collects raw CloudTrail management events for a time window.

    The Boto3 client is injectable (requirement 11.1): tests pass a stub/mock, while
    production leaves it ``None`` so a default ``cloudtrail`` client is built from the
    provided/environment region via the standard credential chain (requirement 9.1).
    """

    def __init__(
        self,
        client: Any = None,
        *,
        region: str | None = None,
        max_retries: int = 5,
    ) -> None:
        if max_retries < 0:
            raise ValidationError("max_retries must be non-negative")
        self._region = region
        self._max_retries = max_retries
        self._client = client if client is not None else self._build_client(region)

    @staticmethod
    def _build_client(region: str | None) -> Any:
        """Build a default Boto3 ``cloudtrail`` client from the credential chain.

        Never accepts hard-coded credentials (requirement 9.1); the region is the only
        optional hint. Any failure to construct a usable client (boto3 unavailable, no
        resolvable region, etc.) is surfaced as a :class:`ValidationError` so callers
        get a clear signal instead of an opaque botocore error.
        """
        try:
            import boto3
        except ImportError as exc:  # pragma: no cover - env-dependent
            raise ValidationError(
                "boto3 is required to build a default CloudTrail client; "
                "install boto3 or pass an explicit client"
            ) from exc
        try:
            kwargs: dict[str, Any] = {}
            if region:
                kwargs["region_name"] = region
            return boto3.client("cloudtrail", **kwargs)
        except Exception as exc:  # noqa: BLE001 - normalized to a typed error
            raise ValidationError(
                f"could not create a CloudTrail client: {exc}"
            ) from exc

    def collect(self, window: TimeWindow, filters: dict | None = None) -> list[dict]:
        # Validate the window BEFORE any AWS call (requirement 1.4). TimeWindow already
        # enforces start < end and UTC on construction; guard the type here so a bad
        # argument fails fast without ever touching the network.
        if not isinstance(window, TimeWindow):
            raise ValidationError("window must be a TimeWindow")

        lookup_attributes = self._build_lookup_attributes(filters)

        def _fetch(token: str | None) -> dict:
            kwargs: dict[str, Any] = {
                "StartTime": window.start,
                "EndTime": window.end,
                "MaxResults": _MAX_RESULTS,
            }
            if lookup_attributes:
                kwargs["LookupAttributes"] = lookup_attributes
            if token:
                kwargs["NextToken"] = token
            return self._call(kwargs)

        # paginate follows NextToken to exhaustion (requirement 1.2) and accumulates the
        # raw event records unmodified (requirement 1.7).
        return paginate(_fetch, items_key="Events", token_key="NextToken")

    def _call(self, kwargs: dict) -> dict:
        """Invoke ``lookup_events`` with bounded backoff and typed error mapping."""

        def _do() -> dict:
            return self._client.lookup_events(**kwargs)

        try:
            # Retry throttling/transient errors with exponential backoff, bounded by
            # max_retries (requirement 1.5). Non-retryable errors propagate immediately.
            return retry_with_backoff(
                _do,
                max_retries=self._max_retries,
                source=SOURCE,
                operation=_OPERATION,
                is_retryable=default_is_retryable,
            )
        except Exception as exc:  # noqa: BLE001 - classified into typed errors below
            code = client_error_code(exc)
            if code in _ACCESS_ERROR_CODES:
                # Non-retryable access failure → typed AccessError, no credential leak
                # (requirements 1.6, 9.3).
                raise AccessError(
                    "access denied while collecting CloudTrail events",
                    source=SOURCE,
                    operation=_OPERATION,
                ) from exc
            # ThrottlingError (raised by retry_with_backoff once the budget is spent) is
            # a CollectionError and already carries source/operation; re-raise as-is.
            if isinstance(exc, CollectionError):
                raise
            raise CollectionError(
                f"failed to collect CloudTrail events: {exc}",
                source=SOURCE,
                operation=_OPERATION,
            ) from exc

    @staticmethod
    def _build_lookup_attributes(filters: dict | None) -> list[dict]:
        """Translate a simple ``{key: value}`` filter mapping into LookupAttributes.

        Supports the CloudTrail lookup attributes (EventName/EventSource/resource, etc.)
        per requirement 1.3. Unknown keys are rejected so typos surface early rather than
        being silently dropped by the AWS API.
        """
        if not filters:
            return []
        attributes: list[dict] = []
        for key, value in filters.items():
            if key not in _ATTRIBUTE_KEYS:
                raise ValidationError(
                    f"unsupported CloudTrail lookup attribute: {key!r}"
                )
            attributes.append({"AttributeKey": key, "AttributeValue": str(value)})
        return attributes
