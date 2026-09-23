"""CloudTrail management-event collector (requirement 1).

Retrieves CloudTrail management events for an investigation window via Boto3
``lookup_events``, following pagination and retrying throttling errors. Returns the raw
event records unmodified so nothing is lost before normalization.
"""

from __future__ import annotations

from typing import Any

from ..errors import AccessError, CollectionError, ValidationError
from ..models.investigation import TimeWindow
from .base import RETRYABLE_ERROR_CODES, retry_with_backoff

SOURCE = "cloudtrail"
_OPERATION = "lookup_events"

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

# Access-related botocore error codes → non-retryable AccessError.
_ACCESS_ERROR_CODES = frozenset(
    {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}
)


def _client_error_code(exc: Exception) -> str | None:
    """Extract a botocore ClientError code without importing botocore at module load."""
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return response.get("Error", {}).get("Code")
    return None


def _is_retryable(exc: Exception) -> bool:
    return _client_error_code(exc) in RETRYABLE_ERROR_CODES


class CloudTrailCollector:
    """Collects raw CloudTrail management events for a time window."""

    def __init__(self, client: Any, *, max_retries: int = 5) -> None:
        if client is None:
            raise ValidationError("CloudTrailCollector requires a boto3 client")
        self._client = client
        self._max_retries = max_retries

    def collect(self, window: TimeWindow, filters: dict | None = None) -> list[dict]:
        # TimeWindow already validates start < end and UTC (requirement 1.4); guard type.
        if not isinstance(window, TimeWindow):
            raise ValidationError("window must be a TimeWindow")

        lookup_attributes = self._build_lookup_attributes(filters)
        events: list[dict] = []
        next_token: str | None = None

        while True:
            kwargs: dict[str, Any] = {
                "StartTime": window.start,
                "EndTime": window.end,
                "MaxResults": 50,
            }
            if lookup_attributes:
                kwargs["LookupAttributes"] = lookup_attributes
            if next_token:
                kwargs["NextToken"] = next_token

            page = self._call(kwargs)
            events.extend(page.get("Events", []))  # raw, unmodified (requirement 1.7)
            next_token = page.get("NextToken")
            if not next_token:
                break

        return events

    def _call(self, kwargs: dict) -> dict:
        def _do() -> dict:
            return self._client.lookup_events(**kwargs)

        try:
            return retry_with_backoff(
                _do,
                max_retries=self._max_retries,
                source=SOURCE,
                operation=_OPERATION,
                is_retryable=_is_retryable,
            )
        except Exception as exc:  # noqa: BLE001 - classified into typed errors
            code = _client_error_code(exc)
            if code in _ACCESS_ERROR_CODES:
                raise AccessError(
                    "access denied while collecting CloudTrail events",
                    source=SOURCE,
                    operation=_OPERATION,
                ) from exc
            # ThrottlingError (from retry exhaustion) already carries context; re-raise.
            from ..errors import CollectionError as _CE

            if isinstance(exc, _CE):
                raise
            raise CollectionError(
                f"failed to collect CloudTrail events: {exc}",
                source=SOURCE,
                operation=_OPERATION,
            ) from exc

    @staticmethod
    def _build_lookup_attributes(filters: dict | None) -> list[dict]:
        """Translate a simple ``{key: value}`` filter mapping into LookupAttributes.

        Unknown keys are rejected so typos surface early rather than being silently
        dropped by the AWS API.
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
