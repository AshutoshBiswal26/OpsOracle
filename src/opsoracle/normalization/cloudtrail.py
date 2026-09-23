"""Normalize raw CloudTrail ``lookup_events`` records into ``EvidenceEvent``s.

Normalization is tolerant of missing fields: any single malformed record is skipped
(recorded in ``skipped``) rather than aborting the whole batch (requirement 3.4). Detail
that only lives inside the nested ``CloudTrailEvent`` JSON is parsed and preserved
(requirement 3.3).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from ..models.evidence import Actor, EvidenceEvent, EvidenceSource, ResourceRef


class CloudTrailNormalizer:
    def __init__(self) -> None:
        # Records that could not be normalized, each: {"reason": str, "raw": dict}.
        self.skipped: list[dict] = []

    def normalize(self, raw_records: list[dict]) -> list[EvidenceEvent]:
        self.skipped = []
        events: list[EvidenceEvent] = []
        for record in raw_records or []:
            event = self._normalize_one(record)
            if event is not None:
                events.append(event)
        return events

    def _normalize_one(self, record: dict) -> EvidenceEvent | None:
        if not isinstance(record, dict):
            self.skipped.append({"reason": "record is not a dict", "raw": record})
            return None

        detail = self._parse_detail(record)

        timestamp = self._extract_timestamp(record, detail)
        if timestamp is None:
            self.skipped.append(
                {"reason": "no parseable timestamp", "raw": record}
            )
            return None

        event_name = record.get("EventName") or detail.get("eventName")
        if not event_name:
            self.skipped.append({"reason": "no event name", "raw": record})
            return None

        event_source = record.get("EventSource") or detail.get("eventSource")
        region = detail.get("awsRegion")
        account = detail.get("recipientAccountId") or detail.get("accountId")
        actor = self._extract_actor(record, detail)
        resources = self._extract_resources(record, detail)

        metadata: dict[str, Any] = {
            "event_source": event_source,
            "event_id": record.get("EventId") or detail.get("eventID"),
            "read_only": _coerce_bool(record.get("ReadOnly")),
            "source_ip": detail.get("sourceIPAddress"),
            "error_code": detail.get("errorCode"),
            "error_message": detail.get("errorMessage"),
        }
        # Drop keys with no value to keep metadata compact.
        metadata = {k: v for k, v in metadata.items() if v is not None}

        summary = self._build_summary(event_name, event_source, actor, metadata)

        return EvidenceEvent(
            source=EvidenceSource.CLOUDTRAIL,
            event_type=event_name,
            timestamp=timestamp,
            summary=summary,
            actor=actor,
            resources=resources,
            region=region,
            account=account,
            metadata=metadata,
            raw_ref=record,  # preserve originating record (requirement 3.5)
        )

    @staticmethod
    def _parse_detail(record: dict) -> dict:
        raw = record.get("CloudTrailEvent")
        if not raw:
            return {}
        if isinstance(raw, dict):
            return raw
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except (TypeError, ValueError):
            return {}

    @staticmethod
    def _extract_timestamp(record: dict, detail: dict) -> datetime | None:
        # Prefer the top-level EventTime (boto3 returns a datetime).
        ts = record.get("EventTime")
        if isinstance(ts, datetime):
            return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        # Fall back to the ISO string inside the detailed event.
        raw = detail.get("eventTime") or (ts if isinstance(ts, str) else None)
        if isinstance(raw, str):
            try:
                parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
            except ValueError:
                return None
        return None

    @staticmethod
    def _extract_actor(record: dict, detail: dict) -> Actor | None:
        identity = detail.get("userIdentity") or {}
        actor = Actor(
            type=identity.get("type"),
            principal_id=identity.get("principalId"),
            arn=identity.get("arn"),
            account=identity.get("accountId"),
        )
        # Fall back to the top-level Username if detail lacked identity.
        if not any([actor.type, actor.principal_id, actor.arn, actor.account]):
            username = record.get("Username")
            if username:
                return Actor(type=None, principal_id=username, arn=None, account=None)
            return None
        return actor

    @staticmethod
    def _extract_resources(record: dict, detail: dict) -> list[ResourceRef]:
        resources: list[ResourceRef] = []
        for res in record.get("Resources", []) or []:
            if isinstance(res, dict):
                resources.append(
                    ResourceRef(
                        type=res.get("ResourceType"),
                        name=res.get("ResourceName"),
                    )
                )
        return resources

    @staticmethod
    def _build_summary(event_name, event_source, actor: Actor | None, metadata: dict) -> str:
        who = "unknown principal"
        if actor is not None:
            who = actor.arn or actor.principal_id or actor.type or who
        svc = (event_source or "aws").split(".")[0]
        base = f"{svc} {event_name} by {who}"
        if metadata.get("error_code"):
            base += f" (error: {metadata['error_code']})"
        return base


def _coerce_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return None
