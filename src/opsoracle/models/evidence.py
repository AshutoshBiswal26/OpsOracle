"""The common evidence model shared across the OpsOracle pipeline.

An :class:`EvidenceEvent` is the normalized representation of a single AWS signal. Every
event carries a stable, content-derived ``evidence_id`` so correlations and the final
report can trace claims back to specific evidence (requirements 2.1, 2.2).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from ..errors import ValidationError


class EvidenceSource(str, Enum):
    """Closed set of evidence sources (requirement 2.5)."""

    CLOUDTRAIL = "cloudtrail"
    CLOUDWATCH_METRIC = "cloudwatch_metric"
    CLOUDWATCH_LOG = "cloudwatch_log"
    CLOUDWATCH_ALARM = "cloudwatch_alarm"


@dataclass(frozen=True)
class ResourceRef:
    """Reference to an AWS resource involved in an event."""

    type: str | None = None
    name: str | None = None
    arn: str | None = None

    def to_dict(self) -> dict:
        return {"type": self.type, "name": self.name, "arn": self.arn}

    @classmethod
    def from_dict(cls, d: dict) -> "ResourceRef":
        return cls(type=d.get("type"), name=d.get("name"), arn=d.get("arn"))

    def key(self) -> str | None:
        """Stable identity used for shared-resource correlation and ID derivation."""
        return self.arn or self.name or self.type


@dataclass(frozen=True)
class Actor:
    """The identity that performed an action."""

    type: str | None = None
    principal_id: str | None = None
    arn: str | None = None
    account: str | None = None

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "principal_id": self.principal_id,
            "arn": self.arn,
            "account": self.account,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Actor":
        return cls(
            type=d.get("type"),
            principal_id=d.get("principal_id"),
            arn=d.get("arn"),
            account=d.get("account"),
        )


def _ensure_utc(ts: datetime) -> datetime:
    """Return a timezone-aware UTC datetime, or raise ValidationError."""
    if not isinstance(ts, datetime):
        raise ValidationError(f"timestamp must be a datetime, got {type(ts).__name__}")
    if ts.tzinfo is None:
        raise ValidationError("timestamp must be timezone-aware (UTC)")
    return ts.astimezone(timezone.utc)


def derive_evidence_id(
    source: EvidenceSource,
    event_type: str,
    timestamp: datetime,
    primary_resource: str | None,
    actor_key: str | None,
) -> str:
    """Deterministic, content-derived evidence id.

    The same logical event always yields the same id, which gives stable traceability
    and free deduplication (requirements 2.2, 11.2).
    """

    parts = "|".join(
        [
            source.value,
            event_type or "",
            timestamp.astimezone(timezone.utc).isoformat(),
            primary_resource or "",
            actor_key or "",
        ]
    )
    digest = hashlib.sha1(parts.encode("utf-8")).hexdigest()[:12]
    return f"{source.value}-{digest}"


@dataclass(frozen=True)
class EvidenceEvent:
    """A single normalized piece of operational evidence."""

    source: EvidenceSource
    event_type: str
    timestamp: datetime
    summary: str
    actor: Actor | None = None
    resources: list[ResourceRef] = field(default_factory=list)
    region: str | None = None
    account: str | None = None
    metadata: dict = field(default_factory=dict)
    raw_ref: dict = field(default_factory=dict)
    evidence_id: str = ""

    def __post_init__(self) -> None:
        # Validate required fields (requirement 2.4).
        if not isinstance(self.source, EvidenceSource):
            raise ValidationError("source must be an EvidenceSource")
        if not self.event_type or not isinstance(self.event_type, str):
            raise ValidationError("event_type is required and must be a non-empty string")
        utc_ts = _ensure_utc(self.timestamp)
        object.__setattr__(self, "timestamp", utc_ts)
        if self.summary is None or not isinstance(self.summary, str):
            raise ValidationError("summary is required and must be a string")

        # Assign a deterministic id if one was not explicitly provided.
        if not self.evidence_id:
            primary_resource = self.resources[0].key() if self.resources else None
            actor_key = None
            if self.actor is not None:
                actor_key = self.actor.arn or self.actor.principal_id
            object.__setattr__(
                self,
                "evidence_id",
                derive_evidence_id(
                    self.source,
                    self.event_type,
                    utc_ts,
                    primary_resource,
                    actor_key,
                ),
            )

    def to_dict(self) -> dict:
        return {
            "evidence_id": self.evidence_id,
            "source": self.source.value,
            "event_type": self.event_type,
            "timestamp": self.timestamp.astimezone(timezone.utc).isoformat(),
            "actor": self.actor.to_dict() if self.actor else None,
            "resources": [r.to_dict() for r in self.resources],
            "region": self.region,
            "account": self.account,
            "summary": self.summary,
            "metadata": self.metadata,
            "raw_ref": self.raw_ref,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "EvidenceEvent":
        ts_raw = d.get("timestamp")
        if not ts_raw:
            raise ValidationError("timestamp is required")
        try:
            timestamp = datetime.fromisoformat(ts_raw)
        except (TypeError, ValueError) as exc:
            raise ValidationError(f"invalid timestamp: {ts_raw!r}") from exc
        try:
            source = EvidenceSource(d["source"])
        except (KeyError, ValueError) as exc:
            raise ValidationError(f"invalid source: {d.get('source')!r}") from exc
        actor_d = d.get("actor")
        return cls(
            source=source,
            event_type=d.get("event_type", ""),
            timestamp=timestamp,
            summary=d.get("summary", ""),
            actor=Actor.from_dict(actor_d) if actor_d else None,
            resources=[ResourceRef.from_dict(r) for r in d.get("resources", [])],
            region=d.get("region"),
            account=d.get("account"),
            metadata=d.get("metadata", {}) or {},
            raw_ref=d.get("raw_ref", {}) or {},
            evidence_id=d.get("evidence_id", ""),
        )
