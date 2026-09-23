"""Investigation model: the evidence window plus the selected evidence and correlations."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..errors import ValidationError
from .correlation import Correlation
from .evidence import EvidenceEvent


@dataclass(frozen=True)
class TimeWindow:
    """A closed investigation window ``[start, end]`` in UTC."""

    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        for name, value in (("start", self.start), ("end", self.end)):
            if not isinstance(value, datetime):
                raise ValidationError(f"{name} must be a datetime")
            if value.tzinfo is None:
                raise ValidationError(f"{name} must be timezone-aware (UTC)")
        object.__setattr__(self, "start", self.start.astimezone(timezone.utc))
        object.__setattr__(self, "end", self.end.astimezone(timezone.utc))
        if not self.start < self.end:
            raise ValidationError("start must be strictly before end")

    def center(self) -> datetime:
        return self.start + (self.end - self.start) / 2

    def to_dict(self) -> dict:
        return {"start": self.start.isoformat(), "end": self.end.isoformat()}


@dataclass
class Investigation:
    """The assembled context handed to the reasoning stage."""

    window: TimeWindow
    events: list[EvidenceEvent] = field(default_factory=list)
    correlations: list[Correlation] = field(default_factory=list)
    truncated: bool = False

    def to_dict(self) -> dict:
        return {
            "window": self.window.to_dict(),
            "events": [e.to_dict() for e in self.events],
            "correlations": [c.to_dict() for c in self.correlations],
            "truncated": self.truncated,
        }
