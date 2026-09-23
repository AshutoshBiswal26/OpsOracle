"""Report models: reasoning result and the final incident report.

Rendering is implemented in ``opsoracle.reporting.incident_report``; this module holds
the data shapes so the reasoning and reporting stages share a contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class CandidateCause:
    """A possible contributing factor, always backed by evidence ids (requirement 8.3)."""

    description: str
    evidence_ids: list[str] = field(default_factory=list)
    confidence: Confidence = Confidence.LOW

    def to_dict(self) -> dict:
        return {
            "description": self.description,
            "evidence_ids": list(self.evidence_ids),
            "confidence": self.confidence.value,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "CandidateCause":
        return cls(
            description=d.get("description", ""),
            evidence_ids=list(d.get("evidence_ids", [])),
            confidence=Confidence(d.get("confidence", "low")),
        )


@dataclass(frozen=True)
class ReasoningResult:
    """Output of the reasoning stage. ``ai_available`` is False on skip/failure."""

    contributing_factors: list[CandidateCause] = field(default_factory=list)
    uncertainty: str = ""
    next_actions: list[str] = field(default_factory=list)
    ai_available: bool = True
    notes: str | None = None

    def to_dict(self) -> dict:
        return {
            "contributing_factors": [c.to_dict() for c in self.contributing_factors],
            "uncertainty": self.uncertainty,
            "next_actions": list(self.next_actions),
            "ai_available": self.ai_available,
            "notes": self.notes,
        }

    @classmethod
    def unavailable(cls, reason: str) -> "ReasoningResult":
        """Construct a graceful-degradation result (requirement 7.7)."""
        return cls(ai_available=False, notes=reason)
