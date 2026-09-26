"""Report models: reasoning result and the final incident report.

Rendering is implemented in ``opsoracle.reporting.incident_report``; this module holds
the data shapes so the reasoning and reporting stages share a contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .correlation import Correlation
from .evidence import EvidenceEvent
from .investigation import TimeWindow


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


@dataclass(frozen=True)
class IncidentReport:
    """The final incident report (requirement 8.1).

    Holds the investigation window, a human-readable summary, the deterministic
    observed timeline and correlations, and the (possibly unavailable) AI reasoning.
    ``truncated`` records whether the context budget dropped evidence (requirement 6.3),
    surfaced as a note in the rendered report.

    Markdown rendering lives in ``opsoracle.reporting.incident_report`` and is invoked
    through :meth:`to_markdown`; keeping the renderer in the reporting stage avoids a
    circular import (that module already imports this one).
    """

    window: TimeWindow
    summary: str
    timeline: list[EvidenceEvent] = field(default_factory=list)
    correlations: list[Correlation] = field(default_factory=list)
    reasoning: ReasoningResult = field(default_factory=ReasoningResult)
    truncated: bool = False

    def to_dict(self) -> dict:
        return {
            "window": self.window.to_dict(),
            "summary": self.summary,
            "timeline": [e.to_dict() for e in self.timeline],
            "correlations": [c.to_dict() for c in self.correlations],
            "reasoning": self.reasoning.to_dict(),
            "truncated": self.truncated,
        }

    def to_markdown(self) -> str:
        """Render the report as Markdown (requirements 8.2-8.5).

        Delegates to the reporting stage's renderer, which separates observed
        deterministic evidence from inferred AI reasoning and cites evidence ids on
        every claim. The import is deferred to call time to avoid a circular import.
        """
        from ..reporting.incident_report import render_markdown

        return render_markdown(self)
