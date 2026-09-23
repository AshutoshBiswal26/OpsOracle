"""Correlation model.

A :class:`Correlation` is a deterministic, explainable relationship between evidence
events. Correlations are never causal proof; their explanations use qualified language
(RULES.md §4, requirement 5.5).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum


class CorrelationType(str, Enum):
    TEMPORAL_PROXIMITY = "temporal_proximity"
    SHARED_RESOURCE = "shared_resource"
    CHANGE_BEFORE_FAILURE = "change_before_failure"


def derive_correlation_id(ctype: CorrelationType, evidence_ids: list[str]) -> str:
    """Deterministic id so identical correlations dedup naturally."""
    parts = ctype.value + "|" + "|".join(sorted(evidence_ids))
    digest = hashlib.sha1(parts.encode("utf-8")).hexdigest()[:12]
    return f"corr-{digest}"


@dataclass(frozen=True)
class Correlation:
    type: CorrelationType
    evidence_ids: list[str]
    explanation: str
    strength: float | None = None
    correlation_id: str = ""

    def __post_init__(self) -> None:
        if not self.correlation_id:
            object.__setattr__(
                self,
                "correlation_id",
                derive_correlation_id(self.type, self.evidence_ids),
            )

    def to_dict(self) -> dict:
        return {
            "correlation_id": self.correlation_id,
            "type": self.type.value,
            "evidence_ids": list(self.evidence_ids),
            "explanation": self.explanation,
            "strength": self.strength,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Correlation":
        return cls(
            type=CorrelationType(d["type"]),
            evidence_ids=list(d.get("evidence_ids", [])),
            explanation=d.get("explanation", ""),
            strength=d.get("strength"),
            correlation_id=d.get("correlation_id", ""),
        )
