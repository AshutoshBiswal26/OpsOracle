"""Investigation context assembly.

Ranks evidence by relevance and enforces a budget so the reasoning stage receives only
the most relevant, traceable evidence (requirement 6). Ranking prefers events that
participate in correlations, then events closest to the center of the investigation
window. Evidence ids are always preserved so the report can trace claims (requirement 6.4).
"""

from __future__ import annotations

from ..models.correlation import Correlation
from ..models.evidence import EvidenceEvent
from ..models.investigation import Investigation, TimeWindow

DEFAULT_MAX_EVENTS = 50


class ContextBuilder:
    def __init__(self, *, max_events: int = DEFAULT_MAX_EVENTS) -> None:
        if max_events <= 0:
            from ..errors import ValidationError

            raise ValidationError("max_events must be positive")
        self._max_events = max_events

    def build(
        self,
        window: TimeWindow,
        events: list[EvidenceEvent],
        correlations: list[Correlation],
    ) -> Investigation:
        correlated_ids = {
            eid for corr in correlations for eid in corr.evidence_ids
        }
        center = window.center()

        def rank_key(event: EvidenceEvent) -> tuple:
            in_corr = event.evidence_id in correlated_ids
            distance = abs((event.timestamp - center).total_seconds())
            # Sort: correlated first (True before False), then closest to center,
            # then evidence_id for deterministic ordering.
            return (0 if in_corr else 1, distance, event.evidence_id)

        ranked = sorted(events, key=rank_key)
        truncated = len(ranked) > self._max_events
        selected = ranked[: self._max_events]

        # Keep only correlations whose evidence survived the budget.
        selected_ids = {e.evidence_id for e in selected}
        kept_correlations = [
            c for c in correlations if set(c.evidence_ids).issubset(selected_ids)
        ]

        return Investigation(
            window=window,
            events=selected,
            correlations=kept_correlations,
            truncated=truncated,
        )
