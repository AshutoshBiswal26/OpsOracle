"""Deterministic correlation engine.

Applies a small set of explainable rules over ordered evidence and emits
:class:`Correlation` objects. Correlations describe relationships, never proven
causality; explanations use qualified language such as "preceded" / "correlated with"
(RULES.md §4, requirement 5.5).
"""

from __future__ import annotations

from datetime import timedelta
from itertools import combinations

from ..models.correlation import Correlation, CorrelationType
from ..models.evidence import EvidenceEvent
from .classify import is_change, is_failure

DEFAULT_PROXIMITY_WINDOW = timedelta(minutes=5)
DEFAULT_CHANGE_BEFORE_FAILURE_WINDOW = timedelta(minutes=15)


class CorrelationEngine:
    def __init__(
        self,
        *,
        proximity_window: timedelta = DEFAULT_PROXIMITY_WINDOW,
        change_before_failure_window: timedelta = DEFAULT_CHANGE_BEFORE_FAILURE_WINDOW,
    ) -> None:
        self._proximity_window = proximity_window
        self._cbf_window = change_before_failure_window

    def correlate(self, events: list[EvidenceEvent]) -> list[Correlation]:
        # Deduplicate by deterministic evidence id first so duplicate inputs cannot
        # produce spurious self-correlations (requirement 11.2).
        unique = {e.evidence_id: e for e in events}
        ordered = sorted(unique.values(), key=lambda e: (e.timestamp, e.evidence_id))
        found: list[Correlation] = []
        found.extend(self._temporal_proximity(ordered))
        found.extend(self._shared_resource(ordered))
        found.extend(self._change_before_failure(ordered))
        # Deduplicate by deterministic correlation id (requirement 5.6 returns [] if none).
        deduped: dict[str, Correlation] = {}
        for corr in found:
            deduped.setdefault(corr.correlation_id, corr)
        return list(deduped.values())

    def _temporal_proximity(self, events: list[EvidenceEvent]) -> list[Correlation]:
        results: list[Correlation] = []
        for a, b in combinations(events, 2):
            delta = abs((b.timestamp - a.timestamp).total_seconds())
            if delta <= self._proximity_window.total_seconds():
                results.append(
                    Correlation(
                        type=CorrelationType.TEMPORAL_PROXIMITY,
                        evidence_ids=[a.evidence_id, b.evidence_id],
                        explanation=(
                            f"{a.event_type} and {b.event_type} occurred within "
                            f"{int(delta)}s of each other (correlated with, not causal)"
                        ),
                        strength=self._proximity_strength(delta),
                    )
                )
        return results

    def _shared_resource(self, events: list[EvidenceEvent]) -> list[Correlation]:
        by_resource: dict[str, list[EvidenceEvent]] = {}
        for event in events:
            for res in event.resources:
                key = res.key()
                if key:
                    by_resource.setdefault(key, []).append(event)

        results: list[Correlation] = []
        for key, group in by_resource.items():
            if len(group) < 2:
                continue
            for a, b in combinations(group, 2):
                results.append(
                    Correlation(
                        type=CorrelationType.SHARED_RESOURCE,
                        evidence_ids=[a.evidence_id, b.evidence_id],
                        explanation=(
                            f"{a.event_type} and {b.event_type} both reference "
                            f"resource {key} (correlated with)"
                        ),
                    )
                )
        return results

    def _change_before_failure(self, events: list[EvidenceEvent]) -> list[Correlation]:
        changes = [e for e in events if is_change(e)]
        failures = [e for e in events if is_failure(e)]
        results: list[Correlation] = []
        for change in changes:
            for failure in failures:
                if change.evidence_id == failure.evidence_id:
                    continue
                delta = (failure.timestamp - change.timestamp).total_seconds()
                if 0 <= delta <= self._cbf_window.total_seconds():
                    results.append(
                        Correlation(
                            type=CorrelationType.CHANGE_BEFORE_FAILURE,
                            evidence_ids=[change.evidence_id, failure.evidence_id],
                            explanation=(
                                f"change {change.event_type} preceded failure "
                                f"{failure.event_type} by {int(delta)}s "
                                f"(candidate cause, not confirmed)"
                            ),
                            strength=self._proximity_strength(
                                delta, window=self._cbf_window.total_seconds()
                            ),
                        )
                    )
        return results

    def _proximity_strength(self, delta_seconds: float, window: float | None = None) -> float:
        span = window if window is not None else self._proximity_window.total_seconds()
        if span <= 0:
            return 1.0
        # Closer in time -> stronger (bounded 0..1). Not a probability of causation.
        return round(max(0.0, 1.0 - (delta_seconds / span)), 3)
