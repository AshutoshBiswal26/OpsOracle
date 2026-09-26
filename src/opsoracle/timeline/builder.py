"""Timeline construction: chronological ordering and resource/service grouping.

Ordering is stable: events are sorted by ``(timestamp, evidence_id)`` so identical
timestamps break ties deterministically (requirements 4.1, 4.2).

The timeline is also where evidence from (potentially overlapping) collections merges,
so it deduplicates by the deterministic, content-derived ``evidence_id``: two identical
signals collapse to a single timeline entry, which keeps duplicate inputs from surfacing
as repeated rows in the final report (requirement 11.2).
"""

from __future__ import annotations

from ..models.evidence import EvidenceEvent, EvidenceSource

# Grouping key used for events that reference no resource.
UNASSIGNED_RESOURCE = "(no resource)"


class TimelineBuilder:
    def build(self, events: list[EvidenceEvent]) -> list[EvidenceEvent]:
        """Return events deduplicated by evidence_id, ordered ascending.

        Events are collapsed by their deterministic ``evidence_id`` (first occurrence
        wins) and then sorted by ``(timestamp, evidence_id)`` so identical signals appear
        once and identical timestamps break ties deterministically (requirements 4.1,
        4.2, 11.2).
        """
        unique: dict[str, EvidenceEvent] = {}
        for event in events:
            unique.setdefault(event.evidence_id, event)
        return sorted(unique.values(), key=lambda e: (e.timestamp, e.evidence_id))

    def group_by_resource(
        self, events: list[EvidenceEvent]
    ) -> dict[str, list[EvidenceEvent]]:
        """Group ordered events by each referenced resource.

        An event referencing multiple resources appears under each of them. Events with
        no resource are collected under :data:`UNASSIGNED_RESOURCE`.
        """
        ordered = self.build(events)
        groups: dict[str, list[EvidenceEvent]] = {}
        for event in ordered:
            keys = [r.key() for r in event.resources if r.key()]
            if not keys:
                keys = [UNASSIGNED_RESOURCE]
            for key in keys:
                groups.setdefault(key, []).append(event)
        return groups

    def group_by_service(
        self, events: list[EvidenceEvent]
    ) -> dict[EvidenceSource, list[EvidenceEvent]]:
        """Group ordered events by their evidence source/service."""
        ordered = self.build(events)
        groups: dict[EvidenceSource, list[EvidenceEvent]] = {}
        for event in ordered:
            groups.setdefault(event.source, []).append(event)
        return groups
