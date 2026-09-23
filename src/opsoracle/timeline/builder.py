"""Timeline construction: chronological ordering and resource/service grouping.

Ordering is stable: events are sorted by ``(timestamp, evidence_id)`` so identical
timestamps break ties deterministically (requirements 4.1, 4.2).
"""

from __future__ import annotations

from ..models.evidence import EvidenceEvent, EvidenceSource

# Grouping key used for events that reference no resource.
UNASSIGNED_RESOURCE = "(no resource)"


class TimelineBuilder:
    def build(self, events: list[EvidenceEvent]) -> list[EvidenceEvent]:
        """Return events ordered ascending by (timestamp, evidence_id)."""
        return sorted(events, key=lambda e: (e.timestamp, e.evidence_id))

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
