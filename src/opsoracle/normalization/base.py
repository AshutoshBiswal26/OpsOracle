"""Normalizer protocol: raw AWS records -> list[EvidenceEvent]."""

from __future__ import annotations

from typing import Protocol

from ..models.evidence import EvidenceEvent


class Normalizer(Protocol):
    def normalize(self, raw_records: list[dict]) -> list[EvidenceEvent]:
        ...
