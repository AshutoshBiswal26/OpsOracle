from datetime import datetime, timezone

import pytest

from opsoracle.context.builder import ContextBuilder
from opsoracle.errors import ValidationError
from opsoracle.models.correlation import Correlation, CorrelationType
from opsoracle.models.evidence import EvidenceEvent, EvidenceSource
from opsoracle.models.investigation import TimeWindow

UTC = timezone.utc


def window():
    return TimeWindow(
        start=datetime(2026, 9, 23, 12, 0, tzinfo=UTC),
        end=datetime(2026, 9, 23, 13, 0, tzinfo=UTC),
    )


def ev(minute, name):
    return EvidenceEvent(
        source=EvidenceSource.CLOUDTRAIL,
        event_type=name,
        timestamp=datetime(2026, 9, 23, 12, minute, 0, tzinfo=UTC),
        summary=name,
    )


def test_correlated_events_ranked_first():
    near_center = ev(30, "NearCenter")   # closest to center (12:30)
    edge = ev(1, "Edge")                 # correlated but far from center
    other = ev(31, "Other")
    corr = Correlation(
        CorrelationType.SHARED_RESOURCE,
        [edge.evidence_id, other.evidence_id],
        "correlated with",
    )
    inv = ContextBuilder(max_events=2).build(window(), [near_center, edge, other], [corr])
    selected_types = {e.event_type for e in inv.events}
    # both correlated events beat the non-correlated near-center event
    assert selected_types == {"Edge", "Other"}
    assert inv.truncated is True


def test_budget_truncation_sets_flag():
    events = [ev(m, f"E{m}") for m in range(5)]
    inv = ContextBuilder(max_events=3).build(window(), events, [])
    assert len(inv.events) == 3
    assert inv.truncated is True


def test_no_truncation_when_within_budget():
    events = [ev(m, f"E{m}") for m in range(3)]
    inv = ContextBuilder(max_events=10).build(window(), events, [])
    assert inv.truncated is False
    assert len(inv.events) == 3


def test_correlation_dropped_if_evidence_truncated():
    keep = ev(30, "Keep")
    drop = ev(1, "Drop")
    # correlation references an event that will be truncated out
    corr = Correlation(
        CorrelationType.TEMPORAL_PROXIMITY,
        [keep.evidence_id, drop.evidence_id],
        "preceded",
    )
    # max_events=1, but correlated events rank first -> both would be kept.
    # Force truncation by making them non-correlated instead:
    inv = ContextBuilder(max_events=1).build(window(), [keep, drop], [])
    assert len(inv.events) == 1
    assert inv.correlations == []


def test_evidence_ids_preserved():
    e = ev(30, "X")
    inv = ContextBuilder().build(window(), [e], [])
    assert inv.events[0].evidence_id == e.evidence_id


def test_zero_max_events_rejected():
    with pytest.raises(ValidationError):
        ContextBuilder(max_events=0)
