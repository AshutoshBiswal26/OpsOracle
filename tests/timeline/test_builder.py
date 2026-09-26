"""Tests for the timeline builder (requirements 4.1–4.5)."""

from datetime import datetime, timezone

from opsoracle.models.evidence import (
    EvidenceEvent,
    EvidenceSource,
    ResourceRef,
)
from opsoracle.timeline.builder import UNASSIGNED_RESOURCE, TimelineBuilder

UTC = timezone.utc


def make_event(
    *,
    event_type: str,
    minute: int,
    source: EvidenceSource = EvidenceSource.CLOUDTRAIL,
    resources: list[ResourceRef] | None = None,
    evidence_id: str = "",
    summary: str = "",
) -> EvidenceEvent:
    return EvidenceEvent(
        source=source,
        event_type=event_type,
        timestamp=datetime(2026, 9, 23, 12, minute, 0, tzinfo=UTC),
        summary=summary or event_type,
        resources=resources or [],
        evidence_id=evidence_id,
    )


def test_build_orders_ascending_by_timestamp():
    """Events are ordered ascending by timestamp (req 4.1)."""
    e_late = make_event(event_type="Late", minute=30)
    e_early = make_event(event_type="Early", minute=5)
    e_mid = make_event(event_type="Mid", minute=15)

    ordered = TimelineBuilder().build([e_late, e_mid, e_early])

    assert [e.event_type for e in ordered] == ["Early", "Mid", "Late"]


def test_build_does_not_mutate_input():
    """Sorting returns a new list, leaving the caller's list untouched."""
    e_a = make_event(event_type="A", minute=20)
    e_b = make_event(event_type="B", minute=10)
    original = [e_a, e_b]

    ordered = TimelineBuilder().build(original)

    assert original == [e_a, e_b]  # unchanged
    assert ordered == [e_b, e_a]


def test_identical_timestamp_stable_tiebreak_by_evidence_id():
    """Events sharing a timestamp are ordered deterministically by evidence_id (req 4.2)."""
    ts_minute = 10
    e_high = make_event(event_type="High", minute=ts_minute, evidence_id="cloudtrail-zzz")
    e_low = make_event(event_type="Low", minute=ts_minute, evidence_id="cloudtrail-aaa")
    e_mid = make_event(event_type="Mid", minute=ts_minute, evidence_id="cloudtrail-mmm")

    # All three share the same timestamp; only evidence_id differentiates them.
    assert e_high.timestamp == e_low.timestamp == e_mid.timestamp

    ordered = TimelineBuilder().build([e_high, e_low, e_mid])

    assert [e.evidence_id for e in ordered] == [
        "cloudtrail-aaa",
        "cloudtrail-mmm",
        "cloudtrail-zzz",
    ]
    # Ordering is deterministic regardless of input order.
    ordered_again = TimelineBuilder().build([e_mid, e_high, e_low])
    assert [e.evidence_id for e in ordered_again] == [e.evidence_id for e in ordered]


def test_timeline_entries_expose_evidence_id():
    """Each ordered entry exposes its evidence_id for traceability (req 4.5)."""
    events = [make_event(event_type="A", minute=1), make_event(event_type="B", minute=2)]
    ordered = TimelineBuilder().build(events)
    for e in ordered:
        assert e.evidence_id
        assert e.evidence_id.startswith("cloudtrail-")


def test_group_by_resource_groups_by_resource_key():
    """Events are grouped by each referenced resource's key (req 4.3)."""
    inst = ResourceRef(type="AWS::EC2::Instance", name="i-123")
    bucket = ResourceRef(type="AWS::S3::Bucket", name="logs-bucket")

    e1 = make_event(event_type="RunInstances", minute=5, resources=[inst])
    e2 = make_event(event_type="StopInstances", minute=10, resources=[inst])
    e3 = make_event(event_type="DeleteBucket", minute=15, resources=[bucket])

    groups = TimelineBuilder().group_by_resource([e3, e2, e1])

    assert set(groups.keys()) == {inst.key(), bucket.key()}
    # Instance group holds both instance events, in chronological order.
    assert [e.event_type for e in groups[inst.key()]] == ["RunInstances", "StopInstances"]
    assert [e.event_type for e in groups[bucket.key()]] == ["DeleteBucket"]


def test_group_by_resource_event_with_multiple_resources_appears_under_each():
    """An event referencing several resources appears under each key (req 4.3)."""
    inst = ResourceRef(type="AWS::EC2::Instance", name="i-abc")
    sg = ResourceRef(type="AWS::EC2::SecurityGroup", name="sg-xyz")
    multi = make_event(event_type="ModifyInstanceAttribute", minute=8, resources=[inst, sg])

    groups = TimelineBuilder().group_by_resource([multi])

    assert multi in groups[inst.key()]
    assert multi in groups[sg.key()]


def test_group_by_resource_events_without_resources_go_to_unassigned():
    """Events lacking any resource land under the unassigned bucket (req 4.3)."""
    e = make_event(event_type="ConsoleLogin", minute=3, resources=[])
    groups = TimelineBuilder().group_by_resource([e])
    assert groups[UNASSIGNED_RESOURCE] == [e]


def test_group_by_service_groups_by_source():
    """Events are grouped by their evidence source/service (req 4.4)."""
    ct = make_event(event_type="RunInstances", minute=5, source=EvidenceSource.CLOUDTRAIL)
    alarm = make_event(
        event_type="AlarmStateChange", minute=10, source=EvidenceSource.CLOUDWATCH_ALARM
    )
    metric = make_event(
        event_type="MetricBreach", minute=15, source=EvidenceSource.CLOUDWATCH_METRIC
    )

    groups = TimelineBuilder().group_by_service([metric, alarm, ct])

    assert set(groups.keys()) == {
        EvidenceSource.CLOUDTRAIL,
        EvidenceSource.CLOUDWATCH_ALARM,
        EvidenceSource.CLOUDWATCH_METRIC,
    }
    assert groups[EvidenceSource.CLOUDTRAIL] == [ct]
    assert groups[EvidenceSource.CLOUDWATCH_ALARM] == [alarm]
    assert groups[EvidenceSource.CLOUDWATCH_METRIC] == [metric]


def test_group_by_service_preserves_chronological_order_within_group():
    """Within a service group, entries stay in ascending timeline order (req 4.1, 4.4)."""
    early = make_event(event_type="Early", minute=5)
    late = make_event(event_type="Late", minute=25)

    groups = TimelineBuilder().group_by_service([late, early])

    assert [e.event_type for e in groups[EvidenceSource.CLOUDTRAIL]] == ["Early", "Late"]


def test_empty_input_yields_empty_results():
    builder = TimelineBuilder()
    assert builder.build([]) == []
    assert builder.group_by_resource([]) == {}
    assert builder.group_by_service([]) == {}
