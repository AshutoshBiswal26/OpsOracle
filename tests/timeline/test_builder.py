from datetime import datetime, timezone

from opsoracle.models.evidence import EvidenceEvent, EvidenceSource, ResourceRef
from opsoracle.timeline.builder import UNASSIGNED_RESOURCE, TimelineBuilder

UTC = timezone.utc


def ev(minute, name, resources=None, source=EvidenceSource.CLOUDTRAIL):
    return EvidenceEvent(
        source=source,
        event_type=name,
        timestamp=datetime(2026, 9, 23, 12, minute, 0, tzinfo=UTC),
        summary=name,
        resources=resources or [],
    )


def test_orders_ascending_by_timestamp():
    a = ev(5, "A")
    b = ev(1, "B")
    c = ev(3, "C")
    ordered = TimelineBuilder().build([a, b, c])
    assert [e.event_type for e in ordered] == ["B", "C", "A"]


def test_identical_timestamp_stable_tiebreak_by_id():
    # Same timestamp, different event types -> deterministic order by evidence_id.
    e1 = ev(0, "Alpha")
    e2 = ev(0, "Beta")
    ordered1 = TimelineBuilder().build([e1, e2])
    ordered2 = TimelineBuilder().build([e2, e1])
    assert [e.evidence_id for e in ordered1] == [e.evidence_id for e in ordered2]
    assert ordered1[0].evidence_id < ordered1[1].evidence_id


def test_group_by_resource():
    r1 = ResourceRef(type="AWS::EC2::Instance", name="i-1")
    r2 = ResourceRef(type="AWS::S3::Bucket", name="bucket-x")
    a = ev(1, "A", [r1])
    b = ev(2, "B", [r1, r2])
    c = ev(3, "C", [])
    groups = TimelineBuilder().group_by_resource([a, b, c])
    assert [e.event_type for e in groups["i-1"]] == ["A", "B"]
    assert [e.event_type for e in groups["bucket-x"]] == ["B"]
    assert [e.event_type for e in groups[UNASSIGNED_RESOURCE]] == ["C"]


def test_group_by_service():
    a = ev(1, "A", source=EvidenceSource.CLOUDTRAIL)
    b = ev(2, "B", source=EvidenceSource.CLOUDWATCH_ALARM)
    groups = TimelineBuilder().group_by_service([b, a])
    assert list(groups[EvidenceSource.CLOUDTRAIL])[0].event_type == "A"
    assert list(groups[EvidenceSource.CLOUDWATCH_ALARM])[0].event_type == "B"


def test_empty_input():
    assert TimelineBuilder().build([]) == []
    assert TimelineBuilder().group_by_resource([]) == {}
