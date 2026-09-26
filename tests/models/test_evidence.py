from datetime import datetime, timedelta, timezone

import pytest

from opsoracle.errors import ValidationError
from opsoracle.models.evidence import (
    Actor,
    EvidenceEvent,
    EvidenceSource,
    ResourceRef,
    derive_evidence_id,
)

UTC = timezone.utc


def make_event(**overrides):
    base = dict(
        source=EvidenceSource.CLOUDTRAIL,
        event_type="RunInstances",
        timestamp=datetime(2026, 9, 23, 12, 0, 0, tzinfo=UTC),
        summary="ec2 RunInstances by alice",
        actor=Actor(type="IAMUser", principal_id="AIDA123", arn="arn:aws:iam::1:user/alice"),
        resources=[ResourceRef(type="AWS::EC2::Instance", name="i-123")],
        region="us-east-1",
        account="123456789012",
    )
    base.update(overrides)
    return EvidenceEvent(**base)


def test_evidence_id_is_deterministic_and_stable():
    e1 = make_event()
    e2 = make_event()
    assert e1.evidence_id == e2.evidence_id
    assert e1.evidence_id.startswith("cloudtrail-")


def test_derive_evidence_id_matches_helper():
    ts = datetime(2026, 9, 23, 12, 0, 0, tzinfo=UTC)
    expected = derive_evidence_id(
        EvidenceSource.CLOUDTRAIL, "RunInstances", ts, "i-123", "arn:aws:iam::1:user/alice"
    )
    assert make_event().evidence_id == expected


def test_round_trip_to_from_dict():
    e = make_event()
    restored = EvidenceEvent.from_dict(e.to_dict())
    assert restored.to_dict() == e.to_dict()
    assert restored.evidence_id == e.evidence_id
    assert restored.timestamp == e.timestamp


def test_naive_timestamp_rejected():
    with pytest.raises(ValidationError):
        make_event(timestamp=datetime(2026, 9, 23, 12, 0, 0))


def test_missing_event_type_rejected():
    with pytest.raises(ValidationError):
        make_event(event_type="")


def test_non_utc_timestamp_normalized_to_utc():
    ist = timezone(timedelta(hours=5, minutes=30))
    e = make_event(timestamp=datetime(2026, 9, 23, 17, 30, 0, tzinfo=ist))
    assert e.timestamp == datetime(2026, 9, 23, 12, 0, 0, tzinfo=UTC)


def test_from_dict_invalid_source_rejected():
    d = make_event().to_dict()
    d["source"] = "not_a_source"
    with pytest.raises(ValidationError):
        EvidenceEvent.from_dict(d)


def test_from_dict_missing_timestamp_rejected():
    d = make_event().to_dict()
    del d["timestamp"]
    with pytest.raises(ValidationError):
        EvidenceEvent.from_dict(d)


def test_events_without_resources_get_id():
    e = make_event(resources=[])
    assert e.evidence_id.startswith("cloudtrail-")


def test_different_input_yields_different_id():
    """Different logical events must produce different evidence IDs (requirement 2.2)."""
    base = make_event()
    # Different event_type
    assert make_event(event_type="TerminateInstances").evidence_id != base.evidence_id
    # Different timestamp
    assert (
        make_event(timestamp=datetime(2026, 9, 23, 13, 0, 0, tzinfo=UTC)).evidence_id
        != base.evidence_id
    )
    # Different primary resource
    assert (
        make_event(resources=[ResourceRef(type="AWS::EC2::Instance", name="i-999")]).evidence_id
        != base.evidence_id
    )
    # Different actor
    assert (
        make_event(
            actor=Actor(type="IAMUser", principal_id="AIDA999", arn="arn:aws:iam::1:user/bob")
        ).evidence_id
        != base.evidence_id
    )


def test_invalid_summary_type_rejected():
    """A non-string summary is an invalid required field (requirement 2.4)."""
    with pytest.raises(ValidationError):
        make_event(summary=123)


def test_none_summary_rejected():
    """A missing (None) summary is an invalid required field (requirement 2.4)."""
    with pytest.raises(ValidationError):
        make_event(summary=None)


def test_non_evidence_source_at_construction_rejected():
    """A source that is not an EvidenceSource must fail at construction (requirement 2.4)."""
    with pytest.raises(ValidationError):
        make_event(source="cloudtrail")


def test_metadata_and_raw_ref_preserved_in_round_trip():
    """metadata and raw_ref survive the to_dict/from_dict round-trip (requirement 2.3)."""
    metadata = {"error_code": "AccessDenied", "read_only": False, "count": 3}
    raw_ref = {"EventId": "abc-123", "CloudTrailEvent": '{"eventVersion": "1.08"}'}
    e = make_event(metadata=metadata, raw_ref=raw_ref)
    restored = EvidenceEvent.from_dict(e.to_dict())
    assert restored.metadata == metadata
    assert restored.raw_ref == raw_ref


def test_all_fields_preserved_in_round_trip():
    """Every field in requirement 2.1 survives serialization without loss (requirement 2.3)."""
    e = make_event()
    restored = EvidenceEvent.from_dict(e.to_dict())
    assert restored.source == e.source
    assert restored.event_type == e.event_type
    assert restored.timestamp == e.timestamp
    assert restored.summary == e.summary
    assert restored.actor == e.actor
    assert restored.resources == e.resources
    assert restored.region == e.region
    assert restored.account == e.account
    assert restored.evidence_id == e.evidence_id
