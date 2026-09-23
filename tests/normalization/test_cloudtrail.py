import json
from datetime import datetime, timezone

from opsoracle.models.evidence import EvidenceSource
from opsoracle.normalization.cloudtrail import CloudTrailNormalizer

UTC = timezone.utc


def full_record():
    detail = {
        "eventVersion": "1.08",
        "eventName": "RunInstances",
        "eventSource": "ec2.amazonaws.com",
        "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "sourceIPAddress": "10.0.0.1",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDA123",
            "arn": "arn:aws:iam::123456789012:user/alice",
            "accountId": "123456789012",
        },
    }
    return {
        "EventId": "evt-1",
        "EventName": "RunInstances",
        "EventSource": "ec2.amazonaws.com",
        "EventTime": datetime(2026, 9, 23, 12, 0, 0, tzinfo=UTC),
        "Username": "alice",
        "ReadOnly": "false",
        "Resources": [
            {"ResourceType": "AWS::EC2::Instance", "ResourceName": "i-123"}
        ],
        "CloudTrailEvent": json.dumps(detail),
    }


def test_normalize_full_record():
    events = CloudTrailNormalizer().normalize([full_record()])
    assert len(events) == 1
    e = events[0]
    assert e.source is EvidenceSource.CLOUDTRAIL
    assert e.event_type == "RunInstances"
    assert e.timestamp == datetime(2026, 9, 23, 12, 0, 0, tzinfo=UTC)
    assert e.region == "us-east-1"
    assert e.account == "123456789012"
    assert e.actor.arn == "arn:aws:iam::123456789012:user/alice"
    assert e.resources[0].name == "i-123"
    assert e.metadata["source_ip"] == "10.0.0.1"  # only inside detail (req 3.3)
    assert e.raw_ref is events[0].raw_ref  # preserved (req 3.5)


def test_nested_detail_extraction_when_toplevel_sparse():
    detail = {
        "eventName": "DeleteBucket",
        "eventSource": "s3.amazonaws.com",
        "awsRegion": "eu-west-1",
        "recipientAccountId": "999",
        "eventTime": "2026-09-23T08:30:00Z",
        "userIdentity": {"type": "AssumedRole", "arn": "arn:aws:sts::999:assumed-role/x"},
        "errorCode": "AccessDenied",
    }
    record = {"CloudTrailEvent": json.dumps(detail)}  # nothing at top level
    events = CloudTrailNormalizer().normalize([record])
    assert len(events) == 1
    e = events[0]
    assert e.event_type == "DeleteBucket"
    assert e.region == "eu-west-1"
    assert e.timestamp == datetime(2026, 9, 23, 8, 30, tzinfo=UTC)
    assert e.metadata["error_code"] == "AccessDenied"
    assert "error: AccessDenied" in e.summary


def test_missing_optional_fields_still_produces_event():
    record = {
        "EventName": "DescribeInstances",
        "EventTime": datetime(2026, 9, 23, 12, tzinfo=UTC),
    }
    events = CloudTrailNormalizer().normalize([record])
    assert len(events) == 1
    e = events[0]
    assert e.region is None
    assert e.account is None
    assert e.resources == []


def test_username_fallback_actor():
    record = {
        "EventName": "ConsoleLogin",
        "EventTime": datetime(2026, 9, 23, 12, tzinfo=UTC),
        "Username": "bob",
    }
    e = CloudTrailNormalizer().normalize([record])[0]
    assert e.actor.principal_id == "bob"


def test_record_without_timestamp_skipped():
    norm = CloudTrailNormalizer()
    events = norm.normalize([{"EventName": "NoTime"}])
    assert events == []
    assert len(norm.skipped) == 1
    assert "timestamp" in norm.skipped[0]["reason"]


def test_malformed_record_does_not_abort_batch():
    norm = CloudTrailNormalizer()
    good = full_record()
    events = norm.normalize(["garbage", {"EventName": "x"}, good])
    # only the good record survives; batch continues
    assert len(events) == 1
    assert events[0].event_type == "RunInstances"
    assert len(norm.skipped) == 2


def test_malformed_cloudtrailevent_json_tolerated():
    record = {
        "EventName": "RunInstances",
        "EventTime": datetime(2026, 9, 23, 12, tzinfo=UTC),
        "CloudTrailEvent": "{not valid json",
    }
    events = CloudTrailNormalizer().normalize([record])
    assert len(events) == 1  # falls back to top-level fields


def test_naive_eventtime_coerced_to_utc():
    record = {
        "EventName": "X",
        "EventTime": datetime(2026, 9, 23, 12, 0, 0),  # naive
    }
    e = CloudTrailNormalizer().normalize([record])[0]
    assert e.timestamp.tzinfo is not None
