from datetime import datetime, timezone

import pytest

from opsoracle.collectors.cloudtrail import CloudTrailCollector
from opsoracle.errors import AccessError, CollectionError, ThrottlingError, ValidationError
from opsoracle.models.investigation import TimeWindow

UTC = timezone.utc


def make_window():
    return TimeWindow(
        start=datetime(2026, 9, 23, 12, tzinfo=UTC),
        end=datetime(2026, 9, 23, 13, tzinfo=UTC),
    )


class ClientError(Exception):
    """Minimal stand-in for botocore ClientError with a ``response`` payload."""

    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeClient:
    """Records calls and returns queued responses (dict) or raises queued exceptions."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def lookup_events(self, **kwargs):
        self.calls.append(kwargs)
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def test_pagination_accumulates_all_events():
    client = FakeClient(
        [
            {"Events": [{"EventId": "1"}, {"EventId": "2"}], "NextToken": "t1"},
            {"Events": [{"EventId": "3"}]},  # no NextToken -> stop
        ]
    )
    collector = CloudTrailCollector(client)
    events = collector.collect(make_window())
    assert [e["EventId"] for e in events] == ["1", "2", "3"]
    assert len(client.calls) == 2
    assert client.calls[1]["NextToken"] == "t1"


def test_raw_events_returned_unmodified():
    raw = {"EventId": "1", "CloudTrailEvent": "{\"x\":1}", "extra": [1, 2, 3]}
    client = FakeClient([{"Events": [raw]}])
    events = CloudTrailCollector(client).collect(make_window())
    assert events[0] is raw


def test_throttling_retried_then_succeeds(monkeypatch):
    import opsoracle.collectors.base as base

    monkeypatch.setattr(base.time, "sleep", lambda s: None)
    client = FakeClient(
        [
            ClientError("ThrottlingException"),
            ClientError("ThrottlingException"),
            {"Events": [{"EventId": "ok"}]},
        ]
    )
    events = CloudTrailCollector(client, max_retries=5).collect(make_window())
    assert [e["EventId"] for e in events] == ["ok"]
    assert len(client.calls) == 3


def test_throttling_exhausts_retries_raises_throttling(monkeypatch):
    import opsoracle.collectors.base as base

    monkeypatch.setattr(base.time, "sleep", lambda s: None)
    client = FakeClient([ClientError("ThrottlingException")] * 10)
    with pytest.raises(ThrottlingError):
        CloudTrailCollector(client, max_retries=2).collect(make_window())
    # initial attempt + 2 retries = 3 calls
    assert len(client.calls) == 3


def test_access_denied_raises_access_error():
    client = FakeClient([ClientError("AccessDenied")])
    with pytest.raises(AccessError):
        CloudTrailCollector(client).collect(make_window())


def test_other_client_error_raises_collection_error():
    client = FakeClient([ClientError("InvalidParameterCombination")])
    with pytest.raises(CollectionError):
        CloudTrailCollector(client).collect(make_window())


def test_filters_translated_to_lookup_attributes():
    client = FakeClient([{"Events": []}])
    CloudTrailCollector(client).collect(
        make_window(), filters={"EventName": "RunInstances"}
    )
    attrs = client.calls[0]["LookupAttributes"]
    assert attrs == [{"AttributeKey": "EventName", "AttributeValue": "RunInstances"}]


def test_unknown_filter_key_rejected():
    client = FakeClient([{"Events": []}])
    with pytest.raises(ValidationError):
        CloudTrailCollector(client).collect(make_window(), filters={"Bogus": "x"})


def test_none_client_rejected():
    with pytest.raises(ValidationError):
        CloudTrailCollector(None)


def test_window_type_guarded():
    client = FakeClient([{"Events": []}])
    with pytest.raises(ValidationError):
        CloudTrailCollector(client).collect("not-a-window")
