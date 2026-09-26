"""Unit tests for the Investigator orchestrator (task 12.1).

These exercise the full pipeline wiring with injected fakes/mocks — no live AWS. They
verify that:
  * the stages are wired in order and produce a rendered report with traceable evidence,
  * a reasoning stage that raises ``ReasoningError`` is caught by the orchestrator and
    degraded to ``ai_available=False`` so a report still renders (requirements 7.7, 8.5),
  * a reasoner that itself returns an unavailable result flows through unchanged,
  * ``from_config`` wires sensible defaults without touching AWS.
"""

import json
from datetime import datetime, timezone

from opsoracle.collectors.cloudtrail import CloudTrailCollector
from opsoracle.config import Config
from opsoracle.errors import ReasoningError
from opsoracle.investigation.investigator import Investigator
from opsoracle.models.investigation import TimeWindow
from opsoracle.models.report import ReasoningResult
from opsoracle.normalization.cloudtrail import CloudTrailNormalizer
from opsoracle.reasoning.bedrock import BedrockReasoner

UTC = timezone.utc


def window():
    return TimeWindow(
        start=datetime(2026, 9, 23, 12, 0, tzinfo=UTC),
        end=datetime(2026, 9, 23, 13, 0, tzinfo=UTC),
    )


def ct_record(event_id, name, minute, *, error=None, resource="fn-1"):
    detail = {
        "eventName": name,
        "eventSource": "lambda.amazonaws.com",
        "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::1:user/dev"},
    }
    if error:
        detail["errorCode"] = error
    return {
        "EventId": event_id,
        "EventName": name,
        "EventSource": "lambda.amazonaws.com",
        "EventTime": datetime(2026, 9, 23, 12, minute, 0, tzinfo=UTC),
        "ReadOnly": "false",
        "Resources": [{"ResourceType": "AWS::Lambda::Function", "ResourceName": resource}],
        "CloudTrailEvent": json.dumps(detail),
    }


RECORDS = [
    ct_record("1", "UpdateFunctionConfiguration", 10),
    ct_record("2", "Invoke", 12, error="Throttled"),
]


class FakeCloudTrail:
    """Minimal boto3 ``cloudtrail`` stub returning canned events."""

    def __init__(self, events):
        self._events = events

    def lookup_events(self, **kwargs):
        return {"Events": self._events}


class StubReasoner:
    """A reasoner test double that records the investigation it received."""

    def __init__(self, result=None, *, raises=None):
        self._result = result
        self._raises = raises
        self.seen = None

    def reason(self, investigation):
        self.seen = investigation
        if self._raises is not None:
            raise self._raises
        return self._result


def expected_ids():
    return [e.evidence_id for e in CloudTrailNormalizer().normalize(RECORDS)]


def make_investigator(reasoner):
    collector = CloudTrailCollector(FakeCloudTrail(RECORDS))
    return Investigator(
        config=Config(max_events=50),
        cloudtrail_collector=collector,
        reasoner=reasoner,
    )


def test_full_wiring_produces_report_with_traceable_evidence():
    ids = expected_ids()
    result = ReasoningResult(
        contributing_factors=[],
        uncertainty="moderate",
        next_actions=["review the config change"],
        ai_available=True,
    )
    stub = StubReasoner(result)
    investigator = make_investigator(stub)

    report = investigator.investigate(window())

    # The reasoner ran over the assembled investigation (stage ordering held).
    assert stub.seen is not None
    assert {e.evidence_id for e in stub.seen.events} == set(ids)
    # Deterministic evidence is present and traceable in the timeline.
    assert {e.evidence_id for e in report.timeline} == set(ids)
    # Change-before-failure correlation surfaced from the two records.
    assert any(c.type.value == "change_before_failure" for c in report.correlations)
    assert report.reasoning.ai_available is True

    md = report.to_markdown()
    for eid in ids:
        assert eid in md
    assert "## Observed evidence" in md


def test_reasoning_error_is_caught_and_report_still_renders():
    stub = StubReasoner(raises=ReasoningError("bedrock exploded"))
    investigator = make_investigator(stub)

    report = investigator.investigate(window())

    # Orchestrator converted the raised ReasoningError into a graceful fallback.
    assert report.reasoning.ai_available is False
    assert "bedrock exploded" in (report.reasoning.notes or "")
    # Deterministic sections still render despite the reasoning failure.
    md = report.to_markdown()
    assert "AI reasoning unavailable" in md
    assert "## Observed evidence" in md
    for eid in expected_ids():
        assert eid in md


def test_reasoner_unavailable_result_flows_through():
    stub = StubReasoner(ReasoningResult.unavailable("reasoning disabled"))
    investigator = make_investigator(stub)

    report = investigator.investigate(window())

    assert report.reasoning.ai_available is False
    assert "reasoning disabled" in report.to_markdown()


def test_investigate_markdown_returns_string():
    stub = StubReasoner(ReasoningResult.unavailable("skip"))
    investigator = make_investigator(stub)

    md = investigator.investigate_markdown(window())

    assert isinstance(md, str)
    assert md.startswith("# OpsOracle Incident Report")


def test_from_config_wires_defaults_without_live_aws():
    config = Config(reasoning_enabled=False, max_events=25)
    investigator = Investigator.from_config(
        config, cloudtrail_client=FakeCloudTrail(RECORDS)
    )

    # reasoning disabled -> no client needed, degrades gracefully.
    report = investigator.investigate(window())
    assert report.reasoning.ai_available is False
    assert {e.evidence_id for e in report.timeline} == set(expected_ids())


def test_filters_are_forwarded_to_collector():
    class RecordingCloudTrail(FakeCloudTrail):
        def __init__(self, events):
            super().__init__(events)
            self.last_kwargs = None

        def lookup_events(self, **kwargs):
            self.last_kwargs = kwargs
            return {"Events": self._events}

    client = RecordingCloudTrail(RECORDS)
    investigator = Investigator(
        config=Config(max_events=50),
        cloudtrail_collector=CloudTrailCollector(client),
        reasoner=StubReasoner(ReasoningResult.unavailable("skip")),
    )

    investigator.investigate(window(), {"EventName": "UpdateFunctionConfiguration"})

    assert client.last_kwargs is not None
    assert client.last_kwargs["LookupAttributes"] == [
        {"AttributeKey": "EventName", "AttributeValue": "UpdateFunctionConfiguration"}
    ]
