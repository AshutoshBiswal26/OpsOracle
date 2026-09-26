import json
from datetime import datetime, timezone

from opsoracle.collectors.cloudtrail import CloudTrailCollector
from opsoracle.config import Config
from opsoracle.investigation.investigator import Investigator
from opsoracle.models.investigation import TimeWindow
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
        "userIdentity": {"type": "IAMUser", "arn": f"arn:aws:iam::1:user/dev"},
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


class FakeCloudTrail:
    def __init__(self, events):
        self._events = events

    def lookup_events(self, **kwargs):
        return {"Events": self._events}


class FakeBedrock:
    def __init__(self, ids):
        self._ids = ids
        self.called = False

    def converse(self, **kwargs):
        self.called = True
        body = {
            "contributing_factors": [
                {
                    "description": "config change preceded the failure (candidate cause)",
                    "evidence_ids": self._ids,
                    "confidence": "medium",
                }
            ],
            "uncertainty": "moderate; correlation is not proof",
            "next_actions": ["review the function config change", "inspect invocation logs"],
        }
        return {
            "output": {"message": {"content": [{"text": json.dumps(body)}]}},
            "usage": {"inputTokens": 100, "outputTokens": 50, "totalTokens": 150},
        }


class FailingBedrock:
    """A Bedrock stub whose converse() raises, exercising the graceful-fallback path."""

    def __init__(self):
        self.called = False

    def converse(self, **kwargs):
        self.called = True
        raise RuntimeError("bedrock unavailable (simulated)")


def make_investigator(bedrock_ids, *, reasoning_enabled=True):
    config = Config(reasoning_enabled=reasoning_enabled, max_events=50)
    records = [
        ct_record("1", "UpdateFunctionConfiguration", 10),
        ct_record("2", "Invoke", 12, error="Throttled"),
    ]
    collector = CloudTrailCollector(FakeCloudTrail(records))
    bedrock = FakeBedrock(bedrock_ids)
    reasoner = BedrockReasoner(
        bedrock if reasoning_enabled else None,
        model_id="m",
        enabled=reasoning_enabled,
    )
    return Investigator(
        config=config, cloudtrail_collector=collector, reasoner=reasoner
    ), records


def test_end_to_end_produces_report_with_traceable_evidence():
    # First discover the evidence ids the pipeline will generate, then feed them to the
    # fake model so its citations are valid.
    from opsoracle.normalization.cloudtrail import CloudTrailNormalizer

    _, records = make_investigator([])
    ids = [e.evidence_id for e in CloudTrailNormalizer().normalize(records)]

    investigator, _ = make_investigator(ids)
    report = investigator.investigate(window())
    md = report.to_markdown()

    # --- deterministic evidence present and traceable in the rendered report ---
    timeline_ids = {e.evidence_id for e in report.timeline}
    assert timeline_ids == set(ids)
    for eid in ids:
        assert eid in md

    # --- correlations reference only real timeline evidence ids (Req 11.3) ---
    assert report.correlations, "expected at least one deterministic correlation"
    for corr in report.correlations:
        assert corr.evidence_ids, "correlation must cite evidence"
        for cited in corr.evidence_ids:
            assert cited in timeline_ids
            assert cited in md
    # change-before-failure correlation surfaced (change event before failure event)
    assert "change_before_failure" in md

    # --- AI candidate cause cites supplied, real evidence ids (Req 11.3) ---
    assert report.reasoning.ai_available is True
    assert "candidate cause" in md
    factors = report.reasoning.contributing_factors
    assert factors, "expected the mocked model's candidate cause to survive validation"
    assert factors[0].evidence_ids == ids
    for factor in factors:
        assert factor.evidence_ids, "every candidate cause must cite evidence"
        for cited in factor.evidence_ids:
            assert cited in timeline_ids
            assert cited in md


def test_end_to_end_graceful_without_reasoning():
    investigator, _ = make_investigator([], reasoning_enabled=False)
    report = investigator.investigate(window())
    md = report.to_markdown()
    assert report.reasoning.ai_available is False
    assert "AI reasoning unavailable" in md
    # deterministic sections still present
    assert "## Observed evidence" in md
    assert "change_before_failure" in md


def test_end_to_end_graceful_on_bedrock_failure():
    # Reasoning is enabled and there is evidence to reason over, but the Bedrock call
    # itself raises. The pipeline must still render a valid report from the
    # deterministic evidence (Req 7.7 / 11.3).
    config = Config(reasoning_enabled=True, max_events=50)
    records = [
        ct_record("1", "UpdateFunctionConfiguration", 10),
        ct_record("2", "Invoke", 12, error="Throttled"),
    ]
    collector = CloudTrailCollector(FakeCloudTrail(records))
    bedrock = FailingBedrock()
    reasoner = BedrockReasoner(bedrock, model_id="m", enabled=True)
    investigator = Investigator(
        config=config, cloudtrail_collector=collector, reasoner=reasoner
    )

    report = investigator.investigate(window())
    md = report.to_markdown()

    # the model was actually invoked and failed
    assert bedrock.called is True
    # graceful fallback: no AI section, but deterministic report still complete
    assert report.reasoning.ai_available is False
    assert "AI reasoning unavailable" in md
    assert "## Observed evidence" in md
    assert "change_before_failure" in md
    # deterministic evidence is still traceable despite the reasoning failure
    for e in report.timeline:
        assert e.evidence_id in md


def test_end_to_end_empty_window_no_events():
    config = Config(reasoning_enabled=True)
    collector = CloudTrailCollector(FakeCloudTrail([]))
    reasoner = BedrockReasoner(FakeBedrock([]), model_id="m")
    investigator = Investigator(
        config=config, cloudtrail_collector=collector, reasoner=reasoner
    )
    report = investigator.investigate(window())
    assert report.timeline == []
    # reasoning skipped because there is no evidence
    assert report.reasoning.ai_available is False
    assert "No evidence collected" in report.to_markdown()
