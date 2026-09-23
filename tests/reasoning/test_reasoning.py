import json
from datetime import datetime, timezone

import pytest

from opsoracle.errors import ReasoningError
from opsoracle.models.evidence import EvidenceEvent, EvidenceSource
from opsoracle.models.investigation import Investigation, TimeWindow
from opsoracle.reasoning.bedrock import BedrockReasoner
from opsoracle.reasoning.schema import parse_reasoning

UTC = timezone.utc


def window():
    return TimeWindow(
        start=datetime(2026, 9, 23, 12, tzinfo=UTC),
        end=datetime(2026, 9, 23, 13, tzinfo=UTC),
    )


def sample_event(name="UpdateFunctionConfiguration"):
    return EvidenceEvent(
        source=EvidenceSource.CLOUDTRAIL,
        event_type=name,
        timestamp=datetime(2026, 9, 23, 12, 30, tzinfo=UTC),
        summary=name,
    )


def investigation_with_event():
    e = sample_event()
    return Investigation(window=window(), events=[e]), e


class FakeBedrock:
    def __init__(self, text=None, exc=None, usage=None):
        self._text = text
        self._exc = exc
        self._usage = usage or {"inputTokens": 10, "outputTokens": 20, "totalTokens": 30}
        self.calls = []

    def converse(self, **kwargs):
        self.calls.append(kwargs)
        if self._exc is not None:
            raise self._exc
        return {
            "output": {"message": {"content": [{"text": self._text}]}},
            "usage": self._usage,
        }


# ---- schema.parse_reasoning ----

def test_parse_valid_output():
    inv, e = investigation_with_event()
    text = json.dumps(
        {
            "contributing_factors": [
                {
                    "description": "config change candidate cause",
                    "evidence_ids": [e.evidence_id],
                    "confidence": "medium",
                }
            ],
            "uncertainty": "moderate",
            "next_actions": ["check function logs"],
        }
    )
    result = parse_reasoning(text, {e.evidence_id})
    assert result.ai_available is True
    assert len(result.contributing_factors) == 1
    assert result.contributing_factors[0].evidence_ids == [e.evidence_id]
    assert result.next_actions == ["check function logs"]


def test_claim_with_unknown_evidence_id_dropped():
    text = json.dumps(
        {
            "contributing_factors": [
                {"description": "hallucinated", "evidence_ids": ["does-not-exist"]}
            ],
            "uncertainty": "",
            "next_actions": [],
        }
    )
    result = parse_reasoning(text, {"real-id"})
    assert result.contributing_factors == []
    assert "dropped" in (result.notes or "")


def test_insufficient_evidence_result_preserved():
    text = json.dumps(
        {"contributing_factors": [], "uncertainty": "insufficient evidence", "next_actions": []}
    )
    result = parse_reasoning(text, set())
    assert result.ai_available is True
    assert result.contributing_factors == []
    assert "insufficient" in result.uncertainty


def test_malformed_json_raises_reasoning_error():
    with pytest.raises(ReasoningError):
        parse_reasoning("this is not json at all", set())


def test_json_embedded_in_prose_extracted():
    inv, e = investigation_with_event()
    text = "Here is my answer:\n" + json.dumps(
        {"contributing_factors": [], "uncertainty": "n/a", "next_actions": ["x"]}
    ) + "\nHope that helps."
    result = parse_reasoning(text, {e.evidence_id})
    assert result.next_actions == ["x"]


# ---- BedrockReasoner ----

def test_reasoner_happy_path_and_usage_logged():
    inv, e = investigation_with_event()
    text = json.dumps(
        {
            "contributing_factors": [
                {"description": "candidate", "evidence_ids": [e.evidence_id], "confidence": "low"}
            ],
            "uncertainty": "some",
            "next_actions": [],
        }
    )
    client = FakeBedrock(text=text)
    reasoner = BedrockReasoner(client, model_id="m", max_tokens=100)
    result = reasoner.reason(inv)
    assert result.ai_available is True
    assert reasoner.last_usage["totalTokens"] == 30
    assert client.calls[0]["modelId"] == "m"


def test_reasoner_disabled_skips_call():
    inv, _ = investigation_with_event()
    client = FakeBedrock(text="{}")
    reasoner = BedrockReasoner(client, model_id="m", enabled=False)
    result = reasoner.reason(inv)
    assert result.ai_available is False
    assert client.calls == []


def test_reasoner_no_events_skips_call():
    client = FakeBedrock(text="{}")
    reasoner = BedrockReasoner(client, model_id="m")
    result = reasoner.reason(Investigation(window=window(), events=[]))
    assert result.ai_available is False
    assert client.calls == []
    assert "no evidence" in result.notes


def test_reasoner_bedrock_exception_degrades_gracefully():
    inv, _ = investigation_with_event()
    client = FakeBedrock(exc=RuntimeError("boom"))
    reasoner = BedrockReasoner(client, model_id="m")
    result = reasoner.reason(inv)
    assert result.ai_available is False
    assert "unavailable" in result.notes


def test_reasoner_malformed_output_degrades_gracefully():
    inv, _ = investigation_with_event()
    client = FakeBedrock(text="not json")
    reasoner = BedrockReasoner(client, model_id="m")
    result = reasoner.reason(inv)
    assert result.ai_available is False
