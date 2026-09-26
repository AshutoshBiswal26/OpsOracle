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


# ---- graceful fallback paths (task 10.3, requirement 7.7) ----


class ShapeBedrock:
    """Client returning a syntactically valid response with an unexpected shape."""

    def __init__(self, payload):
        self._payload = payload
        self.calls = []

    def converse(self, **kwargs):
        self.calls.append(kwargs)
        return self._payload


def test_fallback_client_raises_returns_ai_unavailable_with_note():
    inv, _ = investigation_with_event()
    client = FakeBedrock(exc=RuntimeError("network down"))
    reasoner = BedrockReasoner(client, model_id="m")
    result = reasoner.reason(inv)
    assert result.ai_available is False
    # Note explains why reasoning is unavailable rather than raising.
    assert result.notes
    assert "unavailable" in result.notes


def test_fallback_parse_error_returns_ai_unavailable_with_note():
    inv, _ = investigation_with_event()
    client = FakeBedrock(text="definitely not json {oops")
    reasoner = BedrockReasoner(client, model_id="m")
    result = reasoner.reason(inv)
    assert result.ai_available is False
    assert result.notes
    assert "unavailable" in result.notes


def test_fallback_unexpected_response_shape_returns_ai_unavailable():
    inv, _ = investigation_with_event()
    # Missing the expected output/message/content structure.
    client = ShapeBedrock({"unexpected": "shape"})
    reasoner = BedrockReasoner(client, model_id="m")
    result = reasoner.reason(inv)
    assert result.ai_available is False
    assert result.notes
    assert "unavailable" in result.notes


def test_fallback_empty_text_content_returns_ai_unavailable():
    inv, _ = investigation_with_event()
    # Well-formed envelope but no text blocks in the content list.
    client = ShapeBedrock({"output": {"message": {"content": []}}, "usage": {}})
    reasoner = BedrockReasoner(client, model_id="m")
    result = reasoner.reason(inv)
    assert result.ai_available is False
    assert result.notes
    assert "unavailable" in result.notes


# ---- token usage is logged, not just captured (requirement 10.3) ----


def test_reasoner_logs_token_usage(caplog):
    """last_usage is captured AND emitted to the log for measurability (req 10.3)."""
    import logging

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
    client = FakeBedrock(
        text=text,
        usage={"inputTokens": 11, "outputTokens": 22, "totalTokens": 33},
    )
    reasoner = BedrockReasoner(client, model_id="m", max_tokens=100)

    with caplog.at_level(logging.INFO, logger="opsoracle.reasoning"):
        result = reasoner.reason(inv)

    assert result.ai_available is True
    # Captured for programmatic access.
    assert reasoner.last_usage == {"inputTokens": 11, "outputTokens": 22, "totalTokens": 33}
    # And emitted to the log so token spend is observable.
    usage_logs = [r for r in caplog.records if "usage" in r.getMessage()]
    assert usage_logs, "expected a bedrock usage log record"
    logged = usage_logs[0].getMessage()
    assert "33" in logged and "11" in logged and "22" in logged
