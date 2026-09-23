from datetime import datetime, timezone

import pytest

from opsoracle.errors import ValidationError
from opsoracle.models.correlation import (
    Correlation,
    CorrelationType,
    derive_correlation_id,
)
from opsoracle.models.investigation import Investigation, TimeWindow
from opsoracle.models.report import (
    CandidateCause,
    Confidence,
    ReasoningResult,
)

UTC = timezone.utc


def test_timewindow_rejects_start_after_end():
    with pytest.raises(ValidationError):
        TimeWindow(
            start=datetime(2026, 9, 23, 13, tzinfo=UTC),
            end=datetime(2026, 9, 23, 12, tzinfo=UTC),
        )


def test_timewindow_rejects_naive():
    with pytest.raises(ValidationError):
        TimeWindow(start=datetime(2026, 9, 23, 12), end=datetime(2026, 9, 23, 13))


def test_timewindow_center():
    w = TimeWindow(
        start=datetime(2026, 9, 23, 12, tzinfo=UTC),
        end=datetime(2026, 9, 23, 14, tzinfo=UTC),
    )
    assert w.center() == datetime(2026, 9, 23, 13, tzinfo=UTC)


def test_correlation_deterministic_id_independent_of_order():
    c1 = Correlation(CorrelationType.SHARED_RESOURCE, ["b", "a"], "correlated with")
    c2 = Correlation(CorrelationType.SHARED_RESOURCE, ["a", "b"], "correlated with")
    assert c1.correlation_id == c2.correlation_id
    assert c1.correlation_id == derive_correlation_id(
        CorrelationType.SHARED_RESOURCE, ["a", "b"]
    )


def test_correlation_round_trip():
    c = Correlation(CorrelationType.TEMPORAL_PROXIMITY, ["a", "b"], "preceded", strength=0.5)
    assert Correlation.from_dict(c.to_dict()).to_dict() == c.to_dict()


def test_candidate_cause_round_trip():
    cc = CandidateCause("possible contributor", ["a"], Confidence.MEDIUM)
    assert CandidateCause.from_dict(cc.to_dict()).to_dict() == cc.to_dict()


def test_reasoning_unavailable_factory():
    r = ReasoningResult.unavailable("bedrock timeout")
    assert r.ai_available is False
    assert r.notes == "bedrock timeout"
    assert r.contributing_factors == []


def test_investigation_to_dict():
    w = TimeWindow(
        start=datetime(2026, 9, 23, 12, tzinfo=UTC),
        end=datetime(2026, 9, 23, 13, tzinfo=UTC),
    )
    inv = Investigation(window=w)
    d = inv.to_dict()
    assert d["truncated"] is False
    assert d["events"] == []
    assert d["window"]["start"].startswith("2026-09-23T12")
