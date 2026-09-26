from datetime import datetime, timezone

import pytest

from opsoracle.errors import ValidationError
from opsoracle.models.correlation import (
    Correlation,
    CorrelationType,
    derive_correlation_id,
)
from opsoracle.models.investigation import Investigation, TimeWindow
from opsoracle.models.evidence import (
    Actor,
    EvidenceEvent,
    EvidenceSource,
    ResourceRef,
)
from opsoracle.models.report import (
    CandidateCause,
    Confidence,
    IncidentReport,
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


def _make_window():
    return TimeWindow(
        start=datetime(2026, 9, 23, 12, tzinfo=UTC),
        end=datetime(2026, 9, 23, 13, tzinfo=UTC),
    )


def _make_event():
    return EvidenceEvent(
        source=EvidenceSource.CLOUDTRAIL,
        event_type="RunInstances",
        timestamp=datetime(2026, 9, 23, 12, 30, tzinfo=UTC),
        summary="ec2 RunInstances by alice",
        actor=Actor(type="IAMUser", principal_id="AIDA123"),
        resources=[ResourceRef(type="AWS::EC2::Instance", name="i-123")],
    )


def test_incident_report_defaults_and_to_dict():
    w = _make_window()
    report = IncidentReport(window=w, summary="investigation over one hour")
    # Defaults: empty timeline/correlations, reasoning present and AI-available by default.
    assert report.timeline == []
    assert report.correlations == []
    assert report.reasoning.ai_available is True
    d = report.to_dict()
    assert d["summary"] == "investigation over one hour"
    assert d["window"]["start"].startswith("2026-09-23T12")
    assert d["timeline"] == []
    assert d["correlations"] == []
    assert d["reasoning"]["ai_available"] is True


def test_incident_report_carries_timeline_and_reasoning():
    w = _make_window()
    event = _make_event()
    corr = Correlation(
        CorrelationType.TEMPORAL_PROXIMITY, [event.evidence_id], "correlated with"
    )
    reasoning = ReasoningResult(
        contributing_factors=[CandidateCause("possible contributor", [event.evidence_id])],
        uncertainty="moderate",
        next_actions=["review the change"],
    )
    report = IncidentReport(
        window=w,
        summary="summary",
        timeline=[event],
        correlations=[corr],
        reasoning=reasoning,
    )
    d = report.to_dict()
    assert d["timeline"][0]["evidence_id"] == event.evidence_id
    assert d["correlations"][0]["evidence_ids"] == [event.evidence_id]
    assert d["reasoning"]["contributing_factors"][0]["evidence_ids"] == [event.evidence_id]


def test_incident_report_to_markdown_delegates_to_renderer():
    # to_markdown is now wired to the reporting renderer (task 11): it produces the
    # observed/inferred Markdown rather than raising.
    report = IncidentReport(window=_make_window(), summary="summary")
    md = report.to_markdown()
    assert "# OpsOracle Incident Report" in md
    assert "## Observed evidence" in md
    assert "## AI reasoning (inferred)" in md


def test_incident_report_to_dict_includes_truncated():
    report = IncidentReport(window=_make_window(), summary="summary", truncated=True)
    assert report.to_dict()["truncated"] is True
