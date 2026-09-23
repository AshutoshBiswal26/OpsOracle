from datetime import datetime, timezone

from opsoracle.models.correlation import Correlation, CorrelationType
from opsoracle.models.evidence import EvidenceEvent, EvidenceSource, ResourceRef
from opsoracle.models.investigation import Investigation, TimeWindow
from opsoracle.models.report import CandidateCause, Confidence, ReasoningResult
from opsoracle.reporting.incident_report import ReportBuilder

UTC = timezone.utc


def window():
    return TimeWindow(
        start=datetime(2026, 9, 23, 12, tzinfo=UTC),
        end=datetime(2026, 9, 23, 13, tzinfo=UTC),
    )


def event(name="UpdateFunctionConfiguration", minute=30):
    return EvidenceEvent(
        source=EvidenceSource.CLOUDTRAIL,
        event_type=name,
        timestamp=datetime(2026, 9, 23, 12, minute, tzinfo=UTC),
        summary=f"{name} summary",
        resources=[ResourceRef(type="AWS::Lambda::Function", name="fn-1")],
    )


def test_report_has_observed_and_inferred_sections():
    e = event()
    inv = Investigation(window=window(), events=[e], correlations=[])
    reasoning = ReasoningResult(
        contributing_factors=[
            CandidateCause("config change candidate", [e.evidence_id], Confidence.MEDIUM)
        ],
        uncertainty="moderate",
        next_actions=["inspect logs"],
    )
    md = ReportBuilder().build(inv, reasoning).to_markdown()
    assert "## Observed evidence" in md
    assert "## AI reasoning (inferred)" in md
    # observed appears before inferred
    assert md.index("## Observed evidence") < md.index("## AI reasoning (inferred)")


def test_candidate_causes_cite_evidence_ids():
    e = event()
    inv = Investigation(window=window(), events=[e])
    reasoning = ReasoningResult(
        contributing_factors=[
            CandidateCause("candidate", [e.evidence_id], Confidence.HIGH)
        ]
    )
    md = ReportBuilder().build(inv, reasoning).to_markdown()
    assert e.evidence_id in md
    assert "candidate" in md


def test_ai_unavailable_note_and_observed_still_rendered():
    e = event()
    inv = Investigation(window=window(), events=[e])
    reasoning = ReasoningResult.unavailable("bedrock call failed")
    md = ReportBuilder().build(inv, reasoning).to_markdown()
    assert "AI reasoning unavailable" in md
    assert "bedrock call failed" in md
    # observed evidence still present
    assert e.evidence_id in md
    # no candidate factors section content when unavailable
    assert "Candidate contributing factors" not in md


def test_correlations_rendered_with_evidence_ids():
    e1 = event("CreateBucket", 10)
    e2 = event("PutObject", 12)
    corr = Correlation(
        CorrelationType.TEMPORAL_PROXIMITY,
        [e1.evidence_id, e2.evidence_id],
        "occurred close together (correlated with)",
    )
    inv = Investigation(window=window(), events=[e1, e2], correlations=[corr])
    md = ReportBuilder().build(inv, ReasoningResult.unavailable("x")).to_markdown()
    assert "temporal_proximity" in md
    assert e1.evidence_id in md and e2.evidence_id in md


def test_truncation_note_rendered():
    e = event()
    inv = Investigation(window=window(), events=[e], truncated=True)
    md = ReportBuilder().build(inv, ReasoningResult.unavailable("x")).to_markdown()
    assert "truncated" in md.lower()


def test_summary_reflects_counts():
    e = event()
    inv = Investigation(window=window(), events=[e])
    report = ReportBuilder().build(inv, ReasoningResult.unavailable("x"))
    assert "1 evidence event" in report.summary


def test_insufficient_evidence_rendering():
    e = event()
    inv = Investigation(window=window(), events=[e])
    reasoning = ReasoningResult(contributing_factors=[], uncertainty="insufficient")
    md = ReportBuilder().build(inv, reasoning).to_markdown()
    assert "insufficient evidence" in md.lower()
