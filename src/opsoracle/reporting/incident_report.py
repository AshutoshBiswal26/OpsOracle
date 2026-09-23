"""Incident report construction and Markdown rendering.

The report separates an OBSERVED section (deterministic evidence + correlations) from an
INFERRED section (Bedrock reasoning), and cites evidence ids on every claim
(requirements 8.3, 8.4). If AI reasoning was unavailable, the observed sections still
render and the report notes the AI section is absent (requirement 8.5).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models.correlation import Correlation
from ..models.evidence import EvidenceEvent
from ..models.investigation import Investigation, TimeWindow
from ..models.report import ReasoningResult


@dataclass(frozen=True)
class IncidentReport:
    window: TimeWindow
    summary: str
    timeline: list[EvidenceEvent] = field(default_factory=list)
    correlations: list[Correlation] = field(default_factory=list)
    reasoning: ReasoningResult = field(default_factory=ReasoningResult)
    truncated: bool = False

    def to_dict(self) -> dict:
        return {
            "window": self.window.to_dict(),
            "summary": self.summary,
            "timeline": [e.to_dict() for e in self.timeline],
            "correlations": [c.to_dict() for c in self.correlations],
            "reasoning": self.reasoning.to_dict(),
            "truncated": self.truncated,
        }

    def to_markdown(self) -> str:
        lines: list[str] = []
        w = self.window
        lines.append("# OpsOracle Incident Report")
        lines.append("")
        lines.append(f"**Window (UTC):** {w.start.isoformat()} — {w.end.isoformat()}")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append(self.summary or "_No summary available._")
        lines.append("")

        # ---- OBSERVED (deterministic) ----
        lines.append("## Observed evidence")
        lines.append("")
        lines.append("_Deterministic facts collected from AWS. Each line is traceable "
                     "by its evidence id._")
        lines.append("")
        if self.truncated:
            lines.append("> Note: evidence was truncated to the highest-ranked items "
                         "due to a context budget.")
            lines.append("")
        if self.timeline:
            lines.append("| Evidence ID | Timestamp (UTC) | Source | Event | Resources | Summary |")
            lines.append("|---|---|---|---|---|---|")
            for e in self.timeline:
                resources = ", ".join(r.key() for r in e.resources if r.key()) or "-"
                summary = e.summary.replace("|", "\\|")
                lines.append(
                    f"| `{e.evidence_id}` | {e.timestamp.isoformat()} | {e.source.value} "
                    f"| {e.event_type} | {resources} | {summary} |"
                )
        else:
            lines.append("_No evidence collected in this window._")
        lines.append("")

        lines.append("## Observed correlations")
        lines.append("")
        lines.append("_Deterministic relationships. Correlation is not causation._")
        lines.append("")
        if self.correlations:
            for c in self.correlations:
                ids = ", ".join(f"`{i}`" for i in c.evidence_ids)
                lines.append(f"- **{c.type.value}** ({ids}): {c.explanation}")
        else:
            lines.append("_No deterministic correlations found._")
        lines.append("")

        # ---- INFERRED (AI) ----
        lines.append("## AI reasoning (inferred)")
        lines.append("")
        r = self.reasoning
        if not r.ai_available:
            reason = r.notes or "AI reasoning was not performed."
            lines.append(f"_AI reasoning unavailable: {reason} "
                         "The observed sections above are complete and unaffected._")
            lines.append("")
            return "\n".join(lines)

        lines.append("_Inferred by an LLM over the observed evidence. Treat as hypotheses, "
                     "not confirmed facts._")
        lines.append("")

        lines.append("### Candidate contributing factors")
        lines.append("")
        if r.contributing_factors:
            for cc in r.contributing_factors:
                ids = ", ".join(f"`{i}`" for i in cc.evidence_ids) or "_no evidence cited_"
                lines.append(
                    f"- ({cc.confidence.value} confidence) {cc.description} "
                    f"— evidence: {ids}"
                )
        else:
            lines.append("_No candidate causes identified; insufficient evidence._")
        lines.append("")

        lines.append("### Uncertainty")
        lines.append("")
        lines.append(r.uncertainty or "_Not stated._")
        lines.append("")

        lines.append("### Recommended next actions")
        lines.append("")
        if r.next_actions:
            for action in r.next_actions:
                lines.append(f"- {action}")
        else:
            lines.append("_None suggested._")
        lines.append("")

        if r.notes:
            lines.append(f"> Reasoning note: {r.notes}")
            lines.append("")

        return "\n".join(lines)


class ReportBuilder:
    def build(
        self, investigation: Investigation, reasoning: ReasoningResult
    ) -> IncidentReport:
        summary = self._build_summary(investigation, reasoning)
        return IncidentReport(
            window=investigation.window,
            summary=summary,
            timeline=sorted(
                investigation.events, key=lambda e: (e.timestamp, e.evidence_id)
            ),
            correlations=investigation.correlations,
            reasoning=reasoning,
            truncated=investigation.truncated,
        )

    @staticmethod
    def _build_summary(investigation: Investigation, reasoning: ReasoningResult) -> str:
        n_events = len(investigation.events)
        n_corr = len(investigation.correlations)
        parts = [
            f"Collected {n_events} evidence event(s) and found {n_corr} "
            f"deterministic correlation(s) in the investigation window."
        ]
        if not reasoning.ai_available:
            parts.append("AI reasoning was not applied.")
        elif reasoning.contributing_factors:
            parts.append(
                f"AI reasoning proposed {len(reasoning.contributing_factors)} "
                "candidate contributing factor(s)."
            )
        else:
            parts.append("AI reasoning found insufficient evidence for a root cause.")
        return " ".join(parts)
