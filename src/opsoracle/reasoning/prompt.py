"""Prompt contract for the Bedrock reasoning stage.

The system prompt encodes RULES.md §7: the model may summarize supplied evidence,
identify hypotheses, and recommend next steps, but must not invent evidence, timestamps,
or events, and must reference evidence ids. It may answer "insufficient evidence".

The user prompt serializes only the assembled investigation context (evidence lines with
ids + correlations) — never credentials or secrets (requirement 7.8).
"""

from __future__ import annotations

import json

from ..models.investigation import Investigation

SYSTEM_PROMPT = (
    "You are OpsOracle's reasoning assistant for AWS incident investigation. "
    "You are given already-collected, deterministic evidence. Your job is to reason "
    "over it, not to invent it.\n\n"
    "Hard rules:\n"
    "- Use ONLY the supplied evidence. Never invent evidence, timestamps, events, or "
    "AWS activity.\n"
    "- Every factual claim and every candidate cause MUST cite one or more evidence_id "
    "values that appear in the provided context.\n"
    "- Correlation is not causation. Use qualified language: 'candidate cause', "
    "'possible contributor', 'correlated with', 'preceded'.\n"
    "- If the evidence is insufficient to identify a cause, say so explicitly and set "
    "contributing_factors to an empty list.\n"
    "- Do not recommend or perform remediation actions automatically; only suggest "
    "investigation next steps.\n\n"
    "Respond with a SINGLE JSON object and nothing else, matching this shape:\n"
    "{\n"
    '  "contributing_factors": [\n'
    '    {"description": str, "evidence_ids": [str, ...], '
    '"confidence": "low"|"medium"|"high"}\n'
    "  ],\n"
    '  "uncertainty": str,\n'
    '  "next_actions": [str, ...]\n'
    "}"
)


def build_user_prompt(investigation: Investigation) -> str:
    """Serialize the investigation context compactly for the model."""
    lines: list[str] = []
    window = investigation.window
    lines.append(
        f"Investigation window (UTC): {window.start.isoformat()} to "
        f"{window.end.isoformat()}"
    )
    if investigation.truncated:
        lines.append(
            "NOTE: evidence was truncated to the highest-ranked items due to a budget."
        )

    lines.append("\nEVIDENCE:")
    if investigation.events:
        for e in investigation.events:
            resources = ",".join(r.key() for r in e.resources if r.key()) or "-"
            err = e.metadata.get("error_code")
            err_str = f" error={err}" if err else ""
            lines.append(
                f"- [{e.evidence_id}] {e.timestamp.isoformat()} "
                f"{e.source.value} {e.event_type} resources=[{resources}]{err_str} "
                f":: {e.summary}"
            )
    else:
        lines.append("- (no evidence collected)")

    lines.append("\nCORRELATIONS:")
    if investigation.correlations:
        for c in investigation.correlations:
            ids = ",".join(c.evidence_ids)
            lines.append(f"- [{c.type.value}] evidence=[{ids}] :: {c.explanation}")
    else:
        lines.append("- (no deterministic correlations found)")

    lines.append(
        "\nProduce the JSON report. Cite evidence_id values from the EVIDENCE list only."
    )
    return "\n".join(lines)


def valid_evidence_ids(investigation: Investigation) -> set[str]:
    """The set of evidence ids the model is allowed to cite."""
    return {e.evidence_id for e in investigation.events}


def to_context_json(investigation: Investigation) -> str:
    """Full structured context (used for logging/debugging, not the prompt)."""
    return json.dumps(investigation.to_dict(), default=str)
