"""Validation and repair of the Bedrock reasoning JSON output.

The model output is untrusted. This module parses it, coerces it into a
:class:`ReasoningResult`, and drops any candidate cause that cites an evidence id not
present in the supplied context (requirement 7.5). Malformed output raises
:class:`ReasoningError` so the caller can degrade gracefully (requirement 7.3).
"""

from __future__ import annotations

import json

from ..errors import ReasoningError
from ..models.report import CandidateCause, Confidence, ReasoningResult

_VALID_CONFIDENCE = {c.value for c in Confidence}


def _extract_json_object(text: str) -> dict:
    """Parse a JSON object from model text, tolerating surrounding prose/code fences."""
    if not isinstance(text, str) or not text.strip():
        raise ReasoningError("empty model output")
    stripped = text.strip()
    try:
        parsed = json.loads(stripped)
        if isinstance(parsed, dict):
            return parsed
    except ValueError:
        pass
    # Fall back to the first {...} block in the text.
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            parsed = json.loads(stripped[start : end + 1])
            if isinstance(parsed, dict):
                return parsed
        except ValueError as exc:
            raise ReasoningError(f"could not parse JSON from model output: {exc}") from exc
    raise ReasoningError("model output did not contain a JSON object")


def parse_reasoning(
    text: str, valid_evidence_ids: set[str]
) -> ReasoningResult:
    """Parse and validate model output into a ReasoningResult.

    Candidate causes are kept only if every cited evidence id is valid; a cause with any
    unknown id is dropped (requirement 7.5). An insufficient-evidence answer (empty
    factors) is preserved as a valid result (requirement 7.6).
    """

    data = _extract_json_object(text)

    factors: list[CandidateCause] = []
    dropped: list[str] = []
    raw_factors = data.get("contributing_factors", [])
    if not isinstance(raw_factors, list):
        raise ReasoningError("contributing_factors must be a list")

    for item in raw_factors:
        if not isinstance(item, dict):
            continue
        description = str(item.get("description", "")).strip()
        ids = item.get("evidence_ids", []) or []
        if not isinstance(ids, list):
            continue
        ids = [str(i) for i in ids]
        unknown = [i for i in ids if i not in valid_evidence_ids]
        if unknown:
            # Drop unsupported claim entirely (requirement 7.5).
            dropped.append(description or "(no description)")
            continue
        if not description:
            continue
        conf_raw = str(item.get("confidence", "low")).lower()
        confidence = Confidence(conf_raw) if conf_raw in _VALID_CONFIDENCE else Confidence.LOW
        factors.append(
            CandidateCause(description=description, evidence_ids=ids, confidence=confidence)
        )

    uncertainty = str(data.get("uncertainty", "")).strip()
    next_actions_raw = data.get("next_actions", []) or []
    if not isinstance(next_actions_raw, list):
        next_actions_raw = []
    next_actions = [str(a).strip() for a in next_actions_raw if str(a).strip()]

    notes = None
    if dropped:
        notes = f"dropped {len(dropped)} unsupported claim(s) citing unknown evidence"

    return ReasoningResult(
        contributing_factors=factors,
        uncertainty=uncertainty,
        next_actions=next_actions,
        ai_available=True,
        notes=notes,
    )
