from datetime import datetime, timezone

from opsoracle.models.correlation import Correlation, CorrelationType
from opsoracle.models.evidence import (
    Actor,
    EvidenceEvent,
    EvidenceSource,
    ResourceRef,
)
from opsoracle.models.investigation import Investigation, TimeWindow
from opsoracle.reasoning.prompt import (
    SYSTEM_PROMPT,
    build_user_prompt,
    valid_evidence_ids,
)

UTC = timezone.utc


def window():
    return TimeWindow(
        start=datetime(2026, 9, 23, 12, tzinfo=UTC),
        end=datetime(2026, 9, 23, 13, tzinfo=UTC),
    )


def event_with_secret():
    """An event carrying a fake secret in metadata/raw_ref that must NOT leak."""
    return EvidenceEvent(
        source=EvidenceSource.CLOUDTRAIL,
        event_type="UpdateFunctionConfiguration",
        timestamp=datetime(2026, 9, 23, 12, 30, tzinfo=UTC),
        summary="config change on payments-fn",
        actor=Actor(type="IAMUser", principal_id="AIDAEXAMPLE", arn="arn:aws:iam::111:user/dev"),
        resources=[ResourceRef(type="AWS::Lambda::Function", name="payments-fn")],
        metadata={"error_code": "AccessDenied", "aws_secret_access_key": "SECRETKEY123"},
        raw_ref={"AccessKeyId": "AKIAIOSFODNN7EXAMPLE", "token": "SESSIONTOKENXYZ"},
    )


# ---- system prompt encodes the evidence-first contract ----

def test_system_prompt_encodes_evidence_first_rules():
    text = SYSTEM_PROMPT.lower()
    # Use only supplied evidence / never invent.
    assert "only" in text and "supplied evidence" in text
    assert "never invent" in text
    # Every claim cites evidence ids.
    assert "evidence_id" in text
    # Qualified language / correlation is not causation.
    assert "correlation is not causation" in text
    # Insufficient-evidence answer allowed (empty contributing_factors).
    assert "insufficient" in text
    assert "empty list" in text
    # No auto-remediation.
    assert "remediation" in text


def test_system_prompt_requests_json_shape():
    assert "contributing_factors" in SYSTEM_PROMPT
    assert "evidence_ids" in SYSTEM_PROMPT
    assert "uncertainty" in SYSTEM_PROMPT
    assert "next_actions" in SYSTEM_PROMPT


# ---- user prompt serialization ----

def test_user_prompt_includes_evidence_ids():
    e = event_with_secret()
    inv = Investigation(window=window(), events=[e])
    prompt = build_user_prompt(inv)
    assert e.evidence_id in prompt
    assert "config change on payments-fn" in prompt
    assert "payments-fn" in prompt


def test_user_prompt_includes_correlations_with_evidence_ids():
    e = event_with_secret()
    corr = Correlation(
        type=CorrelationType.CHANGE_BEFORE_FAILURE,
        evidence_ids=[e.evidence_id],
        explanation="change preceded the failure",
    )
    inv = Investigation(window=window(), events=[e], correlations=[corr])
    prompt = build_user_prompt(inv)
    assert e.evidence_id in prompt
    assert "change preceded the failure" in prompt
    assert CorrelationType.CHANGE_BEFORE_FAILURE.value in prompt


def test_user_prompt_does_not_leak_secrets():
    e = event_with_secret()
    inv = Investigation(window=window(), events=[e])
    prompt = build_user_prompt(inv)
    # Fake credentials placed in metadata/raw_ref must never reach the model.
    assert "SECRETKEY123" not in prompt
    assert "AKIAIOSFODNN7EXAMPLE" not in prompt
    assert "SESSIONTOKENXYZ" not in prompt
    assert "aws_secret_access_key" not in prompt


def test_user_prompt_handles_empty_evidence():
    inv = Investigation(window=window(), events=[])
    prompt = build_user_prompt(inv)
    assert "no evidence collected" in prompt
    assert "no deterministic correlations found" in prompt


def test_user_prompt_notes_truncation():
    e = event_with_secret()
    inv = Investigation(window=window(), events=[e], truncated=True)
    prompt = build_user_prompt(inv)
    assert "truncated" in prompt.lower()


def test_valid_evidence_ids_matches_events():
    e = event_with_secret()
    inv = Investigation(window=window(), events=[e])
    assert valid_evidence_ids(inv) == {e.evidence_id}
    assert valid_evidence_ids(Investigation(window=window(), events=[])) == set()
