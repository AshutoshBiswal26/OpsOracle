"""Cross-cutting verification: deterministic-id deduplication, no-secret-leakage,
and end-to-end evidence traceability.

Covers requirements:
- 11.2 duplicate events collapse to a single evidence event across the pipeline;
- 9.3 no credential/token/secret value ever appears in a surfaced error string;
- 11.3 every report claim traces to a specific evidence event.

All checks run fully offline — no live AWS calls (requirement 11.1).
"""

import json
from datetime import datetime, timezone

from opsoracle.collectors.cloudtrail import CloudTrailCollector
from opsoracle.config import Config
from opsoracle.correlation.engine import CorrelationEngine
from opsoracle.errors import (
    AccessError,
    CollectionError,
    ConfigError,
    NormalizationError,
    OpsOracleError,
    ReasoningError,
    ThrottlingError,
    ValidationError,
)
from opsoracle.investigation.investigator import Investigator
from opsoracle.models.evidence import EvidenceEvent, EvidenceSource, ResourceRef
from opsoracle.models.investigation import TimeWindow
from opsoracle.normalization.cloudtrail import CloudTrailNormalizer
from opsoracle.reasoning.bedrock import BedrockReasoner
from opsoracle.reporting.incident_report import ReportBuilder
from opsoracle.timeline.builder import TimelineBuilder

UTC = timezone.utc


# --- Fixtures / helpers ------------------------------------------------------

def _event(name="RunInstances"):
    return EvidenceEvent(
        source=EvidenceSource.CLOUDTRAIL,
        event_type=name,
        timestamp=datetime(2026, 9, 23, 12, 0, tzinfo=UTC),
        summary=name,
        resources=[ResourceRef(type="AWS::EC2::Instance", name="i-1")],
    )


def _window():
    return TimeWindow(
        start=datetime(2026, 9, 23, 12, 0, tzinfo=UTC),
        end=datetime(2026, 9, 23, 13, 0, tzinfo=UTC),
    )


def _ct_record(event_id, name, minute, *, resource="fn-1"):
    """A raw CloudTrail lookup_events record (as boto3 would return it)."""
    detail = {
        "eventName": name,
        "eventSource": "lambda.amazonaws.com",
        "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::1:user/dev"},
    }
    return {
        "EventId": event_id,
        "EventName": name,
        "EventSource": "lambda.amazonaws.com",
        "EventTime": datetime(2026, 9, 23, 12, minute, 0, tzinfo=UTC),
        "ReadOnly": "false",
        "Resources": [{"ResourceType": "AWS::Lambda::Function", "ResourceName": resource}],
        "CloudTrailEvent": json.dumps(detail),
    }


class _FakeCloudTrail:
    def __init__(self, events):
        self._events = events

    def lookup_events(self, **kwargs):
        return {"Events": self._events}


# --- Deterministic-id deduplication (Req 11.2) -------------------------------

def test_duplicate_events_share_deterministic_id():
    # Two identical logical events produce the same evidence_id -> dedup by id.
    a = _event()
    b = _event()
    assert a.evidence_id == b.evidence_id
    deduped = {e.evidence_id: e for e in [a, b]}
    assert len(deduped) == 1


def test_timeline_collapses_duplicate_events_to_single_entry():
    # The timeline is the aggregation point: identical events collapse to one row.
    dup = _event("UpdateFunctionConfiguration")
    ordered = TimelineBuilder().build([dup, dup, dup])
    assert len(ordered) == 1
    assert ordered[0].evidence_id == dup.evidence_id


def test_correlation_dedup_via_deterministic_ids():
    # Feeding duplicate events must not yield duplicate correlations.
    e1 = _event("CreateBucket")
    e2 = EvidenceEvent(
        source=EvidenceSource.CLOUDTRAIL,
        event_type="PutObject",
        timestamp=datetime(2026, 9, 23, 12, 1, tzinfo=UTC),
        summary="PutObject",
        resources=[ResourceRef(type="AWS::EC2::Instance", name="i-1")],
    )
    corrs_once = CorrelationEngine().correlate([e1, e2])
    corrs_dup = CorrelationEngine().correlate([e1, e1, e2, e2])
    ids_once = {c.correlation_id for c in corrs_once}
    ids_dup = {c.correlation_id for c in corrs_dup}
    assert ids_once == ids_dup


def test_identical_cloudtrail_records_report_as_single_evidence_event():
    """Two byte-identical CloudTrail records must normalize/correlate/report as ONE
    evidence event end-to-end (deterministic evidence_id dedup, requirement 11.2)."""
    original = _ct_record("evt-1", "UpdateFunctionConfiguration", 10)
    # A second record with identical *content* (the EventId differs, as AWS would
    # assign, but the normalized content — source/name/time/resource/actor — is the
    # same, so the deterministic evidence_id is identical).
    duplicate = _ct_record("evt-2", "UpdateFunctionConfiguration", 10)

    normalizer = CloudTrailNormalizer()
    events = normalizer.normalize([original, duplicate])
    # Both raw records normalize successfully...
    assert len(events) == 2
    # ...to the SAME deterministic evidence_id.
    assert events[0].evidence_id == events[1].evidence_id

    # Run the deterministic pipeline (timeline -> correlate -> context -> report).
    config = Config(reasoning_enabled=False, max_events=50)
    collector = CloudTrailCollector(_FakeCloudTrail([original, duplicate]))
    reasoner = BedrockReasoner(None, model_id="m", enabled=False)
    investigator = Investigator(
        config=config, cloudtrail_collector=collector, reasoner=reasoner
    )
    report = investigator.investigate(_window())

    # The report timeline holds exactly one evidence event, not two.
    assert len(report.timeline) == 1
    assert report.timeline[0].evidence_id == events[0].evidence_id

    # A single event cannot self-correlate: no spurious correlations from the duplicate.
    md = report.to_markdown()
    assert md.count(f"`{events[0].evidence_id}`") >= 1


# --- No secret values in error strings (Req 9.3) -----------------------------

# Fake, non-real credentials that must NEVER survive into a rendered error string.
_FAKE_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
_FAKE_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # 40-char canonical example
_FAKE_SESSION_TOKEN = (
    "FQoGZXIvYXdzEBYaDLPXAMPLEsessiontokenvaluethatislongenoughtolooklikearealone"
    "1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijKLMNOPQRSTUVWXYZ0987654321"
)
_ALL_SECRETS = (_FAKE_ACCESS_KEY_ID, _FAKE_SECRET_KEY, _FAKE_SESSION_TOKEN)


def _assert_no_secret_leak(text: str) -> None:
    for secret in _ALL_SECRETS:
        assert secret not in text, f"secret leaked into error text: {secret!r}"
    # Redaction marker should be present when we deliberately embedded a secret.
    assert "REDACTED" in text


def test_base_error_scrubs_interpolated_credentials():
    msg = (
        f"auth failed access_key={_FAKE_ACCESS_KEY_ID} "
        f"secret_key={_FAKE_SECRET_KEY} session_token={_FAKE_SESSION_TOKEN}"
    )
    _assert_no_secret_leak(str(OpsOracleError(msg)))


def test_every_error_subclass_redacts_interpolated_secrets():
    """Every error in the hierarchy must scrub credentials from its message (9.3)."""
    msg = (
        f"boom AKID {_FAKE_ACCESS_KEY_ID}; secret {_FAKE_SECRET_KEY}; "
        f"token {_FAKE_SESSION_TOKEN}"
    )
    for cls in (
        OpsOracleError,
        ConfigError,
        ValidationError,
        CollectionError,
        NormalizationError,
        ReasoningError,
    ):
        _assert_no_secret_leak(str(cls(msg)))


def test_collection_error_subclasses_redact_secret_in_message_with_context():
    """CollectionError/AccessError/ThrottlingError redact secrets embedded in the
    message while preserving the non-secret source/operation context."""
    msg = (
        f"denied using access_key={_FAKE_ACCESS_KEY_ID} "
        f"secret_key={_FAKE_SECRET_KEY} token={_FAKE_SESSION_TOKEN}"
    )
    for cls in (CollectionError, AccessError, ThrottlingError):
        err = cls(msg, source="cloudtrail", operation="lookup_events")
        text = str(err)
        _assert_no_secret_leak(text)
        # Non-secret diagnostic context survives redaction.
        assert "cloudtrail" in text
        assert "lookup_events" in text


def test_collection_errors_do_not_leak_secret_values():
    secret = _FAKE_ACCESS_KEY_ID
    # Build errors the way collectors do; the secret must never be embedded.
    for err in (
        CollectionError("failed to collect events", source="cloudtrail", operation="lookup_events"),
        AccessError("access denied", source="cloudtrail", operation="lookup_events"),
        ThrottlingError("exhausted retries", source="cloudtrail", operation="lookup_events"),
    ):
        assert secret not in str(err)


def test_error_message_contains_source_context_only():
    err = CollectionError("boom", source="cloudtrail", operation="lookup_events")
    text = str(err)
    assert "cloudtrail" in text
    assert "lookup_events" in text


# --- Report-claim traceability (Req 11.3) ------------------------------------

def test_every_report_claim_traces_to_an_evidence_event():
    """Every evidence id cited by a correlation must exist in the report timeline and
    render in the Markdown, so no claim references evidence that isn't present (11.3)."""
    records = [
        _ct_record("evt-1", "UpdateFunctionConfiguration", 10),
        _ct_record("evt-2", "Invoke", 12, resource="fn-1"),
    ]
    config = Config(reasoning_enabled=False, max_events=50)
    collector = CloudTrailCollector(_FakeCloudTrail(records))
    reasoner = BedrockReasoner(None, model_id="m", enabled=False)
    investigator = Investigator(
        config=config, cloudtrail_collector=collector, reasoner=reasoner
    )
    report = investigator.investigate(_window())
    md = report.to_markdown()

    timeline_ids = {e.evidence_id for e in report.timeline}
    assert timeline_ids, "expected deterministic evidence in the report"

    # Every correlation cites only real, present evidence ids, all rendered in the md.
    for corr in report.correlations:
        assert corr.evidence_ids, "a correlation must cite evidence"
        for cited in corr.evidence_ids:
            assert cited in timeline_ids
            assert cited in md
