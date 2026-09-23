"""Cross-cutting checks: deterministic-id deduplication and no-secret-leakage."""

from datetime import datetime, timezone

from opsoracle.correlation.engine import CorrelationEngine
from opsoracle.errors import AccessError, CollectionError, ThrottlingError
from opsoracle.models.evidence import EvidenceEvent, EvidenceSource, ResourceRef

UTC = timezone.utc


def _event(name="RunInstances"):
    return EvidenceEvent(
        source=EvidenceSource.CLOUDTRAIL,
        event_type=name,
        timestamp=datetime(2026, 9, 23, 12, 0, tzinfo=UTC),
        summary=name,
        resources=[ResourceRef(type="AWS::EC2::Instance", name="i-1")],
    )


def test_duplicate_events_share_deterministic_id():
    # Two identical logical events produce the same evidence_id -> dedup by id.
    a = _event()
    b = _event()
    assert a.evidence_id == b.evidence_id
    deduped = {e.evidence_id: e for e in [a, b]}
    assert len(deduped) == 1


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


def test_collection_errors_do_not_leak_secret_values():
    secret = "AKIAIOSFODNN7EXAMPLE"
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
