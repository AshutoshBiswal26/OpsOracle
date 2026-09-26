from datetime import datetime, timedelta, timezone

from opsoracle.correlation.classify import is_change, is_failure
from opsoracle.correlation.engine import CorrelationEngine
from opsoracle.models.correlation import CorrelationType
from opsoracle.models.evidence import EvidenceEvent, EvidenceSource, ResourceRef

UTC = timezone.utc


def ev(minute, name, *, resources=None, metadata=None, source=EvidenceSource.CLOUDTRAIL):
    return EvidenceEvent(
        source=source,
        event_type=name,
        timestamp=datetime(2026, 9, 23, 12, minute, 0, tzinfo=UTC),
        summary=name,
        resources=resources or [],
        metadata=metadata or {},
    )


def types(correlations):
    return {c.type for c in correlations}


def test_no_correlations_returns_empty():
    engine = CorrelationEngine()
    # single event, far apart from nothing
    assert engine.correlate([ev(0, "Solo")]) == []


def test_temporal_proximity_within_window():
    engine = CorrelationEngine(proximity_window=timedelta(minutes=5))
    corrs = engine.correlate([ev(0, "A"), ev(3, "B")])
    prox = [c for c in corrs if c.type is CorrelationType.TEMPORAL_PROXIMITY]
    assert len(prox) == 1
    assert set(prox[0].evidence_ids) == {ev(0, "A").evidence_id, ev(3, "B").evidence_id}


def test_temporal_proximity_outside_window_excluded():
    engine = CorrelationEngine(proximity_window=timedelta(minutes=5))
    corrs = engine.correlate([ev(0, "A"), ev(30, "B")])
    assert not any(c.type is CorrelationType.TEMPORAL_PROXIMITY for c in corrs)


def test_shared_resource_correlation():
    r = ResourceRef(type="AWS::Lambda::Function", name="fn-1")
    # far apart in time so proximity does not fire, but same resource
    engine = CorrelationEngine(proximity_window=timedelta(seconds=1))
    corrs = engine.correlate([ev(0, "UpdateFunctionCode", resources=[r]), ev(40, "Invoke", resources=[r])])
    shared = [c for c in corrs if c.type is CorrelationType.SHARED_RESOURCE]
    assert len(shared) == 1
    assert "fn-1" in shared[0].explanation


def test_change_before_failure_ordering():
    engine = CorrelationEngine(
        proximity_window=timedelta(seconds=1),
        change_before_failure_window=timedelta(minutes=15),
    )
    change = ev(0, "UpdateFunctionConfiguration")
    failure = ev(5, "Invoke", metadata={"error_code": "Throttled"})
    corrs = engine.correlate([change, failure])
    cbf = [c for c in corrs if c.type is CorrelationType.CHANGE_BEFORE_FAILURE]
    assert len(cbf) == 1
    # change id must come first in the pair
    assert cbf[0].evidence_ids[0] == change.evidence_id
    assert "candidate cause" in cbf[0].explanation


def test_failure_before_change_not_correlated_as_cbf():
    engine = CorrelationEngine(proximity_window=timedelta(seconds=1))
    failure = ev(0, "Invoke", metadata={"error_code": "X"})
    change = ev(5, "UpdateFunctionConfiguration")
    corrs = engine.correlate([failure, change])
    assert not any(c.type is CorrelationType.CHANGE_BEFORE_FAILURE for c in corrs)


def test_explanations_avoid_causal_language():
    engine = CorrelationEngine()
    change = ev(0, "CreateBucket")
    failure = ev(2, "PutObject", metadata={"error_code": "AccessDenied"})
    for c in engine.correlate([change, failure]):
        lowered = c.explanation.lower()
        assert "caused" not in lowered or "not causal" in lowered
        assert "guaranteed" not in lowered


def test_classify_helpers():
    assert is_change(ev(0, "CreateBucket")) is True
    assert is_change(ev(0, "DescribeInstances")) is False
    assert is_change(ev(0, "CreateBucket", metadata={"read_only": True})) is False
    assert is_failure(ev(0, "X", metadata={"error_code": "Y"})) is True
    alarm = ev(0, "cpu-high", metadata={"state": "ALARM"}, source=EvidenceSource.CLOUDWATCH_ALARM)
    assert is_failure(alarm) is True


def _mixed_events_triggering_all_types():
    """Two events that together trigger temporal-proximity, shared-resource, and
    change-before-failure correlations under the default engine windows."""
    r = ResourceRef(type="AWS::Lambda::Function", name="fn-mixed")
    change = ev(0, "UpdateFunctionConfiguration", resources=[r])
    failure = ev(2, "Invoke", resources=[r], metadata={"error_code": "Throttled"})
    return change, failure


def test_all_correlation_types_present_in_mixed_scenario():
    # Guards the fixture used by the language tests: it must exercise every rule so the
    # "no caused" / qualified-language assertions cover all explanation shapes.
    engine = CorrelationEngine()
    corrs = engine.correlate(list(_mixed_events_triggering_all_types()))
    assert types(corrs) == {
        CorrelationType.TEMPORAL_PROXIMITY,
        CorrelationType.SHARED_RESOURCE,
        CorrelationType.CHANGE_BEFORE_FAILURE,
    }


def test_no_explanation_ever_contains_the_word_caused():
    # Strict form of requirement 5.5: correlation explanations must never assert
    # causality via the word "caused", across every correlation type produced.
    engine = CorrelationEngine()
    corrs = engine.correlate(list(_mixed_events_triggering_all_types()))
    assert corrs, "expected correlations to assert against"
    for c in corrs:
        assert "caused" not in c.explanation.lower(), c.explanation


def test_explanations_use_qualified_language():
    # Positive check (requirement 5.5): each explanation uses qualified/hedged phrasing
    # such as "correlated with", "preceded", or "candidate cause" rather than a
    # definitive causal claim.
    engine = CorrelationEngine()
    corrs = engine.correlate(list(_mixed_events_triggering_all_types()))
    qualified = ("correlated with", "preceded", "candidate cause", "not causal", "not confirmed")
    for c in corrs:
        lowered = c.explanation.lower()
        assert any(phrase in lowered for phrase in qualified), c.explanation
