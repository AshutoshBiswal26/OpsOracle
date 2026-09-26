"""Unit tests for the auditable change/failure classification lookup.

These tests pin down the small, rule-based labels that the change-before-failure
correlation rule depends on (requirements 5.3, 5.5). The classification must be
explainable and deterministic per RULES.md §4, so every rule is exercised directly.
"""

from datetime import datetime, timezone

import pytest

from opsoracle.correlation.classify import is_change, is_failure
from opsoracle.models.evidence import EvidenceEvent, EvidenceSource

UTC = timezone.utc


def make_event(event_type, *, source=EvidenceSource.CLOUDTRAIL, metadata=None):
    return EvidenceEvent(
        source=source,
        event_type=event_type,
        timestamp=datetime(2026, 9, 23, 12, 0, 0, tzinfo=UTC),
        summary=event_type,
        metadata=metadata or {},
    )


# --- is_change -------------------------------------------------------------

# One representative event name per mutating prefix the lookup recognizes.
MUTATING_EVENT_NAMES = [
    "CreateBucket",
    "UpdateFunctionConfiguration",
    "DeleteObject",
    "PutBucketPolicy",
    "ModifyInstanceAttribute",
    "AttachRolePolicy",
    "DetachRolePolicy",
    "RunInstances",
    "StartInstances",
    "StopInstances",
    "TerminateInstances",
    "RebootInstances",
    "AssociateAddress",
    "DisassociateAddress",
    "SetSubnetAttribute",
    "RemoveTags",
    "AddPermission",
    "EnableKey",
    "DisableKey",
    "DeployStack",
    "RegisterTargets",
    "DeregisterTargets",
    "ReplaceRoute",
]


@pytest.mark.parametrize("event_type", MUTATING_EVENT_NAMES)
def test_mutating_prefixes_are_changes(event_type):
    assert is_change(make_event(event_type)) is True


@pytest.mark.parametrize(
    "event_type",
    ["DescribeInstances", "GetObject", "ListBuckets", "LookupEvents", "HeadBucket"],
)
def test_read_event_names_are_not_changes(event_type):
    assert is_change(make_event(event_type)) is False


def test_read_only_flag_excludes_otherwise_mutating_event():
    # Even a mutating-looking name must not be a change when marked read_only.
    event = make_event("CreateBucket", metadata={"read_only": True})
    assert is_change(event) is False


def test_read_only_false_does_not_suppress_change():
    event = make_event("CreateBucket", metadata={"read_only": False})
    assert is_change(event) is True


def test_non_cloudtrail_source_is_not_a_change():
    # The change label only applies to CloudTrail control-plane activity.
    event = make_event(
        "CreateBucket",
        source=EvidenceSource.CLOUDWATCH_ALARM,
        metadata={"read_only": False},
    )
    assert is_change(event) is False


# --- is_failure ------------------------------------------------------------

def test_error_code_marks_failure_regardless_of_source():
    for source in (
        EvidenceSource.CLOUDTRAIL,
        EvidenceSource.CLOUDWATCH_METRIC,
        EvidenceSource.CLOUDWATCH_LOG,
        EvidenceSource.CLOUDWATCH_ALARM,
    ):
        event = make_event("SomeCall", source=source, metadata={"error_code": "AccessDenied"})
        assert is_failure(event) is True


def test_empty_error_code_is_not_a_failure():
    assert is_failure(make_event("CreateBucket", metadata={"error_code": ""})) is False
    assert is_failure(make_event("CreateBucket", metadata={})) is False


def test_alarm_in_alarm_state_is_a_failure():
    event = make_event(
        "cpu-high", source=EvidenceSource.CLOUDWATCH_ALARM, metadata={"state": "ALARM"}
    )
    assert is_failure(event) is True


def test_alarm_state_match_is_case_insensitive():
    event = make_event(
        "cpu-high", source=EvidenceSource.CLOUDWATCH_ALARM, metadata={"state": "alarm"}
    )
    assert is_failure(event) is True


@pytest.mark.parametrize("state", ["OK", "INSUFFICIENT_DATA", "", None])
def test_alarm_not_in_alarm_state_is_not_a_failure(state):
    metadata = {} if state is None else {"state": state}
    event = make_event("cpu-high", source=EvidenceSource.CLOUDWATCH_ALARM, metadata=metadata)
    assert is_failure(event) is False


def test_ordinary_cloudtrail_event_without_error_is_not_a_failure():
    assert is_failure(make_event("CreateBucket")) is False
