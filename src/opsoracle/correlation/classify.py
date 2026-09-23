"""Auditable classification of evidence as "change" vs "failure".

Kept deliberately simple and rule-based so every label is explainable (RULES.md §4).
This module is the single place that decides what counts as a change or a failure for the
change-before-failure correlation rule.
"""

from __future__ import annotations

from ..models.evidence import EvidenceEvent, EvidenceSource

# CloudTrail event-name prefixes that indicate a mutating (change) action.
_CHANGE_PREFIXES = (
    "Create",
    "Update",
    "Delete",
    "Put",
    "Modify",
    "Attach",
    "Detach",
    "Run",
    "Start",
    "Stop",
    "Terminate",
    "Reboot",
    "Associate",
    "Disassociate",
    "Set",
    "Remove",
    "Add",
    "Enable",
    "Disable",
    "Deploy",
    "Register",
    "Deregister",
    "Replace",
)


def is_change(event: EvidenceEvent) -> bool:
    """True if the event represents a mutating change to infrastructure/config."""
    if event.source is EvidenceSource.CLOUDTRAIL:
        # read_only=True is explicitly not a change.
        if event.metadata.get("read_only") is True:
            return False
        return event.event_type.startswith(_CHANGE_PREFIXES)
    return False


def is_failure(event: EvidenceEvent) -> bool:
    """True if the event represents an error, degradation, or alarm firing."""
    if event.metadata.get("error_code"):
        return True
    if event.source is EvidenceSource.CLOUDWATCH_ALARM:
        # Alarm evidence carries its state; treat ALARM state as a failure signal.
        return str(event.metadata.get("state", "")).upper() == "ALARM"
    return False
