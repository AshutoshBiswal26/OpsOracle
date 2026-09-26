"""Unit tests for the OpsOracle error hierarchy and credential redaction.

Covers requirements 1.6 (typed collection errors identifying source without leaking
credentials), 2.4 (ValidationError), and 9.3 (no credentials/tokens/secrets in
surfaced error messages).
"""

import pytest

from opsoracle.errors import (
    AccessError,
    CollectionError,
    ConfigError,
    NormalizationError,
    OpsOracleError,
    ReasoningError,
    ThrottlingError,
    ValidationError,
    redact_secrets,
)


# --- Hierarchy relationships -------------------------------------------------

@pytest.mark.parametrize(
    "error_cls",
    [
        ConfigError,
        ValidationError,
        CollectionError,
        ThrottlingError,
        AccessError,
        NormalizationError,
        ReasoningError,
    ],
)
def test_all_errors_derive_from_base(error_cls):
    assert issubclass(error_cls, OpsOracleError)
    assert issubclass(error_cls, Exception)


def test_base_is_exception():
    assert issubclass(OpsOracleError, Exception)


def test_collection_error_subclasses():
    assert issubclass(ThrottlingError, CollectionError)
    assert issubclass(AccessError, CollectionError)


def test_direct_children_are_not_collection_errors():
    for cls in (ConfigError, ValidationError, NormalizationError, ReasoningError):
        assert not issubclass(cls, CollectionError)


def test_throttling_and_access_are_distinct():
    assert not issubclass(ThrottlingError, AccessError)
    assert not issubclass(AccessError, ThrottlingError)


def test_raise_and_catch_via_base():
    with pytest.raises(OpsOracleError):
        raise ThrottlingError("rate limited", source="cloudtrail")


def test_throttling_caught_as_collection_error():
    with pytest.raises(CollectionError):
        raise ThrottlingError("slow down", source="cloudtrail", operation="LookupEvents")


# --- CollectionError metadata (Req 1.6) --------------------------------------

def test_collection_error_records_source_and_operation():
    err = AccessError(
        "access denied",
        source="cloudtrail",
        operation="LookupEvents",
    )
    assert err.source == "cloudtrail"
    assert err.operation == "LookupEvents"
    text = str(err)
    assert "cloudtrail" in text
    assert "LookupEvents" in text
    assert "access denied" in text


def test_collection_error_defaults_none():
    err = CollectionError("boom")
    assert err.source is None
    assert err.operation is None
    assert str(err) == "boom"


# --- Credential redaction (Req 9.3) ------------------------------------------

_AKID = "AKIAIOSFODNN7EXAMPLE"
_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # 40 chars, canonical example


def test_redact_access_key_id():
    out = redact_secrets(f"failed with key {_AKID}")
    assert _AKID not in out
    assert "REDACTED" in out


def test_redact_secret_access_key():
    out = redact_secrets(f"secret was {_SECRET}")
    assert _SECRET not in out


def test_redact_key_value_pairs():
    msg = "aws_session_token=FQoGZXIvYXdzEID aws_secret_access_key=abc123 password=hunter2"
    out = redact_secrets(msg)
    assert "FQoGZXIvYXdzEID" not in out
    assert "abc123" not in out
    assert "hunter2" not in out


def test_redact_preserves_plain_text():
    msg = "collection failed for source cloudtrail during LookupEvents"
    assert redact_secrets(msg) == msg


def test_error_message_scrubs_access_key():
    err = ConfigError(f"invalid credential {_AKID}")
    assert _AKID not in str(err)


def test_collection_error_scrubs_secret_in_message():
    err = AccessError(
        f"denied using {_SECRET}",
        source="cloudtrail",
        operation="LookupEvents",
    )
    text = str(err)
    assert _SECRET not in text
    # Non-secret diagnostic context is preserved.
    assert "cloudtrail" in text
    assert "LookupEvents" in text


def test_empty_message_is_safe():
    assert redact_secrets("") == ""
    assert str(ConfigError()) == ""
