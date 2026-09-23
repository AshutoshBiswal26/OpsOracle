import pytest

from opsoracle.cli import _parse_filters, _parse_ts, build_parser


def test_parse_ts_handles_z_suffix():
    ts = _parse_ts("2026-09-23T12:00:00Z")
    assert ts.tzinfo is not None
    assert ts.hour == 12


def test_parse_ts_naive_gets_utc():
    ts = _parse_ts("2026-09-23T12:00:00")
    assert ts.utcoffset().total_seconds() == 0


def test_parse_ts_invalid_raises():
    import argparse

    with pytest.raises(argparse.ArgumentTypeError):
        _parse_ts("not-a-date")


def test_parse_filters():
    assert _parse_filters(["EventSource=lambda.amazonaws.com", "EventName=Invoke"]) == {
        "EventSource": "lambda.amazonaws.com",
        "EventName": "Invoke",
    }


def test_parse_filters_bad_pair():
    import argparse

    with pytest.raises(argparse.ArgumentTypeError):
        _parse_filters(["noequals"])


def test_parser_requires_start_end():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])
