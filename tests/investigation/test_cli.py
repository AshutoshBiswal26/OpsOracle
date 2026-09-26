import argparse

import pytest

from opsoracle.cli import (
    _parse_filters,
    _parse_ts,
    build_parser,
    collect_filters,
    main,
)
from opsoracle.config import Config
from opsoracle.errors import ValidationError


def test_parse_ts_handles_z_suffix():
    ts = _parse_ts("2026-09-23T12:00:00Z")
    assert ts.tzinfo is not None
    assert ts.hour == 12


def test_parse_ts_naive_gets_utc():
    ts = _parse_ts("2026-09-23T12:00:00")
    assert ts.utcoffset().total_seconds() == 0


def test_parse_ts_invalid_raises():
    with pytest.raises(argparse.ArgumentTypeError):
        _parse_ts("not-a-date")


def test_parse_filters():
    assert _parse_filters(["EventSource=lambda.amazonaws.com", "EventName=Invoke"]) == {
        "EventSource": "lambda.amazonaws.com",
        "EventName": "Invoke",
    }


def test_parse_filters_bad_pair():
    with pytest.raises(argparse.ArgumentTypeError):
        _parse_filters(["noequals"])


def test_parse_filters_empty_key():
    with pytest.raises(argparse.ArgumentTypeError):
        _parse_filters(["=value"])


def test_parser_requires_start_end():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])


def test_collect_filters_merges_convenience_and_generic():
    parser = build_parser()
    args = parser.parse_args([
        "--start", "2026-09-23T12:00:00Z",
        "--end", "2026-09-23T13:00:00Z",
        "--event-source", "lambda.amazonaws.com",
        "--event-name", "Invoke",
        "--filter", "Username=alice",
    ])
    assert collect_filters(args) == {
        "EventSource": "lambda.amazonaws.com",
        "EventName": "Invoke",
        "Username": "alice",
    }


def test_collect_filters_generic_overrides_convenience():
    parser = build_parser()
    args = parser.parse_args([
        "--start", "2026-09-23T12:00:00Z",
        "--end", "2026-09-23T13:00:00Z",
        "--event-name", "Invoke",
        "--filter", "EventName=CreateBucket",
    ])
    assert collect_filters(args) == {"EventName": "CreateBucket"}


# --- main() integration with an injected Investigator (no live AWS) --------------------


class _FakeReport:
    def __init__(self, markdown: str) -> None:
        self._markdown = markdown

    def to_markdown(self) -> str:
        return self._markdown


class _FakeInvestigator:
    """Records the config/window/filters it was built and called with."""

    last_config: Config | None = None

    def __init__(self, config: Config, markdown: str = "# Incident Report\n") -> None:
        self.config = config
        self._markdown = markdown
        self.calls: list[tuple] = []

    def investigate(self, window, filters=None):
        self.calls.append((window, filters))
        return _FakeReport(self._markdown)


def _factory(markdown="# Incident Report\n"):
    """Return (factory, holder) so the test can inspect the built investigator."""
    holder: dict = {}

    def factory(config: Config) -> _FakeInvestigator:
        inv = _FakeInvestigator(config, markdown)
        holder["investigator"] = inv
        return inv

    return factory, holder


def _config_loader(config: Config):
    return lambda: config


def test_main_prints_markdown_to_stdout(capsys):
    factory, holder = _factory("# My Report\nbody")
    code = main(
        ["--start", "2026-09-23T12:00:00Z", "--end", "2026-09-23T13:00:00Z"],
        investigator_factory=factory,
        config_loader=_config_loader(Config()),
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "# My Report" in out
    # Investigator was called once with the parsed window.
    inv = holder["investigator"]
    assert len(inv.calls) == 1
    window, filters = inv.calls[0]
    assert window.start.hour == 12 and window.end.hour == 13
    assert filters == {}


def test_main_saves_to_output_file(tmp_path, capsys):
    out_file = tmp_path / "report.md"
    factory, _ = _factory("# Saved Report\n")
    code = main(
        [
            "--start", "2026-09-23T12:00:00Z",
            "--end", "2026-09-23T13:00:00Z",
            "-o", str(out_file),
        ],
        investigator_factory=factory,
        config_loader=_config_loader(Config()),
    )
    assert code == 0
    assert out_file.read_text(encoding="utf-8") == "# Saved Report\n"
    assert f"report written to {out_file}" in capsys.readouterr().out


def test_main_start_after_end_errors_nonzero(capsys):
    factory, holder = _factory()
    code = main(
        ["--start", "2026-09-23T13:00:00Z", "--end", "2026-09-23T12:00:00Z"],
        investigator_factory=factory,
        config_loader=_config_loader(Config()),
    )
    assert code == 1
    err = capsys.readouterr().err
    assert "error:" in err
    assert "before end" in err
    # Investigator must never be built/called when the window is invalid.
    assert "investigator" not in holder


def test_main_start_equal_end_errors_nonzero(capsys):
    factory, _ = _factory()
    code = main(
        ["--start", "2026-09-23T12:00:00Z", "--end", "2026-09-23T12:00:00Z"],
        investigator_factory=factory,
        config_loader=_config_loader(Config()),
    )
    assert code == 1
    assert "error:" in capsys.readouterr().err


def test_main_no_reasoning_disables_config():
    factory, holder = _factory()
    code = main(
        [
            "--start", "2026-09-23T12:00:00Z",
            "--end", "2026-09-23T13:00:00Z",
            "--no-reasoning",
        ],
        investigator_factory=factory,
        config_loader=_config_loader(Config(reasoning_enabled=True)),
    )
    assert code == 0
    assert holder["investigator"].config.reasoning_enabled is False


def test_main_passes_filters_through():
    factory, holder = _factory()
    main(
        [
            "--start", "2026-09-23T12:00:00Z",
            "--end", "2026-09-23T13:00:00Z",
            "--event-source", "lambda.amazonaws.com",
        ],
        investigator_factory=factory,
        config_loader=_config_loader(Config()),
    )
    _, filters = holder["investigator"].calls[0]
    assert filters == {"EventSource": "lambda.amazonaws.com"}


def test_main_reports_collection_error_cleanly(capsys):
    def factory(config):
        class _Boom:
            def investigate(self, window, filters=None):
                raise ValidationError("unsupported CloudTrail lookup attribute: 'Nope'")

        return _Boom()

    code = main(
        ["--start", "2026-09-23T12:00:00Z", "--end", "2026-09-23T13:00:00Z"],
        investigator_factory=factory,
        config_loader=_config_loader(Config()),
    )
    assert code == 1
    err = capsys.readouterr().err
    assert "error:" in err
    assert "unsupported CloudTrail lookup attribute" in err
