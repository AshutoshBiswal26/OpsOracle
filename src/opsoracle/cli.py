"""Command-line entrypoint: run an investigation over a time window.

Usage::

    python -m opsoracle.cli --start 2026-09-23T12:00:00Z --end 2026-09-23T13:00:00Z \
        [--event-source lambda.amazonaws.com] [--event-name Invoke] \
        [--filter Username=alice] [--output report.md] [--no-reasoning]

AWS credentials come from the standard Boto3/IAM chain; nothing is read from arguments
and no credential material is ever printed (requirement 9.2).
"""

from __future__ import annotations

import argparse
import dataclasses
import logging
import sys
from datetime import datetime, timezone
from typing import Callable

from .config import Config, load_config
from .errors import OpsOracleError
from .investigation.investigator import Investigator
from .models.investigation import TimeWindow

logger = logging.getLogger("opsoracle.cli")

# A factory takes a Config and returns a ready-to-run Investigator. Injectable so tests
# can supply an Investigator wired with mocked AWS clients (no live AWS, requirement 11.1).
InvestigatorFactory = Callable[[Config], Investigator]

# Convenience flags mapped to their CloudTrail LookupAttribute keys.
_CONVENIENCE_FILTERS = {
    "event_name": "EventName",
    "event_source": "EventSource",
}


def _parse_ts(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid ISO-8601 timestamp: {value!r}") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _parse_filters(pairs: list[str] | None) -> dict:
    """Parse repeated ``KEY=VALUE`` strings into a filter mapping."""
    filters: dict[str, str] = {}
    for pair in pairs or []:
        if "=" not in pair:
            raise argparse.ArgumentTypeError(f"filter must be key=value, got {pair!r}")
        key, value = pair.split("=", 1)
        key, value = key.strip(), value.strip()
        if not key:
            raise argparse.ArgumentTypeError(f"filter must be key=value, got {pair!r}")
        filters[key] = value
    return filters


def collect_filters(args: argparse.Namespace) -> dict:
    """Merge convenience filters (--event-name/--event-source) with generic --filter.

    Explicit ``--filter KEY=VALUE`` entries take precedence over the convenience flags
    when both target the same attribute.
    """
    filters: dict[str, str] = {}
    for attr, key in _CONVENIENCE_FILTERS.items():
        value = getattr(args, attr, None)
        if value:
            filters[key] = value
    filters.update(_parse_filters(args.filter))
    return filters


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="opsoracle",
        description="Evidence-first AWS incident investigation.",
    )
    parser.add_argument("--start", required=True, type=_parse_ts,
                        help="investigation window start (ISO-8601, UTC)")
    parser.add_argument("--end", required=True, type=_parse_ts,
                        help="investigation window end (ISO-8601, UTC)")
    parser.add_argument("--event-name", dest="event_name", metavar="NAME",
                        help="filter to a CloudTrail EventName")
    parser.add_argument("--event-source", dest="event_source", metavar="SOURCE",
                        help="filter to a CloudTrail EventSource, e.g. lambda.amazonaws.com")
    parser.add_argument("--filter", action="append", metavar="KEY=VALUE",
                        help="generic CloudTrail lookup filter (repeatable)")
    parser.add_argument("-o", "--output", metavar="PATH",
                        help="write the Markdown report to this file")
    parser.add_argument("--no-reasoning", action="store_true",
                        help="disable the Bedrock reasoning stage")
    parser.add_argument("--verbose", action="store_true", help="enable info logging")
    return parser


def main(
    argv: list[str] | None = None,
    *,
    investigator_factory: InvestigatorFactory | None = None,
    config_loader: Callable[[], Config] = load_config,
) -> int:
    """Run an investigation from CLI arguments and return a process exit code.

    ``investigator_factory`` and ``config_loader`` are injectable so tests can drive
    ``main`` end-to-end with mocked AWS clients (requirement 11.1). Production defaults
    build an :class:`Investigator` from config via :meth:`Investigator.from_config`.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    factory = investigator_factory or Investigator.from_config

    try:
        config = config_loader()
        if args.no_reasoning:
            config = dataclasses.replace(config, reasoning_enabled=False)

        # Validate the window first so start >= end fails fast with a clear message
        # (requirement 1.1) before any AWS client is constructed.
        window = TimeWindow(start=args.start, end=args.end)
        filters = collect_filters(args)

        investigator = factory(config)
        report = investigator.investigate(window, filters)
        markdown = report.to_markdown()
    except OpsOracleError as exc:
        # Typed errors already have credential material scrubbed (see errors.py).
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(markdown)
        except OSError as exc:
            print(f"error: could not write report to {args.output}: {exc}",
                  file=sys.stderr)
            return 1
        print(f"report written to {args.output}")
    else:
        print(markdown)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
