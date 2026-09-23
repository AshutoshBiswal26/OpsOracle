"""Command-line entrypoint: run an investigation over a time window.

Usage:
    python -m opsoracle.cli --start 2026-09-23T12:00:00Z --end 2026-09-23T13:00:00Z \
        [--filter EventSource=lambda.amazonaws.com] [--output report.md] [--no-reasoning]

AWS credentials come from the standard Boto3/IAM chain; nothing is read from arguments.
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone

from .collectors.cloudtrail import CloudTrailCollector
from .config import Config, load_config
from .errors import OpsOracleError
from .investigation.investigator import Investigator
from .models.investigation import TimeWindow
from .reasoning.bedrock import BedrockReasoner


def _parse_ts(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid ISO-8601 timestamp: {value!r}") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _parse_filters(pairs: list[str] | None) -> dict:
    filters: dict[str, str] = {}
    for pair in pairs or []:
        if "=" not in pair:
            raise argparse.ArgumentTypeError(f"filter must be key=value, got {pair!r}")
        key, value = pair.split("=", 1)
        filters[key.strip()] = value.strip()
    return filters


def build_investigator(config: Config) -> Investigator:
    """Construct an Investigator with real boto3 clients (lazy import)."""
    import boto3

    session = boto3.Session(region_name=config.region)
    cloudtrail = session.client("cloudtrail")
    collector = CloudTrailCollector(cloudtrail, max_retries=config.max_retries)

    bedrock_client = None
    if config.reasoning_enabled:
        bedrock_client = session.client("bedrock-runtime")
    reasoner = BedrockReasoner(
        bedrock_client,
        model_id=config.model_id,
        max_tokens=config.max_tokens,
        enabled=config.reasoning_enabled,
    )
    return Investigator(
        config=config, cloudtrail_collector=collector, reasoner=reasoner
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="opsoracle",
        description="Evidence-first AWS incident investigation.",
    )
    parser.add_argument("--start", required=True, type=_parse_ts,
                        help="investigation window start (ISO-8601, UTC)")
    parser.add_argument("--end", required=True, type=_parse_ts,
                        help="investigation window end (ISO-8601, UTC)")
    parser.add_argument("--filter", action="append", metavar="KEY=VALUE",
                        help="CloudTrail lookup filter (repeatable)")
    parser.add_argument("--output", help="write the Markdown report to this file")
    parser.add_argument("--no-reasoning", action="store_true",
                        help="disable the Bedrock reasoning stage")
    parser.add_argument("--verbose", action="store_true", help="enable info logging")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    config = load_config()
    if args.no_reasoning:
        config = Config(
            region=config.region,
            model_id=config.model_id,
            max_events=config.max_events,
            max_tokens=config.max_tokens,
            reasoning_enabled=False,
            max_retries=config.max_retries,
        )

    try:
        window = TimeWindow(start=args.start, end=args.end)
        filters = _parse_filters(args.filter)
        investigator = build_investigator(config)
        report = investigator.investigate(window, filters)
    except OpsOracleError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    markdown = report.to_markdown()
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(markdown)
        print(f"report written to {args.output}")
    else:
        print(markdown)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
