"""Pipeline orchestrator.

Wires the deterministic stages together and then invokes reasoning last:
``collect -> normalize -> timeline -> correlate -> build_context -> reason -> report``.

The reasoner already degrades gracefully on failure, so the report is always produced
from the deterministic evidence even when AI reasoning is unavailable (requirements 7.7,
8.5).
"""

from __future__ import annotations

import logging

from ..collectors.cloudtrail import CloudTrailCollector
from ..config import Config
from ..context.builder import ContextBuilder
from ..correlation.engine import CorrelationEngine
from ..errors import ReasoningError
from ..models.investigation import TimeWindow
from ..models.report import ReasoningResult
from ..normalization.cloudtrail import CloudTrailNormalizer
from ..reasoning.bedrock import BedrockReasoner
from ..reporting.incident_report import IncidentReport, ReportBuilder
from ..timeline.builder import TimelineBuilder

logger = logging.getLogger("opsoracle.investigation")


class Investigator:
    """Runs a full investigation over a time window and returns an IncidentReport."""

    def __init__(
        self,
        *,
        config: Config,
        cloudtrail_collector: CloudTrailCollector,
        reasoner: BedrockReasoner,
        normalizer: CloudTrailNormalizer | None = None,
        timeline_builder: TimelineBuilder | None = None,
        correlation_engine: CorrelationEngine | None = None,
        context_builder: ContextBuilder | None = None,
        report_builder: ReportBuilder | None = None,
    ) -> None:
        self._config = config
        self._collector = cloudtrail_collector
        self._reasoner = reasoner
        self._normalizer = normalizer or CloudTrailNormalizer()
        self._timeline = timeline_builder or TimelineBuilder()
        self._correlator = correlation_engine or CorrelationEngine()
        self._context = context_builder or ContextBuilder(max_events=config.max_events)
        self._report_builder = report_builder or ReportBuilder()

    @classmethod
    def from_config(
        cls,
        config: Config,
        *,
        cloudtrail_client: object | None = None,
        bedrock_client: object | None = None,
    ) -> "Investigator":
        """Build an Investigator with all stages wired from ``config`` defaults.

        The AWS clients are still injectable (``None`` lets each collector/reasoner
        build a default client from the standard credential chain), which keeps this
        convenience constructor testable without live AWS (requirement 11.1).
        """
        collector = CloudTrailCollector(
            cloudtrail_client, region=config.region, max_retries=config.max_retries
        )
        reasoner = BedrockReasoner(
            bedrock_client,
            model_id=config.model_id,
            max_tokens=config.max_tokens,
            enabled=config.reasoning_enabled,
            region=config.region,
        )
        return cls(
            config=config,
            cloudtrail_collector=collector,
            reasoner=reasoner,
        )

    def investigate(
        self, window: TimeWindow, filters: dict | None = None
    ) -> IncidentReport:
        raw = self._collector.collect(window, filters)
        logger.info("collected %d raw CloudTrail records", len(raw))

        events = self._normalizer.normalize(raw)
        if self._normalizer.skipped:
            logger.info("skipped %d unparseable records", len(self._normalizer.skipped))

        ordered = self._timeline.build(events)
        correlations = self._correlator.correlate(ordered)
        investigation = self._context.build(window, ordered, correlations)

        reasoning = self._reason(investigation)
        return self._report_builder.build(investigation, reasoning)

    def investigate_markdown(
        self, window: TimeWindow, filters: dict | None = None
    ) -> str:
        """Run an investigation and return the rendered Markdown report."""
        return self.investigate(window, filters).to_markdown()

    def _reason(self, investigation) -> ReasoningResult:
        """Invoke the reasoning stage, staying resilient to reasoning failures.

        ``BedrockReasoner.reason`` already degrades gracefully, but the orchestrator
        guards the stage as well: any ``ReasoningError`` that surfaces is converted to a
        graceful ``ReasoningResult(ai_available=False, ...)`` so a report still renders
        from the deterministic evidence (requirements 7.7, 8.5).
        """
        try:
            return self._reasoner.reason(investigation)
        except ReasoningError as exc:
            logger.warning("reasoning stage failed; continuing without AI: %s", exc)
            return ReasoningResult.unavailable(f"reasoning unavailable: {exc}")
