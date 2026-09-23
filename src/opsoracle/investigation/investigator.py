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
from ..models.investigation import TimeWindow
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

        reasoning = self._reasoner.reason(investigation)
        return self._report_builder.build(investigation, reasoning)
