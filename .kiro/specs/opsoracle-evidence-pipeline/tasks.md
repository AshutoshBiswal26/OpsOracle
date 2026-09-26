# Implementation Plan — OpsOracle Evidence-First Investigation Pipeline (MVP)

Each task is incremental and test-backed. Tasks build in dependency order: foundation →
model → collect → normalize → timeline → correlate → context → reason → report →
orchestrate. Requirement references point back to `requirements.md`. All AWS tests use
mocked clients — no live calls (Req 11.1).

- [x] 1. Project foundation and package scaffolding
  - Create the `src/opsoracle/` package tree from the design's module layout (empty
    modules with docstrings): `collectors/`, `models/`, `normalization/`, `timeline/`,
    `correlation/`, `context/`, `reasoning/`, `reporting/`, `investigation/`.
  - Add `.gitignore` (ignore `.env`, `.venv`, `__pycache__`, build artifacts) and
    `.env.example` documenting `OPSORACLE_AWS_REGION`, `AWS_PROFILE`, `OPSORACLE_MODEL_ID`,
    budgets, and flags.
  - Populate `requirements.txt` (boto3, pytest; botocore for stubbing) with pinned versions.
  - Create `tests/` mirror structure with `__init__.py` files.
  - _Requirements: 9.2, 11.1_

- [x] 2. Configuration and typed error hierarchy
  - [x] 2.1 Implement `config.py` loading settings from environment with defaults from
    the design's config table; never read or store secret values.
    - _Requirements: 9.1, 9.2, 10.2_
  - [x] 2.2 Implement `errors.py` with the `OpsOracleError` hierarchy (`ConfigError`,
    `ValidationError`, `CollectionError` + `ThrottlingError`/`AccessError`,
    `NormalizationError`, `ReasoningError`); ensure messages never include credentials.
    - _Requirements: 1.6, 2.4, 9.3_

- [x] 3. Evidence model
  - [x] 3.1 Implement `models/evidence.py`: `EvidenceSource`, `ResourceRef`, `Actor`,
    `EvidenceEvent` with the deterministic content-derived `evidence_id`, plus
    `to_dict`/`from_dict`.
    - _Requirements: 2.1, 2.2, 2.3, 2.5_
  - [x] 3.2 Add construction validation that raises `ValidationError` on missing/invalid
    required fields.
    - _Requirements: 2.4_
  - [x] 3.3 Write tests: to_dict/from_dict round-trip, ID stability/determinism, and
    validation-error cases.
    - _Requirements: 2.1, 2.2, 2.4_

- [x] 4. Supporting models (correlation, investigation, report)
  - Implement `models/correlation.py` (`CorrelationType`, `Correlation`),
    `models/investigation.py` (`TimeWindow`, `Investigation`), and `models/report.py`
    (`CandidateCause`, `ReasoningResult`, `IncidentReport` shell with `to_markdown` stub).
  - Add `TimeWindow` validation (start < end) raising `ValidationError`.
  - _Requirements: 1.4, 5.4, 6.1, 8.1_

- [x] 5. Collector base + CloudTrail collector
  - [x] 5.1 Implement `collectors/base.py`: `Collector` protocol and shared
    pagination/retry-with-backoff helpers bounded by the configured retry limit.
    - _Requirements: 1.2, 1.5_
  - [x] 5.2 Implement `collectors/cloudtrail.py` `CloudTrailCollector` with injectable
    client: window validation, `LookupAttributes` from optional filters, paginated
    `lookup_events`, throttling retry, non-retryable→typed error, raw events returned
    unmodified.
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7_
  - [x] 5.3 Write tests with mocked client: multi-page pagination; throttling→retry→
    success; access-denied→`AccessError`; start≥end→`ValidationError`; raw payload unchanged.
    - _Requirements: 1.2, 1.4, 1.5, 1.6, 1.7, 11.1_

- [x] 6. CloudTrail normalization
  - [x] 6.1 Implement `normalization/base.py` `Normalizer` protocol and
    `normalization/cloudtrail.py` `CloudTrailNormalizer`: extract tz-aware UTC timestamp,
    event source/name, actor, resources, region, account; parse nested `CloudTrailEvent`
    detail; attach `raw_ref`.
    - _Requirements: 3.1, 3.2, 3.3, 3.5_
  - [x] 6.2 Make per-record normalization tolerant: missing optional fields become
    empty/None; unrecoverable records are skipped with a reason, batch continues.
    - _Requirements: 3.4_
  - [x] 6.3 Write tests: full record; record with missing fields; nested-detail
    extraction; raw_ref preserved; malformed record skipped without aborting batch.
    - _Requirements: 3.1, 3.3, 3.4, 3.5, 11.2_

- [x] 7. Timeline builder
  - Implement `timeline/builder.py` `TimelineBuilder`: ascending sort by
    `(timestamp, evidence_id)`, plus `group_by_resource` and `group_by_service`.
  - Write tests: ordering, identical-timestamp stable tiebreak, both groupings.
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5_

- [x] 8. Correlation engine
  - [x] 8.1 Implement `correlation/engine.py` `CorrelationEngine` with configurable
    windows and the three rules (temporal proximity, shared resource,
    change-before-failure), each emitting `Correlation` with participating evidence IDs
    and qualified-language explanations; empty result when none found.
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6_
  - [x] 8.2 Add the auditable change/failure classification lookup used by the
    change-before-failure rule.
    - _Requirements: 5.3, 5.5_
  - [x] 8.3 Write tests: proximity in/out of window; shared-resource; ordered
    change→failure; no-correlation empty result; explanations avoid causal language.
    - _Requirements: 5.1, 5.2, 5.3, 5.5, 5.6_

- [x] 9. Investigation context builder
  - Implement `context/builder.py` `ContextBuilder`: rank evidence (correlated first,
    then proximity to window), enforce `max_events` budget, set `truncated=True` when
    dropping evidence, preserve evidence IDs; return `Investigation`.
  - Write tests: ranking prioritizes correlated events; budget truncation flag.
  - _Requirements: 6.1, 6.2, 6.3, 6.4, 10.2_

- [x] 10. Bedrock reasoning
  - [x] 10.1 Implement `reasoning/prompt.py` (prompt contract encoding RULES.md §7 and
    compact context serialization with evidence IDs) and `reasoning/schema.py` (expected
    JSON schema + validation).
    - _Requirements: 7.2, 7.4, 7.5_
  - [x] 10.2 Implement `reasoning/bedrock.py` `BedrockReasoner` with injectable
    `bedrock-runtime` client: skip when nothing to ask or reasoning disabled; invoke with
    token cap; validate/repair JSON; drop unreferenced claims; preserve
    insufficient-evidence result; IAM auth, no secrets in prompt.
    - _Requirements: 7.1, 7.2, 7.3, 7.5, 7.6, 7.8, 10.2, 10.3_
  - [x] 10.3 Implement graceful fallback: any Bedrock/parse failure returns
    `ReasoningResult(ai_available=False, ...)`.
    - _Requirements: 7.7_
  - [x] 10.4 Write tests with mocked client: malformed JSON handled; unknown-evidence-id
    claim dropped; exception→ai_available=False; insufficient-evidence preserved; token
    usage logged.
    - _Requirements: 7.3, 7.5, 7.6, 7.7, 10.3, 11.1_

- [x] 11. Incident report builder and renderer
  - Implement `reporting/incident_report.py` `ReportBuilder` and `IncidentReport.to_markdown`:
    schema with summary/timeline/correlations/candidate-causes/uncertainty/next-actions;
    Observed vs Inferred sections; evidence-ID citations on every claim; AI-unavailable note.
  - Write tests: observed/inferred separation; candidate causes cite evidence IDs;
    AI-unavailable note rendered when `ai_available` is False.
  - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5_

- [x] 12. Investigation orchestrator and CLI
  - [x] 12.1 Implement `investigation/investigator.py` wiring
    collect→normalize→timeline→correlate→build_context→reason→report, catching
    `ReasoningError` into graceful fallback.
    - _Requirements: 7.7, 8.5_
  - [x] 12.2 Implement `cli.py` to run an investigation over a `--start`/`--end` window
    (optional filters) and print/save the Markdown report; wire config.
    - _Requirements: 1.1, 8.2, 9.2_
  - [x] 12.3 Write an end-to-end test with all AWS clients mocked: canned CloudTrail
    fixtures → rendered Markdown report, asserting evidence traceability end-to-end.
    - _Requirements: 11.1, 11.3_

- [x] 13. Cross-cutting verification pass
  - Add tests for duplicate-event deduplication via deterministic IDs and confirm no
    secret values appear in any error string.
  - Run the full suite offline; confirm every report claim traces to an evidence event.
  - _Requirements: 11.2, 11.3, 9.3_

---

## Deferred (future specs, not part of this MVP)

Tracked so the README's agentic vision is not lost:

- CloudWatch metrics/logs/alarms collectors + multi-source timeline merge (TASKS.md Phase 7).
- EventBridge-triggered detection + ReAct agent loop.
- Strands Agents SDK orchestration; CloudWatch MCP, Application Signals MCP, and a custom
  change-correlation MCP server.
- Numeric confidence-scoring model and golden-set eval harness.
- Human-approved auto-remediation.
- AWS deployment (Lambda/Fargate), report persistence in S3, cost dashboard.
