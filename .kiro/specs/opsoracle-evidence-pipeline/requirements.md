# Requirements — OpsOracle Evidence-First Investigation Pipeline (MVP)

## Introduction

OpsOracle is an evidence-first, AI-assisted AWS incident investigation system. This
spec covers the **MVP pipeline**: given an AWS investigation window, the system
collects operational evidence, normalizes it into a common model, builds a
chronological timeline, deterministically correlates related signals, assembles a
compact evidence context, and only then uses Amazon Bedrock to produce an
evidence-grounded incident report.

The guiding principle (RULES.md §1) is **evidence before inference**: the AI layer
must never become the primary source of operational facts. Deterministic processing
runs first and answers everything it can; Bedrock is invoked last, over already-collected
evidence, and its output is clearly labeled as inference — never ground truth.

### Scope

**In scope (this spec):**
- CloudTrail management-event collection via Boto3 (first milestone).
- CloudWatch metrics and logs/alarms collection where practical.
- A common `EvidenceEvent` model and normalization from raw AWS responses.
- Timeline construction (chronological + resource/service grouping).
- Deterministic correlation engine with explainable correlations.
- Investigation context assembly (evidence window + ranked, traceable evidence).
- Bedrock reasoning that produces a structured, evidence-referenced report.
- Human-readable incident report rendering.
- Cross-cutting concerns: credential safety, cost control, auditability, testing.

**Out of scope (deferred to later specs / stretch, per README.md):**
- Autonomous EventBridge-triggered detection and the ReAct agent loop.
- Strands Agents SDK orchestration and MCP servers (CloudWatch MCP, Application
  Signals MCP, custom change-correlation MCP).
- Confidence-scoring model and the golden-set eval harness.
- Auto-remediation.
- Cloud deployment (Lambda/Fargate), persistence, and dashboards.

These are acknowledged so nothing from the README PRD is lost; they build on top of
the deterministic pipeline defined here.

### Glossary

- **Evidence window** — the `[start, end]` time range under investigation.
- **EvidenceEvent** — the normalized internal representation of a single AWS signal.
- **Correlation** — a deterministic, explainable relationship between two or more
  evidence events (e.g., temporal proximity, shared resource).
- **Investigation context** — the compact, ranked bundle of evidence handed to Bedrock.
- **Candidate cause** — a possible contributing factor, always backed by evidence IDs.

---

## Requirements

### Requirement 1 — CloudTrail evidence collection

**User story:** As an engineer investigating an incident, I want the system to
retrieve CloudTrail management events for a given time window, so that I have the
API-activity evidence needed to understand what changed.

#### Acceptance Criteria

1. WHEN the collector is given a start time and end time THEN the system SHALL
   retrieve CloudTrail management events within that window using Boto3 `lookup_events`.
2. WHEN CloudTrail returns paginated results THEN the system SHALL follow pagination
   until all events in the window are retrieved.
3. WHEN an optional lookup filter (e.g., EventName, EventSource, resource) is provided
   THEN the system SHALL apply it to the CloudTrail query.
4. IF the start time is not before the end time THEN the system SHALL reject the
   request with a validation error before making any AWS call.
5. WHEN AWS returns a throttling or transient error THEN the system SHALL retry with
   exponential backoff up to a configured limit before failing.
6. WHEN a non-retryable AWS error occurs (e.g., access denied) THEN the system SHALL
   raise a clear, typed error identifying the source and cause without leaking credentials.
7. WHEN collection succeeds THEN the system SHALL return the raw events unmodified,
   preserving the original AWS response payload for later reference.

### Requirement 2 — Evidence model

**User story:** As a developer of the pipeline, I want a common evidence model, so
that heterogeneous AWS signals can flow through timeline, correlation, and reasoning
uniformly.

#### Acceptance Criteria

1. The system SHALL define an `EvidenceEvent` type that includes at minimum: a stable
   evidence ID, source (enum/constant), event type, UTC timestamp, actor, affected
   resources, region, account, a human-readable summary, and a reference to the raw event.
2. WHEN an `EvidenceEvent` is created THEN the system SHALL assign a stable, unique
   evidence ID usable for traceability in correlations and the final report.
3. The system SHALL support serialization of an `EvidenceEvent` to and from a
   dictionary/JSON form without loss of the fields above.
4. WHEN a required field is missing or invalid at construction THEN the system SHALL
   raise a validation error rather than produce a partially-formed event.
5. The system SHALL define the evidence source as a closed set of constants (e.g.,
   `CLOUDTRAIL`, `CLOUDWATCH_METRIC`, `CLOUDWATCH_LOG`, `CLOUDWATCH_ALARM`).

### Requirement 3 — CloudTrail normalization

**User story:** As a developer, I want raw CloudTrail records converted into
`EvidenceEvent`s, so that downstream components never depend on raw AWS response shapes.

#### Acceptance Criteria

1. WHEN a raw CloudTrail record is normalized THEN the system SHALL extract the event
   timestamp as a timezone-aware UTC datetime.
2. WHEN normalizing THEN the system SHALL extract event source, event name, actor
   identity, affected resources, region, and account into the `EvidenceEvent`.
3. WHEN detail exists only inside the nested `CloudTrailEvent` JSON THEN the system
   SHALL parse it and preserve useful metadata not present in the top-level record.
4. IF a CloudTrail record is missing expected fields THEN the system SHALL still
   produce a valid `EvidenceEvent`, leaving unavailable fields explicitly empty/None
   rather than failing the whole batch.
5. WHEN normalization completes THEN each produced `EvidenceEvent` SHALL retain a
   reference to its originating raw record.

### Requirement 4 — Timeline construction

**User story:** As an engineer, I want evidence arranged chronologically and grouped
by resource and service, so that I can see what happened and in what order.

#### Acceptance Criteria

1. WHEN given a set of `EvidenceEvent`s THEN the system SHALL order them ascending by
   timestamp.
2. WHEN two events share an identical timestamp THEN the system SHALL apply a stable,
   deterministic secondary ordering (e.g., by evidence ID).
3. The system SHALL provide a grouping of the timeline by affected resource.
4. The system SHALL provide a grouping of the timeline by service/source.
5. WHEN the timeline is produced THEN each entry SHALL expose its evidence ID for
   traceability.

### Requirement 5 — Correlation engine

**User story:** As an engineer, I want the system to surface deterministic
relationships between events, so that I can spot change-before-failure patterns without
manual cross-referencing.

#### Acceptance Criteria

1. The system SHALL detect temporal-proximity correlations between events that occur
   within a configurable time window of each other.
2. The system SHALL detect shared-resource correlations between events referencing the
   same resource.
3. The system SHALL detect change-before-failure patterns where a change/API event
   precedes a failure/degradation signal within a configured window.
4. WHEN a correlation is created THEN the system SHALL produce a correlation object
   that references the participating evidence IDs and a human-readable explanation.
5. The system SHALL NOT present a correlation as confirmed causality; correlation
   descriptions SHALL use qualified language (e.g., "preceded", "correlated with",
   "candidate cause") per RULES.md §4.
6. WHEN no correlations are found THEN the system SHALL return an empty result without
   error.

### Requirement 6 — Investigation context assembly

**User story:** As a developer of the AI layer, I want a compact, ranked evidence
context, so that Bedrock receives only relevant, traceable evidence within token limits.

#### Acceptance Criteria

1. The system SHALL define an investigation object that captures the evidence window,
   the selected evidence events, and the detected correlations.
2. WHEN assembling context THEN the system SHALL rank evidence by relevance (e.g.,
   participation in correlations, proximity to the incident window).
3. WHEN the evidence volume exceeds a configured context budget THEN the system SHALL
   include the highest-ranked evidence and record that truncation occurred.
4. Every item placed in the context SHALL retain its evidence ID so the report can
   trace claims back to specific evidence.

### Requirement 7 — Bedrock reasoning

**User story:** As an engineer, I want AI-assisted reasoning over the assembled
evidence, so that I get probable contributing factors and next steps grounded in the
evidence I collected.

#### Acceptance Criteria

1. WHEN deterministic processing can answer the question THEN the system SHALL NOT
   invoke Bedrock (RULES.md §8, cost).
2. WHEN Bedrock is invoked THEN the system SHALL send only the assembled investigation
   context and a defined prompt contract, and SHALL request structured (JSON) output.
3. WHEN Bedrock returns output THEN the system SHALL validate it against the expected
   schema and reject/repair malformed output rather than passing it downstream.
4. The reasoning output SHALL include: probable contributing factors, supporting
   evidence references, stated uncertainty, and recommended next actions.
5. WHEN the model references a fact THEN the system SHALL require that reference to map
   to a supplied evidence ID; unreferenced factual claims SHALL be flagged or dropped.
6. IF the evidence is insufficient THEN the system SHALL allow and preserve an
   "insufficient evidence / unknown" conclusion rather than forcing a root cause.
7. WHEN the Bedrock call fails or times out THEN the system SHALL degrade gracefully
   and still produce a report from the deterministic evidence, noting AI reasoning was
   unavailable.
8. The system SHALL authenticate to Bedrock via IAM (no hard-coded credentials) and
   SHALL NOT include secrets or raw credentials in prompts.

### Requirement 8 — Incident report

**User story:** As an engineer, I want a human-readable incident report, so that I can
share and act on the investigation output.

#### Acceptance Criteria

1. The system SHALL define a report schema containing: summary, timeline, candidate
   causes, uncertainty, and recommended next actions.
2. WHEN rendering THEN the system SHALL produce a human-readable (Markdown) report.
3. Every candidate cause and factual claim in the report SHALL cite the evidence
   ID(s) supporting it.
4. The report SHALL visually distinguish observed evidence from inferred conclusions.
5. WHEN AI reasoning was unavailable THEN the report SHALL still render the
   deterministic timeline and correlations, clearly noting the AI section is absent.

### Requirement 9 — Credential and data safety (cross-cutting)

**User story:** As the project owner, I want the system to follow AWS security hygiene,
so that no credentials or sensitive data are exposed or committed.

#### Acceptance Criteria

1. The system SHALL use Boto3's default credential chain / IAM and SHALL NOT hard-code
   AWS credentials.
2. The system SHALL read configuration (e.g., region, profile, model ID) from
   environment/config, documented via `.env.example`, and SHALL NOT commit `.env`.
3. WHEN errors are logged or surfaced THEN the system SHALL NOT echo credentials,
   tokens, or secret values.
4. The system SHALL request only least-privilege, read-only AWS permissions for
   collection in the MVP.

### Requirement 10 — Cost control (cross-cutting)

**User story:** As the project owner, I want expensive operations bounded and measured,
so that investigations stay cheap.

#### Acceptance Criteria

1. The system SHALL avoid unnecessary AWS API calls and SHALL not collect unbounded
   telemetry volumes for the MVP.
2. The system SHALL enforce a configurable context/token budget before invoking Bedrock.
3. The system SHALL make Bedrock invocation measurable (e.g., log token usage / call
   counts per investigation).

### Requirement 11 — Testing and auditability (cross-cutting)

**User story:** As a developer, I want core logic covered by tests using mocked AWS
responses, so that the pipeline is verifiable without live AWS calls.

#### Acceptance Criteria

1. The system SHALL provide unit tests for collectors using mocked AWS responses (no
   live calls in the test suite).
2. The system SHALL provide tests covering: normalization of incomplete/malformed
   events, timeline ordering, correlation logic, malformed LLM output, duplicate
   events, and API-failure handling.
3. Every claim in the final report SHALL be traceable to a specific evidence event and
   (where applicable) the tool/collector that produced it.
