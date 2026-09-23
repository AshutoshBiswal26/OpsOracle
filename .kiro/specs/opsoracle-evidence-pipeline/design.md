# Design — OpsOracle Evidence-First Investigation Pipeline (MVP)

## Overview

This document translates the requirements into a concrete technical design for the
OpsOracle MVP: a deterministic, evidence-first pipeline that collects AWS evidence,
normalizes it, builds a timeline, correlates signals, assembles a compact context, and
finally invokes Amazon Bedrock for evidence-grounded reasoning before rendering a report.

The design is intentionally **modular** (DESIGN.md §1): collection, normalization,
timeline, correlation, and reasoning can each evolve independently. Every stage speaks
the common `EvidenceEvent` model so no downstream component depends on raw AWS shapes.

### Design principles (from RULES.md)

- **Evidence before inference.** Deterministic stages run first; Bedrock runs last, over
  already-collected evidence, and its output is labeled inference, not fact.
- **Traceability.** Every evidence item has a stable ID; every correlation and every
  report claim references those IDs.
- **Collectors independent from reasoning.** AWS integration is isolated from business
  logic; reasoning never calls AWS directly.
- **Cost discipline.** No unbounded telemetry; no Bedrock call when deterministic logic
  suffices; token/context budget enforced.
- **Graceful degradation.** A failed tool call or failed Bedrock call is recorded, not
  fatal; the report still renders from deterministic evidence.

## Architecture

```text
                 investigation window [start, end] (+ optional filters)
                                    │
                                    ▼
                        ┌───────────────────────┐
                        │ Collectors             │  Boto3, per-source, independent
                        │  CloudTrailCollector   │  → raw AWS payloads (RawRecord[])
                        │  CloudWatch* (later)   │
                        └───────────┬───────────┘
                                    ▼
                        ┌───────────────────────┐
                        │ Normalizers            │  raw → EvidenceEvent[]
                        │  cloudtrail normalizer │  tolerant of missing fields
                        └───────────┬───────────┘
                                    ▼
                        ┌───────────────────────┐
                        │ TimelineBuilder        │  sort + group (resource/service)
                        └───────────┬───────────┘
                                    ▼
                        ┌───────────────────────┐
                        │ CorrelationEngine      │  rules → Correlation[] (explained)
                        │  temporal / shared-res │
                        │  change-before-failure │
                        └───────────┬───────────┘
                                    ▼
                        ┌───────────────────────┐
                        │ ContextBuilder         │  rank + budget → Investigation
                        └───────────┬───────────┘
                                    ▼
                        ┌───────────────────────┐
                        │ BedrockReasoner        │  invoke iff needed; validate JSON
                        │  (graceful fallback)   │  → ReasoningResult
                        └───────────┬───────────┘
                                    ▼
                        ┌───────────────────────┐
                        │ ReportBuilder/Renderer │  → IncidentReport → Markdown
                        └───────────────────────┘
```

### Orchestration

A thin `Investigator` orchestrator (in `src/opsoracle/investigation/`) wires the stages:
`collect → normalize → build_timeline → correlate → build_context → reason → report`.
Each stage is a pure-ish function/class with explicit inputs and outputs, which keeps the
pipeline testable stage-by-stage and lets the CLI (or a future Lambda handler) call it
uniformly.

### Module layout (extends DESIGN.md §2)

```text
src/opsoracle/
├── config.py                 # settings: region, profile, model id, budgets
├── errors.py                 # typed error hierarchy
├── models/
│   ├── evidence.py           # EvidenceEvent, EvidenceSource, Actor, ResourceRef
│   ├── correlation.py        # Correlation, CorrelationType
│   ├── investigation.py      # Investigation, TimeWindow
│   └── report.py             # IncidentReport, CandidateCause, ReasoningResult
├── collectors/
│   ├── base.py               # Collector protocol + retry/pagination helpers
│   ├── cloudtrail.py         # CloudTrailCollector
│   └── cloudwatch.py         # metrics/logs/alarms collectors (later phase)
├── normalization/
│   ├── base.py               # Normalizer protocol
│   └── cloudtrail.py         # raw CloudTrail record → EvidenceEvent
├── timeline/
│   └── builder.py            # TimelineBuilder
├── correlation/
│   └── engine.py             # CorrelationEngine + rules
├── context/
│   └── builder.py            # ContextBuilder (ranking + budget)
├── reasoning/
│   ├── bedrock.py            # BedrockReasoner
│   ├── prompt.py             # prompt contract / templates
│   └── schema.py             # expected LLM JSON schema + validation
├── reporting/
│   └── incident_report.py    # ReportBuilder + Markdown renderer
├── investigation/
│   └── investigator.py       # orchestrator
└── cli.py                    # entrypoint: run an investigation over a window
```

## Components and Interfaces

Interfaces below are shown as Python signatures/dataclasses to fix contracts. Types are
illustrative; implementation may use `pydantic` or `dataclasses` (see Decisions).

### Data models (`models/`)

```python
class EvidenceSource(str, Enum):
    CLOUDTRAIL = "cloudtrail"
    CLOUDWATCH_METRIC = "cloudwatch_metric"
    CLOUDWATCH_LOG = "cloudwatch_log"
    CLOUDWATCH_ALARM = "cloudwatch_alarm"

@dataclass(frozen=True)
class ResourceRef:
    type: str | None          # e.g. "AWS::Lambda::Function"
    name: str | None          # e.g. function name / ARN tail
    arn: str | None = None

@dataclass(frozen=True)
class Actor:
    type: str | None          # IAMUser, AssumedRole, AWSService, ...
    principal_id: str | None
    arn: str | None
    account: str | None

@dataclass(frozen=True)
class EvidenceEvent:
    evidence_id: str          # stable, unique (see ID strategy)
    source: EvidenceSource
    event_type: str           # e.g. CloudTrail EventName
    timestamp: datetime       # tz-aware UTC
    actor: Actor | None
    resources: list[ResourceRef]
    region: str | None
    account: str | None
    summary: str              # short human-readable line
    metadata: dict            # extra normalized fields
    raw_ref: dict             # original raw record (or pointer to it)

    def to_dict(self) -> dict: ...
    @classmethod
    def from_dict(cls, d: dict) -> "EvidenceEvent": ...
```

**Evidence ID strategy:** deterministic and content-derived so the same input always
yields the same ID (stable across re-runs, aids dedup and test assertions):
`evidence_id = f"{source}-{sha1(source|event_type|timestamp_iso|primary_resource|actor)[:12]}"`.
Deterministic IDs also satisfy Req 2.2 and the duplicate-event test (Req 11.2).

```python
class CorrelationType(str, Enum):
    TEMPORAL_PROXIMITY = "temporal_proximity"
    SHARED_RESOURCE = "shared_resource"
    CHANGE_BEFORE_FAILURE = "change_before_failure"

@dataclass(frozen=True)
class Correlation:
    correlation_id: str
    type: CorrelationType
    evidence_ids: list[str]        # participating evidence
    explanation: str               # qualified language only
    strength: float | None = None  # 0..1 heuristic (NOT causal proof)

@dataclass(frozen=True)
class TimeWindow:
    start: datetime                # tz-aware UTC
    end: datetime

@dataclass
class Investigation:
    window: TimeWindow
    events: list[EvidenceEvent]
    correlations: list[Correlation]
    truncated: bool = False        # set if context budget dropped evidence
```

```python
@dataclass(frozen=True)
class CandidateCause:
    description: str               # qualified: "candidate cause", "possible contributor"
    evidence_ids: list[str]
    confidence: str                # low | medium | high (qualitative in MVP)

@dataclass(frozen=True)
class ReasoningResult:
    contributing_factors: list[CandidateCause]
    uncertainty: str
    next_actions: list[str]
    ai_available: bool             # False if Bedrock failed/skipped
    notes: str | None = None

@dataclass(frozen=True)
class IncidentReport:
    window: TimeWindow
    summary: str
    timeline: list[EvidenceEvent]
    correlations: list[Correlation]
    reasoning: ReasoningResult
    def to_markdown(self) -> str: ...
```

### Collectors (`collectors/`)

```python
class Collector(Protocol):
    def collect(self, window: TimeWindow, filters: dict | None = None) -> list[dict]:
        """Return raw AWS records for the window. No normalization here."""

class CloudTrailCollector:
    def __init__(self, client=None, *, region: str | None = None,
                 max_retries: int = 5): ...
    def collect(self, window: TimeWindow, filters: dict | None = None) -> list[dict]:
        # 1. validate window (start < end)  -> Req 1.4
        # 2. build LookupAttributes from filters (EventName/EventSource/Resource) -> Req 1.3
        # 3. paginate lookup_events over [start, end] -> Req 1.2
        # 4. retry throttling/transient with backoff -> Req 1.5
        # 5. map non-retryable AWS errors to typed errors -> Req 1.6
        # 6. return raw events unmodified -> Req 1.7
```

- Uses a Boto3 paginator (`get_paginator("lookup_events")`) to guarantee full pagination.
- Retry/backoff via Botocore's standard retry mode plus an explicit wrapper for
  `ThrottlingException`/`RequestLimitExceeded` to keep behavior testable and bounded.
- The client is injectable so tests pass a mocked/stubbed client (Req 11.1).

### Normalization (`normalization/`)

```python
class Normalizer(Protocol):
    def normalize(self, raw_records: list[dict]) -> list[EvidenceEvent]: ...

class CloudTrailNormalizer:
    def normalize(self, raw_records): ...
    def _normalize_one(self, record: dict) -> EvidenceEvent:
        # parse top-level (EventTime, EventName, EventSource, Username, Resources)
        # parse nested json.loads(record["CloudTrailEvent"]) for detail  -> Req 3.3
        # tolerate missing fields -> Req 3.4 (empty/None, never crash the batch)
        # attach raw_ref -> Req 3.5
```

Missing-field tolerance: `_normalize_one` never raises on absent optional fields; a
record that cannot yield even a timestamp is collected into a `skipped` list with a
reason (surfaced in logs/metadata) rather than aborting the batch.

### Timeline (`timeline/builder.py`)

```python
class TimelineBuilder:
    def build(self, events: list[EvidenceEvent]) -> list[EvidenceEvent]:
        # sort by (timestamp, evidence_id) -> Req 4.1, 4.2 (stable tiebreak)
    def group_by_resource(self, events) -> dict[str, list[EvidenceEvent]]: ...  # Req 4.3
    def group_by_service(self, events) -> dict[EvidenceSource, list[EvidenceEvent]]: ...  # Req 4.4
```

### Correlation (`correlation/engine.py`)

```python
class CorrelationEngine:
    def __init__(self, *, proximity_window: timedelta = timedelta(minutes=5),
                 change_before_failure_window: timedelta = timedelta(minutes=15)): ...
    def correlate(self, events: list[EvidenceEvent]) -> list[Correlation]:
        # apply each rule; merge; dedup; return [] if none -> Req 5.6
    # rules:
    def _temporal_proximity(self, events) -> list[Correlation]: ...          # Req 5.1
    def _shared_resource(self, events) -> list[Correlation]: ...             # Req 5.2
    def _change_before_failure(self, events) -> list[Correlation]: ...       # Req 5.3
```

- Each rule emits `Correlation` objects carrying the participating `evidence_ids` and an
  `explanation` using only qualified language ("preceded", "correlated with",
  "candidate cause") — never "caused" (Req 5.4, 5.5).
- "Change" vs "failure" classification uses a small, auditable lookup (e.g., mutating
  CloudTrail event names / error result codes) so labels are explainable, not black-box.

### Context builder (`context/builder.py`)

```python
class ContextBuilder:
    def __init__(self, *, max_events: int = 50): ...
    def build(self, window, events, correlations) -> Investigation:
        # rank: events in correlations first, then proximity to window center -> Req 6.2
        # apply budget; set truncated=True if dropped -> Req 6.3
        # preserve evidence_ids -> Req 6.4
```

### Reasoning (`reasoning/`)

```python
class BedrockReasoner:
    def __init__(self, client=None, *, model_id: str, max_tokens: int,
                 enabled: bool = True): ...
    def reason(self, investigation: Investigation) -> ReasoningResult:
        # gate: if nothing worth asking (no events) -> skip Bedrock -> Req 7.1
        # build prompt from context only (no secrets) -> Req 7.2, 7.8
        # invoke Bedrock; request JSON -> Req 7.2
        # validate against schema; repair/reject malformed -> Req 7.3
        # drop/flag claims whose evidence_ids not in context -> Req 7.5
        # on failure/timeout -> ReasoningResult(ai_available=False, ...) -> Req 7.7
```

- `prompt.py` holds the prompt contract: system instructions encoding RULES.md §7 (do
  not invent evidence/timestamps/events; reference evidence IDs; may say "insufficient
  evidence"). The context is serialized compactly (evidence lines with IDs + correlations).
- `schema.py` defines the expected JSON and validates it; unreferenced factual claims are
  filtered against the set of supplied evidence IDs (Req 7.5). An "insufficient evidence"
  result is a first-class, valid output (Req 7.6).
- Bedrock auth is IAM via Boto3 `bedrock-runtime`; no keys in code (Req 7.8, 9.1).

### Reporting (`reporting/incident_report.py`)

```python
class ReportBuilder:
    def build(self, investigation: Investigation, reasoning: ReasoningResult)
        -> IncidentReport: ...   # Req 8.1
# IncidentReport.to_markdown():
#   - Summary
#   - Observed Timeline (evidence, each with its ID)              [OBSERVED]
#   - Correlations (qualified explanations, evidence IDs)         [OBSERVED]
#   - AI Reasoning: candidate causes / uncertainty / next actions [INFERRED]
#   - if reasoning.ai_available is False -> note AI section absent -> Req 8.5
```

The renderer clearly separates an **Observed** section (deterministic evidence +
correlations) from an **Inferred** section (Bedrock output), satisfying Req 8.4. Every
candidate cause line prints its citing evidence IDs (Req 8.3).

## Configuration (`config.py`)

Loaded from environment (documented in `.env.example`, Req 9.2). No secrets committed.

| Setting | Env var | Default | Purpose |
|---|---|---|---|
| AWS region | `OPSORACLE_AWS_REGION` | (from AWS chain) | client region |
| AWS profile | `AWS_PROFILE` | default chain | credentials |
| Bedrock model id | `OPSORACLE_MODEL_ID` | a Claude model id | reasoning model |
| Max context events | `OPSORACLE_MAX_EVENTS` | 50 | context budget (Req 6.3, 10.2) |
| Max output tokens | `OPSORACLE_MAX_TOKENS` | 1500 | Bedrock cap (Req 10.2) |
| Reasoning enabled | `OPSORACLE_REASONING_ENABLED` | true | allow disabling Bedrock (Req 7.1, 10) |
| Retry limit | `OPSORACLE_MAX_RETRIES` | 5 | collector backoff bound (Req 1.5) |

## Error Handling

Typed hierarchy in `errors.py`:

```text
OpsOracleError
├── ConfigError            # bad/missing config
├── ValidationError        # bad window, bad EvidenceEvent construction (Req 1.4, 2.4)
├── CollectionError        # wraps AWS failures
│   ├── ThrottlingError    # retryable (Req 1.5)
│   └── AccessError        # non-retryable, e.g. AccessDenied (Req 1.6)
├── NormalizationError     # only for unrecoverable batch-level issues
└── ReasoningError         # Bedrock invoke/parse failures (caught → graceful fallback)
```

Rules:
- Retryable AWS errors → bounded exponential backoff, then surface as `CollectionError`.
- Non-retryable AWS errors → `AccessError`/`CollectionError` with source + operation, no
  credential material in the message (Req 1.6, 9.3).
- `ReasoningError` is caught by the orchestrator and converted to
  `ReasoningResult(ai_available=False)` so the report still renders (Req 7.7, 8.5).
- Per-record normalization failures are non-fatal; the batch continues (Req 3.4).

## Testing Strategy

All tests run offline with mocked AWS — no live calls (Req 11.1). Preferred tooling:
`pytest` + `botocore.stub.Stubber` (or `moto`) for AWS, and canned JSON fixtures.

| Area | Tests |
|---|---|
| CloudTrailCollector | pagination across multiple pages; throttling→retry→success; access-denied→typed error; window validation rejects start≥end; raw events returned unmodified |
| EvidenceEvent | round-trip to_dict/from_dict; validation error on missing required field; deterministic ID stability |
| CloudTrail normalization | full record; record missing optional fields (Req 3.4); nested CloudTrailEvent detail extraction (Req 3.3); raw_ref preserved |
| Timeline | ascending order; identical-timestamp stable tiebreak; group-by-resource/service |
| Correlation | temporal proximity in/out of window; shared-resource; change-before-failure ordering; empty result when none; explanations use qualified language |
| Context builder | ranking prioritizes correlated events; budget truncation sets `truncated=True` |
| Bedrock reasoning | malformed JSON rejected/repaired (Req 7.3); claim with unknown evidence id dropped (Req 7.5); Bedrock exception → ai_available=False (Req 7.7); insufficient-evidence output preserved (Req 7.6) — Bedrock client mocked |
| Report | markdown separates observed vs inferred; candidate causes cite evidence IDs; AI-unavailable note present |
| Cross-cutting | duplicate events dedup via deterministic ID (Req 11.2); no secret values in error strings |

Test layout mirrors the package under `tests/` (e.g. `tests/collectors/test_cloudtrail.py`).

## Design Decisions and Rationale

1. **Deterministic, content-derived evidence IDs.** Gives stable traceability, free
   deduplication, and reproducible test assertions (Req 2.2, 11.2).
2. **Injectable AWS clients everywhere.** Enables offline, deterministic tests and keeps
   collectors independent from reasoning (RULES.md §6; Req 11.1).
3. **Raw payload preserved on every event (`raw_ref`).** Guarantees auditability — any
   report claim can be traced to the original AWS record (Req 3.5, 11.3).
4. **Bedrock gated + budgeted + optional.** Honors "evidence before inference" and cost
   rules; the pipeline is fully useful even with reasoning disabled (Req 7.1, 10).
5. **Graceful degradation as a first-class path.** AI failure yields a still-valid report
   rather than an error (Req 7.7, 8.5), matching the non-functional reliability goal.
6. **Qualified-language correlations, auditable change/failure classification.** Prevents
   correlation being mis-sold as causation (RULES.md §4; Req 5.5).
7. **`pydantic` vs `dataclasses`:** default to `dataclasses` + a small validation helper to
   keep MVP dependencies minimal (requirements.txt is currently bare); revisit `pydantic`
   if serialization/validation grows. Either satisfies Req 2 — noted as an open choice.

## Traceability Matrix (requirement → component)

| Requirement | Primary component(s) |
|---|---|
| R1 CloudTrail collection | `collectors/cloudtrail.py`, `collectors/base.py`, `errors.py` |
| R2 Evidence model | `models/evidence.py` |
| R3 Normalization | `normalization/cloudtrail.py` |
| R4 Timeline | `timeline/builder.py` |
| R5 Correlation | `correlation/engine.py`, `models/correlation.py` |
| R6 Context | `context/builder.py`, `models/investigation.py` |
| R7 Reasoning | `reasoning/bedrock.py`, `reasoning/prompt.py`, `reasoning/schema.py` |
| R8 Report | `reporting/incident_report.py`, `models/report.py` |
| R9 Credential safety | `config.py`, `errors.py`, `.env.example` |
| R10 Cost control | `config.py`, `context/builder.py`, `reasoning/bedrock.py` |
| R11 Testing/auditability | `tests/**`, `raw_ref` on `EvidenceEvent` |
