# PRD: OpsOracle — AI-Powered AWS Incident Investigation & Root-Cause Analysis

**Owner:** [Your name]
**Status:** Draft v1.0
**Last updated:** August 22, 2026
**Doc type:** Learning project PRD (personal build, structured as a real product spec)

---

## 1. Summary

OpsOracle is an agentic system that investigates AWS production incidents the way a senior on-call engineer would: it watches for anomalies, pulls the relevant logs/metrics/traces/events, reasons about what changed, ranks likely root causes with a confidence score, and produces a written incident report — all with minimal human prompting.

The project is deliberately scoped as **one system that forces five skill areas to intersect**, rather than five separate toy projects, because in real SRE/AI-infra roles these layers are never learned in isolation — the interesting engineering problems live at the seams (e.g., "how do I stop the agent from hallucinating a root cause when the log query returned zero rows").

---

## 2. Goals

### 2.1 Learning goals (primary — this is why the project exists)
| # | Goal | Where it's exercised |
|---|---|---|
| 1 | Get fluent in AWS observability primitives | Phase 1 |
| 2 | Learn to design reliable tool-calling LLM systems | Phase 2 |
| 3 | Learn agentic orchestration patterns (single-agent → multi-agent, MCP) | Phase 3 |
| 4 | Learn applied statistics for anomaly detection & confidence scoring | Phase 4 |
| 5 | Learn to productionize an AI system (IAM, cost, evals, security) | Phase 5 |

### 2.2 Product goals (secondary but real — should still work end-to-end)
- Detect an anomaly in a demo AWS workload within minutes of it occurring.
- Autonomously gather evidence (logs, metrics, traces, deploy/config-change events) without being told where to look.
- Produce a root-cause hypothesis with a **confidence score**, not just a narrative guess.
- Output a structured, shareable incident report (Slack-message-shaped + full Markdown doc).
- Be cheap enough to run continuously on a demo account (target: < $15/month idle, < $2/incident investigated).

### 2.3 Non-goals
- Not building a general-purpose AWS chatbot.
- Not replacing PagerDuty/Opsgenie — no paging/escalation logic in v1.
- Not multi-cloud. AWS-only for v1.
- Not auto-remediation in v1 (investigate and recommend, don't act) — auto-remediation is an explicit stretch goal for later, gated behind human approval.

---

## 3. Technology decisions (with reasoning)

This section is the output of evaluating each phase's options before committing — the point the project brief asked for.

### Phase 1 — AWS Observability: what to standardize on

| Need | Choice | Why |
|---|---|---|
| Structured app/infra logs | **CloudWatch Logs** + Logs Insights | Native, queryable with a SQL-like syntax the agent can generate reliably, no extra infra |
| Metrics (CPU, latency, error rate, custom business metrics) | **CloudWatch Metrics** + embedded metric format (EMF) for custom metrics | Free-tier friendly, integrates directly with alarms and anomaly bands |
| Distributed tracing / "what called what" | **AWS X-Ray + CloudWatch Application Signals** | Application Signals gives SLO-aware service maps out of the box — huge time-saver over building trace correlation yourself |
| Change/event correlation ("what changed right before this broke") | **EventBridge** (CloudTrail management events routed through it) + CloudTrail | This is the piece most tutorials skip and it's usually where the *actual* root cause is (a deploy, a config change, an IAM policy edit) |
| Alarm triggering | **CloudWatch Alarms** → EventBridge → triggers the agent | Keeps detection decoupled from investigation |

**Decision:** Don't build a custom telemetry pipeline. Use CloudWatch as the single pane of glass and spend the saved time on the agent logic — that's where the actual learning value is for Phases 2–4.

### Phase 2 — AI investigation layer

| Need | Choice | Why |
|---|---|---|
| LLM | **Amazon Bedrock (Claude models)** | Native IAM auth, no separate API key management, keeps everything inside the AWS trust boundary for Phase 5's security story |
| Tool-calling interface to AWS data | **AWS Labs CloudWatch MCP Server** + **Application Signals MCP Server** (open source, maintained by AWS) | These already expose alarms, log queries, metric math, and trace/service-health tools as ready-made MCP tools — writing this from scratch would be reinventing a well-maintained wheel and would eat the whole timeline. Use them, but read their source to understand tool design patterns |
| Evidence-gathering strategy | ReAct-style loop: observe alarm → hypothesize → pick a tool → evaluate result → refine or conclude | This is the actual "AI investigation" skill — sequencing tool calls under uncertainty, not the tools themselves |

**Decision:** Don't hand-roll the AWS API wrappers. The learning value in Phase 2 is in *investigation strategy* (what to check first, when to stop gathering evidence, how to handle empty/ambiguous results) — not in re-implementing `describe_log_groups`.

### Phase 3 — Agentic architecture

| Need | Choice | Why |
|---|---|---|
| Agent framework | **Strands Agents SDK** (AWS open source, Apache-2.0) | Model-driven (not hardcoded workflow graphs), native Bedrock + MCP support, built-in OpenTelemetry observability, actively used in AWS production systems (Q Developer, Glue) — directly relevant to real-world agentic-AI roles |
| Tool orchestration | **MCP** as the tool protocol (CloudWatch MCP + Application Signals MCP + a custom "EventBridge/CloudTrail change-correlation" MCP tool you build yourself) | Standardizes tool interfaces; building one custom MCP server yourself (the change-correlation one) is where you actually learn MCP server design, rather than only ever being a client |
| Multi-agent vs single-agent | **Start single-agent with a rich toolset. Add a 2-agent split (Investigator + Report-writer) in v2** | Avoids premature complexity; Strands' "agent-as-tool" pattern makes the v2 split cheap once v1 works |

**Decision:** Build one custom MCP server (change-correlation) so the project isn't 100% "assemble other people's tools" — that's the one piece with no off-the-shelf equivalent and the best learning ROI.

### Phase 4 — ML / statistics layer

| Need | Choice | Why |
|---|---|---|
| Anomaly detection | **CloudWatch Anomaly Detection** (built-in ML bands on metrics) as the trigger, **not** Amazon Lookout for Metrics | Lookout for Metrics was discontinued by AWS (end of support Oct 2025) — it's no longer a viable choice for a new project. CloudWatch's native anomaly bands are free-tier friendly and sufficient for the trigger layer |
| Confidence scoring for root-cause hypotheses | **Custom scoring model**: weighted combination of (a) temporal correlation strength between the change event and the anomaly onset, (b) LLM self-reported certainty, (c) evidence-count/agreement across independent signals (logs + metrics + traces all pointing the same way) | This is the actual statistics learning: you're not calling an API, you're designing and justifying a scoring function — good source of interview-story material |
| Incident classification (severity, category) | Simple rule-based first pass (error-rate thresholds, SLO burn rate from Application Signals) refined by LLM classification into categories: deploy-induced / capacity / dependency-failure / config-drift / unknown | Keeps classification auditable — you can explain *why* something was labeled "deploy-induced" without just trusting a black box |

**Decision:** Explicitly avoid Lookout for Metrics (deprecated) and avoid building a full ML anomaly-detection pipeline from scratch for v1 — use CloudWatch's built-in bands for detection, and spend the "ML/stats" learning budget on the confidence-scoring model instead, since that's the more transferable and less commoditized skill.

### Phase 5 — Production concerns

| Need | Choice | Why |
|---|---|---|
| IAM | Dedicated least-privilege role for the agent; read-only on investigation tools, explicit separate role if remediation is ever added | Core AWS security hygiene; also directly testable ("can the agent read a secret it shouldn't?") |
| Guardrails | **Bedrock Guardrails** on the investigation agent's inputs/outputs | Prevents the agent from including sensitive data verbatim in reports, blocks prompt-injection attempts from log content |
| Observability of the agent itself | OpenTelemetry (built into Strands) → CloudWatch, so you can trace the agent's own tool-call sequence, latency, and token spend per investigation | "Who investigates the investigator" — necessary for debugging the agent and for the cost/eval work below |
| Cost control | Per-investigation token budget + step limit in the agent loop; CloudWatch dashboard tracking $/incident | Bedrock cost is the main variable cost; without a budget the agent can loop expensively on ambiguous incidents |
| Evaluation | Golden-set of 15–20 synthetic incidents (seeded via chaos scripts) with known root causes, scored automatically for: correct root cause identified (Y/N), confidence calibration, time-to-report, cost | This is what makes "did the agent actually get better" answerable instead of vibes-based |

---

## 4. System architecture (v1)

```
 CloudWatch Alarm fires (anomaly band breach)
            │
            ▼
       EventBridge  ───────────────► triggers ──────────► OpsOracle Agent (Strands, on Lambda/Fargate)
                                                                     │
                                        ┌────────────────────────────┼─────────────────────────────┐
                                        ▼                            ▼                              ▼
                          CloudWatch MCP Server        Application Signals MCP Server     Custom Change-Correlation
                          (logs, metrics, alarms)       (service map, SLOs, traces)         MCP Server (CloudTrail +
                                                                                             EventBridge history)
                                        │                            │                              │
                                        └────────────────────────────┴──────────────────────────────┘
                                                                     │
                                                                     ▼
                                                     Bedrock (Claude) — reasoning loop
                                                                     │
                                                                     ▼
                                            Confidence Scoring Module (Phase 4 logic)
                                                                     │
                                                                     ▼
                                        Incident Report (Markdown + Slack summary) → S3 + notification
                                                                     │
                                                                     ▼
                                             Eval harness scores it against golden set (offline, async)
```

---

## 5. Functional requirements

| ID | Requirement | Priority |
|---|---|---|
| FR1 | System ingests a CloudWatch alarm event via EventBridge and starts an investigation within 30s | P0 |
| FR2 | Agent autonomously queries logs, metrics, traces, and change history without a human specifying which service is affected | P0 |
| FR3 | Agent produces a root-cause hypothesis with a numeric confidence score (0–100) | P0 |
| FR4 | Agent classifies the incident into one of: deploy-induced / capacity / dependency-failure / config-drift / unknown | P0 |
| FR5 | Agent produces a Markdown incident report with an evidence appendix (what it checked, what it found, what it ruled out) | P0 |
| FR6 | Agent stops gathering evidence after a configurable step/token budget and reports "insufficient evidence" rather than fabricating a cause | P0 |
| FR7 | Every tool call and its result is logged and traceable end-to-end (OpenTelemetry) | P1 |
| FR8 | Reports are versioned/stored in S3 with a queryable index | P1 |
| FR9 | Eval harness can replay the golden-set incidents and score agent output automatically | P1 |
| FR10 | (Stretch) Two-agent split: Investigator agent + Report-writer agent, communicating via Strands agent-as-tool | P2 |
| FR11 | (Stretch) Human-approved auto-remediation for a narrow, safe class of issues (e.g., restart unhealthy task) | P2 |

---

## 6. Non-functional requirements

- **Security:** least-privilege IAM, no long-lived credentials in the agent runtime, Bedrock Guardrails active, secrets never echoed into reports.
- **Cost:** target < $2 per investigation (token + compute), < $15/month idle infra cost on demo account; dashboard tracks actual spend.
- **Latency:** first evidence gathered within 60s of alarm; full report within 5 minutes for a single-service incident.
- **Reliability:** agent must degrade gracefully — a failed tool call should not crash the investigation, it should be noted as "unavailable" in the report.
- **Auditability:** every claim in the final report must be traceable to a specific tool call and its raw result (no unsupported claims).

---

## 7. Phased build plan

| Phase | Focus | Key deliverable | Rough effort |
|---|---|---|---|
| 1 | AWS Observability | A demo workload (e.g. small containerized app on ECS/Fargate) instrumented end-to-end with CloudWatch Logs, Metrics, Application Signals, EventBridge, CloudTrail. Manually break it and confirm you can find the cause by hand in the console. | 1–1.5 weeks |
| 2 | AI investigation | Single Bedrock-backed agent (no framework yet) that can call the CloudWatch MCP Server tools and answer "what's wrong" for one seeded incident type. | 1 week |
| 3 | Agentic architecture | Port to Strands Agents SDK, wire up Application Signals MCP + your own custom change-correlation MCP server, build the ReAct evidence-gathering loop with step/budget limits. | 1.5–2 weeks |
| 4 | ML/statistics | CloudWatch anomaly-detection bands as trigger; build and tune the confidence-scoring function; build the incident classifier; build the 15–20 item golden set with chaos-injection scripts. | 1.5 weeks |
| 5 | Production | IAM hardening, Bedrock Guardrails, OpenTelemetry tracing of the agent, cost dashboard, eval harness automation, write-up. | 1 week |

Total: roughly **6–7 weeks** at a steady part-time pace — adjust to your actual schedule; the phases are sequential but each is independently demoable, so slipping one doesn't block showing progress on the others.

---

## 8. Success metrics

- **Learning:** can explain, from memory, how each phase's component works and why it was chosen over the alternative (this doc's Section 3 is the test).
- **Product:** ≥ 80% correct root-cause identification on the golden set, with confidence scores that are reasonably calibrated (high-confidence answers are right more often than low-confidence ones).
- **Portfolio value:** project is demoable end-to-end in under 5 minutes (trigger a real incident, watch the report come out).

---

## 9. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Agent hallucinates a root cause when evidence is thin | Hard rule: if evidence-agreement score is below threshold, output "unknown/insufficient evidence" instead of a guess (FR6) |
| Bedrock cost runs away on ambiguous incidents | Hard step/token budget per investigation, with cost dashboard alerting |
| MCP server dependency changes/breaks (fast-moving ecosystem) | Pin versions; since these are AWS Labs open-source projects, changes are usually additive — review changelog before upgrading |
| Scope creep into a full AIOps platform | Non-goals section (2.3) is the guardrail — revisit before adding anything not listed there |

---

## 10. References

- AWS Labs CloudWatch MCP Server — awslabs.github.io/mcp/servers/cloudwatch-mcp-server
- AWS open-source MCP servers hub — awslabs.github.io/mcp
- Strands Agents SDK — strandsagents.com
- AWS blog: "Enhance your AIOps: Introducing Amazon CloudWatch and Application Signals MCP servers"
- AWS blog: "Transitioning off Amazon Lookout for Metrics" (why it's excluded from this design)
