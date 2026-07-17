# Agent Failure Taxonomy — AFT-1

**Status:** Draft v0.3
**Authors:** Tracelane
**License:** CC0 1.0 Universal (public domain dedication) — see `LICENSE` in this directory.

> AFT-1 is released into the **public domain (CC0 1.0)**. Anyone may use, adapt,
> implement, or extend it — in commercial or open-source products, standards, or
> research — with no attribution required and no patent or trademark grant implied.

---

## Overview

The Agent Failure Taxonomy (AFT) is a structured, vendor-neutral catalogue of
failure modes observed in production AI-agent systems, with an emphasis on the
**MCP tool-poisoning** family that has become the fastest-moving attack surface in
the agent stack. It exists so that tools, gateways, observability platforms, and
red-teams can refer to the same failure by the same stable name.

Each AFT entry has:

- A **stable identifier** — `AFT-<DOMAIN>-<NAME>-<SEQ>`.
- A **description** of the failure mode.
- A **detection** method — the signal that indicates the failure.
- An **intervention type** — `Warn` or `Block` — read through the **observe-first**
  model (see the Intervention Type Reference): a decision is *recorded* by default;
  enforcement (turning a `Block` into a hard stop) is an explicit opt-in, because
  stopping an agent mid-run is itself destructive.
- Public **references** where the failure mode has been documented.

The taxonomy is deliberately broader than any one implementation's current
coverage. See *Reference implementation* for how the open-source Tracelane gateway
maps to a subset of these entries.

---

## Taxonomy

### MCP Domain

#### AFT-MCP-RUGPULL-001

| Field | Value |
|---|---|
| **Name** | MCP server rug-pull |
| **Description** | An MCP server's tool definitions change after the agent has consented to use them. The new definitions may have different parameter types, hidden side effects, or escalated permissions. |
| **Detection** | The hash of the tool manifest changes between calls within a session (compare a content hash of the full tool-set at consent time against each subsequent call). |
| **Intervention** | `Block` — hold execution pending human confirmation. |
| **References** | Invariant Labs MCP-security research; OX Security MCP-ecosystem report (2026); Microsoft poisoned-MCP-tool advisory (2026). |

#### AFT-MCP-ARGDRIFT-001

| Field | Value |
|---|---|
| **Name** | MCP argument drift |
| **Description** | Arguments passed to an MCP tool deviate from the schema declared at consent time. May indicate prompt injection rewriting the call, or a compromised tool server. |
| **Detection** | Argument type/shape validation against the consented schema on every call. |
| **Intervention** | `Warn` — record and flag for human review. |
| **References** | Promptfoo red-team pattern library; prompt-injection literature. |

#### AFT-TOOL-SCHEMA-001

| Field | Value |
|---|---|
| **Name** | Hallucinated tool-call schema violation |
| **Description** | A model emits a tool call that does not conform to the tool schema the request declared: an undeclared tool name, arguments that aren't the expected object, a missing `required` field, a wrong primitive type, or (under `additionalProperties: false`) an undeclared field. Canonical case: the agent calls `lookup_order(email=…)` when the schema requires `order_id`. |
| **Detection** | Stateless JSON-Schema-subset validation (top-level `type` / `required` / `properties` / `additionalProperties`) of every tool call against the request's declared tool `input_schema`. |
| **Intervention** | `Warn` — record a schema-violation event (structural detail only; argument values redacted). Enforcement (returning a structured error so the agent self-corrects) is an opt-in policy layer. |
| **References** | Tool-use / function-calling conformance failures in agent frameworks. |

#### AFT-TOOL-DRIFT-001

| Field | Value |
|---|---|
| **Name** | Tool-definition drift (silent rug-pull) |
| **Description** | A declared tool keeps its name but its **definition mutates** across requests for the same tenant — its `input_schema` grows/loses a field, or its description is rewritten. The tool-set hash (AFT-MCP-RUGPULL-001) is unchanged and individual calls still validate (AFT-TOOL-SCHEMA-001), yet the contract the user consented to has shifted. Canonical attack: `transfer_money` quietly grows a `recipient_override` parameter. |
| **Detection** | A per-`(tenant, tool)` content fingerprint of the full definition (name + description + key-sorted `input_schema`), compared across requests. Any drift is flagged; it is classified as a **rug-pull** when it (a) introduces a sensitive-named field (`*_override` / `admin` / exfiltration-shaped), (b) mutates the description to introduce an injection/exfiltration directive, or (c) *loosens* an existing field's constraint (dropped from `required`, or its `enum` allow-list widened/removed). Tightenings re-baseline as ordinary drift. |
| **Intervention** | `Warn` on ordinary drift (re-baselines, so a legitimate update warns once); a rug-pull shape raises a high-severity `Block` decision. Observe-first: the decision is recorded; a hard stop fires only under opt-in enforcement. |
| **References** | Complements AFT-MCP-RUGPULL-001; MCP tool-poisoning disclosures (2026). |

---

### Taint Domain

#### AFT-TAINT-LETHAL-001

| Field | Value |
|---|---|
| **Name** | Lethal-trifecta taint propagation |
| **Description** | An agent simultaneously has: (1) access to sensitive/private data, (2) access to an external communication channel (email, HTTP, chat), and (3) exposure to untrusted input. Any two raise a warning; all three is the high-risk exfiltration shape. |
| **Detection** | Taint labels on span attributes for data access, channel access, and untrusted input; evaluate their co-occurrence within a trace. |
| **Intervention** | All three present → `Block`. Any two → `Warn`. |
| **References** | The "lethal trifecta" framing for prompt-injection data exfiltration (Simon Willison, 2025). |

---

### Prompt-Injection Domain

#### AFT-PI-CASCADE-001

| Field | Value |
|---|---|
| **Name** | Prompt-injection cascade |
| **Description** | Untrusted content in one span propagates to a downstream LLM call without sanitisation; the downstream call may execute injected instructions. |
| **Detection** | An untrusted-content sentinel is present in LLM input that originated from a previous span's output. |
| **Intervention** | `Warn`, high severity. Escalates to `Block` when combined with lethal-trifecta taint. |
| **References** | EchoLeak-class zero-click prompt-injection disclosures (Microsoft 365 Copilot, 2025); indirect-prompt-injection literature. |

---

### Context Domain

#### AFT-CONTEXT-OVERFLOW-001

| Field | Value |
|---|---|
| **Name** | Context-window overflow |
| **Description** | A model response is cut off because the context or output-token window filled before the model finished — a truncated, incomplete result that downstream steps may consume as if it were complete. |
| **Detection** | The completion terminated on a length signal rather than a natural stop: `finish_reason = length` (OpenAI-family), `stop_reason = max_tokens` (Anthropic-family), or an equivalent provider truncation flag. |
| **Intervention** | `Warn` — record a truncation event. A truncated result is a reliability defect, not a security halt; observe-first records it and the request continues. |
| **References** | OpenAI Chat Completions `finish_reason` and Anthropic Messages `stop_reason` API semantics (the documented `length` / `max_tokens` truncation signals). |

---

### A2UI Domain (Agent-to-UI)

#### AFT-A2UI-CATALOG-001

| Field | Value |
|---|---|
| **Name** | A2UI non-catalog component type |
| **Description** | An agent attempts to render a UI component whose `type` is not in the standard catalogue — a hallucinated component name, or an attempt to inject arbitrary markup. |
| **Detection** | Component `type` is not in the standard-catalogue allowlist. |
| **Intervention** | `Block` — do not render unknown components. |
| **References** | A2UI Protocol v0.9. |

#### AFT-A2UI-STUCKLOOP-001

| Field | Value |
|---|---|
| **Name** | A2UI stuck-loop |
| **Description** | The DOM-mutation score is zero across multiple agent steps: the agent is repeatedly generating UI actions that have no effect — a runaway loop or a broken action-perception cycle. |
| **Detection** | A zero DOM-mutation score persisting past the first step. |
| **Intervention** | `Warn` — flag for review; escalate to `Block` when the score is zero for a sustained run of steps. |
| **References** | Browser-agent loop-detection practice. |

#### AFT-A2UI-CAPTCHA-001

| Field | Value |
|---|---|
| **Name** | CAPTCHA blocking agent progress |
| **Description** | A browser agent has reached a page where a CAPTCHA blocks further automation; it cannot proceed without human intervention. |
| **Detection** | A CAPTCHA-detected signal, or URL/content matching CAPTCHA signatures. |
| **Intervention** | `Warn` — pause automation and request a human to solve or confirm. |
| **References** | Browser-automation CAPTCHA handling. |

---

### A2A Domain (Agent-to-Agent)

#### AFT-A2A-LIFECYCLE-001

| Field | Value |
|---|---|
| **Name** | A2A handoff lifecycle violation |
| **Description** | An agent-to-agent handoff does not follow the expected lifecycle: init → running → complete/failed. Missing transitions, double-init, or completion without a prior running state indicate a broken orchestration layer. |
| **Detection** | Validate the A2A span sequence against the lifecycle state machine. |
| **Intervention** | `Warn` — record the anomalous transition for review. |
| **References** | Google A2A protocol specification. |

---

### Trajectory Domain

#### AFT-TRAJ-RETRYLOOP-001

| Field | Value |
|---|---|
| **Name** | Retry storm (tool-call loop) |
| **Description** | An agent repeats the same tool call — same tool, equivalent arguments — without making progress, spending tokens and latency in a runaway retry loop instead of advancing or terminating. |
| **Detection** | Near-identical tool calls (same tool name + equivalent argument shape) recur within a single trace beyond a threshold count, with no intervening progress. A rule-based loop detector — distinct from the learned AFT-TRAJ-ANOMALY-001. |
| **Intervention** | `Warn` — flag the loop; escalate to `Block` when it persists past a higher threshold. Observe-first: recorded by default. |
| **References** | Agent-framework iteration caps that exist to bound this failure (e.g. LangChain `max_iterations`, ReAct step limits); agent loop-detection practice. |

#### AFT-TRAJ-ANOMALY-001

| Field | Value |
|---|---|
| **Name** | Trajectory-level anomaly |
| **Description** | The sequence of spans in an agent trace is statistically anomalous compared to a learned distribution of normal traces — a catch-all for novel failure modes not covered by rule-based entries. |
| **Detection** | A learned sequence model (e.g. a recurrent autoencoder) flags a reconstruction error above threshold. This is a model-based, roadmap-class detector, not a rule. |
| **Intervention** | `Warn` initially; escalates to `Block` above a higher threshold. |
| **References** | Sequence-anomaly / autoencoder approaches to trace-level outlier detection. |

---

## Intervention Type Reference

| Type | Meaning | Default effect (observe-first) |
|---|---|---|
| `Allow` | No anomaly detected | Request continues normally. |
| `Warn { aft_id }` | Anomaly flagged | Recorded as a flagged event; request continues. |
| `Block { aft_id }` | Anomaly severe enough that enforcement *would* halt it | **Recorded as a flagged event; request continues by default.** A hard stop fires only when enforcement is explicitly opted in. |

A conformant implementation SHOULD surface the most-severe decision across all
detectors (`Block` > `Warn` > `Allow`). The recommended posture is
**flight-recorder-first**: *record and prove* the failure. Because stopping an
agent is destructive, moving a `Block` from "recorded" to "enforced" SHOULD be an
explicit, per-deployment opt-in.

---

## Reference implementation

The open-source Tracelane gateway (Apache-2.0, in this repository) ships reference
detectors for a subset of these entries under `crates/gateway/src/predictive/`, and
its pain-point eval suite under `evals/pain-points/` exercises them. Coverage is a
subset of the taxonomy and is expanding — this document is the standard; the gateway
is one implementation of it. The observe-first model above is the gateway default:
detectors record and flag; enforcement is opt-in.

---

## Proposing a new AFT entry

AFT is CC0 and open to extension. To propose an entry:

1. Give it a stable `AFT-<DOMAIN>-<NAME>-<SEQ>` identifier and populate every field.
2. Specify a **detection** method precise enough that two implementers would agree
   on when the failure fires.
3. Specify the **intervention** type under the observe-first model.
4. Cite at least one public **reference** documenting the failure mode.

---

## Changelog

| Version | Date | Change |
|---|---|---|
| v0.1 | 2026-04-29 | Initial taxonomy — 9 entries across 5 domains. |
| v0.2 | 2026-07-10 | Relicensed to CC0 1.0 for public-domain publication; made vendor-neutral (detection/intervention described independently of any one implementation); observe-first intervention model; added the tool-definition-drift (silent rug-pull) entry; removed unverifiable model-training figures. |
| v0.3 | 2026-07-14 | Added AFT-CONTEXT-OVERFLOW-001 (context-window overflow, new Context domain) and AFT-TRAJ-RETRYLOOP-001 (retry storm, Trajectory domain). Reference-implementation detectors for both are roadmap, not yet shipped (see *Reference implementation* — coverage is a subset and expanding). |
