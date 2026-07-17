# Predictive guardrails

Tracelane runs eight predictive guardrails inline on the gateway hot path. The
budget is **<30ms p50, <50ms p95, <100ms p99** for the entire predictive layer
combined. Each guard either passes the request through, attaches a
`predictive.*` span attribute with severity + score, or short-circuits with
a deterministic block.

The guardrails encode the [50 pain-point evals](./../evals/pain-points/INDEX.md).
A claim on the website that a guard exists is gated on its eval being green
on `main`.

## At a glance

| ID | Guard | Inline cost (p95) | Eval IDs |
|---|---|---|---|
| PR1 | MCP rug-pull detection | <2ms | PP-MCP1..3 |
| PR2 | Lethal-trifecta taint tracking | <3ms | PP-TFT1..4 |
| PR3 | A2UI catalog conformance | <1ms | PP-UI1..3 |
| PR4 | Prompt-injection classifier (Llama Prompt Guard 2 ONNX) | <8ms | PP-PI1..6 |
| PR5 | Browser stuck-loop prediction | <2ms | PP-BR1..3 |
| PR6 | A2A handoff validation | <2ms | PP-A2A1..4 |
| PR7 | Output-policy regex + SLM judge sandwich | <12ms | PP-OUT1..5 |
| PR8 | Argument drift (PR8-lite Mahalanobis) | <3ms | PP-G3, PP-PR8 |

Total typical add-on at p95: ~32ms — within budget because the heaviest two
(PR4, PR7) only fire on a subset of requests and run concurrently.

## PR1 — MCP rug-pull detection

Catches an MCP tool whose schema, description, or pinned hash mutates
mid-session — the canonical "rug-pull" attack where a benign tool gets
swapped for an exfiltrating clone after the model has already trusted it.

**Signal:** SHA-256 of `(name, description, input_schema_json)` per tool,
recorded on first use; later mismatches block before the call is dispatched.

**Span attribute on hit:** `predictive.mcp_rugpull = { tool, prev_hash, new_hash }`,
severity `block`.

**Failure mode:** First tool call after an MCP server restart looks like a
rug-pull. We special-case server-version-bump events; all other diffs block.

## PR2 — Lethal-trifecta taint tracking

Tracks the three ingredients of the well-known agent attack: untrusted input,
private data access, and external write capability. When all three taints
co-occur on the same agent step, we block.

**Taint sources:**
- `untrusted`: any span produced from a tool whose return is user-controllable (web, MCP, file read of a writable path)
- `private`: any tool that reads tenant-scoped private data (DB, vault, "personal" mailbox, etc.)
- `external_write`: any tool that emits to a third-party-observable destination (HTTP, email, slack, paste, write to public bucket)

The taint set propagates through the agent's working memory; the gateway
inspects each tool-call span before dispatch.

**Span attribute on hit:** `predictive.trifecta = ["untrusted","private","external_write"]`, severity `block`.

## PR3 — A2UI catalog conformance

Validates Agent-to-UI surfaces (cards, buttons, forms emitted via A2UI) match
the published per-tenant catalog. Catches drift where the agent emits a
button targeting a route the UI no longer ships, or a form schema the UI
can't render.

**Signal:** A2UI surface schemas are registered per-tenant; runtime emissions
are JSON-Schema-validated against the registered version.

**Span attribute on hit:** `predictive.a2ui = { surface_id, version, error }`, severity `warn`.

## PR4 — Prompt-injection classifier

Llama Prompt Guard 2 distilled to ONNX for low-latency inference. Runs on every
incoming user-supplied span content wrapped in `<UNTRUSTED_USER_DATA>`.

**Model:** `prompt-guard-2-86m` exported via `ml/eval_corpus/scripts/export_prompt_guard.py`.
**Runtime:** `onnxruntime` 1.22, INT8 weights, CPU inference (no GPU
required for the gateway hot path).

**Span attribute on hit:** `predictive.injection = { score: f32, label: "jailbreak"|"injection"|"benign" }`.
Score >0.85 on a `block` policy short-circuits; otherwise it's an annotated warn.

## PR5 — Browser stuck-loop prediction

Operator agents (Browserbase, Playwright via MCP) sometimes loop on the same
page action — clicking the same button, scrolling the same element. Detects
the loop early via a fingerprint chain and breaks it before burning quota.

**Signal:** sliding window of (URL, DOM-action-fingerprint) tuples; if the
window ratio of unique fingerprints < `STUCK_LOOP_THRESHOLD` (default 0.4)
across N steps, we emit a stop event the agent can read.

**Span attribute on hit:** `predictive.browser_loop = { window_size, unique_ratio }`, severity `warn`.

## PR6 — A2A handoff validation

Agent-to-Agent (A2A) protocol: when one agent hands off a task to another,
the receiver gets a "task envelope". Validates: envelope schema, required
fields, signed origin, no circular handoff (A → B → A → B …).

**Span attribute on hit:** `predictive.a2a = { reason, depth }`, severity `block` for circular, `warn` for schema drift.

## PR7 — Output-policy regex + SLM judge sandwich

Two-stage output guard. Cheap regex pass first (PII, credentials, profanity
heuristics), then an SLM judge ([1B encoder](./../ml/slm_judge/README.md))
on a configurable severity gate.

The judge runs on a dedicated GPU pool (L4); the gateway calls it via gRPC
with a 50ms p95 SLA. If the judge isn't reachable, we fall back to
"regex-only" mode and emit a `predictive.judge_unavailable = true` warn —
we never silently drop the guard.

**Span attribute on hit:** `predictive.output_policy = { stage, rule_id, action }`, severity per rule.

## PR8 — Argument drift (PR8-lite Mahalanobis)

Catches an agent calling a familiar tool with arguments it has never used
before — the precursor to the "agent goes off the rails" pattern observed
in dogfooding.

**Signal:** rolling Mahalanobis distance over featurised tool-call argument
embeddings, per (tenant, tool) pair. Background EMA mean + covariance,
threshold 4σ → arg-drift event. PR8-lite is the lightweight version; the
full PR8 in roadmap §3 swaps the EMA for a learned encoder.

**Bias correction:** EMA mean is initialised directly on the first sample
(not zero — fixes a 60-sample warm-up bias surfaced during eval).

**Span attribute on hit:** `predictive.arg_drift = { tool, distance, threshold }`, severity `warn`.

## Configuring per-tenant

Each guard has a `policy` per tenant — `disabled`, `warn`, or `block`. Set
via `/v1/policies` (admin) or via the dashboard. Defaults:

```yaml
predictive:
  pr1_mcp_rugpull:        block
  pr2_lethal_trifecta:    block
  pr3_a2ui_catalog:       warn
  pr4_prompt_injection:   block       # threshold 0.85
  pr5_browser_loop:       warn
  pr6_a2a_handoff:        block
  pr7_output_policy:      warn        # block specific rule_ids individually
  pr8_arg_drift:          warn
```

A "drop to warn" policy never blocks the request — it just annotates the
span. Useful for observability rollouts before flipping to `block`.

## Reading predictive output

Every guard hit emits a span attribute under `predictive.*`. The dashboard
trace viewer surfaces these in the predictive lane (separate from tool /
LLM lanes). The MCP server filters traces by predictive severity:

```typescript
// via @tracelanedev/mcp
mcp.traces.list({
  filter: { "predictive.severity": "block" },
  since: "1h",
});
```

CLI:

```bash
tlane trace 9f2c8a1b... --format timeline
# … shows predictive lane inline with tool/LLM lanes
```

## Eval coverage

| Pain point | Eval file | Predictive guard |
|---|---|---|
| PP-MCP1 | `evals/pain-points/PP-MCP1.eval.ts` | PR1 |
| PP-TFT1 | `evals/pain-points/PP-TFT1.eval.ts` | PR2 |
| PP-PI1 | `evals/pain-points/PP-PI1.eval.ts` | PR4 |
| PP-G3 | `evals/pain-points/PP-G3.eval.ts` | PR8 / PR8-lite |
| … | … | … |

Full mapping in [INDEX.md](./../evals/pain-points/INDEX.md).

## Performance budgets

The combined predictive layer must stay under the budget table at the top
of [CLAUDE.md](./../CLAUDE.md). `benchmark-runner` enforces:

- p50 add-on: <30ms
- p95 add-on: <50ms
- p99 add-on: <100ms

Any commit that pushes a guard's p95 over its individual budget is rejected
by `benchmark-runner` until the regression is fixed or the budget is
re-negotiated via an ADR.

## Related

- [`decisions/ADR-009-b1-prompt-promotion.md`](./../decisions/ADR-009-b1-prompt-promotion.md) — interacts with PR8 (post-promotion drift)
- [`decisions/ADR-011-path-to-live.md`](./../decisions/ADR-011-path-to-live.md) — wiring sequence
- [`evals/pain-points/INDEX.md`](./../evals/pain-points/INDEX.md) — claim ↔ eval map
- [`ml/slm_judge/README.md`](./../ml/slm_judge/README.md) — PR7 SLM judge
- [`ml/trajectory_guard/README.md`](./../ml/trajectory_guard/README.md) — full PR8 roadmap
