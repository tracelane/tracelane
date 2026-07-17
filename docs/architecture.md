# Architecture

A 30,000-foot view of what's running when you send a request through
Tracelane. Five components, one monorepo, ~10 ms p99 added overhead.

```
                    ┌──────────────────────────────────────────────────┐
                    │  YOUR AGENT  (any OpenAI / Anthropic / Bedrock SDK) │
                    └──────────────────────────┬───────────────────────┘
                                               │ HTTPS
                                               ▼
        ┌─────────────────────────────────────────────────────────────┐
        │  ① Rust gateway (Axum, tokio, ring)                          │
        │  ───────────────────────────────────────────────────────────  │
        │  • Auth: JWT or tlane_<key>  →  TenantId from claim only     │
        │  • Predictive layer (PR1–PR8, ~50 ms p99 inline)             │
        │  • Audit append (SHA-256 chain, PII pre-redacted)            │
        │  • Provider dispatch (35 adapters, prefix-routed)            │
        │  • Failover chain (5xx + retryable codes only)               │
        │  • OTLP emit → NATS JetStream                                 │
        └────────────┬─────────────────────────┬──────────────────────┘
                     │ HTTPS to provider         │ NATS publish
                     ▼                           ▼
       ┌──────────────────────┐   ┌──────────────────────────────────┐
       │ Anthropic / OpenAI / │   │ ② Rust ingest workers             │
       │ Bedrock / Google /   │   │ ──────────────────────────────────│
       │ … 30+ providers       │   │ • NATS JetStream consumer        │
       └──────────────────────┘   │ • Span enrichment + PII redact    │
                                  │ • ClickHouse batched insert       │
                                  │ • R2 cold-tier Parquet (90d+)    │
                                  └────┬────────────────────┬────────┘
                                       │                    │
                                       ▼                    ▼
                              ┌───────────────────┐  ┌──────────────┐
                              │ ClickHouse hot    │  │ Cloudflare R2│
                              │ (90d retention)   │  │ (indefinite) │
                              └─────────┬─────────┘  └──────┬───────┘
                                        │                    │
                                        ▼                    ▼
        ┌─────────────────────────────────────────────────────────────┐
        │ ③ Next.js 15 dashboard (apps/web)                           │
        │  • /traces — WebGL waterfall (deck.gl)                      │
        │  • /prompts/[name] — B1 prompt-promotion view + timeline    │
        │  • /trust — public Trust Center                              │
        │  • /billing — Polar customer-portal launcher                 │
        └─────────────────────────────────────────────────────────────┘

  ④ TypeScript MCP server  (apps/mcp)            ⑤ Python eval orchestrator (evals/)
     read-only, OAuth 2.1, npx @tracelanedev/mcp        DeepEval + Ragas + Inspect AI
```

---

## Source-of-truth split

The gateway writes to **two** databases with different roles:

| Data | Database | Why |
|---|---|---|
| Spans / audit_log / prompt_versions / promotion_decisions / rollback_events | **ClickHouse** (hot, 90d) + R2 (cold, indefinite) | High-cardinality observational data, append-only, columnar wins. |
| Tenants / api_keys / users / admin_audit | **Postgres** (Neon-compatible) | Low-cardinality metadata, OLTP, joins via foreign keys. |

The split is structural: ClickHouse is for observations, Postgres for
identity. Cross-DB joins happen client-side in the dashboard layer.

---

## Tenant isolation

Every ClickHouse query has `WHERE tenant_id = ?` as the first clause.
A CI grep blocks any new SQL without it. The `tenant_id` flows from a
verified JWT claim or API-key Postgres lookup — **never** from a
request body or header. This is enforced structurally by Rust's type
system: the `TenantId` type can only be constructed via
`TenantId::from_jwt_claim(uuid)` (see [SECURITY.md](../SECURITY.md)).

---

## Predictive guardrail layer

The gateway runs the predictive layer **inline** on every request,
under a 50 ms p99 budget. V1 ships eight predictors:

| ID | Name | Tier |
|---|---|---|
| PR1 | MCP Tool-Description Hash Watcher | Builder |
| PR2 | Lethal-Trifecta Taint Tracker | Builder |
| PR3 | A2UI Catalog Conformance | Team |
| PR4 | Browser-Agent Stuck-Loop Predictor | Builder |
| PR5 | CAPTCHA / Bot-Wall Pre-empter | Builder |
| PR6 | Replay-Against-Known-Bad Corpus | Team |
| PR7 | Trajectory Guard (autoencoder) | Team |
| PR8-lite | Argument-Distribution Drift (Mahalanobis) | Team |

Each returns `Allow | Warn | Block` with an `aft_id` for marker. See
[predictive-guardrails.md](predictive-guardrails.md).

---

## Tamper-evident audit chain

Every gateway request appends one row to `audit_log` with a chain
hash:

```
row_hash = SHA256(tenant_id ‖ seq ‖ event_type ‖ actor ‖ payload_json ‖ prev_hash)
```

Every 100 rows, the Merkle root over the batch is signed (Ed25519)
and submitted to **Sigstore Rekor v2** — a public, append-only
transparency log. Customers verify offline using any of three
byte-identical reference implementations (Rust / Python / TypeScript)
shipped alongside the audit-export endpoint.

Format spec: [audit-format.md](audit-format.md).

---

## B1 prompt promotion

A separate routing layer for managed prompts. Customers register
versions, run eval suites, and promote `staging → production` via
either CLI (`tlane prompt promote`) or HTTP (`POST
/v1/prompts/:name/promote`). Production traffic uses an `ArcSwap`
pointer — promote is wait-free; no request ever sees a half-applied
state.

EWMA-based per-prompt-version drift detection (cost / latency /
error_rate / accuracy / hallucination_rate) auto-rolls-back on
2σ drift for objective metrics, suggests rollback for subjective.

ADR: [ADR-009](../decisions/ADR-009-prompt-promotion-v1.md).

---

## Trust + supply chain

- Apache 2.0 + License Pledge (no relicense to BSL/SSPL/ELv2)
- Trusted Publishing OIDC (no long-lived crates.io / npm / PyPI tokens)
- Sigstore-signed releases on every artifact
- CycloneDX SBOM attached to every release
- OpenSSF Scorecard ≥ 9.0 target
- 3-language byte-identical audit verifier (offline reproducibility)

See [Trust Center](https://app.tracelane.dev/trust).

---

## Performance budgets (internal CI targets)

These are **internal CI targets**, not measured public benchmarks — the
`benchmark-runner` subagent rejects PRs that push any p95 over budget. Published,
independently measured figures ship with the [Reliability Benchmark v1.0](benchmarks/index.md);
until then no public performance numbers are quoted.

| Metric (internal target) | p50 | p95 | p99 |
|---|---|---|---|
| Gateway overhead (excl. provider time) | <5 ms | <15 ms | <25 ms |
| Ingest end-to-end | <1 s | <3 s | <5 s |
| Dashboard 10K-span trace load | <200 ms | <500 ms | <1 s |
| MCP query (filtered, indexed) | <50 ms | <150 ms | <300 ms |
| Predictive layer (inline) | <30 ms | <50 ms | <100 ms |

Throughput floors are likewise internal targets pending the Reliability Benchmark v1.0:
- High-throughput single-node and multi-node ingest
- Single-instance gateway throughput with full tracing on

These targets are enforced by the `benchmark-runner` subagent on every PR
touching the hot path; measured public figures publish with the benchmark.

---

## Repository layout

```
crates/
  gateway/        Rust gateway (Axum + tokio)
  ingest/         Rust ingest workers (NATS → ClickHouse + R2)
  mcp-rs/         (reserved for future Rust MCP impl)
  policy/         Cedar + PII redaction
  shared/         universal types (ChatRequest, TenantId, …)

apps/
  web/            Next.js 15 dashboard
  mcp/            TypeScript MCP server (npx @tracelanedev/mcp)
  docs/           (this site — Mintlify when published)

packages/
  cli/                       tlane CLI
  sdk-python/, sdk-typescript/
  verifier-rust/, verifier-python/, verifier-typescript/

evals/            Pain-point + fault-tolerance + provider correctness evals
ml/               Trajectory guard, SLM judge, eval corpus
infra/dev/        docker-compose for local stack
decisions/        ADRs (numbered, append-only)
docs/             User + operator + architecture docs
runbooks/         Incident-response runbooks (auto-generated by incident-responder agent)
```
