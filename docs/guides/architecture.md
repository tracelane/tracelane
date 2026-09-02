<!-- tracelane:classification: PUBLIC -->
# Architecture

> Read this when you need to know which process does what — who writes spans,
> where the tenant boundary is, and which key signs which artifact in the audit
> ledger.

A 30,000-foot view of what's running when you send a request through
Tracelane. Five components, one monorepo.

```
                    ┌──────────────────────────────────────────────────┐
                    │  YOUR AGENT  (any OpenAI-compatible client)       │
                    └──────────────────────────┬───────────────────────┘
                                               │ HTTPS  POST /v1/chat/completions
                                               ▼
        ┌─────────────────────────────────────────────────────────────┐
        │  ① Rust gateway (Axum, tokio, ring)                          │
        │  ───────────────────────────────────────────────────────────  │
        │  • Auth: JWT or tlane_<key>  →  TenantId from claim only     │
        │  • Detection layer (observe-first; MCP / agent-tool payloads)│
        │  • Inline guardrail rails (8, request + response side)        │
        │  • Audit publish (v2 SHA-256 chain, PII pre-redacted)        │
        │  • Dispatch to 150+ providers (prefix-routed, fail-closed)    │
        │  • 1 same-provider retry; cross-provider failover is opt-in  │
        │  • OTLP emit → NATS JetStream (NATS_URL required at boot)    │
        └────────────┬─────────────────────────┬──────────────────────┘
                     │ HTTPS to provider         │ NATS publish
                     ▼                           ▼
       ┌──────────────────────┐   ┌──────────────────────────────────┐
       │ Anthropic / OpenAI / │   │ ② Rust ingest workers             │
       │ Bedrock / Google /   │   │ ──────────────────────────────────│
       │ … 150+ routable       │   │ • NATS JetStream consumer        │
       └──────────────────────┘   │ • Span enrichment + PII redact    │
                                  │ • ClickHouse batched insert       │
                                  │   (ack AFTER the flush)           │
                                  └────┬─────────────────────────────┘
                                       │
                                       ▼
                              ┌───────────────────┐
                              │ ClickHouse hot    │
                              │ (90d TTL)         │
                              └─────────┬─────────┘
                                        │  reads only via the gateway's /v1/* routes
                                        ▼
        ┌─────────────────────────────────────────────────────────────┐
        │ ③ Next.js 15 dashboard (apps/web)                           │
        │  • /traces — transcript-spine waterfall (no WebGL)          │
        │  • /prompts/[name] — B1 prompt-promotion view + timeline    │
        │  • /audit — ledger + offline-verification panel              │
        │  • /settings/billing — Polar customer-portal launcher        │
        └─────────────────────────────────────────────────────────────┘

  ④ TypeScript MCP server  (apps/mcp)            ⑤ Python eval orchestrator (evals/)
     read-only; bearer auth via the gateway's        DeepEval + Ragas + Inspect AI
     /v1/auth/whoami. Not published to a
     registry — build it from source.
```

> **R2 cold tier is code, not a live path.** `crates/ingest/src/r2_batcher.rs`
> exists and buffers **NDJSON** (not Parquet), but nothing ever feeds its
> channel — `crates/ingest/src/main.rs:350` drops the sender. No span has ever
> been written to R2. It is drawn nowhere above on purpose.

---

## Source-of-truth split

Two databases with different roles — and the part that trips people up is
*which process writes what*:

| Data | Written by | Database |
|---|---|---|
| `spans` | **ingest only** — `crates/ingest/src/clickhouse_writer.rs:374`. The gateway never writes a span; it publishes to NATS and ingest is the sole writer. | ClickHouse (hot, 90d TTL) |
| `audit_log` · `audit_anchor_records` · `guardrail_verdicts` · `promotion_decisions` · `rollback_events` · `prompt_versions` | gateway | ClickHouse |
| tenants · api_keys · users · workspace_entitlements · alert_rules · tool_capabilities · webhook_events | gateway + `apps/web` (Drizzle) | Postgres (Neon-compatible) |

R2 has no row in this table because nothing writes to it — see the note under
the diagram.

The split is structural: ClickHouse is for observations, Postgres for
identity. Cross-DB joins happen client-side in the dashboard layer.

---

## Tenant isolation

Every ClickHouse query has `WHERE tenant_id = ?` as the first clause.
A CI grep blocks any new SQL without it. The `tenant_id` flows from a
verified JWT claim or API-key Postgres lookup — **never** from a
request body or header. This is enforced structurally by Rust's type
system: `TenantId` has exactly **three** named constructors, one per trust
boundary, so `grep 'TenantId::from_'` enumerates every one
(`crates/shared/src/tenant.rs`):

| Constructor | Line | Trust boundary |
|---|---|---|
| `TenantId::from_jwt_claim` | `:25` | a WorkOS JWT whose signature the caller has already verified against the JWKS |
| `TenantId::from_spiffe_svid` | `:33` | a verified SPIFFE X.509-SVID (the ingest mTLS path) |
| `TenantId::from_self_host_config` | `:45` | the single operator-configured tenant of a self-host deployment, reachable only in single-tenant mode |

There is no `From<String>`, no deserialization shortcut, and no fourth door.
See [SECURITY.md](../../SECURITY.md).

---

## Predictive guardrail layer

The gateway runs the detection layer **inline** on every request. These are
**inline heuristic guardrails**; the ML ensemble is on the roadmap. Detection is
observe-first by design — a false-positive block is worse than the failure it prevents.

Shipped and able to return a verdict today
(`crates/gateway/src/predictive/mod.rs`):

| ID | Name |
|---|---|
| PR1 | MCP tool-description hash watcher |
| — | Tool-definition drift (name kept, schema mutated) |
| PR2 | Lethal-trifecta taint tracker |
| PR4 | Browser-agent stuck-loop detector |
| PR5 | CAPTCHA / bot-wall pre-empter |
| — | Prompt-injection heuristics |
| PR3 | A2UI catalog conformance |
| — | A2A handoff validator |
| PR8-lite | Argument-distribution drift (Mahalanobis, bag-of-bytes extractor) |
| PR13 | Tool-call schema validation |
| — | Browser-agent passive observer (`tracelane.browser.step_index`) |

**Important — most of the above do not fire on `/v1/chat/completions` today.** They gate
on payload fields (`mcp_server_name`, `tool_name`, `a2a_handoff`, `protocol`,
`tracelane.browser.step_index`) that a chat-completions request does not carry. They fire
on MCP and agent-tool traffic. This is the same disclosure as `README.md`; what runs
inline on chat traffic is the guardrail rail set.

**Roadmap — registered but returning a constant.** Trajectory Guard and the inline SLM
judge are wired into the stack with their `ort` inference call commented out, so they
cannot currently produce a verdict. Replay-against-a-known-bad-corpus is not implemented.
Do not plan against these. (The retired `PRn` numbering is deliberately dropped here — the
same label meant different things across doc generations.)

Each returns `Allow | Warn | Block` with an `aft_id` for marker. A `Block` is
**recorded, not enforced**, unless the operator sets
`TRACELANE_PREDICTIVE_ENFORCE=1` — the observe-first default
(`crates/gateway/src/server.rs:1138-1163`).

---

## Tamper-evident audit chain

Every **admitted** gateway request appends one row to `audit_log`. "Admitted"
is load-bearing: auth failure, the RPM 429, the monthly-quota 429 and an
enforced predictive block all return *before* the audit publish
(`server.rs:1064` / `:1119` / `:1152` vs the publish at `:1202`), so a
throttled request leaves no ledger row. The publish itself is **fail-closed** —
if it cannot be recorded, the request is refused with `503 audit_unavailable`.

The chain hash is the **v2** encoding
(`crates/gateway/src/audit_format/mod.rs:102-134`):

```
lp(x)    = u64_be(len(x)) ‖ x            // length-prefixed — no field-boundary ambiguity
row_hash = SHA256(
             "tracelane-audit-row-v2\0"
             ‖ lp(tenant_id_bytes)        // 16-byte UUID
             ‖ u64_be(seq)
             ‖ lp(event_type)
             ‖ lp(actor)
             ‖ lp(payload_canonical_json) // RFC 8785 JCS
             ‖ lp(prev_hash)              // 32 bytes
           )

prev_hash[seq=0] = SHA256("tracelane-audit-v2-genesis\0" ‖ tenant_id_bytes)
```

The Merkle tree is RFC 6962 §2.1 — `leaf = SHA256(0x00 ‖ data)`,
`node = SHA256(0x01 ‖ L ‖ R)`, a lone odd element **promoted** rather than
duplicated.

> The earlier v1 format is `#[deprecated]` in
> `crates/gateway/src/audit.rs:159-171` (row hash) and `:177-203` (Merkle root),
> and kept only to re-verify pre-migration rows. Its own deprecation notes say
> why: the `|`-separated row hash is **vulnerable to field-boundary attacks**
> (`actor` is attacker-controlled, so `alice|0|request|bob` re-partitions the
> input), and the duplicate-last Merkle tree is **second-preimage-vulnerable**.
> Do not implement against it.

### Two keys, two jobs — do not conflate them

Every 100 events by default (`TRACELANE_REKOR_ANCHOR_EVERY`) the batch's Merkle
root is closed out, and **two different keys** sign two different things
(byte formats frozen):

| Key | Algorithm | Signs | Why this algorithm |
|---|---|---|---|
| Local attestation | **Ed25519**, per tenant | `"tracelane-audit-ed25519-v1\0" ‖ root ‖ anchor_commitment` | the offline trust root — this is the key `tlane verify --tenant-pubkey` takes (`audit.rs:237-239`) |
| Rekor anchor | **ECDSA-P256** (SHA-256, ASN.1 DER), per tenant | `"tracelane-anchor-ecdsa-v1\0" ‖ root`, submitted as a Rekor v2 `hashedrekord` | Rekor v2's hashedrekord **rejects pure Ed25519** — it loads the verifier with `WithED25519ph` (`audit_keys.rs:92-97`) |

So: **Ed25519 is the local-attestation signer; the thing that goes to Sigstore
Rekor v2 is signed with ECDSA-P256.** The `anchor_commitment` binds the anchor's
identity (ECDSA SPKI hash, log URL hash, log index) into the Ed25519 message, so
a stripped, swapped or downgraded bundle fails offline verification.

Anchoring is **best-effort**: an unanchored batch is still signed and still
verifies, and the verifier reports the anchor state honestly rather than
claiming coverage it does not have. Customers verify offline using any of three
byte-identical reference implementations (`packages/verifier-rust`,
`verifier-python`, `verifier-typescript`).

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

The write path (`promote` / `rollback` / `observe`) is gated on the Team-tier
`f_prompt_promotion_write` entitlement and **fails closed with 503** when no
entitlement source is reachable. Reads are not gated.

---

## Trust + supply chain

- Apache 2.0 + License Pledge (no relicense to BSL/SSPL/ELv2)
- Trusted Publishing OIDC (no long-lived crates.io / npm / PyPI tokens)
- Cosign **keyless** `sign-blob` over every release binary + the SBOM, with the
  Sigstore bundle attached alongside each asset
- `actions/attest-build-provenance` on the release artifacts
- CycloneDX SBOM attached to every release
- OpenSSF Scorecard ≥ 9.0 **target** (the workflow runs; the score is not a claim)
- 3-language byte-identical audit verifier (offline reproducibility)

Tracelane makes **no** eIDAS or qualified-timestamp claim, and does not claim a
verified SLSA Level 3 attestation.

---

## Performance budgets (internal CI targets)

These are **internal CI targets**, not measured public benchmarks. The
Benchmarks workflow measures p95 against them. It runs on a schedule or by dispatch, not on pull requests. The same
budgets are the merge gate documented in
[CONTRIBUTING.md](../../CONTRIBUTING.md). Published, independently measured
figures ship with the Reliability Benchmark v1.0; **until then no public
performance numbers are quoted here** — including in the diagram above.

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

These targets are measured by the Benchmarks workflow, which runs on a schedule or by dispatch rather than on every PR
touching the hot path; measured public figures publish with the benchmark.

---

## Repository layout

```
crates/
  gateway/              Rust gateway (Axum + tokio) — the whole hot path
  ingest/               Rust ingest workers (NATS → ClickHouse)
  policy/               PII redaction (used by gateway + ingest).
                        `policy/engine.rs` is an UNWIRED Cedar scaffold —
                        no call sites, no `cedar-policy` dependency, and
                        every method returns Deny.
  shared/               universal types (ChatRequest, TenantId, TracelaneSpan, …)
  tracelane-audit-cli/  standalone `tracelane-audit` verifier binary

apps/
  web/            Next.js 15 dashboard (Cloudflare Workers)
  mcp/            TypeScript MCP server — read-only, build from source
  docs/           Mintlify documentation site

packages/
  cli/                       tlane CLI            (npm @tracelanedev/cli)
  sdk-python/                (PyPI  tracelane)
  sdk-typescript/            (npm   @tracelanedev/sdk)
  verifier-rust/, verifier-python/, verifier-typescript/
  ui/                        shared design tokens + components

bench/            k6 + criterion benchmark harnesses
evals/            Pain-point + fault-tolerance + provider correctness evals
ml/               Trajectory guard, SLM judge, eval corpus
infra/dev/        docker-compose for the local stack
infra/self-host/  single-tenant self-host deployment
docs/guides/      these guides
```

> `crates/mcp-rs` does not exist. The MCP server is TypeScript only
> (`apps/mcp`), and it is **not published to npm** — the release workflow
> publishes exactly three JS packages (`@tracelanedev/audit-verifier`,
> `@tracelanedev/sdk`, `@tracelanedev/cli`), so `npx @tracelanedev/mcp` will
> not resolve. Build it from source and point your client at the built entry.
