# `crates/` — Rust workspace

The Rust half of Tracelane: the gateway hot path, the ingest pipeline, and the
shared libraries they build on. Edition 2024, MSRV pinned in
`rust-toolchain.toml`. See `../docs/REPO_MAP.md` for how these fit the whole system.

| Crate | Role |
|---|---|
| [`gateway`](gateway/) | 35+ provider LLM router — BYOK envelope encryption, inline predictive guardrails, per-tenant entitlements + rate limits, circuit breaker + failover, tamper-evident audit ledger, Polar billing. The performance-critical hot path (zero allocations past `accept()`). |
| [`ingest`](ingest/) | OTLP receiver + NATS JetStream consumer → batched ClickHouse (hot) and R2 (cold) writes, with ack-after-write durability and ingest mTLS (SPIRE). |
| [`shared`](shared/) | Cross-crate types: universal chat `model`, `span` (OTel/OpenInference semconv), `TenantId` (constructible only from a JWT claim), credential `redact`ion. |
| [`policy`](policy/) | Cedar per-tenant access-control policy evaluation (routing, export, retention, predictive config). |
| [`mcp-rs`](mcp-rs/) | In-gateway MCP tool-description hash watcher (rug-pull detection). |
| [`tracelane-audit-cli`](tracelane-audit-cli/) | `tlane` audit-ledger CLI. |

**Rules:** `../.claude/rules/rust.md` (idiom), `../.claude/rules/security.md`
(auth/crypto/tenant). No `unwrap`/`expect` outside tests; `?`+`thiserror`
internally, `anyhow::Context` at boundaries; `ring`/`rustls`/`aws-lc-rs` only.
