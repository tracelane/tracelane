<!-- tracelane:classification: PUBLIC -->
# `crates/` — Rust workspace

The Rust half of Tracelane: the gateway hot path, the ingest pipeline, and the
shared libraries they build on. Edition 2024, MSRV pinned in
`rust-toolchain.toml`. See the root `README.md` for how these fit the whole system.

| Crate | Role |
|---|---|
| [`gateway`](gateway/) | 191-provider LLM router (`providers.tsv` catalog + 6 native adapters) — BYOK envelope encryption, inline predictive guardrails, per-tenant entitlements + rate limits, circuit breaker + failover, tamper-evident audit ledger, Polar billing. The performance-critical hot path. |
| [`ingest`](ingest/) | OTLP receiver + NATS JetStream consumer → batched ClickHouse writes, with ack-after-write durability and ingest mTLS. |
| [`shared`](shared/) | Cross-crate types: universal chat `model`, `span` (OTel/OpenInference semconv), `TenantId` (constructible only from a JWT claim), credential `redact`ion. |
| [`policy`](policy/) | PII redaction used by the audit path. A Cedar policy engine is scaffolded here but is **not wired into the gateway in V1** — per-tenant authorization is Postgres `workspace_entitlements`. |
| [`tracelane-audit-cli`](tracelane-audit-cli/) | `tlane` audit-ledger CLI. |

**Rules:** the Rust idiom and security conventions cover auth, crypto and tenant handling. No `unwrap`/`expect` outside tests; `?`+`thiserror`
internally, `anyhow::Context` at boundaries; `ring`/`rustls`/`aws-lc-rs` only.
