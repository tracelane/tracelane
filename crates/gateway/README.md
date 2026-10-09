<!-- tracelane:classification: PUBLIC -->
# crates/gateway

Tracelane's Rust gateway — the performance-critical hot path.

## Responsibility

- Proxy LLM requests from customer agents to 205 providers (BYOK, zero markup)
- Run the predictive guardrail layer inline on every request
- Emit OTLP spans to NATS JetStream for ingest
- Maintain a tamper-evident SHA-256 audit log with Ed25519 Merkle commitments

## Key modules

| Module | Purpose |
|---|---|
| `main.rs` | Binary entry point — initialise logging, load config, start server |
| `server.rs` | Axum router and boot — config, `AppState`, every route mount, admission layer, `/health` |
| `server/` | The request path, one file per concern — `chat.rs` (`POST /v1/chat/completions`), `embeddings.rs`, `dispatch.rs` (BYOK key + provider dispatch + retry), `stream.rs` (SSE), `buffered.rs`, `spans.rs`, `errors.rs`, `quota.rs` |
| `admission.rs` | The ONE admission pipeline every inference route runs — auth → scope → parse → entitlements + rate limit → quota → budgets → predictive → audit publish |
| `providers/` | Provider adapters (Anthropic, OpenAI, Gemini, Bedrock, Together, …) |
| `predictive/` | Predictive guardrail layer — MCP hash watcher, taint tracker, A2UI, A2A, … |
| `audit.rs` | SHA-256 hash chain — compute_row_hash(), Rekor anchoring queue |
| `auth/` | WorkOS JWKS, API key, SPIFFE mTLS — tenant_id always from JWT claim |
| `rate_limiter.rs` | Per-tenant token bucket — free/builder/team/business RPM limits |
| `otlp_emit.rs` | OTLP span emission to NATS — zero-copy on hot path |

## Performance

No latency or throughput figure is published for this crate beyond what `apps/docs/benchmarks.mdx` reports; a live-perf eval is skipped in CI (it needs a real gateway).

## Security invariants

- Provider keys never in logs or spans (tracing redaction filter)
- `tenant_id` always from JWT claim, never request body
- No `unwrap()` outside `#[cfg(test)]` — enforced by clippy
