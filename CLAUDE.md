# Tracelane — CLAUDE.md (Public Version)

This file is the technical operating manual for Claude Code working in this repository.
Read it fully before any non-trivial task.

## What we're building

Tracelane is the predictive reliability platform for AI agents. Apache 2.0 OSS,
combining a Rust gateway, ClickHouse-backed observability, and a predictive
guardrail layer.

Customers point agent traffic at Tracelane and get: provider failover across 30+
providers, low gateway overhead, full-fidelity trace capture with
tamper-evident audit logs, MCP rug-pull detection, lethal-trifecta taint
tracking, A2UI catalog conformance, browser stuck-loop prediction, A2A handoff
validation, distilled SLM judges, time-travel debugging, and CI-gate evals.

## Architecture

Five components in one monorepo:

1. **Rust gateway** (`crates/gateway/`) — Axum + tokio, BYOK, OTLP emit, predictive layer inline
2. **Rust ingest workers** (`crates/ingest/`) — OTLP receiver, NATS consumer, ClickHouse batched writes
3. **Next.js 15 dashboard** (`apps/web/`) — App Router, Tailwind 4, shadcn/ui, Motion, in-house transcript-spine viewer (SVG/DOM)
4. **TypeScript MCP server** (`apps/mcp/`) — read-only, tenant-scoped, OAuth 2.1
5. **Python eval orchestrator** (`evals/`) — DeepEval + Ragas + Inspect AI

Plus packages: `packages/sdk-python/`, `packages/sdk-typescript/`, `packages/cli/`.
Plus ML: `ml/trajectory_guard/`, `ml/slm_judge/`, `ml/eval_corpus/`.

## Coding conventions

### Rust (gateway, ingest, predictive layer)
- Edition 2024, MSRV pinned in workspace Cargo.toml
- `cargo fmt` and `cargo clippy --workspace -- -D warnings` blocking on CI
- No `unwrap()` or `expect()` outside tests — clippy enforces
- `tokio` only; `axum 0.8+`; `tracing` JSON in prod
- RPITIT (return-position impl-trait in trait), not `async-trait`, in hot path
- Crypto: `ring`, `rustls`, `aws-lc-rs` only — never `openssl`
- `tracing::instrument` on every public async fn with default field `tenant_id`
- `anyhow::Context` at API boundaries, `thiserror` for internal errors

### TypeScript (dashboard, MCP server, SDK, CLI)
- TS 5.5+ strict mode; `noUncheckedIndexedAccess: true`
- Biome (not ESLint+Prettier)
- React 19 + Next.js 15 App Router; RSC by default
- shadcn/ui + Motion + Tailwind 4
- Drizzle ORM + `@clickhouse/client` parameter binding; never raw SQL strings
- TanStack Query + Zustand for client state
- Vitest + Playwright for testing

### Python (eval orchestrator, SDK, ML pipeline)
- Python 3.12+
- Ruff for lint and format
- Pydantic v2 for all schemas
- pytest + pytest-asyncio for testing

### SQL (ClickHouse)
- Every query starts `WHERE tenant_id = ?` — CI grep blocks any new SQL without it
- ORDER BY `(tenant_id, ...)`, PARTITION BY `toYYYYMM(timestamp)`

## Performance budgets

| Metric | p99 |
|---|---|
| Gateway overhead (excl. provider time) | <25ms |
| Ingest end-to-end | <5s |
| Dashboard 10K-span trace load | <1s |
| Predictive layer (inline) | <100ms |
| SLM judge (1B encoder, L4 GPU) | <200ms |

## Security

- No secrets in code
- BYOK only — provider keys envelope-encrypted at rest with `aws-lc-rs` AEAD (AWS KMS in prod)
- Provider keys NEVER appear in logs, spans, or errors
- Tenant isolation is structural — every ClickHouse query has `WHERE tenant_id = ?`
- `tenant_id` always from JWT claim, never request body
- mTLS for ingest; TLS 1.3 minimum for external

## Build / test / lint

```bash
pnpm install && cargo build --workspace
docker compose -f infra/dev/docker-compose.yml up -d

pnpm lint && pnpm typecheck
cargo fmt --check && cargo clippy --workspace -- -D warnings
ruff check . && ruff format --check .

pnpm test && cargo test --workspace --all-features && pytest
pnpm eval:run --suite=all
```

## DO

- Read CONTRIBUTING.md and SECURITY.md before contributing
- `tracing::instrument` on every public async fn, default field `tenant_id`
- Treat the 50 pain points in `evals/pain-points/` as test assertions
- Pin every external dependency version
- Test-first when fixing bugs

## DON'T

- `unwrap()` outside tests
- Query ClickHouse without `tenant_id` filter
- Write raw SQL strings in TypeScript
- Use `console.log` in committed code — use structured logger
- Hard-code a model name in business logic
