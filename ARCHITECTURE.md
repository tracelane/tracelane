# Architecture index

This is a source index for the entry points present in this repository. It describes
where each surface starts; it does not make claims about deployment state or runtime
quality. See [`docs/architecture-diagrams.md`](docs/architecture-diagrams.md) for
code-derived diagrams and request flows.

## Runtime applications

| Entry point | What it is | Location |
|---|---|---|
| Gateway binary | Rust/Axum HTTP gateway. `main.rs` loads environment configuration and starts the server; `server.rs` assembles the routes. | [`crates/gateway/src/main.rs`](crates/gateway/src/main.rs), [`crates/gateway/src/server.rs`](crates/gateway/src/server.rs) |
| Ingest binary | Rust ingest process containing the OTLP HTTP receiver, NATS JetStream consumer, bounded span channel, and ClickHouse writer. | [`crates/ingest/src/main.rs`](crates/ingest/src/main.rs) |
| Web application | Next application containing the dashboard, application API routes, and Drizzle-backed control-plane data access. | [`apps/web/app/`](apps/web/app/), [`apps/web/package.json`](apps/web/package.json) |
| Public site | Astro application for the public site. | [`apps/site/src/`](apps/site/src/), [`apps/site/package.json`](apps/site/package.json) |
| Documentation source | MDX documentation-site content and navigation metadata. | [`apps/docs/`](apps/docs/) |
| MCP server | Node MCP server. It selects stdio by default or streamable HTTP by environment; its reader selects gateway HTTP or direct ClickHouse access. | [`apps/mcp/src/index.ts`](apps/mcp/src/index.ts), [`apps/mcp/src/reader.ts`](apps/mcp/src/reader.ts) |
| Audit CLI | Rust `tracelane-audit` command for fetching and verifying audit-ledger exports. | [`crates/tracelane-audit-cli/src/main.rs`](crates/tracelane-audit-cli/src/main.rs) |
| `tlane` CLI | TypeScript command-line package. | [`packages/cli/src/`](packages/cli/src/), [`packages/cli/package.json`](packages/cli/package.json) |

## Rust workspace libraries

| Crate | What it provides | Location |
|---|---|---|
| `tracelane-policy` | Policy and PII-redaction library consumed in process by gateway and ingest. | [`crates/policy/`](crates/policy/) |
| `tracelane-shared` | Shared types and helpers, including OTLP decoding and NATS stream/connection helpers. | [`crates/shared/`](crates/shared/) |
| `tracelane-audit-verifier` | Rust audit-ledger verification library used by the audit CLI and gateway. | [`packages/verifier-rust/`](packages/verifier-rust/) |

The Cargo workspace membership is declared in [`Cargo.toml`](Cargo.toml).

## Installable SDKs and libraries

| Package | What it is | Location |
|---|---|---|
| Python SDK | Python agent-instrumentation SDK. | [`packages/sdk-python/`](packages/sdk-python/) |
| TypeScript SDK | TypeScript agent- and MCP-instrumentation SDK. | [`packages/sdk-typescript/`](packages/sdk-typescript/) |
| UI package | Shared TypeScript UI package. | [`packages/ui/`](packages/ui/) |
| Python verifier | Python audit-ledger verifier. | [`packages/verifier-python/`](packages/verifier-python/) |
| TypeScript verifier | TypeScript audit-ledger verifier. | [`packages/verifier-typescript/`](packages/verifier-typescript/) |
| Rust verifier | Rust audit-ledger verifier and Cargo workspace library. | [`packages/verifier-rust/`](packages/verifier-rust/) |

The pnpm workspace membership is declared in [`pnpm-workspace.yaml`](pnpm-workspace.yaml),
and the package roles are summarized in [`packages/README.md`](packages/README.md).

## Schemas and migrations

| Store / mechanism | Source locations |
|---|---|
| Web Drizzle schema and migration journal | [`apps/web/db/schema.ts`](apps/web/db/schema.ts), [`apps/web/db/migrations/`](apps/web/db/migrations/) |
| Development PostgreSQL migrations | [`infra/dev/postgres/migrations/`](infra/dev/postgres/migrations/) |
| Development ClickHouse base schema and migrations | [`infra/dev/clickhouse/schema.sql`](infra/dev/clickhouse/schema.sql), [`infra/dev/clickhouse/migrations/`](infra/dev/clickhouse/migrations/) |
| Self-host ClickHouse schema | [`infra/self-host/clickhouse/schema.sql`](infra/self-host/clickhouse/schema.sql), [`infra/self-host/clickhouse/02_slo_alerting.sql`](infra/self-host/clickhouse/02_slo_alerting.sql) |
| Public-site SQL migration | [`apps/site/migrations/`](apps/site/migrations/) |

This index does not designate an authority among the four application/development
PostgreSQL and ClickHouse schema/migration locations. No single top-level document in
the examined tree explains their combined authority and application order.

## Compose environments

| Environment | Services declared by its Compose file | Location |
|---|---|---|
| Contributor development data plane | ClickHouse, NATS JetStream, PostgreSQL, and Grafana. It does not declare gateway, ingest, web, site, or MCP services. | [`infra/dev/docker-compose.yml`](infra/dev/docker-compose.yml) |
| Single-node self-host | ClickHouse, NATS JetStream, gateway, and ingest. It does not declare PostgreSQL, Grafana, web, site, or MCP services. | [`infra/self-host/docker-compose.yml`](infra/self-host/docker-compose.yml) |

## Specifications, model work, evaluations, and benchmarks

| Area | Contents | Location |
|---|---|---|
| Specifications | AFT and OpenAgentTrace documents and schema. | [`spec/`](spec/) |
| Model work | Python training, serving, distillation, and export projects for prompt guard, SLM judge, and trajectory guard. | [`ml/`](ml/) |
| Evaluations | TypeScript evaluation suites and fixtures. | [`evals/`](evals/) |
| Benchmarks | Gateway, ingest, and supporting benchmark material. | [`bench/`](bench/) |
