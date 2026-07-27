# Contributing to Tracelane

Thank you for your interest in contributing. Tracelane is Apache 2.0 licensed
and welcomes contributions that align with its technical direction.

## Before you start

Read [`CLAUDE.md`](./CLAUDE.md) — it is the operating manual for all development
work in this repository. Contributions that violate conventions in CLAUDE.md
will not be merged.

Read the relevant [`decisions/`](./decisions/) ADRs before proposing
architectural changes. If you disagree with a decision, open an issue first.

---

## Prerequisites

| Tool | Version | Install |
|---|---|---|
| Rust | 1.87+ (pinned in `rust-toolchain.toml`) | [rustup.rs](https://rustup.rs) |
| Node.js | 22+ (pinned in `.nvmrc`) | [nodejs.org](https://nodejs.org) |
| pnpm | 9+ | `npm install -g pnpm` |
| Docker | 24+ | [docker.com](https://docker.com) |
| Python | 3.12+ | [python.org](https://python.org) |

Use the pinned versions in `rust-toolchain.toml` and `.nvmrc` exactly — CI enforces these.

## First-time setup

```bash
git clone https://github.com/tracelane/tracelane
cd tracelane

# Node dependencies
pnpm install

# Rust workspace
cargo build --workspace

# Start ClickHouse, Postgres, NATS, Redis
docker compose -f infra/dev/docker-compose.yml up -d

# Apply Postgres migrations
psql "$DATABASE_URL" -f infra/dev/postgres/migrations/01_init.sql
psql "$DATABASE_URL" -f infra/dev/postgres/migrations/02_audit_ledger.sql
psql "$DATABASE_URL" -f infra/dev/postgres/migrations/03_audit_keys.sql

# Apply ClickHouse schema
cat infra/dev/clickhouse/schema.sql | clickhouse-client --multiquery

# Python SDK dev install
pip install -e packages/sdk-python[dev]
pip install -e evals/

# Copy env template and fill in required vars
cp .env.example .env.local
```

Required env vars in `.env.local`:

| Var | Description |
|---|---|
| `DATABASE_URL` | Postgres DSN (default: `postgresql://tracelane:tracelane@localhost:5432/tracelane`) |
| `CLICKHOUSE_DSN` | ClickHouse DSN (default: `http://localhost:8123`) |
| `NATS_URL` | NATS JetStream URL (default: `nats://localhost:4222`) |
| `TRACELANE_AUDIT_MASTER_KEY` | AES-256 master key for BYOK envelope encryption (generate with `openssl rand -hex 32`) |
| `WORKOS_API_KEY` | WorkOS API key (sign up at workos.com) |
| `WORKOS_CLIENT_ID` | WorkOS client ID |
| `POLAR_ACCESS_TOKEN` | Polar.sh organization access token (sandbox token for local dev) |

## Running the stack

Open four terminals or use a process manager:

```bash
# Rust gateway (port 8080)
cargo run -p gateway

# Rust ingest workers (OTLP gRPC port 4317)
cargo run -p ingest

# Next.js dashboard (port 3000)
pnpm dev

# TypeScript MCP server (port 3001)
pnpm dev:mcp
```

Verify the stack is up:

```bash
curl http://localhost:8080/health   # gateway
curl http://localhost:3000/api/health  # dashboard
```

## Running tests

```bash
# Rust unit + integration
cargo test --workspace --all-features

# TypeScript unit (Vitest)
pnpm test

# Python SDK
pytest packages/sdk-python/

# Eval orchestrator
pytest evals/

# Full eval suite — merge gate, must pass before PR
pnpm eval:run --suite=all
```

CI fails if `pnpm eval:run --suite=all` regresses. Never disable an eval — mark it flaky in `evals/FLAKY.md` and fix within 48 hours.

## Linting and formatting

```bash
cargo fmt --check
cargo clippy --workspace -- -D warnings
pnpm lint        # Biome (not ESLint)
pnpm typecheck
ruff check .
ruff format --check .
```

All must pass before opening a PR.

## Benchmarks

Run before any hot-path change (gateway, ingest, predictive layer):

```bash
pnpm bench:gateway
pnpm bench:ingest
pnpm bench:predictive
```

A >10% regression blocks merge. Hard budgets:

| Surface | p99 |
|---|---|
| Gateway overhead | <25ms |
| Ingest end-to-end | <5s |
| Predictive layer | <100ms |
| Dashboard 10K-span load | <1s |

---

## How to contribute

### Bug reports

Open a GitHub issue using the bug report template. Include:
- Tracelane version (`tlane --version` or git SHA)
- Minimal reproduction
- Expected vs actual behavior
- Logs with sensitive data redacted

### Feature requests

Open a GitHub issue using the feature request template. Before doing so:
- Check `evals/pain-points/INDEX.md` — if the feature addresses a listed pain
  point, it may already be on the roadmap
- Describe the user pain, not just the solution

### Pull requests

1. Fork the repo and create a branch: `git checkout -b feat/your-feature`
2. Write the failing test or eval first (test-first for bug fixes)
3. Implement the change
4. Run the full check suite (see above)
5. Commit with Conventional Commits (`feat(gateway):`, `fix(ingest):`, `perf:`, `sec:`, etc.)
6. Open a PR against `main`

### Adding a new instrumentation adapter

1. Create `packages/sdk-python/src/tracelane/adapters/<name>.py` or `packages/sdk-typescript/src/adapters/<name>.ts`.
2. Follow the existing adapter pattern — wrap the provider client, emit OTel spans with GenAI semconv attributes.
3. Add the adapter to the table in the relevant SDK README.
4. Add or update the corresponding pain-point eval in `evals/pain-points/`.

### Conventions (non-negotiable)

- No `unwrap()` or `expect()` outside `#[cfg(test)]` — Clippy enforces this
- `tracing::instrument` on every new public async fn with `tenant_id` as a default field
- Every new ClickHouse query must have `WHERE tenant_id = ?` — CI rejects queries without it
- `tenant_id` comes from the JWT claim, never the request body
- No raw SQL strings in TypeScript — use `@clickhouse/client` parameter binding
- No `console.log` in committed code — use the structured logger
- No secrets in code — `gitleaks` + `trufflehog` run in pre-commit and CI
- `secrecy::SecretString` for any Rust field named `*_key`, `*_token`, `*_secret`
- Pin every external dependency version
- No new deps without `cargo audit` / `pnpm audit` / `pip-audit` clean

### Banned dependencies

Do not add: `litellm` (CVE-2026-42208), `arize-phoenix` (ELv2), `openssl` crate (use `rustls`), `eslint`/`prettier` (use Biome), `trivy` (CVE-2026-33634). Full list in `CLAUDE.md`.

### Security-sensitive changes

If your PR touches auth, crypto, PII handling, or the predictive layer, add the
label `needs-security-review`. The security reviewer uses deeper reasoning and
will check for OWASP Top 10, credential leakage, and tenant isolation invariants.

---

## License

By contributing, you agree that your contributions are licensed under the
Apache License 2.0 and that you have the right to submit them under that license.
We do not require a CLA for contributions from individuals.

## Code of Conduct

See [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md).
