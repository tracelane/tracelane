<!-- tracelane:classification: PUBLIC -->
# Contributing to Tracelane

Thank you for your interest in contributing. Tracelane is Apache 2.0 licensed
and welcomes contributions that align with its technical direction.

## Before you start

Read [`CLAUDE.md`](./CLAUDE.md) — it is the operating manual for all development
work in this repository. Contributions that violate conventions in CLAUDE.md
will not be merged.

Read the [architectural decisions](https://docs.tracelane.dev/decisions) index before proposing
architectural changes. If you disagree with a decision, open an issue first.

---

## Prerequisites

| Tool | Version | Install |
|---|---|---|
| Rust | 1.95 (pinned in `rust-toolchain.toml`; published-crate MSRV is 1.88) | [rustup.rs](https://rustup.rs) |
| Node.js | 22+ (`package.json` `engines.node`) | [nodejs.org](https://nodejs.org) |
| pnpm | 9+ | `npm install -g pnpm` |
| Docker | 24+ | [docker.com](https://docker.com) |
| Python | 3.12+ | [python.org](https://python.org) |

Use the pinned versions in `rust-toolchain.toml` and `package.json` (`engines`, `packageManager: pnpm@9.15.0`) exactly.

## First-time setup

```bash
git clone https://github.com/tracelane/tracelane
cd tracelane

# Enable the repo's git hooks. DO THIS FIRST — see the note below.
git config core.hooksPath .githooks

# Node dependencies
pnpm install

# Rust workspace
cargo build --workspace

# Start ClickHouse, Postgres, NATS, Grafana
docker compose -f infra/dev/docker-compose.yml up -d

# Apply Postgres migrations
# Drizzle is canonical for the control plane (apps/web/db/schema.ts). Applying the
# three legacy .sql files below would give you 3 of 17, and the schema has since moved
# to Drizzle — an incomplete control plane fails at runtime, not here.
#
# READ THIS BEFORE YOU ASSUME THE SCHEMA IS COMPLETE. `drizzle-kit migrate` applies
# only the 9 JOURNALLED migrations (`meta/_journal.json` ends at 0008). There are 30
# .sql files on disk; 0009+ are hand-written Neon migrations applied out-of-band and
# deliberately un-journaled, so this command gives you 9 of 30. That is enough for the
# gateway to boot and for most local work, and it is NOT the production schema.
pnpm --filter @tracelanedev/web exec drizzle-kit migrate

# infra/dev/postgres/migrations/ is RETAINED FOR REFERENCE, not for applying: several
# evals and guards read those files. Do not run them by hand and do not delete them.

# Apply ClickHouse schema
cat infra/dev/clickhouse/schema.sql | clickhouse-client --multiquery

# Python SDK dev install
pip install -e packages/sdk-python[dev]
pip install -e evals/

# Copy env template and fill in required vars
cp .env.example .env.local
```

> **`git config core.hooksPath .githooks` is not optional, and nothing will remind you.**
> **On the PUBLIC mirror `.githooks/` is not present** — it is withheld from the export,
> so this command silently configures a path that does not exist and no hook runs. The
> gating described here happens in the canonical repo before anything is exported.
>
> `core.hooksPath` is per-clone local config — it is not carried by the clone and there is no
> `postinstall` that sets it. Until you run it, `.githooks/pre-commit` and `.githooks/pre-push`
> do not execute, so the checks below never run on your machine and nothing reports that they
> did not. Verify with:
>
> ```bash
> git config --get core.hooksPath   # must print: .githooks
> ```

Required env vars in `.env.local`:

| Var | Description |
|---|---|
| `DATABASE_URL` | Postgres DSN (default: `postgresql://tracelane:tracelane@localhost:5432/tracelane`) |
| `CLICKHOUSE_URL` | ClickHouse endpoint (default: `http://localhost:8123`) |
| `NATS_URL` | NATS JetStream URL (default: `nats://localhost:4222`). **Required** — the gateway refuses to boot without it; set `TRACELANE_ALLOW_NO_CAPTURE=1` to run deliberately without span capture |
| `TRACELANE_BYOK_MASTER_KEY` | AES-256-GCM master key for BYOK envelope encryption — 32 bytes, **base64** (generate with `openssl rand -base64 32`) |
| `WORKOS_API_KEY` | WorkOS API key (sign up at workos.com) |
| `WORKOS_CLIENT_ID` | WorkOS client ID |
| `POLAR_ACCESS_TOKEN` | Polar.sh organization access token (sandbox token for local dev) |

## Running the stack

Open four terminals or use a process manager:

```bash
# Rust gateway (port 8080)
cargo run -p gateway

# Rust ingest workers (OTLP HTTP, port 4318)
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

CI fails if `pnpm eval:run --suite=all` regresses. Never disable an eval — mark it flaky in the suite in `evals/FLAKY.md` and fix within 48 hours.

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
pnpm bench:gateway
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
- Browse `evals/` — if the feature addresses a conformance eval that
  already has an eval there, it may already be on the roadmap
- Describe the user pain, not just the solution

### Pull requests

1. Fork the repo and create a branch: `git checkout -b feat/your-feature`
2. Write the failing test or eval first (test-first for bug fixes)
3. Implement the change
4. Run the full check suite (see above)
5. Commit with Conventional Commits (`feat(gateway):`, `fix(ingest):`, `perf:`, `sec:`, etc.)
6. Open a PR against `main`

### Adding a new instrumentation adapter

1. Create `packages/sdk-python/tracelane/instrumentations/<name>.py` or `packages/sdk-typescript/src/instrumentations/<name>.ts`.
2. Follow the existing adapter pattern — wrap the provider client, emit OTel spans with GenAI semconv attributes.
3. Add the adapter to the table in the relevant SDK README.
4. Add or update the corresponding instrumentation test beside the adapter
   (`*.test.ts` for TypeScript, `packages/sdk-python/tests/` for Python).

### Conventions (non-negotiable)

- No `unwrap()` or `expect()` outside `#[cfg(test)]` — Clippy enforces this
- `tracing::instrument` on every new public async fn with `tenant_id` as a default field
- Every new ClickHouse query must have `WHERE tenant_id = ?` — CI rejects queries without it
- `tenant_id` comes from the JWT claim, never the request body
- No raw SQL strings in TypeScript — use `@clickhouse/client` parameter binding
- No `console.log` in committed code — use the structured logger
- No secrets in code — `gitleaks` runs in CI and in the pre-push gate
- `secrecy::SecretString` for any Rust field named `*_key`, `*_token`, `*_secret`
- Pin every external dependency version
- No new deps without `cargo audit` / `pnpm audit` / `pip-audit` clean

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
