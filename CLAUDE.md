<!-- tracelane:classification: PUBLIC -->
# Tracelane — CLAUDE.md

Technical operating manual for Claude Code (and humans) working in this repository.
Read it before any non-trivial task.

> **Rebuilt 2026-08-02 from a full-repo evidence pass.** Every claim carries a `file:line`.
> **If this file disagrees with the code, the CODE wins** — and that is a bug in this file.
> Where something is specified but not built, this file says so rather than implying it ships.

---

## 1. What this is

Tracelane is **the flight recorder for AI agents**: full-fidelity capture of every LLM,
tool, and agent call through a Rust gateway, with a tamper-evident audit ledger that can be
verified offline by a third party. Blocking is **deliberately observe-first** — stopping an
agent is destructive, and a false-positive block is worse than the failure it prevents.

Apache 2.0. Rust gateway + ClickHouse-backed observability + a detection layer that records
and flags rather than intercepts.

**Delivery standard.** *What we promise is delivered as premium — exceeding
expectation, never lazily meeting it.* A change that merely satisfies its spec
sentence is not done: the shipped version should leave margin in the user's favour.
"Meets spec" is a finding, not a pass.

---

## 2. The system graph — what actually runs

Every edge carries its invariant. Dotted boxes are **not built**.

```
                    ┌───────────────────────────────────────────────────┐
   SDK / CLI /      │  RUST GATEWAY   crates/gateway  (ONE binary)       │
   OpenAI client ──►│                                                    │
   Bearer tlane_…   │  chat_completions_handler  server.rs:882-1712      │
   or WorkOS JWT    │  ── the ENTIRE hot path is this one 860-line fn ── │
                    │                                                    │
                    │  1  auth::validate_authorization      :925         │
                    │  2  entitlement resolve + rate limit  :955         │
                    │  2b monthly quota hard-cap → 429      :988         │
                    │  3  detection layer (OBSERVE-first)   :1036        │
                    │  4  audit publish  ── FAIL-CLOSED 503 :1076        │
                    │     provider resolve + BYOK key       :1103        │
                    │  4b inline guardrails ─ FAIL-CLOSED   :1203        │
                    │     <UNTRUSTED_USER_DATA> wrap                     │
                    │     kill-switch + circuit breaker     :1319-1345   │
                    │     dispatch                          :1341        │
                    └───┬──────────────┬──────────────┬─────────────┬────┘
                        │              │              │             │
        spans │ NATS    │      audit │ NATS          │ Postgres    │ HTTPS
        tracelane.      │      tracelane.            │ (control    │
        spans.{tenant}  │      audit.{tenant}        │  plane)     ▼
                        ▼              ▼              │        30+ upstream
              ┌──────────────┐  ┌─────────────┐       │        providers
              │ INGEST       │  │ audit head- │  ┌────┴─────┐  BYOK, AAD-bound
              │ crates/      │  │ writer      │  │ entitle- │  to (tenant,
              │ ingest       │  │ (consumer,  │  │ ments,   │   provider)
              │ 6 tasks in   │  │  IN the     │  │ api_keys,│
              │ try_join!    │  │  gateway    │  │ tenants, │
              │ ANY Err      │  │  process)   │  │ chain    │
              │ kills all    │  │             │  │ heads    │
              └──────┬───────┘  └──────┬──────┘  └────┬─────┘
                     │ ack AFTER write │              │ LISTEN/NOTIFY
                     ▼                 ▼              │ (DIRECT endpoint —
              ┌────────────────────────────────┐      │  a transaction pooler
              │  CLICKHOUSE                    │◄─────┘  cannot carry NOTIFY)
              │  tracelane.spans (sole writer  │
              │   = ingest), trace_summaries,  │
              │   audit_log, guardrail_verdicts│
              └───────────┬────────────────────┘
                          │  reads ONLY via gateway /v1/* (trace_reads.rs, 17 routes)
                          ▼
              ┌────────────────────────────────┐        ┌──────────────────┐
              │  apps/web  Next.js 15 on CF    │        │  Rekor v2        │
              │  Workers. NO ClickHouse client.│        │  ECDSA-P256      │
              │  Drizzle for Postgres only.    │        │  batch anchors   │
              └────────────────────────────────┘        └──────────────────┘

   ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐
     R2 cold tier      ml/ ONNX models        ee/ license zone
   │ NDJSON batcher    3 predictors are     │ DOES NOT EXIST         │
     wired to NOTHING  unconditional stubs    (whole tree Apache-2.0)
   └ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘
```

### Edge invariants

| Edge | Invariant | Evidence |
|---|---|---|
| client → gateway | `tenant_id` comes ONLY from `Claims.tenant_id`, never a request body. `TenantId` has three named constructors — `from_jwt_claim`, `from_spiffe_svid`, `from_self_host_config` | `crates/shared/src/tenant.rs:25,:33,:45`; `server.rs:947` |
| client → gateway | **The identity-provider org id is NOT the internal tenant UUID.** It is bridged by `auth::resolve_tenant_id` via a 30s cache; if a JWT carries both, they must agree or the token is rejected | `crates/gateway/src/auth/mod.rs:361-388`; `auth/org_tenant_cache.rs:40` |
| gateway → NATS (spans) | `NATS_URL` is **OPTIONAL**. Unset ⇒ span publish DISABLED, **all spans dropped**, gateway still returns 200 | `server.rs:331-357` |
| gateway → NATS (audit) | ACKED JetStream publish, **fail-CLOSED** → `503 {"error":"audit_unavailable"}`. `seq` is assigned only by the durable consumer | `audit.rs:493-554`; `server.rs:1111`, `:1239` |
| NATS → ingest | Ack **after** the ClickHouse flush. OTLP-direct spans carry **no ack** — 200 is returned on channel `try_send` | `nats_consumer.rs:119-130`; `clickhouse_writer.rs:277-280`; `span_envelope.rs:20-23` |
| ingest → ClickHouse | Ingest is the **sole** span writer. The gateway never writes spans | `clickhouse_writer.rs:374`; no such insert under `crates/gateway/src/` |
| gateway ↔ Postgres | **Never per-request.** In-process cache, 15-min TTL, invalidated by `LISTEN/NOTIFY` | `entitlement_cache.rs:65`, `:565-567`, `:30-32` |
| web → data | apps/web has **no ClickHouse client**. Every ClickHouse read is a gateway `/v1/*` call | `apps/web/package.json:22-32`; `lib/gateway.ts:4-13` |
| gateway → provider | Model→provider map **fails closed** (`_ => return None` → 400 `unroutable_model`). No default provider — defaulting would ship the wrong tenant's BYOK credential | `providers/mod.rs:709-712`; `server.rs:1141-1144` |

---

## 3. Invariants & traps

### 3.1 The three ways a control lies

**Green-is-not-proof** — the check RAN and passed **wrongly**. It measured the wrong
artifact, or asserted reachability instead of the real row/shape.

**CLASS-1** — the check **never ran, or blocked nothing.** Configured, documented, visible,
emitting output; nothing downstream depends on it. Harder to catch, because nothing looks
wrong — there is no false green, only an absence.

**CLASS-2** — the check ran, was **correct**, and **nobody acted on it.** The defect is
entirely in the absence of a consumer.

**The test.** A guard that has never been observed blocking is not a guard. For any control
we rely on, the bar is a **deliberate, recorded falsification**: break it on purpose and
watch it go red. For a control that **emits** rather than **blocks**, name the consumer and
the cadence. **A control with no recorded falsification date is assumed decorative until
proven otherwise.** On adding a control, its PR must show it failing — landing the guard and
proving it bites are one change, never two.

### 3.2 A failed falsification is a claim about your TEST until you've read the detector

When a planted violation does not fire, "this guard is decorative" is **unearned** until you
have read how the detector selects its input. Get it wrong and you "discover" broken guards
that were fine — then go and *fix working code*, which is worse than leaving it alone.

Answer three questions first: **which files does it enumerate** (`git ls-files` = tracked-only
is the common trap), **which extensions**, **which directories**. "Did not fire" ≠ "did not
look" — they present identically and mean opposite things. Prefer a probe the detector cannot
miss. **State which guards you proved and which you did not.**

This covers **recovery procedures** too: a recovery command in a runbook is a claim about
what it retrieves, unverified until run against real data — and worse than a dead guard,
because a recovery that returns *most* of the data looks like it worked.

### 3.3 Two tool defaults that damage the probe

**A piped exit code is the LAST command's.**
```bash
some_guard | head -5          # $? is head's — head basically always succeeds
some_guard > out.txt; rc=$?   # correct
some_guard | head -5; rc=${PIPESTATUS[0]}
```
Related: `grep | wc -l` under `pipefail` fails the line when grep matches nothing, so it
needs `|| true`.

**Destructive git belongs in a throwaway clone** — `git am`, `reset --hard`,
`checkout -- <path>`, `clean -fd`, `stash drop`, `rebase`, `restore`. `git status --short`
must be empty before any tree-destroying command. **`reflog` recovers commits, not
uncommitted changes.** And **`git commit -am` never stages a new file** — `-a` is
tracked-only, so a file a probe just created is silently omitted, and a later `reset --hard`
deletes it.

### 3.4 The tenant seam

The identity-provider organisation id is **not** the internal tenant UUID. Binding the raw
org id into a ClickHouse or Postgres query silently matches **zero rows** — no error, no
alert. The gateway's `auth::resolve_tenant_id` is the only bridge
(`crates/gateway/src/auth/mod.rs:361-388`); `scripts/ci/check-tenant-id-provenance.sh`
guards `apps/web`, `apps/mcp`, `packages/cli` plus two gateway audit endpoints.

**The tenant-isolation guard is per-query.** `scripts/ci/check-tenant-isolation.py`
takes the containing string literal as the query unit and resolves one interpolation hop;
its `--selftest` plants an unscoped query beside scoped ones and proves it blocks.

### 3.5 `NEXT_PUBLIC_*` is constant-folded at BUILD time

A `NEXT_PUBLIC_*` var is inlined into the bundle when the app is built — setting it at
runtime does nothing, and a stray `.env.local` present at build time bakes dev values into a
production deploy. Only `wrangler secret put` bridges a runtime secret into a Cloudflare
Worker.

### 3.6 Webhook timestamp units differ by provider — do not unify

Different providers stamp `t=` in **milliseconds** and **seconds** respectively. The HMAC is
computed over the raw value, so "normalising" them breaks signature verification.

### 3.7 Billing state changes ONLY through the webhook

Never change a tenant's plan by editing the database. The billing provider is the source of
truth; the plan flips through the webhook path only. A manual in-DB downgrade does not cancel
the upstream subscription, so the customer keeps an active subscription while the database
says `free` — which then blocks them from buying anything else.

- The single receiver is `apps/web/app/api/webhooks/polar/route.ts`.
- Idempotency keys on the **`webhook-id` HEADER**, not a body field — the envelope has no
  top-level `id`, and requiring one rejects every real delivery.
- The webhook secret's HMAC key is the **raw UTF-8 bytes of the entire secret string**,
  prefix included. Do not strip the prefix and do not base64-decode.

### 3.8 Migrations: Drizzle is canonical, but not everything is journaled

`apps/web/db/schema.ts` is the canonical control-plane schema. **But `drizzle-kit migrate`
applies only `0000`–`0008`** — the journal stops there; later migrations are applied out of
band and are explicitly un-journaled (`apps/web/db/migrations/0010_…sql:16-19`). There is no
`db:migrate` script and no automated production applier.
`crates/gateway/src/db/mod.rs::apply_migrations()` is a **test-only** helper.

A new entitlement column must land in the database **before** the gateway that reads it is
deployed, or the resolver 500s on a missing column.

### 3.9 Distroless containers have no shell

Gateway and ingest run on `cgr.dev/chainguard/glibc-dynamic` (**not** `static` — the binary
is glibc-linked). There is no shell, so `docker exec … printenv` returns nothing and reads as
"the variable is unset". Use `docker inspect -f '{{json .Config.Env}}'`.

### 3.10 `ponytail:` comments are a debt ledger — never delete one as "unclear"

A `// ponytail:` comment is a marker in a documented protocol, not commentary. The convention
is `ponytail: <ceiling>, <upgrade path>`, so each one is the written record of a **known,
accepted limitation** — several are the only place a real concurrency ceiling is documented.

- Never remove one as unclear, redundant, or restates-what.
- Remove one only when the ceiling is genuinely gone — and say so in the commit message.
- A marker naming no ceiling and no upgrade path is malformed: make it conform or drop it
  deliberately.

There are **10** in source today. Harvesting tools that anchor `ponytail:` to the start of a
line **under-report by ~30%** — they miss mid-line markers, JSDoc-block markers, and Python
docstring markers. Use a non-anchored pattern.

---

## 4. What is shipped vs. what is specified

Stated plainly, because several committed documents in this repository still overstate it.
**Do not describe anything in this table as delivered.**

| Thing | Reality |
|---|---|
| 3 ML predictors (SLM judge, trajectory guard, prompt guard) | **Unconditional stubs.** `SlmJudge::judge` returns `1.0/1.0/1.0` on **both** branches — shipping a trained model would not switch it on (`crates/gateway/src/predictive/slm_judge.rs:57-73`). No model weights are committed anywhere, and the gateway has **no ONNX runtime dependency**, so in-process inference is impossible as the crate stands |
| Prompt-guard sidecar | Not in any compose file; its URL defaults to the gateway's own port (self-call → non-2xx → fail-open) |
| A2UI / stuck-loop / MCP rug-pull / A2A / taint detection | Gated on payload fields **no live ingress produces** (`protocol`, `tool_name`, `mcp_server_name`, `tracelane_message_type`). The gateway has exactly one proxied route. `apps/docs/archive/predictive-guardrails.mdx` correctly labels these **Roadmap** |
| Detection enforcement | **Observe-first by default** — a `Block` verdict is logged, not a 403, unless `TRACELANE_PREDICTIVE_ENFORCE` is set (`server.rs:486`, `:1052`). This is the intended posture, not a bug |
| Tool-pinning and trifecta rails | No customer-facing write path for `tool_capabilities` yet, so these are inert for real tenants |
| `crates/policy` | A Cedar **scaffold**, not wired, with no `cedar-policy` dependency. Every method returns `Deny` (fail-closed) |
| R2 cold tier | The NDJSON batcher exists; **nothing feeds it** — `crates/ingest/src/main.rs:350` does `drop(r2_tx)` |
| `ee/` license zone | **Does not exist.** The whole tree is Apache-2.0 |
| ClickHouse tiered storage | No `storage_policy` or `TTL … TO DISK` anywhere under `infra/` — retention tiers are not backed by a warm/cold tier |
| Performance budgets (§6) | **Targets, not measurements.** `bench/gateway/RESULTS.md` is explicitly UNPOPULATED; `bench/predictive/RESULTS.md` is empty. Do not quote these as achieved numbers |
| Eval suite as a merge gate | The gate runs with **mock providers**, so behavioral assertions **SKIP**. Only the separate live-stack job exercises real behaviour, and it currently runs one suite |
| Provider coverage | **30+.** Exactly 35 are routable — 7 native adapters + 28 OpenAI-compatible — derived by `scripts/ci/check-provider-count.py` |

---

## 5. Coding conventions

Only what differs from the ecosystem default or is otherwise non-obvious.

### Rust
- Edition **2024**. Toolchain pinned in `rust-toolchain.toml` → **1.95**. The MSRV is a
  **separate contract**: `Cargo.toml:16` → **1.88**.
- **No `unwrap()` / `expect()` outside tests.** `?` + `thiserror` internally,
  `anyhow::Context` at boundaries. Never `Box<dyn Error>`.
- **Fail-CLOSED on security paths, fail-OPEN on fault-tolerance paths.** Each fn's
  `# Errors` doc must say which.
- **Crypto: `ring`, `rustls`, `aws-lc-rs` only. `openssl` is banned.**
- **Credentials are `secrecy::SecretString` with `Zeroize`-on-drop.** Never `String`.
- **RPITIT, not `async-trait`, on the gateway hot path** — off the hot path `async-trait` is
  fine and is used in 20+ places.
- Zero allocations past `accept()` on the hot path: `bytes::Bytes`, `arc-swap`, pre-sized
  buffers.
- `#[tracing::instrument]` on public async fns with a `tenant_id` field. **Measured adherence
  is 42.2% and no CI guard exists** — treat this as an aspiration, honestly, not a satisfied
  rule.
- `tokio` only. Axum **0.8** — paths are `/{id}`, no `#[async_trait]` on extractors. Never
  hold a lock across `.await`. `tokio::spawn` on an accept loop must be bounded by a
  semaphore permit.
- **`main.rs` and `lib.rs` both carry crate-wide `#![allow(dead_code, unused_imports, …)]`**,
  so `clippy -D warnings` **cannot** catch dead code in the gateway. An unwired module
  compiles clean.
- **`crates/gateway/src/lib.rs` exposes only `rate_limiter` and `circuit_breaker`.** Use
  `cargo test -p gateway --bin gateway` to target the bin's ~743 tests.

### TypeScript
- TS 5.5+ strict, `noUncheckedIndexedAccess`. **Biome**, not ESLint+Prettier — but **no biome
  config file exists in the repo**, so only the recommended set applies.
- React 19 + Next.js 15 App Router, RSC by default. Tailwind 4, TanStack Query, Drizzle.
  UI primitives come from the workspace-internal `@tracelanedev/ui` package.
- **Never write raw SQL strings.** Drizzle for Postgres; ClickHouse is reached only through
  the gateway's `/v1/*` endpoints.
- **Timestamps: UTC everywhere, always labeled.** Use `format-date.ts` — never
  `toLocaleString` for user-facing dates. Gateway `toString()` dates are **naive** (no `Z`),
  so `new Date()` parses them as local time and shifts per viewer. Test under a non-UTC `TZ`.
- **No `console.log`.** *(51 exist; the rule is currently unenforced.)* The honoured
  convention is to sanitise any customer-controlled value before interpolating it into a log.
- **Design tokens only — never hardcode hex.** `packages/ui/src/styles/tokens.css`.

### Python
- 3.12+, **Ruff** only. Pydantic v2. pytest + pytest-asyncio.
- **Match the CI-pinned tool version** — a locally-newer linter passes what the pinned one
  fails.

### SQL (ClickHouse)
- **Every query starts `WHERE tenant_id = ?`**, from a validated claim, never a request body.
- `ORDER BY (tenant_id, …)`. Partitioning is **time-only** on all core tables today; exactly
  one table partitions on tenant.
- Aggregations above ~1 RPS go through a materialized view, never a live query.
- `clickhouse::Row` UUID fields need the `uuid` feature **and**
  `#[serde(with="clickhouse::serde::uuid")]`, or you get green-on-empty and a failure on the
  first real row.
- A `ReplacingMergeTree` soft-delete loses data unless the exclusion read uses `FINAL` and the
  create path writes `archived=0`.

### Banned dependencies

| Dep | Reason | Enforced? |
|---|---|---|
| `litellm` (as a dependency) | Known RCE advisory | **Yes** — `deny.toml`. *(It is a legitimate instrumentation TARGET; the ban is on depending on it)* |
| `openssl` (Rust) | Use `rustls` + `aws-lc-rs` | Partial — a dedicated `cargo tree` job |
| Trivy | Known advisory; use Grype + OSV-Scanner + Syft | **No check exists** |
| `arize-phoenix` | ELv2, SaaS-blocked | **No check exists** |
| Helicone `ai-gateway` code | GPL-3.0 viral copyleft | **No check exists** — study patterns, copy zero code |
| `eslint`, `prettier` | Use Biome | **No check exists** |

New dependencies must be Apache-2.0 / MIT / BSD / ISC / MPL-2.0 and clear `cargo audit` /
`pnpm audit` / `pip-audit`.

---

## 6. Performance budgets — targets, not measurements

| Surface | p99 target |
|---|---|
| Gateway overhead (excl. provider time) | <25ms |
| Ingest end-to-end | <5s |
| Dashboard 10K-span trace load | <1s |
| MCP query | <300ms |
| Detection layer (inline) | <100ms |

**None of these is CI-enforced.** The only enforced budgets are 8 criterion microbenchmarks
with nanosecond ceilings (`scripts/ci/bench-budgets.json`). No end-to-end p99 has been
measured on production hardware — the results files are explicitly unpopulated. Do not
publish these as achieved numbers.

---

## 7. Security

- **Tenant isolation is structural** — `tenant_id` comes from a validated JWT claim or a
  verified SPIFFE SVID, never a request body, enforced by the `TenantId` newtype's three
  constructors.
- **BYOK only.** Provider keys are envelope-encrypted at rest with AEAD, with the AAD bound
  to `(tenant_id, provider_id)` — an empty AAD would allow cross-tenant ciphertext swap.
- **Provider keys never appear in logs, spans, or errors.** A `tracing` redaction layer
  scrubs known key shapes as defence in depth — but redaction is not the first line; do not
  log the value at all.
- **JWT validation:** algorithm allowlist `RS256/RS384/RS512/ES256/EdDSA`; the HMAC family is
  hard-denied. `aud` and `iss` are mandatory. JWKS is fetched via a TLS-pinned client.
- **Webhooks:** constant-time HMAC compare, 5-minute replay tolerance, idempotency recorded
  **after** successful dispatch (at-least-once beats at-most-once).
- **SSRF:** call `ssrf_guard::validate_url()` before every outbound request to an
  operator- or customer-supplied URL, and build clients with `safe_client_builder()`.
  **Redirects are disabled entirely** on that client — per-hop validation could not detect a
  DNS-rebind TOCTOU. Blocked ranges include RFC1918, CGNAT, link-local, loopback, IPv4-mapped
  IPv6, and cloud metadata endpoints.
- **Prompt-injection aware:** user-supplied span content is wrapped in an
  `<UNTRUSTED_USER_DATA>` sentinel before any model consumes it.
- **Transport:** mTLS for ingest; TLS 1.3 minimum end-to-end. The gateway itself does not
  terminate TLS — a sidecar does.
- **Supply chain:** all GitHub Actions SHA-pinned; Sigstore Cosign keyless signing;
  CycloneDX SBOM; OIDC Trusted Publishing for npm and PyPI (no long-lived registry tokens);
  Grype + OSV-Scanner + Syft for scanning; Chainguard Wolfi container bases.

**Test bypasses** (`TRACELANE_SSRF_ALLOW_LOOPBACK_FOR_TESTS`, `TRACELANE_AUTH_TEST_NO_AUDIENCE`,
and the billing organisation-check bypass) are `#[cfg(debug_assertions)]`-gated. **A release
binary cannot enable any of them via an environment variable.**

---

## 8. Build / test / lint

```bash
pnpm install && cargo build --workspace
docker compose -f infra/dev/docker-compose.yml up -d

pnpm lint && pnpm typecheck
cargo fmt --check && cargo clippy --workspace -- -D warnings
ruff check . && ruff format --check .

pnpm test && cargo test --workspace --all-features && pytest
pnpm eval:run --suite=all      # valid suites: all, ft, gc, is, pp, pir, pi
```

`scripts/verify-all.sh --fast` runs the full local gate (~36 checks: fmt, clippy
`--all-targets`, `cargo test --all-features`, cargo-deny/audit/machete, 19 guard scripts,
biome, typecheck, vitest, knip, `pnpm audit`, gitleaks, ruff, pytest). Enable the pre-push
hook with `git config core.hooksPath .githooks` — it runs that gate and blocks on failure.

**Hot-path changes should go through a PR**: the bench job does not run on a direct push.

---

## 9. Testing

- **Negative tests first.** For every "must accept" assertion, write the matching "must
  reject" assertion in the same module.
- **Test-only secrets must not look real** — use clearly-marked literals like
  `b"unit-test-secret-key-do-not-use-in-prod"`.
- **Injectable clocks** for time-dependent assertions, never `Utc::now()` in the assertion
  path.
- **No real network calls.** `wiremock` (Rust) / MSW (TS) / Polly (Python).
- **No sleeps for synchronisation** — use `tokio::sync::Notify` or poll-until-condition.
- **No leaked state between runs.** Env mutation in tests holds a process `Mutex` *and* uses a
  `Drop` guard; tempdirs always.
- Fault-tolerance chaos evals live in `evals/fault-tolerance/` (FT-01…FT-10). Note these are
  currently structural assertions — the real chaos tests are the wiremock integration tests in
  `crates/gateway/tests/`.

---

## 10. DO / DON'T

**DO**
- Read `CONTRIBUTING.md` and `SECURITY.md` before contributing.
- Cite `file:line` for every technical claim.
- Test-first when fixing bugs — every fix commit carries a regression test that would have
  caught it.
- Pin every external version.
- Prove a control fails before trusting that it works.

**DON'T**
- `unwrap()` / `expect()` outside tests.
- Query ClickHouse without a `tenant_id` filter.
- Write raw SQL strings in TypeScript.
- Take a tenant id from a request body.
- Ship a claim the code does not support — if it is specified but not built, say so.
- Copy code from GPL-3.0 or ELv2 projects.
- Hard-code a model name in business logic.
