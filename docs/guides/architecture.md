<!-- tracelane:classification: PUBLIC -->
# Architecture

> Read this when you need to know which process does what — who writes spans,
> where the tenant boundary is, which store holds the audit ledger, and which
> key signs which artifact.

A 30,000-foot view of what runs when you send a request through Tracelane, plus
the two side-cars that read what it produces. Each statement below points at a
`file:line` in this repository; where the code and this page disagree, the code
is right and this page is the bug.

```
                ┌──────────────────────────────────────────────────────────────┐
                │  YOUR AGENT  (OpenAI-compatible or Anthropic client)         │
                └─────────────────────────────┬────────────────────────────────┘
                                              │ HTTPS  POST /v1/chat/completions
                                              │        POST /v1/embeddings · /v1/messages
                                              ▼
  ┌──────────────────────────────────────────────────────────────────────────────┐
  │ ① Rust gateway (Axum, tokio, ring) — one binary                              │
  │ ──────────────────────────────────────────────────────────────────────────── │
  │ admission, shared by all three routes (crates/gateway/src/admission.rs):     │
  │   auth (JWT or tlane_ key → TenantId from the claim) → scope → parse         │
  │   → entitlements → rate limit → budgets → predictive layer (observe-first)   │
  │   → audit publish (acked JetStream write; fail-closed 503)                   │
  │ then (crates/gateway/src/server/chat.rs): BYOK key → guardrail rails R1–R8   │
  │   → circuit breaker → dispatch (191 routable providers, prefix-routed,       │
  │   no default provider; one same-provider retry; cross-provider failover is   │
  │   a per-request opt-in) → span publish                                       │
  └───────┬──────────────────────────┬───────────────────────────┬───────────────┘
          │ HTTPS                    │ NATS JetStream            │ Postgres — through
          ▼                          │ tracelane.spans.>         │ caches, never per
  ┌───────────────────┐              │ tracelane.audit.>         │ request
  │ 191 routable      │              ▼                           ▼
  │ providers:        │   ┌────────────────────────┐   ┌────────────────────────────┐
  │ 6 native adapters │   │ ② Rust ingest          │   │ Postgres (Neon-compatible) │
  │ + 185 OpenAI-     │   │ consumes               │   │ • control plane: tenants,  │
  │ compatible rows   │   │ tracelane.spans.>      │   │   api_keys, users,         │
  └───────────────────┘   │ • PII redaction        │   │   entitlements, keys …     │
                          │ • batched insert;      │   │ • CANONICAL audit ledger:  │
                          │   ack AFTER the flush  │   │   audit_log_rows,          │
                          └───────────┬────────────┘   │   audit_anchor_records,    │
                                      │                │   audit_chain_state        │
  audit consumer — a task inside the  │                └─────────────┬──────────────┘
  gateway process — consumes          │                              │ derived copy of the
  tracelane.audit.> and appends the   │                              │ ledger, written after
  ledger row inside the Postgres      │                              │ the commit and
  head-advance transaction            │                              │ rebuilt at boot
                                      ▼                              ▼
  ┌──────────────────────────────────────────────────────────────────────────────┐
  │ ClickHouse                                                                   │
  │ • spans — ingest is the only writer; 365-day TTL backstop; per-plan          │
  │   retention is enforced by a gateway sweep job                               │
  │ • audit_log · audit_anchor_records — the ledger's DERIVED copy               │
  │ • guardrail_verdicts, prompt-promotion tables (gateway); meter_counters,     │
  │   blobs, blob_refs (ingest)                                                  │
  │ • an R2-backed cold volume, when configured, is a storage policy on `spans`, │
  │   not a second table or a second writer                                      │
  └──────────────────────────────────────┬───────────────────────────────────────┘
                                         │ reads only through the gateway's /v1/* routes
                                         ▼
  ┌──────────────────────────────────────────────────────────────────────────────┐
  │ ③ Next.js 15 dashboard (apps/web) — Drizzle for Postgres, no ClickHouse      │
  │  • /traces — waterfall and transcript-with-a-spine views                     │
  │  • /prompts/[name] — versions per environment, history, promotion control    │
  │  • /audit — ledger view, in-browser verifier, export                         │
  │  • /settings/billing — Polar checkout and customer-portal launcher           │
  └──────────────────────────────────────────────────────────────────────────────┘

  ④ TypeScript MCP server (apps/mcp; `@tracelanedev/mcp` on npm) — read-only; the
     bearer is validated against the gateway's /v1/auth/whoami and reads go through
     the gateway's /v1/* routes (stdio self-host mode with CLICKHOUSE_URL set is
     the one direct-ClickHouse reader; the HTTP transport refuses that variable).
  ⑤ Python eval orchestrator (evals/) — DeepEval + Ragas + Inspect AI.
```

Where each line of the diagram comes from:

- Gateway dependencies: `crates/gateway/Cargo.toml:16-17,33` (tokio, axum, ring).
  The three routes: `crates/gateway/src/server.rs:1022,1026,1038`.
- The admission steps and their order: `crates/gateway/src/admission.rs:79-99`
  (`enum Step`: Auth, Scope, Parse, Entitlements, RateLimit, KeyBudget,
  WorkspaceBudget, Predictive, Audit). Auth accepts a WorkOS JWT or a
  `tlane_<base62>` API key (`crates/gateway/src/auth/mod.rs:7-9`,
  `crates/gateway/src/auth/api_key.rs:26-35`).
- After admission: BYOK key lookup (`server/chat.rs:433-449`), guardrail
  request evaluation (`server/chat.rs:559`), circuit breaker
  (`server/chat.rs:655-657`), dispatch with one same-provider retry
  (`crates/gateway/src/providers/failover.rs:104-118`) and per-request
  cross-provider failover behind `X-Tracelane-Failover: cross-provider`
  (`server/chat.rs:917-925`).
- Provider count: 185 OpenAI-compatible rows in `crates/gateway/providers.tsv`
  plus the 6 native adapters on `ProviderRegistry`
  (`crates/gateway/src/providers/mod.rs:553-568`) — 191 routable. The count is
  derived, not typed: `scripts/ci/check-provider-count.py` fails the gate when a
  written number disagrees. An unknown model is refused with `unroutable_model`;
  there is no default provider (`providers/mod.rs:636-641,676-681`).
- `NATS_URL` unset is a boot refusal unless `TRACELANE_ALLOW_NO_CAPTURE=1`
  (`crates/gateway/src/server.rs:547-568,637-639`). Spans publish to
  `tracelane.spans.<tenant>` through JetStream (`crates/gateway/src/otlp_emit.rs:99-112,266-272`).
- Ingest: JetStream consumer with ack-after-write
  (`crates/ingest/src/nats_consumer.rs:264-270`,
  `crates/ingest/src/clickhouse_writer.rs:846-856`), PII redaction of every
  attribute payload before the insert (`clickhouse_writer.rs:227-252`), the
  batched `INSERT INTO tracelane.spans` (`clickhouse_writer.rs:952-961`) and the
  `meter_counters` / `blobs` / `blob_refs` writes (`clickhouse_writer.rs:651,764,792`).
- The audit consumer is a background task of the gateway process
  (`crates/gateway/src/server.rs:694`, `crates/gateway/src/audit_consumer.rs:1-10`).
- Dashboard: Next.js `15.5.24` (`apps/web/package.json:29`); no ClickHouse
  dependency in that package; the Postgres and gateway reads meet in its own
  server components (for example `apps/web/app/audit/page.tsx:32-37`). Views:
  `apps/web/components/trace-viewer/TraceDetailView.tsx:11-12,48-52`,
  `apps/web/app/prompts/[name]/page.tsx:1-8`, `apps/web/app/audit/page.tsx:2-6`,
  `apps/web/components/billing/PlanCard.tsx:8-17`.
- MCP server: `apps/mcp/src/reader.ts:7-21,518-521` (gateway-backed reads by
  default; `ClickHouseReader` only when `CLICKHOUSE_URL` is set),
  `apps/mcp/src/auth.ts:13,132` (whoami), `apps/mcp/src/http.ts:88,104-120` (the
  HTTP transport registers only `GatewayReader` and refuses to start with
  `CLICKHOUSE_URL` set), published by `.github/workflows/release.yml:466`.
- Eval orchestrator: `evals/pyproject.toml:8-15`.

> **Cold storage is a ClickHouse policy, not an ingest writer.** The baseline
> `spans` table deletes at 365 days (`infra/dev/clickhouse/schema.sql:109`), a
> backstop the schema comment calls "the MAX plan retention" (`schema.sql:101-108`).
> Per-plan retention is enforced by the gateway's sweep job, which reads each
> plan's `queryable_days` (`crates/gateway/src/retention_sweep.rs:3-9`). A later
> migration documents manual `ALTER` statements that move older parts to an
> R2-backed cold volume at 365 days and delete them at 730
> (`infra/dev/clickhouse/migrations/24_bill01_meters_blobs_tiering.sql:102-130`).
> Those statements are comments in the migration file; source alone does not say
> whether a deployment applied them.

---

## Source-of-truth split

Two databases with different roles — and the part that trips people up is
*which process writes what*:

| Data | Written by | Database |
|---|---|---|
| `spans` | **ingest only** — `crates/ingest/src/clickhouse_writer.rs:366-591` (the writer loop) and `:952-961` (the insert). The gateway publishes to NATS and never inserts a span. | ClickHouse (365-day TTL backstop, `infra/dev/clickhouse/schema.sql:109`; per-plan window by `crates/gateway/src/retention_sweep.rs`) |
| `meter_counters` · `blobs` · `blob_refs` | ingest — `clickhouse_writer.rs:651,764,792` | ClickHouse |
| `audit_log_rows` · `audit_anchor_records` · `audit_chain_state` — the tamper-evident ledger, **canonical** | gateway — chain rows in the same transaction as the head, anchor bundles in the same database (`crates/gateway/src/db/ledger.rs:1-8,168-211,232-260`) | Postgres |
| `audit_log` · `audit_anchor_records` — the ledger's **derived copy**, written after the Postgres commit and rebuilt by the boot reconcile (`crates/gateway/src/audit.rs:1665-1679,986-1008`); the chain's only home when the gateway runs without Postgres (`audit.rs:1067-1093`) | gateway | ClickHouse |
| `guardrail_verdicts` · `promotion_decisions` | gateway — `crates/gateway/src/guardrail/recorder.rs:140`, `crates/gateway/src/prompt_router.rs:265` | ClickHouse |
| tenants · api_keys · users · workspace_entitlements · alert_rules · tool_capabilities · webhook_events (`apps/web/db/schema.ts:92,552,941,366,470,759,642`) | gateway + `apps/web` (Drizzle) | Postgres (Neon-compatible) |

An R2-backed cold volume, when configured and activated, is a ClickHouse
storage location for `spans` (`24_bill01_meters_blobs_tiering.sql:102-130`),
not a separate span table or ingest writer.

The split is structural: ClickHouse stores observations and the ledger's copy;
Postgres stores control-plane records and the canonical ledger. The dashboard
has no ClickHouse client — it reads Postgres through Drizzle and observations
through the gateway's `/v1/*` routes (`crates/gateway/src/trace_reads.rs`), and
combines them in its own server components (`apps/web/app/audit/page.tsx:32-37`).

---

## Tenant isolation

Gateway trace reads bind `tenant_id` from validated credentials in their SQL
(`crates/gateway/src/trace_reads.rs:2163-2218`). The ClickHouse query wrapper
adds resource caps; its caller remains responsible for the `tenant_id = ?`
placement (`crates/gateway/src/clickhouse_query.rs:143-151`). A CI guard checks
each literal query against `tracelane.*` for a tenant filter, and documents the
query shapes it cannot see (`scripts/ci/check-tenant-isolation.py:1-40`).

Rust's `TenantId` has three named constructors, one per trust boundary
(`crates/shared/src/tenant.rs:41-70`):

| Constructor | Line | Trust boundary |
|---|---|---|
| `TenantId::from_jwt_claim` | `:48` | a WorkOS JWT whose signature the caller has already verified against the JWKS |
| `TenantId::from_spiffe_svid` | `:56` | a verified SPIFFE X.509-SVID (the ingest mTLS path) |
| `TenantId::from_self_host_config` | `:68` | the single operator-configured tenant of a self-host deployment, reachable only in single-tenant mode |

There is a fourth path, and the type's own docs say so (`tenant.rs:9-33`): the
struct derives `Deserialize` with `#[serde(transparent)]` (`tenant.rs:41-43`),
so serde can build a `TenantId` from bytes. What contains that path is the
deployment, not the type: the only production bytes-to-`TenantId` site is the
ingest NATS consumer decoding a payload the gateway wrote from a validated
claim, and the OTLP resource-attribute fallback is compiled only into debug
builds (`crates/shared/src/otlp/decode.rs:117-125`). A guard fails any
`Deserialize`-deriving struct that carries a `TenantId` field unless it is
allowlisted with a note saying who writes the bytes
(`scripts/ci/check-tenant-id-provenance.sh:276-295`).
See [SECURITY.md](../../SECURITY.md).

---

## Predictive guardrail layer

The gateway runs the predictive layer inline, as one step of the shared
admission pipeline (`crates/gateway/src/admission.rs:710-739`). It is a set of
**inline heuristic guardrails**; the ML ensemble is on the roadmap. Detection is
observe-first by design: each predictor returns `Allow | Warn | Block` with an
`aft_id` (`crates/gateway/src/predictive/mod.rs:42-46`); a `Block` is
**recorded, not enforced** — the `aft_id` rides into the chat and messages
ledger payloads as `warn_aft_id` (`admission.rs:858`,
`crates/gateway/src/anthropic_messages.rs:986`) and the request proceeds — unless
the operator sets `TRACELANE_PREDICTIVE_ENFORCE=1` (`admission.rs:724-738`,
`crates/gateway/src/server.rs:999-1002`).

The stack, in registration order (`predictive/mod.rs:89-156`), and the body
field each predictor reads before it does any work:

| Predictor | Reads | Reaches a plain chat body? |
|---|---|---|
| `mcp-hash-watcher` | `mcp_server_url` / `mcp_server_name` + `mcp_tools` (`mcp_hash_watcher.rs:316-325`) | no |
| `tool-definition-drift` | `tools[]` (`tool_definition_drift.rs:284`) | yes |
| `taint-tracker` | `tool_name`, `tracelane_untrusted_input` (`taint_tracker.rs:63-72`) | no |
| `stuck-loop` | `tool_name` (`stuck_loop.rs:115`) | no |
| `browser-passive-observer` | `tracelane.browser.step_index` (`browser_capture.rs:65-70`) | no |
| `prompt-injection` | top-level `tool_output` / `content` (`prompt_injection.rs:63-67`) | no |
| `a2a-validator` | `tracelane_message_type == "a2a_handoff"` (`a2a_validator.rs:45-53`) | no |
| `a2ui-catalog-validator` | `protocol == "a2ui"` (`a2ui_validator.rs:66`) | no |
| `captcha-preemptor` | `tool_url`, `page_content` (`captcha.rs:59-70`) | no |
| `pr8-lite-argument-drift` | `tool_name`, `tool_args` (`pr8_lite_argument_drift.rs:217-224`) | no |
| `tool-schema-validator` | `messages[].tool_calls` + `tools[]` (`tool_schema_validator.rs:188-227`) | yes |

So on a `/v1/chat/completions` body only `tool-definition-drift` and
`tool-schema-validator` do reachable work; the rest return `Allow` until a
request carries their field. This is the same disclosure as `README.md`; what
runs inline on chat requests is the guardrail rail set, below (which rails a
tenant gets is plan-gated, `crates/gateway/src/guardrail/rail.rs:65,159`).

**Registered, returning a constant.** `trajectory_guard` and `slm_judge` are in
the stack with their `ort` inference commented out
(`predictive/trajectory_guard.rs:78-79`, `predictive/slm_judge.rs:66`), so they
return `Allow`. The `prompt_guard_pr6` sidecar predictor is added only when
`PROMPT_GUARD_URL` is set (`predictive/mod.rs:113-130`). Do not plan against
these. (Older `PRn` labels are dropped here on purpose — the same label meant
different things across doc generations; the names above are the predictors'
`name()` values.)

**Guardrail rails.** Separate from the predictive layer, eight rail families
R1–R8 (nine rail objects; R3 is split into schema and pinning) run on the
request side and, for the applicable rails, on the response side
(`crates/gateway/src/guardrail/engine.rs:143-158,263,353`).

---

## Tamper-evident audit chain

The admission pipeline publishes an audit event as its last step, before
provider dispatch (`crates/gateway/src/admission.rs:741-765`). Authentication,
scope, parse, rate-limit, budget and enforced predictive refusals return before
publication; entitlement resolution sits between parse and rate limit and, with
no control plane, resolves to the operator-configured default rather than
refusing (`admission.rs:551-580`). The publish is an acked JetStream write, and
a publish or ack failure refuses the request with `503 audit_unavailable`
(`crates/gateway/src/audit.rs:1050-1140` — `publish`, through the ack error; `admission.rs:761-764`). A
background consumer inside the gateway process appends the canonical Postgres
row and acks the message only after the commit
(`crates/gateway/src/audit_consumer.rs:1-10,358-401`).

**The ledger is canonical in Postgres.** Chain rows (`audit_log_rows`) land in
the same transaction as the chain head, and anchor bundles
(`audit_anchor_records`) in the same database (`crates/gateway/src/db/ledger.rs:1-17`). ClickHouse `audit_log` is a derived
copy written after the commit; a failed copy is counted and the boot reconcile
rebuilds it (`audit.rs:1665-1679`). The reconcile adopts a copy row into
Postgres only if it chains from the running hash **and** its content re-hashes
to its stored `row_hash` (`audit.rs:1290-1332,986-1008`); a head that is ahead of
its rows is left red for verifiers rather than reset (`audit.rs:1349-1356`).
`GET /v1/audit/export` reads Postgres (`crates/gateway/src/audit_export.rs:440-488`)
and fails closed: a read error before the body is a `500`, and one after the
body has started aborts the transfer rather than shipping a short file
(`audit_export.rs:1258-1273`).

The self-host path without Postgres uses a process-local chain and a ClickHouse
table written through a bounded, batched, retried queue (`audit.rs:1740`,
`append_in_memory`): a row that cannot be queued refuses the request, rows still
queued at exit are lost, and the code's own comment (`audit.rs:1060-1088`) says
not to describe that tier as a tamper-evident ledger.

The chain hash is the **v2** encoding
(`crates/gateway/src/audit_format/mod.rs:77-80,102-134,278-281`):

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
duplicated (`audit_format/mod.rs:55-60,83-86`).

> The earlier v1 format is `#[deprecated]` in `crates/gateway/src/audit.rs:157-160`
> (row hash) and `:178-181` (Merkle root), kept only to re-verify pre-migration
> rows. Its deprecation notes say why: the `|`-separated row hash is vulnerable
> to field-boundary attacks, and the duplicate-last Merkle tree is
> second-preimage-vulnerable. Do not implement against it.

### Two keys, two jobs — do not conflate them

A batch closes at `TRACELANE_REKOR_ANCHOR_EVERY` rows (default 100,
`crates/gateway/src/server.rs:163-166`) or when its oldest unsigned row is older
than 24 hours (`audit.rs:812-817,1868`). At close-out the batch's Merkle root is
signed by **two different keys** over two different messages (byte formats
frozen, `audit.rs:221-223`):

| Key | Algorithm | Signs | Why this algorithm |
|---|---|---|---|
| Local attestation | **Ed25519**, per tenant (`audit_keys.rs:10,185-186`) | `"tracelane-audit-ed25519-v1\0" ‖ root ‖ anchor_commitment` (`audit.rs:262-268`) | the offline trust root — the key `tlane verify --tenant-pubkey` takes (`packages/cli/src/commands/verify.ts:62`) |
| Rekor anchor | **ECDSA-P256**, per tenant (`audit_keys.rs:111-116`) | `"tracelane-anchor-ecdsa-v1\0" ‖ root`, submitted as a Rekor v2 `hashedrekord` (`audit.rs:226-232`) | Rekor v2's hashedrekord rejects pure Ed25519 — it loads the verifier with `WithED25519ph` (`audit_keys.rs:114-115`) |

So: **Ed25519 is the local-attestation signer; the thing that goes to Sigstore
Rekor v2 is signed with ECDSA-P256.** The `anchor_commitment` binds the anchor's
identity — SHA-256 of the ECDSA public key, SHA-256 of the log URL, the log
index — into the Ed25519 message (`audit.rs:242-258`), so a stripped, swapped
or downgraded bundle fails offline verification.

Anchoring is **best-effort** and does not block the request: a Rekor failure
leaves the batch signed-but-unanchored and the verifier reports that state
(`audit.rs:2806-2818`, `packages/cli/src/commands/verify.ts:119,177`). The
hosted product mints and stores the per-tenant keys itself
(`audit_keys.rs:10,185-186`); the dashboard's ledger view names which trust level
a batch reached (`apps/web/components/audit/AuditLedgerView.tsx:1293-1311`).
Customers verify offline with any of three reference implementations
(`packages/verifier-rust`, `verifier-python`, `verifier-typescript`), which CI
holds to the same verdicts on the same vectors
(`scripts/ci/verifier-roundtrip/run.sh:4-15`).

Format spec: [audit-format.md](audit-format.md).

---

## Prompt promotion

A routing layer for managed prompts. Customers register versions, and promote
`staging → production` via the CLI (`tlane prompt promote`,
`packages/cli/src/commands/prompt.ts:218`) or HTTP (`POST /v1/prompts/{name}/promote`,
`crates/gateway/src/prompt_routes.rs:117-133`). Production routing is an
`ArcSwap` pointer, so reads are wait-free and a promotion is one atomic swap
(`crates/gateway/src/prompt_router.rs:10,930-966`).

Per-version drift detection is EWMA-based (`crates/gateway/src/auto_rollback.rs:8-19`).
Above 2σ drift (`auto_rollback.rs:346-363`) the objective metrics — cost,
latency, error rate, guardrail fire — flip production back automatically; the
subjective ones — accuracy, hallucination — return a suggestion for a human to
confirm (`auto_rollback.rs:28-49`, `prompt_router.rs:1592-1657`).

The write path (`promote` / `rollback` / `observe`) is gated on the
`f_prompt_promotion_write` entitlement, seeded true on the Team plan and above
(`apps/web/db/seed.mjs:32-34,117-120`), and answers `503` when no entitlement
source is wired (`prompt_routes.rs:231-271`). The gate is called only from
the promote, rollback and observe handlers and the eval-judge path
(`prompt_routes.rs:704,780,859,997`); the read routes do not call it.

---

## Trust + supply chain

- Apache 2.0 (`LICENSE`) + the License Pledge — no relicense to BSL, SSPL or
  ELv2 (`LICENSE-PLEDGE.md:26`).
- npm and PyPI publish through OIDC Trusted Publishing, with no long-lived
  token (`.github/workflows/release.yml:377-397,647-648`). No crate is published
  to crates.io (`release.yml:368-374`).
- Cosign **keyless** `sign-blob` over each gateway release binary and over the
  SBOM, with the Sigstore bundle attached beside each asset (`release.yml:230-250,276-281`).
- `actions/attest-build-provenance` on the release artifacts
  (`release.yml:334`), in the SLSA provenance format (`SECURITY.md:242-244`).
- CycloneDX SBOM attached to each release (`release.yml:226-229,280`).
- OpenSSF Scorecard ≥ 9.0 is a **target** (`apps/docs/security.mdx:199`); the
  workflow runs (`.github/workflows/scorecard.yml`); the score is not a claim.
- Three reference audit verifiers held to the same verdicts by CI
  (`scripts/ci/verifier-roundtrip/run.sh`).

Tracelane makes **no** eIDAS or qualified-timestamp claim, and does not claim a
verified SLSA Level 3 attestation (`release.yml:360-365`).

---

## Performance budgets

The p99 targets below are engineering targets, not measurements, and **none of
them is enforced in CI**. The only enforced budgets are eight criterion
micro-benchmarks with nanosecond ceilings (`scripts/ci/bench-budgets.json`,
checked by `scripts/ci/check-bench-budgets.mjs`). The `Benchmarks` job that
runs them is not on the pull-request path or any schedule: it runs only on a
manual `workflow_dispatch` with an explicit hosted-runner opt-in
(`.github/workflows/ci.yml:1501-1525`, `CONTRIBUTING.md:169-177`).

| Surface | p99 target |
|---|---|
| Gateway overhead (excl. provider time) | <25 ms |
| Ingest end-to-end | <5 s |
| Dashboard 10K-span trace load | <1 s |
| Predictive layer (inline) | <100 ms |

The one published measurement is gateway overhead: 2 / 4 / 5 ms at p50 / p95 /
p99 over a direct-to-mock baseline, at 16 concurrent clients on one small host
with a mock upstream, two runs on 2026-09-07 (`apps/docs/benchmarks.mdx:46-54`).
It measures added latency only — not throughput ceilings, streaming inter-chunk
latency, or production hardware — and no other figure in this table has been
measured.

---

## Repository layout

```
crates/
  gateway/              Rust gateway (Axum + tokio) — the whole hot path
  ingest/               Rust ingest workers (NATS → ClickHouse)
  policy/               PII redaction (used by gateway + ingest).
                        `policy/engine.rs` is an unwired scaffold — no call
                        sites outside the crate, no `cedar-policy` dependency,
                        and both of its evaluate methods return Deny
                        (`crates/policy/src/engine.rs:64-89`).
  shared/               universal types (ChatRequest, TenantId, TracelaneSpan, …)
  tracelane-audit-cli/  standalone `tracelane-audit` verifier binary

apps/
  web/            Next.js 15 dashboard (Cloudflare Workers)
  mcp/            TypeScript MCP server — `@tracelanedev/mcp` on npm
  docs/           Mintlify documentation site
  site/           Astro marketing site

packages/
  cli/                       tlane CLI            (npm @tracelanedev/cli)
  sdk-python/                (PyPI  tracelane)
  sdk-typescript/            (npm   @tracelanedev/sdk)
  verifier-rust/, verifier-python/, verifier-typescript/
  ui/                        shared design tokens + components

bench/            k6 scripts (bench/gateway/*.js) + criterion benches (crates/*/benches)
evals/            Pain-point + fault-tolerance + provider correctness evals
ml/               Trajectory guard, SLM judge, prompt guard, eval corpus
infra/dev/        docker-compose for the local stack
infra/self-host/  single-tenant self-host deployment
docs/guides/      these guides
```

> `crates/mcp-rs` does not exist. The MCP server is TypeScript only (`apps/mcp`)
> and is published to npm as `@tracelanedev/mcp` by the release workflow
> (`.github/workflows/release.yml:466`, `apps/mcp/server.json:12-19`), so
> `npx @tracelanedev/mcp` resolves. Building from source
> (`pnpm --filter @tracelanedev/mcp build`) remains the local-development path.
