<!-- tracelane:classification: PUBLIC -->
# API Reference — Tracelane Gateway HTTP API

> Read this when you are calling the gateway directly: every mounted route, what
> makes each one mount, the machine-readable error codes, and the two 429 layers.

All endpoints under `https://gateway.tracelane.dev` (or your self-hosted
gateway). Authentication is `Authorization: Bearer <token>` where
`<token>` is either:

- A Tracelane API key (`tlane_<base62>`) — issued at tenant signup
- A WorkOS-issued JWT — for dashboard-side requests

`tenant_id` is always derived from the verified token, never from a
request body or query parameter. This is the structural guarantee
documented in [SECURITY.md](../../SECURITY.md).

**Every route below is a real mount in `crates/gateway/src/server.rs`.** Several
mount **conditionally** — if the gateway is missing the backing dependency the
route is *absent* and you get a `404`, not a `503`. The "Mounted when" column on
each section says which.

## Error shape

Errors return `application/json`. The stable field is `error`; richer paths add
`message`, and provider-facing paths add `provider`:

```json
{
  "error": "provider_key_rejected",
  "message": "the configured provider key was rejected by the upstream provider — verify the key for this provider",
  "provider": "openai"
}
```

`error` is a **short code you can branch on**, not a sentence — the codes the
chat path can return are:

| `error` | HTTP | Meaning |
|---|---|---|
| `unroutable_model` | 400 | the `model` string matches no provider prefix. The map **fails closed** — there is no default provider. Body also echoes `model`. |
| `audit_unavailable` | 503 | the tamper-evident append could not be published. Fail-closed by design: the audit product does not serve unrecorded requests. |
| `quota_exceeded` | 429 | monthly trace quota × the plan's hard-cap multiplier exhausted. |
| `upstream_circuit_open` | 503 | per-(provider, region) breaker open. (An operator kill-switch can also open it; that lever is configured at service start, not at runtime.) Carries `Retry-After: 10`. |
| `provider_key_rejected` | 401 | upstream rejected your BYOK key. |
| `provider_rate_limited` | 429 | the **upstream** provider throttled you — not us. Carries `Retry-After: 60`. |
| `model_not_found` | 404 | the upstream provider does not serve this model for your account. |
| `provider_request_rejected` | mirrors upstream 4xx | upstream rejected the request and the reason is in a body we deliberately do not forward. |
| `provider unavailable` | 502 | dispatch failed after the retry. |

Two older auth/limit paths still return a human string in `error` rather than a
code — `missing Authorization header` / `invalid or expired credentials` (401)
and `rate limit exceeded` (429). Branch on the **status** for those, not the
string.

Provider error bodies and headers are **never** forwarded, and every response
body is scrubbed for key-shaped strings before it leaves the gateway
(`server.rs:2159-2189`).

### `Retry-After`

`Retry-After` is set as a **header** on `upstream_circuit_open` (503, `10`) and
`provider_rate_limited` (429, `60`).

The per-tenant **rate-limit 429 does not set the header** — it returns the delay
in the body instead:

```json
{ "error": "rate limit exceeded", "retry_after_secs": 7 }
```

Read both: header first, then `retry_after_secs`.

---

## Health

### `GET /health`

Unauthenticated liveness probe. Returns `{"status":"ok","service":"tracelane-gateway"}`.
Use this from your load balancer. Always mounted.

### `GET /v1/auth/whoami`

Validates the bearer credential and returns the tenant it resolves to — the same
hardened auth surface the chat path uses (JWT alg allowlist, audience check,
JWKS, peppered HMAC API-key lookup). Always mounted.

```json
{ "tenant_id": "…uuid…", "auth_method": "ApiKey" }
```

`401 {"error":"missing bearer"}` / `401 {"error":"invalid credentials"}`.

---

## Chat completions

### `POST /v1/chat/completions`

Always mounted. OpenAI-compatible, and it is the **only** completion route —
there is no `/v1/messages` or other provider-native surface. Auth is read from
the `authorization` header only; `x-api-key` is not consulted.

Routes to the right upstream provider based on the `model` prefix:

| Prefix | Provider |
|---|---|
| `claude-*` or `anthropic/*` | Anthropic |
| `gpt-*`, `o1*`, `o3*`, `openai/*` | OpenAI |
| `gemini-*`, `google/*` | Google |
| `bedrock/*` | AWS Bedrock (SigV4) |
| `azure/*` | Azure OpenAI |
| `command*`, `cohere/*` | Cohere |
| `mistral*`, `mixtral*` | Mistral |
| `sonar*`, `perplexity/*` | Perplexity |
| `deepseek*` | DeepSeek |
| `grok*`, `xai/*` | xAI |
| `vertex/*` | Google Vertex (service-account OAuth, not an API key) |
| `together/*`, `fireworks/*`, `openrouter/*`, `ai21/*`, `@cf/*`, … | explicit-prefix aggregators + regional hosts |
| ... | 150+ routable providers in total — 6 native adapters plus every row of the OpenAI-compatible catalog `crates/gateway/providers.tsv`; see [providers.md](providers.md) |

**The map fails closed.** An unmatched model does not fall back to a default
provider — it returns `400 unroutable_model`. That is deliberate: defaulting
would send one provider's key to a model you never asked for.

**Request:**
```json
{
  "model": "claude-sonnet-4-6",
  "messages": [{"role": "user", "content": "Hello"}],
  "max_tokens": 1024,
  "temperature": 0.7,
  "stream": false
}
```

**Response (non-streaming):** OpenAI `chat.completion` shape.

**Response (streaming, `"stream": true`):** SSE stream of OpenAI
`chat.completion.chunk` events terminated with `data: [DONE]`.

**Side effects.** Every request runs the detection layer and the inline
guardrail rails. Detection is **observe-first**: a `Block` verdict is *recorded*
and the request proceeds, unless the operator has set
`TRACELANE_PREDICTIVE_ENFORCE=1`, in which case it returns `403` with the
`aft_id`. A `Warn` always proceeds and lands an `aft_id` on the trace.

**Admitted** requests are appended to the tamper-evident audit chain. Requests
rejected earlier in the pipeline — 401, the rate-limit 429, the quota 429, an
enforced detection block — return **before** the audit publish and therefore
leave no ledger row.

---

## Prompts

Always mounted. Three gates apply, and they are **not** the same on every route —
the previous wording said writes were uniformly entitlement-gated, which was not
true of two of them:

| Gate | Applies to |
|---|---|
| **Scope** — `read` for reads, `admin` for writes | every prompt route. A key minted with `scope` unset (`LegacyFullSurface`) is unaffected |
| **Role** — owner, or a machine credential; `member`/`viewer` denied | all five write routes |
| **Entitlement** — Team-tier `f_prompt_promotion_write`, fail **closed** (`403` without it, `503` if no entitlement source is reachable) | `promote`, `rollback`, `observe` **only** |

`POST /v1/prompts/:name/versions` and `DELETE /v1/prompts/:name` carry **no
entitlement gate by design** — authoring and archiving are free, promoting is the
paid act. They still require the `admin` scope and the owner/machine role.

### `GET /v1/prompts/:name?env=production`

Resolve the active version for `(tenant, name, env)`. Returns:

```json
{
  "prompt_version_id": "...",
  "prompt_id": "...",
  "version_number": 7,
  "content": "You are a helpful…",
  "model_pin": "claude-sonnet-4-6",
  "sha256_hex": "..."
}
```

`env` is one of `dev | staging | production | canary` — defaults to
`production` if omitted.

### `GET /v1/prompts/:name/history?limit=50`

Recent promotion + rollback events for a prompt, merged by timestamp
(most recent first). Each entry is one of:

```json
{ "kind": "promotion", "promotion_id": "...", "from_env": "staging",
  "to_env": "production", "to_version_id": "...",
  "decision": "promoted", "notes": "...", "at_micros": 1778... }
```

```json
{ "kind": "rollback", "rollback_id": "...", "trigger_metric": "latency",
  "trigger_value": 1234.5, "sigma_drift": 2.3,
  "rollback_mode": "auto", "at_micros": 1778... }
```

`limit` clamps to `1..=500`, default 50.

### `GET /v1/prompts`

The tenant's prompts plus recent activity. Read-only, no entitlement gate.

### `POST /v1/prompts/:name/versions`

Register a new version. **Write** — available on every paid plan. Authoring is
read-adjacent; it is *promotion to production* that is Team-tier gated
(`crates/gateway/src/prompt_routes.rs:523-525`).

### `DELETE /v1/prompts/:name`

Soft-delete (archive) a prompt. **Write** — available on every paid plan, as the
inverse of authoring; it is not the Team+ promotion gate
(`crates/gateway/src/prompt_routes.rs:613-615`).

### `POST /v1/prompts/:name/promote`

**Write** — Team-tier gated.

```json
{
  "from_env": "staging",
  "to_env": "production",
  "to_version_id": "<uuid>",
  "eval_run_id": "<uuid|null>",
  "override_reason": "<string|omitted>"
}
```

`200` when the swap happened (`decision` is `promoted` or `manual_override`),
`409` when it did not (`blocked_by_eval` / `blocked_by_policy`). Both statuses
return the same body:

```json
{ "promotion_id": "…", "from_version_id": "…|null", "to_version_id": "…",
  "from_env": "staging", "to_env": "production", "eval_run_id": "…|null",
  "decision": "promoted", "notes": "…" }
```

A non-empty `override_reason` bypasses the eval gate and records an attributed,
tamper-evident `manual_override` decision. The Team-tier gate still applies.

### `POST /v1/prompts/:name/rollback`

**Write** — Team-tier gated.

```json
{ "env": "production", "to_version_id": "<uuid>", "reason": "incident" }
```

Atomically swaps the routing pointer back to the named version and chains the
decision into the audit ledger. Same response body as `promote`, with
`decision: "manual_override"` — a manual rollback bypasses the eval gate by
design, and is recorded as the bypass it is.

It writes a **`promotion_decisions`** row, not a `rollback_events` row. That
table is written only by the auto-rollback ENGINE when drift fires; a rollback
you request yourself is a promotion decision in the other direction, and lives in
the same ledger as every other pointer move.

### `POST /v1/prompts/:name/observe`

Feed a drift observation for the active version. **Write** — Team-tier gated.

---

## Audit

**Mounted when `CLICKHOUSE_URL` is set** — except `/v1/audit/pubkey`, which is
always mounted.

### `GET /v1/audit/export?since=<iso8601>&until=<iso8601>&limit=<u32>`

Requires the **$999/mo Audit add-on** (`f_audit_addon`). Without it: `403
{"error":"entitlement_required","feature":"audit_ledger","message":…,"upgrade_url":…}`.
If the entitlement cache is unreachable the export fails **closed** with `503` —
it never serves a paid capability it cannot verify.

Streams NDJSON from the tamper-evident chain, filtered to the requesting tenant
and window. The stream carries **two kinds of line**: the `audit_log` rows first,
then the anchor records (Rekor inclusion proof + checkpoint per anchored batch).
Both are what `tlane verify` consumes — see [audit-format.md](audit-format.md).

| Param | Default | Notes |
|---|---|---|
| `since` | 30 days ago | RFC 3339. Unparseable ⇒ the default, not an error. |
| `until` | now | RFC 3339. `since > until` ⇒ `400`. |
| `limit` | **absent = the complete ledger, uncapped** | Present ⇒ a single page clamped to `1..=50,000`. The uncapped path is seq-paginated internally in bounded memory; it is the download / compliance path. |

`Content-Type: application/x-ndjson`. `Content-Disposition: attachment;
filename="tracelane-audit-<tenant>.ndjson"` so browser downloads work.

### `GET /v1/audit/summary?since=&until=`

Aggregate totals + per-day + per-type breakdown for the window. Same auth and
same Audit-SKU gate as the export.

### `GET /v1/audit/self-verify`

Free-tier chain self-verification over your own ledger, scope-floored to your
retention window. Distinct route and distinct gate from the paid export —
`f_audit_selfverify` is granted by default.

### `GET /v1/audit/pubkey?tenant_id=<uuid>`

**Unauthenticated by design** — a public key is public, and an auditor holding
only your export and your tenant id must be able to fetch ground truth over a
TLS-authenticated domain rather than trusting the key embedded in the export.
Globally rate-limited (600/min); `429` carries a `retry-after` header.
`tenant_id` is **required** — omit it and you get a `400`.

```json
{
  "tenant_id": "…",
  "ed25519_pubkey_b64": "…",              // pass THIS to tlane verify --tenant-pubkey
  "ed25519_fingerprint_sha256": "…",
  "anchor_ecdsa_spki_b64": "…",           // empty until the first anchor
  "anchor_ecdsa_fingerprint_sha256": "…"
}
```

---

## Reads (traces, SLO, guardrails, sessions)

**Mounted when `CLICKHOUSE_URL` is set.** These are the ClickHouse read surface —
the dashboard and `tlane replay` reach ClickHouse only through them, with the
tenant taken from the validated claim.

`GET /v1/traces` · `/v1/traces/count` · `/v1/traces/export` · `/v1/traces/groups` ·
`/v1/traces/{trace_id}/spans` · `/v1/traces/{trace_id}/chain` · `/v1/slo` ·
`/v1/slo/summary` · `/v1/slo/models` · `/v1/slo/timeseries` · `/v1/gateway/stats` ·
`/v1/query/latency-breakdown` · `/v1/query/signatures` · `/v1/query/tool-analytics` ·
`/v1/guardrails/stats` · `/v1/guardrails/verdicts` · `/v1/sessions` ·
`/v1/sessions/{session_id}/traces`

---

## Keys, BYOK and tool pinning

**Mounted when Postgres is configured.**

| Route | What |
|---|---|
| `POST /v1/keys` | mint a `tlane_…` API key |
| `POST` / `GET /v1/byok/provider-keys` | upload / list BYOK provider credentials |
| `DELETE /v1/byok/provider-keys/{provider_id}` | revoke one |
| `POST` / `GET /v1/guardrails/tool-pins` | pin / list tool definitions (R3 rug-pull detection) |
| `POST /v1/guardrails/tool-pins/approve` | approve a drifted tool |
| `DELETE /v1/guardrails/tool-pins/{tool_name}` | unpin |
| `GET /v1/guardrails/observed-tools` | tools seen but not yet pinned |

---

## Alerts

**Mounted when Postgres, ClickHouse and the entitlement cache are all present.**
Gated on `f_alerts`; the background checker re-gates every tenant each tick, so
revoking the entitlement stops delivery without deleting rules.

`GET`/`POST /v1/alerts/rules` · `DELETE /v1/alerts/rules/{id}` ·
`GET`/`POST /v1/alerts/destinations` · `DELETE /v1/alerts/destinations/{id}` ·
`POST /v1/alerts/test`

---

## Billing

**Mounted when `POLAR_ACCESS_TOKEN` is set.** Without it these routes are
**absent** — a request returns `404`, not `503`.

### `POST /v1/billing/portal`

Exchange the bearer token for a Polar-hosted customer-portal session URL. The
portal lets customers manage plan, payment method, invoices and cancellation
without an in-app billing UI.

**Owner-only.** A non-owner gets `403` with a typed role-forbidden body.

**Request:**
```json
{ "return_url": "https://app.tracelane.dev/settings/billing" }
```

`return_url` is optional; falls back to `TRACELANE_BILLING_RETURN_URL`.

**Response:** `{ "url": "https://polar.sh/customer-portal/sess_…" }`

Other statuses: `503` when no Postgres pool is available, `404` when the tenant
row is missing, `409` when the tenant has no Polar customer yet (onboard via
checkout first), `502` when Polar itself fails.

### `POST /v1/billing/checkout`

Start a hosted Polar checkout for a tier.

```json
{
  "product_id": "<polar product uuid>",
  "customer_email": "you@example.com",
  "success_url": "<optional>",
  "cancel_url": "<optional>"
}
```

**Response:** `{ "url": "https://polar.sh/checkout/…" }` — redirect the browser
there. Defaults for the redirect URLs come from `TRACELANE_CHECKOUT_SUCCESS_URL`
/ `TRACELANE_CHECKOUT_CANCEL_URL`.

---

## Webhooks

### `POST /v1/webhooks/workos` — on the gateway

**Mounted when `WORKOS_WEBHOOK_SECRET` is set**; absent otherwise.

WorkOS POSTs identity lifecycle events signed `WorkOS-Signature: t=<unix_millis>,
v1=<hex>` — HMAC-SHA256 over `<t>.<body>` with `WORKOS_WEBHOOK_SECRET`. WorkOS's
`t` is **milliseconds** (Stripe's and Polar's are seconds — do not unify them),
and the replay window is 5 minutes. The HMAC is computed over `t` exactly as it
arrived; normalising it corrupts the signed payload.

- `organization.created` → upserts a tenant keyed on `workos_org_id` (free tier).
- `user.created` / `dsync.user.created` → resolves the tenant by **lookup** on
  `tenants.workos_org_id`, then upserts a `users` row. `user_id` *is* derived
  deterministically: `SHA256("workos_user:" ‖ workos_user_id)[..16]`.

> **`tenant_id` is not derived from the org id.** Production tenant ids are
> random `uuid4`; `tenants.workos_org_id` is the authoritative mapping and it is
> a real column, not a derivation. A `tenant_uuid_from_workos_org` helper exists
> but is reachable only from a debug-build, no-Postgres local-dev fallback —
> deriving an id in production matches no `tenants` row and orphans the users.
> An archived (kill-switched) tenant is never resurrected by a replayed event.

### `POST /api/webhooks/polar` — **on the web tier, not the gateway**

This route lives in `apps/web`, not in this API. The gateway once mounted a
second Polar receiver and it was retired (2026-07-28) because it correlated on a
column no real checkout populates, so it could never flip a subscription and the
two receivers could silently drift. **One receiver, one correct path.**

The web receiver verifies the Standard Webhooks signature (`webhook-id`,
`webhook-timestamp`, `webhook-signature` — HMAC-SHA256, base64, `v1,`-prefixed,
over `<webhook-id>.<webhook-timestamp>.<body>` with `POLAR_WEBHOOK_SECRET`),
cross-checks the organization id, dedupes on `(source, webhook-id)` **before**
dispatch and records **after** it, then:

- base-plan `subscription.*` events update `tenants` (plan, `polar_customer_id`,
  `polar_subscription_id`) and the `workspace_entitlements.plan_lookup_key`;
- add-on events (the separate $999 Audit SKU subscription) grant the matching
  entitlement boolean and **never** touch the base plan;
- `canceled` / `revoked` clear them.

Per-plan feature flags are plan defaults and are not set here.

---

## SDK + CLI surfaces (not HTTP)

The HTTP API is the canonical contract. SDKs and CLIs wrap it:

- `pip install tracelane` (Python SDK)
- `pnpm add @tracelanedev/sdk` (TypeScript SDK)
- `tlane <subcommand>` — see [cli.md](cli.md):
  - `tlane verify` — offline audit-log verification
  - `tlane prompt {list,show,promote,rollback,diff}` — B1 prompt workflow
  - `tlane import-litellm` / `tlane import-helicone` — migration
  - `tlane export` — generate a compliance evidence pack (offline; not a span exporter)
  - `tlane replay` — re-render a captured trace step by step (read-only; it does
    not re-execute against a model)

---

## Rate limits and quota

Two independent layers, both per tenant, both returning `429`.

### RPM — token bucket

Requests per minute, enforced by an in-process token bucket whose capacity
equals the per-minute allowance and which refills at `rpm / 60000` tokens per
millisecond (`crates/gateway/src/rate_limiter.rs:41-49, 149-167`). A cold bucket
starts full, so the first burst can be the whole minute's allowance.

| Tier | RPM | Burst (bucket capacity) |
|---|---|---|
| Free | 60 | 60 |
| Builder ($59/mo) | 600 | 600 |
| Team ($249/mo) | 6,000 | 6,000 |
| Business ($899/mo) | 60,000 | 60,000 |
| Enterprise | uncapped (short-circuits the bucket entirely) | — |

An unrecognised plan string resolves to **Free**, never to a higher tier.

Throttled:

```json
{ "error": "rate limit exceeded", "retry_after_secs": 7 }
```

`retry_after_secs` is at least `1`. **This response carries no `Retry-After`
header** — read the body field. (The circuit-breaker `503` and the upstream
`provider_rate_limited` `429` *do* set the header; see [Error shape](#error-shape).)

### Monthly quota — hard cap

Separately, each plan has a monthly trace quota with a hard-cap multiplier
(5× on paid plans). Past `quota × multiplier` the gateway returns:

```json
{
  "error": "quota_exceeded",
  "limit": 750000,
  "used": 750001,
  "reset_at": "2026-09-01T00:00:00Z",
  "upgrade_url": "https://app.tracelane.dev/settings/billing"
}
```

The counter is rehydrated from ClickHouse once per tenant per month per process,
so a restart or blue-green deploy does not forgive accrued usage.

---

## Versioning

The HTTP API is versioned by URL prefix (`/v1`). Breaking changes
get a new prefix; non-breaking additions land under `/v1`. The
[CHANGELOG](../../CHANGELOG.md) documents every wire-affecting change.
