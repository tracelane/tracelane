# API Reference — Tracelane Gateway HTTP API

All endpoints under `https://gateway.tracelane.dev` (or your self-hosted
gateway). Authentication is `Authorization: Bearer <token>` where
`<token>` is either:

- A Tracelane API key (`tlane_<base62>`) — issued at tenant signup
- A WorkOS-issued JWT — for dashboard-side requests

`tenant_id` is always derived from the verified token, never from a
request body or query parameter. This is the structural guarantee
documented in [SECURITY.md](../SECURITY.md).

Errors return `application/json` with `{"error": "<message>"}`.

---

## Health

### `GET /health`

Unauthenticated liveness probe. Returns `{"status":"ok","service":"tracelane-gateway"}`.
Use this from your load balancer.

---

## Chat completions

### `POST /v1/chat/completions`

OpenAI-compatible. Routes to the right upstream provider based on the
`model` prefix:

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
| ... | (30+ providers total — see [providers.md](providers.md)) |

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

**Side effects:** every request hits the predictive guardrail layer
(PR1–PR8). A request can be `Block`'d (HTTP 403) or `Warn`'d (response
proceeds; an `aft_id` lands on the trace). All requests are appended
to the tamper-evident audit chain.

---

## Prompts (B1 — Team tier and up)

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

### `POST /v1/prompts/:name/promote`

```json
{
  "from_env": "staging",
  "to_env": "production",
  "to_version_id": "<uuid>",
  "eval_run_id": "<uuid|null>"
}
```

200 → `{"decision":"promoted",...}`. 409 → `{"decision":"blocked_by_eval"}`
or `blocked_by_policy`.

### `POST /v1/prompts/:name/rollback`

```json
{ "env": "production", "to_version_id": "<uuid>", "reason": "incident" }
```

Atomically swaps the routing pointer back to the named version and
appends a `rollback_events` row.

---

## Audit log export ($999/mo Audit-SKU)

### `GET /v1/audit/export?since=<iso8601>&until=<iso8601>&limit=<u32>`

Streams NDJSON rows from the tamper-evident audit chain filtered by
the requesting tenant + time window. Each line is a JSON object
matching the [audit-format.md](audit-format.md) schema — directly
consumable by `tlane verify` for offline integrity checks.

Defaults: `since` 30 days ago, `until` now, `limit` 1000 (hard max
50,000 — caller paginates via `since` cursor).

`Content-Type: application/x-ndjson`. `Content-Disposition:
attachment; filename="tracelane-audit-<tenant>.ndjson"` so browser
downloads work.

---

## Billing

### `POST /v1/billing/portal`

Exchange the bearer token for a Polar-hosted customer-portal session
URL. The portal lets customers manage plan, payment method, invoices,
and cancellation without an in-app billing UI.

**Request:**
```json
{ "return_url": "https://app.tracelane.dev/billing" }
```

`return_url` is optional; defaults to `TRACELANE_BILLING_RETURN_URL`
configured at the gateway.

**Response:**
```json
{ "url": "https://polar.sh/tracelane/portal/session/abc..." }
```

Mounted only when `POLAR_ACCESS_TOKEN` is set
on the gateway. Returns 503 with no Polar configured.

---

## Webhooks

### `POST /api/webhooks/polar`

Polar POSTs subscription lifecycle events here. We verify the
Standard Webhooks signature (the `webhook-id`, `webhook-timestamp`, and
`webhook-signature` headers — HMAC-SHA256, base64-encoded, prefixed
`v1,`, over `<webhook-id>.<webhook-timestamp>.<body>` with
`POLAR_WEBHOOK_SECRET`) and dispatch:

- `subscription.created` / `subscription.active` → `tenants.set_plan_tier(<lookup_key>)`
- `subscription.canceled` / `subscription.revoked` → `tenants.set_plan_tier(free)`
- `subscription.updated` (e.g. `past_due` after a failed payment) → log only (no auto-suspend in V1)

5-minute replay window. Configure in the Polar dashboard under
Settings → Webhooks.

### `POST /v1/webhooks/workos`

WorkOS POSTs identity lifecycle events, signed with a `t=,v1=` HMAC
over `<timestamp>.<body>` using `WORKOS_WEBHOOK_SECRET`. Dispatches:

- `organization.created` → provisions a Tracelane `tenant` (free tier),
  tenant_id derived deterministically from `SHA256("workos_org:" || workos_org_id)[..16]`
- `user.created` / `dsync.user.created` → upserts a `users` row,
  `user_id` deterministically from the WorkOS user id

Re-creating the WorkOS organization gives the same Tracelane tenant
id — no separate mapping table needed.

---

## SDK + CLI surfaces (not HTTP)

The HTTP API is the canonical contract. SDKs and CLIs wrap it:

- `pip install tracelane` (Python SDK)
- `pnpm add @tracelanedev/sdk` (TypeScript SDK)
- `tlane <subcommand>` — see [cli.md](cli.md):
  - `tlane verify` — offline audit-log verification
  - `tlane prompt {list,show,promote,rollback,diff}` — B1 prompt workflow
  - `tlane import-litellm` / `tlane import-helicone` — migration
  - `tlane export` — extract spans/audit data
  - `tlane replay` — replay against a known-bad corpus

---

## Rate limits

Per-tenant token-bucket. Defaults:

| Tier | RPS | Burst |
|---|---|---|
| Free | 10 | 30 |
| Builder ($59/mo) | 100 | 300 |
| Team ($249/mo) | 500 | 1500 |
| Enterprise | negotiated | negotiated |

429 responses include `Retry-After` (seconds).

---

## Versioning

The HTTP API is versioned by URL prefix (`/v1`). Breaking changes
get a new prefix; non-breaking additions land under `/v1`. The
[CHANGELOG](../CHANGELOG.md) documents every wire-affecting change.
