<!-- tracelane:classification: PUBLIC -->
# Quickstart — first trace in 60 seconds

> Read this when you have a Tracelane API key and want your first traced request
> and your first offline ledger verification, end to end.

This guide takes you from "I have a Tracelane API key" to "I'm seeing my
first trace in the dashboard."

If you don't have an API key yet, skip ahead to [Onboarding](onboarding.md).

---

## 1. Point an OpenAI-compatible client at the gateway

Tracelane is a drop-in proxy on the **OpenAI wire format**. You reach every
provider — Anthropic, Bedrock, Google, 150+ in all — through
`POST /v1/chat/completions`, choosing the upstream with a **model prefix**.

> **Use an OpenAI-compatible client, not a provider-native SDK.** The gateway
> mounts exactly one completion route. There is no `/v1/messages`, and auth is
> read from the `authorization` header — an Anthropic-native client would POST
> to `/v1/messages` with `x-api-key` and get a 404. Keep the Anthropic *models*;
> swap the *client*.

### Python

```python
import os
from openai import OpenAI

client = OpenAI(
    base_url="https://gateway.tracelane.dev/v1",
    api_key=os.environ["TRACELANE_API_KEY"],  # tlane_… from app.tracelane.dev
)

resp = client.chat.completions.create(
    model="claude-sonnet-4-6",  # routed to Anthropic by prefix
    messages=[{"role": "user", "content": "Say hello"}],
)
```

### TypeScript

```typescript
import OpenAI from "openai";

const client = new OpenAI({
  baseURL: "https://gateway.tracelane.dev/v1",
  apiKey: process.env.TRACELANE_API_KEY!,
});
```

### Direct HTTP (no SDK)

Set two environment variables:

```bash
export TRACELANE_API_KEY="tlane_..."
export TRACELANE_GATEWAY_URL="https://gateway.tracelane.dev"
```

Then change one line in your code — replace your provider's base URL
with `$TRACELANE_GATEWAY_URL/v1`, and prefix the model:

| You want | Base URL | `model` |
|---|---|---|
| OpenAI | `$TRACELANE_GATEWAY_URL/v1` | `gpt-…`, `o1…`, `o3…`, or `openai/…` |
| Anthropic | `$TRACELANE_GATEWAY_URL/v1` | `claude-…` or `anthropic/…` |
| Google | `$TRACELANE_GATEWAY_URL/v1` | `gemini-…` or `google/…` |
| Bedrock | `$TRACELANE_GATEWAY_URL/v1` | `bedrock/…` |

A model matching no prefix returns `400 unroutable_model` — the routing map
fails closed rather than guessing a provider and spending the wrong key.

Authenticate with your **Tracelane** key (`tlane_…`) as the bearer token — not your
provider key. The gateway resolves the tenant from it
(`crates/gateway/src/auth/api_key.rs`).

Your provider credentials are supplied once under **BYOK** and are stored
envelope-encrypted with AES-256-GCM, bound to `(tenant_id, provider_id)` via AAD, and
decrypted per request to call upstream. They are never written to logs, spans or errors.
See [SECURITY.md](../../SECURITY.md) for the key-handling detail.

---

## 2. Make a request

```bash
curl $TRACELANE_GATEWAY_URL/v1/chat/completions \
  -H "authorization: Bearer $TRACELANE_API_KEY" \
  -H "content-type: application/json" \
  -d '{
    "model": "claude-sonnet-4-6",
    "messages": [{"role": "user", "content": "Say hello"}]
  }'
```

`model` selects the upstream by prefix across 150+ routable providers (6 native
adapters plus every row of the OpenAI-compatible catalog): `claude-*` →
Anthropic, `gpt-*` → OpenAI, `bedrock/*` → AWS Bedrock, `gemini-*` → Google, and
so on. Full list in [providers.md](providers.md).

---

## 3. See your trace in the dashboard

Open [`https://app.tracelane.dev/traces`](https://app.tracelane.dev/traces).

**How fast?** The engineering budget for ingest end-to-end is **p99 < 5 s**
(the merge gate in [CONTRIBUTING.md](../../CONTRIBUTING.md)). We do not publish
a measured arrival-time figure yet, so treat 5 s as the number to plan against —
in practice it is usually much faster, and that gap is deliberately in your
favour, not a promise.

Click into a trace for the waterfall view. What a gateway-proxied trace carries
today:

- **Model, token usage per step, and cost** — provider-reported when available,
  otherwise derived from the token counts and the price catalog. An unknown
  model yields no cost rather than a fabricated one.
- **Status and error reason**, so a real provider outage shows as errors instead
  of a structural 0%.
- **Guardrail rail verdicts** — 8 rails run inline on chat traffic: cost,
  secrets/PII, tool safety, lethal-trifecta, format, system-prompt leak, topic,
  injection. The MCP/agent-tool detectors fire on tool traffic, not on chat
  completions.
- **Cross-provider failover trail** — only when you opted in with
  `X-Tracelane-Failover: cross-provider` *and* the primary failed *and* you hold
  a BYOK key for the fallback. The default behaviour is one same-provider retry
  after 100 ms within a 200 ms budget, which is not surfaced as a failover.
- **Tamper-evident chain correlation** — the trace id is written into the audit
  payload, so a trace can be tied to its ledger row. Rekor entry ids appear on
  batches that actually anchored.

> **What a gateway-proxied span does *not* carry: your prompt and completion
> text.** The gateway records the model, tokens, cost, timings, status and
> guardrail verdicts — not the message bodies. The audit-ledger payload is
> likewise metadata (model, trace id, warn id, optional business reference),
> PII-redacted. Message bodies (`gen_ai.input_messages` /
> `gen_ai.output_messages`) reach ClickHouse only from **OTLP spans your own SDK
> emits**. Separately, `f_full_capture` — the entitlement that forces the
> full-capture sampling policy — is **false on Free, Builder and Team**
> (`apps/web/db/seed.mjs`); it is granted on Business and Enterprise, and the
> Audit add-on forces full capture on any plan.

---

## 4. Verify your audit log offline (Audit-SKU)

```bash
npm install -g @tracelanedev/cli

# Pull your ledger as NDJSON (requires the Audit add-on)
curl -H "authorization: Bearer $TRACELANE_API_KEY" \
  "$TRACELANE_GATEWAY_URL/v1/audit/export?since=2026-01-01T00:00:00Z" > audit.ndjson

# Verify it offline. The key is the trust root — fetch it separately.
# /v1/audit/pubkey is UNAUTHENTICATED (a public key is public) and REQUIRES
# ?tenant_id=. It returns a JSON object; --tenant-pubkey wants the raw base64
# 32-byte Ed25519 key, so pull out `ed25519_pubkey_b64`.
TRACELANE_TENANT_ID=$(curl -s -H "authorization: Bearer $TRACELANE_API_KEY" \
  "$TRACELANE_GATEWAY_URL/v1/auth/whoami" | jq -r .tenant_id)
TRACELANE_AUDIT_PUBKEY=$(curl -s \
  "$TRACELANE_GATEWAY_URL/v1/audit/pubkey?tenant_id=$TRACELANE_TENANT_ID" \
  | jq -r .ed25519_pubkey_b64)
tlane verify audit.ndjson --tenant-pubkey "$TRACELANE_AUDIT_PUBKEY"

# Separately: the Article 12 documentation pack (templates, not your data)
tlane export --pack eu-ai-act-art12 --output-dir ./audit-pack
```

**`--tenant-pubkey` is what makes the run mean something.** Without it the verifier checks the hash chain only: signature and Rekor-anchor verification never run, so a forged anchor would not be caught. The CLI therefore exits **non-zero with `INCOMPLETE`** whenever a ledger contains anchor records and no trusted key was supplied. Get the key out-of-band from Settings → Audit signing key, or `GET /v1/audit/pubkey` — not from the export itself.

The verifier is reproducible across three independent implementations
(Rust, Python, TypeScript) and produces byte-identical reports. Given the export
and the public key, anyone can verify a Tracelane audit log **offline, with no
Tracelane credentials and no call back to us**.

**What "anchored" means here.** Anchoring is per Merkle **batch** — every 100
events by default — and **best-effort**. A batch that did not reach Sigstore
Rekor v2 is still Ed25519-signed and still verifies; the verifier reports the
anchor state honestly instead of implying coverage it does not have. Rekor v2
has no online per-entry lookup, so the inclusion proof and signed checkpoint
captured at anchor time are what ship in the export — that is why they are
lines in the NDJSON.

Tracelane makes **no eIDAS or qualified-timestamp claim**.

Not on the Audit add-on? `GET /v1/audit/self-verify` runs a chain check over
your own ledger within your retention window, on every plan.

See [audit-format.md](audit-format.md) for the canonical format spec.

---

## Next steps

- [API reference](api-reference.md) — every mounted route, its error codes and
  its rate limits
- [Providers](providers.md) — the 150+ routable providers and their model prefixes
- [Architecture](architecture.md) — what's running under the hood, including
  which detectors fire on which traffic
- [Audit format](audit-format.md) — the v2 chain encoding and the two signing keys
- [CLI](cli.md) — `tlane verify`, `tlane prompt`, `tlane export`, `tlane replay`
- [MCP server](mcp-server.md) — the read-only MCP surface
- [Onboarding](onboarding.md) — if you don't have a key yet
