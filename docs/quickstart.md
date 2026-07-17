# Quickstart — first trace in 60 seconds

This guide takes you from "I have a Tracelane API key" to "I'm seeing my
first trace in the dashboard." Total time: ~60 seconds.

If you don't have an API key yet, skip ahead to [Onboarding](onboarding.md).

---

## 1. Install the SDK or point your existing OpenAI client

Tracelane is a drop-in proxy. You don't need to rewrite your agent code —
just point your existing client at our gateway.

### Python (any OpenAI / Anthropic / Bedrock client)

Point your existing client at the gateway base URL — it routes the call and
captures the trace. No SDK swap, no hand-instrumentation.

```python
import os
from anthropic import Anthropic

client = Anthropic(
    base_url="https://gateway.tracelane.dev",
    api_key=os.environ["TRACELANE_API_KEY"],  # tlane_… from app.tracelane.dev
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
with `$TRACELANE_GATEWAY_URL/v1`:

| Provider | Before | After |
|---|---|---|
| OpenAI | `https://api.openai.com/v1` | `$TRACELANE_GATEWAY_URL/v1` |
| Anthropic | `https://api.anthropic.com/v1` | `$TRACELANE_GATEWAY_URL/v1` |
| Bedrock | `https://bedrock-runtime.<region>.amazonaws.com` | `$TRACELANE_GATEWAY_URL/v1` (model prefix `bedrock/`) |

Use your provider's API key as the bearer token. We forward it to the
upstream provider — never store it.

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

`model` accepts any model name from the 35 supported providers. The
gateway routes by prefix: `claude-*` → Anthropic, `gpt-*` → OpenAI,
`bedrock/*` → AWS Bedrock, `gemini-*` → Google, etc. Full list in
[providers.md](providers.md).

---

## 3. See your trace in the dashboard

Open [`https://app.tracelane.dev/traces`](https://app.tracelane.dev/traces).
Your request shows up within 1 second of returning. Click into it for the
WebGL waterfall view.

What you'll see in V1:
- Full request + response (with PII auto-redacted in storage)
- Token usage per step + cost estimate
- Predictive guardrail decisions (PR1–PR8 fires inline on every request)
- Provider failover trail if the primary errored
- Tamper-evident chain hash + Rekor entry id (for the $999/mo Audit-SKU)

---

## 4. Verify your audit log offline (Audit-SKU)

```bash
tlane audit export --since 2026-01-01 > audit.ndjson
tlane verify audit.ndjson
```

The verifier is reproducible across three independent implementations
(Rust, Python, TypeScript) and produces byte-identical reports. Anyone
can verify a Tracelane audit log against the public Sigstore Rekor
transparency log without any Tracelane credentials.

See [audit-format.md](audit-format.md) for the canonical format spec.

---

## Next steps

- [Predictive guardrails](predictive-guardrails.md) — PR1–PR8 catalog
- [Prompt promotion](prompt-promotion.md) — eval-gated promote +
  auto-rollback (B1, Team tier)
- [Migrating from Helicone](migrations/from-helicone.md) — the 16K-org
  orphan path
- [Migrating from LiteLLM](migrations/from-litellm.md) — the CVE
  refugee path
- [API reference](api-reference.md) — full REST catalog
- [Architecture](architecture.md) — what's running under the hood
