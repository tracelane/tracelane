# Migrating from Helicone to Tracelane

**Time to migrate:** <2 minutes  
**Status:** Helicone was acquired by Mintlify (March 3, 2026) and is in maintenance mode.
16,000+ organizations are affected.

---

## One-command migration

```bash
npx @tracelanedev/cli migrate helicone --apply
```

This command:
1. Scans `.env*` files and replaces `HELICONE_API_KEY` / `HELICONE_BASE_URL` with
   Tracelane equivalents
2. Scans `*.{ts,js,py}` for Helicone SDK imports and base-URL references
3. Shows a diff before writing (dry-run by default)

---

## Manual migration

### Environment variables

| Before | After |
|---|---|
| `HELICONE_API_KEY=sk-helicone-...` | `TRACELANE_API_KEY=tlk-...` |
| `HELICONE_BASE_URL=https://oai.helicone.ai/v1` | `TRACELANE_GATEWAY_URL=https://gateway.tracelane.dev/v1` |

### OpenAI SDK (Python)

**Before:**
```python
client = openai.OpenAI(
    api_key=os.environ["OPENAI_API_KEY"],
    base_url="https://oai.helicone.ai/v1",
    default_headers={"Helicone-Auth": f"Bearer {os.environ['HELICONE_API_KEY']}"}
)
```

**After:**
```python
client = openai.OpenAI(
    api_key=os.environ["OPENAI_API_KEY"],
    base_url=os.environ["TRACELANE_GATEWAY_URL"],
    default_headers={"Authorization": f"Bearer {os.environ['TRACELANE_API_KEY']}"}
)
```

### OpenAI SDK (TypeScript)

**Before:**
```typescript
const client = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
  baseURL: "https://oai.helicone.ai/v1",
  defaultHeaders: { "Helicone-Auth": `Bearer ${process.env.HELICONE_API_KEY}` },
});
```

**After:**
```typescript
const client = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
  baseURL: `${process.env.TRACELANE_GATEWAY_URL}/v1`,
  defaultHeaders: { "Authorization": `Bearer ${process.env.TRACELANE_API_KEY}` },
});
```

---

## What's different

| Feature | Helicone | Tracelane |
|---|---|---|
| BYOK proxy | ✅ | ✅ |
| Request logging | ✅ | ✅ Full-fidelity OTel traces |
| Caching | ✅ | Roadmap |
| Rate limiting | ✅ | ✅ |
| Predictive guardrails | ❌ | ✅ 10 inline, <30ms |
| Tamper-evident audit log | ❌ | ✅ Merkle chain + Rekor |
| EU AI Act Art. 12 export | ❌ | ✅ |
| OTel `gen_ai.*` semconv | ❌ | ✅ |
| License | MIT | Apache 2.0 |
| Status | Maintenance (acquired Mar 2026) | Active |

---

## Get help

- Run `tlane migrate helicone --help` for all options
- Docs: https://tracelane.dev/docs/migrations/from-helicone
- GitHub: https://github.com/tracelane/tracelane/issues
