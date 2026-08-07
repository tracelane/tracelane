<!-- tracelane:classification: INTERNAL -->
# apps/web

Tracelane's Next.js 15 dashboard — the customer-facing observability UI.

## Stack

- Next.js 15 App Router + React Server Components
- Tailwind 4. UI primitives come from `@tracelanedev/ui` — there is no shadcn/ui, no Motion, no Zustand
- In-house transcript-spine trace viewer (SVG/DOM, `@tracelanedev/ui`) — no third-party viewer dependency
- TanStack Query for client-side fetching state
- **No ClickHouse client.** Every span/trace read is a gateway `/v1/*` call through `lib/gateway.ts`; a new dashboard read means extending `crates/gateway/src/trace_reads.rs`. Drizzle talks to the control-plane Postgres (Neon) and nothing else
- Vitest + Playwright for testing

## Key pages

| Route | Purpose |
|---|---|
| `/` | Redirect only — new users to `/onboarding`, everyone else to `/dashboard` (`app/page.tsx`) |
| `/dashboard` | Overview landing surface — SLO burn, error rate, latency, top failure signatures; every card a real gateway read |
| `/traces/[traceId]` | Trace inspector — transcript-spine viewer (span tree, LLM messages, tool calls) |
| `/sessions` | Multi-turn agent sessions — traces threaded by `gen_ai.conversation.id`, via gateway `/v1/sessions` |
| `tlane replay <traceId>` (CLI) | Step through a recorded trace in the terminal (shadow-fork replay UI is roadmap) |
| `/settings` | API keys, BYOK vault, providers, team, billing, alerts, audit |

## Key components

| Component | Purpose |
|---|---|
| `packages/ui/src/signature/TranscriptSpine.tsx` | In-house transcript-spine trace viewer (SVG/DOM) |
| `components/command-palette/` | Cmd+K palette |
| `components/trace-viewer/` | Trace list, waterfall, span inspector, chain-status chip |
| `components/audit/` | Audit-ledger view + sales surface (tamper-evident hash chain) |

## Performance

No dashboard-side latency benchmark exists yet — `bench/` covers the gateway and
the predictive ML channels only, so this README carries no frontend numbers.
Measure before you publish one.
