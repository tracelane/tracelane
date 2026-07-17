# apps/web

Tracelane's Next.js 15 dashboard — the customer-facing observability UI.

## Stack

- Next.js 15 App Router + React Server Components
- Tailwind 4 + shadcn/ui + Motion (animations)
- In-house transcript-spine trace viewer (SVG/DOM, `@tracelanedev/ui`) — no third-party viewer dependency
- TanStack Query + Zustand for client state
- `@clickhouse/client` with parameter binding (never raw SQL)
- Vitest + Playwright for testing

## Key pages

| Route | Purpose |
|---|---|
| `/` | Dashboard home — cost summary, predictive alerts feed, recent traces |
| `/traces/[traceId]` | Trace inspector — transcript-spine viewer (span tree, LLM messages, tool calls) |
| `/sessions` | Browser session replay — rrweb + span synchronisation (Week 7) |
| `/evals` | Eval scoreboard — CI-gate visualisation, trace-to-dataset 1-click |
| `tlane replay <traceId>` (CLI) | Step through a recorded trace in the terminal (shadow-fork replay UI is roadmap) |
| `/settings` | API keys, BYOK vault, team, billing |

## Key components

| Component | Purpose |
|---|---|
| `packages/ui/src/signature/TranscriptSpine.tsx` | In-house transcript-spine trace viewer (SVG/DOM) |
| `components/command-palette/` | Cmd+K palette — Linear-grade, <100ms response |
| `components/eval-scoreboard/` | Pain-point eval status table |
| `components/audit/` | Audit-ledger view + sales surface (tamper-evident hash chain) |

## Performance targets

- 10K-span trace load: <200ms p50, <500ms p95, <1s p99
- Cmd+K palette: <100ms response
- Trace search: <100ms p50, <300ms p95
