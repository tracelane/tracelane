# apps/web — local rules

> Loads only when working under `apps/web/`. Long form: `docs/TRAPS.md`.

## `NEXT_PUBLIC_*` is constant-folded at BUILD time

A `NEXT_PUBLIC_*` var is **inlined into the bundle when the app is built**. Setting it
at runtime does nothing.

deployed Worker → the 2026-07-28 production sign-in outage. Only `wrangler secret put`
bridges a runtime secret into a Cloudflare Worker.

Before any deploy, confirm the build environment — not the runtime environment — holds
the right values. → `docs/TRAPS.md` §6

## Webhook timestamp units differ by provider — never unify them

| Provider | `t=` unit |
|---|---|
| **WorkOS** | **milliseconds** |
| **Polar** / Standard Webhooks | **seconds** |

The HMAC is computed over the **raw** `t` value, so "normalising" them breaks signature
verification. → `docs/TRAPS.md` §7

Polar specifics that have each cost a debugging session:
- Idempotency keys on the **`webhook-id` HEADER**, not a body field — the envelope has
  no top-level `id`, and requiring one rejects every real delivery.
- The HMAC key is the **raw UTF-8 bytes of the entire secret string**, prefix included.
  Do **not** strip `polar_whs_` and do **not** base64-decode.
- Org id for subscription/order events lives at `data.product.organization_id` — there
  is no top-level `organization_id` on them.
- **Never** change a plan by editing the DB. → `.claude/rules/billing.md`

## This app has no ClickHouse client

Every ClickHouse read is a gateway `/v1/*` call. `lib/gateway.ts` owns the one
validated base URL. Adding a dashboard read means **extending
`crates/gateway/src/trace_reads.rs`**, not writing a client here — that is what created
the org_id seam bugs.

Binding `session.tenantId` into a Postgres `eq(tenants.workosOrgId, …)` filter is
correct and sanctioned; binding an org id into a *gateway/ClickHouse* query is not.

## Timestamps: UTC everywhere, always labelled

Use `format-date.ts` (`absoluteDate` / `formatStartedUtc`). **Never `toLocaleString`
for user-facing dates.** Gateway `toString()` dates are **naive** (no `Z`), so
`new Date()` parses them as local time and shifts per viewer. Parse with `parseUtcMs`.
Test under a non-UTC `TZ` (e.g. `TZ=Asia/Kolkata`).

## Migrations

`db/schema.ts` is canonical, but **`drizzle-kit migrate` applies only 0000–0008** — the
journal stops there. 0009+ were applied to Neon by hand and are explicitly un-journaled
(`db/migrations/0010_…sql:16-19`). A new entitlement column must land in Neon **before**
the gateway that reads it deploys, or the resolver 500s. → `docs/TRAPS.md` §9

`infra/dev/postgres/migrations/` is the **retired** pre-ADR-040 tree — nothing applies
it, though `db/seed.mjs:6-8` still cites it as authoritative.

## Conventions that differ from the ecosystem default

- **No biome config file exists anywhere in the repo**, so only the recommended set
  applies and `noConsoleLog` is off. The honoured convention is `logSafe()` on any
  customer-controlled value before interpolating it into a log.
- **Design tokens only — never hardcode hex** (`packages/ui/src/styles/tokens.css`).
- UI primitives come from `@tracelanedev/ui`. There is no shadcn, no Motion, no Zustand.
