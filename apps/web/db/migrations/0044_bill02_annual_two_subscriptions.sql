-- 0044 — BILL-02 (founder ruling B14 → option (c), 2026-09-16): annual billing
-- as TWO Polar subscriptions per tenant — a yearly BASE product (no meters, no
-- credits) and a $0 monthly USAGE product carrying the six meters and the
-- monthly allowance credits. The pair resolver (apps/web/lib/polar-webhook.ts
-- `resolvePair`) serves the tier only when both halves are active on the same
-- plan and refuses every half-state to Free with a named alert
-- (specs/BILL-02-annual-two-subscriptions.md §2.4).
--
-- Expand-only. The gateway's entitlement SELECT reads NONE of these columns
-- (billing_interval + current_period_* stay the interface), so the boot schema
-- check is unaffected and the refusal logic lives in exactly one place.
--
-- ORDER — applied BY HAND on Neon like every migration since 0009:
--   1. THIS file,
--   2. `node scripts/ops/polar-sync.mjs --apply` (creates the two products per
--      plan and writes their ids into plan_entitlements),
--   3. deploy apps/web (webhook + resolver + checkout).
-- Un-journaled like every migration since 0009 (`0010_…sql:16-19`). Idempotent.

-- `annual_pair` is the resolver's INPUT, verbatim: the last-seen state of each
-- half ({ base: {id, plan, status, period_end}, usage: {id, plan, status,
-- period_start, period_end}, alert }) so the webhook can resolve the pair from
-- Neon alone — it never calls Polar mid-request. The two id columns are the
-- same ids again, as plain columns, for lookups by subscription id.
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS polar_base_subscription_id text,
    ADD COLUMN IF NOT EXISTS polar_usage_subscription_id text,
    ADD COLUMN IF NOT EXISTS annual_pair jsonb;

ALTER TABLE plan_entitlements
    ADD COLUMN IF NOT EXISTS polar_product_id_base_year text,
    ADD COLUMN IF NOT EXISTS polar_product_id_usage_month text;
