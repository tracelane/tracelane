-- 0043 — BILL-01 amendment A5 (founder ruling B6, 2026-09-14) + B-410.
--
-- (a) Every paid tier gets a COLD-ARCHIVE ALLOWANCE = 24 x its monthly ingest
--     allowance (two years of included ingest); meter 5 ($0.08/GB-month,
--     pricing_rates cold_gb_month) bills only BEYOND it, on the same mean-daily
--     basis as meter 2. Free: NULL (7-day cold window, no allowance).
--     Enterprise: NULL = custom. The VALUES come from apps/web/db/plans.v3.json
--     via `node apps/web/db/seed.mjs`; this file only adds the column.
-- (b) The Polar subscription cycle on the tenant, written by the webhook from
--     `current_period_start/end`, so the usage route rates per BILLING PERIOD
--     and agrees with the invoice (Polar credits and bills per cycle). NULL =
--     no paid cycle known -> calendar-month fallback.
--
-- ORDER — applied BY HAND on Neon like every migration since 0009 (nothing
-- applies migrations at prod boot; the gateway now REFUSES TO BOOT when a
-- column its entitlement query names is absent — see server.rs):
--   1. THIS file,
--   2. `node apps/web/db/seed.mjs` (fills cold_gb_included + the re-derived
--      ingest allowances 20/100/200),
--   3. deploy apps/web (webhook writes the period), then the gateway.
-- Un-journaled like every migration since 0009 (`0010_…sql:16-19`). Idempotent.

ALTER TABLE plan_entitlements
    ADD COLUMN IF NOT EXISTS cold_gb_included numeric(12,3);

ALTER TABLE workspace_entitlements
    ADD COLUMN IF NOT EXISTS cold_gb_included numeric(12,3);

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS current_period_start timestamptz,
    ADD COLUMN IF NOT EXISTS current_period_end   timestamptz;

COMMENT ON COLUMN plan_entitlements.cold_gb_included IS
  'BILL-01 A5 (2026-09-14): included cold-archive GB-month per period = 24 x ingest_gb_included on paid tiers; meter 5 bills only beyond it. NULL = none (Free) or custom (Enterprise).';
COMMENT ON COLUMN tenants.current_period_start IS
  'B-410: the Polar subscription cycle start, from the webhook; the usage route rates from here so the dashboard agrees with the invoice.';
