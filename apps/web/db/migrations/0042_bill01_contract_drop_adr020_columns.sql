-- 0042 — BILL-01 / ADR-076, the CONTRACT step of expand → migrate → contract
-- (spec `specs/BILL-01-metering-and-tiers.md` §2.6). Founder, 2026-09-14:
-- "no old code logic should exist" — so the ADR-020 columns go now, not one
-- release later. Nothing reads them: the gateway resolver dropped
-- `retention_days` / `f_hipaa_gcp_addon` from its SELECT in the same commit and
-- never read the other six; `apps/web/db/schema.ts` no longer declares them;
-- `seed.mjs` no longer writes them.
--
-- ORDER — applied BY HAND on Neon like every migration since 0009 (the gateway's
-- `db/mod.rs` MIGRATIONS list is what the TEST databases and the integration
-- runners apply; nothing runs it at prod boot — verified 2026-09-14 when a fresh
-- gateway booted with all 17 columns still present):
--   1. deploy apps/web (its Drizzle schema no longer names these columns),
--   2. deploy the gateway (no longer reads them),
--   3. THEN apply this file. Applied on prod 2026-09-14 09:08 UTC; read back: 0 left.
--
-- Un-journaled like every migration since 0009 (`0010_…sql:16-19`). Idempotent.

ALTER TABLE plan_entitlements
    DROP COLUMN IF EXISTS seat_cap_included,
    DROP COLUMN IF EXISTS seat_cap_max,
    DROP COLUMN IF EXISTS retention_days,
    DROP COLUMN IF EXISTS trace_quota_monthly,
    DROP COLUMN IF EXISTS gateway_quota_monthly,
    DROP COLUMN IF EXISTS overage_hard_cap_multiplier,
    DROP COLUMN IF EXISTS overage_price_per_10k_usd,
    DROP COLUMN IF EXISTS f_hipaa_gcp_addon;

ALTER TABLE workspace_entitlements
    DROP COLUMN IF EXISTS seat_cap_included,
    DROP COLUMN IF EXISTS seat_cap_max,
    DROP COLUMN IF EXISTS retention_days,
    DROP COLUMN IF EXISTS trace_quota_monthly,
    DROP COLUMN IF EXISTS gateway_quota_monthly,
    DROP COLUMN IF EXISTS overage_hard_cap_multiplier,
    DROP COLUMN IF EXISTS overage_price_per_10k_usd,
    DROP COLUMN IF EXISTS f_hipaa_gcp_addon,
    -- B-388's clock for the Audit SKU add-on subscription. The add-on purchase
    -- path is deleted with this migration (the SKU is not sold, B-392); the
    -- base plan keeps its own clock on `tenants.polar_subscription_modified_at`.
    DROP COLUMN IF EXISTS addon_modified_at;
