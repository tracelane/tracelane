-- 0029_gwy43_per_key_rate_limit_and_workspace_budget.sql
--
-- GWY-43 — per-key rate limits (Sprint 1 item 3). Additive and idempotent.
--
-- ORDERING RULE (CLAUDE.md §4.0, S2 · apps/web/CLAUDE.md "Migrations"): this
-- lands in Neon **BEFORE** the gateway that reads the column deploys. The
-- gateway's hot-path auth SELECT now reads `rate_limit_rpm` in the same round
-- trip that authenticates the key, so a gateway deployed ahead of this migration
-- 500s on every API-key request — not degrades, 500s. Apply first.
--
-- Migrations 0009+ are un-journaled and hand-applied (CLAUDE.md rule 5), so
-- `drizzle-kit migrate` will NOT run this. `scripts/ci/audit-migration-drift.py`
-- is what notices if it half-lands.
--
-- ═══════════════════════════════════════════════════════════════════════════
-- WHY A SECOND LIMIT AT ALL
--
-- The gateway's rate limiter is keyed `(tenant_id, plan_tier)`: one bucket per
-- workspace, sized by what they pay. That protects the PLATFORM and is the right
-- shape for it. It does nothing for the customer's own problem, which is that a
-- runaway script holding one key consumes the whole workspace's allowance and
-- takes production down with it. Per-key limits are that ceiling, and they are
-- table stakes against LiteLLM and Portkey.
--
-- NULL = "use the tenant's plan tier", which is exactly what every key did
-- before this column existed. So NULL preserves today's behaviour for every
-- existing row, and there is no backfill.
--
-- The check constraint rejects 0 rather than treating it as "block everything":
-- a key that can never be used is a foot-gun, and `revoked_at` already exists
-- for switching a key off. Same reasoning as `budget_usd_monthly`, whose 0 the
-- gateway reads as uncapped.
-- ═══════════════════════════════════════════════════════════════════════════

ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS rate_limit_rpm integer;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'api_keys_rate_limit_rpm_positive_chk'
    ) THEN
        ALTER TABLE api_keys
            ADD CONSTRAINT api_keys_rate_limit_rpm_positive_chk
            CHECK (rate_limit_rpm IS NULL OR rate_limit_rpm > 0);
    END IF;
END $$;

COMMENT ON COLUMN api_keys.rate_limit_rpm IS
    'GWY-43. Per-key requests-per-minute ceiling. NULL = inherit the tenant plan tier '
    '(pre-GWY-43 behaviour). Enforced in the gateway by RateLimiter::check_scoped, which '
    'checks the TENANT bucket first — a per-key value can only narrow the platform limit, '
    'never widen it.';

-- ═══════════════════════════════════════════════════════════════════════════
-- WORKSPACE-LEVEL SPEND CAP (the "per-team" half of Sprint 1 item 2).
--
-- There is no `teams` table in this schema and there never was — a "team" in
-- this product IS the workspace (WorkOS org → `tenants` row), and
-- `TeamManager.tsx` manages that workspace's members. So the per-team cap is a
-- per-tenant cap, on `tenants`, and this comment exists so the next reader does
-- not go looking for a table that would have to be invented to satisfy a word.
--
-- `tenants` already has a monthly TRACE quota driven by the plan. This is a
-- separate, customer-set DOLLAR ceiling across every key in the workspace, and
-- it composes with the per-key one: a request must pass BOTH. That is what makes
-- "give the CI key $50 of a $500 workspace budget" expressible.
--
-- NULL = uncapped, matching `api_keys.budget_usd_monthly`. Same numeric(12,4),
-- so the two are read and compared the same way and neither can silently hold
-- more precision than the other.
-- ═══════════════════════════════════════════════════════════════════════════

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS budget_usd_monthly numeric(12, 4);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'tenants_budget_nonneg_chk'
    ) THEN
        ALTER TABLE tenants
            ADD CONSTRAINT tenants_budget_nonneg_chk
            CHECK (budget_usd_monthly IS NULL OR budget_usd_monthly >= 0);
    END IF;
END $$;

COMMENT ON COLUMN tenants.budget_usd_monthly IS
    'GWY-43. Workspace-wide monthly USD spend ceiling across ALL keys. NULL = uncapped. '
    'Composes with api_keys.budget_usd_monthly: a request must pass both. Enforced in the '
    'gateway by crate::spend, which tracks per-key and per-tenant totals in one place.';
