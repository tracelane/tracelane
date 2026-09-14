-- 0040 — BILL-01 / ADR-076: pricing v3 — six-meter allowances, windows, ceilings, per-key
-- budget cadences. EXPAND phase of expand → migrate → contract: every column is ADDED;
-- the retired trace-count / seat-cap columns are dropped by a later migration once no
-- deployed binary reads them (TRAPS §9 ordering: this lands in Neon BEFORE the gateway
-- that reads the new columns deploys, and the old columns stay until AFTER it does).
--
-- Un-journaled (TRAPS §9): apply by hand with psql against the DIRECT endpoint. Additive
-- and idempotent. The numbers are the founder's 2026-09-12 ruling, verbatim from
-- specs/BILL-01-metering-and-tiers.md §0.3; seed.mjs carries the same values and is the
-- source the docs/site/README copy guard compares against.

-- ── plan_entitlements: the ruled allowances per tier ──────────────────────────────────────
ALTER TABLE plan_entitlements
    ADD COLUMN IF NOT EXISTS price_monthly_usd        integer,          -- NULL = contract (Enterprise "from")
    ADD COLUMN IF NOT EXISTS price_annual_month_usd   integer,          -- the annual plan's per-month price; NULL = no annual
    ADD COLUMN IF NOT EXISTS price_from_usd           integer,          -- Enterprise "from $2,499"
    ADD COLUMN IF NOT EXISTS hot_gb_included          numeric(12,3),    -- NULL = custom (Enterprise)
    ADD COLUMN IF NOT EXISTS ingest_gb_included       numeric(12,3),
    ADD COLUMN IF NOT EXISTS series_included          bigint,
    ADD COLUMN IF NOT EXISTS scan_units_included      bigint,
    ADD COLUMN IF NOT EXISTS eval_runs_included       bigint,
    ADD COLUMN IF NOT EXISTS indexed_window_days      integer,
    ADD COLUMN IF NOT EXISTS queryable_days           integer,
    ADD COLUMN IF NOT EXISTS ledger_days              integer,
    ADD COLUMN IF NOT EXISTS cold_archive_days        integer,          -- NULL = complete (whole queryable history)
    ADD COLUMN IF NOT EXISTS unlimited_seats          boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS f_sso                    boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS overage_allowed          boolean NOT NULL DEFAULT false,  -- Free: no overage, ages out
    ADD COLUMN IF NOT EXISTS overflow_mode            text    NOT NULL DEFAULT 'auto_age'
        CHECK (overflow_mode IN ('auto_age', 'auto_overage')),
    -- The Polar product ids for this plan, written by scripts/ops/polar-sync.mjs (idempotent on
    -- lookup_key). The checkout route reads THESE, not a POLAR_PRODUCT_ID_<TIER> env var — an
    -- env-var product map is the class the ruling removes, and it is why annual products could
    -- not be added without a Worker redeploy.
    ADD COLUMN IF NOT EXISTS polar_product_id_month   text,
    ADD COLUMN IF NOT EXISTS polar_product_id_year    text,
    -- Per-tenant requests-per-minute, from the DB rather than `RateLimitTier::from_plan_tier_str`
    -- (a tier-string compare the ruling removes). NULL = no limit (Enterprise; also the
    -- no-control-plane self-host default, B-357). Values are the ones apps/docs/pricing.mdx
    -- has published since ADR-020: 60 / 600 / 6,000 / 60,000.
    ADD COLUMN IF NOT EXISTS rate_limit_rpm           integer;

UPDATE plan_entitlements SET rate_limit_rpm = 60     WHERE plan_lookup_key = 'free_v1';
UPDATE plan_entitlements SET rate_limit_rpm = 600    WHERE plan_lookup_key = 'builder_v1';
UPDATE plan_entitlements SET rate_limit_rpm = 6000   WHERE plan_lookup_key = 'team_v1';
UPDATE plan_entitlements SET rate_limit_rpm = 60000  WHERE plan_lookup_key = 'business_v1';
UPDATE plan_entitlements SET rate_limit_rpm = NULL   WHERE plan_lookup_key = 'enterprise_v1';

UPDATE plan_entitlements SET
    price_monthly_usd = 0,   price_annual_month_usd = NULL, price_from_usd = NULL,
    hot_gb_included = 0.25,  ingest_gb_included = 1,     series_included = 100,
    scan_units_included = 10, eval_runs_included = 50,
    indexed_window_days = 3, queryable_days = 30, ledger_days = 30, cold_archive_days = 7,
    unlimited_seats = false, f_sso = false, overage_allowed = false, overflow_mode = 'auto_age'
WHERE plan_lookup_key = 'free_v1';

UPDATE plan_entitlements SET
    price_monthly_usd = 29,  price_annual_month_usd = 24,  price_from_usd = NULL,
    hot_gb_included = 5,     ingest_gb_included = 25,    series_included = 2000,
    scan_units_included = 150, eval_runs_included = 2000,
    indexed_window_days = 30, queryable_days = 730, ledger_days = 730, cold_archive_days = NULL,
    unlimited_seats = true,  f_sso = false, overage_allowed = true, overflow_mode = 'auto_age'
WHERE plan_lookup_key = 'builder_v1';

UPDATE plan_entitlements SET
    price_monthly_usd = 229, price_annual_month_usd = 190, price_from_usd = NULL,
    hot_gb_included = 75,    ingest_gb_included = 300,   series_included = 15000,
    scan_units_included = 2000, eval_runs_included = 40000,
    indexed_window_days = 90, queryable_days = 730, ledger_days = 730, cold_archive_days = NULL,
    unlimited_seats = true,  f_sso = true,  overage_allowed = true, overflow_mode = 'auto_age'
WHERE plan_lookup_key = 'team_v1';

UPDATE plan_entitlements SET
    price_monthly_usd = 799, price_annual_month_usd = 665, price_from_usd = NULL,
    hot_gb_included = 300,   ingest_gb_included = 1500,  series_included = 75000,
    scan_units_included = 12000, eval_runs_included = 250000,
    indexed_window_days = 180, queryable_days = 730, ledger_days = 730, cold_archive_days = NULL,
    unlimited_seats = true,  f_sso = true,  overage_allowed = true, overflow_mode = 'auto_age'
WHERE plan_lookup_key = 'business_v1';

-- Enterprise: "custom" allowances are NULL (the resolver treats NULL as no cap); the 7-year
-- ledger folds in here because the Audit SKU is not sold (spec §10.4, founder ruling B1).
UPDATE plan_entitlements SET
    price_monthly_usd = NULL, price_annual_month_usd = NULL, price_from_usd = 2499,
    hot_gb_included = NULL,  ingest_gb_included = NULL,  series_included = NULL,
    scan_units_included = NULL, eval_runs_included = NULL,
    indexed_window_days = 365, queryable_days = 730, ledger_days = 2555, cold_archive_days = NULL,
    unlimited_seats = true,  f_sso = true,  overage_allowed = true, overflow_mode = 'auto_age'
WHERE plan_lookup_key = 'enterprise_v1';

-- ── workspace_entitlements: the same columns as NULLABLE overrides (deny-overrides-grant) ──
ALTER TABLE workspace_entitlements
    ADD COLUMN IF NOT EXISTS hot_gb_included          numeric(12,3),
    ADD COLUMN IF NOT EXISTS ingest_gb_included       numeric(12,3),
    ADD COLUMN IF NOT EXISTS series_included          bigint,
    ADD COLUMN IF NOT EXISTS scan_units_included      bigint,
    ADD COLUMN IF NOT EXISTS eval_runs_included       bigint,
    ADD COLUMN IF NOT EXISTS indexed_window_days      integer,
    ADD COLUMN IF NOT EXISTS queryable_days           integer,
    ADD COLUMN IF NOT EXISTS ledger_days              integer,
    ADD COLUMN IF NOT EXISTS f_sso                    boolean,
    ADD COLUMN IF NOT EXISTS overage_allowed          boolean,
    ADD COLUMN IF NOT EXISTS rate_limit_rpm           integer,
    ADD COLUMN IF NOT EXISTS overflow_mode            text
        CHECK (overflow_mode IS NULL OR overflow_mode IN ('auto_age', 'auto_overage'));

-- ── tenants: the customer-set ceiling (OFF by default), billing interval, price protection ─
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS spend_ceiling_usd        numeric(12,2),    -- NULL = no ceiling (the default)
    ADD COLUMN IF NOT EXISTS overflow_mode            text
        CHECK (overflow_mode IS NULL OR overflow_mode IN ('auto_age', 'auto_overage')),
    ADD COLUMN IF NOT EXISTS billing_interval         text
        CHECK (billing_interval IS NULL OR billing_interval IN ('month', 'year')),
    ADD COLUMN IF NOT EXISTS price_protected_until    timestamptz,      -- signup + 12 months, set by the webhook on first paid sub
    ADD COLUMN IF NOT EXISTS dunning_started_at       timestamptz,      -- set on subscription.past_due; cleared on .active
    ADD COLUMN IF NOT EXISTS data_hold_until          timestamptz,      -- drop-to-Free + 30 d; the purge refuses before this
    -- A3 velocity breaker: prompt promotion is frozen while these are set; a human clears them.
    ADD COLUMN IF NOT EXISTS promotion_frozen_at      timestamptz,
    ADD COLUMN IF NOT EXISTS promotion_frozen_reason  text;

-- ── api_keys: A3 — daily / weekly reset cadences for the existing monthly USD budget ───────
ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS budget_reset             text NOT NULL DEFAULT 'monthly'
        CHECK (budget_reset IN ('daily', 'weekly', 'monthly')),
    ADD COLUMN IF NOT EXISTS velocity_breaker         boolean NOT NULL DEFAULT false;

-- ── REFERENCE TABLES (founder, 2026-09-13: "try not to hardcode prices, limits, config
-- values and have them on reference tables so that is easy to update or modify later").
-- Rates and policy numbers are DATA: seeded from apps/web/db/plans.v3.json by seed.mjs,
-- read by the gateway on its entitlement-cache refresh (never per request), by the web
-- app, by scripts/ops/polar-sync.mjs (which sets the Polar unit prices from here) and by
-- the copy guard. No price, band, threshold or retry schedule is a literal in Rust or TS.
--
-- `price_version` is how price protection works: a tenant pins the version current at
-- signup for 12 months (`tenants.price_version`, below); a new ruling inserts a new
-- version and flips `is_current`, and nobody's pinned rows move.
CREATE TABLE IF NOT EXISTS pricing_rates (
    price_version   text        NOT NULL,             -- 'v3' (ADR-076)
    meter           text        NOT NULL,             -- ingest_gb | hot_gb_month | series | scan_units | cold_gb_month | eval_runs
    band_lo         numeric(14,3) NOT NULL DEFAULT 0, -- inclusive lower bound of the band, in the meter's unit
    band_hi         numeric(14,3),                    -- exclusive upper bound; NULL = open
    usd_per_unit    numeric(12,4) NOT NULL,
    unit            text        NOT NULL,             -- 'GB' | 'GB-month' | 'series-month' | 'scan-unit' | 'run'
    is_current      boolean     NOT NULL DEFAULT false,
    effective_from  date        NOT NULL DEFAULT current_date,
    PRIMARY KEY (price_version, meter, band_lo)
);

CREATE TABLE IF NOT EXISTS billing_policy (
    key             text PRIMARY KEY,                 -- burst_multiple | warn_pct_1 | warn_pct_2 | price_protection_months | free_idle_reclaim_days | dunning_retry_days | dunning_data_hold_days | refund_days | enterprise_onboarding_fee_usd | prepaid_credit_tiers | prepaid_expiry_months
    value           jsonb NOT NULL,
    updated_at      timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS price_version           text;             -- pinned at first paid subscription; NULL = current

-- ── meter-warning idempotency: one 75% and one 90% email per (tenant, meter, month) ───────
CREATE TABLE IF NOT EXISTS meter_warnings (
    tenant_id   uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    meter       text        NOT NULL,
    period      date        NOT NULL,   -- first day of the calendar month
    threshold   smallint    NOT NULL CHECK (threshold IN (75, 90, 100)),
    sent_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, meter, period, threshold)
);
