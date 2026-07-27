-- Migration 09: Pricing v2 — Postgres-row entitlements + per-tenant Slack alert
-- channel. Postgres 17 + Neon-compatible. Idempotent.
--
-- Why this exists:
--   Per-feature entitlement grants live in Postgres
--   rows under deny-overrides-grant, not in a hardcoded TypeScript map.
--   Until Migration 09 there was no row table, so the dashboard's
--   `/api/entitlements` derived flags from `tenants.plan_tier` only.
--   Pricing v2 needs per-tenant overrides (seat caps, retention, PR-feature
--   phasing, HIPAA opt-in), so the row table cannot be deferred to V1.5.
--
-- Why no `workspaces` table:
--   Tracelane uses `tenants` as the workspace concept (see 01_tenants.sql).
--   "workspaces" terminology is normalised to "tenants" here to avoid
--   forking the data model.
--
-- Two new tables + one column on `tenants`:
--   1. plan_entitlements      — per-plan defaults (one row per plan lookup_key).
--   2. workspace_entitlements — per-tenant overrides (deny-overrides-grant).
--   3. tenants.slack_webhook_url — nullable; quota-exceeded 429 alerts POST here.

------------------------------------------------------------------------------
-- 1. plan_entitlements: per-plan defaults
------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS plan_entitlements (
    plan_lookup_key            TEXT          PRIMARY KEY,    -- 'builder_v1' | 'team_v1' | ...
    seat_cap_included          INT           NOT NULL DEFAULT 1,
    seat_cap_max               INT           NOT NULL DEFAULT 1,    -- 0 = unlimited (Enterprise)
    retention_days             INT           NOT NULL DEFAULT 7,
    trace_quota_monthly        BIGINT        NOT NULL DEFAULT 10000,
    gateway_quota_monthly      BIGINT        NOT NULL DEFAULT 10000,
    overage_hard_cap_multiplier NUMERIC(4,1) NOT NULL DEFAULT 1.0,  -- 5.0 => quota * 5 then 429
    overage_price_per_10k_usd  NUMERIC(6,2)  NOT NULL DEFAULT 0.00,
    -- Predictive-feature flags
    f_pr7_trajectory           BOOLEAN       NOT NULL DEFAULT FALSE,
    f_pr8_argdrift             BOOLEAN       NOT NULL DEFAULT FALSE,
    f_pr9_a2a_handoff          BOOLEAN       NOT NULL DEFAULT FALSE,
    f_pr10_inline_slm_judge    BOOLEAN       NOT NULL DEFAULT FALSE,
    f_pr11_slo_drift           BOOLEAN       NOT NULL DEFAULT FALSE,
    f_pr12_langgraph_branch    BOOLEAN       NOT NULL DEFAULT FALSE,
    f_cohort_baselines         BOOLEAN       NOT NULL DEFAULT FALSE,
    f_hipaa_gcp_addon          BOOLEAN       NOT NULL DEFAULT FALSE,
    f_audit_addon              BOOLEAN       NOT NULL DEFAULT FALSE,
    created_at                 TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at                 TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

------------------------------------------------------------------------------
-- 2. workspace_entitlements: per-tenant overrides (deny-overrides-grant)
--    Lookup pattern: read the row by tenant_id; for each column, NULL means
--    "inherit from plan_entitlements". Any non-NULL value overrides the
--    plan default. Deny wins — if `f_*` is FALSE here it overrides a
--    TRUE in plan_entitlements.
------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS workspace_entitlements (
    tenant_id                  UUID          PRIMARY KEY REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    plan_lookup_key            TEXT          NOT NULL REFERENCES plan_entitlements(plan_lookup_key),
    -- All override columns nullable so NULL == "inherit plan default"
    seat_cap_included          INT,
    seat_cap_max               INT,
    retention_days             INT,
    trace_quota_monthly        BIGINT,
    gateway_quota_monthly      BIGINT,
    overage_hard_cap_multiplier NUMERIC(4,1),
    overage_price_per_10k_usd  NUMERIC(6,2),
    f_pr7_trajectory           BOOLEAN,
    f_pr8_argdrift             BOOLEAN,
    f_pr9_a2a_handoff          BOOLEAN,
    f_pr10_inline_slm_judge    BOOLEAN,
    f_pr11_slo_drift           BOOLEAN,
    f_pr12_langgraph_branch    BOOLEAN,
    f_cohort_baselines         BOOLEAN,
    f_hipaa_gcp_addon          BOOLEAN,
    f_audit_addon              BOOLEAN,
    created_at                 TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at                 TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_workspace_entitlements_plan
    ON workspace_entitlements(plan_lookup_key);

------------------------------------------------------------------------------
-- 3. tenants.slack_webhook_url for hard-cap quota-exceeded 429 alerts.
--    Nullable. Failure to POST must not block the 429 response (gateway code
--    is fire-and-forget — see crates/gateway/src/rate_limiter.rs).
------------------------------------------------------------------------------
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS slack_webhook_url TEXT;

------------------------------------------------------------------------------
-- 4. Seed plan_entitlements for the v2 ladder. INSERT…ON CONFLICT DO UPDATE
--    so re-running the migration normalises rows to the latest values.
------------------------------------------------------------------------------
INSERT INTO plan_entitlements (
    plan_lookup_key, seat_cap_included, seat_cap_max, retention_days,
    trace_quota_monthly, gateway_quota_monthly,
    overage_hard_cap_multiplier, overage_price_per_10k_usd,
    f_pr7_trajectory, f_pr8_argdrift, f_pr9_a2a_handoff,
    f_pr10_inline_slm_judge, f_pr11_slo_drift, f_pr12_langgraph_branch,
    f_cohort_baselines, f_hipaa_gcp_addon, f_audit_addon
) VALUES
    -- Free hosted: 10K + 10K, 60 RPM, 7d retention, no overage allowed.
    ('free_v1',       1, 1,   7,    10000,    10000, 1.0, 0.00,
                       FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE),
    -- Builder: 150K + 150K, 600 RPM, 30d retention, $1.20/10K (5× hard cap → 429).
    ('builder_v1',    1, 1,   30,  150000,   150000, 5.0, 1.20,
                       FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE),
    -- Team: 1M + 1M, 6K RPM, 90d retention, 10 seats incl + $19/seat to 25, 99% SLA.
    ('team_v1',      10, 25,  90, 1000000,  1000000, 5.0, 1.20,
                       FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE),
    -- Business: 5M + 5M, 60K RPM, 180d retention, 25 seats incl + $19/seat to 50, 99.9% SLA.
    ('business_v1',  25, 50, 180, 5000000,  5000000, 5.0, 1.20,
                       FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE),
    -- Enterprise: 25M+ custom, unlimited seats (seat_cap_max=0), 365d, 99.95% SLA.
    -- Per-tenant grants flip f_* TRUE on rollout.
    -- f_cohort_baselines: flipped per-tenant when cohort size n≥30.
    ('enterprise_v1', 0,  0, 365, 25000000, 25000000, 99.0, 1.00,
                       FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE)
ON CONFLICT (plan_lookup_key) DO UPDATE SET
    seat_cap_included           = EXCLUDED.seat_cap_included,
    seat_cap_max                = EXCLUDED.seat_cap_max,
    retention_days              = EXCLUDED.retention_days,
    trace_quota_monthly         = EXCLUDED.trace_quota_monthly,
    gateway_quota_monthly       = EXCLUDED.gateway_quota_monthly,
    overage_hard_cap_multiplier = EXCLUDED.overage_hard_cap_multiplier,
    overage_price_per_10k_usd   = EXCLUDED.overage_price_per_10k_usd,
    updated_at                  = NOW();
