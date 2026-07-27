-- Migration 14: full-capture entitlement flag + per-tenant sampling policy
-- + operational force-tail kill-switch (ADR-048 D1/D2/D4). Postgres 17 +
-- Neon-compatible. Idempotent (additive ALTERs + ON CONFLICT-free UPDATEs).
--
-- Why this exists:
--   ADR-048 closes the unbounded full-capture COGS hole opened post-#81 (where
--   prod was pinned to 100% full-fidelity for every tenant). Sampling now
--   defaults to `tail`; `full` capture becomes a gated entitlement granted to
--   Business + Enterprise base (and forced while the Audit SKU is active).
--   The tail sampler today is process-global and tenant-blind
--   (crates/ingest/src/tail_sampler.rs), so a tiered model needs real columns,
--   not config — see the sampling-mechanism design.
--
-- Adds:
--   1. plan_entitlements.f_full_capture       — per-plan default gate.
--   2. workspace_entitlements.f_full_capture  — per-tenant override (NULL=inherit).
--   3. tenants.sampling_policy {tail|full}    — the tenant's preference WITHIN
--                                               what f_full_capture entitles.
--   4. tenants.force_tail                     — operational kill-switch (ADR-048
--                                               entitlements; stops one runaway
--                                               tenant without a deploy.
--   5. NOTIFY trigger on tenants → the ingest tenant_config_cache.
--
-- The migration-12 entitlements_changed triggers are table-level (AFTER
-- INSERT/UPDATE/DELETE FOR EACH ROW), so f_full_capture changes already
-- propagate to the gateway entitlement cache — no trigger change needed there.
--
-- ⚠ APPLY WITH PRODUCTION MIGRATION TOOLING (drizzle-kit migrate / psql), NOT
-- the gateway dev `apply_migrations` helper: it splits on ';' and would shred
-- the PL/pgSQL `$$` function body below.

------------------------------------------------------------------------------
-- 1 + 2. f_full_capture columns. plan default NOT NULL DEFAULT FALSE; the
--        workspace override is nullable (NULL == inherit the plan default),
--        matching every other f_* override column from migration 09.
------------------------------------------------------------------------------
ALTER TABLE plan_entitlements
    ADD COLUMN IF NOT EXISTS f_full_capture BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE workspace_entitlements
    ADD COLUMN IF NOT EXISTS f_full_capture BOOLEAN;

------------------------------------------------------------------------------
-- 3. sampling_policy on tenants: the tenant's preference, honoured only when
--    f_full_capture is granted. Default 'tail' (ADR-048 D1). CHECK-constrained.
------------------------------------------------------------------------------
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS sampling_policy TEXT NOT NULL DEFAULT 'tail';
ALTER TABLE tenants
    DROP CONSTRAINT IF EXISTS tenants_sampling_policy_chk;
ALTER TABLE tenants
    ADD CONSTRAINT tenants_sampling_policy_chk
    CHECK (sampling_policy IN ('tail', 'full'));

------------------------------------------------------------------------------
-- 4. force_tail operational kill-switch (ADR-048 D4.4). TRUE forces tail even
--    on a full-entitled tenant — bounds a runaway tenant without a deploy.
--    Does NOT override the Audit-SKU forced-full guarantee (an audited tenant's
--    completeness is bounded by the per-trace ceiling + quota 429, not by
--    silently dropping spans). Default FALSE.
------------------------------------------------------------------------------
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS force_tail BOOLEAN NOT NULL DEFAULT FALSE;

-- 4b. billing_email: the contact that receives the D5 quota-breach notice
--     (1/tenant/24h). Nullable — when unset, the ingest quota still 429s; the
--     breach is logged loudly instead of emailed.
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS billing_email TEXT;

------------------------------------------------------------------------------
-- 5. Grant f_full_capture to Business + Enterprise base (ADR-048 D2). All other
--    tiers stay FALSE (the column default). Idempotent; explicit on every tier
--    so a re-run normalises drift.
------------------------------------------------------------------------------
UPDATE plan_entitlements SET f_full_capture = TRUE,  updated_at = NOW()
    WHERE plan_lookup_key IN ('business_v1', 'enterprise_v1');
UPDATE plan_entitlements SET f_full_capture = FALSE, updated_at = NOW()
    WHERE plan_lookup_key IN ('free_v1', 'builder_v1', 'team_v1');

------------------------------------------------------------------------------
-- 6. NOTIFY trigger on tenants for the ingest tenant_config_cache
--    (sampling_policy / force_tail / plan changes). Channel:
--    'tenant_config_changed', payload = tenant_id. Mirrors migration 12; the
--    cache's 30s TTL bounds staleness if LISTEN is unavailable.
------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION notify_tenant_config_changed()
RETURNS trigger AS $$
DECLARE
    affected UUID;
BEGIN
    affected := COALESCE(NEW.tenant_id, OLD.tenant_id);
    PERFORM pg_notify('tenant_config_changed', affected::text);
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_tenants_config_notify ON tenants;
CREATE TRIGGER trg_tenants_config_notify
    AFTER INSERT OR UPDATE OR DELETE ON tenants
    FOR EACH ROW EXECUTE FUNCTION notify_tenant_config_changed();
