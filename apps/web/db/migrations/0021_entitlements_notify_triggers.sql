-- 0021: emit `entitlements_changed` NOTIFY on every entitlement write so
-- the gateway's in-process entitlement cache (`crates/gateway/src/
-- entitlement_cache.rs`) evicts IMMEDIATELY instead of waiting out the 15-min TTL.
--
-- WHY THIS EXISTS: migration 12 (`infra/dev/postgres/migrations/12_entitlements_
-- notify.sql`) created these triggers for DEV only. Prod applies the numbered
-- Drizzle files here (like 0019 for key_revoked), and the entitlements pair was
-- NEVER ported — so prod had the functions/triggers MISSING while the gateway
-- logged "control-plane LISTEN active on entitlements_changed". The LISTEN was
-- connected but nothing ever fired the NOTIFY: a plan upgrade (webhook → tenants.
-- plan + workspace_entitlements) took up to 15 min to unlock gated features at
-- the gateway (prompt promotion, quotas, guardrails). Green-while-broken +
-- dev-only-migration drift (class). Found 2026-07-28 verifying the
-- free→team flip actually unlocks prompt promotion.
--
-- Payload:
--   - workspace_entitlements → the affected tenant_id (UUID) → evict that tenant.
--   - plan_entitlements      → 'ALL' → a plan default changed → evict every tenant.
-- The gateway LISTENs over a DIRECT Neon connection (PgBouncer transaction
-- pooling does not pass LISTEN/NOTIFY). The 15-min TTL remains the backstop if
-- LISTEN drops; correctness never depends on NOTIFY delivery.
--
-- Idempotent (CREATE OR REPLACE + DROP TRIGGER IF EXISTS). Applied to prod
-- directly 2026-07-28 (like 0009–0019; the drizzle journal does not track these).

CREATE OR REPLACE FUNCTION notify_workspace_entitlements_changed()
RETURNS trigger AS $$
DECLARE
    affected UUID;
BEGIN
    affected := COALESCE(NEW.tenant_id, OLD.tenant_id);
    PERFORM pg_notify('entitlements_changed', affected::text);
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION notify_plan_entitlements_changed()
RETURNS trigger AS $$
BEGIN
    -- A plan default changed → invalidate every cached workspace.
    PERFORM pg_notify('entitlements_changed', 'ALL');
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_workspace_entitlements_notify ON workspace_entitlements;
CREATE TRIGGER trg_workspace_entitlements_notify
    AFTER INSERT OR UPDATE OR DELETE ON workspace_entitlements
    FOR EACH ROW EXECUTE FUNCTION notify_workspace_entitlements_changed();

DROP TRIGGER IF EXISTS trg_plan_entitlements_notify ON plan_entitlements;
CREATE TRIGGER trg_plan_entitlements_notify
    AFTER INSERT OR UPDATE OR DELETE ON plan_entitlements
    FOR EACH ROW EXECUTE FUNCTION notify_plan_entitlements_changed();
