--
-- Drives the gateway's in-process entitlement cache invalidation
-- (`crates/gateway/src/entitlement_cache.rs`). A write to either entitlement
-- table fires `NOTIFY entitlements_changed, '<payload>'`:
--   - workspace_entitlements → payload = the affected tenant_id (UUID).
--   - plan_entitlements      → payload = 'ALL' (a plan default affects every
--                              tenant on that plan; the listener clears all).
-- The gateway LISTENs on this channel over a DIRECT Neon connection (a
-- PgBouncer transaction pooler does not pass LISTEN/NOTIFY). If LISTEN is
-- unavailable the 30s cache TTL bounds staleness — correctness never depends
-- on NOTIFY delivery.
--
-- ⚠ APPLY WITH PRODUCTION MIGRATION TOOLING (drizzle-kit migrate / psql), NOT
-- the gateway's dev `apply_migrations` helper: that helper splits on ';' and
-- would shred the PL/pgSQL `$$` function body below. This file is checked in
-- for the prod migration runner per ADR-039 §23.8 (expand-contract, reviewed).

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
