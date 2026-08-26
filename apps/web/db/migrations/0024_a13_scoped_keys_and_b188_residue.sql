-- 0024_a13_scoped_keys_and_b188_residue.sql
--
-- APPLIED to Neon Frankfurt 2026-08-12 by Claude Code (additive + idempotent;
-- founder granted standing authority for reversible, non-monetary changes).
--
-- ONE migration, ONE review, ONE apply (founder, 2026-08-08). It bundles A13's
-- schema half with the three incompletely-applied migrations audit found,
-- because hand-applying them separately is exactly what produced.
--
-- ORDERING RULE (CLAUDE.md §4.0, S2): this lands in Neon **BEFORE** the gateway
-- that reads the new columns deploys. A13's code half (`key_routes.rs` scope
-- enforcement + `db/schema.ts` + `db/seed.mjs`) ships AFTER this is applied.
--
-- Idempotent throughout: safe to re-run, and safe if some part is already present.
--
-- ═══════════════════════════════════════════════════════════════════════════
-- ⚠️ READ FIRST — migration 14's trigger function is DEFECTIVE AS WRITTEN, and
--    this migration does NOT reproduce it.
--
--    `infra/dev/postgres/migrations/14_full_capture_sampling.sql:76` defines
--        affected := COALESCE(NEW.tenant_id, OLD.tenant_id);
--    and then attaches that trigger to `tenants` — a table whose primary key is
--    `id`. There is no `tenant_id` column on `tenants` (verified: 0 rows in
--    information_schema).
--
--    Falsified on scratch objects against prod, 2026-08-08:
--        ERROR: record "new" has no field "tenant_id"
--        CONTEXT: PL/pgSQL assignment "affected := COALESCE(NEW.tenant_id, …)"
--    and the corrected form (`NEW.id`) inserts cleanly.
--
--    So applying migration 14 verbatim would have made EVERY insert, update and
--    delete on `tenants` fail — tenant creation, plan changes, soft-delete, and
--    the erasure purge itself. Its absence was not merely a half-apply; shipping
--    it as written would have been worse than skipping it. Section 2 below uses
--    `COALESCE(NEW.id, OLD.id)`.
--
--    `infra/dev/postgres/migrations/14_full_capture_sampling.sql` still carries
--    the defect and should be corrected in the same change that applies this.
-- ═══════════════════════════════════════════════════════════════════════════

BEGIN;

------------------------------------------------------------------------------
-- 1. A13 / SET-20 — scoped, time-bounded, budget-capped API keys.
--
-- The wedge requires handing a third party a key. The key we can hand an
-- external auditor today grants the workspace's ENTIRE API surface, FOREVER.
--
-- All three columns are NULLABLE and NULL preserves today's behaviour, so the
-- 22 existing keys keep working unchanged:
--     scope              NULL = full surface  (as today)
--     expires_at         NULL = never expires (as today)
--     budget_usd_monthly NULL = uncapped      (as today)
--
-- ⚠️ HAND-OFF TO THE CODE HALF: NULL-means-unrestricted is a *backwards
-- compatibility* choice for existing rows, NOT a safe default for new ones. The
-- mint route must REQUIRE an explicit scope, and the gateway must treat a NULL
-- scope as full-surface rather than as "no permissions". Do not let this
-- migration's permissiveness read as the policy.
------------------------------------------------------------------------------
ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS scope TEXT[];
ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS budget_usd_monthly NUMERIC(12, 4);

-- Reject an empty array explicitly: `{}` would mean "no permissions", which the
-- gateway would have to special-case. NULL is the only "unscoped" representation.
ALTER TABLE api_keys
    DROP CONSTRAINT IF EXISTS api_keys_scope_not_empty_chk;
ALTER TABLE api_keys
    ADD CONSTRAINT api_keys_scope_not_empty_chk
    CHECK (scope IS NULL OR cardinality(scope) > 0);

ALTER TABLE api_keys
    DROP CONSTRAINT IF EXISTS api_keys_budget_nonneg_chk;
ALTER TABLE api_keys
    ADD CONSTRAINT api_keys_budget_nonneg_chk
    CHECK (budget_usd_monthly IS NULL OR budget_usd_monthly >= 0);

-- Partial: only keys that actually expire are of interest to the sweep.
CREATE INDEX IF NOT EXISTS api_keys_expires_at_idx
    ON api_keys (expires_at)
    WHERE expires_at IS NOT NULL AND revoked_at IS NULL;

COMMENT ON COLUMN api_keys.scope IS
    'Permission scopes from the closed vocabulary {chat,read,admin}. NULL = full API surface (legacy keys). Never empty; an unknown scope denies.';
COMMENT ON COLUMN api_keys.expires_at IS
    'Hard expiry. NULL = never expires (legacy keys). Enforced in the gateway, not by the DB.';
COMMENT ON COLUMN api_keys.budget_usd_monthly IS
    'Per-key monthly spend cap in USD. NULL = uncapped.';

------------------------------------------------------------------------------
-- 2. — migration 14 residue, WITH THE DEFECT FIXED (see the header).
--
-- Columns `sampling_policy` and `force_tail` already landed in Frankfurt; the
-- CHECK, the function and the trigger did not.
--
-- The trigger is an OPTIMISATION, not a correctness requirement: the ingest
-- tenant-config cache has a 30s TTL that bounds staleness on its own
-- (`crates/ingest/src/tenant_config.rs:12-15`). Applying it makes
-- sampling_policy / force_tail changes take effect immediately instead of
-- within 30s — which matters most for the force_tail kill-switch.
------------------------------------------------------------------------------
ALTER TABLE tenants
    DROP CONSTRAINT IF EXISTS tenants_sampling_policy_chk;
ALTER TABLE tenants
    ADD CONSTRAINT tenants_sampling_policy_chk
    CHECK (sampling_policy IN ('tail', 'full'));

CREATE OR REPLACE FUNCTION notify_tenant_config_changed()
RETURNS trigger AS $$
DECLARE
    affected UUID;
BEGIN
    -- `tenants` keys on `id`. Using NEW.tenant_id here (as migration 14 does)
    -- raises `record "new" has no field "tenant_id"` and fails the write.
    affected := COALESCE(NEW.id, OLD.id);
    PERFORM pg_notify('tenant_config_changed', affected::text);
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_tenants_config_notify ON tenants;
CREATE TRIGGER trg_tenants_config_notify
    AFTER INSERT OR UPDATE OR DELETE ON tenants
    FOR EACH ROW EXECUTE FUNCTION notify_tenant_config_changed();

------------------------------------------------------------------------------
-- 3. — migration 05 residue. The column landed; its index did not.
-- Reverse-map index for the Polar webhook's `get_by_polar_customer` lookup,
-- which currently sequential-scans.
------------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS tenants_polar_customer_id_idx
    ON tenants (polar_customer_id)
    WHERE polar_customer_id IS NOT NULL AND archived_at IS NULL;

------------------------------------------------------------------------------
-- 4. — migration 10 residue. RULED 2026-08-12: NOT RESTORED.
--
-- The draft asked for a decision and recommended deleting this section. Taking
-- the recommendation. `workspace_attr_cardinality` never landed in Frankfurt and
-- has NO READER ANYWHERE — a repo-wide grep finds it only in its own migration.
-- Creating it would restore fidelity with a migration set for its own sake and
-- leave behind a table nothing writes and nothing reads, which is the same
-- dead-weight this migration exists to clean up.
--
-- Migration 10 is therefore RETIRED rather than applied. If per-workspace
-- attribute cardinality is ever needed, it comes back with its writer and its
-- reader in the same change.
------------------------------------------------------------------------------

COMMIT;

------------------------------------------------------------------------------
-- VERIFY — run after applying. Every row must report `ok`.
-- (Outside the transaction: this is a read-only check, not part of the change.)
------------------------------------------------------------------------------
-- SELECT 'api_keys.scope',              CASE WHEN to_regclass('api_keys') IS NOT NULL AND EXISTS
--          (SELECT 1 FROM information_schema.columns WHERE table_name='api_keys' AND column_name='scope')
--        THEN 'ok' ELSE 'MISSING' END
-- UNION ALL SELECT 'api_keys.expires_at', CASE WHEN EXISTS
--          (SELECT 1 FROM information_schema.columns WHERE table_name='api_keys' AND column_name='expires_at')
--        THEN 'ok' ELSE 'MISSING' END
-- UNION ALL SELECT 'api_keys.budget_usd_monthly', CASE WHEN EXISTS
--          (SELECT 1 FROM information_schema.columns WHERE table_name='api_keys' AND column_name='budget_usd_monthly')
--        THEN 'ok' ELSE 'MISSING' END
-- UNION ALL SELECT 'tenants_sampling_policy_chk', CASE WHEN EXISTS
--          (SELECT 1 FROM pg_constraint WHERE conname='tenants_sampling_policy_chk')
--        THEN 'ok' ELSE 'MISSING' END
-- UNION ALL SELECT 'notify_tenant_config_changed', CASE WHEN EXISTS
--          (SELECT 1 FROM pg_proc WHERE proname='notify_tenant_config_changed')
--        THEN 'ok' ELSE 'MISSING' END
-- UNION ALL SELECT 'trg_tenants_config_notify', CASE WHEN EXISTS
--          (SELECT 1 FROM pg_trigger WHERE tgname='trg_tenants_config_notify' AND NOT tgisinternal)
--        THEN 'ok' ELSE 'MISSING' END
-- UNION ALL SELECT 'tenants_polar_customer_id_idx', CASE WHEN EXISTS
--          (SELECT 1 FROM pg_indexes WHERE indexname='tenants_polar_customer_id_idx')
--        THEN 'ok' ELSE 'MISSING' END;
--
-- Then prove the trigger actually FIRES rather than merely existing — the
-- distinction turned on:
--   UPDATE tenants SET sampling_policy = sampling_policy WHERE id = '<any-id>';
-- with `RUST_LOG=info,ingest::tenant_config=debug` on ingest, expect
--   "tenant-config cache entry invalidated via NOTIFY".
-- A trigger that exists and errors looks identical to one that works, until a
-- write to `tenants` fails.
