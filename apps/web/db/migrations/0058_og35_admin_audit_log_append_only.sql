-- 0058 — OG-35 / AUD-16: every control change recorded with before / after, in an
-- APPEND-ONLY trail (`specs/OG-35-control-change-audit.md`).
--
-- UN-JOURNALED, like every migration from 0009 on: `drizzle-kit migrate` applies
-- only 0000–0008, so this is applied to Neon BY HAND.
--
-- **SERIALIZATION POINT S2.** The gateway that ships OG-35 WRITES the three new
-- columns on every control change (`crates/gateway/src/db/control_audit.rs`
-- `record`), inside the change's own transaction, and refuses the change when the
-- write fails (fail-CLOSED). Deployed before this file, every control change —
-- minting a key, setting a ceiling, editing an alias — would answer 503. Order:
--   1. THIS file, then 0059 (`tenant_admin_security`),
--   2. deploy the gateway,
--   3. deploy apps/web.
-- Step 1 is safe under the CURRENT binaries: the columns are NULLable and nothing
-- deployed today UPDATEs or DELETEs `admin_audit_log` (grep 2026-10-04: INSERTs in
-- `crates/gateway/src/db/{api_keys,provider_keys}.rs` and `apps/web/lib/admin-audit.ts`,
-- SELECTs in `db/provider_keys.rs`; the only DELETE is `scripts/ops/tenant-purge.sh`,
-- which writes its `purged_tenants` tombstone first — see the trigger below).
--
-- THE STORE IS `admin_audit_log` (ADR-031), NOT A NEW TABLE. ADR-031 decided every
-- mutating admin endpoint writes a row here inside its transaction; the key
-- rotate / edit / revoke paths already did. A second trail would split what an
-- auditor reads in two.
--
-- APPEND-ONLY IS A CONSTRAINT, NOT A CONVENTION. A trigger refuses every UPDATE and
-- TRUNCATE, and every DELETE except of a workspace already tombstoned in
-- `purged_tenants` (migration 0053) — the GDPR purge (`tenant-purge.sh` writes the
-- tombstone at step 3 before it deletes, `:513`), which is the one sanctioned erase.
-- A row with a NULL workspace (a cross-workspace operator action) can never be
-- deleted.
--
-- Idempotent (IF NOT EXISTS / CREATE OR REPLACE / DROP TRIGGER IF EXISTS).
-- REVERSIBLE before step 2: DROP the triggers and the two functions, DROP the three
-- columns and the index. After step 2 the gateway's control writes need the columns.
--
-- `admin_audit_log` is small (an admin-action trail, not a request log), but the
-- ALTER still takes an ACCESS EXCLUSIVE lock; bounded like 0055 so a busy table
-- fails this file fast instead of stalling writers behind it.
SET lock_timeout = '5s';

ALTER TABLE admin_audit_log ADD COLUMN IF NOT EXISTS request_id        text;
ALTER TABLE admin_audit_log ADD COLUMN IF NOT EXISTS actor_role        text;
ALTER TABLE admin_audit_log ADD COLUMN IF NOT EXISTS actor_auth_method text;

COMMENT ON COLUMN admin_audit_log.request_id IS
    'OG-35: minted by the gateway per control request (never taken from the caller). NULL on rows written before OG-35 and on dashboard best-effort rows.';
COMMENT ON COLUMN admin_audit_log.actor_role IS
    'OG-35: the actor''s role when the change was made — admin / developer / viewer / billing / unrecognised, or a principal label (api_key, self_host_operator, operator).';
COMMENT ON COLUMN admin_audit_log.actor_auth_method IS
    'OG-35: how the actor authenticated — workos_session / api_key / self_host_master_key / operator.';

-- `GET /v1/audit/control-changes` pages a workspace newest-first by id.
CREATE INDEX IF NOT EXISTS idx_admin_audit_workspace_id
    ON admin_audit_log (actor_workspace_id, id DESC);

CREATE OR REPLACE FUNCTION admin_audit_log_append_only()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'admin_audit_log is append-only (OG-35): rows cannot be updated';
    END IF;
    -- DELETE: only the GDPR purge of a tombstoned workspace.
    IF OLD.actor_workspace_id IS NOT NULL
       AND EXISTS (SELECT 1 FROM purged_tenants p WHERE p.tenant_id = OLD.actor_workspace_id) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'admin_audit_log is append-only (OG-35): a row is deleted only by tenant-purge.sh after the workspace is tombstoned in purged_tenants';
END;
$$;

DROP TRIGGER IF EXISTS trg_admin_audit_log_append_only ON admin_audit_log;
CREATE TRIGGER trg_admin_audit_log_append_only
    BEFORE UPDATE OR DELETE ON admin_audit_log
    FOR EACH ROW EXECUTE FUNCTION admin_audit_log_append_only();

CREATE OR REPLACE FUNCTION admin_audit_log_no_truncate()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'admin_audit_log is append-only (OG-35): it cannot be truncated';
END;
$$;

DROP TRIGGER IF EXISTS trg_admin_audit_log_no_truncate ON admin_audit_log;
CREATE TRIGGER trg_admin_audit_log_no_truncate
    BEFORE TRUNCATE ON admin_audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION admin_audit_log_no_truncate();

RESET lock_timeout;
