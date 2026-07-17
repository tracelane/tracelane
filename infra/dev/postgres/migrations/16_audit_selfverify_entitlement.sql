-- Migration 16: free-tier audit self-verify entitlement (ADR-066).
-- Postgres 17 + Neon-compatible. Idempotent (ALTER … IF NOT EXISTS; the column
-- default TRUE backfills existing rows on ADD, and the UPDATE is value-stable).
--
-- ADR-066 splits the audit surface: the FREE, default-granted
-- `f_audit_selfverify` lets any tenant SEE + verify their OWN recent chain
-- in-app (gateway `FeatureKey::AuditSelfVerify`, endpoint
-- `/v1/audit/self-verify`), distinct from the PAID `f_audit_addon` ($999
-- Article-12 evidence-pack export). Default-TRUE on every plan; a per-tenant
-- `workspace_entitlements.f_audit_selfverify = FALSE` can still switch it off
-- (deny-overrides-grant).
--
-- ⚠ DEPLOY ORDER: apply this migration BEFORE deploying a gateway built with the
-- ADR-066 resolver (its SQL reads f_audit_selfverify; a missing column fails
-- every entitlement resolve → fail-open-to-last-known/deny-all). Applying the
-- migration first is always safe (old binaries ignore the column).
--
-- The prod-Neon twin lives in the drizzle set
-- (`apps/web/db/migrations/0015_audit_selfverify.sql`).

------------------------------------------------------------------------------
-- 1. plan_entitlements: per-plan default (NOT NULL, default TRUE = free on all).
------------------------------------------------------------------------------
ALTER TABLE plan_entitlements
    ADD COLUMN IF NOT EXISTS f_audit_selfverify BOOLEAN NOT NULL DEFAULT TRUE;

------------------------------------------------------------------------------
-- 2. workspace_entitlements: per-tenant override (NULL = inherit plan).
------------------------------------------------------------------------------
ALTER TABLE workspace_entitlements
    ADD COLUMN IF NOT EXISTS f_audit_selfverify BOOLEAN;

------------------------------------------------------------------------------
-- 3. Seed the default grant on every plan (value-stable on re-run). The column
--    default already sets TRUE on ADD; this makes the intent explicit and
--    corrects any pre-existing row that was left NULL/FALSE.
------------------------------------------------------------------------------
UPDATE plan_entitlements
   SET f_audit_selfverify = TRUE,
       updated_at = NOW()
 WHERE f_audit_selfverify IS DISTINCT FROM TRUE;
