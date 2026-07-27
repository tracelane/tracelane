-- Migration 0015 — free-tier audit self-verify entitlement (ADR-066).
-- Prod-Neon twin of infra/dev/postgres/migrations/16_audit_selfverify_entitlement.sql.
--
-- ADR-066 splits the audit surface: the FREE, default-granted `f_audit_selfverify`
-- lets any tenant SEE + verify their OWN recent chain in-app (gateway
-- `/v1/audit/self-verify`), distinct from the PAID `f_audit_addon` ($999
-- Article-12 evidence-pack export). Default-TRUE on every plan; a per-tenant
-- `workspace_entitlements.f_audit_selfverify = FALSE` still switches it off
-- (deny-overrides-grant).
--
-- Column default TRUE backfills existing plan rows on ADD. Idempotent + hand-
-- applied on Neon (same pattern as 0009-0014). Apply BEFORE the ADR-066 gateway
-- deploy (its resolver reads f_audit_selfverify).

ALTER TABLE "plan_entitlements" ADD COLUMN IF NOT EXISTS "f_audit_selfverify" boolean DEFAULT true NOT NULL;--> statement-breakpoint
ALTER TABLE "workspace_entitlements" ADD COLUMN IF NOT EXISTS "f_audit_selfverify" boolean;--> statement-breakpoint
UPDATE plan_entitlements SET f_audit_selfverify = TRUE, updated_at = now()
  WHERE f_audit_selfverify IS DISTINCT FROM TRUE;
