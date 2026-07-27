-- Custom data migration (drizzle-kit generate --custom).
--
-- (promote / rollback / observe) is Team+; Builder is read-only. Migration
-- 0004 added the column with DEFAULT FALSE; this seeds the locked tier split.
-- Idempotent: the WHERE guard makes re-runs no-ops.
UPDATE "plan_entitlements"
   SET "f_prompt_promotion_write" = TRUE,
       "updated_at" = NOW()
 WHERE "plan_lookup_key" IN ('team_v1', 'business_v1', 'enterprise_v1')
   AND "f_prompt_promotion_write" IS DISTINCT FROM TRUE;--> statement-breakpoint

-- ratified 2026-07-03): every tenant granted the Audit SKU via the legacy
-- `tenants.audit_enabled` column gets a `workspace_entitlements` row with
-- `f_audit_addon = TRUE`, so BOTH the web resolver and the gateway export
-- `f_audit_addon`. The legacy column itself is retained (retirement is a
-- separate founder-gated step); the web READ arm for it is dropped in
-- `apps/web/lib/entitlements.ts` in the same PR as this migration.
--
-- The JOIN guards the plan_entitlements FK: a tenant whose plan row is
-- missing is skipped rather than failing the migration (prod must have the
-- Migration-09 plan seed applied — verify with the read-only check in the
-- PR notes). Idempotent via ON CONFLICT.
INSERT INTO "workspace_entitlements" ("tenant_id", "plan_lookup_key", "f_audit_addon")
SELECT t."id", pe."plan_lookup_key", TRUE
  FROM "tenants" t
  JOIN "plan_entitlements" pe
    ON pe."plan_lookup_key" = t."plan"::text || '_v1'
 WHERE t."audit_enabled" = TRUE
ON CONFLICT ("tenant_id") DO UPDATE
   SET "f_audit_addon" = TRUE,
       "updated_at" = NOW();
