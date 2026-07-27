-- Postgres 17 + Neon-compatible. Idempotent (ALTER … IF NOT EXISTS;
-- UPDATE is value-stable on re-run).
--
-- ADR-009 hybrid pricing locks the Prompt Promotion / Eval Gates /
-- Auto-Rollback WRITE workflow (promote / rollback / observe) to Team+;
-- Builder is read-only. The gateway enforces this via
-- `FeatureKey::PromptPromotionWrite` (`crates/gateway/src/prompt_routes.rs`),
-- resolved through the Migration-09 deny-overrides-grant tables.
--
-- Unlike the Migration-12 guardrail flags (tiering deferred to a pricing
-- ADR), the tier split here is ALREADY LOCKED by ADR-009 — so this migration
-- seeds the plan defaults: TRUE for team_v1 / business_v1 / enterprise_v1,
-- FALSE (column default) for free_v1 / builder_v1.
--
-- ⚠ DEPLOY ORDER: apply this migration BEFORE deploying a gateway built with
-- column fails every entitlement resolve → fail-open-to-last-known/deny-all).
-- Applying the migration first is always safe (old binaries ignore the column).
--
-- The prod-Neon twin of this migration lives in the drizzle set
-- backfill (the legacy `tenants.audit_enabled` column is drizzle-only and
-- does not exist in this dev-stack schema).

------------------------------------------------------------------------------
-- 1. plan_entitlements: per-plan default (NOT NULL).
------------------------------------------------------------------------------
ALTER TABLE plan_entitlements
    ADD COLUMN IF NOT EXISTS f_prompt_promotion_write BOOLEAN NOT NULL DEFAULT FALSE;

------------------------------------------------------------------------------
-- 2. workspace_entitlements: per-tenant override (NULL = inherit plan).
------------------------------------------------------------------------------
ALTER TABLE workspace_entitlements
    ADD COLUMN IF NOT EXISTS f_prompt_promotion_write BOOLEAN;

------------------------------------------------------------------------------
-- 3. Seed the ADR-009 tier split: Team+ gets the write workflow.
------------------------------------------------------------------------------
UPDATE plan_entitlements
   SET f_prompt_promotion_write = TRUE,
       updated_at = NOW()
 WHERE plan_lookup_key IN ('team_v1', 'business_v1', 'enterprise_v1')
   AND f_prompt_promotion_write IS DISTINCT FROM TRUE;
