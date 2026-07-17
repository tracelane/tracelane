-- 0010_a5_tenants_plan_default_free — reconcile the tenants.plan column default.
--
-- WHY: schema.ts and PROD both have `tenants.plan DEFAULT 'free'` (the ADR-040
-- push, verified 2026-06-08 — an unbilled fresh signup must resolve to free-tier
-- entitlements, NOT get the 150K Builder quota for free). But that default was
-- pushed straight to prod and NEVER captured in a migration: 0000_initial_baseline
-- still writes `"plan" "plan" DEFAULT 'builder' NOT NULL`, and no later migration
-- overrides it. So ANY environment rebuilt from the migration SQL (DR restore, a
-- fresh prod, staging) would regress to the Builder-quota leak. This migration
-- closes that gap.
--
-- SAFETY: pure default change — sets no existing row's value, only the default
-- for future inserts. On current prod it is a NO-OP (the default is already
-- 'free'). Idempotent — safe to re-run. Existing tenants are untouched.
--
-- APPLY: hand-written + manual-paste to Neon, matching the 0009 pattern
-- (un-journaled; recent Neon migrations here are applied by paste, not
-- a non-urgent reconcile whose real value is rebuild-safety.

ALTER TABLE "tenants" ALTER COLUMN "plan" SET DEFAULT 'free';
