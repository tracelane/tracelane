-- 0060 — OG-25 / OG-21 / OG-22: the workspace's own gateway controls.
--
-- UN-JOURNALED, like every migration from 0009 on: applied to Neon BY HAND.
--
-- **SERIALIZATION POINT S2.** The gateway's entitlement resolve reads this table on
-- every refresh (`entitlement_cache::attach_workspace_controls`), and its boot check
-- (`entitlement_cache::verify_schema`, `db::controls::CONTROLS_SCHEMA_COLUMNS`)
-- REFUSES TO BOOT when the table or a column is absent. Order:
--   1. THIS file (and 0061_og24_spend_alerts.sql),
--   2. deploy the gateway.
-- Step 1 is safe under the CURRENT binaries: nothing deployed reads the table, and an
-- absent row is "nothing set" = today's behaviour.
--
-- ONE ROW PER TENANT, absent = nothing set:
--   * policy            — the WORKSPACE layer of the OG-21/OG-22 policy document
--                         (`limits`, `budget`, `end_user_budget` ONLY). The gateway
--                         validates it on write and parses it on read; a stored document
--                         it cannot parse, or one carrying a key/project rule, REFUSES
--                         every request in the workspace (403 policy_invalid) —
--                         fail-CLOSED. Authority for the vocabulary:
--                         crates/shared/src/key_policy.rs.
--   * paused_at/_by/pause_reason — OG-25 pause: every inference route answers
--                         423 workspace_paused while paused_at IS NOT NULL.
--   * blocked_*         — OG-25 block lists: model globs, provider ids, end-user ids.
-- Written ONLY by the gateway's owner-gated /v1/controls routes, each write recording
-- one admin_audit_log row in the same transaction.
--
-- Idempotent. REVERSIBLE before step 2: DROP TABLE workspace_controls;

CREATE TABLE IF NOT EXISTS workspace_controls (
    tenant_id          uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    policy             jsonb,
    paused_at          timestamptz,
    paused_by          text,
    pause_reason       text,
    blocked_models     text[] NOT NULL DEFAULT '{}',
    blocked_providers  text[] NOT NULL DEFAULT '{}',
    blocked_end_users  text[] NOT NULL DEFAULT '{}',
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    updated_by         text
);

ALTER TABLE workspace_controls DROP CONSTRAINT IF EXISTS workspace_controls_policy_object_chk;
ALTER TABLE workspace_controls ADD CONSTRAINT workspace_controls_policy_object_chk
    CHECK (policy IS NULL OR jsonb_typeof(policy) = 'object');

COMMENT ON TABLE workspace_controls IS
  'OG-25: one tenant''s own gateway controls — pause, block lists, and the workspace layer of the OG-21/OG-22 policy (limits and budgets). Read by the gateway entitlement refresh; written only by the owner-gated /v1/controls routes.';
COMMENT ON COLUMN workspace_controls.policy IS
  'OG-21/OG-22: the workspace policy layer (limits, budget, end_user_budget only). NULL = none. Unparseable = every request refused (fail-closed).';
COMMENT ON COLUMN workspace_controls.paused_at IS
  'OG-25: NOT NULL = every inference route answers 423 workspace_paused. Control routes keep working.';
