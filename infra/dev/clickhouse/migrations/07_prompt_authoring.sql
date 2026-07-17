-- 07_prompt_authoring.sql — ADR-054: persist the prompt NAME so the B1 routing
-- state is reconstructable after a gateway restart.
--
-- Root cause (ADR-054 §Context): the routing map is keyed by (tenant, name, env)
-- but the name was never stored, and ClickHousePersister wrote prompt_id =
-- to_version_id as a proxy. Neither prompt_versions nor promotion_decisions
-- carried the prompt name, so active-version routing died on every restart.
--
-- Additive + idempotent. prod prompt_versions is empty today (no writer existed),
-- so no backfill is needed; a pre-existing promotion_decisions row (test data)
-- gets an empty prompt_name and is simply skipped by the startup reconstruction
-- (which requires a non-empty name), never mis-routed.

ALTER TABLE prompt_versions
    ADD COLUMN IF NOT EXISTS prompt_name String AFTER prompt_id;

ALTER TABLE promotion_decisions
    ADD COLUMN IF NOT EXISTS prompt_name String AFTER prompt_id;
