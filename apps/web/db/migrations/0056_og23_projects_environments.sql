-- 0056 — OG-23: projects and environments (the gateway half of PLT-01).
--
-- UN-JOURNALED, like every migration from 0009 on: `drizzle-kit migrate` applies
-- only 0000–0008, so this is applied to Neon BY HAND.
--
-- **SERIALIZATION POINT S2.** The gateway's API-key auth SELECT (cold path and the
-- warm refresh, `crates/gateway/src/db/api_keys.rs`) LEFT JOINs `projects` and reads
-- `api_keys.project_id` / `api_keys.environment`; its boot check
-- (`entitlement_cache::verify_schema`) REFUSES TO BOOT when either column or the
-- table is absent. Order:
--   1. THIS file,
--   2. 0057_og20_key_policy.sql (OG-20 — the policy columns, also read by that SELECT),
--   3. deploy the gateway.
-- Steps 1-2 are safe under the CURRENT binaries: nothing deployed reads the new table,
-- and both new api_keys columns are NULL, which is today's behaviour (no project, no
-- environment). apps/web needs no deploy: it reads `api_keys` with explicit columns.
--
-- WHAT IT ADDS (spec `specs/OG-23-projects-environments.md`):
--   * `projects` — a tenant's named group of API keys, with the environments its keys
--     may be labelled with. Archived, never deleted (`archived_at`): a key in an
--     archived project stays governed by it, so an archive can never loosen a key.
--   * `api_keys.project_id` — RESTRICT, not SET NULL: a deleted project must never
--     silently strip the governing policy (OG-20) from a live key. The gateway only
--     ever archives.
--   * `api_keys.environment` — the attribution label the span records over the
--     caller's `x-tracelane-environment` header. Requires a project.
--
-- Tenant isolation is the WRITE path's job (every statement filters tenant_id, and the
-- assignment joins `projects.tenant_id = api_keys.tenant_id`); the gateway's auth JOIN
-- repeats the tenant predicate so a hand-edited cross-tenant `project_id` grants nothing.
--
-- Idempotent (IF NOT EXISTS / DROP CONSTRAINT IF EXISTS).
-- REVERSIBLE before step 3: ALTER TABLE api_keys DROP COLUMN environment, DROP COLUMN
-- project_id; DROP TABLE projects. After step 3 the gateway refuses to boot without them.

-- rev5 L2 (2026-10-04): every ALTER below takes an ACCESS EXCLUSIVE lock on `api_keys`
-- -- the table EVERY authenticated request reads. Bounded like 0055/0058: a busy table
-- fails this file fast (re-run it; it is idempotent) instead of queueing every key
-- lookup behind the lock while it waits.
SET lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS projects (
    id            uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name          text         NOT NULL,
    -- The labels this project's keys may carry. Never empty: a project with no
    -- environment could hold no labelled key, and `{}` reads as "anything".
    environments  text[]       NOT NULL DEFAULT '{production}',
    created_at    timestamptz  NOT NULL DEFAULT now(),
    updated_at    timestamptz  NOT NULL DEFAULT now(),
    archived_at   timestamptz,
    CONSTRAINT projects_name_not_blank_chk CHECK (length(btrim(name)) > 0),
    CONSTRAINT projects_environments_not_empty_chk CHECK (cardinality(environments) > 0)
);

CREATE INDEX IF NOT EXISTS projects_tenant_id_idx ON projects (tenant_id);
-- One LIVE project per name per tenant (case-insensitive); an archived name is reusable.
CREATE UNIQUE INDEX IF NOT EXISTS projects_tenant_live_name_idx
    ON projects (tenant_id, lower(name)) WHERE archived_at IS NULL;

ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS project_id  uuid REFERENCES projects(id) ON DELETE RESTRICT,
    ADD COLUMN IF NOT EXISTS environment text;

ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS api_keys_environment_slug_chk;
ALTER TABLE api_keys ADD CONSTRAINT api_keys_environment_slug_chk
    CHECK (environment IS NULL OR environment ~ '^[a-z0-9][a-z0-9_-]{0,31}$');
ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS api_keys_environment_needs_project_chk;
ALTER TABLE api_keys ADD CONSTRAINT api_keys_environment_needs_project_chk
    CHECK (environment IS NULL OR project_id IS NOT NULL);

CREATE INDEX IF NOT EXISTS api_keys_project_id_idx ON api_keys (project_id)
    WHERE project_id IS NOT NULL;

COMMENT ON TABLE projects IS
  'OG-23: a tenant''s named group of API keys. Archived (archived_at), never deleted. Written ONLY by the gateway''s /v1/projects routes; read by the API-key auth JOIN.';
COMMENT ON COLUMN api_keys.project_id IS
  'OG-23: the project this key belongs to (NULL = none). Governs the key with the project''s policy (OG-20) in addition to its own. ON DELETE RESTRICT: never silently cleared.';
COMMENT ON COLUMN api_keys.environment IS
  'OG-23: the environment label recorded on this key''s spans (deployment_environment), over the caller''s header. One of the project''s environments; requires project_id.';

RESET lock_timeout;
