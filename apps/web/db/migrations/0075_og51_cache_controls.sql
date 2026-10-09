-- 0075 — OG-51: response-cache controls per workspace and per key, and the invalidation
-- generation counter.
--
-- UN-JOURNALED, like every migration from 0009 on: applied to Neon BY HAND, and WRITTEN
-- NEVER APPLIED by the builder. Number final (2026-10-05 consolidation merge).
--
-- **SERIALIZATION POINT S2.** The gateway's boot schema check
-- (`scripts/ci/check-deploy-schema.py` reads every table `crates/gateway/src/db/` names)
-- refuses a deploy against a Neon without these objects. Order: this file, THEN the
-- gateway. Safe under the CURRENT binaries: nothing deployed reads any of it. A gateway
-- whose read of them FAILS (a missing table) resolves the workspace to the PRIVACY
-- default — the response cache OFF for it (`entitlement_cache::attach_cache_settings`).
--
-- workspace_cache_settings — one row per workspace that set anything.
--   mode          inherit (default: serve per the operator block AND the workspace's content
--                 capture, `translation_policy.v1.json` response_cache.inherit_requires_capture)
--               | on  (the workspace explicitly enables the cache — needs the plan's
--                 `f_cache_control`, checked at write and again on every request)
--               | off (no request of this workspace is served from or stored in the cache)
--   ttl_hours     NULL = the operator/plan TTL; else the workspace's own (min'd with both)
--   namespace_by  workspace | project | key | end_user — what a cache entry is private to
--   semantic      false = the semantic (embedding) tier is off; the exact tier is unaffected
--
-- cache_epochs — the invalidation GENERATION COUNTER. The gateway's ClickHouse user holds
--   no DELETE grant, so "invalidate" bumps `epoch`, which is folded into both cache hashes:
--   the old entries become unreachable (and age out by TTL / capacity / the sweeper).
--   scope = workspace | project:<uuid> | key:<uuid> | model:<name>.
--
-- api_keys.cache — a key's own narrowing: {"mode":"off"?, "namespace_by"?}. A key can only
--   narrow (switch the cache off, or a narrower namespace) — never turn it on or widen.
--
-- Idempotent. REVERSIBLE before the gateway deploy: DROP TABLE cache_epochs;
-- DROP TABLE workspace_cache_settings; ALTER TABLE api_keys DROP COLUMN cache;

CREATE TABLE IF NOT EXISTS workspace_cache_settings (
    tenant_id     uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    mode          text NOT NULL DEFAULT 'inherit'
                  CHECK (mode IN ('inherit', 'on', 'off')),
    ttl_hours     integer CHECK (ttl_hours IS NULL OR ttl_hours > 0),
    namespace_by  text NOT NULL DEFAULT 'workspace'
                  CHECK (namespace_by IN ('workspace', 'project', 'key', 'end_user')),
    semantic      boolean NOT NULL DEFAULT true,
    updated_by    text,
    updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cache_epochs (
    tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    scope       text NOT NULL CHECK (char_length(scope) BETWEEN 1 AND 200),
    epoch       bigint NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, scope)
);

ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS cache jsonb;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'api_keys_cache_object_chk'
    ) THEN
        ALTER TABLE api_keys ADD CONSTRAINT api_keys_cache_object_chk
            CHECK (cache IS NULL OR jsonb_typeof(cache) = 'object');
    END IF;
END $$;

COMMENT ON TABLE workspace_cache_settings IS
  'OG-51: a workspace''s response-cache mode / TTL / namespace / semantic-tier switch. Written only by the gateway''s PUT /v1/cache/settings (one admin_audit_log row per write).';
COMMENT ON TABLE cache_epochs IS
  'OG-51: the cache invalidation generation counter (the gateway has no ClickHouse delete grant). Bumped by POST /v1/cache/invalidate; folded into both cache hashes.';
COMMENT ON COLUMN api_keys.cache IS
  'OG-51: a key''s own cache narrowing {"mode":"off"?,"namespace_by"?}; never widens the workspace''s choice.';
