-- Migration 01: Tenants + API keys + Users (auth + billing metadata).
-- Postgres 17 + Neon-compatible. Idempotent — every CREATE has IF NOT EXISTS.
--
-- Tracelane's source-of-truth split:
--   - ClickHouse holds high-cardinality observational data (spans, audit_log)
--   - Postgres holds low-cardinality metadata (tenants, keys, plan + billing)
--
-- Tenant identity invariant (CLAUDE.md): tenant_id is a UUID, only ever
-- constructed from a JWT claim or an API-key Postgres lookup. Never from
-- a request body.

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id            UUID         PRIMARY KEY,
    name                 TEXT         NOT NULL,
    plan_tier            TEXT         NOT NULL DEFAULT 'free',  -- free | pro | enterprise
    stripe_customer_id   TEXT         UNIQUE,                   -- cus_…
    stripe_subscription_id TEXT       UNIQUE,                   -- sub_…
    workos_org_id        TEXT         UNIQUE,                   -- WorkOS Organization
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    archived_at          TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_tenants_stripe_customer
    ON tenants(stripe_customer_id) WHERE stripe_customer_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS api_keys (
    api_key_id           UUID         PRIMARY KEY,
    tenant_id            UUID         NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    key_hash             BYTEA        NOT NULL UNIQUE,         -- SHA-256 of the raw key body
    name                 TEXT         NOT NULL,                 -- operator-supplied label
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_used_at         TIMESTAMPTZ,
    revoked_at           TIMESTAMPTZ
);

-- Hot-path lookup: gateway hashes the bearer key and queries here. Index
-- on the hash + a (NOT revoked) partial filter so the planner uses a
-- single index scan even at 10M+ rows.
CREATE INDEX IF NOT EXISTS idx_api_keys_lookup
    ON api_keys(key_hash) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS users (
    user_id              UUID         PRIMARY KEY,
    tenant_id            UUID         NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    email                TEXT         NOT NULL UNIQUE,
    workos_user_id       TEXT         UNIQUE,                   -- WorkOS User
    name                 TEXT,
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_login_at        TIMESTAMPTZ
);

-- Per-tenant audit of admin events (separate from ClickHouse audit_log
-- which holds API-traffic hashes). Used for compliance reporting on
-- 'who created the key', 'who promoted v3', etc.
CREATE TABLE IF NOT EXISTS admin_audit (
    audit_id             UUID         PRIMARY KEY,
    tenant_id            UUID         NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    actor_user_id        UUID         REFERENCES users(user_id) ON DELETE SET NULL,
    action               TEXT         NOT NULL,                 -- e.g. 'tenant.create', 'api_key.revoke'
    target               TEXT,                                   -- target id (key, prompt, etc.)
    metadata             JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_admin_audit_tenant_time
    ON admin_audit(tenant_id, created_at DESC);
