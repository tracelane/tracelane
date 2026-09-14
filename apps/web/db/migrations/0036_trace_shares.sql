-- 0036 — OBS-48 shareable verified trace link.
--
-- One row per minted public share link. `token_hash` is sha256 of a 256-bit
-- random token; the RAW token is returned to the owner ONCE, at mint time, and
-- is never stored anywhere — same "cannot show it again" shape as
-- `api_keys.lookup_hash`.
--
-- WRITTEN BY THE GATEWAY (Rust, its own deadpool Postgres pool), not by the
-- web app's Drizzle client — same precedent as `audit_chain_state` /
-- `tenant_audit_keys`. Un-journaled (TRAPS §9): this file must be applied to
-- Neon BEFORE the gateway build that reads/writes `trace_shares` deploys, or
-- every share route 500s on missing-relation.
--
-- `GET /v1/share/{token}` is UNAUTHENTICATED and looks the row up by
-- `sha256(token) = token_hash` — the unique index on `token_hash` is what
-- makes that lookup O(1) instead of a table scan on the hot public path.
--
-- `revoked_at` is a soft marker (DELETE sets it; the row and its view_count
-- survive). Additive and idempotent: every DDL uses IF NOT EXISTS.

CREATE TABLE IF NOT EXISTS trace_shares (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- ClickHouse trace id (hex/UUID-shaped text) — spans live in ClickHouse,
    -- never Postgres, so this is deliberately not a foreign key.
    trace_id    text        NOT NULL,
    -- sha256(token), raw bytes. The token itself is never stored.
    token_hash  bytea       NOT NULL,
    -- WorkOS claim `sub` of the minting user.
    created_by  text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    -- NULL = active. Non-NULL = revoked (soft — see header comment).
    revoked_at  timestamptz,
    view_count  bigint      NOT NULL DEFAULT 0
);

-- The owner-facing list (`GET /v1/traces/{id}/shares`) and the mint route's
-- 10-active-links-per-trace cap both filter on this pair.
CREATE INDEX IF NOT EXISTS trace_shares_tenant_trace_idx
    ON trace_shares (tenant_id, trace_id);

-- The unauthenticated public read's ONLY lookup path.
CREATE UNIQUE INDEX IF NOT EXISTS trace_shares_token_hash_idx
    ON trace_shares (token_hash);

COMMENT ON TABLE trace_shares IS
    'OBS-48 shareable public trace links. token_hash is sha256 of a 256-bit '
    'token never stored in plaintext; GET /v1/share/{token} is unauthenticated '
    'and looks up by sha256(token). Content (prompts/responses/tool bodies) is '
    'stripped by the gateway before serialization — this table never holds any.';
