-- Migration 0016 — per-workspace tool-capability registry (B-114).
-- Prod-Neon twin of infra/dev/postgres/migrations/13_tool_capabilities.sql.
--
-- WHY THIS EXISTS AS A NEW MIGRATION
-- The table was created only in the RETIRED `infra/dev/postgres/migrations/`
-- non-Drizzle SQL into Drizzle FIRST, THEN delete infra", and this file is that
-- migration for `13_tool_capabilities.sql`. Consequence on prod (B-114): the
-- table never existed anywhere, so `guardrail::registry_loader` errored on EVERY
-- cache-miss and fell back to PERMISSIVE while logging `db error` — implying a
-- store outage when the relation was simply absent.
--
-- IMPORTANT — this is NOT a verbatim port. The infra original declares
--   tenant_id UUID REFERENCES tenants(tenant_id)
-- against the pre-ADR-040 tenants shape. **Prod `tenants` has no `tenant_id`
-- The FK is corrected to `tenants(id)` — the shape `scripts/ci/check-tenants-pk-column.sh`
-- enforces everywhere except the retired dir.
--
-- BEHAVIOUR NOTE (deliberate, not an omission): creating this table does NOT
-- switch enforcement on. There is no write path to it anywhere in the codebase,
-- so it stays empty, and an empty registry resolves to PERMISSIVE **by design**
-- (`registry_loader`: zero rows → empty → permissive). What changes is honesty:
-- permissive-because-unconfigured instead of permissive-because-the-query-failed,
-- and the loader stops erroring on the hot path. It also makes R3Pinning
-- *possible* — the loader can pin a `def_hash` once a row exists, which is the

CREATE TABLE IF NOT EXISTS tool_capabilities (
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    tool_name   TEXT        NOT NULL,
    -- CapabilitySet bitset (0..7). The CHECK is the load-bearing part: the
    -- loader maps this to a typed CapabilitySet, and an out-of-range value would
    -- be a silently-wrong capability grant.
    caps        SMALLINT    NOT NULL DEFAULT 0,
    -- Pinned tool-definition hash for R3Pinning (rug-pull / TOOL_DEF_DRIFT).
    -- Nullable: a row may grant capabilities without pinning a definition.
    def_hash    TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, tool_name),
    CONSTRAINT tool_capabilities_caps_range CHECK (caps BETWEEN 0 AND 7)
);
