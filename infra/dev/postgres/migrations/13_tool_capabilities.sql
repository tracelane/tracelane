-- Migration 13: per-workspace tool capability registry (the guardrail spec
-- §2.3). Postgres 17 + Neon-compatible. Idempotent.
--
-- The capability registry is workspace-owned: each row tags one tool with the
-- capability bitset R3 (definition pinning) and R4 (lethal trifecta) reason
-- over. The gateway loads a tenant's rows into an in-process `CapabilityRegistry`
-- (Moka-cached) on the request hot path.
--
-- Safe-default posture (founder rule): a tenant with ZERO rows resolves to a
-- PERMISSIVE registry — untagged tools hold no caps and are NOT blocked en
-- masse. Registering ≥ 1 row flips the tenant to ENFORCING (untagged tools →
-- all-caps, fail-closed). A Postgres outage falls back to permissive (never
-- block traffic because the registry store is down).
--
-- `caps` is the CapabilitySet bitset matching the Rust flags:
--   READS_PRIVATE_DATA = 1, SEES_UNTRUSTED_CONTENT = 2, CAN_EXFILTRATE = 4.
-- 0 = reviewed-and-harmless (explicitly no dangerous capability) — distinct
-- from never registering.

CREATE TABLE IF NOT EXISTS tool_capabilities (
    tenant_id   UUID        NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    tool_name   TEXT        NOT NULL,
    caps        SMALLINT    NOT NULL DEFAULT 0,   -- CapabilitySet bitset (0..7)
    -- R3 definition pinning: the workspace's last-approved blake3 def_hash (hex,
    -- 64 chars) for this tool. NULL = caps-only registration, no pinning. A
    -- request whose tool def_hash differs from this is a rug-pull
    -- (TOOL_DEF_DRIFT). Re-approval = UPDATE this column to the new hash.
    def_hash    TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, tool_name),
    CONSTRAINT tool_capabilities_caps_range CHECK (caps BETWEEN 0 AND 7)
);

-- Hot-path read is `WHERE tenant_id = $1`; the PK's leading column already
-- indexes it, so no extra index is needed.
