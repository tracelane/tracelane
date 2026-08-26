--  commit B — observed tools, the "approve" half of R3 rug-pull detection.
--
-- Commit A gave tenants a way to PIN a tool definition. Nobody hand-authors tool
-- JSON, so a pin-only feature ships correct and unused. This table is what makes
-- it usable: the gateway records every tool definition it actually sees, and the
-- dashboard offers one-click approve.
--
-- WHAT IS DELIBERATELY NOT STORED: the tool's schema or description text. R3
-- records the HASH, never the tool text (`capability.rs:139-140`), and the
-- observe path must not weaken that posture. Approving copies the `def_hash`
-- WE computed at request time (`capability.rs:297`), so the server-side-hashing
-- rule from commit A holds here for free — there is no path by which a
-- client-supplied hash can become a pin.
--
-- PRIMARY KEY includes def_hash on purpose: when a tool's definition CHANGES,
-- that is a new row rather than an update. The old row stays, so the pending
-- list shows "this tool now has a second definition" — which is precisely the
-- rug-pull signal a tenant needs to see before approving.
--
-- Un-journaled (0009+, CLAUDE.md §5): apply to Neon BEFORE deploying the
-- gateway that reads it, or the gateway 500s on a missing relation.

CREATE TABLE IF NOT EXISTS observed_tools (
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    tool_name   TEXT        NOT NULL,
    -- Hex blake3 computed by the gateway, never supplied by a client.
    def_hash    TEXT        NOT NULL,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Advisory: incremented per flush, not per request (the gateway dedupes
    -- in-process and flushes off the hot path). Under N replicas this
    -- under-counts rather than over-counts; it is a "have I seen this a lot"
    -- signal for the approve UI, never a billing or quota input.
    seen_count  BIGINT      NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, tool_name, def_hash)
);

-- The pending-list query orders by recency within a tenant.
CREATE INDEX IF NOT EXISTS observed_tools_tenant_last_seen_idx
    ON observed_tools (tenant_id, last_seen DESC);
