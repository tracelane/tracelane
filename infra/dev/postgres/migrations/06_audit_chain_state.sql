-- Persistent audit-chain state, per tenant.
--
-- Reviewer R1 H4 fix: in v1, the `seq` counter and `prev_hash` lived
-- only in `Mutex<ChainState>` inside the gateway process. Restart →
-- seq resets to 0 → prev_hash resets to "" → the next batch of rows
-- forms a parallel chain off the genesis, and the verifier sees
-- `seq_out_of_order` for everything after the restart.
--
-- v2 persists `(tenant_id, last_seq, last_row_hash)` on every append
-- (transactional with the ClickHouse row insert in the common case,
-- best-effort in the dev-without-pg case). Startup loads every
-- known tenant's state into a per-tenant `Mutex<TenantChainState>`
-- in a `DashMap` — restart resumes exactly where we left off, and
-- cross-tenant appends no longer serialise on a single mutex.

CREATE TABLE IF NOT EXISTS audit_chain_state (
    tenant_id     UUID        PRIMARY KEY,
    last_seq      BIGINT      NOT NULL,
    -- Raw 32-byte SHA-256 of the most recent row in the v2 chain.
    -- BYTEA (not TEXT) because the v2 chain operates on bytes
    -- end-to-end; only the storage / wire boundary hex-encodes.
    last_row_hash BYTEA       NOT NULL CHECK (octet_length(last_row_hash) = 32),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- For startup load: scan the whole table once. No index needed beyond
-- the PK; the table is bounded by tenant count (<<10K in V1).
