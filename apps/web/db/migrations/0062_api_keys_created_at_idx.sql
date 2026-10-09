-- 0062 — api_keys.created_at index for the valid-key-set DELTA read (rev6 residual).
--
-- UN-JOURNALED, like every migration from 0009 on: applied to Neon BY HAND. WRITTEN, NEVER
-- APPLIED by whoever wrote it. Nothing depends on it: it is an index only, so the gateway
-- is correct with or without it and the apply order against a deploy does not matter.
--
-- THE QUERY (the only one in the tree that filters or orders `api_keys` by created_at —
-- `crates/gateway/src/db/api_keys.rs` `fetch_known_keys`, the `Some(since)` arm):
--
--   SELECT now(), ARRAY(SELECT lookup_hash FROM api_keys
--                       WHERE lookup_hash IS NOT NULL AND created_at >= $2 LIMIT $1)
--
-- It runs on every valid-key-set refresh (the OG-... rev4 H1 d / M1 negative-lookup
-- gate) to pick up keys minted since the last read. It has NO tenant_id predicate — the
-- set is global across tenants — so a (tenant_id, created_at) index would NOT serve it
-- (tenant_id is the leading column; Postgres < 18 has no skip scan). The index is shaped
-- to the query instead: created_at alone, partial on the same `lookup_hash IS NOT NULL`
-- the query carries (the rows the set can contain at all).
--
-- No other gateway or web query orders or filters api_keys by created_at: the key list
-- selects created_at as a column only, and no mint-rate / per-tenant-capacity check reads
-- it today. If one is added, it gets its own (tenant_id, created_at) index with that query
-- quoted here.
--
-- PLAIN CREATE INDEX, not CONCURRENTLY, on purpose: every migration here is applied as one
-- multi-statement script (the gateway's embedded runner uses `batch_execute`, an implicit
-- transaction, and CONCURRENTLY cannot run in one) and none of 0000-0061 uses it. The
-- build takes a SHARE lock on api_keys (writes wait, reads do not) for as long as the
-- build takes — milliseconds at today's row count. If api_keys is ever large, run the
-- statement by hand OUTSIDE a transaction as CREATE INDEX CONCURRENTLY with this name.
--
-- Idempotent. REVERSIBLE: DROP INDEX api_keys_created_at_idx;

CREATE INDEX IF NOT EXISTS api_keys_created_at_idx
    ON api_keys (created_at)
    WHERE lookup_hash IS NOT NULL;
