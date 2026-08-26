-- Migration 17: GWY-24 semantic response cache.
--
-- ONE table. Append-only, TTL-expired, brute-force cosine scan.
--
-- WHY MergeTree AND NOT ReplacingMergeTree: a cache entry is written once and
-- expires; there is nothing to replace. `eval_runs` is a version-less
-- ReplacingMergeTree and that choice has already cost this repo a reader that
-- must remember `FINAL`.
--
-- WHY NO `hit_count` COLUMN: counting hits would need a mutation on a MergeTree.
-- Hits are counted from SPANS instead (`tracelane_semantic_cache_hit`), which
-- needs no mutation, is already tenant-isolated, and is the flight-recorder
-- answer — the reuse becomes evidence rather than a counter nobody can audit.
--
-- WHY NO ROW POLICY: migration 03 declares five and prod has
-- `count() FROM system.row_policies = 0` instance-wide — none was ever applied,
-- and they could not work anyway because the gateway never sets the
-- `X-Tenant-Id` header they test. Declaring one here would add a control that
-- has never functioned. Isolation is the explicit `WHERE tenant_id = ?` bind in
-- every query in `semantic_cache.rs`, proven by a two-tenant test.
CREATE TABLE IF NOT EXISTS semantic_cache (
    tenant_id         String,
    cache_id          UUID,
    model             LowCardinality(String),
    -- sha256 hex of every request parameter that is NOT a message: temperature,
    -- top_p, max_tokens, stop, tools, tool_choice, response_format, seed.
    -- An EXACT match on this is REQUIRED before any similarity comparison. Two
    -- requests whose sampling parameters differ are not interchangeable however
    -- similar their text reads.
    params_hash       FixedString(64),
    -- blake3 hex of the canonical full request. The exact tier's key, and the
    -- reason most repeats never pay for an embedding.
    exact_hash        FixedString(64),
    embedding         Array(Float32),
    embedding_model   LowCardinality(String),
    embedding_dims    UInt16,
    response_json     String,
    prompt_tokens     UInt32,
    completion_tokens UInt32,
    -- Cost of the ORIGINAL provider call. What a hit saves; never re-charged.
    cost_usd          Float64,
    -- The trace that produced this entry. The flight-recorder link, so "which
    -- answer was reused" is always answerable — the question `GWY-25` said a
    -- cache could not answer.
    source_trace_id   UUID,
    created_at        DateTime64(3, 'UTC')
)
ENGINE = MergeTree
-- (tenant, model, params_hash) is the prefilter every lookup applies, so the
-- scan reads one contiguous range rather than the table. `created_at` last
-- makes the recency window a range scan too.
ORDER BY (tenant_id, model, params_hash, created_at)
PARTITION BY toYYYYMM(created_at)
TTL toDateTime(created_at) + INTERVAL 7 DAY;
