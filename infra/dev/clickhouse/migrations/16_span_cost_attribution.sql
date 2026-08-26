-- Migration 16: cost attribution dimensions on `spans` (GWY-43, Sprint 1 items 2 + 5).
--
-- THE PROBLEM THIS FIXES IS NOT PERFORMANCE, IT IS ABSENCE. Spans carried
-- tenant, model and provider, so "spend by model" was answerable and "spend by
-- key" or "spend by team" was **impossible** — the fact was never recorded. No
-- amount of dashboard work could have shown it. That is the `OBS-N1` shape: a
-- read path with no writer.
--
-- Both columns are MATERIALIZED off the attributes JSON, the same pattern as
-- `time_to_first_chunk_s` (migration 04) and `gateway_overhead_us` (migration
-- 13). Computed on INSERT, so **only spans written after this deploy carry
-- them** — which is correct and deliberate: these are measured values, never
-- backfilled or estimated. A per-key spend total therefore begins at the
-- cutover, and the surfaces that render it must say so rather than implying the
-- history was always there.
--
-- `api_key_id` is the `api_keys.id` UUID, never the key. The key material does
-- not exist in plaintext anywhere in the system (`db/api_keys.rs` stores a
-- peppered HMAC lookup hash plus an Argon2id verifier), and putting a
-- secret-derived value on a span would be exactly the leak an observability
-- product must not have (ADR-042 / security review M-2). Empty string for a
-- session-authenticated request, which has no API key — that is distinct from
-- "unattributed" and read paths must not merge the two.
--
-- `cost_usd` was already on every span, but only INSIDE the attributes JSON. So
-- every read path spent a `JSONExtractFloat` per row with no index, and — worse
-- — each wrapped it in `if(isFinite(x) AND x > 0, x, 0)`, which turns an
-- HONESTLY UNKNOWN cost into a confident **$0.00**. Before GWY-42 the price
-- table covered 13 models across 3 vendors, so most real traffic took that
-- path and the "Spend (est.)" tile under-reported silently. A real column does
-- not fix the coercion by itself, but it is what lets a read path tell
-- "no cost recorded" from "cost was zero" (`cost_usd_present`).
ALTER TABLE tracelane.spans
    ADD COLUMN IF NOT EXISTS api_key_id String
        MATERIALIZED JSONExtractString(attributes, 'tracelane_api_key_id');

ALTER TABLE tracelane.spans
    ADD COLUMN IF NOT EXISTS cost_usd Float64
        MATERIALIZED JSONExtractFloat(attributes, 'gen_ai_usage_cost');

-- The distinction the `if(… , 0)` wrappers destroyed: was a cost RECORDED at
-- all? `JSONHas` is true only when the key is present, and the gateway omits it
-- entirely (`#[serde(skip_serializing_if = "Option::is_none")]`) when the model
-- has no known price. So `cost_usd_present = 0` means "we do not know what this
-- cost", and summing those rows as zero is a claim we cannot support.
ALTER TABLE tracelane.spans
    ADD COLUMN IF NOT EXISTS cost_usd_present UInt8
        MATERIALIZED toUInt8(JSONHas(attributes, 'gen_ai_usage_cost'));

-- Skip index on the attribution key. Per-key spend queries filter
-- `tenant_id = ? AND api_key_id = ?`, and the table's ORDER BY is
-- (tenant_id, trace_id, span_id) — so the tenant prunes and then the key
-- predicate scans every granule of that tenant. A bloom filter over the low-
-- cardinality key id prunes granules that contain no rows for the key at all.
-- GRANULARITY 4 matches the existing ngram indexes on this table.
ALTER TABLE tracelane.spans
    ADD INDEX IF NOT EXISTS idx_api_key_id api_key_id TYPE bloom_filter(0.01) GRANULARITY 4;
