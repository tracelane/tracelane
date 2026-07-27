-- Migration 04 — OTel GenAI semconv v1.41 canonical columns (ADR-032 + ADR-039)
--
-- Additive-only, zero-downtime (ADR-039 §23.8): every change is an
-- `ALTER TABLE ... ADD COLUMN ... MATERIALIZED`. No existing column is dropped
-- or renamed; no data is rewritten. New rows compute these columns at INSERT
-- time from the `attributes` JSON blob; the values are the canonical v1.41
-- token-economics + streaming attributes.
--
-- Store-side normalization contract (ADR-032): the ingest decoder
-- (`crates/ingest/src/otlp_decode.rs`) maps BOTH the legacy `gen_ai.system`
-- and the v1.41 `gen_ai.provider.name` wire attributes into the canonical
-- snake_case JSON key `gen_ai_provider_name`, so a legacy-emitting adapter and
-- a v1.41-emitting adapter land in identical rows here (PP-SCHEMA-EVOLUTION).
-- These columns therefore extract the canonical snake_case keys, not the
-- dotted wire keys.
--
-- The v1.41 metrics MVs (`mv_token_economics`, `mv_ttft`, migration 05 /
-- ADR-039 §23.8) read these columns instead of live-aggregating JSON.

ALTER TABLE tracelane.spans
    -- Canonical provider (v1.37 `gen_ai.provider.name`, replaces `gen_ai.system`)
    ADD COLUMN IF NOT EXISTS provider_name LowCardinality(String)
        MATERIALIZED JSONExtractString(attributes, 'gen_ai_provider_name'),

    -- v1.40 prompt-cache token counters
    ADD COLUMN IF NOT EXISTS cache_read_input_tokens UInt32
        MATERIALIZED JSONExtractUInt(attributes, 'gen_ai_usage_cache_read_input_tokens'),
    ADD COLUMN IF NOT EXISTS cache_creation_input_tokens UInt32
        MATERIALIZED JSONExtractUInt(attributes, 'gen_ai_usage_cache_creation_input_tokens'),

    -- v1.41 reasoning/thinking token counter
    ADD COLUMN IF NOT EXISTS reasoning_output_tokens UInt32
        MATERIALIZED JSONExtractUInt(attributes, 'gen_ai_usage_reasoning_output_tokens'),

    -- v1.41 streaming attributes
    ADD COLUMN IF NOT EXISTS request_stream UInt8
        MATERIALIZED JSONExtractBool(attributes, 'gen_ai_request_stream'),
    ADD COLUMN IF NOT EXISTS time_to_first_chunk_s Float64
        MATERIALIZED JSONExtractFloat(attributes, 'gen_ai_response_time_to_first_chunk'),

    -- v1.36 conversation correlation + v1.40 agent version
    ADD COLUMN IF NOT EXISTS conversation_id String
        MATERIALIZED JSONExtractString(attributes, 'gen_ai_conversation_id'),
    ADD COLUMN IF NOT EXISTS agent_version String
        MATERIALIZED JSONExtractString(attributes, 'gen_ai_agent_version');
