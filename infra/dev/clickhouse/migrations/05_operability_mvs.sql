-- Migration 05 — Operability MVs: token economics, TTFT, SLO budgets
-- (ADR-039 §23.7/§23.8). Additive-only (new tables + MVs); no existing object
-- is altered. All tenant-scoped — every read MUST filter tenant_id.
--
-- These read the CANONICAL v1.41 keys: the snake_case JSON keys the ingest
-- writer stores (`gen_ai_usage_*`, `gen_ai_agent_name`) and the MATERIALIZED
-- columns added in migration 04 (`provider_name`, `cache_read_input_tokens`,
-- `reasoning_output_tokens`, `time_to_first_chunk_s`, …). The pre-existing
-- `mv_slo_hourly_stats` / `mv_usage_from_spans` extract `llm.*` keys that the
-- v1.41 store does not emit; those are not touched here (separate cleanup).

-- ── Token economics (§23.8) ──────────────────────────────────────────────────
-- Per (tenant_id, agent, day) roll-up of every token class — the COGS-not-
-- latency watch item (§23.10 #2). SummingMergeTree accumulates the daily sums.
CREATE TABLE IF NOT EXISTS tracelane.token_economics
(
    tenant_id              String,
    day                    Date,
    agent                  String,
    provider               LowCardinality(String),
    input_tokens           Int64,
    output_tokens          Int64,
    cache_read_tokens      Int64,
    cache_creation_tokens  Int64,
    reasoning_tokens       Int64,
    request_count          Int64
)
ENGINE = SummingMergeTree(
    (input_tokens, output_tokens, cache_read_tokens,
     cache_creation_tokens, reasoning_tokens, request_count)
)
PARTITION BY toYYYYMM(day)
ORDER BY (tenant_id, day, agent, provider)
TTL day + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS tracelane.mv_token_economics
TO tracelane.token_economics
AS
SELECT
    tenant_id,
    toDate(start_time)                                              AS day,
    JSONExtractString(attributes, 'gen_ai_agent_name')             AS agent,
    provider_name                                                  AS provider,
    toInt64(JSONExtractUInt(attributes, 'gen_ai_usage_input_tokens'))  AS input_tokens,
    toInt64(JSONExtractUInt(attributes, 'gen_ai_usage_output_tokens')) AS output_tokens,
    toInt64(cache_read_input_tokens)                               AS cache_read_tokens,
    toInt64(cache_creation_input_tokens)                           AS cache_creation_tokens,
    toInt64(reasoning_output_tokens)                               AS reasoning_tokens,
    toInt64(1)                                                     AS request_count
FROM tracelane.spans;

-- Per-tenant-per-day COGS panel input. Cache-read tokens are billed at a
-- fraction of input (provider-dependent); surfaced separately so a heavy
-- inline-judge tenant on a low tier is caught as a margin problem (§23.10 #2).
CREATE VIEW IF NOT EXISTS tracelane.v_token_economics AS
SELECT
    tenant_id,
    day,
    agent,
    provider,
    sum(input_tokens)          AS input_tokens,
    sum(output_tokens)         AS output_tokens,
    sum(cache_read_tokens)     AS cache_read_tokens,
    sum(cache_creation_tokens) AS cache_creation_tokens,
    sum(reasoning_tokens)      AS reasoning_tokens,
    sum(request_count)         AS requests
FROM tracelane.token_economics
GROUP BY tenant_id, day, agent, provider;

-- ── Time-to-first-chunk (§23.8) ──────────────────────────────────────────────
-- Streaming TTFT p50/p95/p99 per (tenant_id, provider, model). Reads the
-- materialized `time_to_first_chunk_s` column (migration 04), seconds → ms.
CREATE TABLE IF NOT EXISTS tracelane.ttft_stats
(
    tenant_id   String,
    bucket_hour DateTime,
    provider    LowCardinality(String),
    model       String,
    ttft_p50    AggregateFunction(quantile(0.50), Float64),
    ttft_p95    AggregateFunction(quantile(0.95), Float64),
    ttft_p99    AggregateFunction(quantile(0.99), Float64),
    stream_count AggregateFunction(countIf, UInt8, UInt8)
)
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(bucket_hour)
ORDER BY (tenant_id, bucket_hour, provider, model)
TTL toDate(bucket_hour) + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS tracelane.mv_ttft
TO tracelane.ttft_stats
AS
SELECT
    tenant_id,
    toStartOfHour(start_time)                          AS bucket_hour,
    provider_name                                      AS provider,
    JSONExtractString(attributes, 'gen_ai_request_model') AS model,
    quantileStateIf(0.50)(time_to_first_chunk_s, request_stream = 1) AS ttft_p50,
    quantileStateIf(0.95)(time_to_first_chunk_s, request_stream = 1) AS ttft_p95,
    quantileStateIf(0.99)(time_to_first_chunk_s, request_stream = 1) AS ttft_p99,
    countIfState(request_stream = 1)                   AS stream_count
FROM tracelane.spans
GROUP BY tenant_id, bucket_hour, provider, model;

CREATE VIEW IF NOT EXISTS tracelane.v_ttft AS
SELECT
    tenant_id,
    bucket_hour,
    provider,
    model,
    round(quantileMerge(0.50)(ttft_p50) * 1000, 1) AS ttft_p50_ms,
    round(quantileMerge(0.95)(ttft_p95) * 1000, 1) AS ttft_p95_ms,
    round(quantileMerge(0.99)(ttft_p99) * 1000, 1) AS ttft_p99_ms,
    countMerge(stream_count)                       AS streams
FROM tracelane.ttft_stats
GROUP BY tenant_id, bucket_hour, provider, model;

-- ── SLO / error-budget inputs (§23.7) ────────────────────────────────────────
-- 28-day availability + gateway-overhead budget per tenant. Availability SLO
-- 99.9% (43 min/28d); overhead p99 <25ms for 99% of 1-min windows. Reads the
-- correct duration_us + status_code (those columns are accurate regardless of
-- the legacy llm.* MV key bug).
CREATE TABLE IF NOT EXISTS tracelane.slo_minute_stats
(
    tenant_id     String,
    bucket_minute DateTime,
    request_count AggregateFunction(count, UInt8),
    error_count   AggregateFunction(countIf, UInt8, UInt8),
    overhead_p99  AggregateFunction(quantile(0.99), Int64)
)
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(bucket_minute)
ORDER BY (tenant_id, bucket_minute)
TTL toDate(bucket_minute) + INTERVAL 35 DAY
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS tracelane.mv_slo_minute_stats
TO tracelane.slo_minute_stats
AS
SELECT
    tenant_id,
    toStartOfMinute(start_time)         AS bucket_minute,
    countState()                        AS request_count,
    countIfState(status_code = 2)       AS error_count,
    quantileState(0.99)(duration_us)    AS overhead_p99
FROM tracelane.spans
GROUP BY tenant_id, bucket_minute;

-- 28-day SLO scorecard: availability % + the share of 1-min windows whose p99
-- overhead stayed under the 25ms budget (§23.7). Budget burn > 2×/week freezes
-- non-critical deploys (§23.4 lever).
CREATE VIEW IF NOT EXISTS tracelane.v_slo_28d AS
SELECT
    tenant_id,
    countMerge(request_count)                                         AS requests_28d,
    countMerge(error_count)                                           AS errors_28d,
    round(
        100.0 * (countMerge(request_count) - countMerge(error_count))
        / greatest(countMerge(request_count), 1), 4)                  AS availability_pct,
    round(quantileMerge(0.99)(overhead_p99) / 1000, 2)                AS overhead_p99_ms
FROM tracelane.slo_minute_stats
WHERE bucket_minute >= now() - INTERVAL 28 DAY
GROUP BY tenant_id;
