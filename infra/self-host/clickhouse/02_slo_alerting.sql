-- Migration 02: Per-tenant cost/latency SLO alerting
-- Adds materialized views that power the dashboard SLO panel and alert webhooks.
-- All tables are tenant-scoped — every query MUST include WHERE tenant_id = ?

-- ── Per-hour latency quantiles + cost ─────────────────────────────────────────
-- AggregatingMergeTree stores partial aggregates that are finalized at query time.
-- Populate via mv_slo_hourly_stats materialized view (below).
CREATE TABLE IF NOT EXISTS tracelane.slo_hourly_stats
(
    tenant_id       String,
    bucket_hour     DateTime,                    -- toStartOfHour(start_time)
    provider        String,
    model           String,

    -- Latency quantiles (microseconds) — quantileState for query-time merge
    latency_p50     AggregateFunction(quantile(0.50), Int64),
    latency_p95     AggregateFunction(quantile(0.95), Int64),
    latency_p99     AggregateFunction(quantile(0.99), Int64),

    -- Request counts
    request_count   AggregateFunction(count, UInt8),
    error_count     AggregateFunction(countIf, UInt8, UInt8),

    -- Token usage (for cost estimation)
    input_tokens    AggregateFunction(sum, Int64),
    output_tokens   AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(bucket_hour)
ORDER BY (tenant_id, bucket_hour, provider, model)
TTL toDate(bucket_hour) + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS tracelane.mv_slo_hourly_stats
TO tracelane.slo_hourly_stats
AS
SELECT
    tenant_id,
    toStartOfHour(start_time)                              AS bucket_hour,
    -- ADR-043 / Migration 06: read the flattened gen_ai_* keys the gateway
    -- writes, coalescing to dotted + OpenInference forms (else the SLO panel
    -- ships with no provider/model rows on self-host).
    coalesce(
        nullIf(JSONExtractString(attributes, 'gen_ai_provider_name'), ''),
        nullIf(JSONExtractString(attributes, 'gen_ai_system'), ''),
        JSONExtractString(attributes, 'llm.provider')
    )                                                      AS provider,
    coalesce(
        nullIf(JSONExtractString(attributes, 'gen_ai_response_model'), ''),
        nullIf(JSONExtractString(attributes, 'gen_ai_request_model'), ''),
        JSONExtractString(attributes, 'llm.model_name')
    )                                                      AS model,

    quantileState(0.50)(duration_us)                       AS latency_p50,
    quantileState(0.95)(duration_us)                       AS latency_p95,
    quantileState(0.99)(duration_us)                       AS latency_p99,

    countState()                                           AS request_count,
    countIfState(status_code = 2)                          AS error_count,

    sumState(
        toInt64(JSONExtractInt(attributes, 'gen_ai_usage_input_tokens'))
    )                                                      AS input_tokens,
    sumState(
        toInt64(JSONExtractInt(attributes, 'gen_ai_usage_output_tokens'))
    )                                                      AS output_tokens
FROM tracelane.spans
GROUP BY tenant_id, bucket_hour, provider, model;

-- ── Query helper: readable SLO stats ─────────────────────────────────────────
-- This view finalizes the AggregatingMergeTree partials for dashboard queries.
-- Usage: SELECT * FROM tracelane.v_slo_stats WHERE tenant_id = ? AND bucket_hour >= ?
CREATE VIEW IF NOT EXISTS tracelane.v_slo_stats AS
SELECT
    tenant_id,
    bucket_hour,
    provider,
    model,
    round(quantileMerge(0.50)(latency_p50) / 1000, 1)     AS p50_ms,
    round(quantileMerge(0.95)(latency_p95) / 1000, 1)     AS p95_ms,
    round(quantileMerge(0.99)(latency_p99) / 1000, 1)     AS p99_ms,
    countMerge(request_count)                              AS requests,
    countMerge(error_count)                                AS errors,
    round(countMerge(error_count) * 100.0
          / greatest(countMerge(request_count), 1), 2)     AS error_rate_pct,
    sumMerge(input_tokens)                                 AS total_input_tokens,
    sumMerge(output_tokens)                                AS total_output_tokens
FROM tracelane.slo_hourly_stats
GROUP BY tenant_id, bucket_hour, provider, model;

-- ── SLO alert records ─────────────────────────────────────────────────────────
-- Alert-event sink for the ADR-061 alert job (one row per breach). NOTE: the
-- job is not built yet (B-103) — this table is provisioned ahead of it; there
-- is no writer today.
-- Append-only; one row per breach event.
CREATE TABLE IF NOT EXISTS tracelane.slo_alerts
(
    tenant_id       String,
    alert_time      DateTime64(3, 'UTC') DEFAULT now64(),
    alert_type      String,   -- latency_p95_breach | latency_p99_breach | error_rate_breach | cost_spike
    provider        String,
    model           String,
    bucket_hour     DateTime,

    -- Observed vs threshold
    observed_value  Float64,
    threshold_value Float64,
    unit            String,   -- ms | pct | usd

    -- Metadata
    severity        String,   -- warn | critical
    resolved_at     Nullable(DateTime64(3, 'UTC')),
    webhook_sent    UInt8 DEFAULT 0
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(alert_time)
ORDER BY (tenant_id, alert_time)
TTL toDate(alert_time) + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

-- ── Materialized view: usage_counters from spans ──────────────────────────────
-- Populates the billing-side usage_counters table directly from span ingest.
-- Replaces the future manual counter writes in the gateway.
CREATE MATERIALIZED VIEW IF NOT EXISTS tracelane.mv_usage_from_spans
TO tracelane.usage_counters
AS
SELECT
    tenant_id,
    toStartOfHour(start_time)                              AS bucket_hour,
    coalesce(
        nullIf(JSONExtractString(attributes, 'gen_ai_provider_name'), ''),
        nullIf(JSONExtractString(attributes, 'gen_ai_system'), ''),
        JSONExtractString(attributes, 'llm.provider')
    )                                                      AS provider,
    coalesce(
        nullIf(JSONExtractString(attributes, 'gen_ai_response_model'), ''),
        nullIf(JSONExtractString(attributes, 'gen_ai_request_model'), ''),
        JSONExtractString(attributes, 'llm.model_name')
    )                                                      AS model,
    toInt64(JSONExtractInt(attributes, 'gen_ai_usage_input_tokens'))  AS input_tokens,
    toInt64(JSONExtractInt(attributes, 'gen_ai_usage_output_tokens')) AS output_tokens,
    toInt64(1)                                             AS request_count
FROM tracelane.spans
WHERE JSONHas(attributes, 'gen_ai_usage_input_tokens')
   OR JSONHas(attributes, 'llm.usage.prompt_tokens');

-- ── Cost estimation view ──────────────────────────────────────────────────────
-- Updated monthly; values are estimates for budget alerting only.
CREATE VIEW IF NOT EXISTS tracelane.v_cost_by_hour AS
SELECT
    tenant_id,
    bucket_hour,
    provider,
    model,
    sum(input_tokens)  AS input_tokens,
    sum(output_tokens) AS output_tokens,
    sum(request_count) AS requests,
    -- Approximate cost in USD cents (1M token pricing × usage ÷ 1M)
    round(
        sum(input_tokens) * multiIf(
            model LIKE '%claude-opus%',    1500,   -- $15/M
            model LIKE '%claude-sonnet%',  300,    -- $3/M
            model LIKE '%claude-haiku%',   25,     -- $0.25/M
            model LIKE '%gpt-4o%',         250,    -- $2.50/M
            model LIKE '%gpt-4%',          3000,   -- $30/M
            model LIKE '%gemini-1.5-pro%', 125,    -- $1.25/M
            50                                     -- fallback: $0.50/M
        ) / 1000000000.0   -- × price_per_1M ÷ 1M → USD cents
        +
        sum(output_tokens) * multiIf(
            model LIKE '%claude-opus%',    7500,
            model LIKE '%claude-sonnet%',  1500,
            model LIKE '%claude-haiku%',   125,
            model LIKE '%gpt-4o%',         1000,
            model LIKE '%gpt-4%',          6000,
            model LIKE '%gemini-1.5-pro%', 500,
            150
        ) / 1000000000.0,
    6) AS estimated_cost_usd
FROM tracelane.usage_counters
GROUP BY tenant_id, bucket_hour, provider, model;
