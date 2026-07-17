-- Migration 06: fix OTel-GenAI attribute keys + apply the SLO pipeline.
--
-- Root cause: the gateway emits OTel-GenAI span attributes FLATTENED with
-- underscores (`gen_ai_request_model`, `gen_ai_response_model`,
-- `gen_ai_provider_name`, `gen_ai_usage_input_tokens`, …), but the original MVs
-- extracted OpenInference dotted keys (`llm.model_name`, `llm.provider`,
-- `llm.usage.prompt_tokens`). Result: the Traces `model` column was always empty
-- and the SLO panel had no data. (The SLO tables were also never applied to
-- prod — `02_slo_alerting.sql` wasn't run, so /v1/slo errored with UNKNOWN_TABLE.)
--
-- Fix: read the actual `gen_ai_*` keys, with COALESCE fallbacks to the dotted
-- OTel form and the OpenInference form so any adapter's shape resolves. Then
-- rebuild `trace_summaries` from existing spans and backfill `slo_hourly_stats`.
--
-- Idempotent: safe to re-run. `trace_summaries` + `slo_hourly_stats` are 100%
-- derived from `spans`, so TRUNCATE + rebuild is non-destructive.

-- ── 1) Traces: model column ──────────────────────────────────────────────────
DROP TABLE IF EXISTS tracelane.mv_trace_summaries;

CREATE MATERIALIZED VIEW tracelane.mv_trace_summaries
TO tracelane.trace_summaries
AS
SELECT
    s.tenant_id AS tenant_id,
    s.trace_id  AS trace_id,
    argMinIf(s.name, s.start_time, s.parent_span_id IS NULL) AS root_name,
    min(s.start_time)                                        AS start_time,
    max(s.end_time)                                          AS end_time,
    dateDiff('microsecond', min(s.start_time), max(s.end_time)) AS duration_us,
    count()                                                  AS span_count,
    countIf(s.status_code = 2)                               AS error_count,
    max(s.intervention)                                      AS intervention,
    argMinIf(
        coalesce(
            nullIf(JSONExtractString(s.attributes, 'gen_ai_response_model'), ''),
            nullIf(JSONExtractString(s.attributes, 'gen_ai_request_model'), ''),
            nullIf(JSONExtractString(s.attributes, 'gen_ai.response.model'), ''),
            nullIf(JSONExtractString(s.attributes, 'gen_ai.request.model'), ''),
            JSONExtractString(s.attributes, 'llm.model_name')
        ),
        s.start_time,
        coalesce(
            nullIf(JSONExtractString(s.attributes, 'gen_ai_response_model'), ''),
            nullIf(JSONExtractString(s.attributes, 'gen_ai_request_model'), ''),
            nullIf(JSONExtractString(s.attributes, 'gen_ai.response.model'), ''),
            nullIf(JSONExtractString(s.attributes, 'gen_ai.request.model'), ''),
            JSONExtractString(s.attributes, 'llm.model_name')
        ) != ''
    )                                                        AS model
FROM tracelane.spans AS s
GROUP BY s.tenant_id, s.trace_id;

-- Rebuild existing rows (MV only fires on new inserts).
TRUNCATE TABLE tracelane.trace_summaries;
INSERT INTO tracelane.trace_summaries
SELECT
    s.tenant_id,
    s.trace_id,
    argMinIf(s.name, s.start_time, s.parent_span_id IS NULL),
    min(s.start_time),
    max(s.end_time),
    dateDiff('microsecond', min(s.start_time), max(s.end_time)),
    count(),
    countIf(s.status_code = 2),
    max(s.intervention),
    argMinIf(
        coalesce(
            nullIf(JSONExtractString(s.attributes, 'gen_ai_response_model'), ''),
            nullIf(JSONExtractString(s.attributes, 'gen_ai_request_model'), ''),
            JSONExtractString(s.attributes, 'llm.model_name')
        ),
        s.start_time,
        coalesce(
            nullIf(JSONExtractString(s.attributes, 'gen_ai_response_model'), ''),
            nullIf(JSONExtractString(s.attributes, 'gen_ai_request_model'), ''),
            JSONExtractString(s.attributes, 'llm.model_name')
        ) != ''
    )
FROM tracelane.spans AS s
GROUP BY s.tenant_id, s.trace_id;

-- ── 2) SLO pipeline (apply + fix keys + countIf-type bug) ────────────────────
-- Drop-and-recreate: these are 100% derived from spans, and the original
-- `error_count AggregateFunction(countIf, UInt8, UInt8)` (two args) doesn't
-- match `countIfState(status_code = 2)` (one arg) → the MV creation type-errors.
-- Correct form is one `UInt8` arg.
DROP TABLE IF EXISTS tracelane.mv_slo_hourly_stats;
DROP TABLE IF EXISTS tracelane.slo_hourly_stats;
CREATE TABLE tracelane.slo_hourly_stats
(
    tenant_id       String,
    bucket_hour     DateTime,
    provider        String,
    model           String,
    latency_p50     AggregateFunction(quantile(0.50), Int64),
    latency_p95     AggregateFunction(quantile(0.95), Int64),
    latency_p99     AggregateFunction(quantile(0.99), Int64),
    request_count   AggregateFunction(count, UInt8),
    error_count     AggregateFunction(countIf, UInt8),
    input_tokens    AggregateFunction(sum, Int64),
    output_tokens   AggregateFunction(sum, Int64)
)
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(bucket_hour)
ORDER BY (tenant_id, bucket_hour, provider, model)
TTL toDate(bucket_hour) + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW tracelane.mv_slo_hourly_stats
TO tracelane.slo_hourly_stats
AS
SELECT
    tenant_id,
    toStartOfHour(start_time) AS bucket_hour,
    coalesce(
        nullIf(JSONExtractString(attributes, 'gen_ai_provider_name'), ''),
        nullIf(JSONExtractString(attributes, 'gen_ai_system'), ''),
        nullIf(JSONExtractString(attributes, 'gen_ai.provider.name'), ''),
        JSONExtractString(attributes, 'llm.provider')
    ) AS provider,
    coalesce(
        nullIf(JSONExtractString(attributes, 'gen_ai_response_model'), ''),
        nullIf(JSONExtractString(attributes, 'gen_ai_request_model'), ''),
        nullIf(JSONExtractString(attributes, 'gen_ai.response.model'), ''),
        JSONExtractString(attributes, 'llm.model_name')
    ) AS model,
    quantileState(0.50)(duration_us) AS latency_p50,
    quantileState(0.95)(duration_us) AS latency_p95,
    quantileState(0.99)(duration_us) AS latency_p99,
    countState()                     AS request_count,
    countIfState(status_code = 2)    AS error_count,
    sumState(toInt64(JSONExtractInt(attributes, 'gen_ai_usage_input_tokens')))  AS input_tokens,
    sumState(toInt64(JSONExtractInt(attributes, 'gen_ai_usage_output_tokens'))) AS output_tokens
FROM tracelane.spans
GROUP BY tenant_id, bucket_hour, provider, model;

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

-- Backfill SLO aggregates from existing spans.
INSERT INTO tracelane.slo_hourly_stats
SELECT
    tenant_id,
    toStartOfHour(start_time) AS bucket_hour,
    coalesce(
        nullIf(JSONExtractString(attributes, 'gen_ai_provider_name'), ''),
        nullIf(JSONExtractString(attributes, 'gen_ai_system'), ''),
        JSONExtractString(attributes, 'llm.provider')
    ) AS provider,
    coalesce(
        nullIf(JSONExtractString(attributes, 'gen_ai_response_model'), ''),
        nullIf(JSONExtractString(attributes, 'gen_ai_request_model'), ''),
        JSONExtractString(attributes, 'llm.model_name')
    ) AS model,
    quantileState(0.50)(duration_us),
    quantileState(0.95)(duration_us),
    quantileState(0.99)(duration_us),
    countState(),
    countIfState(status_code = 2),
    sumState(toInt64(JSONExtractInt(attributes, 'gen_ai_usage_input_tokens'))),
    sumState(toInt64(JSONExtractInt(attributes, 'gen_ai_usage_output_tokens')))
FROM tracelane.spans
GROUP BY tenant_id, bucket_hour, provider, model;
