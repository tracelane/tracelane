-- Spend over time. WRITTEN ONLY: an operator applies this after migration 31.
-- Pause ingest before this cutover. Execute in this order:
-- (1) Install services.xml grants (tl_ingest INSERT and tl_sweeper SELECT, ALTER DELETE on
--     tracelane.spend_hourly — B-601: tl_gateway holds no delete), install the config by
--     atomic rename, recreate ClickHouse, VERIFY grants.
-- (2) CREATE TABLE below.
-- (3) CREATE MATERIALIZED VIEW below.
-- (4) Backfill below with ingest still paused, then verify stored totals.
--     Time the first chunk on prod before running the rest; stop if it hits a cap.
-- (5) Resume ingest only after grants, DDL and backfill are verified.
-- (6) Deploy readers only after a fresh ingest row reaches the aggregate.
-- Supply backfill_days from plans.v3.json policy.spend_spikes.backfill_days;
-- backfill_until is the fixed UTC cutover timestamp. Sums are additive.
-- tl_gateway SELECT is already covered by tracelane.*; verify it at read-back.
-- ClickHouse 24.12 REJECTS query parameters inside SETTINGS ("Expected substitution type",
-- measured on prod 2026-10-01): the operator validates the two integer limits and inlines
-- them in the two SETTINGS clauses below. Applied on prod 2026-10-01 that way (30 one-day
-- chunks, totals equal to direct aggregation over spans).

CREATE TABLE IF NOT EXISTS tracelane.spend_hourly
(
    tenant_id String,
    bucket_hour DateTime('UTC'),
    model LowCardinality(String),
    api_key_id String,
    environment LowCardinality(String),
    service LowCardinality(String),
    cost_usd SimpleAggregateFunction(sum, Float64),
    priced_requests SimpleAggregateFunction(sum, UInt64),
    unpriced_requests SimpleAggregateFunction(sum, UInt64),
    requests SimpleAggregateFunction(sum, UInt64)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(bucket_hour)
ORDER BY (tenant_id, bucket_hour, model, api_key_id, environment, service)
-- Same retention as slo_hourly_stats; no independent retention policy.
TTL toDate(bucket_hour) + INTERVAL 365 DAY
-- Source-table dedup alone does not protect additive MV targets. Ingest retries
-- the same token with deduplicate_blocks_in_dependent_materialized_views = 1;
-- retain 1000 target blocks, matching the other span MV targets' retry window.
SETTINGS non_replicated_deduplication_window = 1000;

CREATE MATERIALIZED VIEW IF NOT EXISTS tracelane.mv_spend_hourly
TO tracelane.spend_hourly AS
SELECT tenant_id, toStartOfHour(start_time) AS bucket_hour,
    coalesce(nullIf(JSONExtractString(attributes, 'gen_ai_request_model'), ''), nullIf(JSONExtractString(attributes, 'gen_ai.request.model'), ''), JSONExtractString(attributes, 'llm.model_name')) AS model,
    api_key_id, environment, service,
    sumIf(source.cost_usd, source.cost_usd_present = 1 AND isFinite(source.cost_usd)) AS cost_usd,
    countIf(source.cost_usd_present = 1 AND isFinite(source.cost_usd)) AS priced_requests,
    countIf(NOT (source.cost_usd_present = 1 AND isFinite(source.cost_usd))) AS unpriced_requests,
    count() AS requests
FROM tracelane.spans AS source
WHERE coalesce(nullIf(JSONExtractString(attributes, 'gen_ai_provider_name'), ''), nullIf(JSONExtractString(attributes, 'gen_ai_system'), ''), nullIf(JSONExtractString(attributes, 'gen_ai.provider.name'), ''), JSONExtractString(attributes, 'llm.provider')) <> ''
GROUP BY tenant_id, bucket_hour, model, api_key_id, environment, service;

-- Backfill: one UTC-day chunk at a time, ingest paused throughout. Do not run
-- this file as an unattended multiquery that continues after a failed guard.
-- Supply all three backfill_* limits from plans.v3.json policy.spend_spikes.
-- Fix backfill_until to an hour-aligned UTC cutover. Partition the interval
-- [backfill_until - backfill_days, backfill_until) into adjacent UTC-day ranges
-- (first/last may be shorter), with hour-aligned chunk_start/chunk_end.
-- Run BOTH guards then the INSERT for EACH range, serially; stop on any error.
-- Verify each range before proceeding. A failed INSERT may have written rows:
-- never retry blindly; inspect and clear ONLY that range before retrying.
-- A populated different range is safe; this range must be empty.
SELECT throwIf(
    {backfill_days:UInt32} = 0 OR {backfill_max_memory_bytes:UInt64} = 0
    OR {backfill_max_execution_seconds:UInt32} = 0
    OR {chunk_start:DateTime64(6, 'UTC')} >= {chunk_end:DateTime64(6, 'UTC')}
    OR {chunk_end:DateTime64(6, 'UTC')} > {chunk_start:DateTime64(6, 'UTC')} + toIntervalDay(1)
    OR {chunk_start:DateTime64(6, 'UTC')} < {backfill_until:DateTime64(6, 'UTC')} - toIntervalDay({backfill_days:UInt32})
    OR {chunk_end:DateTime64(6, 'UTC')} > {backfill_until:DateTime64(6, 'UTC')}
    OR {chunk_start:DateTime64(6, 'UTC')} != toStartOfHour({chunk_start:DateTime64(6, 'UTC')})
    OR {chunk_end:DateTime64(6, 'UTC')} != toStartOfHour({chunk_end:DateTime64(6, 'UTC')})
    OR {backfill_until:DateTime64(6, 'UTC')} != toStartOfHour({backfill_until:DateTime64(6, 'UTC')}),
    'invalid backfill range or resource limits');
SELECT throwIf((SELECT count() FROM (SELECT 1 FROM tracelane.spend_hourly
    WHERE bucket_hour >= {chunk_start:DateTime64(6, 'UTC')}
      AND bucket_hour < {chunk_end:DateTime64(6, 'UTC')} LIMIT 1)) > 0,
    'spend_hourly range is not empty; refuse additive backfill')
SETTINGS max_memory_usage = {backfill_max_memory_bytes:UInt64},
    max_execution_time = {backfill_max_execution_seconds:UInt32};
INSERT INTO tracelane.spend_hourly
SELECT tenant_id, toStartOfHour(start_time) AS bucket_hour,
    coalesce(nullIf(JSONExtractString(attributes, 'gen_ai_request_model'), ''), nullIf(JSONExtractString(attributes, 'gen_ai.request.model'), ''), JSONExtractString(attributes, 'llm.model_name')) AS model,
    api_key_id, environment, service,
    sumIf(source.cost_usd, source.cost_usd_present = 1 AND isFinite(source.cost_usd)) AS cost_usd,
    countIf(source.cost_usd_present = 1 AND isFinite(source.cost_usd)) AS priced_requests,
    countIf(NOT (source.cost_usd_present = 1 AND isFinite(source.cost_usd))) AS unpriced_requests,
    count() AS requests
FROM tracelane.spans AS source FINAL
WHERE coalesce(nullIf(JSONExtractString(attributes, 'gen_ai_provider_name'), ''), nullIf(JSONExtractString(attributes, 'gen_ai_system'), ''), nullIf(JSONExtractString(attributes, 'gen_ai.provider.name'), ''), JSONExtractString(attributes, 'llm.provider')) <> ''
  AND start_time >= {chunk_start:DateTime64(6, 'UTC')}
  AND start_time < {chunk_end:DateTime64(6, 'UTC')}
GROUP BY tenant_id, bucket_hour, model, api_key_id, environment, service
SETTINGS max_memory_usage = {backfill_max_memory_bytes:UInt64},
    max_execution_time = {backfill_max_execution_seconds:UInt32};
