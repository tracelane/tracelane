-- 29 — B-493 (2026-09-21): give `spans` the same server-side INSERT dedup window as
-- `meter_counters` (migration 28), so a span batch the ingest writer retries with the SAME
-- `insert_deduplication_token` is accepted and discarded rather than inserted a second time.
--
-- WHY. Reproduced on 2026-09-21: a batch INSERT the client gave up on (a 20 s attempt
-- timeout against a paused ClickHouse) COMMITTED server-side once the server resumed, and the
-- retry inserted the same rows again. `spans` is ReplacingMergeTree and collapsed the
-- duplicate rows on merge — but `mv_trace_summaries` and `mv_slo_hourly_stats` fire per
-- INSERT and have no key to collapse on: 100 traces read `span_count 2`, and the hour's
-- request/token counts doubled for that batch. Every batch now carries a uuid token
-- (crates/ingest/src/clickhouse_writer.rs `flush`), retried unchanged; with this window > 0
-- the server dedups BY TOKEN, data-independent, for the last N inserts, and a deduplicated
-- insert never reaches a materialized view.
--
-- The views fed by `spans` — `mv_trace_summaries` → `trace_summaries`, `mv_slo_hourly_stats` →
-- `slo_hourly_stats` — need their OWN window: proven on a real server that the source
-- table's dedup alone lets the view fire twice (the row is discarded, the aggregate is not).
-- Ingest sends `deduplicate_blocks_in_dependent_materialized_views = 1` on every span INSERT,
-- which makes the views dedup by the same token against these windows.
--
-- 1000 inserts ≈ 200 s of ingest flushes at the 200 ms cadence under continuous load, ≈ hours
-- at prod's rate — wider than any retry ladder (≈ 63 s). A token sent to a table with the
-- window at 0 is accepted and IGNORED, so the ORDER is: these ALTERs on prod BY HAND, THEN the
-- ingest that sends the token. Apply as the admin user (the service users have no DDL grant,
-- B-383). Idempotent.
ALTER TABLE tracelane.spans MODIFY SETTING non_replicated_deduplication_window = 1000;
ALTER TABLE tracelane.trace_summaries MODIFY SETTING non_replicated_deduplication_window = 1000;
ALTER TABLE tracelane.slo_hourly_stats MODIFY SETTING non_replicated_deduplication_window = 1000;
