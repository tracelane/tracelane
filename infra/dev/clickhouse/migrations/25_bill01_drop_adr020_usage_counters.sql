-- 25 — BILL-01 / ADR-076 contract step, ClickHouse half (2026-09-14).
--
-- `usage_counters` was ADR-020's hourly (tenant, provider, model) token/request
-- counter table, fed by `mv_usage_from_spans` (migration 02) and read by the
-- `v_cost_by_hour` estimate view. Under the ruled model nothing reads any of
-- them: the six meters are `meter_counters` / `meter_gauges` (migration 24), and
-- cost is `spans.cost_usd` / `token_economics` (migration 05). The generated data
-- model (`scripts/ci/build-data-model.py`) listed `usage_counters` as a table no
-- code reads or writes; on prod it held 0 rows and the feeder MV had never been
-- applied there. Founder, 2026-09-14: "no old code logic should exist."
--
-- Fresh installs: `schema.sql` (dev + self-host) no longer declare the table, and
-- the self-host `02_slo_alerting.sql` no longer creates the MV or the view.
-- Idempotent; safe to re-run. Nothing is dropped that anything reads.

DROP VIEW IF EXISTS tracelane.v_cost_by_hour;
DROP TABLE IF EXISTS tracelane.mv_usage_from_spans;
DROP TABLE IF EXISTS tracelane.usage_counters;
