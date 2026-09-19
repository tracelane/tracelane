-- 26 — B17 (founder ruling 2026-09-19, from B-421's first live drift run): make the
-- declared ClickHouse tree equal prod by DROPPING what prod never carried and what
-- nothing reads, instead of applying it.
--
-- What `scripts/ops/check-db-drift.py` reported on prod (2026-09-19): ZERO objects
-- live-but-undeclared, and 14 declared-but-absent — all of them either columns on
-- `spans_v2` (migration 22's rollback copy of the OLD `spans`, EXCHANGEd on
-- 2026-09-12; the tool attributes migration 04's eight never-applied semconv columns,
-- `span_bytes` and `idx_trace_id` to it) or migration 05's four operability views
-- (`mv_token_economics`, `v_token_economics`, `mv_ttft`, `v_ttft`), never applied on
-- prod. Plus three tables acknowledged PENDING (`slo_alerts` from 02, `token_economics`
-- and `ttft_stats` from 05) — read by nothing in `crates/` (verified: zero hits).
--
-- `spans_v2` on prod held 15,099 rows against `spans`' 11,356 at the time of the drop:
-- 14,277 of the surplus belong to the free-tier dogfood tenant (newest 2026-09-07 —
-- all past its 3-day hot window and invisible to every read path, which only ever
-- read `spans`), 100 to the disposable proof tenant, 21 + 6 to two others (newest
-- 2026-08-10 / 2026-08-08). Nothing reads `spans_v2` (grep: only the drift tool names
-- it). The 2026-09-19 04:03 backup (restore-proven from BOTH R2 copies that day, RTO
-- 20 s) carries the table for the 14-day retention of that backup — the rollback copy
-- has served its purpose.
--
-- Fresh installs: `schema.sql` never declared any of these. Idempotent; safe to re-run.
-- Applied BY HAND on prod like every ClickHouse migration (`check-deploy-schema.py`).

DROP TABLE IF EXISTS tracelane.spans_v2;
DROP VIEW  IF EXISTS tracelane.mv_token_economics;
DROP VIEW  IF EXISTS tracelane.v_token_economics;
DROP VIEW  IF EXISTS tracelane.mv_ttft;
DROP VIEW  IF EXISTS tracelane.v_ttft;
DROP TABLE IF EXISTS tracelane.slo_alerts;
DROP TABLE IF EXISTS tracelane.token_economics;
DROP TABLE IF EXISTS tracelane.ttft_stats;
