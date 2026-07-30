--
-- Both objects below have NO runtime reader (verified 2026-07-18): nothing in
-- crates/gateway or apps/web queries them; only a migration-text eval asserts
-- v_slo_28d exists. A dead view is worse than a fixed one nobody reads, so we
-- DELETE rather than fix. The live SLO path uses v_slo_stats (unchanged) and the
-- dashboard cost tile reads the real per-span gen_ai.usage.cost (not these).
--
-- #7 v_cost_by_hour — orphaned AND wrong: its cost math divides by 1e9 instead
--    of 1e8 (10x under) and labels USD as "cents". Delete it.
--
-- #8 the v_slo_28d chain — orphaned; its overhead_p99 field also mislabels total
--    collateral). Drop the view + its materialized view (stops the per-span
--    write it did for a table nobody reads) + the target table.
--
-- These DROPs are intentional and idempotent (IF EXISTS). They do not touch any
-- surfaced object; re-running is a no-op.
DROP VIEW IF EXISTS tracelane.v_cost_by_hour;
DROP VIEW IF EXISTS tracelane.v_slo_28d;
DROP TABLE IF EXISTS tracelane.mv_slo_minute_stats;
DROP TABLE IF EXISTS tracelane.slo_minute_stats;
