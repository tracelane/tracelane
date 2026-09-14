-- 0035 — DSH-13 / B-342: one tile per (dashboard, position).
--
-- Two concurrent POST /api/dashboards/[id]/tiles both read max(position)+1, both inserted,
-- and the order became undefined with nothing failing (verifier, 2026-09-05). The API now
-- retries an insert that trips this index with a fresh max, and reorders through a
-- temporary slot (-1) so a swap never holds two tiles at one position.
--
-- Un-journaled (TRAPS §9): apply to Neon BEFORE the web that reads it deploys; additive;
-- idempotent. Safe on an empty table and on any table without duplicates.
CREATE UNIQUE INDEX IF NOT EXISTS dashboard_tiles_dashboard_position_uniq
    ON dashboard_tiles (dashboard_id, position);
