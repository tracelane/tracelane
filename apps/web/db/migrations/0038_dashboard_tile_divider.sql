-- 0038 — DSH-13 section dividers (founder request, 2026-09-07): "add divider on
-- page so that when some metrics or tiles are added, they are aligned and of
-- right shape and size."
--
-- A divider is a fourth `dashboard_tiles.shape` value, `'divider'` — a pure
-- layout tile with no metric, no query, one fixed size. Because it is always
-- 12 columns wide, CSS Grid can only start it on a brand-new row, which is
-- what forces every tile placed after it to line up at column 1 (see spec §9.1
-- for the full mechanism).
--
-- Two changes, both additive and idempotent:
--   1. Widen `dashboard_tiles_shape_chk` to admit 'divider'.
--   2. Add `dashboard_tiles_divider_shape_chk`: a divider row can ONLY ever
--      have width=12 and metric_id='__divider__' — enforced at the database
--      layer so an application bug can never write an inconsistent one.
--
-- Neither touches an existing row: every row already in the table has
-- shape IN ('stat','series','breakdown'), which trivially satisfies both the
-- widened enum and the OR-guarded new check.
--
-- Un-journaled (TRAPS §9): this file must be applied to Neon BEFORE the web
-- build that writes shape='divider' deploys, or every divider INSERT 500s on
-- the (still-narrow) CHECK constraint instead of failing cleanly at the API.

ALTER TABLE dashboard_tiles
    DROP CONSTRAINT IF EXISTS dashboard_tiles_shape_chk;
ALTER TABLE dashboard_tiles
    ADD CONSTRAINT dashboard_tiles_shape_chk
    CHECK (shape IN ('stat', 'series', 'breakdown', 'divider'));

ALTER TABLE dashboard_tiles
    DROP CONSTRAINT IF EXISTS dashboard_tiles_divider_shape_chk;
ALTER TABLE dashboard_tiles
    ADD CONSTRAINT dashboard_tiles_divider_shape_chk
    CHECK (shape <> 'divider' OR (width = 12 AND metric_id = '__divider__'));

COMMENT ON CONSTRAINT dashboard_tiles_divider_shape_chk ON dashboard_tiles IS
    'DSH-13 §9: a divider tile is pure layout — always full-width (12 cols) '
    'and always the reserved metric_id sentinel __divider__, which is '
    'deliberately not a METRICS registry key. Enforced here so an application '
    'bug can never write an inconsistent divider row.';
