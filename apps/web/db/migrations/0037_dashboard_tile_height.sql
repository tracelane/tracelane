-- 0037 — DSH-13 tile height (founder report, 2026-09-07): a width=4/6 tile
-- rendered at ~1/12 the grid because `col-span-${tile.width}` is a TEMPLATE
-- class Tailwind never generates (only `col-span-12` was ever emitted — see
-- the fix in apps/web/lib/metrics/tile-support.ts, WIDTH_CLASS). Fixing width
-- alone still left every series/breakdown tile pinned at a 140px chart
-- regardless of its box, so this migration adds the other half: a persisted
-- height class.
--
-- `height` ∈ {compact, regular, tall} → chart pixel height 220/320/480
-- (CHART_HEIGHT_PX) for series/breakdown tiles, and a smaller min-height
-- (STAT_MIN_HEIGHT_PX) for stat tiles. Never the old fixed 140px.
--
-- Un-journaled (TRAPS §9): this file must be applied to Neon BEFORE the web
-- build that reads/writes `dashboard_tiles.height` deploys, or every tile
-- read/write 500s on the missing column. Additive, idempotent, and safe on
-- existing rows: DEFAULT 'regular' means every tile already on a dashboard
-- keeps rendering exactly as it does today until a customer resizes it.

ALTER TABLE dashboard_tiles
    ADD COLUMN IF NOT EXISTS height text NOT NULL DEFAULT 'regular';

ALTER TABLE dashboard_tiles
    DROP CONSTRAINT IF EXISTS dashboard_tiles_height_chk;
ALTER TABLE dashboard_tiles
    ADD CONSTRAINT dashboard_tiles_height_chk
    CHECK (height IN ('compact', 'regular', 'tall'));

COMMENT ON COLUMN dashboard_tiles.height IS
    'DSH-13 tile height class: compact | regular | tall. Drives chart pixel '
    'height (220/320/480) for series/breakdown tiles and a smaller min-height '
    'for stat tiles. Default regular keeps every pre-existing tile unchanged.';
