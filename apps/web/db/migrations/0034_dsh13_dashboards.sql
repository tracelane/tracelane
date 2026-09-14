-- 0034 — DSH-13 Custom dashboards.
--
-- Two tables. A dashboard is a saved *question*, never a saved *answer*:
-- no tile stores a query, a window, or a number. The window comes from the URL;
-- the number comes from the gateway at render time.
--
-- `metric_id` is validated against the registry at write time (web API).
-- At read time, an unknown id renders "This tile's metric no longer exists —
-- remove it" (registry drift — graceful degradation, not a crash).
--
-- CHECK constraints on `width`, `shape`, and `dimension` enforce the closed
-- enums at the database layer so no application bypass can produce invalid state.
--
-- Idempotent: every DDL uses IF NOT EXISTS / DROP CONSTRAINT IF EXISTS.

CREATE TABLE IF NOT EXISTS dashboards (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        text        NOT NULL,
    created_by  text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS dashboards_tenant_id_idx ON dashboards (tenant_id);

CREATE TABLE IF NOT EXISTS dashboard_tiles (
    id              uuid    PRIMARY KEY DEFAULT gen_random_uuid(),
    dashboard_id    uuid    NOT NULL REFERENCES dashboards(id) ON DELETE CASCADE,
    position        integer NOT NULL DEFAULT 0,
    -- Column span on the 12-column grid. CHECK enforces the closed set.
    width           integer NOT NULL DEFAULT 6,
    -- Free-text tile title. 60-char limit is enforced by the API, not the DB.
    title           text    NOT NULL DEFAULT '',
    -- Registry metric id. Validated against the METRICS registry at write time.
    metric_id       text    NOT NULL,
    -- Visualization shape. CHECK enforces the closed set.
    shape           text    NOT NULL DEFAULT 'stat',
    -- For `breakdown` tiles: the grouping dimension. NULL for stat and series.
    dimension       text,
    -- Optional filter on one dimension value (e.g. model = claude-haiku-4-5).
    filter_dimension    text,
    filter_value        text
);

CREATE INDEX IF NOT EXISTS dashboard_tiles_dashboard_id_idx
    ON dashboard_tiles (dashboard_id);

-- ── CHECK constraints — closed enum enforcement at the DB layer ──────────────

ALTER TABLE dashboard_tiles
    DROP CONSTRAINT IF EXISTS dashboard_tiles_width_chk;
ALTER TABLE dashboard_tiles
    ADD CONSTRAINT dashboard_tiles_width_chk
    CHECK (width IN (4, 6, 12));

ALTER TABLE dashboard_tiles
    DROP CONSTRAINT IF EXISTS dashboard_tiles_shape_chk;
ALTER TABLE dashboard_tiles
    ADD CONSTRAINT dashboard_tiles_shape_chk
    CHECK (shape IN ('stat', 'series', 'breakdown'));

ALTER TABLE dashboard_tiles
    DROP CONSTRAINT IF EXISTS dashboard_tiles_dimension_chk;
ALTER TABLE dashboard_tiles
    ADD CONSTRAINT dashboard_tiles_dimension_chk
    CHECK (
        dimension IS NULL OR
        dimension IN ('model', 'provider', 'api_key', 'status', 'operation', 'decision', 'rail')
    );

COMMENT ON TABLE dashboards IS
    'DSH-13 custom dashboards. One row per named dashboard per tenant. '
    'A dashboard is a saved question, not a saved answer — no tile stores '
    'a query, a window, or a number.';

COMMENT ON TABLE dashboard_tiles IS
    'DSH-13 tiles that compose a custom dashboard. metric_id validated against '
    'the registry at write time; unknown ids render gracefully at read time. '
    'The window for every tile comes from the page URL, not this table.';
