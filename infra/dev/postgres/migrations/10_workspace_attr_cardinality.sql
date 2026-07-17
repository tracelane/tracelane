-- Migration 10 — Per-workspace attribute-key cardinality (ADR-030).
--
-- Stores serialised HyperLogLog++ sketches per workspace, one row per
-- daily window. The rolling 30-day union for a workspace is computed
-- by hydrating the last 30 rows + merging.
--
-- V1 launch ships this schema but does NOT wire flush/hydrate yet —
-- ingest currently has no Postgres pool. The methods on
-- `CardinalityTracker::flush_to_postgres` + `::hydrate_from_postgres`
-- exist and are unit-tested in isolation; V1.1 turns them on. See
-- ADR-030 §Persistence for the deviation rationale.
--
-- `sketch` is a serde-encoded `HyperLogLogPlus` blob (≈16 KB at p=14).
-- `estimated_unique` is cached so dashboards can render without
-- re-deserialising the sketch.
--
-- Indexed on `(workspace_id, window_start)` (the PK) and on
-- `updated_at` for the "stale workspaces to flush" sweep.

CREATE TABLE IF NOT EXISTS workspace_attr_cardinality (
    workspace_id       UUID         NOT NULL,
    window_start       DATE         NOT NULL,
    sketch             BYTEA        NOT NULL,
    estimated_unique   INTEGER      NOT NULL DEFAULT 0,
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, window_start)
);

CREATE INDEX IF NOT EXISTS idx_workspace_attr_cardinality_updated
    ON workspace_attr_cardinality (updated_at);

-- Operational note: the eventual cleanup policy retires rows older
-- than 30 days. V1 ship does not enable the cleanup job; the table
-- will grow ~1 row × workspace × day. At 1 000 workspaces × 365 days
-- = ~365 K rows × ~16 KB sketch = ~6 GB max — comfortable for a
-- year of V1 ops without GC.
--
-- COMMENT placed on the table so a future operator looking at
-- `\dt+` in psql sees the design intent inline.
COMMENT ON TABLE workspace_attr_cardinality IS
  'ADR-030: per-workspace HyperLogLog++ p=14 sketch of unique attribute keys observed per UTC day. Hydrated into ingest at startup; flushed every 60s. The rolling 30-day union is computed by merging the last 30 rows for a workspace_id.';

COMMENT ON COLUMN workspace_attr_cardinality.sketch IS
  'serde-encoded hyperloglogplus::HyperLogLogPlus blob, ~16 KB at p=14';

COMMENT ON COLUMN workspace_attr_cardinality.estimated_unique IS
  'sketch.estimate() cached at last flush — for dashboard read-side without deserialising the sketch';
