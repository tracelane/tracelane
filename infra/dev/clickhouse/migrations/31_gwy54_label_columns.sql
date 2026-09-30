-- Materialized developer labels. Apply by hand before deploying readers.
-- No backfill and no part rewrite: a MATERIALIZED column absent from an old part is COMPUTED
-- from `attributes` at read time, so an old row that already carried the key reads its value
-- and an old row without it reads empty ('' / []). Apply BEFORE the gateway that reads it.
ALTER TABLE tracelane.spans
  ADD COLUMN IF NOT EXISTS environment LowCardinality(String)
      MATERIALIZED JSONExtractString(attributes, 'deployment_environment'),
  ADD COLUMN IF NOT EXISTS release String
      MATERIALIZED JSONExtractString(attributes, 'service_version'),
  ADD COLUMN IF NOT EXISTS service LowCardinality(String)
      MATERIALIZED JSONExtractString(attributes, 'service_name'),
  ADD COLUMN IF NOT EXISTS tags Array(LowCardinality(String))
      MATERIALIZED JSONExtract(attributes, 'tracelane_tags', 'Array(String)'),
  ADD INDEX IF NOT EXISTS idx_tags tags TYPE bloom_filter(0.01) GRANULARITY 4;
