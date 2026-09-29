-- 27 — RI-06 / B-449 (ADR-077 Part III, batch E1, 2026-09-19): the durable record of
-- spans lost at the JetStream boundary. Apply BY HAND on prod before the ingest that
-- writes it deploys (nothing applies migrations at boot). Then GRANT INSERT to tl_ingest
-- (infra/prod/clickhouse/users.d/services.xml carries the grant; the users file is
-- re-read on container recreate). Idempotent.

-- RI-06 / B-449 (2026-09-19): spans lost at the JetStream boundary — one row per
-- detected episode, written by ingest (the sole span writer records its own gaps).
-- FLEET-LEVEL BY NECESSITY: a trimmed message's tenant went with its subject, so there
-- is no tenant_id column and this table is NEVER served by a tenant read route. It is
-- operator evidence and the input to a chained gap attestation once the operator-chain
-- decision exists (ADR-078 / ADR-077 Part III R2). TTL 730 d = the longest queryable
-- window: evidence outlives the data it describes, by design (RI-06 §5).
-- The Rust row (crates/ingest/src/capture_gaps.rs) mirrors these columns EXACTLY —
-- RowBinary is positional and typed (the B-292…B-297 class); the real-server test in
-- scripts/ci/run-clickhouse-integration.sh is the control.
CREATE TABLE IF NOT EXISTS tracelane.capture_gaps
(
    detected_at        DateTime64(6, 'UTC'),
    source             LowCardinality(String),
    kind               LowCardinality(String),
    first_missing_seq  UInt64,
    last_missing_seq   UInt64,
    lost               UInt64,
    ingest_instance    String,
    note               String
)
ENGINE = MergeTree
ORDER BY (detected_at)
TTL toDateTime(detected_at) + INTERVAL 730 DAY
SETTINGS index_granularity = 8192;
