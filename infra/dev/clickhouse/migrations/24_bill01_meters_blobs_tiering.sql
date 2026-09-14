-- Migration 24: BILL-01 (pricing v3, ADR-076) — the six meters' storage, content-addressed
-- blobs with reference counting, and the hot→cold MOVE tiering on `spans`.
--
-- Spec: specs/BILL-01-metering-and-tiers.md §2.1–2.4. Apply on prod with clickhouse-client as
-- the admin user (the service users have no DDL grant, B-383). Idempotent: every statement is
-- IF NOT EXISTS / ADD COLUMN IF NOT EXISTS, and the two TIERING statements at the bottom are
-- guarded by a storage-policy precondition described there.
--
-- ── 1. LOGICAL bytes per span — the number every byte meter reads ─────────────────────────
--
-- `span_bytes` is what the CUSTOMER SENT, not what we store: the writer sets it BEFORE any
-- blob substitution (§2.3) so dedup is our margin, never a markdown (ADR-076 §3). It is a
-- DEFAULT (not MATERIALIZED) so (a) the writer can override it with the pre-dedup size and
-- (b) rows written before this migration get the expression at read time — history is
-- billable without rewriting parts. The 96 covers the fixed columns (two 36-char ids, two
-- timestamps, status). Prod measured 2026-09-13: content-off attributes ≈ 315 B → ~430 B/span.
ALTER TABLE tracelane.spans
    ADD COLUMN IF NOT EXISTS span_bytes UInt32
        DEFAULT toUInt32(length(attributes) + length(name) + length(status_message) + 96);

-- ── 2. Meter COUNTERS — append-only deltas, summed at read ────────────────────────────────
--
-- Meters 1 (ingest_bytes) and 6 (eval_runs) are counters: the gateway publish path, the
-- ingest OTLP decoder and the judge sites each INSERT a delta row per flush. `source` names
-- the writer (`gateway`, `ingest`, `judge`) so two writers never collapse into one row that
-- looks like a single source, and so a defect in one is attributable. Read:
--   SELECT meter, sum(value) FROM meter_counters WHERE tenant_id = ? AND day BETWEEN ? AND ? GROUP BY meter
-- NEVER read a raw row as a total — SummingMergeTree sums on MERGE, not on insert.
CREATE TABLE IF NOT EXISTS tracelane.meter_counters
(
    tenant_id   String,
    day         Date,
    meter       LowCardinality(String),   -- ingest_bytes | eval_runs | key_output_tokens | key_spend_micro_usd
    -- for per-key meters (A3 velocity breaker) the key id rides in `dim`; '' otherwise
    dim         String DEFAULT '',
    value       Float64,
    source      LowCardinality(String) DEFAULT '',
    recorded_at DateTime64(3, 'UTC') DEFAULT now64()
)
ENGINE = SummingMergeTree(value)
PARTITION BY toYYYYMM(day)
ORDER BY (tenant_id, day, meter, dim, source)
-- 800 d > the 730-day queryable history so a February-of-year-2 invoice can still be re-derived.
TTL day + INTERVAL 800 DAY
SETTINGS index_granularity = 8192;

-- ── 3. Meter GAUGES — one value per (tenant, day, meter); last write wins ─────────────────
--
-- Meters 2 (hot_resident_bytes), 3 (series), 4 (scan_bytes), 5 (cold_bytes) are computed by
-- the daily metering job in the gateway process. A re-run for the same day REPLACES, never
-- doubles — which a Summing table cannot express. Read with FINAL or argMax(value, computed_at).
CREATE TABLE IF NOT EXISTS tracelane.meter_gauges
(
    tenant_id   String,
    day         Date,
    meter       LowCardinality(String),   -- hot_resident_bytes | series | scan_bytes | cold_bytes
    value       Float64,
    computed_at DateTime64(3, 'UTC') DEFAULT now64()
)
ENGINE = ReplacingMergeTree(computed_at)
PARTITION BY toYYYYMM(day)
ORDER BY (tenant_id, day, meter)
TTL day + INTERVAL 800 DAY
SETTINGS index_granularity = 8192;

-- ── 4. Content-addressed blobs (blake3), PER TENANT, reference-counted ────────────────────
--
-- `hash` is FixedString(32) = the 32 RAW BYTES of the blake3 digest. The Rust Row type MUST
-- be `[u8; 32]`, never `String` — a `String` against FixedString desynchronises RowBinary on
-- the first field and the insert fails SILENTLY at debug! level (B-274, five instances). The
-- key is (tenant_id, hash): two tenants sending the identical system prompt hold two blobs
-- by design, which is what makes erasure a per-tenant DELETE (§2.4).
CREATE TABLE IF NOT EXISTS tracelane.blobs
(
    tenant_id  String,
    hash       FixedString(32),
    bytes      String CODEC(ZSTD(3)),
    size       UInt32,
    first_seen DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree
ORDER BY (tenant_id, hash)
SETTINGS index_granularity = 8192;

-- One row per (span, blob) reference. Written in the SAME insert batch as the span, no
-- read-modify-write on the hot path. Its TTL equals the spans' queryable-history DELETE
-- (730 d) so a reference dies exactly when its span does; the GC (§2.3) deletes a blob whose
-- (tenant_id, hash) has no surviving reference. `refcount` is a query, never a column.
CREATE TABLE IF NOT EXISTS tracelane.blob_refs
(
    tenant_id String,
    hash      FixedString(32),
    span_id   String,
    day       Date
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(day)
ORDER BY (tenant_id, hash, day)
TTL day + INTERVAL 730 DAY
SETTINGS index_granularity = 8192;

-- ── 5. TIERING — a MOVE, never a copy (§2.2, ADR-022 mechanism) ──────────────────────────
--
-- PRECONDITION: infra/prod/clickhouse/config.xml declares
--   <storage_configuration><disks><r2_cold type=s3 …/></disks>
--     <policies><hot_cold><volumes><default>default</default><cold>r2_cold</cold></volumes></hot_cold></policies>
--   </storage_configuration>
-- The hot volume MUST be named `default`: switching an existing table from the `default`
-- policy is refused (BAD_ARGUMENTS, "shall contain volumes of the old storage policy")
-- unless the new policy carries the old volume by name — hit on prod 2026-09-14.
-- and `SELECT policy_name FROM system.storage_policies WHERE policy_name = 'hot_cold'` returns
-- one row. Run the two statements below ONLY after that read succeeds; on a box without the
-- policy the first ALTER fails loudly with UNKNOWN_POLICY and nothing is changed — correct.
--
-- `materialize_ttl_after_modify = 0` is a SESSION setting: set it before the MODIFY TTL or
-- ClickHouse rewrites every existing part on a 16 GiB box under a 6 GiB cap (the same trap the
-- config.xml system-log comment records). The new TTL applies to parts as they merge/move.
--
--   SET materialize_ttl_after_modify = 0;
--   ALTER TABLE tracelane.spans MODIFY SETTING storage_policy = 'hot_cold';
--   ALTER TABLE tracelane.spans MODIFY TTL
--       toDate(start_time) + INTERVAL 365 DAY TO VOLUME 'cold',
--       toDate(start_time) + INTERVAL 730 DAY DELETE;
--
-- What this makes true: a part whose newest start_time is > 365 d old is MOVED to the R2 disk
-- by the background TTL mover; its bytes leave NVMe when the move commits (system.parts
-- .disk_name = 'r2_cold'); the same SELECT reads it, seconds not milliseconds; at 730 d the
-- part is DELETED (two-year queryable history, every paid tier). The per-TENANT indexed window
-- (3/30/90/180/365 d) is a READ-side and METER-side boundary (spec §2.2, founder ruling B3),
-- and Free's 30-day queryable history is the retention sweep reading `queryable_days`.
