-- 11: audit_log MergeTree -> ReplacingMergeTree (B-108 forward fix, ADR-065 F1).
--
-- WHY: the cross-process seq-assignment race (B-108) is closed by a per-tenant
-- Postgres-serialized append (FOR UPDATE row lock) — crates/gateway/src/audit.rs
-- append_pg_serialized + db/audit_chain_state.rs append_atomic). That fix writes
-- the ClickHouse row DURABLY *before* it advances + commits the Postgres head
-- (CH-durable-before-PG-advance), so a crash between the CH write and the commit
-- can leave an orphan CH row at a seq that a later retry re-mints for a different
-- event. Under a plain MergeTree that is a PERMANENT duplicate (the exact failure
-- being repaired). ReplacingMergeTree keyed on ORDER BY (tenant_id, seq) with a
-- version column = event_time makes the crash-retry row (later event_time = the
-- canonical row the Postgres head chains to) the version WINNER — the orphan is
-- superseded. Every read that feeds verification (audit export, anchor leaf-set,
-- warm-reconcile) reads FINAL, so the orphan is invisible even BEFORE the
-- background merge (ADR-065 GATE 1).
--
-- ClickHouse cannot ALTER a table's engine in place: create the new table, copy
-- the rows, then atomically multi-table RENAME-swap. The column set MUST match
-- the post-migration-09/10 audit_log (adds signature / signing_pubkey).
--
-- ONE-SHOT, controlled deploy. MUST run BEFORE the ADR-065 gateway build deploys
-- (the gateway's export + anchor reads assume the dedup).
--
-- !! STOP (or drain writes from) THE RUNNING GATEWAY BEFORE RUNNING THIS !!
-- The `INSERT ... SELECT` copy + multi-table RENAME swap below is NOT
-- concurrent-write-safe: any audit_log row written between the copy and the
-- RENAME is LOST after the swap (it lands in the old table, which becomes
-- audit_log_pre_rmt). On the blue-green node, take the gateway out of rotation
-- (or dual-write to audit_log + audit_log_rmt for the cutover window) so the
-- audit chain has no writer during the swap. A lost row is a chain GAP the
-- verifier will flag — the exact failure class this migration exists to remove.
--
-- Run only on a node where audit_log already exists (migrations 09/10 applied). Re-running after a
-- successful swap requires first dropping tracelane.audit_log_pre_rmt (the
-- retained rollback copy). DO NOT run against prod without ADR-065 sign-off.

-- Clean up a half-applied prior attempt (idempotent guard).
DROP TABLE IF EXISTS tracelane.audit_log_rmt;

CREATE TABLE tracelane.audit_log_rmt
(
    tenant_id      String,
    seq            UInt64,
    event_time     DateTime64(6, 'UTC'),
    event_type     String,
    actor          String,
    payload        String DEFAULT '{}',
    prev_hash      String DEFAULT '',
    row_hash       String,
    rekor_entry_id Nullable(String),
    signature      String DEFAULT '',
    signing_pubkey String DEFAULT ''
)
ENGINE = ReplacingMergeTree(event_time)
PARTITION BY toYYYYMM(event_time)
ORDER BY (tenant_id, seq)
SETTINGS index_granularity = 8192;

-- Copy every existing row (positional column list — never SELECT *).
INSERT INTO tracelane.audit_log_rmt
SELECT tenant_id, seq, event_time, event_type, actor, payload, prev_hash,
       row_hash, rekor_entry_id, signature, signing_pubkey
FROM tracelane.audit_log;

-- Atomic multi-table swap: audit_log (MergeTree) is retained as
-- audit_log_pre_rmt for rollback, and the ReplacingMergeTree becomes audit_log.
RENAME TABLE tracelane.audit_log     TO tracelane.audit_log_pre_rmt,
             tracelane.audit_log_rmt TO tracelane.audit_log;

-- After verifying the swap (row counts match, export FINAL-dedups), drop the
-- rollback copy:
--   DROP TABLE IF EXISTS tracelane.audit_log_pre_rmt
