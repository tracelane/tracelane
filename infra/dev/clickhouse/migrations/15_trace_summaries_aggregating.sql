-- B-243 — one trace rendered as TWO rows with fractional span counts, for every real agent.
--
-- THE DEFECT. `mv_trace_summaries` does `GROUP BY tenant_id, trace_id`, and a materialized
-- view aggregates PER INSERT BLOCK, never across the table. A trace whose spans arrive in two
-- ingest flushes therefore emits TWO summary rows, each holding that batch's own
-- `min(start_time)`. `start_time` was IN THE SORTING KEY, so the rows had DIFFERENT keys and
-- ReplacingMergeTree could not collapse them — `SELECT ... FROM trace_summaries FINAL` returned
-- both. Real latency is the trigger: synthetic ~40ms calls all leave in one BatchSpanProcessor
-- flush, so no test ever saw it.
--
-- Measured on prod 2026-08-17: 8,893 rows / 8,892 distinct traces. Exactly one duplicated
-- trace, and it is the B-227 SDK proof run — the only real multi-span trace with real latency
-- the system has recorded. The defect is not rare; the traffic is. What the customer saw:
--     research.run   5 spans   6.55s
--     (empty name)   3 spans   3.72s
-- against a truth in `spans` of ONE trace, EIGHT spans, 6.551008s.
--
-- WHY REPLACINGMERGETREE CANNOT BE FIXED BY CHANGING ONLY THE KEY. Replacing keeps ONE row and
-- discards the other; it does not MERGE them. With `ORDER BY (tenant_id, trace_id)` the survivor
-- would carry 5 spans or 3 spans — never 8. The rows are PARTIAL, so the engine must aggregate.
--
-- THE FIX, and the part that makes it cheap: AggregatingMergeTree with SimpleAggregateFunction
-- columns. SimpleAggregateFunction stores the PLAIN value (not an opaque state), merges it with
-- the named function on background merge, and is read back as an ordinary value — so
-- `SELECT span_count` keeps working and no `-Merge` suffix leaks into the read path.
--
-- CONSEQUENCE WORTH STATING: every existing Rust reader already says `FROM trace_summaries
-- FINAL` (trace_reads.rs:1362,1573, alerts/checker.rs:67, server.rs:3566). FINAL on an
-- AggregatingMergeTree applies the aggregate functions, so those readers become CORRECT with
-- ZERO code changes. This migration is the whole fix.
--
-- `duration_us` becomes an ALIAS rather than a stored column. It is `dateDiff(min(start),
-- max(end))` — a value that cannot be merged from two partial rows, because neither row's
-- duration is a component of the true one. As an ALIAS it is computed at read time from the
-- MERGED min/max, so `WHERE duration_us >= ?` and `ORDER BY duration_us` (trace_reads.rs:1368,
-- :1418) keep working and are now right instead of ranging over partial values.
--
-- `PARTITION BY tuple()` — NO partitioning, and this is the subtle half of the bug.
-- **ClickHouse merges parts only WITHIN a partition.** The old key was `toYYYYMM(start_time)`,
-- derived from the very value that differs between the two rows, so a trace straddling a month
-- boundary would produce two rows that could NEVER merge no matter how correct the sort key
-- was. Any per-batch-derived partition key reintroduces the defect in a rarer form, which is
-- worse: it would survive this fix and reappear once a year.
-- Dropping partitioning is safe here because nothing depends on it: `retention_sweep.rs:136`
-- deletes with `DELETE FROM ... WHERE`, a mutation, NOT `DROP PARTITION`. The 365d fail-safe
-- TTL becomes a row-level TTL, which ClickHouse applies during merges either way. This is a
-- one-row-per-trace summary table, not the span firehose — `spans` keeps its own partitioning.

-- 1. The new table, alongside the old one. Nothing reads it yet.
CREATE TABLE IF NOT EXISTS tracelane.trace_summaries_v2
(
    tenant_id        String,
    trace_id         String,
    -- max() over String: a real name beats '' lexicographically, which is exactly the observed
    -- split (batch 2 carried no root span, so its root_name was empty).
    root_name        SimpleAggregateFunction(max, String),
    start_time       SimpleAggregateFunction(min, DateTime64(6, 'UTC')),
    end_time         SimpleAggregateFunction(max, DateTime64(6, 'UTC')),
    span_count       SimpleAggregateFunction(sum, UInt64),
    error_count      SimpleAggregateFunction(sum, UInt64),
    intervention     SimpleAggregateFunction(max, UInt8),
    model            SimpleAggregateFunction(max, String),
    -- Read-time, from the MERGED bounds. Never stored: a per-batch duration is not a component
    -- of the trace's duration.
    duration_us      Int64 ALIAS dateDiff('microsecond', start_time, end_time)
)
ENGINE = AggregatingMergeTree
PARTITION BY tuple()
ORDER BY (tenant_id, trace_id)
TTL toDate(start_time) + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

-- ── ORDER IS LOAD-BEARING. A MATERIALIZED VIEW RESOLVES ITS TARGET BY NAME, NOT BY UUID. ──
--
-- Proven in a throwaway ClickHouse 24.12 before this ran anywhere near prod: renaming a table
-- out from under a live MV does not re-point the MV, and the failure is not confined to the
-- view. The very next INSERT INTO spans was REJECTED outright:
--
--   Code: 60. DB::Exception: Target table 'tracelane.trace_summaries_v2' of view
--   'tracelane.mv_trace_summaries_v2' doesn't exists.
--
-- On prod that is a CAPTURE OUTAGE, not a stale dashboard: the gateway's span writes start
-- failing. So the sequence below never renames a table that an MV points at — the old MV is
-- dropped first, the rename happens with no MV attached to either table, and the new MV is
-- created LAST against the final name.
--
-- The window between step 3 and step 5 is the only exposure: spans inserted then produce no
-- summary row. The steps are consecutive statements (sub-second) and step 6 reconciles anything
-- that slipped through — scoped to traces MISSING from the new table, because re-inserting a
-- trace the MV already captured would DOUBLE its span_count under `sum`.

-- 2. Backfill from `spans`, the source of truth. Not from the old summaries: those rows are the
--    defect, and two partial rows cannot be repaired into one correct row. One statement means
--    one aggregation over the whole set, so every trace lands as a single correct part.
INSERT INTO tracelane.trace_summaries_v2
SELECT
    s.tenant_id,
    s.trace_id,
    maxIf(s.name, s.parent_span_id IS NULL),
    min(s.start_time),
    max(s.end_time),
    toUInt64(count()),
    toUInt64(countIf(s.status_code = 2)),
    max(s.intervention),
    max(
        coalesce(
            nullIf(JSONExtractString(s.attributes, 'gen_ai_response_model'), ''),
            nullIf(JSONExtractString(s.attributes, 'gen_ai_request_model'), ''),
            nullIf(JSONExtractString(s.attributes, 'gen_ai.response.model'), ''),
            nullIf(JSONExtractString(s.attributes, 'gen_ai.request.model'), ''),
            JSONExtractString(s.attributes, 'llm.model_name')
        )
    )
FROM tracelane.spans AS s
GROUP BY s.tenant_id, s.trace_id;

-- 3. Detach the old MV FIRST, so nothing points at either table during the rename.
DROP TABLE IF EXISTS tracelane.mv_trace_summaries;

-- 4. Atomic swap. The old table is KEPT as `_old` — it is the rollback, and it is dropped by
--    hand only after the new table has been verified against `spans`.
RENAME TABLE tracelane.trace_summaries   TO tracelane.trace_summaries_old,
             tracelane.trace_summaries_v2 TO tracelane.trace_summaries;

-- 5. The MV, recreated under its CANONICAL name against the FINAL table name. Same source and
--    same GROUP BY as before; what changed is that its per-batch output is now a PARTIAL
--    AGGREGATE the engine merges, rather than a whole row that overwrites its sibling.
CREATE MATERIALIZED VIEW IF NOT EXISTS tracelane.mv_trace_summaries
TO tracelane.trace_summaries
AS
SELECT
    s.tenant_id AS tenant_id,
    s.trace_id  AS trace_id,
    -- maxIf over the root's name: batches with no root span contribute '' and lose the merge.
    maxIf(s.name, s.parent_span_id IS NULL)                  AS root_name,
    min(s.start_time)                                        AS start_time,
    max(s.end_time)                                          AS end_time,
    toUInt64(count())                                        AS span_count,
    toUInt64(countIf(s.status_code = 2))                     AS error_count,
    max(s.intervention)                                      AS intervention,
    -- OTel-GenAI attrs are stored flattened with underscores (`gen_ai_response_model`);
    -- coalesce to the dotted + OpenInference forms (ADR-043 / migration 06). `max` rather than
    -- the old `argMinIf`: argMin has no mergeable simple form, and a batch that saw no model
    -- contributes '' and loses — same shape as root_name.
    max(
        coalesce(
            nullIf(JSONExtractString(s.attributes, 'gen_ai_response_model'), ''),
            nullIf(JSONExtractString(s.attributes, 'gen_ai_request_model'), ''),
            nullIf(JSONExtractString(s.attributes, 'gen_ai.response.model'), ''),
            nullIf(JSONExtractString(s.attributes, 'gen_ai.request.model'), ''),
            JSONExtractString(s.attributes, 'llm.model_name')
        )
    )                                                        AS model
FROM tracelane.spans AS s
GROUP BY s.tenant_id, s.trace_id;

-- 6. RECONCILE the step-3→step-5 window. Scoped to traces MISSING from the new table, never a
--    blanket re-run: `span_count` is a `sum`, so re-inserting a trace the MV already captured
--    would double it. Idempotent — running this twice is a no-op.
INSERT INTO tracelane.trace_summaries
SELECT
    s.tenant_id, s.trace_id,
    maxIf(s.name, s.parent_span_id IS NULL),
    min(s.start_time), max(s.end_time),
    toUInt64(count()), toUInt64(countIf(s.status_code = 2)), max(s.intervention),
    max(coalesce(
        nullIf(JSONExtractString(s.attributes, 'gen_ai_response_model'), ''),
        nullIf(JSONExtractString(s.attributes, 'gen_ai_request_model'), ''),
        nullIf(JSONExtractString(s.attributes, 'gen_ai.response.model'), ''),
        nullIf(JSONExtractString(s.attributes, 'gen_ai.request.model'), ''),
        JSONExtractString(s.attributes, 'llm.model_name')))
FROM tracelane.spans AS s
WHERE s.trace_id NOT IN (SELECT trace_id FROM tracelane.trace_summaries)
GROUP BY s.tenant_id, s.trace_id;
