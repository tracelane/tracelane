-- Tracelane ClickHouse schema
-- All tables are tenant-scoped: every query MUST include WHERE tenant_id = ?
-- ORDER BY includes tenant_id first for per-tenant data locality

CREATE DATABASE IF NOT EXISTS tracelane;

-- ── Core spans table ────────────────────────────────────────────────────────
-- ReplacingMergeTree deduplicates spans by (tenant_id, trace_id, span_id).
-- Deduplication is eventually consistent; queries use FINAL for exact results.
CREATE TABLE IF NOT EXISTS tracelane.spans
(
    -- Identity
    --
    -- WHY THESE ARE `String` AND MUST NOT BE "TIGHTENED" TO FixedString.
    -- The ingest path stores them as a 36-char dashed UUID, but the WIRE decides
    -- the type and the wire is OTLP: a span_id is 8 raw bytes and a trace_id is
    -- 16 (`crates/shared/src/otlp/decode.rs`, which bails on any other length).
    -- **8 bytes IS 16 hex chars and 16 bytes IS 32 hex chars** — the byte count
    -- and the hex-char count are the same width in two notations, not two
    -- competing widths. `otlp_span_id_to_uuid` left-pads the 8 bytes into a
    -- 128-bit UUID; the transform is injective, lossless in the low 64 bits, and
    -- applied identically to span_id and parent_span_id, which is exactly why the
    -- self-join that rebuilds the tree returns zero orphans.
    -- A FixedString here would be a guess dressed as a constraint: it would fix a
    -- RENDERING width while the real constraint lives at the receiver, in bytes.
    -- Verified end to end on prod 2026-08-31 with an unmodified LangGraph agent
    -- via stock openinference (trace 32435b24-…): 11 spans, 1 root, 10 parented,
    -- 11 distinct ids, 0 dangling parents. Harness: scripts/proofs/.
    tenant_id        String,
    trace_id         String,
    span_id          String,
    parent_span_id   Nullable(String),

    -- Span metadata
    name             String,
    start_time       DateTime64(6, 'UTC'),
    end_time         DateTime64(6, 'UTC'),
    duration_us      Int64 MATERIALIZED dateDiff('microsecond', start_time, end_time),
    status_code      UInt8,                -- 0=Unset, 1=Ok, 2=Error
    status_message   String DEFAULT '',

    -- OTel + OpenInference attributes (JSON blob)
    attributes       String DEFAULT '{}',  -- JSON: llm.*, gen_ai.*, tracelane.*

    -- Predictive layer annotations
    aft_ids          Array(String) DEFAULT [],
    intervention     UInt8 DEFAULT 0,      -- 0=none, 1=warn, 2=block

    -- Ingestion timestamp for deduplication windowing
    ingested_at      DateTime64(3, 'UTC') DEFAULT now64()
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(start_time)
ORDER BY (tenant_id, trace_id, span_id)
TTL toDate(start_time) + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

-- ── Materialized view: per-trace aggregates ─────────────────────────────────
-- Pre-aggregated at write time; used by dashboard /v1/traces list endpoint.
CREATE TABLE IF NOT EXISTS tracelane.trace_summaries
(
    tenant_id        String,
    trace_id         String,
    root_name        SimpleAggregateFunction(max, String),
    start_time       SimpleAggregateFunction(min, DateTime64(6, 'UTC')),
    end_time         SimpleAggregateFunction(max, DateTime64(6, 'UTC')),
    span_count       SimpleAggregateFunction(sum, UInt64),
    error_count      SimpleAggregateFunction(sum, UInt64),
    intervention     SimpleAggregateFunction(max, UInt8),
    model            SimpleAggregateFunction(max, String),
    -- Read-time from the MERGED bounds; a per-batch duration is not a component of the
    -- trace's duration, so it must never be stored.
    duration_us      Int64 ALIAS dateDiff('microsecond', start_time, end_time)
)
-- B-243 (migration 15): was ReplacingMergeTree(end_time) ORDER BY (tenant_id, start_time,
-- trace_id) PARTITION BY toYYYYMM(start_time). A materialized view aggregates PER INSERT
-- BLOCK, so a trace whose spans arrive in two ingest flushes emitted TWO rows, each with its
-- own min(start_time) — and because start_time was IN THE SORTING KEY the rows had different
-- keys and FINAL could not collapse them. Replacing is also the wrong operation: it keeps one
-- partial row rather than merging two, so the survivor would carry 5 spans or 3, never 8.
-- AggregatingMergeTree + SimpleAggregateFunction merges them, and PARTITION BY tuple() is
-- required because ClickHouse merges only WITHIN a partition — any per-batch-derived
-- partition key reintroduces the defect in a rarer, harder-to-find form.
ENGINE = AggregatingMergeTree
PARTITION BY tuple()
ORDER BY (tenant_id, trace_id)
TTL toDate(start_time) + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS tracelane.mv_trace_summaries
TO tracelane.trace_summaries
AS
SELECT
    s.tenant_id AS tenant_id,
    s.trace_id  AS trace_id,
    -- maxIf over the ROOT span's name: a batch carrying no root contributes '' and loses the
    -- merge. `argMinIf` has no mergeable simple form, which is why this changed with B-243.
    maxIf(s.name, s.parent_span_id IS NULL)                  AS root_name,
    min(s.start_time)                                        AS start_time,
    max(s.end_time)                                          AS end_time,
    toUInt64(count())                                        AS span_count,
    toUInt64(countIf(s.status_code = 2))                     AS error_count,
    max(s.intervention)                                      AS intervention,
    -- OTel-GenAI attrs are stored flattened with underscores (ADR-043 / migration 06).
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

-- ── Per-tenant usage counters ────────────────────────────────────────────────
-- Used for billing and rate-limit reporting. SummingMergeTree accumulates deltas.
CREATE TABLE IF NOT EXISTS tracelane.usage_counters
(
    tenant_id     String,
    bucket_hour   DateTime,              -- truncated to hour
    provider      String,
    model         String,
    input_tokens  Int64,
    output_tokens Int64,
    request_count Int64
)
ENGINE = SummingMergeTree((input_tokens, output_tokens, request_count))
PARTITION BY toYYYYMM(bucket_hour)
ORDER BY (tenant_id, bucket_hour, provider, model)
TTL toDate(bucket_hour) + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

-- ── Audit log (tamper-evident) ───────────────────────────────────────────────
-- Append-only; hash_chain forms a Merkle chain per tenant.
-- Ed25519 Merkle commitments anchored to Rekor (Week 5).
CREATE TABLE IF NOT EXISTS tracelane.audit_log
(
    tenant_id      String,
    seq            UInt64,
    event_time     DateTime64(6, 'UTC'),
    event_type     String,               -- e.g. request, intervention, export
    actor          String,               -- sub from JWT
    payload        String DEFAULT '{}',  -- JSON event payload
    prev_hash      String DEFAULT '',    -- SHA256 of previous row
    row_hash       String,               -- SHA256 of this row
    -- Sigstore Rekor transparency log entry (populated every anchor_every events)
    rekor_entry_id Nullable(String)       -- UUID returned by Rekor on anchor
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(event_time)
ORDER BY (tenant_id, seq)
SETTINGS index_granularity = 8192;
