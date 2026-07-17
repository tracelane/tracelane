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
    root_name        String,
    start_time       DateTime64(6, 'UTC'),
    end_time         DateTime64(6, 'UTC'),
    duration_us      Int64,
    span_count       UInt32,
    error_count      UInt32,
    intervention     UInt8,
    model            String DEFAULT ''
)
ENGINE = ReplacingMergeTree(end_time)
PARTITION BY toYYYYMM(start_time)
ORDER BY (tenant_id, start_time, trace_id)
TTL toDate(start_time) + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS tracelane.mv_trace_summaries
TO tracelane.trace_summaries
AS
SELECT
    tenant_id,
    trace_id,
    argMinIf(name, start_time, parent_span_id IS NULL) AS root_name,
    min(start_time)                                     AS start_time,
    max(end_time)                                       AS end_time,
    dateDiff('microsecond', min(start_time), max(end_time)) AS duration_us,
    count()                                             AS span_count,
    countIf(status_code = 2)                            AS error_count,
    max(intervention)                                   AS intervention,
    -- OTel-GenAI attrs are stored flattened with underscores
    -- (`gen_ai_response_model`); coalesce to the dotted + OpenInference forms
    -- (ADR-043 / Migration 06). Without this the Model column ships empty.
    argMinIf(
        coalesce(
            nullIf(JSONExtractString(attributes, 'gen_ai_response_model'), ''),
            nullIf(JSONExtractString(attributes, 'gen_ai_request_model'), ''),
            nullIf(JSONExtractString(attributes, 'gen_ai.response.model'), ''),
            nullIf(JSONExtractString(attributes, 'gen_ai.request.model'), ''),
            JSONExtractString(attributes, 'llm.model_name')
        ),
        start_time,
        coalesce(
            nullIf(JSONExtractString(attributes, 'gen_ai_response_model'), ''),
            nullIf(JSONExtractString(attributes, 'gen_ai_request_model'), ''),
            nullIf(JSONExtractString(attributes, 'gen_ai.response.model'), ''),
            nullIf(JSONExtractString(attributes, 'gen_ai.request.model'), ''),
            JSONExtractString(attributes, 'llm.model_name')
        ) != ''
    )                                                   AS model
FROM tracelane.spans
GROUP BY tenant_id, trace_id;

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
--
-- ReplacingMergeTree(event_time) (B-108 forward fix, ADR-065 F1): the gateway
-- writes the CH row durably before it advances the Postgres chain head, so a
-- crash-retry can leave an orphan at a re-minted seq. Version = event_time makes
-- the retry the winner; verification reads use FINAL so the orphan is invisible
-- pre-merge. See infra/dev/clickhouse/migrations/11_audit_log_replacingmergetree.sql.
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
ENGINE = ReplacingMergeTree(event_time)
PARTITION BY toYYYYMM(event_time)
ORDER BY (tenant_id, seq)
SETTINGS index_granularity = 8192;

-- Audit anchor records (ADR-062 Amendment 1 — public Rekor v2 anchoring).
-- Per-batch offline-verifiable bundle streamed by the audit export.
CREATE TABLE IF NOT EXISTS tracelane.audit_anchor_records
(
    tenant_id           String,
    batch_start_seq     UInt64,
    batch_end_seq       UInt64,
    merkle_root         String,
    anchor_state        String,
    ed25519_sig         String DEFAULT '',
    ed25519_pubkey      String DEFAULT '',
    ecdsa_pubkey_spki   String DEFAULT '',
    rekor_log_url       String DEFAULT '',
    rekor_log_index     String DEFAULT '',
    canonicalized_body  String DEFAULT '',
    inclusion_proof     String DEFAULT '',
    checkpoint_envelope String DEFAULT '',
    anchored_at         DateTime64(6, 'UTC')
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(anchored_at)
ORDER BY (tenant_id, batch_start_seq)
SETTINGS index_granularity = 8192;
