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
-- per-plan window. Per-tenant retention (Free 7 / Builder 30 / Team 90 / Business 180
-- / Enterprise 365) is enforced by the entitlement-driven sweep job
-- (crates/gateway/src/retention_sweep.rs, reads plan_entitlements.retention_days).
-- Flat 365d here can only OVER-retain (never delete a paying tenant's data early);
-- the previous flat 90d silently deleted Business/Enterprise data despite 180/365d sold.
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
-- is done by the entitlement-driven retention sweep job, not this flat TTL.
TTL toDate(start_time) + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

-- NOTE: source columns are qualified with the table alias `s` (e.g.
-- `min(s.start_time)`) so they resolve to the spans COLUMN, not the output
-- alias of the same name (`… AS start_time`). Unqualified `min(start_time)`
-- here makes ClickHouse read the inner `start_time` as the alias `min(start_time)`
-- → `min(min(...))` → ILLEGAL_AGGREGATION (the MV then fails to create, which
-- silently halts the whole schema apply). Keep every aggregate's input qualified.
CREATE MATERIALIZED VIEW IF NOT EXISTS tracelane.mv_trace_summaries
TO tracelane.trace_summaries
AS
SELECT
    s.tenant_id AS tenant_id,
    s.trace_id  AS trace_id,
    argMinIf(s.name, s.start_time, s.parent_span_id IS NULL) AS root_name,
    min(s.start_time)                                        AS start_time,
    max(s.end_time)                                          AS end_time,
    dateDiff('microsecond', min(s.start_time), max(s.end_time)) AS duration_us,
    count()                                                  AS span_count,
    countIf(s.status_code = 2)                               AS error_count,
    max(s.intervention)                                      AS intervention,
    -- OTel-GenAI attrs are stored flattened with underscores
    -- (`gen_ai_response_model`); coalesce to the dotted + OpenInference forms.
    argMinIf(
        coalesce(
            nullIf(JSONExtractString(s.attributes, 'gen_ai_response_model'), ''),
            nullIf(JSONExtractString(s.attributes, 'gen_ai_request_model'), ''),
            nullIf(JSONExtractString(s.attributes, 'gen_ai.response.model'), ''),
            nullIf(JSONExtractString(s.attributes, 'gen_ai.request.model'), ''),
            JSONExtractString(s.attributes, 'llm.model_name')
        ),
        s.start_time,
        coalesce(
            nullIf(JSONExtractString(s.attributes, 'gen_ai_response_model'), ''),
            nullIf(JSONExtractString(s.attributes, 'gen_ai_request_model'), ''),
            nullIf(JSONExtractString(s.attributes, 'gen_ai.response.model'), ''),
            nullIf(JSONExtractString(s.attributes, 'gen_ai.request.model'), ''),
            JSONExtractString(s.attributes, 'llm.model_name')
        ) != ''
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
--
-- ReplacingMergeTree(event_time) (B-108 forward fix, ADR-065 F1): the
-- per-tenant Postgres-serialized append writes the CH row durably BEFORE it
-- advances + commits the Postgres head, so a crash between the CH write and the
-- commit can leave an orphan row at a seq a later retry re-mints. Keying replace
-- on ORDER BY (tenant_id, seq) with version = event_time makes the retry (later
-- event_time = the row the PG head chains to) the winner; the orphan is
-- superseded. Verification reads (export / anchor leaf-set / warm-reconcile) use
-- FINAL so the orphan is invisible pre-merge. See migration
-- 11_audit_log_replacingmergetree.sql for the conversion of an existing table.
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
    rekor_entry_id Nullable(String),      -- UUID returned by Rekor on anchor
    -- Ed25519 signature over the batch Merkle root (ADR-057, zero-third-party);
    -- '' until the batch anchors. Backfilled per anchor batch by the gateway.
    signature      String DEFAULT '',
    signing_pubkey String DEFAULT ''
)
ENGINE = ReplacingMergeTree(event_time)
PARTITION BY toYYYYMM(event_time)
ORDER BY (tenant_id, seq)
SETTINGS index_granularity = 8192;

-- ── Audit anchor records (ADR-062 Amendment 1 — public Rekor v2 anchoring) ──
-- Per-batch offline-verifiable bundle: the bound Ed25519 attestation + (when
-- anchored) the ECDSA hashedrekord body, inclusion proof, and signed checkpoint.
-- Rekor v2 has no online lookup, so this is the ONLY offline-verification source.
-- Written once per signed batch; streamed by the audit export. See migration 10.
CREATE TABLE IF NOT EXISTS tracelane.audit_anchor_records
(
    tenant_id           String,
    batch_start_seq     UInt64,
    batch_end_seq       UInt64,
    merkle_root         String,
    anchor_state        String,               -- 'anchored' | 'unanchored'
    ed25519_sig         String DEFAULT '',    -- base64, over LOCAL_ATTEST_MSG
    ed25519_pubkey      String DEFAULT '',    -- base64 raw 32B (reference)
    ecdsa_pubkey_spki   String DEFAULT '',    -- base64 DER SPKI (anchored only)
    rekor_log_url       String DEFAULT '',
    rekor_log_index     String DEFAULT '',
    canonicalized_body  String DEFAULT '',    -- base64 hashedrekord body (anchored only)
    inclusion_proof     String DEFAULT '',    -- JSON (anchored only)
    checkpoint_envelope String DEFAULT '',    -- C2SP signed-note (anchored only)
    anchored_at         DateTime64(6, 'UTC')
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(anchored_at)
ORDER BY (tenant_id, batch_start_seq)
SETTINGS index_granularity = 8192;

-- ── Guardrail verdicts (the guardrail spec §2.5) ──────────────────────────
-- One row per side (request | response) per request. The tamper-evident copy
-- lives in audit_log (hash-chained, ungated); this table is the queryable
-- surface for the per-rail §4 dashboards (counts, p50/p99 latency, block rate,
-- fail-open rate). `rails` holds the already-redacted per-rail JSON — no raw
-- secret / PII / full-prompt text (enforced by the recorder + CI grep).
CREATE TABLE IF NOT EXISTS tracelane.guardrail_verdicts
(
    tenant_id            String,
    correlation_id       String,                  -- ULID; matches the trace + ledger entry
    side                 LowCardinality(String),  -- request | response
    event_time           DateTime64(6, 'UTC'),    -- micros since epoch
    decision             LowCardinality(String),  -- allow | block | redact | warn
    rails                String DEFAULT '[]',     -- JSON array of per-rail verdicts (redacted)
    total_latency_micros UInt64,
    fail_open_rails      Array(String) DEFAULT [],
    schema_version       LowCardinality(String) DEFAULT 'tracelane.guardrail.verdict.v1'
)
ENGINE = MergeTree()
-- CLAUDE.md SQL rule: partition by (tenant_id, month) under 50 tenants; switch
-- to toYYYYMM(event_time) only above 50 tenants and document the migration.
PARTITION BY (tenant_id, toYYYYMM(event_time))
ORDER BY (tenant_id, event_time, correlation_id)
TTL toDate(event_time) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- ── V2 reserved: gen_ai.memory.* attributes ─────────────────────────────────
-- These attributes are reserved in the JSON attributes column (no dedicated columns yet).
-- V1 schema accepts them via the attributes JSON blob; V2 will add dedicated columns
-- when memory-aware reliability adapters (mem0, letta, zep) begin writing them.
-- Reserving now avoids a schema migration when V2 ships.
--
-- gen_ai.memory.system:             mem0 | letta | zep | cognee | supermemory | custom
-- gen_ai.memory.operation:          write | read | update | delete | search
-- gen_ai.memory.scope:              user | session | agent
-- gen_ai.memory.tier:               working | archival | recall
-- gen_ai.memory.embedding_id:       string (vector ID in the memory backend)
-- gen_ai.memory.validity_window_start: ISO-8601 (when memory record becomes valid)
-- gen_ai.memory.validity_window_end:   ISO-8601 (when memory record expires)
--
-- See: docs/adr/ADR-001-otel-gen-ai-semconv.md

-- ── V2 reserved: gen_ai.guardrail.decision event ────────────────────────────
-- Proposed to open-telemetry/semantic-conventions. Tracelane is the reference impl.
-- Stored as an event in the attributes JSON blob:
-- {
--   "gen_ai.guardrail.decision": {
--     "decision":   "allow | block | modify",
--     "reason":     "string",
--     "latency_ms": float,
--     "confidence": float (0–1),
--     "ruleset_id": "string"
--   }
-- }
--
-- V1: gen_ai.guardrail.decision is derived from tracelane.intervention + tracelane.aft_ids.
-- V2: stored as a first-class event when the OTel SIG PR is merged.

-- ── V2 reserved: gen_ai.retrieval.* attributes ───────────────────────────────
-- RAG quality metrics for retrieval-augmented agent steps.
-- Stored in the attributes JSON blob; dedicated columns added in V2 when
-- RAG adapters (LlamaIndex, LangChain retrieval, custom) begin writing them.
--
-- gen_ai.retrieval.system:            chromadb | pgvector | pinecone | weaviate | qdrant | custom
-- gen_ai.retrieval.operation:         query | index | delete | upsert
-- gen_ai.retrieval.query:             string (the raw retrieval query)
-- gen_ai.retrieval.top_k:             uint32 (number of results requested)
-- gen_ai.retrieval.returned_count:    uint32 (actual results returned)
-- gen_ai.retrieval.latency_ms:        float (time from query to first result)
-- gen_ai.retrieval.rerank_applied:    bool (whether a reranker was applied post-retrieval)
-- gen_ai.retrieval.max_score:         float (highest relevance score in result set)
-- gen_ai.retrieval.min_score:         float (lowest relevance score in result set)
-- gen_ai.retrieval.collection:        string (vector store collection / index name)
--
-- Enables: recall@k tracking, empty-result detection, slow-retrieval SLO alerts.
-- See: docs/adr/ADR-001-otel-gen-ai-semconv.md

-- ── V2 reserved: gen_ai.tool_cost.* attributes ───────────────────────────────
-- Per-tool-call cost forecasting and budget enforcement for agentic workflows.
-- Stored in the attributes JSON blob; dedicated columns added in V2.
--
-- gen_ai.tool_cost.tool_name:          string (name of the tool invoked)
-- gen_ai.tool_cost.estimated_usd:      float (pre-call cost estimate, from pricing table)
-- gen_ai.tool_cost.actual_usd:         float (post-call actual cost, if provider returns it)
-- gen_ai.tool_cost.budget_remaining_usd: float (tenant tool-budget balance after this call)
-- gen_ai.tool_cost.budget_exceeded:    bool (true if this call pushed the tenant over budget)
-- gen_ai.tool_cost.pricing_model:      per_call | per_token | per_second | flat
-- gen_ai.tool_cost.currency:           ISO-4217 currency code (default: USD)
--
-- Enables: per-agent cost attribution, budget guardrails, cost anomaly detection.
-- See: docs/adr/ADR-001-otel-gen-ai-semconv.md

-- ── federation_signals: cross-customer failure-signature substrate ───────────
-- The anonymized aggregate for opt-in federated detection across tenants,
-- accumulating from the first customer (write path in crates/ingest/federation.rs).
--
-- PRIVACY (load-bearing): tenant_id_hash = SHA256(tenant_id) is
-- ONE-WAY (never the raw id); rows carry NO content, only a bounded AFT taxonomy
-- id + counts + a content-free span-name shape hash. Queries must NEVER join to
-- tracelane.spans / tracelane.audit_log; a V2 surface may expose ONLY a
-- k-anonymized cross-tenant aggregate (count + confidence per AFT class per
-- hour, gated on count(distinct tenant_id_hash) >= K). This is a DELIBERATE
-- cross-tenant table (no tenant_id column) — the one documented exception to the
-- WHERE tenant_id = ? rule; the write path is insert-only so the isolation guard
-- needs no change, and the contract binds the V2 read surface (ADR-056).
CREATE TABLE IF NOT EXISTS tracelane.federation_signals (
    tenant_id_hash  String,
    bucket_hour     DateTime,
    aft_class       String,
    signal_count    UInt32,
    confidence_sum  Float32,
    anonymized_hash String
) ENGINE = SummingMergeTree((signal_count, confidence_sum))
ORDER BY (aft_class, bucket_hour, tenant_id_hash)
TTL toDate(bucket_hour) + INTERVAL 365 DAY;
