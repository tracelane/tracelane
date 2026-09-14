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
    ingested_at      DateTime64(3, 'UTC') DEFAULT now64(),

    -- GWY-43 (migration 16): cost-attribution dimensions. MATERIALIZED off the
    -- attributes JSON, so only spans written after that deploy carry them —
    -- measured values, never backfilled.
    --
    -- `api_key_id` is the dimension per-key spend needs and the table did not
    -- have: "spend by model" was answerable, "spend by KEY" was impossible
    -- because the fact was never recorded. Empty for a session-authenticated
    -- request (no API key), which is NOT the same as unattributed.
    -- It is the `api_keys.id` UUID, never the key: no secret-derived value goes
    -- on a span (ADR-042 / security review M-2).
    --
    -- `cost_usd_present` exists because every read path wrapped the JSON cost in
    -- `if(isFinite AND > 0, x, 0)`, which renders an HONESTLY UNKNOWN cost as a
    -- confident $0.00. This separates "no cost recorded" from "cost was zero".
    api_key_id       String  MATERIALIZED JSONExtractString(attributes, 'tracelane_api_key_id'),
    cost_usd         Float64 MATERIALIZED JSONExtractFloat(attributes, 'gen_ai_usage_cost'),
    cost_usd_present UInt8   MATERIALIZED toUInt8(JSONHas(attributes, 'gen_ai_usage_cost')),

    -- BILL-01 (migration 24): LOGICAL bytes of the span as the customer sent it — the
    -- number meters 1 (ingest), 2 (hot window) and 5 (cold) read. DEFAULT, not
    -- MATERIALIZED: the ingest writer overrides it with the PRE-dedup size (blobs are our
    -- margin, never a markdown — ADR-076 §3), and rows older than the column get the
    -- expression at read time so history is billable without rewriting parts.
    span_bytes       UInt32  DEFAULT toUInt32(length(attributes) + length(name) + length(status_message) + 96),

    -- OBS-01 full-text search on `name`: ngrambf_v1 (not tokenbf_v1) because the
    -- predicate is a SUBSTRING match (`LIKE '%q%'`); n=4 sets the minimum useful
    -- query length and the route enforces it. The SAME index over `attributes`
    -- (the ~450-byte JSON blob) was deleted in migration 22 (B-379, 2026-09-12) on
    -- measurement: it pruned NOTHING — the bloom saturates on ~450 4-grams per row.
    -- A substring search over the blob is a scan by nature; the time-first ORDER BY
    -- below bounds it to the requested window instead, and the read path always
    -- sends one.
    INDEX idx_api_key_id       api_key_id TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_name_ngram       name       TYPE ngrambf_v1(4, 4096, 3, 0) GRANULARITY 4,
    -- B-379 (migration 22): the single-trace waterfall (`trace_id = ?`, no time
    -- predicate) lost its key prefix when the key became time-first; this bloom
    -- prunes it to the trace's own hourly bucket(s). Measured: 24,576 → 8,192 rows.
    INDEX idx_trace_id         trace_id   TYPE bloom_filter(0.01) GRANULARITY 1
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(start_time)
-- B-379 (migration 22, 2026-09-12): TIME-FIRST. `trace_id` is random, so the old
-- `(tenant_id, trace_id, span_id)` pruned no granule for the `start_time` predicate
-- that 10 of the 22 read sites carry — every metric breakdown read the tenant's whole
-- history (measured: 384,602 rows for a 1-hour window on 1M spans; 20,247 with this
-- key). `toStartOfHour(start_time)` is deterministic per span, so this is still a valid
-- Replacing dedup key. HOUR is the finest bucket that keeps a trace's spans adjacent.
ORDER BY (tenant_id, toStartOfHour(start_time), trace_id, span_id)
-- 365d = the MAX plan retention (Enterprise) — a fail-safe BACKSTOP, not the
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
    root_name        SimpleAggregateFunction(max, String),
    start_time       SimpleAggregateFunction(min, DateTime64(6, 'UTC')),
    end_time         SimpleAggregateFunction(max, DateTime64(6, 'UTC')),
    span_count       SimpleAggregateFunction(sum, UInt64),
    error_count      SimpleAggregateFunction(sum, UInt64),
    intervention     SimpleAggregateFunction(max, UInt8),
    model            SimpleAggregateFunction(max, String),
    -- Read-time from the MERGED bounds; a per-batch duration is not a component of the
    -- trace's duration, so it must never be stored.
    duration_us      Int64 ALIAS dateDiff('microsecond', start_time, end_time),
    -- B-379 (migration 22): the table's key STAYS (tenant_id, trace_id) — B-243's
    -- constraint below holds — and the LIST query reads through this time-ordered
    -- projection instead. It cannot be used under FINAL, so the list query does its
    -- own merge with GROUP BY (SimpleAggregateFunction(max/min/sum) merges ARE
    -- max/min/sum) over only the rows the projection returns for the window.
    -- Measured: 1,000,576 rows for "last 50" → 33,920 at a 1-day window.
    PROJECTION p_by_time (SELECT * ORDER BY tenant_id, start_time)
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
-- `deduplicate_merge_projection_mode = 'rebuild'`: 24.12 refuses a projection on an
-- AggregatingMergeTree otherwise; `rebuild` recomputes the projection part from the
-- merged rows, the only mode that keeps it correct as partial rows combine (B-379).
-- `lightweight_mutation_projection_mode` is deliberately LEFT AT ITS DEFAULT (`throw`):
-- a lightweight DELETE on this table is REFUSED (Code 344). Migration 23 (2026-09-12)
-- reverted the `rebuild` migration 22 set, because on prod a lightweight delete under
-- `rebuild` left `p_by_time` holding the deleted rows (14,980 in the projection over
-- a 794-row base after the merge) — a read routed through the projection returned rows
-- the retention sweep had removed. The sweep deletes from this table with a HEAVY
-- `ALTER TABLE … DELETE` (`retention_sweep.rs`), which rewrites part and projection
-- from the same surviving rows; `throw` is what stops the unsafe form coming back.
SETTINGS index_granularity = 8192, deduplicate_merge_projection_mode = 'rebuild';

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


-- ── Audit log (tamper-evident) ───────────────────────────────────────────────
-- Append-only; hash_chain forms a Merkle chain per tenant.
-- Ed25519 Merkle commitments anchored to Rekor (Week 5).
--
-- ReplacingMergeTree(event_time) (forward fix, ADR-065 F1): the
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
    correlation_id       String,                  -- ULID minted per gateway request; returned to the caller in the 403 block body and copied onto the audit-ledger entry. NOT a column on `spans` — a blocked request 403s pre-span, so there is no trace to join to.
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
-- See: docs/archive/ADR-001-otel-gen-ai-semconv-docsadr-copy.md

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
-- See: docs/archive/ADR-001-otel-gen-ai-semconv-docsadr-copy.md

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
-- See: docs/archive/ADR-001-otel-gen-ai-semconv-docsadr-copy.md

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

-- ── SLO hourly stats (migration 06, DSH-11) — prod's definitions, verbatim ────────
-- Added to the canonical schema 2026-09-12 (B-383 c): prod has carried this table, its
-- MV over `spans` and the read view since migration 06, and schema.sql did not — so a
-- self-host built from this file had no SLO view, and the per-service ClickHouse grants
-- proof (`check-clickhouse-users.sh`) passed against ONE MV over spans while prod has
-- TWO. Every MV over `spans` runs its SELECT as the INSERTING user, and the one this
-- file lacked is why every span flush on prod failed for 70 minutes on 2026-09-12.
-- Read from prod with `SELECT create_table_query FROM system.tables`; only the
-- `IF NOT EXISTS` guards were added.

CREATE TABLE IF NOT EXISTS tracelane.slo_hourly_stats (`tenant_id` String, `bucket_hour` DateTime, `provider` String, `model` String, `latency_p50` AggregateFunction(quantile(0.5), Int64), `latency_p95` AggregateFunction(quantile(0.95), Int64), `latency_p99` AggregateFunction(quantile(0.99), Int64), `request_count` AggregateFunction(count, UInt8), `error_count` AggregateFunction(countIf, UInt8), `input_tokens` AggregateFunction(sum, Int64), `output_tokens` AggregateFunction(sum, Int64)) ENGINE = AggregatingMergeTree PARTITION BY toYYYYMM(bucket_hour) ORDER BY (tenant_id, bucket_hour, provider, model) TTL toDate(bucket_hour) + toIntervalDay(365) SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS tracelane.mv_slo_hourly_stats TO tracelane.slo_hourly_stats (`tenant_id` String, `bucket_hour` DateTime('UTC'), `provider` String, `model` String, `latency_p50` AggregateFunction(quantile(0.5), Int64), `latency_p95` AggregateFunction(quantile(0.95), Int64), `latency_p99` AggregateFunction(quantile(0.99), Int64), `request_count` AggregateFunction(count), `error_count` AggregateFunction(countIf, UInt8), `input_tokens` AggregateFunction(sum, Int64), `output_tokens` AggregateFunction(sum, Int64)) AS SELECT tenant_id, toStartOfHour(start_time) AS bucket_hour, coalesce(nullIf(JSONExtractString(attributes, 'gen_ai_provider_name'), ''), nullIf(JSONExtractString(attributes, 'gen_ai_system'), ''), nullIf(JSONExtractString(attributes, 'gen_ai.provider.name'), ''), JSONExtractString(attributes, 'llm.provider')) AS provider, coalesce(nullIf(JSONExtractString(attributes, 'gen_ai_response_model'), ''), nullIf(JSONExtractString(attributes, 'gen_ai_request_model'), ''), nullIf(JSONExtractString(attributes, 'gen_ai.response.model'), ''), JSONExtractString(attributes, 'llm.model_name')) AS model, quantileState(0.5)(duration_us) AS latency_p50, quantileState(0.95)(duration_us) AS latency_p95, quantileState(0.99)(duration_us) AS latency_p99, countState() AS request_count, countIfState(status_code = 2) AS error_count, sumState(toInt64(JSONExtractInt(attributes, 'gen_ai_usage_input_tokens'))) AS input_tokens, sumState(toInt64(JSONExtractInt(attributes, 'gen_ai_usage_output_tokens'))) AS output_tokens FROM tracelane.spans GROUP BY tenant_id, bucket_hour, provider, model;

CREATE VIEW IF NOT EXISTS tracelane.v_slo_stats (`tenant_id` String, `bucket_hour` DateTime, `provider` String, `model` String, `p50_ms` Float64, `p95_ms` Float64, `p99_ms` Float64, `requests` UInt64, `errors` UInt64, `error_rate_pct` Float64, `total_input_tokens` Int64, `total_output_tokens` Int64) AS SELECT tenant_id, bucket_hour, provider, model, round(quantileMerge(0.5)(latency_p50) / 1000, 1) AS p50_ms, round(quantileMerge(0.95)(latency_p95) / 1000, 1) AS p95_ms, round(quantileMerge(0.99)(latency_p99) / 1000, 1) AS p99_ms, countMerge(request_count) AS requests, countMerge(error_count) AS errors, round((countMerge(error_count) * 100.) / greatest(countMerge(request_count), 1), 2) AS error_rate_pct, sumMerge(input_tokens) AS total_input_tokens, sumMerge(output_tokens) AS total_output_tokens FROM tracelane.slo_hourly_stats GROUP BY tenant_id, bucket_hour, provider, model;

-- ── BILL-01 (migration 24, 2026-09-13, ADR-076) — meter storage + content-addressed blobs ──
-- Mirrors infra/dev/clickhouse/migrations/24_bill01_meters_blobs_tiering.sql so a FRESH
-- install gets the six meters' tables. The hot→cold tiering ALTERs are NOT here: they need
-- the `hot_cold` storage policy from infra/prod/clickhouse/config.xml and are applied by
-- hand after that policy exists (see the migration's §5). Column docs live in the migration.

CREATE TABLE IF NOT EXISTS tracelane.meter_counters
(
    tenant_id   String,
    day         Date,
    meter       LowCardinality(String),
    dim         String DEFAULT '',
    value       Float64,
    source      LowCardinality(String) DEFAULT '',
    recorded_at DateTime64(3, 'UTC') DEFAULT now64()
)
ENGINE = SummingMergeTree(value)
PARTITION BY toYYYYMM(day)
ORDER BY (tenant_id, day, meter, dim, source)
TTL day + INTERVAL 800 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS tracelane.meter_gauges
(
    tenant_id   String,
    day         Date,
    meter       LowCardinality(String),
    value       Float64,
    computed_at DateTime64(3, 'UTC') DEFAULT now64()
)
ENGINE = ReplacingMergeTree(computed_at)
PARTITION BY toYYYYMM(day)
ORDER BY (tenant_id, day, meter)
TTL day + INTERVAL 800 DAY
SETTINGS index_granularity = 8192;

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
