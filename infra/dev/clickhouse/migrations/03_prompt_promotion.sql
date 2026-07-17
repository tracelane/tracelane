-- Migration 03: B1 Prompt Promotion + Eval Gates + Auto-Rollback
--
-- Five tables. tenant_id is String (UUID representation) to match the
-- audit_log convention; the Enum8 columns from earlier drafts were
-- replaced with LowCardinality(String) so the clickhouse-rs client can
-- write them via the same serde path as audit_log without custom Enum8
-- wire-format handling.
--
-- All ORDER BY (tenant_id, …), all PARTITION BY toYYYYMM(...) — under
-- multi-tenancy pattern.

-- prompts: the named prompt entity
CREATE TABLE IF NOT EXISTS prompts (
    tenant_id String,
    prompt_id UUID,
    name LowCardinality(String),
    description String,
    created_at DateTime64(3, 'UTC'),
    created_by_user_id String,
    archived UInt8 DEFAULT 0
)
ENGINE = ReplacingMergeTree(created_at)
ORDER BY (tenant_id, prompt_id)
PARTITION BY toYYYYMM(created_at);

-- prompt_versions: parent-child DAG of versions
CREATE TABLE IF NOT EXISTS prompt_versions (
    tenant_id String,
    prompt_version_id UUID,
    prompt_id UUID,
    parent_version_id Nullable(UUID),
    version_number UInt32,
    content String,                          -- the actual prompt template
    template_variables Array(String),
    -- Nullable(LowCardinality(String)) is ILLEGAL in ClickHouse 24.12
    -- ("Nullable cannot wrap LowCardinality") — this is why migration 03 never
    -- applied to prod. Plain Nullable(String) (ADR-054 fix, 2026-07-07).
    model_pin Nullable(String),
    created_at DateTime64(3, 'UTC'),
    created_by_user_id String,
    sha256 FixedString(64)                   -- content-addressable hash (hex)
)
ENGINE = MergeTree
ORDER BY (tenant_id, prompt_id, version_number)
PARTITION BY toYYYYMM(created_at);

-- eval_runs: results of eval suite execution against a candidate version
CREATE TABLE IF NOT EXISTS eval_runs (
    tenant_id String,
    eval_run_id UUID,
    prompt_version_id UUID,
    eval_suite_id UUID,
    started_at DateTime64(3, 'UTC'),
    completed_at Nullable(DateTime64(3, 'UTC')),
    status LowCardinality(String),           -- running | passed | failed | errored
    pass_count UInt32,
    fail_count UInt32,
    error_count UInt32,
    duration_ms UInt32,
    results_json String                      -- per-assertion details
)
-- ReplacingMergeTree(completed_at) is ILLEGAL: the version column can't be
-- Nullable (ClickHouse 24.12). Version-less ReplacingMergeTree dedups by
-- ORDER BY keeping the last-written row — correct for the running→passed
-- update (ADR-054 fix, 2026-07-07).
ENGINE = ReplacingMergeTree()
ORDER BY (tenant_id, eval_run_id)
PARTITION BY toYYYYMM(started_at);

-- promotion_decisions: every promote attempt, allowed or blocked
CREATE TABLE IF NOT EXISTS promotion_decisions (
    tenant_id String,
    promotion_id UUID,
    prompt_id UUID,
    from_version_id Nullable(UUID),
    to_version_id UUID,
    from_env LowCardinality(String),         -- dev | staging | production | canary
    to_env LowCardinality(String),
    eval_run_id Nullable(UUID),
    decision LowCardinality(String),         -- promoted | blocked_by_eval | blocked_by_policy | manual_override
    decided_at DateTime64(3, 'UTC'),
    decided_by_user_id Nullable(String),
    notes String
)
ENGINE = MergeTree
ORDER BY (tenant_id, prompt_id, decided_at)
PARTITION BY toYYYYMM(decided_at);

-- rollback_events: every auto-rollback or suggest-rollback fired
CREATE TABLE IF NOT EXISTS rollback_events (
    tenant_id String,
    rollback_id UUID,
    prompt_id UUID,
    from_version_id UUID,
    to_version_id UUID,
    trigger_metric LowCardinality(String),   -- cost | latency | error_rate | guardrail_fire | accuracy | hallucination
    trigger_value Float64,
    ewma_baseline Float64,
    sigma_drift Float32,
    rollback_mode LowCardinality(String),    -- auto | suggested | human_confirmed | human_dismissed
    fired_at DateTime64(3, 'UTC'),
    confirmed_at Nullable(DateTime64(3, 'UTC')),
    confirmed_by_user_id Nullable(String)
)
ENGINE = MergeTree
ORDER BY (tenant_id, prompt_id, fired_at)
PARTITION BY toYYYYMM(fired_at);

-- Row policies: per-tenant isolation, getClientHeader pattern (per CLAUDE.md)
CREATE ROW POLICY IF NOT EXISTS prompts_tenant_isolation ON prompts USING tenant_id = getClientHeader('X-Tenant-Id') TO tenant_role;
CREATE ROW POLICY IF NOT EXISTS prompt_versions_tenant_isolation ON prompt_versions USING tenant_id = getClientHeader('X-Tenant-Id') TO tenant_role;
CREATE ROW POLICY IF NOT EXISTS eval_runs_tenant_isolation ON eval_runs USING tenant_id = getClientHeader('X-Tenant-Id') TO tenant_role;
CREATE ROW POLICY IF NOT EXISTS promotion_decisions_tenant_isolation ON promotion_decisions USING tenant_id = getClientHeader('X-Tenant-Id') TO tenant_role;
CREATE ROW POLICY IF NOT EXISTS rollback_events_tenant_isolation ON rollback_events USING tenant_id = getClientHeader('X-Tenant-Id') TO tenant_role;
