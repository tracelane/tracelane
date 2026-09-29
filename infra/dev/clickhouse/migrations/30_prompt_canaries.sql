-- Apply before deploying prompt-resolution canary support. Application is an operator step.
CREATE TABLE IF NOT EXISTS tracelane.prompt_canaries (
    tenant_id String,
    prompt_name String,
    canary_id UUID,
    stable_version_id UUID,
    candidate_version_id UUID,
    candidate_percent Float64,
    enabled UInt8,
    changed_at DateTime64(3, 'UTC'),
    changed_by String
) ENGINE = MergeTree
ORDER BY (tenant_id, prompt_name, changed_at, canary_id);
