-- 20 — `online_eval_scores` (EVL-28 / Sprint 3 item 11).
--
-- WHY A NEW TABLE RATHER THAN `eval_runs` + `eval_run_items`.
--
-- The re-anchor (EVL-28 §11.1) found the old plan — add `kind` to `eval_runs`
-- and seven columns to `eval_run_items` — arguing against migration 19's
-- zero-columns rule, and the shapes do not actually match. An eval RUN is a
-- bounded batch: N cases, a start, a completion, a pass rate that means
-- something. An online eval is a CONTINUOUS STREAM keyed by trace, with no
-- batch, no completion and no denominator. Forcing it into a run means either
-- synthesising a run per score (a run of one, forever) or a rolling run whose
-- `status` never settles. Both make `eval_runs` mean two things.
--
-- So: its own table, keyed by what it actually scores.
--
-- ReplacingMergeTree, and the argument is migration 18's verbatim: at-least-once
-- is the safe direction everywhere in this tree, a retried insert must not
-- double-count, and (tenant, trace, policy) is already a natural dedup key —
-- one policy scores one trace exactly once.
--
-- SCORE IS NULLABLE AND NULL MEANS UNKNOWN, NEVER ZERO. A judge whose response
-- fails validation produces `status = 'errored'` with no score at all. Rendering
-- an unvalidated number, or a 0.0 standing in for "we could not tell", is the
-- §21 failure this feature is downstream of — `Assertion::JsonValid` was deleted
-- for exactly that.
--
-- `cost_usd` is Nullable for the same reason: NULL = unpriced model, never 0.
-- The monthly SUM of this column is what re-seeds the judge sub-limit counter
-- after a redeploy, so a 0 standing in for "unknown" would forgive real money.

CREATE TABLE IF NOT EXISTS online_eval_scores (
    tenant_id     String,                    -- validated claim ONLY, never a body
    trace_id      String,                    -- the live trace this scored
    span_id       String,                    -- the chat span within it
    policy_id     UUID,                      -- online_eval_policies.id
    rubric        LowCardinality(String),    -- built-in name, or the version id
    judge_model   LowCardinality(String),
    status        LowCardinality(String),    -- scored | errored
    score         Nullable(Float64),         -- NULL = UNKNOWN. Never 0 for unknown
    verdict       LowCardinality(String),    -- the judge's own label; '' when errored
    reason        String,                    -- the judge's justification, capped
    error         Nullable(String),          -- present iff status = 'errored'
    cost_usd      Nullable(Float64),         -- NULL = unpriced model. NEVER 0
    latency_ms    UInt32,
    scored_at     DateTime64(3, 'UTC')       -- MILLIS via datetime64_millis_now()
)
ENGINE = ReplacingMergeTree
ORDER BY (tenant_id, trace_id, policy_id)
PARTITION BY toYYYYMM(scored_at);
