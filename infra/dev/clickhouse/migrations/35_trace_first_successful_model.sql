-- 35 — rank the first successful LLM model on each trace (CAP-6, 2026-10-05).
-- Hand-apply only after pausing writes to tracelane.spans; resume after the
-- backfill and readback. This file is WRITTEN, NEVER APPLIED by Codex.
-- The rank is a mergeable min(String): 0:<20-digit start micros>:<model> beats
-- the sentinel 2: from a batch with no successful LLM model. Existing rows
-- read as 2: until the zero-count backfill below supplies their real rank.

ALTER TABLE tracelane.trace_summaries
    ADD COLUMN IF NOT EXISTS model_rank SimpleAggregateFunction(min, String) DEFAULT '2:' AFTER model;

-- Recreate the insert-triggering view while writes are paused.
DROP TABLE IF EXISTS tracelane.mv_trace_summaries;

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
    )                                                        AS model,
    -- A success ranks before every error, then by span start time. Batches with no
    -- successful model contribute '2:' so they cannot hide a later success.
    min(if(
        s.status_code != 2 AND coalesce(
            nullIf(JSONExtractString(s.attributes, 'gen_ai_response_model'), ''),
            nullIf(JSONExtractString(s.attributes, 'gen_ai_request_model'), ''),
            nullIf(JSONExtractString(s.attributes, 'gen_ai.response.model'), ''),
            nullIf(JSONExtractString(s.attributes, 'gen_ai.request.model'), ''),
            JSONExtractString(s.attributes, 'llm.model_name')
        ) != '',
        concat(
            '0:', leftPad(toString(toUnixTimestamp64Micro(s.start_time)), 20, '0'), ':',
            coalesce(
                nullIf(JSONExtractString(s.attributes, 'gen_ai_response_model'), ''),
                nullIf(JSONExtractString(s.attributes, 'gen_ai_request_model'), ''),
                nullIf(JSONExtractString(s.attributes, 'gen_ai.response.model'), ''),
                nullIf(JSONExtractString(s.attributes, 'gen_ai.request.model'), ''),
                JSONExtractString(s.attributes, 'llm.model_name')
            )
        ),
        '2:'
    ))                                                       AS model_rank
FROM tracelane.spans AS s
GROUP BY s.tenant_id, s.trace_id;

-- 4. Backfill only the new rank into existing trace summaries. The other aggregate
-- values are identities, so this insert cannot double span or error counts.
-- The source is restricted to traces already present in the summary table.
INSERT INTO tracelane.trace_summaries
    (tenant_id, trace_id, root_name, start_time, end_time, span_count,
     error_count, intervention, model, model_rank)
SELECT
    s.tenant_id, s.trace_id,
    '' AS root_name,
    min(s.start_time) AS start_time,
    fromUnixTimestamp64Micro(0) AS end_time,
    toUInt64(0) AS span_count,
    toUInt64(0) AS error_count,
    toUInt8(0) AS intervention,
    '' AS model,
    min(if(
        s.status_code != 2 AND coalesce(
            nullIf(JSONExtractString(s.attributes, 'gen_ai_response_model'), ''),
            nullIf(JSONExtractString(s.attributes, 'gen_ai_request_model'), ''),
            nullIf(JSONExtractString(s.attributes, 'gen_ai.response.model'), ''),
            nullIf(JSONExtractString(s.attributes, 'gen_ai.request.model'), ''),
            JSONExtractString(s.attributes, 'llm.model_name')
        ) != '',
        concat(
            '0:', leftPad(toString(toUnixTimestamp64Micro(s.start_time)), 20, '0'), ':',
            coalesce(
                nullIf(JSONExtractString(s.attributes, 'gen_ai_response_model'), ''),
                nullIf(JSONExtractString(s.attributes, 'gen_ai_request_model'), ''),
                nullIf(JSONExtractString(s.attributes, 'gen_ai.response.model'), ''),
                nullIf(JSONExtractString(s.attributes, 'gen_ai.request.model'), ''),
                JSONExtractString(s.attributes, 'llm.model_name')
            )
        ),
        '2:'
    )) AS model_rank
FROM tracelane.spans AS s
WHERE (s.tenant_id, s.trace_id) IN
    (SELECT tenant_id, trace_id FROM tracelane.trace_summaries)
GROUP BY s.tenant_id, s.trace_id;
