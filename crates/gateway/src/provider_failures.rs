//! Counts of recorded failed dispatch attempts, never an all-call failure rate.
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Deserialize, Serialize, clickhouse::Row)]
pub(crate) struct FailureRow {
    pub overall: u64,
    pub provider: String,
    pub failed: u64,
    pub rate_limited: u64,
    pub server_error: u64,
    pub other: u64,
    pub unknown: u64,
    pub captured_spans: u64,
    pub recorded_spans: u64,
    pub capped_spans: u64,
    pub provider_count: u64,
}

// Positional RowBinary order matches FailureRow. LEFT ARRAY JOIN keeps spans
// without a ledger in capture coverage, without inventing a failed attempt.
pub(crate) fn summary_sql() -> String {
    format!(
        "SELECT toUInt64(grouping(provider)) AS overall, provider, \
         toUInt64(countIf(is_failure)) AS failed, \
         toUInt64(countIf(is_failure AND code = 429)) AS rate_limited, \
         toUInt64(countIf(is_failure AND code BETWEEN 500 AND 599)) AS server_error, \
         toUInt64(countIf(is_failure AND code BETWEEN 300 AND 499 AND code != 429)) AS other, \
         failed - rate_limited - server_error - other AS unknown, \
         toUInt64(uniqExact(span_key)) AS captured_spans, \
         toUInt64(uniqExactIf(span_key, ledger_size > 0)) AS recorded_spans, \
         toUInt64(uniqExactIf(span_key, ledger_size >= {cap})) AS capped_spans, \
         toUInt64(uniqExactIf(provider, is_failure)) AS provider_count \
         FROM (SELECT (trace_id, span_id) AS span_key, length(ledger) AS ledger_size, \
         JSONExtractString(attempt, 'provider') AS provider, \
         JSONExtractString(attempt, 'outcome') = 'error' AS is_failure, \
         if(NOT startsWith(JSONExtractString(attempt, 'reason'), 'upstream_timeout:') \
         AND match(JSONExtractRaw(attempt, 'status'), '^[0-9]{{3}}$'), \
            toUInt16OrZero(JSONExtractRaw(attempt, 'status')), 0) AS code \
         FROM (SELECT trace_id, span_id, \
         JSONExtractArrayRaw(attributes, 'tracelane_dispatch_attempts') AS ledger \
         FROM tracelane.spans FINAL WHERE tenant_id = ? \
         AND start_time >= w_since AND start_time <= w_until \
         AND JSONExtractString(attributes, 'gen_ai_provider_name') != '') \
         LEFT ARRAY JOIN ledger AS attempt) \
         GROUP BY GROUPING SETS ((), (provider)) \
         HAVING overall = 1 OR failed > 0 \
         ORDER BY overall DESC, failed DESC, provider ASC LIMIT ?",
        cap = tracelane_shared::span::MAX_DISPATCH_ATTEMPTS,
    )
}
