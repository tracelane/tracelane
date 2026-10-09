//! Dispatch-ledger rescue semantics; skipped routing hops never count as failures.
use serde::Deserialize;
#[derive(Debug, Default, Clone, Deserialize, clickhouse::Row)]
pub(crate) struct RescueRow {
    pub overall: u64,
    pub provider: String,
    pub failed: u64,
    pub failover: u64,
    pub retry: u64,
    pub added_ms_p50: Option<f64>,
}
#[derive(Debug, Clone, Deserialize, clickhouse::Row)]
pub(crate) struct TraceRescueRow {
    pub trace_id: String,
    pub rescued: String,
}
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RescueFilter {
    Any,
    Failover,
    Retry,
}
impl RescueFilter {
    pub fn predicate(self) -> String {
        match self {
            Self::Any => "rescue_kind != ''",
            Self::Failover => "rescue_kind = 'failover'",
            Self::Retry => "rescue_kind = 'retry'",
        }
        .to_owned()
    }
}
pub(crate) fn evidence_sql() -> String {
    evidence_with("")
}
fn evidence_with(extra: &str) -> String {
    format!(
        "SELECT trace_id, JSONExtractString(attributes, 'gen_ai_provider_name') AS provider, \
notEmpty(failures) AS had_failure, \
if(had_failure AND JSONExtractString(arrayElement(active, -1), 'outcome') = 'ok', \
if(JSONExtractString(arrayElement(active, -1), 'provider') != JSONExtractString(arrayElement(failures, 1), 'provider'), 'failover', 'retry'), '') AS rescue_kind, \
arraySum(arrayMap(a -> JSONExtractFloat(a, 'took_ms'), failures)) AS added_ms \
FROM (SELECT trace_id, attributes, \
arrayFilter(a -> JSONExtractString(a, 'outcome') = 'error', JSONExtractArrayRaw(attributes, 'tracelane_dispatch_attempts')) AS failures, \
arrayFilter(a -> JSONExtractString(a, 'outcome') != 'skipped', JSONExtractArrayRaw(attributes, 'tracelane_dispatch_attempts')) AS active \
FROM tracelane.spans FINAL WHERE tenant_id = ? AND start_time >= w_since AND start_time <= w_until \
AND JSONExtractString(attributes, 'gen_ai_provider_name') != ''{extra})"
    )
}
pub(crate) fn summary_sql() -> String {
    format!(
        "SELECT toUInt64(grouping(provider)) AS overall, provider, \
toUInt64(countIf(had_failure)) AS failed, toUInt64(countIf(rescue_kind = 'failover')) AS failover, \
toUInt64(countIf(rescue_kind = 'retry')) AS retry, \
if(countIf(rescue_kind != '') = 0, CAST(NULL, 'Nullable(Float64)'), quantileExactIf(0.5)(added_ms, rescue_kind != '')) AS added_ms_p50 \
FROM ({}) GROUP BY GROUPING SETS ((), (provider))",
        evidence_sql()
    )
}
pub(crate) fn trace_sql() -> String {
    format!(
        "SELECT trace_id, if(countIf(rescue_kind = 'failover') > 0, 'failover', if(countIf(rescue_kind = 'retry') > 0, 'retry', '')) AS rescued \
FROM ({}) GROUP BY trace_id",
        evidence_with(" AND trace_id IN ?")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rescue_requires_failed_attempt_and_final_non_skipped_success() {
        let sql = evidence_sql();
        assert!(
            sql.contains("'error'"),
            "rescue must have an actual failed attempt"
        );
        assert!(sql.contains("'skipped'"));
        assert!(sql.contains("'ok'"));
        assert!(
            !sql.contains("status_code"),
            "a later guardrail block does not undo a dispatch rescue"
        );
        assert!(
            !sql.contains("tracelane_failover_activated"),
            "ZDR pruning must not be counted as a rescue"
        );
        assert!(
            sql.contains("WHERE tenant_id = ? AND start_time >= w_since AND start_time <= w_until")
        );
    }
}
