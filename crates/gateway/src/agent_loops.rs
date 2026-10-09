//! Read-time loop evidence, computed from tenant-bound stored calls.
use crate::billing::rating::AgentLoopPolicy;
use serde::{Deserialize, Serialize};

// timestamp µs, span id, trace id, priced flag, cost USD, output tokens.
type Call = (i64, String, String, u8, f64, u64, u32);
#[derive(Debug, Clone, Deserialize, clickhouse::Row)]
pub(crate) struct LoopRow {
    pub group_kind: String,
    pub group_id: String,
    pub tool: String,
    pub first_call_index: u32,
    pub calls: u64,
    pub first_us: i64,
    pub last_us: i64,
    pub repeat_cost_usd: Option<f64>,
    pub repeat_unpriced: u64,
    pub repeat_output_tokens: u64,
    pub records: Vec<Call>,
}
#[derive(Debug, Clone, Serialize)]
pub(crate) struct LoopInstance {
    pub group_kind: String,
    pub group_id: String,
    pub tool: String,
    pub instance_id: String,
    /// 0 = OTLP tool span; otherwise 1-based response-tool position.
    pub first_call_index: u32,
    pub calls: u64,
    pub first_at: String,
    pub last_at: String,
    pub trace_ids: Vec<String>,
    pub span_ids: Vec<String>,
    pub repeat_cost_usd: Option<f64>,
    pub repeat_unpriced: u64,
    pub repeat_output_tokens: u64,
}
#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct LoopTotals {
    pub min_repeats: u32,
    pub window_secs: u32,
    pub instances: u64,
    pub groups: u64,
    pub unfingerprinted_tool_calls: u64,
    pub tool_calls: u64,
}
#[derive(Debug, Clone, Serialize)]
pub(crate) struct LoopResponse {
    pub min_repeats: u32,
    pub window_secs: u32,
    pub instances: Vec<LoopInstance>,
    pub total_instances: u64,
    pub truncated: bool,
    pub tool_calls: u64,
    pub unfingerprinted_tool_calls: u64,
}

/// Clocks are bound once by the caller; every stored-row read is tenant first.
fn calls_sql() -> String {
    "SELECT if(JSONExtractString(attributes, 'gen_ai_conversation_id') != '', 'session', 'trace') AS group_kind, \
if(JSONExtractString(attributes, 'gen_ai_conversation_id') != '', JSONExtractString(attributes, 'gen_ai_conversation_id'), trace_id) AS group_id, \
call.1 AS tool, call.2 AS arg_fp, toUnixTimestamp64Micro(start_time) AS t, \
span_id, trace_id, toUInt8(cost_usd_present = 1 AND isFinite(cost_usd)) AS priced, \
if(priced, cost_usd, 0.) AS cost, JSONExtractUInt(attributes, 'gen_ai_usage_output_tokens') AS output_tokens, call.3 AS call_index \
FROM tracelane.spans FINAL \
ARRAY JOIN arrayConcat( \
arrayZip(JSONExtract(attributes, 'tracelane_response_tool_names', 'Array(String)'), \
arrayResize(JSONExtract(attributes, 'tracelane_response_tool_arg_fps', 'Array(String)'), length(JSONExtract(attributes, 'tracelane_response_tool_names', 'Array(String)')), ''), arrayEnumerate(JSONExtract(attributes, 'tracelane_response_tool_names', 'Array(String)'))), \
if(JSONExtractString(attributes, 'gen_ai.tool.name') != '', [(JSONExtractString(attributes, 'gen_ai.tool.name'), JSONExtractString(attributes, 'gen_ai_tool_call_arg_fp'), toUInt32(0))], [])) AS call \
WHERE tenant_id = ? AND start_time >= w_since AND start_time <= w_until".to_owned()
}

#[derive(Debug, Clone, Default)]
pub(crate) struct LoopScope {
    pub trace_ids: Vec<String>,
    pub session_ids: Vec<String>,
}
impl LoopScope {
    fn calls_sql(&self) -> String {
        let mut sql = calls_sql();
        if !self.trace_ids.is_empty() {
            sql.push_str(" AND (trace_id IN ? OR (JSONExtractString(attributes, 'gen_ai_conversation_id') != '' AND JSONExtractString(attributes, 'gen_ai_conversation_id') IN (SELECT JSONExtractString(attributes, 'gen_ai_conversation_id') FROM tracelane.spans FINAL WHERE tenant_id = ? AND start_time >= w_since AND start_time <= w_until AND trace_id IN ?)))");
        } else if !self.session_ids.is_empty() {
            sql.push_str(" AND JSONExtractString(attributes, 'gen_ai_conversation_id') IN ?");
        }
        sql
    }
    pub fn bind(
        &self,
        mut query: clickhouse::query::Query,
        tenant: &tracelane_shared::TenantId,
    ) -> clickhouse::query::Query {
        if !self.trace_ids.is_empty() {
            query = query
                .bind(&self.trace_ids)
                .bind(tenant.to_string())
                .bind(&self.trace_ids);
        } else if !self.session_ids.is_empty() {
            query = query.bind(&self.session_ids);
        }
        query
    }
}

/// Uncapped intermediate used only INSIDE ClickHouse (filters and rollups).
pub(crate) fn grouped_sql(policy: AgentLoopPolicy, scope: &LoopScope) -> String {
    grouped_from(policy, &scope.calls_sql())
}
fn grouped_from(policy: AgentLoopPolicy, source: &str) -> String {
    let n = policy.min_repeats;
    let offset = n.saturating_sub(1);
    let window = u64::from(policy.window_secs) * 1_000_000;
    format!(
        "SELECT group_kind, group_id, tool, arg_fp, \
arraySort(groupArray((t, span_id, trace_id, priced, cost, output_tokens, call_index))) AS records \
FROM ({source}) WHERE arg_fp != '' \
GROUP BY group_kind, group_id, tool, arg_fp \
HAVING length(records) >= {n} AND arrayExists((a, b) -> b.1 - a.1 <= {window}, \
arraySlice(records, 1, greatest(length(records), {offset}) - {offset}), arraySlice(records, {n}))"
    )
}

/// Apply the requested trace/session scope BEFORE counts and LIMIT. Session
/// expansion supplies the whole loop but must not include unrelated instances.
fn instance_scope(scope: &LoopScope) -> &'static str {
    match (scope.trace_ids.is_empty(), scope.session_ids.is_empty()) {
        (false, false) => {
            " WHERE arrayExists(r -> has(?, r.3), records) AND group_kind = 'session' AND group_id IN ?"
        }
        (false, true) => " WHERE arrayExists(r -> has(?, r.3), records)",
        (true, false) => " WHERE group_kind = 'session' AND group_id IN ?",
        (true, true) => "",
    }
}
impl LoopScope {
    pub fn bind_instances(&self, mut query: clickhouse::query::Query) -> clickhouse::query::Query {
        if !self.trace_ids.is_empty() {
            query = query.bind(&self.trace_ids);
        }
        if !self.session_ids.is_empty() {
            query = query.bind(&self.session_ids);
        }
        query
    }
}

#[cfg(test)]
pub(crate) fn instances_sql(policy: AgentLoopPolicy) -> String {
    scoped_instances_sql(policy, &LoopScope::default())
}
pub(crate) fn scoped_instances_sql(policy: AgentLoopPolicy, scope: &LoopScope) -> String {
    // Spend is deduped by span AFTER excluding the first call. All aggregates
    // cover the full group; only the wire evidence array is sliced.
    format!(
        "SELECT group_kind, group_id, tool, records[1].7 AS first_call_index, toUInt64(length(records)) AS calls, \
records[1].1 AS first_us, records[-1].1 AS last_us, \
if(arrayCount(r -> r.2 != 0, repeats) > 0, arraySum(arrayMap(r -> r.3, repeats)), NULL) AS repeat_cost_usd, \
toUInt64(arrayCount(r -> r.2 = 0, repeats)) AS repeat_unpriced, \
toUInt64(arraySum(arrayMap(r -> r.4, repeats))) AS repeat_output_tokens, \
arraySlice(records, 1, {}) AS bounded_records \
FROM (SELECT *, arrayDistinct(arrayMap(r -> (r.2, r.4, r.5, r.6), arraySlice(records, 2))) AS repeats FROM ({})){} \
ORDER BY calls DESC, group_kind, group_id, tool, arg_fp LIMIT {}",
        policy.max_span_ids_per_instance,
        grouped_sql(policy, scope),
        instance_scope(scope),
        policy.max_instances
    )
}

/// Scalar-only result: no call arrays cross the ClickHouse boundary.
pub(crate) fn totals_sql(policy: AgentLoopPolicy, scope: &LoopScope) -> String {
    format!(
        "WITH calls AS ({}), loops AS (SELECT * FROM ({}){}) \
SELECT ifNull((SELECT count() FROM loops), 0) AS total_instances, ifNull((SELECT uniqExact((group_kind, group_id)) FROM loops), 0) AS groups, \
toUInt64(count()) AS tool_calls, toUInt64(countIf(arg_fp = '')) AS unfingerprinted FROM calls",
        scope.calls_sql(),
        grouped_from(policy, "SELECT * FROM calls"),
        instance_scope(scope)
    )
}

/// Only one scalar per requested page id; full records stay inside ClickHouse.
pub(crate) fn rollup_sql(policy: AgentLoopPolicy, scope: &LoopScope) -> String {
    if !scope.trace_ids.is_empty() {
        format!(
            "SELECT id, max(calls) FROM (SELECT arrayJoin(arrayFilter(id -> has(?, id), arrayDistinct(arrayMap(r -> r.3, records)))) AS id, toUInt64(length(records)) AS calls FROM ({})) GROUP BY id LIMIT {}",
            grouped_sql(policy, scope),
            scope.trace_ids.len()
        )
    } else {
        format!(
            "SELECT group_id, max(toUInt64(length(records))) FROM ({}) WHERE group_kind = 'session' AND group_id IN ? GROUP BY group_id LIMIT {}",
            grouped_sql(policy, scope),
            scope.session_ids.len()
        )
    }
}
#[derive(Debug, Clone)]
pub(crate) struct LoopData {
    pub policy: AgentLoopPolicy,
    pub rows: Vec<LoopRow>,
    pub total_instances: u64,
    pub groups: u64,
    pub tool_calls: u64,
    pub unfingerprinted: u64,
}
impl LoopData {
    pub fn totals(&self) -> LoopTotals {
        LoopTotals {
            min_repeats: self.policy.min_repeats,
            window_secs: self.policy.window_secs,
            instances: self.total_instances,
            groups: self.groups,
            unfingerprinted_tool_calls: self.unfingerprinted,
            tool_calls: self.tool_calls,
        }
    }
    pub fn response(&self, limit: Option<u32>) -> LoopResponse {
        let totals = self.totals();
        let limit = limit
            .unwrap_or(self.policy.max_instances)
            .clamp(1, self.policy.max_instances) as usize;
        LoopResponse {
            min_repeats: self.policy.min_repeats,
            window_secs: self.policy.window_secs,
            instances: self
                .rows
                .iter()
                .take(limit)
                .map(LoopRow::instance)
                .collect(),
            total_instances: totals.instances,
            truncated: self.total_instances > limit as u64,
            tool_calls: self.tool_calls,
            unfingerprinted_tool_calls: self.unfingerprinted,
        }
    }
}
impl LoopRow {
    fn instance(&self) -> LoopInstance {
        let timestamp = |us| {
            chrono::DateTime::from_timestamp_micros(us)
                .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
                .unwrap_or_default()
        };
        let unique = |index: usize| {
            let mut seen = std::collections::HashSet::new();
            self.records
                .iter()
                .map(|r| if index == 1 { &r.1 } else { &r.2 })
                .filter(|id| seen.insert(*id))
                .cloned()
                .collect()
        };
        LoopInstance {
            group_kind: self.group_kind.clone(),
            group_id: self.group_id.clone(),
            tool: self.tool.clone(),
            instance_id: uuid::Uuid::new_v4().to_string(),
            first_call_index: self.first_call_index,
            calls: self.calls,
            first_at: timestamp(self.first_us),
            last_at: timestamp(self.last_us),
            trace_ids: unique(2),
            span_ids: unique(1),
            repeat_cost_usd: self.repeat_cost_usd.filter(|n| n.is_finite()),
            repeat_unpriced: self.repeat_unpriced,
            repeat_output_tokens: self.repeat_output_tokens,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cf_m1_loop_instances_have_per_response_ids_and_no_fingerprint() {
        let row = LoopRow {
            group_kind: "trace".into(),
            group_id: "trace".into(),
            tool: "search".into(),
            first_call_index: 2,
            calls: 3,
            first_us: 0,
            last_us: 2,
            repeat_cost_usd: None,
            repeat_unpriced: 2,
            repeat_output_tokens: 0,
            records: vec![(0, "span".into(), "trace".into(), 0, 0., 0, 2)],
        };
        let a = serde_json::to_value(row.instance()).unwrap();
        let b = serde_json::to_value(row.instance()).unwrap();
        assert!(a.get("arg_fp").is_none());
        assert_ne!(a["instance_id"], b["instance_id"]);
        assert_eq!(a["first_call_index"], 2);
        let sql = instances_sql(AgentLoopPolicy::embedded().unwrap());
        assert!(
            sql.starts_with("SELECT group_kind, group_id, tool, records[1].7 AS first_call_index")
        );
    }

    #[test]
    fn cf_h1_instance_reads_are_bounded_in_sql() {
        let policy = AgentLoopPolicy::embedded().unwrap();
        let sql = instances_sql(policy);
        assert!(
            sql.contains(&format!(
                "arraySlice(records, 1, {})",
                policy.max_span_ids_per_instance
            )),
            "record arrays must be capped before leaving ClickHouse"
        );
        assert!(
            sql.ends_with(&format!("LIMIT {}", policy.max_instances)),
            "instance rows must be capped before leaving ClickHouse"
        );
    }

    #[test]
    fn loop_totals_expose_policy_for_metric_definition() {
        let policy = AgentLoopPolicy::embedded().unwrap();
        let data = LoopData {
            policy,
            rows: vec![],
            total_instances: 0,
            groups: 0,
            tool_calls: 0,
            unfingerprinted: 0,
        };
        let value = serde_json::to_value(data.totals()).unwrap();
        assert_eq!(value["min_repeats"], policy.min_repeats);
        assert_eq!(value["window_secs"], policy.window_secs);
        let response = serde_json::to_value(data.response(None)).unwrap();
        assert_eq!(response["tool_calls"], 0);
    }
    #[test]
    fn cf_h1_totals_and_rollups_do_not_return_record_arrays() {
        let policy = AgentLoopPolicy::embedded().unwrap();
        let scope = LoopScope {
            trace_ids: vec!["last-trace".into()],
            session_ids: vec![],
        };
        let sql = totals_sql(policy, &scope);
        assert!(sql.contains("SELECT count() FROM loops"));
        assert!(
            !sql.contains("LIMIT"),
            "totals must include instances beyond the response cap"
        );
        let rollup = rollup_sql(policy, &scope);
        assert!(rollup.starts_with("SELECT id, max(calls)"));
        assert!(rollup.ends_with("LIMIT 1"));
        assert!(rollup.contains("WHERE tenant_id = ?"));
    }

    #[test]
    fn page_scopes_bind_tenant_again_before_session_expansion() {
        let scope = LoopScope {
            trace_ids: vec!["trace-a".into()],
            session_ids: vec![],
        };
        let sql = scoped_instances_sql(AgentLoopPolicy::embedded().unwrap(), &scope);
        assert_eq!(
            sql.matches("WHERE tenant_id = ? AND start_time >= w_since")
                .count(),
            2
        );
        assert!(
            !sql.contains("trace-a"),
            "ids must be bound, never interpolated"
        );
        assert!(
            totals_sql(AgentLoopPolicy::embedded().unwrap(), &scope)
                .contains("countIf(arg_fp = '')")
        );
    }

    /// Runs actual SQL in a disposable offline engine; never touches a database.
    #[test]
    #[ignore = "requires the already-installed ClickHouse 24.12 Docker image"]
    fn cf_h1_million_calls_return_only_policy_caps() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let mut policy = AgentLoopPolicy::embedded().unwrap();
        policy.max_instances = 2;
        policy.max_span_ids_per_instance = 3;
        let source = r#"(SELECT if(number = 1000010, 'other', 'tenant') AS tenant_id, fromUnixTimestamp64Micro(toInt64(number)) AS start_time, toString(number) AS span_id, toString(number) AS trace_id, toUInt8(1) AS cost_usd_present, toFloat64(1) AS cost_usd, concat('{"gen_ai_conversation_id":"', if(number < 1000000, 'huge', toString(intDiv(number - 1000000, 3))), '","tracelane_response_tool_names":["search"],"tracelane_response_tool_arg_fps":["fp"],"gen_ai_usage_output_tokens":2}') AS attributes FROM numbers(1000011))"#;
        let execute = |sql: String| {
            let sql = sql
                .replace("tracelane.spans FINAL", source)
                .replace('?', "'tenant'");
            let sql = format!(
                "WITH fromUnixTimestamp64Micro(toInt64(-1)) AS w_since, fromUnixTimestamp64Micro(toInt64(2000000)) AS w_until SELECT * FROM ({sql}) FORMAT JSON"
            );
            let mut child = Command::new("docker")
                .args([
                    "run",
                    "--rm",
                    "--pull=never",
                    "--network",
                    "none",
                    "--entrypoint",
                    "clickhouse-local",
                    "-i",
                    "clickhouse/clickhouse-server:24.12-alpine",
                    "--multiquery",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(sql.as_bytes())
                .unwrap();
            let result = child.wait_with_output().unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            serde_json::from_slice::<serde_json::Value>(&result.stdout).unwrap()["data"]
                .as_array()
                .unwrap()
                .clone()
        };
        let rows = execute(instances_sql(policy));
        assert_eq!(rows.len(), policy.max_instances as usize);
        assert!(
            rows.iter()
                .all(|r| r["bounded_records"].as_array().unwrap().len()
                    <= policy.max_span_ids_per_instance as usize)
        );
        assert_eq!(rows[0]["calls"], "1000000");
        assert_eq!(rows[0]["repeat_cost_usd"], 999999.);
        assert_eq!(rows[0]["repeat_output_tokens"], "1999998");
        assert_eq!(rows[0]["last_us"], "999999");
        let totals = execute(totals_sql(policy, &LoopScope::default()));
        assert_eq!(totals[0]["total_instances"], "4");
        // A trace outside the first three records still receives the full count.
        let scope = LoopScope {
            trace_ids: vec!["999999".into()],
            session_ids: vec![],
        };
        let rollup = rollup_sql(policy, &scope)
            .replacen('?', "['999999']", 1)
            .replacen('?', "'tenant'", 1)
            .replacen('?', "['999999']", 1)
            .replacen('?', "'tenant'", 1)
            .replacen('?', "['999999']", 1);
        let rollup = execute(rollup);
        assert_eq!(rollup.len(), 1);
        assert_eq!(rollup[0]["max(calls)"], "1000000");
    }

    #[tokio::test]
    #[ignore = "requires CLICKHOUSE_TEST_URL; read-only synthetic ClickHouse fixtures"]
    async fn clickhouse_loops_require_same_arguments_window_and_tenant() {
        let client =
            clickhouse::Client::default().with_url(std::env::var("CLICKHOUSE_TEST_URL").unwrap());
        let policy = AgentLoopPolicy::embedded().unwrap();
        let source = "(SELECT x.1 AS tenant_id, fromUnixTimestamp64Micro(x.2) AS start_time, x.3 AS span_id, x.4 AS trace_id, toUInt8(1) AS cost_usd_present, toFloat64(1) AS cost_usd, if(x.5 = '{}', '{\"gen_ai_conversation_id\":\"session\"}', concat('{\"gen_ai_conversation_id\":\"session\",', substring(x.5, 2))) AS attributes FROM (SELECT arrayJoin(?) AS x))";
        let sql = format!(
            "WITH fromUnixTimestamp64Micro(?) AS w_since, fromUnixTimestamp64Micro(?) AS w_until {}",
            instances_sql(policy).replace("tracelane.spans FINAL", source)
        );
        let sql =
            crate::clickhouse_query::TenantQuery::new(sql, crate::clickhouse_query::PlanTier::Free)
                .sql_with_settings();
        let attrs = |fp: &str| {
            serde_json::json!({"tracelane_response_tool_names":["search"], "tracelane_response_tool_arg_fps":[fp]}).to_string()
        };
        for (tenants, fps, times, expected) in [
            (
                vec!["a", "a", "a"],
                vec!["x", "x", "x"],
                vec![0, 60, 120],
                1,
            ),
            (
                vec!["a", "a", "a"],
                vec!["x", "y", "z"],
                vec![0, 60, 120],
                0,
            ),
            (
                vec!["a", "a", "a"],
                vec!["x", "x", "x"],
                vec![0, 301, 602],
                0,
            ),
            (vec!["a", "a"], vec!["x", "x"], vec![0, 60], 0),
            (
                vec!["a", "a", "b"],
                vec!["x", "x", "x"],
                vec![0, 60, 120],
                0,
            ),
        ] {
            let records: Vec<_> = tenants
                .into_iter()
                .zip(fps)
                .zip(times)
                .enumerate()
                .map(|(i, ((t, fp), time))| {
                    (
                        t,
                        i64::from(time) * 1_000_000,
                        format!("s{i}"),
                        format!("t{i}"),
                        attrs(fp),
                    )
                })
                .collect();
            let rows = client
                .query(&sql)
                .bind(-1i64)
                .bind(1_000_000_000i64)
                .bind(records)
                .bind("a")
                .fetch_all::<LoopRow>()
                .await
                .unwrap();
            assert_eq!(rows.len(), expected);
        }
    }

    #[test]
    fn loop_sql_is_tenant_first_and_requires_identical_arguments_in_window() {
        let policy = AgentLoopPolicy::embedded().unwrap();
        let sql = instances_sql(policy);
        assert!(
            sql.contains("WHERE tenant_id = ? AND start_time >= w_since AND start_time <= w_until"),
            "loop calls must be tenant-first and window-bound"
        );
        assert!(sql.contains("arg_fp != ''"));
        assert!(sql.contains("GROUP BY group_kind, group_id, tool, arg_fp"));
        assert!(sql.contains("arraySort(groupArray"));
        assert!(sql.contains("arrayExists"));
        assert!(sql.contains(&(u64::from(policy.window_secs) * 1_000_000).to_string()));
    }
}
