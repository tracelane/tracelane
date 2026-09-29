//! Tenant-scoped agent and model activity. Display identity conveys no authority.

use crate::clickhouse_query::{PlanTier, TenantQuery};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracelane_shared::TenantId;

#[derive(Clone)]
pub struct KyaState {
    pub ch: clickhouse::Client,
    pub entitlements: Option<Arc<crate::entitlement_cache::EntitlementCache>>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Kind {
    Agent,
    Model,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
pub(crate) enum Window {
    #[default]
    #[serde(rename = "7d")]
    Seven,
    #[serde(rename = "30d")]
    Thirty,
}
impl Window {
    fn days(self) -> u32 {
        match self {
            Self::Seven => 7,
            Self::Thirty => 30,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    kind: Kind,
    #[serde(default)]
    window: Window,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileQuery {
    #[serde(default)]
    window: Window,
}

pub fn routes() -> Router<KyaState> {
    Router::new()
        .route("/v1/kya/identities", get(list))
        .route("/v1/kya/identities/{kind}/{key}", get(profile))
}

// Shared with the trace-list filter: a profile link must select the same population.
// Empty keys remain distinct from every named identity, including our URL sentinel.
pub(crate) fn agent_key_sql() -> String {
    let cap = crate::kya_identity::limits().map_or(0, |l| l.agent_name_chars);
    format!(
        "substringUTF8(lowerUTF8(trimBoth(coalesce(nullIf(trimBoth(JSONExtractString(attributes, 'gen_ai_agent_name')), ''), JSONExtractString(attributes, 'tracelane_client_name')))), 1, {cap})"
    )
}
pub(crate) const MODEL_KEY_SQL: &str = r"replaceRegexpOne(replaceRegexpOne(lowerUTF8(trimBoth(coalesce(nullIf(trimBoth(JSONExtractString(attributes, 'gen_ai_response_model')), ''), JSONExtractString(attributes, 'gen_ai_request_model')))), '^([^/]+/)+', ''), '-[0-9]{8}$', '')";
pub(crate) const CALL_SQL: &str =
    "JSONExtractString(attributes, 'gen_ai_operation_name') IN ('chat', 'embeddings', 'messages')";

pub(crate) fn decode_key(kind: Kind, key: &str) -> String {
    if key
        == match kind {
            Kind::Agent => "~direct",
            Kind::Model => "~unidentified",
        }
    {
        String::new()
    } else if key.starts_with("~~") || key == "~." || key == "~.." {
        key[1..].to_lowercase()
    } else {
        // The stored key is lowercased (`agent_key_sql`, `MODEL_KEY_SQL`), so a
        // bound value must be too, or `?agent=Codex` silently matches nothing.
        key.to_lowercase()
    }
}
fn encode_key(kind: Kind, key: &str) -> String {
    if key.is_empty() {
        match kind {
            Kind::Agent => "~direct",
            Kind::Model => "~unidentified",
        }
        .into()
    } else if key.starts_with('~') || key == "." || key == ".." {
        format!("~{key}")
    } else {
        key.to_owned()
    }
}

/// One tenant-first grouped read, including an all-identity totals row BEFORE LIMIT.
/// Dates/prefixes normalize generically; labels, makers and artwork are web catalog data.
fn build_sql(kind: Kind, detail: bool) -> String {
    let agent = agent_key_sql();
    let (key, cross) = match kind {
        Kind::Agent => (agent.as_str(), MODEL_KEY_SQL),
        Kind::Model => (MODEL_KEY_SQL, agent.as_str()),
    };
    let limits = crate::kya_identity::limits();
    let cap = limits.map_or(0, |l| l.identities);
    let cross_cap = limits.map_or(0, |l| l.cross_list);
    let recent_cap = limits.map_or(0, |l| l.recent_traces);
    let recent_map = if detail {
        "maxMapIf([trace_id], [toUnixTimestamp64Micro(start_time)], active_call)"
    } else {
        "tuple(CAST([], 'Array(String)'), CAST([], 'Array(Int64)'))"
    };
    let selection = if detail { "AND identity_key = ?" } else { "" };
    format!(
        r"WITH fromUnixTimestamp64Micro(?) AS end_at,
        end_at - toIntervalDay(?) AS since_at,
        end_at - toIntervalDay(?) AS retained_at
    SELECT is_total, identity_key, calls, traces, input_tokens, output_tokens,
        input_usage_calls, output_usage_calls, priced_calls, measured_cost, errors,
        latency_us, first_seen_us, last_seen_us, sources, providers,
        arraySlice(arraySort(x -> (-toInt64(x.2), x.1), arrayZip(cross_map.1, cross_map.2)), 1, {cross_cap}) AS cross_list,
        toUInt64(length(cross_map.1)) AS cross_count,
        arraySlice(arraySort(x -> (-toInt64(x.2), x.1), arrayZip(tools_map.1, tools_map.2)), 1, {cross_cap}) AS tools,
        toUInt64(length(tools_map.1)) AS tool_count,
        arraySlice(arraySort(x -> (-x.2, x.1), arrayZip(recent_map.1, recent_map.2)), 1, {recent_cap}) AS recent_traces,
        history_calls, identity_count
    FROM (
        SELECT *, toUInt64(countIf(is_total = 0 AND calls > 0) OVER ()) AS identity_count
        FROM (
            SELECT toUInt8(grouping(identity_key)) AS is_total, identity_key,
                toUInt64(countIf(active_call)) AS calls,
                toUInt64(uniqExactIf(trace_id, active_call)) AS traces,
                toUInt64(sumIf(JSONExtractUInt(attributes, 'gen_ai_usage_input_tokens'), active_call)) AS input_tokens,
                toUInt64(sumIf(JSONExtractUInt(attributes, 'gen_ai_usage_output_tokens'), active_call)) AS output_tokens,
                toUInt64(countIf(active_call AND JSONHas(attributes, 'gen_ai_usage_input_tokens'))) AS input_usage_calls,
                toUInt64(countIf(active_call AND JSONHas(attributes, 'gen_ai_usage_output_tokens'))) AS output_usage_calls,
                toUInt64(countIf(active_call AND cost_usd_present = 1)) AS priced_calls,
                sumIf(cost_usd, active_call AND cost_usd_present = 1) AS measured_cost,
                toUInt64(countIf(active_call AND status_code = 2)) AS errors,
                quantilesIf(0.5, 0.95)(duration_us, active_call) AS latency_us,
                toInt64(minIf(toUnixTimestamp64Micro(start_time), active_call)) AS first_seen_us,
                toInt64(maxIf(toUnixTimestamp64Micro(start_time), active_call)) AS last_seen_us,
                sumMapIf([identity_source], [toUInt64(1)], active_call) AS sources,
                groupUniqArrayIf(provider, active_call AND provider != '') AS providers,
                sumMapIf([cross_key], [toUInt64(1)], active_call) AS cross_map,
                sumMapIf(tool_names, arrayMap(x -> toUInt64(1), tool_names), start_time >= since_at) AS tools_map,
                {recent_map} AS recent_map,
                toUInt64(countIf(is_call)) AS history_calls
            FROM (
                SELECT attributes, trace_id, start_time, status_code, cost_usd, cost_usd_present, duration_us, {key} AS identity_key, {cross} AS cross_key,
                    {CALL_SQL} AS is_call, is_call AND start_time >= since_at AS active_call,
                    multiIf(trimBoth(JSONExtractString(attributes, 'gen_ai_agent_name')) != '',
                        if(JSONExtractString(attributes, 'tracelane_agent_name_source') = 'header', 'header', 'sdk'),
                        trimBoth(JSONExtractString(attributes, 'tracelane_client_name')) != '', 'client', 'direct') AS identity_source,
                    coalesce(nullIf(JSONExtractString(attributes, 'gen_ai_system'), ''), JSONExtractString(attributes, 'gen_ai_provider_name')) AS provider,
                    arrayFilter(x -> x != '', arrayConcat(
                        JSONExtract(attributes, 'tracelane_response_tool_names', 'Array(String)'),
                        if(JSONExtractString(attributes, 'gen_ai.tool.name') = '', [], [JSONExtractString(attributes, 'gen_ai.tool.name')])
                    )) AS tool_names
                FROM tracelane.spans FINAL
                WHERE tenant_id = ? AND start_time >= retained_at AND start_time <= end_at
            ) GROUP BY GROUPING SETS ((identity_key), ())
        )
    ) WHERE is_total = 1 OR (calls > 0 {selection})
    ORDER BY is_total DESC, calls DESC, identity_key ASC LIMIT {limit}",
        limit = if detail { 2 } else { cap + 1 }
    )
}

#[derive(Debug, Deserialize, clickhouse::Row)]
struct ActivityRow {
    is_total: u8,
    identity_key: String,
    calls: u64,
    traces: u64,
    input_tokens: u64,
    output_tokens: u64,
    input_usage_calls: u64,
    output_usage_calls: u64,
    priced_calls: u64,
    measured_cost: f64,
    errors: u64,
    latency_us: Vec<f64>,
    first_seen_us: i64,
    last_seen_us: i64,
    sources: (Vec<String>, Vec<u64>),
    providers: Vec<String>,
    cross_list: Vec<(String, u64)>,
    cross_count: u64,
    tools: Vec<(String, u64)>,
    tool_count: u64,
    recent_traces: Vec<(String, i64)>,
    history_calls: u64,
    identity_count: u64,
}

#[derive(Debug, Serialize)]
struct CountedKey {
    key: String,
    calls: u64,
}
#[derive(Debug, Serialize)]
struct RecentTrace {
    trace_id: String,
    last_seen_us: i64,
}
#[derive(Debug, Serialize)]
struct Activity {
    key: String,
    // secret-field-ok: the identity key before URL-safe encoding (an agent or model name), not a credential
    raw_key: String,
    calls: u64,
    traces: u64,
    tokens_in: Option<u64>,
    tokens_out: Option<u64>,
    input_usage_missing: u64,
    output_usage_missing: u64,
    cost_usd: Option<f64>,
    unpriced_calls: u64,
    errors: u64,
    error_rate: Option<f64>,
    p50_us: Option<f64>,
    p95_us: Option<f64>,
    first_seen_us: i64,
    last_seen_us: i64,
    share_of_workspace: Option<f64>,
    sources: Vec<CountedKey>,
    providers: Vec<String>,
    cross_list: Vec<CountedKey>,
    cross_count: u64,
    tools: Vec<CountedKey>,
    tool_count: u64,
    recent_traces: Vec<RecentTrace>,
}
impl ActivityRow {
    fn into_activity(self, kind: Kind, workspace_calls: u64) -> Activity {
        let other = if kind == Kind::Agent {
            Kind::Model
        } else {
            Kind::Agent
        };
        Activity {
            key: encode_key(kind, &self.identity_key),
            raw_key: self.identity_key,
            calls: self.calls,
            traces: self.traces,
            tokens_in: (self.input_usage_calls > 0).then_some(self.input_tokens),
            tokens_out: (self.output_usage_calls > 0).then_some(self.output_tokens),
            input_usage_missing: self.calls - self.input_usage_calls,
            output_usage_missing: self.calls - self.output_usage_calls,
            cost_usd: (self.priced_calls > 0).then_some(self.measured_cost),
            unpriced_calls: self.calls - self.priced_calls,
            errors: self.errors,
            error_rate: (self.calls > 0).then(|| self.errors as f64 / self.calls as f64),
            p50_us: self.latency_us.first().copied().filter(|v| v.is_finite()),
            p95_us: self.latency_us.get(1).copied().filter(|v| v.is_finite()),
            first_seen_us: self.first_seen_us,
            last_seen_us: self.last_seen_us,
            share_of_workspace: (workspace_calls > 0)
                .then(|| self.calls as f64 / workspace_calls as f64),
            sources: self
                .sources
                .0
                .into_iter()
                .zip(self.sources.1)
                .map(|(key, calls)| CountedKey { key, calls })
                .collect(),
            providers: self.providers,
            cross_list: self
                .cross_list
                .into_iter()
                .map(|(key, calls)| CountedKey {
                    key: encode_key(other, &key),
                    calls,
                })
                .collect(),
            cross_count: self.cross_count,
            tools: self
                .tools
                .into_iter()
                .map(|(key, calls)| CountedKey { key, calls })
                .collect(),
            tool_count: self.tool_count,
            recent_traces: self
                .recent_traces
                .into_iter()
                .map(|(trace_id, last_seen_us)| RecentTrace {
                    trace_id,
                    last_seen_us,
                })
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
struct ActivityResponse {
    kind: Kind,
    requested_days: u32,
    window_days: u32,
    retention_days: u32,
    since_us: i64,
    until_us: i64,
    workspace_calls: u64,
    has_retained_activity: bool,
    total_identities: u64,
    truncated: bool,
    identities: Vec<Activity>,
}

/// # Errors
/// Read failures fail CLOSED as errors, never a fabricated empty list or zero.
#[allow(clippy::too_many_arguments)] // Explicit tenant, entitlement and fixed-clock inputs for the read proof.
async fn read(
    ch: &clickhouse::Client,
    tier: PlanTier,
    tenant: &TenantId,
    kind: Kind,
    window: Window,
    retention: u32,
    key: Option<&str>,
    now_us: i64,
) -> anyhow::Result<ActivityResponse> {
    anyhow::ensure!(retention > 0, "identity retention is unavailable");
    crate::kya_identity::initialize()?;
    let days = window.days().min(retention);
    let sql = TenantQuery::new(build_sql(kind, key.is_some()), tier)
        .with_log_comment(format!("tenant_id={tenant}"))
        .sql_with_settings();
    let mut query = ch
        .query(&sql)
        .bind(now_us)
        .bind(days)
        .bind(retention)
        .bind(tenant.to_string());
    if let Some(key) = key {
        query = query.bind(decode_key(kind, key));
    }
    let rows = query.fetch_all::<ActivityRow>().await?;
    let totals = rows
        .iter()
        .find(|r| r.is_total == 1)
        .ok_or_else(|| anyhow::anyhow!("identity totals missing"))?;
    let workspace_calls = totals.calls;
    let total_identities = totals.identity_count;
    let has_retained_activity = totals.history_calls > 0;
    let identities: Vec<_> = rows
        .into_iter()
        .filter(|r| r.is_total == 0)
        .map(|r| r.into_activity(kind, workspace_calls))
        .collect();
    Ok(ActivityResponse {
        kind,
        requested_days: window.days(),
        window_days: days,
        retention_days: retention,
        since_us: now_us - i64::from(days) * 86_400_000_000,
        until_us: now_us,
        workspace_calls,
        has_retained_activity,
        total_identities,
        truncated: key.is_none() && (identities.len() as u64) < total_identities,
        identities,
    })
}

async fn authenticate(headers: &HeaderMap) -> Result<crate::auth::Claims, Response> {
    let bearer = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if bearer.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error":"missing_authorization"})),
        )
            .into_response());
    }
    let claims = crate::auth::validate_authorization(bearer)
        .await
        .map_err(|err| {
            let (status, message) = crate::auth::failure(&err);
            (status, Json(serde_json::json!({"error":message}))).into_response()
        })?;
    // Same capability as traces: the canonical scope slug is `read`.
    if !claims.allows_scope(crate::auth::scope::Scope::Read) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"insufficient_scope", "required_scope":"read"})),
        )
            .into_response());
    }
    Ok(claims)
}

#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn list(
    State(state): State<KyaState>,
    Query(q): Query<ListQuery>,
    headers: HeaderMap,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    serve(&state, &claims, q.kind, q.window, None).await
}
#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn profile(
    State(state): State<KyaState>,
    Path((kind, key)): Path<(Kind, String)>,
    Query(q): Query<ProfileQuery>,
    headers: HeaderMap,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    serve(&state, &claims, kind, q.window, Some(&key)).await
}
async fn serve(
    state: &KyaState,
    claims: &crate::auth::Claims,
    kind: Kind,
    window: Window,
    key: Option<&str>,
) -> Response {
    tracing::Span::current().record("tenant_id", tracing::field::display(&claims.tenant_id));
    // No control plane resolves to the existing Free defaults, never a paid grant.
    let resolved = match &state.entitlements {
        Some(c) => c.resolved(*claims.tenant_id.as_uuid()).await,
        None => Arc::new(crate::entitlement_cache::ResolvedEntitlements::deny_all()),
    };
    let retention = u32::try_from(resolved.queryable_days).unwrap_or(0);
    match read(
        &state.ch,
        PlanTier::from_plan_key(&resolved.plan_lookup_key),
        &claims.tenant_id,
        kind,
        window,
        retention,
        key,
        chrono::Utc::now().timestamp_micros(),
    )
    .await
    {
        Ok(v) if key.is_some() && v.identities.is_empty() => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error":"identity_not_found"})),
        )
            .into_response(),
        Ok(v) => Json(v).into_response(),
        Err(_) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error":"identity_read_failed"})),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn kya_routes_require_authentication_on_list_and_profile() {
        let state = KyaState {
            ch: clickhouse::Client::default(),
            entitlements: None,
        };
        let server = axum_test::TestServer::new(routes().with_state(state));
        for path in [
            "/v1/kya/identities?kind=agent&window=7d",
            "/v1/kya/identities/agent/kya-proof?window=7d",
        ] {
            server.get(path).await.assert_status_unauthorized();
        }
    }
    #[test]
    fn kya_filter_keys_match_the_lowercased_index() {
        // The stored key is `lowerUTF8(...)` (agent_key_sql / MODEL_KEY_SQL), so a
        // hand-typed `?agent=Codex` must bind `codex`, not match nothing silently.
        assert_eq!(decode_key(Kind::Agent, "Codex"), "codex");
        assert_eq!(decode_key(Kind::Model, "GPT-6-Sol"), "gpt-6-sol");
        assert_eq!(decode_key(Kind::Agent, "~direct"), "");
    }
    #[test]
    fn kya_pseudo_keys_never_collide_with_named_identities() {
        for kind in [Kind::Agent, Kind::Model] {
            assert_eq!(encode_key(kind, "."), "~.");
            assert_eq!(encode_key(kind, ".."), "~..");
            for raw in [".", "..", "~.", "~.."] {
                assert_eq!(decode_key(kind, &encode_key(kind, raw)), raw);
            }
        }

        for kind in [Kind::Agent, Kind::Model] {
            for key in ["", "~direct", "~unidentified", "~~literal", "ordinary"] {
                assert_eq!(decode_key(kind, &encode_key(kind, key)), key);
            }
        }
    }
    #[test]
    fn kya_sql_is_one_capped_tenant_bound_aggregate_before_the_limit() {
        for kind in [Kind::Agent, Kind::Model] {
            for detail in [false, true] {
                let sql = build_sql(kind, detail);
                assert_eq!(sql.matches("FROM tracelane.spans FINAL").count(), 1);
                assert!(sql.contains("WHERE tenant_id = ? AND start_time >= retained_at"));
                assert!(sql.contains("GROUPING SETS"));
                assert!(sql.find("OVER ()").unwrap() < sql.find("LIMIT").unwrap());
                assert!(sql.contains("uniqExactIf(trace_id"));
            }
        }
    }
    const FIXTURE_NOW: i64 = 1_800_000_000_000_000;

    fn fixture_source() -> String {
        let values = [
            serde_json::json!({"gen_ai_operation_name":"chat", "gen_ai_agent_name":" KYA-Proof ","tracelane_agent_name_source":"header","gen_ai_request_model":"claude-haiku-4-5", "gen_ai_usage_input_tokens":10,"gen_ai_usage_output_tokens":5,"tracelane_response_tool_names":["edit_file","edit_file"],"gen_ai_system":"anthropic"}),
            serde_json::json!({"gen_ai_operation_name":"messages","gen_ai_agent_name":"kya-proof", "gen_ai_response_model":"vertex/claude-haiku-4-5-20251001", "gen_ai_usage_input_tokens":10,"gen_ai_usage_output_tokens":5,"gen_ai_system":"vertex"}),
            serde_json::json!({"gen_ai_operation_name":"embeddings","tracelane_client_name":"kya-proof", "gen_ai_request_model":"llama-3.3-70b-versatile", "gen_ai_usage_output_tokens":2,"gen_ai_system":"groq"}),
            serde_json::json!({"gen_ai_operation_name":"chat"}),
            serde_json::json!({"gen_ai_operation_name":"execute_tool","gen_ai_agent_name":"kya-proof","gen_ai.tool.name":"bash"}),
            serde_json::json!({"gen_ai_operation_name":"chat","gen_ai_agent_name":"old-agent"}),
            serde_json::json!({"gen_ai_operation_name":"chat","gen_ai_agent_name":"foreign"}),
            serde_json::json!({"gen_ai_operation_name":"chat","gen_ai_agent_name":"future"}),
        ];
        let attrs = values
            .iter()
            .map(|v| {
                format!(
                    "'{}'",
                    v.to_string().replace('\\', "\\\\").replace('\'', "\\'")
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            r"(SELECT if(number = 6, '00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000001') AS tenant_id,
            concat('trace-', toString(if(number < 2, 1, number))) AS trace_id,
            fromUnixTimestamp64Micro({FIXTURE_NOW} + multiIf(number = 5, -8 * 86400000000, number = 7, 86400000000, -toInt64(number + 1) * 60000000)) AS start_time,
            toInt64((number + 1) * 1000000) AS duration_us,
            toUInt8(if(number = 1, 2, 0)) AS status_code,
            if(number = 0, 1.25, 0.0) AS cost_usd,
            toUInt8(number IN (0, 2)) AS cost_usd_present,
            arrayElement([{attrs}], number + 1) AS attributes FROM numbers(8))"
        )
    }

    async fn fixture_read(
        ch: &clickhouse::Client,
        kind: Kind,
        days: u32,
        tenant: u128,
        key: Option<&str>,
    ) -> Vec<ActivityRow> {
        let sql =
            build_sql(kind, key.is_some()).replace("tracelane.spans FINAL", &fixture_source());
        let sql = TenantQuery::new(sql, PlanTier::Free).sql_with_settings();
        let mut q = ch
            .query(&sql)
            .bind(FIXTURE_NOW)
            .bind(days)
            .bind(30)
            .bind(uuid::Uuid::from_u128(tenant).to_string());
        if let Some(key) = key {
            q = q.bind(decode_key(kind, key));
        }
        q.fetch_all::<ActivityRow>()
            .await
            .expect("real ClickHouse executes the identity aggregate")
    }

    fn local_ch() -> clickhouse::Client {
        let url =
            std::env::var("CLICKHOUSE_TEST_URL").expect("explicit local ClickHouse URL required");
        assert!(url.starts_with("http://127.0.0.1:") || url.starts_with("http://localhost:"));
        crate::clickhouse_query::ch_client(url)
    }

    #[tokio::test]
    #[ignore = "requires local ClickHouse; SELECT-only fixtures, no schema or stored rows changed"]
    async fn kya_real_clickhouse_exact_counts_usage_prices_families_and_tools() {
        let ch = local_ch();
        let rows = fixture_read(&ch, Kind::Agent, 7, 1, None).await;
        let totals = rows.iter().find(|r| r.is_total == 1).unwrap();
        assert_eq!(
            (totals.calls, totals.history_calls, totals.identity_count),
            (4, 5, 2)
        );
        let row = rows
            .into_iter()
            .find(|r| r.identity_key == "kya-proof" && r.is_total == 0)
            .unwrap();
        let a = row.into_activity(Kind::Agent, 4);
        assert_eq!(
            (a.calls, a.traces, a.tokens_in, a.tokens_out),
            (3, 2, Some(20), Some(12))
        );
        assert_eq!(
            (
                a.input_usage_missing,
                a.output_usage_missing,
                a.cost_usd,
                a.unpriced_calls
            ),
            (1, 0, Some(1.25), 1)
        );
        assert_eq!(
            (a.errors, a.error_rate, a.share_of_workspace),
            (1, Some(1.0 / 3.0), Some(0.75))
        );
        assert_eq!(a.p50_us, Some(2_000_000.0));
        assert_eq!(a.cross_count, 2);
        assert_eq!(
            (a.cross_list[0].key.as_str(), a.cross_list[0].calls),
            ("claude-haiku-4-5", 2)
        );
        assert_eq!(
            (a.tools[0].key.as_str(), a.tools[0].calls),
            ("edit_file", 2)
        );
        assert_eq!((a.tools[1].key.as_str(), a.tools[1].calls), ("bash", 1));
        assert_eq!(a.sources.len(), 3);
        let models = fixture_read(&ch, Kind::Model, 7, 1, None).await;
        let haiku = models
            .iter()
            .find(|r| r.is_total == 0 && r.identity_key == "claude-haiku-4-5")
            .unwrap();
        assert_eq!((haiku.calls, haiku.traces), (2, 1));
        let direct = models
            .into_iter()
            .find(|r| r.is_total == 0 && r.identity_key.is_empty())
            .unwrap()
            .into_activity(Kind::Model, 4);
        assert_eq!(
            (direct.tokens_in, direct.tokens_out, direct.cost_usd),
            (None, None, None)
        );
        assert_eq!(direct.key, "~unidentified");
    }

    #[tokio::test]
    #[ignore = "requires local ClickHouse; SELECT-only fixtures"]
    async fn kya_real_clickhouse_profile_tenant_isolation_and_empty_window() {
        let ch = local_ch();
        let rows = fixture_read(&ch, Kind::Agent, 7, 1, Some("kya-proof")).await;
        assert_eq!(rows.len(), 2);
        let a = rows
            .into_iter()
            .find(|r| r.is_total == 0)
            .unwrap()
            .into_activity(Kind::Agent, 4);
        assert_eq!(a.recent_traces.len(), 2);
        assert_eq!(a.recent_traces[0].trace_id, "trace-1");
        let foreign = fixture_read(&ch, Kind::Agent, 7, 2, Some("kya-proof")).await;
        assert!(!foreign.iter().any(|r| r.is_total == 0));
        let foreign_list = fixture_read(&ch, Kind::Agent, 7, 2, None).await;
        assert!(
            foreign_list
                .iter()
                .all(|r| r.is_total == 1 || r.identity_key == "foreign")
        );
        let empty = fixture_read(&ch, Kind::Agent, 7, 3, None).await;
        assert_eq!(empty.len(), 1);
        assert_eq!(
            (empty[0].is_total, empty[0].calls, empty[0].history_calls),
            (1, 0, 0)
        );
        let wider = fixture_read(&ch, Kind::Agent, 30, 1, None).await;
        assert!(
            wider
                .iter()
                .any(|r| r.identity_key == "old-agent" && r.calls == 1)
        );
        assert!(!wider.iter().any(|r| r.identity_key == "future"));
    }
    #[tokio::test]
    #[ignore = "requires local ClickHouse; SELECT only, including the real materialized-column schema"]
    async fn kya_real_clickhouse_empty_schema_retention_and_profile_404() {
        let ch = local_ch();
        let tenant = TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        let data = read(
            &ch,
            PlanTier::Free,
            &tenant,
            Kind::Agent,
            Window::Thirty,
            7,
            None,
            FIXTURE_NOW,
        )
        .await
        .unwrap();
        assert_eq!(
            (data.requested_days, data.window_days, data.retention_days),
            (30, 7, 7)
        );
        assert_eq!(data.until_us - data.since_us, 7 * 86_400_000_000);
        assert_eq!(data.workspace_calls, 0);
        assert!(!data.has_retained_activity);
        assert!(data.identities.is_empty());
        let claims = crate::auth::Claims {
            tenant_id: tenant,
            ..crate::auth::dev_stub_claims(crate::auth::AuthMethod::JwtBearer)
        };
        let state = KyaState {
            ch,
            entitlements: None,
        };
        for key in ["kya-proof", "never-existed"] {
            let response = serve(&state, &claims, Kind::Agent, Window::Seven, Some(key)).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                serde_json::json!({"error":"identity_not_found"})
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires local ClickHouse; SELECT-only fixtures"]
    async fn kya_real_clickhouse_caps_keep_full_totals_and_exact_top_lists() {
        let ch = local_ch();
        for crowded in [false, true] {
            let name = if crowded {
                "'crowded'"
            } else {
                "concat('agent-', toString(number))"
            };
            let source = format!(
                r#"(SELECT '00000000-0000-0000-0000-000000000001' AS tenant_id,
                concat('trace-', toString(number)) AS trace_id,
                fromUnixTimestamp64Micro({FIXTURE_NOW}-toInt64(number+1)*1000000) AS start_time,
                toInt64(100) AS duration_us, toUInt8(0) AS status_code,
                toFloat64(0) AS cost_usd, toUInt8(0) AS cost_usd_present,
                concat('{{"gen_ai_operation_name":"chat","gen_ai_agent_name":"', {name},
                    '","gen_ai_request_model":"model-',toString(number),
                    '","tracelane_response_tool_names":["tool-',toString(number),'"]}}') AS attributes
                FROM numbers(205))"#
            );
            let sql = build_sql(Kind::Agent, crowded).replace("tracelane.spans FINAL", &source);
            let sql = TenantQuery::new(sql, PlanTier::Free).sql_with_settings();
            let mut q = ch
                .query(&sql)
                .bind(FIXTURE_NOW)
                .bind(7)
                .bind(30)
                .bind("00000000-0000-0000-0000-000000000001");
            if crowded {
                q = q.bind("crowded");
            }
            let rows = q.fetch_all::<ActivityRow>().await.unwrap();
            let total = rows.iter().find(|r| r.is_total == 1).unwrap();
            assert_eq!(total.calls, 205);
            if crowded {
                let one = rows.iter().find(|r| r.is_total == 0).unwrap();
                assert_eq!((one.cross_count, one.tool_count), (205, 205));
                assert_eq!(
                    (
                        one.cross_list.len(),
                        one.tools.len(),
                        one.recent_traces.len()
                    ),
                    (10, 10, 20)
                );
                assert_eq!(one.recent_traces[0].0, "trace-0");
            } else {
                assert_eq!(total.identity_count, 205);
                assert_eq!(rows.len(), 201);
            }
        }
    }

    #[test]
    fn kya_queries_refuse_tenant_injection_unknown_kinds_and_windows() {
        for value in [
            serde_json::json!({"kind":"agent","window":"7d","tenant_id":"another-tenant"}),
            serde_json::json!({"kind":"user","window":"7d"}),
            serde_json::json!({"kind":"agent","window":"365d"}),
        ] {
            assert!(serde_json::from_value::<ListQuery>(value).is_err());
        }
    }
}
