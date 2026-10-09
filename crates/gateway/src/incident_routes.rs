//! Tenant-scoped incident evidence, regression fixtures and explicit outcomes.
use crate::{
    auth::{Claims, scope::Scope},
    clickhouse_query::{PlanTier, TenantQuery},
};
use anyhow::Result;
use arc_swap::ArcSwap;
use axum::response::{IntoResponse, Response};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::get,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tracelane_shared::TenantId;

type ApiError = (StatusCode, Json<Value>);
fn error(status: StatusCode, code: &str) -> ApiError {
    (status, Json(json!({"code":code,"error":code})))
}
fn unavailable(_: anyhow::Error) -> ApiError {
    error(StatusCode::BAD_GATEWAY, "incident_read_failed")
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct IncidentPolicy {
    pub outcome_reason_max_bytes: usize,
    pub outcomes_per_minute_per_tenant: u32,
    pub incident_reads_per_minute_per_tenant: u32,
    pub incident_last_good_lookback_hours: u32,
    pub outcome_session_window_hours: u32,
    pub incident_max_candidates: usize,
    pub incident_max_sessions_per_candidate: usize,
    pub regression_max_cases_per_export: usize,
    pub outcome_tile_window_days: u32,
}
impl IncidentPolicy {
    /// Check that the cached policy can safely bound every consumer.
    /// # Errors
    /// Infallible; invalid values make policy consumers fail CLOSED.
    pub(crate) fn valid(&self) -> bool {
        self.outcome_reason_max_bytes > 0
            && self.outcomes_per_minute_per_tenant > 0
            && self.incident_reads_per_minute_per_tenant > 0
            && self.incident_last_good_lookback_hours > 0
            && self.outcome_session_window_hours > 0
            && self.incident_max_candidates > 0
            && self.incident_max_sessions_per_candidate > 0
            && self.regression_max_cases_per_export > 0
            && self.regression_max_cases_per_export < usize::MAX
            && self.outcome_tile_window_days > 0
    }
    /// Read the packaged defaults for operation without a control plane.
    /// # Errors
    /// Fails CLOSED with None if the packaged policy cannot be decoded or is invalid.
    pub fn embedded() -> Option<Self> {
        let seed: Value =
            serde_json::from_str(include_str!("../../../apps/web/db/plans.v3.json")).ok()?;
        serde_json::from_value(seed["policy"]["incident_regression"].clone())
            .ok()
            .filter(Self::valid)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, clickhouse::Row)]
pub struct IncidentSpan {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub start_us: i64,
    pub status_code: u8,
    #[serde(serialize_with = "crate::tool_fingerprint::public_attributes")]
    pub attributes: String,
}
impl IncidentSpan {
    fn attr(&self, key: &str) -> Value {
        serde_json::from_str::<Value>(&self.attributes)
            .ok()
            .and_then(|v| v.get(key).cloned())
            .filter(|v| !v.is_null() && v != "")
            .unwrap_or(Value::Null)
    }
    fn identity(&self) -> Option<(&'static str, String)> {
        ["tracelane_kya_agent_id", "gen_ai_agent_name"]
            .into_iter()
            .find_map(|key| self.attr(key).as_str().map(|v| (key, v.to_owned())))
    }
}

#[derive(Debug, Clone, Deserialize, clickhouse::Row)]
pub struct IncidentCandidate {
    pub trace_id: String,
    pub root: (String, Option<String>, i64, u8, String),
    pub sessions: Vec<String>,
}
impl IncidentCandidate {
    fn span(&self) -> IncidentSpan {
        IncidentSpan {
            trace_id: self.trace_id.clone(),
            span_id: self.root.0.clone(),
            parent_span_id: self.root.1.clone(),
            start_us: self.root.2,
            status_code: self.root.3,
            attributes: self.root.4.clone(),
        }
    }
}
#[async_trait::async_trait]
pub trait IncidentStore: Send + Sync {
    /// Read the tenant-owned trace using the query resource ceilings.
    /// # Errors
    /// Fails CLOSED on read failure; an absent trace returns an empty set.
    async fn spans(&self, tenant: &TenantId, id: &str) -> Result<Vec<IncidentSpan>>;
    /// Read at most cap comparable roots and their session ids within the window.
    /// # Errors
    /// Fails CLOSED on query failure; never treats a failed scan as no comparable run.
    async fn candidates(
        &self,
        tenant: &TenantId,
        failing: &IncidentSpan,
        hours: u32,
        cap: usize,
        max_sessions: usize,
    ) -> Result<Vec<IncidentCandidate>>;
    /// Read annotations for all bounded candidate ids in one query.
    /// # Errors
    /// Fails CLOSED on database errors; fails OPEN to no annotations only when no
    /// annotation database is configured (the self-hosted configuration).
    async fn labels(
        &self,
        tenant: &TenantId,
        ids: &[String],
    ) -> Result<HashMap<String, Vec<String>>>;
}
pub struct ClickHouseIncidentStore {
    pub ch: clickhouse::Client,
    pub pg: Option<deadpool_postgres::Pool>,
}
const SPANS_SQL: &str = "SELECT trace_id, span_id, parent_span_id, toUnixTimestamp64Micro(start_time) AS start_us, status_code, attributes FROM tracelane.spans FINAL WHERE tenant_id = ? AND trace_id = ? ORDER BY start_time, span_id";
fn candidates_sql(max_sessions: usize) -> String {
    format!(
        "SELECT trace_id, argMin(tuple(span_id, parent_span_id, toUnixTimestamp64Micro(start_time), status_code, attributes), tuple(notEmpty(ifNull(parent_span_id, '')), start_time, span_id)) AS root, groupUniqArray({max_sessions})(nullIf(JSONExtractString(attributes, 'gen_ai_conversation_id'), '')) AS sessions FROM tracelane.spans FINAL WHERE tenant_id = ? AND start_time >= fromUnixTimestamp64Micro(?) - toIntervalHour(?) GROUP BY trace_id HAVING max(status_code) = 1 AND min(start_time) < fromUnixTimestamp64Micro(?) AND countIf(JSONExtractString(attributes, ?) = ?) > 0 ORDER BY min(start_time) DESC, trace_id LIMIT ?"
    )
}
#[async_trait::async_trait]
impl IncidentStore for ClickHouseIncidentStore {
    async fn spans(&self, tenant: &TenantId, id: &str) -> Result<Vec<IncidentSpan>> {
        let sql = TenantQuery::new(SPANS_SQL, PlanTier::Free).sql_with_settings();
        Ok(self
            .ch
            .query(&sql)
            .bind(tenant.to_string())
            .bind(id)
            .fetch_all()
            .await?)
    }
    async fn candidates(
        &self,
        tenant: &TenantId,
        failing: &IncidentSpan,
        hours: u32,
        cap: usize,
        max_sessions: usize,
    ) -> Result<Vec<IncidentCandidate>> {
        let Some((key, identity)) = failing.identity() else {
            return Ok(vec![]);
        };
        let sql =
            TenantQuery::new(candidates_sql(max_sessions), PlanTier::Free).sql_with_settings();
        Ok(self
            .ch
            .query(&sql)
            .bind(tenant.to_string())
            .bind(failing.start_us)
            .bind(hours)
            .bind(failing.start_us)
            .bind(key)
            .bind(identity)
            .bind(cap as u64)
            .fetch_all()
            .await?)
    }
    async fn labels(
        &self,
        tenant: &TenantId,
        ids: &[String],
    ) -> Result<HashMap<String, Vec<String>>> {
        let Some(pool) = &self.pg else {
            return Ok(HashMap::new());
        };
        let client = pool.get().await?;
        let rows = client.query("SELECT DISTINCT trace_id, label FROM trace_annotations WHERE tenant_id = $1 AND trace_id = ANY($2)", &[tenant.as_uuid(), &ids]).await?;
        let mut labels: HashMap<String, Vec<String>> = HashMap::new();
        for row in rows {
            labels.entry(row.get(0)).or_default().push(row.get(1));
        }
        Ok(labels)
    }
}

#[derive(Clone)]
pub struct IncidentState {
    pub limiter: Arc<crate::rate_limiter::RateLimiter>,
    pub store: Arc<dyn IncidentStore>,
    pub rate_card: Arc<ArcSwap<crate::billing::RateCard>>,
    pub outcomes: Arc<dyn crate::outcome_routes::OutcomeStore>,
    pub entitlements: Option<Arc<crate::entitlement_cache::EntitlementCache>>,
}
/// Mount tenant-scoped incident reads.
/// # Errors
/// Construction is infallible; handlers fail CLOSED on auth, policy or read errors.
pub fn routes() -> Router<IncidentState> {
    Router::new().route("/v1/traces/{trace_id}/incident", get(incident))
}
/// Validate the credential before using any claim as a tenant boundary.
/// # Errors
/// Fails CLOSED on missing or invalid credentials.
pub(crate) async fn claims_from_auth(headers: &HeaderMap) -> Result<Claims, ApiError> {
    let authorization = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| error(StatusCode::UNAUTHORIZED, "unauthorized"))?;
    crate::auth::validate_authorization(authorization)
        .await
        .map_err(|e| error(crate::auth::failure_status(&e), "unauthorized"))
}
/// Require the recorded-data Read scope.
/// # Errors
/// Fails CLOSED with 403 when the credential lacks Read.
pub(crate) fn authorize_read(claims: &Claims) -> Result<(), ApiError> {
    if !claims.allows_scope(Scope::Read) {
        return Err(error(StatusCode::FORBIDDEN, "read_scope_required"));
    }
    Ok(())
}
/// Resolve the bounded incident policy from the refreshed snapshot.
/// # Errors
/// Fails CLOSED with 503 when the row is missing or invalid.
pub(crate) fn policy(state: &IncidentState) -> Result<IncidentPolicy, ApiError> {
    state
        .rate_card
        .load()
        .policy
        .incident_regression
        .clone()
        .filter(IncidentPolicy::valid)
        .ok_or_else(|| {
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "incident_policy_unavailable",
            )
        })
}
async fn incident(
    State(state): State<IncidentState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let claims = claims_from_auth(&headers)
        .await
        .map_err(IntoResponse::into_response)?;
    authorize_read(&claims).map_err(IntoResponse::into_response)?;
    let limits = policy(&state).map_err(IntoResponse::into_response)?;
    check_rate(&state.limiter, &claims.tenant_id, &limits).map_err(IntoResponse::into_response)?;
    let mut packet = incident_for(&state, &claims.tenant_id, &id)
        .await
        .map_err(IntoResponse::into_response)?;
    let export_permission = if crate::dataset_routes::authorize_write(&claims).is_err() {
        "forbidden"
    } else if let Some(cache) = &state.entitlements {
        if cache
            .check(
                *claims.tenant_id.as_uuid(),
                crate::entitlement_cache::FeatureKey::Datasets,
            )
            .await
        {
            "allowed"
        } else {
            "forbidden"
        }
    } else {
        "unavailable"
    };
    packet["limits"]["export_permission"] = json!(export_permission);
    packet["limits"]["can_record_outcome"] = json!(
        claims.can(crate::auth::capability::Capability::AnnotateTraces)
            && claims.allows_scope(Scope::Ingest)
    );
    packet["limits"]["outcome_reason_max_bytes"] = json!(limits.outcome_reason_max_bytes);
    Ok(Json(packet).into_response())
}
async fn incident_for(
    state: &IncidentState,
    tenant: &TenantId,
    id: &str,
) -> Result<Value, ApiError> {
    let id = uuid::Uuid::parse_str(id)
        .map_err(|_| error(StatusCode::NOT_FOUND, "not_found"))?
        .to_string();
    let spans = state.store.spans(tenant, &id).await.map_err(unavailable)?;
    let failing = spans
        .iter()
        .find(|s| s.status_code == 2)
        .or_else(|| spans.first())
        .ok_or_else(|| error(StatusCode::NOT_FOUND, "not_found"))?;
    let limits = policy(state)?;
    let candidates = state
        .store
        .candidates(
            tenant,
            failing,
            limits.incident_last_good_lookback_hours,
            limits.incident_max_candidates,
            limits.incident_max_sessions_per_candidate,
        )
        .await
        .map_err(unavailable)?;
    let trace_ids: Vec<String> = std::iter::once(id.clone())
        .chain(candidates.iter().map(|c| c.trace_id.clone()))
        .collect();
    let labels = state
        .store
        .labels(tenant, &trace_ids)
        .await
        .map_err(unavailable)?;
    let mut current_sessions = HashSet::new();
    for span in &spans {
        if let Some(session) = span
            .attr("gen_ai_conversation_id")
            .as_str()
            .filter(|s| !s.is_empty())
        {
            current_sessions.insert(session.to_owned());
            if current_sessions.len() >= limits.incident_max_sessions_per_candidate {
                break;
            }
        }
    }
    let sessions: Vec<String> = current_sessions
        .iter()
        .cloned()
        .chain(
            candidates
                .iter()
                .flat_map(|c| c.sessions.iter().filter(|s| !s.is_empty()).cloned()),
        )
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    let failures = state
        .outcomes
        .failures(tenant, &trace_ids, &sessions)
        .await
        .map_err(unavailable)?;
    let failed_outcome = failures.contains(&("trace".into(), id.clone()))
        || current_sessions
            .iter()
            .any(|s| failures.contains(&("session".into(), s.clone())));
    let good = candidates
        .iter()
        .find(|c| {
            !labels
                .get(&c.trace_id)
                .is_some_and(|ls| ls.iter().any(|l| l == "bad"))
                && !failures.contains(&("trace".into(), c.trace_id.clone()))
                && !c
                    .sessions
                    .iter()
                    .any(|s| failures.contains(&("session".into(), s.clone())))
        })
        .map(IncidentCandidate::span);
    let mut packet = assemble(&spans, good.as_ref())?;
    if failed_outcome && let Some(triggers) = packet["trigger"].as_array_mut() {
        triggers.push(json!({"kind":"outcome","result":"failure"}));
    }
    for label in labels
        .get(&id)
        .into_iter()
        .flatten()
        .filter(|l| l.as_str() == "bad" || l.as_str() == "needs_review")
    {
        if let Some(v) = packet["trigger"].as_array_mut() {
            v.push(json!({"kind":"annotation","label":label}));
        }
    }
    packet["what_happened"]["note"] = if packet["trigger"].as_array().is_some_and(Vec::is_empty) {
        json!("no failing signal recorded")
    } else {
        Value::Null
    };
    packet["limits"] = json!({"incident_last_good_lookback_hours": limits.incident_last_good_lookback_hours, "incident_max_candidates": limits.incident_max_candidates, "incident_max_sessions_per_candidate": limits.incident_max_sessions_per_candidate, "prompt_version":"prompt version: not linked"});
    Ok(packet)
}
type RateLimitError = (
    StatusCode,
    [(axum::http::header::HeaderName, String); 1],
    Json<Value>,
);

/// Enforce the shared per-tenant read budget for incident, export and outcome GETs.
/// # Errors
/// Fails CLOSED with 429 and Retry-After when the configured budget is exhausted.
pub(crate) fn check_rate(
    limiter: &crate::rate_limiter::RateLimiter,
    tenant: &TenantId,
    policy: &IncidentPolicy,
) -> Result<(), RateLimitError> {
    if let crate::rate_limiter::RateLimitDecision::Throttle { retry_after_secs } =
        limiter.check(tenant, Some(policy.incident_reads_per_minute_per_tenant))
    {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            [(
                axum::http::header::RETRY_AFTER,
                retry_after_secs.to_string(),
            )],
            Json(json!({"code":"incident_rate_limited"})),
        ));
    }
    Ok(())
}
fn assemble(spans: &[IncidentSpan], good: Option<&IncidentSpan>) -> Result<Value, ApiError> {
    let failing = spans
        .iter()
        .find(|s| s.status_code == 2)
        .or_else(|| spans.first())
        .ok_or_else(|| error(StatusCode::NOT_FOUND, "not_found"))?;
    let trigger: Vec<Value> = spans
        .iter()
        .filter(|s| s.status_code == 2)
        .map(|s| json!({"kind":"error","span_id":s.span_id}))
        .collect();
    let fields = [
        "gen_ai_request_model",
        "gen_ai_response_model",
        "tracelane_model_substitution",
        "tracelane_request_tool_definitions_hash",
        "tracelane_request_tool_count",
        "deployment_environment",
        "service_version",
    ];
    let mut changes = vec![];
    let mut explanations = vec![];
    if let Some(good) = good {
        for field in fields {
            let before = good.attr(field);
            let after = failing.attr(field);
            changes.push(
                json!({"field":field,"failing":after,"good":before,"changed":before != after}),
            );
            if before != after && !before.is_null() && !after.is_null() {
                let supported = field == "gen_ai_response_model"
                    && failing.attr("tracelane_model_substitution") == "provider";
                let mut evidence = vec![json!({"field":field,"failing":after,"good":before})];
                if supported {
                    evidence.push(json!({"field":"tracelane_model_substitution","failing":"provider","good":good.attr("tracelane_model_substitution")}));
                }
                explanations.push(json!({"what": if supported {"Provider substituted the served model"} else {"Recorded field changed; its effect is uncertain"},"confidence": if supported {"supported"} else {"uncertain"}, "evidence":evidence}));
            }
        }
    }
    explanations.sort_by_key(|e| e["confidence"] != "supported");
    let mut linked = vec![json!({"span_id":failing.span_id,"trace_id":failing.trace_id})];
    let mut parent = failing.parent_span_id.as_deref();
    let mut seen = std::collections::HashSet::from([failing.span_id.as_str()]);
    while let Some(p) = parent.and_then(|id| spans.iter().find(|s| s.span_id == id)) {
        if !seen.insert(p.span_id.as_str()) {
            break;
        }
        linked.push(json!({"span_id":p.span_id,"trace_id":p.trace_id}));
        parent = p.parent_span_id.as_deref();
    }
    Ok(
        json!({"trigger":trigger,"what_happened":{"trace_id":failing.trace_id,"span_id":failing.span_id},"what_changed":{"good_trace_id":good.map(|s|&s.trace_id),"fields":changes,"note": if good.is_none() {Some("no comparable good run in the window")} else {None},"prompt_version":"prompt version: not linked"},"linked_spans":linked,"explanations":{"note":if explanations.is_empty(){Some("no single change explains this")}else{None},"items":explanations},"limits":{}}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    fn span() -> IncidentSpan {
        IncidentSpan {
            trace_id: uuid::Uuid::from_u128(1).to_string(),
            span_id: "failed".into(),
            parent_span_id: None,
            start_us: 10,
            status_code: 2,
            attributes: "{}".into(),
        }
    }
    #[test]
    fn cf2_low_incident_span_strips_both_fingerprints() {
        let mut incident = span();
        incident.attributes = r#"{"gen_ai_tool_call_arg_fp":"secret-otlp","tracelane_response_tool_arg_fps":["secret-gateway"],"other":"kept"}"#.into();
        let public = serde_json::to_string(&incident).unwrap();
        assert!(!public.contains("secret-"));
        assert!(!public.contains("arg_fp"));
        assert!(public.contains("kept"));
        // Internal evidence is still available for loop analysis.
        assert!(incident.attributes.contains("secret-otlp"));
        incident.attributes = "bad json".into();
        assert_eq!(serde_json::to_value(&incident).unwrap()["attributes"], "{}");
    }

    #[test]
    fn incident_no_good_is_explicit_and_never_invents_a_cause() {
        let result = assemble(&[span()], None).unwrap();
        assert_eq!(
            result["what_changed"]["note"],
            "no comparable good run in the window"
        );
        assert_eq!(
            result["explanations"]["note"],
            "no single change explains this"
        );
        assert_eq!(result["trigger"][0]["kind"], "error");
    }
    #[test]
    fn incident_missing_or_foreign_trace_is_the_same_404() {
        assert_eq!(assemble(&[], None).unwrap_err().0, StatusCode::NOT_FOUND);
    }
    #[test]
    fn incident_sql_is_tenant_first_and_workflow_is_never_end_user() {
        assert!(
            candidates_sql(20).contains("WHERE tenant_id = ? AND start_time >="),
            "lookback must bound the scan in WHERE"
        );
        assert!(
            candidates_sql(20).contains("LIMIT ?"),
            "candidate rows must be capped"
        );
        for sql in [SPANS_SQL.to_owned(), candidates_sql(20)] {
            assert!(sql.contains("FROM tracelane.spans FINAL WHERE tenant_id = ?"));
        }
        assert!(candidates_sql(20).contains("HAVING max(status_code) = 1"));
        let mut row = span();
        row.attributes = json!({"user_id":"shared-user"}).to_string();
        assert!(row.identity().is_none());
        row.attributes = json!({"gen_ai_agent_name":"agent"}).to_string();
        assert_eq!(row.identity().unwrap().1, "agent");
    }
    #[test]
    fn incident_changes_have_evidence_and_uncertainty() {
        let mut failed = span();
        let mut good = span();
        failed.attributes=json!({"gen_ai_response_model":"other","tracelane_model_substitution":"provider","deployment_environment":"prod"}).to_string();
        good.attributes =
            json!({"gen_ai_response_model":"original","deployment_environment":"staging"})
                .to_string();
        let result = assemble(&[failed], Some(&good)).unwrap();
        assert_eq!(
            result["explanations"]["items"][0]["confidence"],
            "supported"
        );
        assert_eq!(
            result["explanations"]["items"][1]["confidence"],
            "uncertain"
        );
        assert_eq!(result["what_changed"]["fields"][3]["failing"], Value::Null);
    }
    struct CountingStore {
        count: std::sync::atomic::AtomicUsize,
        candidates: usize,
        current_sessions: usize,
    }
    #[async_trait::async_trait]
    impl IncidentStore for CountingStore {
        async fn spans(&self, _: &TenantId, _: &str) -> Result<Vec<IncidentSpan>> {
            self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok((0..self.current_sessions.max(1))
                .map(|i| {
                    let mut row = span();
                    if self.current_sessions > 0 {
                        row.attributes =
                            json!({"gen_ai_conversation_id": format!("current-{i}")}).to_string();
                    }
                    row
                })
                .collect())
        }
        async fn candidates(
            &self,
            _: &TenantId,
            _: &IncidentSpan,
            _: u32,
            _: usize,
            _: usize,
        ) -> Result<Vec<IncidentCandidate>> {
            self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok((2..self.candidates + 2)
                .map(|n| IncidentCandidate {
                    trace_id: uuid::Uuid::from_u128(n as u128).to_string(),
                    root: ("root".into(), None, 1, 1, "{}".into()),
                    sessions: vec![format!("session-{n}")],
                })
                .collect())
        }
        async fn labels(
            &self,
            _: &TenantId,
            ids: &[String],
        ) -> Result<HashMap<String, Vec<String>>> {
            self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(ids
                .iter()
                .map(|id| (id.clone(), vec!["bad".into()]))
                .collect())
        }
    }
    #[async_trait::async_trait]
    impl crate::outcome_routes::OutcomeStore for CountingStore {
        async fn failures(
            &self,
            _: &TenantId,
            traces: &[String],
            sessions: &[String],
        ) -> Result<HashSet<(String, String)>> {
            self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            assert_eq!(traces.len(), self.candidates + 1);
            assert_eq!(
                sessions.len(),
                self.candidates + self.current_sessions.min(20),
                "current trace sessions must be bounded too"
            );
            Ok(HashSet::new())
        }
        async fn exists(&self, _: &TenantId, _: &str, _: &str, _: u32) -> Result<bool> {
            unreachable!()
        }
        async fn get(
            &self,
            _: &TenantId,
            _: &str,
            _: &str,
        ) -> Result<Option<crate::outcome_routes::Outcome>> {
            self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(None)
        }
        async fn write(&self, _: &TenantId, _: &crate::outcome_routes::Outcome) -> Result<()> {
            unreachable!()
        }
    }
    #[tokio::test]
    async fn incident_sessions_are_bounded_for_current_trace() {
        let store = Arc::new(CountingStore {
            count: std::sync::atomic::AtomicUsize::new(0),
            candidates: 0,
            current_sessions: 21,
        });
        let state = IncidentState {
            limiter: Arc::new(crate::rate_limiter::RateLimiter::new()),
            store: store.clone(),
            outcomes: store,
            entitlements: None,
            rate_card: Arc::new(ArcSwap::from_pointee(
                crate::billing::RateCard::unavailable(),
            )),
        };
        incident_for(
            &state,
            &TenantId::from_jwt_claim(uuid::Uuid::from_u128(1)),
            &uuid::Uuid::from_u128(1).to_string(),
        )
        .await
        .unwrap();
    }
    #[test]
    fn incident_candidate_session_aggregate_is_bounded() {
        assert!(
            candidates_sql(20).contains("groupUniqArray(20)("),
            "candidate session aggregate must be bounded: {}",
            candidates_sql(20)
        );
    }
    #[tokio::test]
    async fn incident_candidate_loop_has_constant_query_count() {
        for n in [1, 10, 50] {
            let store = Arc::new(CountingStore {
                count: std::sync::atomic::AtomicUsize::new(0),
                candidates: n,
                current_sessions: 0,
            });
            let state = IncidentState {
                limiter: Arc::new(crate::rate_limiter::RateLimiter::new()),
                store: store.clone(),
                outcomes: store.clone(),
                entitlements: None,
                rate_card: Arc::new(ArcSwap::from_pointee(
                    crate::billing::RateCard::unavailable(),
                )),
            };
            let tenant = TenantId::from_jwt_claim(uuid::Uuid::from_u128(1));
            let packet = incident_for(&state, &tenant, &uuid::Uuid::from_u128(1).to_string())
                .await
                .unwrap();
            assert!(packet["what_changed"]["good_trace_id"].is_null());
            assert_eq!(
                store.count.load(std::sync::atomic::Ordering::SeqCst),
                4,
                "one spans, candidates, labels and outcomes query for {n} candidates"
            );
        }
    }
    struct MemoryStore;
    #[async_trait::async_trait]
    impl IncidentStore for MemoryStore {
        async fn spans(&self, t: &TenantId, id: &str) -> Result<Vec<IncidentSpan>> {
            Ok(
                if t.as_uuid().as_u128() == 1 && id == uuid::Uuid::from_u128(1).to_string() {
                    vec![span()]
                } else {
                    vec![]
                },
            )
        }
        async fn candidates(
            &self,
            _: &TenantId,
            _: &IncidentSpan,
            _: u32,
            _: usize,
            _: usize,
        ) -> Result<Vec<IncidentCandidate>> {
            Ok(vec![])
        }
        async fn labels(
            &self,
            _: &TenantId,
            ids: &[String],
        ) -> Result<HashMap<String, Vec<String>>> {
            Ok(ids
                .iter()
                .map(|id| (id.clone(), vec!["needs_review".into()]))
                .collect())
        }
    }
    #[async_trait::async_trait]
    impl crate::outcome_routes::OutcomeStore for MemoryStore {
        async fn failures(
            &self,
            _: &TenantId,
            _: &[String],
            _: &[String],
        ) -> Result<HashSet<(String, String)>> {
            Ok(HashSet::new())
        }
        async fn exists(&self, _: &TenantId, _: &str, _: &str, _: u32) -> Result<bool> {
            Ok(false)
        }
        async fn get(
            &self,
            _: &TenantId,
            _: &str,
            _: &str,
        ) -> Result<Option<crate::outcome_routes::Outcome>> {
            Ok(None)
        }
        async fn write(&self, _: &TenantId, _: &crate::outcome_routes::Outcome) -> Result<()> {
            anyhow::bail!("read-only fixture")
        }
    }
    #[tokio::test]
    async fn incident_and_regression_gets_throttle_before_queries() {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;
        let limiter = Arc::new(crate::rate_limiter::RateLimiter::new());
        let tenant = TenantId::from_jwt_claim(uuid::Uuid::from_u128(1));
        let limits = IncidentPolicy::embedded().unwrap();
        for _ in 0..limits.incident_reads_per_minute_per_tenant {
            limiter.check(&tenant, Some(limits.incident_reads_per_minute_per_tenant));
        }
        let claims = Claims {
            tenant_id: tenant,
            sub: "test".into(),
            auth_method: crate::auth::AuthMethod::ApiKey,
            role: None,
            key_scope: crate::auth::scope::KeyScope::LegacyFullSurface,
            budget_usd_monthly: None,
            rate_limit_rpm: None,
            budget_reset: crate::spend::BudgetReset::Monthly,
            governance: None,
        };
        let _guard = crate::auth::test_claims::Guard::set(claims);
        let state = IncidentState {
            limiter,
            store: Arc::new(MemoryStore),
            outcomes: Arc::new(MemoryStore),
            entitlements: None,
            rate_card: Arc::new(ArcSwap::from_pointee(
                crate::billing::RateCard::unavailable(),
            )),
        };
        let app = routes().with_state(state.clone()).merge(
            crate::regression_routes::routes().with_state(
                crate::regression_routes::RegressionState {
                    incident: state,
                    datasets: Arc::new(crate::dataset_routes::ClickHouseDatasetStore::new(
                        clickhouse::Client::default(),
                    )),
                    entitlements: None,
                },
            ),
        );
        for suffix in ["incident", "regression"] {
            let response = app
                .clone()
                .oneshot(
                    Request::get(format!("/v1/traces/{}/{suffix}", uuid::Uuid::from_u128(1)))
                        .header("authorization", "Bearer test")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS, "{suffix}");
            assert!(response.headers().contains_key("retry-after"));
        }
    }
    #[tokio::test]
    async fn incident_two_tenants_foreign_id_404_owner_gets_packet() {
        let state = IncidentState {
            limiter: Arc::new(crate::rate_limiter::RateLimiter::new()),
            store: Arc::new(MemoryStore),
            outcomes: Arc::new(MemoryStore),
            entitlements: None,
            rate_card: Arc::new(ArcSwap::from_pointee(
                crate::billing::RateCard::unavailable(),
            )),
        };
        let id = uuid::Uuid::from_u128(1).to_string();
        let a = TenantId::from_jwt_claim(uuid::Uuid::from_u128(1));
        let b = TenantId::from_jwt_claim(uuid::Uuid::from_u128(2));
        assert_eq!(
            incident_for(&state, &b, &id).await.unwrap_err().0,
            StatusCode::NOT_FOUND
        );
        let packet = incident_for(&state, &a, &id).await.unwrap();
        assert_eq!(packet["trigger"][1]["label"], "needs_review");
    }
    #[tokio::test]
    async fn incident_clickhouse_reader_binds_validated_tenant_first() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::path("/"))
            .respond_with(wiremock::ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let store = ClickHouseIncidentStore {
            ch: clickhouse::Client::default().with_url(server.uri()),
            pg: None,
        };
        let tenant = TenantId::from_jwt_claim(uuid::Uuid::from_u128(7));
        assert!(store.spans(&tenant, "target").await.is_err());
        let mut failing = span();
        failing.attributes = json!({"gen_ai_agent_name":"workflow"}).to_string();
        assert!(
            store
                .candidates(&tenant, &failing, 168, 50, 7)
                .await
                .is_err()
        );
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        for req in requests {
            let sql = req
                .url
                .query_pairs()
                .find(|(k, _)| k == "query")
                .unwrap()
                .1
                .into_owned();
            assert!(
                sql.contains(&format!("WHERE tenant_id = '{}'", tenant)),
                "{sql}"
            );
            if sql.contains("GROUP BY trace_id") {
                assert!(sql.contains("groupUniqArray(7)("), "{sql}");
            }
            assert!(sql.contains("SETTINGS"), "{sql}");
            assert!(!sql.contains('?'), "unbound SQL: {sql}");
        }
    }
}
