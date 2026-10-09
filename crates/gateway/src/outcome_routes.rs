//! Explicit tenant-owned task outcomes; a successful span never implies success.
use crate::{
    auth::{Claims, scope::Scope},
    clickhouse_query::{PlanTier, TenantQuery},
    incident_routes::IncidentPolicy,
    rate_limiter::{RateLimitDecision, RateLimiter},
};
use anyhow::Result;
use arc_swap::ArcSwap;
use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::Mutex;
use tracelane_shared::TenantId;
type ApiError = (StatusCode, Json<Value>);
async fn claims_from_auth(headers: &HeaderMap) -> Result<Claims, ApiError> {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| error(StatusCode::UNAUTHORIZED, "unauthorized"))?;
    crate::auth::validate_authorization(authorization)
        .await
        .map_err(|e| error(crate::auth::failure_status(&e), "unauthorized"))
}
fn error(status: StatusCode, code: &str) -> ApiError {
    (status, Json(json!({"code":code,"error":code})))
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeBody {
    pub subject_kind: String,
    pub subject_id: String,
    pub result: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub source: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, clickhouse::Row)]
pub struct Outcome {
    pub subject_kind: String,
    pub subject_id: String,
    pub result: String,
    pub reason: String,
    pub source: String,
    pub version: u64,
    pub recorded_at_ms: i64,
}
#[async_trait::async_trait]
pub trait OutcomeStore: Send + Sync {
    /// Fetch latest failing subjects in one tenant-scoped batch.
    /// # Errors
    /// Fails CLOSED on a storage error; callers must not infer success.
    async fn failures(
        &self,
        tenant: &TenantId,
        traces: &[String],
        sessions: &[String],
    ) -> Result<HashSet<(String, String)>>;
    /// Verify tenant ownership, bounding session lookup by the policy window.
    /// # Errors
    /// Fails CLOSED on a storage error; absence is not authorization.
    async fn exists(&self, tenant: &TenantId, kind: &str, id: &str, hours: u32) -> Result<bool>;
    /// Read the latest recorded outcome for the tenant-owned subject.
    /// # Errors
    /// Fails CLOSED on a storage error; absence is distinct from a failed read.
    async fn get(&self, tenant: &TenantId, kind: &str, id: &str) -> Result<Option<Outcome>>;
    /// Persist an explicit outcome version.
    /// # Errors
    /// Fails CLOSED on insert failure; the route returns a stable 502.
    async fn write(&self, tenant: &TenantId, outcome: &Outcome) -> Result<()>;
}
pub struct ClickHouseOutcomeStore {
    pub ch: clickhouse::Client,
}
fn subject_not_found(kind: &str) -> &'static str {
    if kind == "session" {
        "session_not_found_in_window"
    } else {
        "not_found"
    }
}
fn subject_sql(kind: &str) -> &'static str {
    if kind == "trace" {
        "SELECT toUInt8(1) FROM tracelane.spans FINAL WHERE tenant_id = ? AND trace_id = ? LIMIT 1"
    } else {
        "SELECT toUInt8(1) FROM tracelane.spans FINAL WHERE tenant_id = ? AND JSONExtractString(attributes, 'gen_ai_conversation_id') = ? AND start_time >= now64(6) - toIntervalHour(?) LIMIT 1"
    }
}
const FAILURES_SQL: &str = "SELECT toString(subject_kind), subject_id FROM tracelane.outcomes FINAL WHERE tenant_id = ? AND question_id = '' AND result = 'failure' AND ((subject_kind = 'trace' AND subject_id IN ?) OR (subject_kind = 'session' AND subject_id IN ?)) LIMIT ?";
fn failures_sql(has_traces: bool, has_sessions: bool) -> &'static str {
    match (has_traces, has_sessions) {
        (true, true) => FAILURES_SQL,
        (true, false) => {
            "SELECT toString(subject_kind), subject_id FROM tracelane.outcomes FINAL WHERE tenant_id = ? AND question_id = '' AND result = 'failure' AND subject_kind = 'trace' AND subject_id IN ? LIMIT ?"
        }
        (false, true) => {
            "SELECT toString(subject_kind), subject_id FROM tracelane.outcomes FINAL WHERE tenant_id = ? AND question_id = '' AND result = 'failure' AND subject_kind = 'session' AND subject_id IN ? LIMIT ?"
        }
        (false, false) => {
            "SELECT toString(subject_kind), subject_id FROM tracelane.outcomes FINAL WHERE tenant_id = ? AND 0 LIMIT 0"
        }
    }
}
pub const OUTCOME_SQL: &str = "SELECT toString(subject_kind), subject_id, toString(result), reason, source, version, toUnixTimestamp64Milli(recorded_at) AS recorded_at_ms FROM tracelane.outcomes FINAL WHERE tenant_id = ? AND subject_kind = ? AND subject_id = ? AND question_id = '' LIMIT 1";
#[async_trait::async_trait]
impl OutcomeStore for ClickHouseOutcomeStore {
    async fn failures(
        &self,
        tenant: &TenantId,
        traces: &[String],
        sessions: &[String],
    ) -> Result<HashSet<(String, String)>> {
        if traces.is_empty() && sessions.is_empty() {
            return Ok(HashSet::new());
        }
        let sql = TenantQuery::new(
            failures_sql(!traces.is_empty(), !sessions.is_empty()),
            PlanTier::Free,
        )
        .sql_with_settings();
        let mut query = self.ch.query(&sql).bind(tenant.to_string());
        if !traces.is_empty() {
            query = query.bind(traces);
        }
        if !sessions.is_empty() {
            query = query.bind(sessions);
        }
        Ok(query
            .bind((traces.len() + sessions.len()) as u64)
            .fetch_all::<(String, String)>()
            .await?
            .into_iter()
            .collect())
    }
    async fn exists(&self, tenant: &TenantId, kind: &str, id: &str, hours: u32) -> Result<bool> {
        let sql = TenantQuery::new(subject_sql(kind), PlanTier::Free).sql_with_settings();
        let mut query = self.ch.query(&sql).bind(tenant.to_string()).bind(id);
        if kind == "session" {
            query = query.bind(hours);
        }
        Ok(query.fetch_optional::<u8>().await?.is_some())
    }
    async fn get(&self, tenant: &TenantId, kind: &str, id: &str) -> Result<Option<Outcome>> {
        let sql = TenantQuery::new(OUTCOME_SQL, PlanTier::Free).sql_with_settings();
        Ok(self
            .ch
            .query(&sql)
            .bind(tenant.to_string())
            .bind(kind)
            .bind(id)
            .fetch_optional()
            .await?)
    }
    async fn write(&self, tenant: &TenantId, o: &Outcome) -> Result<()> {
        self.ch.query("INSERT INTO tracelane.outcomes (tenant_id, subject_kind, subject_id, question_id, result, actual, reason, source, version, recorded_at) VALUES (?, ?, ?, '', ?, '', ?, ?, ?, fromUnixTimestamp64Milli(?))")
            .bind(tenant.to_string()).bind(&o.subject_kind).bind(&o.subject_id).bind(&o.result).bind(&o.reason).bind(&o.source).bind(o.version).bind(o.recorded_at_ms).execute().await?;
        Ok(())
    }
}
#[derive(Clone)]
pub struct OutcomeState {
    pub store: Arc<dyn OutcomeStore>,
    pub rate_card: Arc<ArcSwap<crate::billing::RateCard>>,
    pub audit: Option<Arc<crate::audit::AuditChain>>,
    pub limiter: Arc<RateLimiter>,
    pub read_limiter: Arc<RateLimiter>,
    pub locks: Arc<Mutex<HashMap<TenantId, std::sync::Weak<Mutex<()>>>>>,
}
impl OutcomeState {
    /// Construct the shared outcome store, audit connection and tenant limiter.
    /// # Errors
    /// Construction is infallible; write handlers fail CLOSED on auth, policy,
    /// audit or storage errors. An absent audit connection is an explicit opt-out.
    pub fn new(
        store: Arc<dyn OutcomeStore>,
        rate_card: Arc<ArcSwap<crate::billing::RateCard>>,
        audit: Option<Arc<crate::audit::AuditChain>>,
    ) -> Self {
        Self {
            store,
            rate_card,
            audit,
            limiter: Arc::new(RateLimiter::new()),
            read_limiter: Arc::new(RateLimiter::new()),
            locks: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    async fn lock(&self, t: &TenantId) -> Arc<Mutex<()>> {
        let mut locks = self.locks.lock().await;
        locks.retain(|_, v| v.strong_count() > 0);
        if let Some(lock) = locks.get(t).and_then(std::sync::Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(Mutex::new(()));
        locks.insert(t.clone(), Arc::downgrade(&lock));
        lock
    }
}
/// Mount authenticated outcome reads and Ingest-scoped writes.
/// # Errors
/// Construction is infallible; handlers fail CLOSED on authorization, rate,
/// validation, audit and storage errors.
pub fn routes() -> Router<OutcomeState> {
    Router::new().route("/v1/outcomes", get(get_outcome).post(post_outcome))
}
fn validate(body: &mut OutcomeBody, policy: &IncidentPolicy) -> Result<(), ApiError> {
    if body.subject_kind == "decision" || body.result == "label" {
        return Err(error(StatusCode::BAD_REQUEST, "not_supported"));
    }
    if !matches!(body.subject_kind.as_str(), "trace" | "session")
        || !matches!(body.result.as_str(), "success" | "failure")
    {
        return Err(error(StatusCode::BAD_REQUEST, "invalid_outcome"));
    }
    if body.subject_id.is_empty() {
        return Err(error(StatusCode::NOT_FOUND, "not_found"));
    }
    if body.subject_kind == "trace" {
        body.subject_id = uuid::Uuid::parse_str(&body.subject_id)
            .map_err(|_| error(StatusCode::NOT_FOUND, "not_found"))?
            .to_string();
    }
    for (value, code) in [
        (&mut body.reason, "reason_too_long"),
        (&mut body.source, "source_too_long"),
    ] {
        if value.len() > policy.outcome_reason_max_bytes {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"code":code,"max_bytes":policy.outcome_reason_max_bytes})),
            ));
        }
        *value = tracelane_policy::pii::redact(value);
        if value.len() > policy.outcome_reason_max_bytes {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"code":code,"max_bytes":policy.outcome_reason_max_bytes})),
            ));
        }
    }
    Ok(())
}
fn authorize_write(claims: &Claims) -> Result<(), ApiError> {
    // OG-34: the matrix's `annotate_traces` row (viewer, billing and an
    // unrecognised slug are refused; the error code is unchanged for the dashboard).
    if !claims.can(crate::auth::capability::Capability::AnnotateTraces) {
        return Err(error(
            StatusCode::FORBIDDEN,
            "viewer_cannot_record_outcomes",
        ));
    }
    if !claims.allows_scope(Scope::Ingest) {
        return Err(error(StatusCode::FORBIDDEN, "ingest_scope_required"));
    }
    Ok(())
}
async fn post_outcome(
    State(state): State<OutcomeState>,
    headers: HeaderMap,
    Json(body): Json<OutcomeBody>,
) -> Result<Response, ApiError> {
    let claims = claims_from_auth(&headers).await?;
    authorize_write(&claims)?;
    if let Some(key) = headers.get("idempotency-key") {
        let bytes = key.as_bytes();
        if bytes.is_empty() || bytes.len() > 255 || !bytes.iter().all(|b| (0x21..=0x7e).contains(b))
        {
            return Err(error(StatusCode::BAD_REQUEST, "invalid_idempotency_key"));
        }
    }
    let policy = state
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
        })?;
    // Security-sensitive policy absence/invalidity fails CLOSED; no unlimited fallback.
    if policy.outcomes_per_minute_per_tenant == 0 || policy.outcome_reason_max_bytes == 0 {
        return Err(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "incident_policy_unavailable",
        ));
    }
    if let RateLimitDecision::Throttle { retry_after_secs } = state.limiter.check(
        &claims.tenant_id,
        Some(policy.outcomes_per_minute_per_tenant),
    ) {
        return Ok((
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, retry_after_secs.to_string())],
            Json(json!({"code":"outcome_rate_limited"})),
        )
            .into_response());
    }
    let outcome = write_for(
        &state,
        &claims,
        &policy,
        body,
        chrono::Utc::now().timestamp_millis(),
    )
    .await?;
    let mut response=Json(json!({"subject_kind":outcome.subject_kind,"subject_id":outcome.subject_id,"result":outcome.result,"version":outcome.version})).into_response();
    if let Some(key) = headers.get("idempotency-key") {
        response
            .headers_mut()
            .insert("idempotency-key", key.clone());
    }
    Ok(response)
}
async fn write_for(
    state: &OutcomeState,
    claims: &Claims,
    policy: &IncidentPolicy,
    mut body: OutcomeBody,
    now_ms: i64,
) -> Result<Outcome, ApiError> {
    authorize_write(claims)?;
    validate(&mut body, policy)?;
    let tenant = &claims.tenant_id;
    let lock = state.lock(tenant).await;
    let _guard = lock.lock().await;
    if !state
        .store
        .exists(
            tenant,
            &body.subject_kind,
            &body.subject_id,
            policy.outcome_session_window_hours,
        )
        .await
        .map_err(|_| error(StatusCode::BAD_GATEWAY, "outcome_read_failed"))?
    {
        return Err(error(
            StatusCode::NOT_FOUND,
            subject_not_found(&body.subject_kind),
        ));
    }
    let previous = state
        .store
        .get(tenant, &body.subject_kind, &body.subject_id)
        .await
        .map_err(|_| error(StatusCode::BAD_GATEWAY, "outcome_read_failed"))?;
    if let Some(old) = &previous
        && old.result == body.result
    {
        return Ok(old.clone());
    }
    let version = u64::try_from(now_ms)
        .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "clock_unavailable"))?
        .max(previous.as_ref().map_or(0, |p| p.version.saturating_add(1)));
    let outcome = Outcome {
        subject_kind: body.subject_kind,
        subject_id: body.subject_id,
        result: body.result,
        reason: body.reason,
        source: body.source,
        version,
        recorded_at_ms: now_ms,
    };
    // Audit records the requested transition before the durable write, labelled as an attempt:
    // a failed ClickHouse insert must never be described as a committed outcome.
    if let Some(audit) = &state.audit {
        audit
            .append(crate::audit::AuditEvent {
                tenant_id: tenant.clone(),
                event_type: "outcome.record_attempt",
                actor: claims.sub.clone(),
                payload: json!({"previous":previous.as_ref().map(audit_outcome),"requested":audit_outcome(&outcome)}),
            })
            .await
            .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "audit_unavailable"))?;
    }
    state
        .store
        .write(tenant, &outcome)
        .await
        .map_err(|_| error(StatusCode::BAD_GATEWAY, "outcome_write_failed"))?;
    Ok(outcome)
}
fn audit_outcome(outcome: &Outcome) -> Value {
    json!({
        "subject_kind": outcome.subject_kind, "subject_id": tracelane_policy::pii::redact(&outcome.subject_id),
        "result": outcome.result, "version": outcome.version,
        "recorded_at_ms": outcome.recorded_at_ms,
        "reason_len": outcome.reason.len(),
        "source_len": outcome.source.len(),
    })
}
#[derive(Deserialize)]
struct OutcomeQuery {
    subject: String,
    #[serde(default = "trace_kind")]
    subject_kind: String,
}
fn trace_kind() -> String {
    "trace".into()
}
async fn get_outcome(
    State(state): State<OutcomeState>,
    Query(q): Query<OutcomeQuery>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let claims = claims_from_auth(&headers)
        .await
        .map_err(IntoResponse::into_response)?;
    if !claims.allows_scope(Scope::Read) {
        return Err(error(StatusCode::FORBIDDEN, "read_scope_required").into_response());
    }
    let policy = state
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
            .into_response()
        })?;
    crate::incident_routes::check_rate(&state.read_limiter, &claims.tenant_id, &policy)
        .map_err(IntoResponse::into_response)?;
    if !matches!(q.subject_kind.as_str(), "trace" | "session") {
        return Err(error(StatusCode::BAD_REQUEST, "not_supported").into_response());
    }
    let id = if q.subject_kind == "trace" {
        uuid::Uuid::parse_str(&q.subject)
            .map_err(|_| error(StatusCode::NOT_FOUND, "not_found").into_response())?
            .to_string()
    } else {
        q.subject
    };
    if !state
        .store
        .exists(
            &claims.tenant_id,
            &q.subject_kind,
            &id,
            policy.outcome_session_window_hours,
        )
        .await
        .map_err(|_| error(StatusCode::BAD_GATEWAY, "outcome_read_failed").into_response())?
    {
        return Err(
            error(StatusCode::NOT_FOUND, subject_not_found(&q.subject_kind)).into_response(),
        );
    }
    let outcome = state
        .store
        .get(&claims.tenant_id, &q.subject_kind, &id)
        .await
        .map_err(|_| error(StatusCode::BAD_GATEWAY, "outcome_read_failed").into_response())?;
    Ok(Json(json!({"outcome":outcome})).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Role;
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn af3_outcome_post_rejects_missing_auth_and_read_only_key() {
        use axum::{
            body::{Body, to_bytes},
            http::Request,
        };
        use tower::ServiceExt;

        let store = Arc::new(MemoryStore::default());
        let app = routes().with_state(state(store.clone()));
        for (scope, status, code) in [
            (None, StatusCode::UNAUTHORIZED, "unauthorized"),
            (Some("read"), StatusCode::FORBIDDEN, "ingest_scope_required"),
        ] {
            let mut request =
                Request::post("/v1/outcomes").header("content-type", "application/json");
            if scope.is_some() {
                request = request.header("authorization", "Bearer test");
            }
            let _guard = scope.map(|scope| {
                let mut c = claims(1);
                c.key_scope = crate::auth::scope::KeyScope::from_column(Some(&[scope.into()]));
                crate::auth::test_claims::Guard::set(c)
            });
            let response = app
                .clone()
                .oneshot(
                    request
                        .body(Body::from(
                            json!({
                                "subject_kind": "trace",
                                "subject_id": uuid::Uuid::from_u128(9).to_string(),
                                "result": "success"
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), status, "scope: {scope:?}");
            let data: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                    .unwrap();
            assert_eq!(data["code"], code);
        }
        assert_eq!(store.writes.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn outcome_session_ownership_uses_its_own_window_and_error() {
        use axum::{
            body::{Body, to_bytes},
            http::Request,
        };
        use tower::ServiceExt;
        let store = Arc::new(MemoryStore::default());
        let s = state(store.clone());
        let policy = IncidentPolicy::embedded().unwrap();
        let mut b = body();
        b.subject_kind = "session".into();
        b.subject_id = "old-session".into();
        assert!(
            write_for(&s, &claims(1), &policy, b.clone(), 100)
                .await
                .is_ok(),
            "a session older than the incident lookback remains owned inside the span window"
        );
        b.subject_id = "expired-session".into();
        let e = write_for(&s, &claims(1), &policy, b, 101)
            .await
            .unwrap_err();
        assert_eq!(e.0, StatusCode::NOT_FOUND);
        assert_eq!(e.1.0["code"], "session_not_found_in_window");
        let _guard = crate::auth::test_claims::Guard::set(claims(1));
        let app = routes().with_state(s);
        for (id, status) in [
            ("old-session", StatusCode::OK),
            ("expired-session", StatusCode::NOT_FOUND),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::get(format!("/v1/outcomes?subject_kind=session&subject={id}"))
                        .header("authorization", "Bearer test")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), status);
            if status == StatusCode::NOT_FOUND {
                let data: Value = serde_json::from_slice(
                    &to_bytes(response.into_body(), usize::MAX).await.unwrap(),
                )
                .unwrap();
                assert_eq!(data["code"], "session_not_found_in_window");
            }
        }
        assert_eq!(store.ownership_hours.load(Ordering::SeqCst), 8760);
    }
    #[tokio::test]
    async fn outcome_read_and_write_rate_budgets_are_independent() {
        use axum::{
            body::{Body, to_bytes},
            http::Request,
        };
        use tower::ServiceExt;
        let _guard = crate::auth::test_claims::Guard::set(claims(1));
        let seed: Value =
            serde_json::from_str(include_str!("../../../apps/web/db/plans.v3.json")).unwrap();
        let read_cap =
            seed["policy"]["incident_regression"]["incident_reads_per_minute_per_tenant"]
                .as_u64()
                .unwrap_or(120);
        let write_cap = IncidentPolicy::embedded()
            .unwrap()
            .outcomes_per_minute_per_tenant as u64;
        for read_first in [true, false] {
            let app = routes().with_state(state(Arc::new(MemoryStore::default())));
            let request = |read: bool| {
                if read {
                    Request::get(format!("/v1/outcomes?subject={}", uuid::Uuid::from_u128(9)))
                        .header("authorization", "Bearer test")
                        .body(Body::empty())
                        .unwrap()
                } else {
                    Request::post("/v1/outcomes").header("authorization", "Bearer test").header("content-type", "application/json").body(Body::from(json!({"subject_kind":"trace","subject_id":uuid::Uuid::from_u128(9).to_string(),"result":"success"}).to_string())).unwrap()
                }
            };
            let cap = if read_first { read_cap } else { write_cap };
            for n in 0..cap {
                assert_eq!(
                    app.clone()
                        .oneshot(request(read_first))
                        .await
                        .unwrap()
                        .status(),
                    StatusCode::OK,
                    "request {n} of {cap}, read={read_first}"
                );
            }
            let limited = app.clone().oneshot(request(read_first)).await.unwrap();
            assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
            assert!(limited.headers().contains_key("retry-after"));
            let data: Value =
                serde_json::from_slice(&to_bytes(limited.into_body(), usize::MAX).await.unwrap())
                    .unwrap();
            assert_eq!(
                data["code"],
                if read_first {
                    "incident_rate_limited"
                } else {
                    "outcome_rate_limited"
                }
            );
            assert_eq!(
                app.oneshot(request(!read_first)).await.unwrap().status(),
                StatusCode::OK,
                "one budget must not exhaust the other"
            );
        }
    }
    #[derive(Default)]
    struct MemoryStore {
        rows: Mutex<HashMap<(TenantId, String, String), Outcome>>,
        writes: AtomicUsize,
        ownership_hours: AtomicUsize,
        fail: bool,
    }
    #[async_trait::async_trait]
    impl OutcomeStore for MemoryStore {
        async fn failures(
            &self,
            _: &TenantId,
            _: &[String],
            _: &[String],
        ) -> Result<HashSet<(String, String)>> {
            unreachable!()
        }
        async fn exists(&self, t: &TenantId, _: &str, id: &str, hours: u32) -> Result<bool> {
            self.ownership_hours.store(hours as usize, Ordering::SeqCst);
            Ok(t.as_uuid().as_u128() == 1
                && (id == uuid::Uuid::from_u128(9).to_string()
                    || id == "jane@example.com"
                    || (id == "old-session" && hours == 8760)))
        }
        async fn get(&self, t: &TenantId, k: &str, id: &str) -> Result<Option<Outcome>> {
            Ok(self
                .rows
                .lock()
                .await
                .get(&(t.clone(), k.into(), id.into()))
                .cloned())
        }
        async fn write(&self, t: &TenantId, o: &Outcome) -> Result<()> {
            if self.fail {
                anyhow::bail!("unavailable");
            }
            self.writes.fetch_add(1, Ordering::SeqCst);
            self.rows.lock().await.insert(
                (t.clone(), o.subject_kind.clone(), o.subject_id.clone()),
                o.clone(),
            );
            Ok(())
        }
    }
    fn claims(tenant: u128) -> Claims {
        Claims {
            tenant_id: TenantId::from_jwt_claim(uuid::Uuid::from_u128(tenant)),
            sub: "test-user".into(),
            auth_method: crate::auth::AuthMethod::ApiKey,
            role: None,
            key_scope: crate::auth::scope::KeyScope::LegacyFullSurface,
            budget_usd_monthly: None,
            rate_limit_rpm: None,
            budget_reset: crate::spend::BudgetReset::Monthly,
            governance: None,
        }
    }
    fn body() -> OutcomeBody {
        OutcomeBody {
            subject_kind: "trace".into(),
            subject_id: uuid::Uuid::from_u128(9).to_string(),
            result: "failure".into(),
            reason: "Contact jane@example.com".into(),
            source: "test".into(),
        }
    }
    fn state(store: Arc<MemoryStore>) -> OutcomeState {
        OutcomeState::new(
            store,
            Arc::new(ArcSwap::from_pointee(
                crate::billing::RateCard::unavailable(),
            )),
            None,
        )
    }
    #[tokio::test]
    async fn outcome_double_post_is_one_write_changed_result_is_new_version() {
        let store = Arc::new(MemoryStore::default());
        let s = state(store.clone());
        let p = IncidentPolicy::embedded().unwrap();
        let c = claims(1);
        let first = write_for(&s, &c, &p, body(), 100).await.unwrap();
        let again = write_for(&s, &c, &p, body(), 101).await.unwrap();
        assert_eq!(
            store.writes.load(Ordering::SeqCst),
            1,
            "same result must not insert again"
        );
        assert_eq!(first.version, again.version);
        let mut changed = body();
        changed.result = "success".into();
        let last = write_for(&s, &c, &p, changed, 100).await.unwrap();
        assert!(last.version > first.version);
        assert_eq!(store.writes.load(Ordering::SeqCst), 2);
    }
    #[tokio::test]
    async fn outcome_reserved_values_never_write_a_row() {
        let store = Arc::new(MemoryStore::default());
        let s = state(store.clone());
        let p = IncidentPolicy::embedded().unwrap();
        for (kind, result) in [("decision", "success"), ("trace", "label")] {
            let mut b = body();
            b.subject_kind = kind.into();
            b.result = result.into();
            let e = write_for(&s, &claims(1), &p, b, 100).await.unwrap_err();
            assert_eq!(e.0, StatusCode::BAD_REQUEST);
            assert_eq!(e.1.0["code"], "not_supported");
        }
        assert_eq!(store.writes.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn outcome_customer_text_is_redacted_and_over_cap_is_refused_not_truncated() {
        let store = Arc::new(MemoryStore::default());
        let s = state(store.clone());
        let p = IncidentPolicy::embedded().unwrap();
        let saved = write_for(&s, &claims(1), &p, body(), 100).await.unwrap();
        assert!(!saved.reason.contains("jane@example.com"));
        assert!(saved.reason.contains("[REDACTED:"));
        let mut b = body();
        b.reason = "é".repeat(p.outcome_reason_max_bytes);
        let e = write_for(&s, &claims(1), &p, b, 101).await.unwrap_err();
        assert_eq!(e.0, StatusCode::BAD_REQUEST);
        assert_eq!(e.1.0["code"], "reason_too_long");
        assert_eq!(e.1.0["max_bytes"], p.outcome_reason_max_bytes);
        assert_eq!(store.writes.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn outcome_foreign_subject_and_viewer_never_write() {
        let store = Arc::new(MemoryStore::default());
        let s = state(store.clone());
        let p = IncidentPolicy::embedded().unwrap();
        assert_eq!(
            write_for(&s, &claims(2), &p, body(), 100)
                .await
                .unwrap_err()
                .0,
            StatusCode::NOT_FOUND
        );
        // A human viewer: OG-34 reads the role on a WorkOS session, never on a key.
        let mut c = claims(1);
        c.auth_method = crate::auth::AuthMethod::JwtBearer;
        c.role = Some(Role::Viewer);
        assert_eq!(
            write_for(&s, &c, &p, body(), 100).await.unwrap_err().0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(store.writes.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn outcome_write_failure_is_stable_502() {
        let s = state(Arc::new(MemoryStore {
            fail: true,
            ..Default::default()
        }));
        let p = IncidentPolicy::embedded().unwrap();
        let e = write_for(&s, &claims(1), &p, body(), 100)
            .await
            .unwrap_err();
        assert_eq!(e.0, StatusCode::BAD_GATEWAY);
        assert_eq!(e.1.0["code"], "outcome_write_failed");
    }
    #[tokio::test]
    async fn outcome_audit_never_appends_short_customer_text() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let mut s = state(Arc::new(MemoryStore::default()));
        s.audit = Some(Arc::new(
            crate::audit::AuditChain::new(1000, None, Some(&server.uri())).unwrap(),
        ));
        let policy = IncidentPolicy::embedded().unwrap();
        let reason = "yes";
        let source = "Customer private source label";
        let mut b = body();
        b.subject_kind = "session".into();
        b.subject_id = "jane@example.com".into();
        b.reason = reason.into();
        b.source = source.into();
        let first = write_for(&s, &claims(1), &policy, b.clone(), 100)
            .await
            .unwrap();
        assert_eq!(
            audit_outcome(&first)["subject_id"],
            tracelane_policy::pii::redact("jane@example.com"),
            "subject must be redacted before append"
        );
        b.result = "success".into();
        write_for(&s, &claims(1), &policy, b, 101).await.unwrap();
        s.audit
            .as_ref()
            .unwrap()
            .drain_ledger_writer(std::time::Duration::from_secs(5))
            .await
            .unwrap();
        let requests = server.received_requests().await.unwrap();
        assert!(!requests.is_empty());
        for request in requests {
            let body = request.body;
            let mut bytes = Vec::new();
            let mut at = 0;
            while at + 25 <= body.len() {
                let compressed =
                    u32::from_le_bytes(body[at + 17..at + 21].try_into().unwrap()) as usize;
                let raw = u32::from_le_bytes(body[at + 21..at + 25].try_into().unwrap()) as usize;
                bytes.extend(
                    lz4_flex::block::decompress(&body[at + 25..at + 16 + compressed], raw).unwrap(),
                );
                at += 16 + compressed;
            }
            let text = String::from_utf8_lossy(&bytes);
            assert!(
                !text.contains(reason),
                "short customer reason reached appended audit payload"
            );
            assert!(
                !text.contains(source),
                "short customer source reached appended audit payload"
            );
            assert!(
                !text.contains("jane@example.com"),
                "session email reached appended audit payload"
            );
            for digest in [
                hex::encode(Sha256::digest(reason.as_bytes())),
                hex::encode(Sha256::digest(source.as_bytes())),
            ] {
                assert!(
                    !text.contains(&digest),
                    "customer text digest reached appended audit payload"
                );
            }
            assert!(!text.contains("reason_sha256") && !text.contains("source_sha256"));
            for key in ["reason_len", "source_len"] {
                assert!(text.contains(key), "missing {key}");
            }
            assert!(text.contains("requested"));
        }
    }
    #[test]
    fn outcome_sql_reads_are_tenant_first_and_final() {
        for sql in [
            subject_sql("trace"),
            subject_sql("session"),
            OUTCOME_SQL,
            FAILURES_SQL,
        ] {
            assert!(sql.contains("FINAL WHERE tenant_id = ?"), "{sql}");
        }
        assert!(OUTCOME_SQL.contains("question_id = ''"));
        assert!(
            subject_sql("session").contains("start_time >= now64(6) - toIntervalHour(?) LIMIT 1")
        );
        assert!(!subject_sql("session").contains("count()"));
        assert!(FAILURES_SQL.contains("subject_id IN ?"));
        assert!(FAILURES_SQL.contains("LIMIT ?"));
    }
    #[tokio::test]
    async fn outcome_scope_boundary_keeps_sdk_writes_and_read_only_reads() {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;
        let app = routes().with_state(state(Arc::new(MemoryStore::default())));
        let unauthenticated = app
            .clone()
            .oneshot(
                Request::get(format!("/v1/outcomes?subject={}", uuid::Uuid::from_u128(9)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
        for (scope, get_status, post_status) in [
            ("ingest", StatusCode::FORBIDDEN, StatusCode::OK),
            ("read", StatusCode::OK, StatusCode::FORBIDDEN),
        ] {
            let mut c = claims(1);
            c.key_scope = crate::auth::scope::KeyScope::from_column(Some(&[scope.into()]));
            let _guard = crate::auth::test_claims::Guard::set(c);
            let get = app
                .clone()
                .oneshot(
                    Request::get(format!("/v1/outcomes?subject={}", uuid::Uuid::from_u128(9)))
                        .header("authorization", "Bearer test")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(get.status(), get_status);
            let post = app.clone().oneshot(Request::post("/v1/outcomes").header("authorization", "Bearer test").header("content-type", "application/json")
                .body(Body::from(json!({"subject_kind":"trace","subject_id":uuid::Uuid::from_u128(9).to_string(),"result":"success"}).to_string())).unwrap()).await.unwrap();
            assert_eq!(post.status(), post_status);
        }
    }
    #[tokio::test]
    async fn outcome_idempotency_key_rejects_non_visible_ascii_and_bad_lengths() {
        use axum::body::Body;
        use tower::ServiceExt;
        let store = Arc::new(MemoryStore::default());
        let app = routes().with_state(state(store.clone()));
        let _guard = crate::auth::test_claims::Guard::set(claims(1));
        let payload = json!({"subject_kind":"trace","subject_id":uuid::Uuid::from_u128(9).to_string(),"result":"success"}).to_string();
        for key in [
            vec![],
            vec![b'x'; 256],
            b"has space".to_vec(),
            b"has\ttab".to_vec(),
            vec![0x80],
        ] {
            let response = app
                .clone()
                .oneshot(
                    axum::http::Request::post("/v1/outcomes")
                        .header("authorization", "Bearer test")
                        .header("content-type", "application/json")
                        .header(
                            "idempotency-key",
                            axum::http::HeaderValue::from_bytes(&key).unwrap(),
                        )
                        .body(Body::from(payload.clone()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "invalid key {key:?}"
            );
        }
        assert_eq!(store.writes.load(Ordering::SeqCst), 0);
        for key in ["!".to_string(), "x".repeat(255)] {
            let response = app
                .clone()
                .oneshot(
                    axum::http::Request::post("/v1/outcomes")
                        .header("authorization", "Bearer test")
                        .header("content-type", "application/json")
                        .header("idempotency-key", &key)
                        .body(Body::from(payload.clone()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()["idempotency-key"], key);
        }
    }
    #[tokio::test]
    async fn outcome_http_reserved_values_rate_header_and_echo() {
        use axum::body::{Body, to_bytes};
        use tower::ServiceExt;
        let store = Arc::new(MemoryStore::default());
        let s = state(store.clone());
        let _claims = crate::auth::test_claims::Guard::set(claims(1));
        let app = routes().with_state(s.clone());
        for payload in [
            json!({"subject_kind":"decision","subject_id":"x","result":"success"}),
            json!({"subject_kind":"trace","subject_id":"x","result":"label"}),
        ] {
            let response = app
                .clone()
                .oneshot(
                    axum::http::Request::post("/v1/outcomes")
                        .header("authorization", "Bearer test")
                        .header("content-type", "application/json")
                        .body(Body::from(payload.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let data: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                    .unwrap();
            assert_eq!(data["code"], "not_supported");
        }
        assert_eq!(store.writes.load(Ordering::SeqCst), 0);
        let payload = json!({"subject_kind":"trace","subject_id":uuid::Uuid::from_u128(9).to_string(),"result":"success"});
        let response = app
            .clone()
            .oneshot(
                axum::http::Request::post("/v1/outcomes")
                    .header("authorization", "Bearer test")
                    .header("content-type", "application/json")
                    .header("idempotency-key", "retry-1")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["idempotency-key"], "retry-1");
        let p = IncidentPolicy::embedded().unwrap();
        for _ in 0..p.outcomes_per_minute_per_tenant {
            s.limiter
                .check(&claims(1).tenant_id, Some(p.outcomes_per_minute_per_tenant));
        }
        let response = app
            .clone()
            .oneshot(
                axum::http::Request::post("/v1/outcomes")
                    .header("authorization", "Bearer test")
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(response.headers().contains_key("retry-after"));
        let response = app
            .oneshot(
                axum::http::Request::get(format!(
                    "/v1/outcomes?subject={}",
                    uuid::Uuid::from_u128(9)
                ))
                .header("authorization", "Bearer test")
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key("retry-after"));
    }
}

#[cfg(test)]
mod sql_tests {
    use super::*;
    #[tokio::test]
    async fn outcome_failures_without_sessions_omit_the_session_clause() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::path("/"))
            .respond_with(wiremock::ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let store = ClickHouseOutcomeStore {
            ch: clickhouse::Client::default().with_url(server.uri()),
        };
        let tenant = TenantId::from_jwt_claim(uuid::Uuid::from_u128(7));
        assert!(store.failures(&tenant, &[], &[]).await.unwrap().is_empty());
        assert!(server.received_requests().await.unwrap().is_empty());
        for (traces, sessions) in [
            (vec!["trace-id".into()], vec![]),
            (vec![], vec!["session-id".into()]),
            (vec!["trace-id".into()], vec!["session-id".into()]),
        ] {
            assert!(store.failures(&tenant, &traces, &sessions).await.is_err());
            let requests = server.received_requests().await.unwrap();
            let sql = requests
                .last()
                .unwrap()
                .url
                .query_pairs()
                .find(|(k, _)| k == "query")
                .unwrap()
                .1
                .into_owned();
            assert_eq!(
                sql.contains("subject_kind = 'session'"),
                !sessions.is_empty(),
                "empty sessions must omit the clause: {sql}"
            );
            assert_eq!(
                sql.contains("subject_kind = 'trace'"),
                !traces.is_empty(),
                "empty traces must omit the clause: {sql}"
            );
            assert!(
                !sql.contains("[]"),
                "an empty array has no ClickHouse element type: {sql}"
            );
            assert!(sql.contains(&format!("FINAL WHERE tenant_id = '{}'", tenant)));
            assert!(sql.contains(&format!("LIMIT {}", traces.len() + sessions.len())));
            assert!(!sql.contains('?'));
        }
    }
    #[test]
    fn outcome_migration_reserves_decisions_without_accepting_them() {
        let migration = include_str!("../../../infra/dev/clickhouse/migrations/33_outcomes.sql");
        let schema = include_str!("../../../infra/dev/clickhouse/schema.sql");
        for required in [
            "'decision' = 3",
            "'label' = 3",
            "question_id String DEFAULT ''",
            "actual String DEFAULT ''",
            "ReplacingMergeTree(version)",
            "ORDER BY (tenant_id, subject_kind, subject_id, question_id)",
            "PARTITION BY tuple()",
            "source String",
        ] {
            assert!(migration.contains(required), "missing {required}");
            assert!(schema.contains(required), "missing {required}");
        }
    }
    #[tokio::test]
    async fn outcome_reader_binds_tenant_and_reserves_empty_question_id() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::path("/"))
            .respond_with(wiremock::ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let store = ClickHouseOutcomeStore {
            ch: clickhouse::Client::default().with_url(server.uri()),
        };
        let tenant = TenantId::from_jwt_claim(uuid::Uuid::from_u128(7));
        assert!(store.get(&tenant, "trace", "subject").await.is_err());
        assert!(
            store
                .exists(&tenant, "session", "session", 168)
                .await
                .is_err()
        );
        assert!(
            store
                .failures(&tenant, &["trace-id".into()], &["customer-session'".into()])
                .await
                .is_err()
        );
        for req in server.received_requests().await.unwrap() {
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
            assert!(sql.contains("SETTINGS"));
            assert!(!sql.contains('?'));
        }
    }
}
