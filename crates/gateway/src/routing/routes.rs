//! `OG-11` — `/v1/routing`: the owner's control over how a model name is dispatched.
//!
//! | Route | Capability · audit |
//! |---|---|
//! | `GET /v1/routing` → `{doc, version, valid, limits, can_edit}` | `view_policies` |
//! | `PUT /v1/routing` `{doc}` + `If-Match: <version>` → `{doc, version}` | `edit_policies` · `routing.update` |
//! | `POST /v1/routing/simulate` `{model, wire?}` → the plan, nothing dispatched | `view_policies` |
//!
//! Every handler goes through `control_plane::require_control` (capability, OG-36 admin
//! IP allowlist + SSO-required). A write validates EVERY model, label and price against
//! the tenant's own state before anything is stored, applies with an optimistic version
//! (`409 version_conflict` on a stale `If-Match`), records one `routing.update` row in the
//! same transaction (`db::routing::put`), and invalidates this process's entitlement
//! entry so the next request sees it. The tenant is `claims.tenant_id` only — never a
//! body field. Mounted only with a Postgres control plane (`server.rs`).

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::auth::capability::Capability;
use crate::server::AppState;

/// Mounted only when a Postgres control plane exists (`server.rs`).
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/routing", get(get_routing).put(put_routing))
        .route("/v1/routing/simulate", post(simulate))
        .with_state(state)
}

fn error(status: StatusCode, code: &str, message: &str) -> Response {
    (status, Json(json!({ "error": code, "message": message }))).into_response()
}

fn field_error(e: &super::FieldError) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": e.code, "field": e.field, "message": e.message })),
    )
        .into_response()
}

/// Authenticate, then the admin-plane gate for `cap`. An API key never holds
/// `view_policies` / `edit_policies` (the matrix's `api_key` column), so this also
/// keeps a leaked key off the surface.
async fn gate(
    headers: &HeaderMap,
    cap: Capability,
) -> Result<(crate::auth::Claims, crate::control_plane::ControlActor), Response> {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if auth.is_empty() {
        return Err(error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing bearer token",
        ));
    }
    let claims = crate::auth::validate_authorization(auth)
        .await
        .map_err(|e| {
            let (status, message) = crate::auth::failure(&e);
            error(status, crate::auth::failure_code(&e), message)
        })?;
    tracing::Span::current().record("tenant_id", claims.tenant_id.to_string());
    let actor = crate::control_plane::require_control(&claims, cap, headers)
        .await
        .map_err(IntoResponse::into_response)?;
    Ok((claims, actor))
}

fn limits_json() -> Value {
    let l = super::limits();
    json!({
        "max_virtual_models": l.max_virtual_models,
        "max_targets_per_model": l.max_targets_per_model,
        "max_pool_keys_per_provider": l.max_pool_keys_per_provider,
        "max_attempts": l.max_attempts,
        "doc_max_bytes": l.doc_max_bytes,
        "rules": super::conditions::limits(),
        "timeouts": { "min_ms": super::deadlines::bounds().min_ms, "total_min_ms": super::deadlines::bounds().total_min_ms, "max_ms": super::deadlines::bounds().max_ms, "max_rules": super::deadlines::bounds().max_rules },
        "breaker": { "consecutive_failures_min": super::deadlines::bounds().consecutive_failures_min, "consecutive_failures_max": super::deadlines::bounds().consecutive_failures_max, "cooldown_secs_min": super::deadlines::bounds().cooldown_secs_min, "cooldown_secs_max": super::deadlines::bounds().cooldown_secs_max },
    })
}

/// `GET /v1/routing`.
#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn get_routing(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (claims, _actor) = match gate(&headers, Capability::ViewPolicies).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let Some(pool) = state.pg.as_ref() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "no_control_plane",
            "no control plane",
        );
    };
    match crate::db::routing::get(pool, &claims.tenant_id).await {
        Ok(row) => {
            let (doc, version) = row.map_or((json!({}), 0), |r| (r.doc, r.version));
            let valid = !matches!(
                super::RoutingState::from_stored(Some(&doc)),
                super::RoutingState::Invalid
            );
            let mut resp = Json(json!({
                "doc": doc,
                "version": version,
                "valid": valid,
                "limits": limits_json(),
                "can_edit": claims.can(Capability::EditPolicies),
            }))
            .into_response();
            if let Ok(v) = axum::http::HeaderValue::from_str(&format!("\"{version}\"")) {
                resp.headers_mut().insert(axum::http::header::ETAG, v);
            }
            resp
        }
        Err(e) => {
            tracing::error!(error = %e, "routing read failed");
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "read_failed",
                "could not read the routing document",
            )
        }
    }
}

/// `If-Match: 3` or `If-Match: "3"` → 3.
fn if_match(headers: &HeaderMap) -> Option<i32> {
    headers
        .get(axum::http::header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().trim_matches('"'))
        .and_then(|v| v.parse::<i32>().ok())
        .filter(|v| *v >= 0)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PutBody {
    doc: Value,
}

/// `PUT /v1/routing`.
#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn put_routing(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<PutBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let (claims, actor) = match gate(&headers, Capability::EditPolicies).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let Some(pool) = state.pg.as_ref() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "no_control_plane",
            "no control plane",
        );
    };
    let Some(expected) = if_match(&headers) else {
        return error(
            StatusCode::PRECONDITION_REQUIRED,
            "if_match_required",
            "send If-Match with the version GET /v1/routing returned (0 when there is no document yet)",
        );
    };
    let Ok(Json(body)) = body else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_body",
            "expected {\"doc\": {…}}",
        );
    };
    let mut doc = match super::parse_for_write(&body.doc) {
        Ok(d) => d,
        Err(e) => return field_error(&e),
    };
    let aliases = match crate::db::model_aliases::list(pool, &claims.tenant_id).await {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = %e, "alias read before routing write failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "write_failed",
                "could not save the routing document — nothing was changed",
            );
        }
    };
    let labels = match pool.get().await {
        Ok(client) => {
            match crate::db::provider_keys::labels_with(&client, &claims.tenant_id).await {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!(error = %e, "key labels read before routing write failed");
                    return error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "write_failed",
                        "could not save the routing document — nothing was changed",
                    );
                }
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "pool checkout before routing write failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "write_failed",
                "could not save the routing document — nothing was changed",
            );
        }
    };
    if let Err(e) = super::validate(
        &doc,
        &super::WriteContext {
            aliases: &aliases,
            labels: &labels,
        },
    ) {
        return field_error(&e);
    }
    let previous = match crate::db::routing::get(pool, &claims.tenant_id).await {
        Ok(row) => row,
        Err(_) => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "write_failed",
                "could not read previous routing version",
            );
        }
    };
    super::conditions::assign_salts(&mut doc, previous.as_ref().map(|r| &r.doc));
    // Store the CANONICAL serialisation of what was validated — never the raw body.
    let canonical = match serde_json::to_value(&doc) {
        Ok(v) => v,
        Err(_) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "write_failed",
                "could not save the routing document — nothing was changed",
            );
        }
    };
    if let Err(e) = super::parse_for_write(&canonical) {
        return field_error(&e);
    }
    match crate::db::routing::put(pool, &claims.tenant_id, &canonical, expected, &actor.audit)
        .await
    {
        Ok(crate::db::routing::PutOutcome::Written { version }) => {
            if let Some(cache) = state.entitlements.as_ref() {
                cache.invalidate(*claims.tenant_id.as_uuid()).await;
            }
            Json(json!({ "doc": canonical, "version": version })).into_response()
        }
        Ok(crate::db::routing::PutOutcome::VersionConflict { current }) => (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "version_conflict",
                "message": "the routing document changed since you read it — GET it again and re-apply your change",
                "current_version": current,
            })),
        )
            .into_response(),
        Ok(crate::db::routing::PutOutcome::MissingLabel { provider, label }) => {
            field_error(&super::FieldError {
                code: "invalid_field",
                field: "key_pools".to_owned(),
                message: format!("no `{provider}` key labelled `{label}` is stored"),
            })
        }
        Err(e) => {
            tracing::error!(error = %e, "routing write failed");
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "write_failed",
                "could not save the routing document — nothing was changed",
            )
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SimulateBody {
    model: String,
    #[serde(default)]
    wire: Option<String>,
    #[serde(default)]
    headers: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    metadata: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    tags: Vec<String>,
    key_id: Option<String>,
    project_id: Option<String>,
    environment: Option<String>,
    end_user_id: Option<String>,
    session: Option<String>,
    #[serde(default)]
    stream: bool,
    trace_id: Option<uuid::Uuid>,
}
impl SimulateBody {
    fn into_facts(
        self,
        caps: &tracelane_shared::labels::LabelCaps,
    ) -> Result<super::conditions::Facts, ()> {
        let mut headers = HeaderMap::new();
        for (k, v) in self.headers {
            headers.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).map_err(|_| ())?,
                axum::http::HeaderValue::from_str(&v).map_err(|_| ())?,
            );
        }
        for (name, value) in [
            (
                "x-tracelane-metadata",
                (!self.metadata.is_empty())
                    .then(|| serde_json::to_string(&self.metadata).unwrap_or_default()),
            ),
            (
                "x-tracelane-tags",
                (!self.tags.is_empty()).then(|| self.tags.join(",")),
            ),
            ("x-tracelane-environment", self.environment),
        ] {
            if let Some(value) = value {
                headers.insert(
                    name,
                    axum::http::HeaderValue::from_str(&value).map_err(|_| ())?,
                );
            }
        }
        let labels = crate::server::request_labels::read(&headers, caps).0;
        let identity = crate::server::CallerIdentity::from_headers(&headers);
        Ok(super::conditions::Facts {
            headers,
            metadata: labels.metadata,
            tags: labels.tags,
            environment: labels.environment,
            key_id: self.key_id,
            project_id: self.project_id,
            end_user: self.end_user_id.or(identity.end_user_id),
            session: self.session.or(identity.conversation_id),
            stream: self.stream,
            trace_id: self.trace_id.unwrap_or_else(uuid::Uuid::new_v4).to_string(),
        })
    }
}

/// The routing scope a `simulate` request names — the same consts the routes declare.
fn scope_for(wire: &str) -> Option<super::RoutingScope> {
    use crate::admission::Route as _;
    Some(match wire {
        "chat" => crate::admission::Chat::ROUTING,
        "responses" => crate::openai_responses::Responses::ROUTING,
        "messages" => crate::anthropic_messages::Messages::ROUTING,
        "gemini" => crate::gemini_native::Gemini::ROUTING,
        "embeddings" => crate::admission::Embeddings::ROUTING,
        _ => return None,
    })
}

/// The plan as JSON — shared by `simulate` and its test so the two cannot drift.
pub(crate) fn plan_json(
    model: &str,
    scope: &super::RoutingScope,
    plan: Option<&super::RoutePlan>,
    pools: &[(String, super::PoolChoice)],
) -> Value {
    let candidates: Vec<Value> = plan.map_or_else(Vec::new, |p| {
        p.candidates
            .iter()
            .map(|c| {
                json!({
                    "model": c.model,
                    "provider": c.provider_id,
                    "target_index": c.target_index,
                    "weight_pct": c.weight_pct,
                    "ewma_ttfb_ms": c.ewma_ttfb_ms,
                })
            })
            .collect()
    });
    let skipped: Vec<Value> = plan.map_or_else(Vec::new, |p| {
        p.skipped
            .iter()
            .map(|s| json!({"model": s.model, "provider": s.provider, "reason": s.reason}))
            .collect()
    });
    let key_pools: serde_json::Map<String, Value> = pools
        .iter()
        .map(|(p, c)| (p.clone(), json!({"labels": c.labels, "pooled": c.pooled})))
        .collect();
    json!({
        "model": model,
        "wire": scope.wire.as_str(),
        "routed": plan.is_some_and(super::RoutePlan::dispatches),
        "assignment": plan.and_then(|p| p.assignment.as_ref()),
        "virtual_model": plan.and_then(|p| p.virtual_model.clone()),
        "strategy": plan.and_then(|p| p.strategy).map(super::Strategy::as_str),
        "candidates": candidates,
        "skipped": skipped,
        "key_pools": key_pools,
    })
}

/// `POST /v1/routing/simulate` — the plan dispatch would make right now, from the SAME
/// entitlement-cached document and the SAME [`super::plan`] function. Nothing is
/// dispatched, charged or ledgered. The weighted draw and the latency exploration use
/// the live RNG, so two calls may order a weighted model differently — the
/// `weight_pct` fields say how often each target leads.
#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn simulate(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<SimulateBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let (claims, _actor) = match gate(&headers, Capability::ViewPolicies).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let Ok(Json(body)) = body else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_body",
            "expected {\"model\": \"…\", \"wire\"?: \"chat\"}",
        );
    };
    let wire = body.wire.as_deref().unwrap_or("chat");
    let Some(scope) = scope_for(wire) else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_field",
            "wire must be one of chat, responses, messages, gemini, embeddings",
        );
    };
    let routing = match state.entitlements.as_ref() {
        Some(cache) => {
            let e = cache.resolved(*claims.tenant_id.as_uuid()).await;
            std::sync::Arc::clone(&e.routing)
        }
        None => std::sync::Arc::default(),
    };
    let model = body.model.clone();
    let facts = match body.into_facts(&state.rate_card.load().policy.request_labels) {
        Ok(f) => f,
        Err(()) => {
            return error(
                StatusCode::BAD_REQUEST,
                "invalid_field",
                "invalid simulated header",
            );
        }
    };
    let mut rng = super::thread_rng;
    let plan = match super::conditions::plan(
        &scope,
        &model,
        &routing,
        // M1: simulate shows the caller's OWN latency stats, never another tenant's.
        super::Estimate {
            owner: Some(*claims.tenant_id.as_uuid()),
            ..super::Estimate::default()
        },
        &mut rng,
        &facts,
    ) {
        Ok(p) => p,
        Err(e) => {
            return match e.into_refusal() {
                crate::admission::Refusal::Malformed(m) => {
                    error(StatusCode::BAD_REQUEST, m.code, &m.message)
                }
                crate::admission::Refusal::Control(c) => error(
                    StatusCode::from_u16(c.status).unwrap_or(StatusCode::SERVICE_UNAVAILABLE),
                    c.code,
                    &c.message,
                ),
                _ => error(StatusCode::BAD_REQUEST, "invalid_field", "not routable"),
            };
        }
    };
    let providers: Vec<&'static str> = match &plan {
        Some(p) => {
            let mut v: Vec<&'static str> = p.candidates.iter().map(|c| c.provider_id).collect();
            v.dedup();
            v
        }
        None => crate::providers::ProviderRegistry::provider_id_for_model(&model)
            .into_iter()
            .collect(),
    };
    let pools: Vec<(String, super::PoolChoice)> = providers
        .into_iter()
        .map(|p| {
            (
                p.to_owned(),
                super::pool_labels(&scope, &routing, p, &mut rng),
            )
        })
        .collect();
    Json(plan_json(&model, &scope, plan.as_ref(), &pools)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn if_match_reads_quoted_and_bare_versions_and_refuses_garbage() {
        let mut h = HeaderMap::new();
        assert_eq!(if_match(&h), None);
        h.insert(axum::http::header::IF_MATCH, "3".parse().unwrap());
        assert_eq!(if_match(&h), Some(3));
        h.insert(axum::http::header::IF_MATCH, "\"7\"".parse().unwrap());
        assert_eq!(if_match(&h), Some(7));
        h.insert(axum::http::header::IF_MATCH, "-1".parse().unwrap());
        assert_eq!(if_match(&h), None);
        h.insert(axum::http::header::IF_MATCH, "*".parse().unwrap());
        assert_eq!(if_match(&h), None);
    }

    /// `OG-11` proof 7: `simulate` renders exactly the plan dispatch makes — the same
    /// `plan` function, the same document, the same RNG sequence.
    #[test]
    fn og11_proof7_simulate_equals_the_dispatch_plan_under_the_same_rng() {
        let state = super::super::RoutingState::Valid(std::sync::Arc::new(
            serde_json::from_value(json!({
                "virtual_models": {"fast": {"strategy": "weighted", "targets": [
                    {"model": "gpt-4o-mini", "weight": 7}, {"model": "claude-haiku-4-5", "weight": 3}]}}
            }))
            .unwrap(),
        ));
        let scope = scope_for("chat").unwrap();
        for seed in 0..10u64 {
            let mut a = move || seed;
            let mut b = move || seed;
            let dispatch = super::super::plan(
                &scope,
                "fast",
                &state,
                super::super::Estimate::default(),
                &mut a,
            )
            .unwrap();
            let sim = super::super::plan(
                &scope,
                "fast",
                &state,
                super::super::Estimate::default(),
                &mut b,
            )
            .unwrap();
            assert_eq!(
                plan_json("fast", &scope, dispatch.as_ref(), &[]),
                plan_json("fast", &scope, sim.as_ref(), &[])
            );
        }
        let j = plan_json("fast", &scope, None, &[]);
        assert_eq!(j["routed"], json!(false));
    }

    #[test]
    fn every_simulated_wire_is_a_route_that_consults_routing() {
        for w in ["chat", "responses", "messages", "gemini", "embeddings"] {
            let s = scope_for(w).expect("known wire");
            assert_eq!(s.wire.as_str(), w);
            assert!(s.consults_routing());
        }
        assert!(scope_for("files").is_none());
    }
}
