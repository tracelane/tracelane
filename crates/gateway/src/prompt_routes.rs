//!
//! Always compiled; never a `cfg(feature)` flag or tier-string compare.
//!
//!
//! ADR-009 hybrid pricing: the READ surface (list + resolve + history) AND
//! authoring (create a version — read-adjacent per ADR-054) are available to
//! every authenticated tenant (Builder); the PROMOTION workflow — promote /
//! rollback / observe (the observe feed drives auto-rollback) — is Team+ and
//! gated on `FeatureKey::PromptPromotionWrite` (`f_prompt_promotion_write`, plan
//! defaults overlaid by workspace overrides, deny-overrides-grant). An unentitled
//! tenant gets a typed `403 entitlement_required` with an upgrade pointer and
//! **zero routing mutation** — the check runs before any router call. Fail
//! **closed**: if the entitlement cache is absent (no Postgres), promotions are
//!
//! Routes:
//!   GET  /v1/prompts                       -> list prompts + activity (ADR-054)
//!   GET  /v1/prompts/:name?env=production  -> resolved PromptVersion JSON
//!   POST /v1/prompts/:name/versions        -> author a version (Builder; ADR-054)
//!   GET  /v1/prompts/:name/history         -> promotion history JSON
//!   POST /v1/prompts/:name/promote         -> PromotionDecision JSON (Team+ gated)
//!   POST /v1/prompts/:name/rollback        -> PromotionDecision JSON (Team+ gated)
//!   POST /v1/prompts/:name/observe         -> drift observation + maybe auto-rollback (gated)
//!
//! Tenant identity comes from a validated JWT (or `tlane_` API key) via
//! `crate::auth::validate_authorization`. CLAUDE.md is explicit: `tenant_id`
//! never comes from the request body. The previous `X-Tenant-Id` stand-in
//! has been removed (Move #1 of ADR-011).

#![allow(dead_code)]

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use tracelane_shared::TenantId;

use crate::audit::{AuditChain, AuditEvent};
use crate::auto_rollback::{PromptMetrics, RollbackMode, TriggerMetric};
use crate::entitlement_cache::{EntitlementCache, FeatureKey};
use crate::prompt_router::{DecisionKind, Env, PromotionDecision, PromptRouter};

/// State for the prompt-promotion routes: the shared B1 router plus the
#[derive(Clone)]
pub struct PromptRoutesState {
    pub router: Arc<PromptRouter>,
    /// `None` only when Postgres is unset (no entitlement source) — the write
    /// gate. In production the cache is always present.
    pub entitlements: Option<Arc<EntitlementCache>>,
    /// The tamper-evident hash chain. Every promotion/rollback decision is
    /// appended as an `eval.verdict` event so the promotion record itself is
    /// chained + independently verifiable (wedge item 3). Shared with the chat
    /// hot path via `Arc`.
    pub audit_chain: Arc<AuditChain>,
}

/// String label for a decision kind — reused by the DTO and the chained
/// `eval.verdict` payload so both read identically.
fn decision_kind_str(d: DecisionKind) -> &'static str {
    match d {
        DecisionKind::Promoted => "promoted",
        DecisionKind::BlockedByEval => "blocked_by_eval",
        DecisionKind::BlockedByPolicy => "blocked_by_policy",
        DecisionKind::ManualOverride => "manual_override",
    }
}

/// Append the promotion/rollback decision to the hash chain as a signed
/// `eval.verdict` event (wedge item 3). Fire-and-forget: an append failure is
/// logged and NEVER blocks the promotion response (same posture as the chat
/// hot path's audit append). `eval_run_id` is `null` for a manual override —
/// honest: no eval ran, the gate was explicitly bypassed.
async fn chain_eval_verdict(
    chain: &AuditChain,
    tenant: TenantId,
    actor: &str,
    d: &PromotionDecision,
) {
    let event = AuditEvent {
        tenant_id: tenant,
        event_type: "eval.verdict",
        actor: actor.to_string(),
        payload: serde_json::json!({
            "prompt": d.prompt_name,
            "promotion_id": d.promotion_id,
            "from_env": format!("{:?}", d.from_env).to_lowercase(),
            "to_env": format!("{:?}", d.to_env).to_lowercase(),
            "to_version_id": d.to_version_id,
            "decision": decision_kind_str(d.decision),
            "eval_run_id": d.eval_run_id,
        }),
    };
    if let Err(err) = chain.append(event).await {
        tracing::warn!(error = %err, "eval.verdict chain append failed — promotion still recorded");
    }
}

/// Plug the prompt-promotion routes into an axum Router. Caller adds
/// `.with_state(PromptRoutesState { .. })`.
pub fn routes() -> Router<PromptRoutesState> {
    Router::new()
        .route("/v1/prompts", get(list_handler))
        .route(
            "/v1/prompts/{name}",
            get(get_active_handler).delete(delete_handler),
        )
        .route("/v1/prompts/{name}/versions", post(create_version_handler))
        .route("/v1/prompts/{name}/history", get(history_handler))
        .route("/v1/prompts/{name}/promote", post(promote_handler))
        .route("/v1/prompts/{name}/rollback", post(rollback_handler))
        .route("/v1/prompts/{name}/observe", post(observe_handler))
}

/// Error shape for the WRITE handlers: always a typed JSON body (machine-
type WriteError = (StatusCode, Json<serde_json::Value>);

fn write_err(status: StatusCode, msg: impl Into<String>) -> WriteError {
    (status, Json(serde_json::json!({ "error": msg.into() })))
}

/// the already-validated tenant BEFORE any router mutation.
///
/// # Errors
/// - `403 entitlement_required` (typed, with `upgrade_url`) when the tenant
///   lacks the grant — deny-overrides-grant via the entitlement cache.
/// - `503` when no entitlement cache is wired (fail closed — never serve a
///   paid write path we cannot verify).
async fn require_promotion_write(
    entitlements: &Option<Arc<EntitlementCache>>,
    tenant: &TenantId,
) -> Result<(), WriteError> {
    match entitlements {
        Some(cache) => {
            if cache
                .check(*tenant.as_uuid(), FeatureKey::PromptPromotionWrite)
                .await
            {
                Ok(())
            } else {
                tracing::info!(
                    tenant_id = %tenant,
                    "prompt promotion write denied — tenant lacks f_prompt_promotion_write (Team+ only)"
                );
                Err((
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "error": "entitlement_required",
                        "feature": "prompt_promotion_write",
                        "message": "The Prompt Promotion / Eval Gates / Auto-Rollback write workflow requires the Team plan or above; Builder is read-only.",
                        "upgrade_url": "https://app.tracelane.dev/settings/billing",
                    })),
                ))
            }
        }
        None => {
            tracing::error!(
                "prompt promotion write: entitlement cache unavailable (no Postgres) — denying"
            );
            Err(write_err(
                StatusCode::SERVICE_UNAVAILABLE,
                "entitlement verification unavailable",
            ))
        }
    }
}

#[derive(Debug, Deserialize)]
struct EnvQuery {
    /// dev | staging | production | canary. Defaults to production.
    #[serde(default)]
    env: Option<String>,
}

#[derive(Debug, Serialize)]
struct PromptVersionDto {
    prompt_version_id: Uuid,
    prompt_id: Uuid,
    version_number: u32,
    content: String,
    model_pin: Option<String>,
    sha256_hex: String,
}

#[derive(Debug, Deserialize)]
struct CreateVersionBody {
    content: String,
    #[serde(default)]
    model_pin: Option<String>,
    #[serde(default)]
    template_variables: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct PromoteBody {
    from_env: String,
    to_env: String,
    to_version_id: Uuid,
    eval_run_id: Option<Uuid>,
    /// When present + non-empty, bypass the eval gate and record a
    /// tamper-evident ManualOverride decision (who + reason). The promote
    /// entitlement gate (Team+) still applies. This is how a user promotes to
    /// prod today — the eval gate has no producer of `eval_runs` yet, so the
    /// non-override path 409s; the override is honest because every use writes
    /// a durable, attributed promotion record.
    #[serde(default)]
    override_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RollbackBody {
    env: String,
    to_version_id: Uuid,
    reason: String,
}

#[derive(Debug, Serialize)]
struct PromotionDecisionDto {
    promotion_id: Uuid,
    from_version_id: Option<Uuid>,
    to_version_id: Uuid,
    from_env: String,
    to_env: String,
    eval_run_id: Option<Uuid>,
    decision: &'static str,
    notes: String,
}

impl From<PromotionDecision> for PromotionDecisionDto {
    fn from(d: PromotionDecision) -> Self {
        PromotionDecisionDto {
            promotion_id: d.promotion_id,
            from_version_id: d.from_version_id,
            to_version_id: d.to_version_id,
            from_env: d.from_env.as_str().to_string(),
            to_env: d.to_env.as_str().to_string(),
            eval_run_id: d.eval_run_id,
            decision: decision_kind_str(d.decision),
            notes: d.notes,
        }
    }
}

fn parse_env(s: &str) -> Result<Env, (StatusCode, String)> {
    match s {
        "dev" => Ok(Env::Dev),
        "staging" => Ok(Env::Staging),
        "production" => Ok(Env::Production),
        "canary" => Ok(Env::Canary),
        other => Err((
            StatusCode::BAD_REQUEST,
            format!("invalid env {other:?} — expected dev|staging|production|canary"),
        )),
    }
}

/// Extract a validated `TenantId` from the `Authorization` header.
///
/// Hot-path contract: tenant identity is *only* sourced from a verified
/// JWT (or hashed API key). No `X-Tenant-Id` header, no body field —
/// CLAUDE.md treats this as a tenant-isolation invariant.
async fn tenant_from_auth(headers: &HeaderMap) -> Result<TenantId, (StatusCode, String)> {
    let header = headers.get("authorization").ok_or((
        StatusCode::UNAUTHORIZED,
        "missing Authorization header".into(),
    ))?;
    let header_str = header.to_str().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Authorization must be ASCII".into(),
        )
    })?;
    let claims = crate::auth::validate_authorization(header_str)
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("auth failed: {e}")))?;
    Ok(claims.tenant_id)
}

/// Like [`tenant_from_auth`] but also returns the actor (JWT `sub`) — the
/// authenticated user id — so an override promotion records WHO bypassed the
/// eval gate in the tamper-evident decision.
async fn actor_from_auth(headers: &HeaderMap) -> Result<(TenantId, String), (StatusCode, String)> {
    let header = headers.get("authorization").ok_or((
        StatusCode::UNAUTHORIZED,
        "missing Authorization header".into(),
    ))?;
    let header_str = header.to_str().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Authorization must be ASCII".into(),
        )
    })?;
    let claims = crate::auth::validate_authorization(header_str)
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("auth failed: {e}")))?;
    Ok((claims.tenant_id, claims.sub))
}

#[tracing::instrument(skip(state, headers), fields(prompt_name = %name, tenant_id = tracing::field::Empty))]
async fn get_active_handler(
    State(state): State<PromptRoutesState>,
    Path(name): Path<String>,
    Query(q): Query<EnvQuery>,
    headers: HeaderMap,
) -> Result<Json<PromptVersionDto>, (StatusCode, String)> {
    let tenant = tenant_from_auth(&headers).await?;
    tracing::Span::current().record("tenant_id", tenant.to_string());
    let env = parse_env(q.env.as_deref().unwrap_or("production"))?;
    let v = state
        .router
        .route(tenant, &name, env)
        .await
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;
    Ok(Json(PromptVersionDto {
        prompt_version_id: v.prompt_version_id,
        prompt_id: v.prompt_id,
        version_number: v.version_number,
        content: v.content,
        model_pin: v.model_pin,
        sha256_hex: hex::encode(v.sha256),
    }))
}

/// GET /v1/prompts — the tenant's prompts + activity (ADR-054). Builder-allowed
/// read; tenant from the JWT claim only.
#[tracing::instrument(skip(state, headers), fields(tenant_id = tracing::field::Empty))]
async fn list_handler(
    State(state): State<PromptRoutesState>,
    headers: HeaderMap,
) -> Result<Json<Vec<crate::prompt_router::PromptSummary>>, (StatusCode, String)> {
    let tenant = tenant_from_auth(&headers).await?;
    tracing::Span::current().record("tenant_id", tenant.to_string());
    let prompts = state
        .router
        .list_prompts(&tenant)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    Ok(Json(prompts))
}

/// POST /v1/prompts/{name}/versions — author a new prompt version (ADR-054).
/// **Builder-allowed** — authoring is read-adjacent; promotion to production is
/// the separate Team+ gated action, so NO `require_promotion_write` here. The new
/// version lands in `staging`. Returns 201 + the created version.
#[tracing::instrument(skip(state, headers, body), fields(prompt_name = %name, tenant_id = tracing::field::Empty))]
async fn create_version_handler(
    State(state): State<PromptRoutesState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<CreateVersionBody>,
) -> Result<(StatusCode, Json<PromptVersionDto>), WriteError> {
    let header = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| write_err(StatusCode::UNAUTHORIZED, "missing Authorization header"))?;
    let claims = crate::auth::validate_authorization(header)
        .await
        .map_err(|e| write_err(StatusCode::UNAUTHORIZED, format!("auth failed: {e}")))?;
    tracing::Span::current().record("tenant_id", claims.tenant_id.to_string());
    if body.content.trim().is_empty() {
        return Err(write_err(
            StatusCode::BAD_REQUEST,
            "content must not be empty",
        ));
    }
    let v = state
        .router
        .create_version(
            &claims.tenant_id,
            &name,
            body.content,
            body.model_pin,
            body.template_variables,
            &claims.sub,
        )
        .await
        .map_err(|e| {
            // Log the full chain server-side; return a user-facing message that is
            // safe + non-actionable (an internal store error is not the caller's
            // to fix). Never leak the raw `.context()` string to the UI.
            tracing::error!(error = format!("{e:#}"), prompt_name = %name, "prompt version create failed");
            write_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Couldn't save the prompt version — please try again. The gateway has logged the details.",
            )
        })?;
    Ok((
        StatusCode::CREATED,
        Json(PromptVersionDto {
            prompt_version_id: v.prompt_version_id,
            prompt_id: v.prompt_id,
            version_number: v.version_number,
            content: v.content,
            model_pin: v.model_pin,
            sha256_hex: hex::encode(v.sha256),
        }),
    ))
}

/// **Builder-allowed** — the inverse of authoring (`create_version`), NOT the
/// Team+ promotion gate, so no `require_promotion_write`. Tenant from the JWT
/// claim only. Idempotent: deleting an already-gone prompt still returns 204.
#[tracing::instrument(skip(state, headers), fields(prompt_name = %name, tenant_id = tracing::field::Empty))]
async fn delete_handler(
    State(state): State<PromptRoutesState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, WriteError> {
    let header = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| write_err(StatusCode::UNAUTHORIZED, "missing Authorization header"))?;
    let claims = crate::auth::validate_authorization(header)
        .await
        .map_err(|e| write_err(StatusCode::UNAUTHORIZED, format!("auth failed: {e}")))?;
    tracing::Span::current().record("tenant_id", claims.tenant_id.to_string());
    state
        .router
        .delete_prompt(&claims.tenant_id, &name, &claims.sub)
        .await
        .map_err(|e| {
            tracing::error!(error = format!("{e:#}"), prompt_name = %name, "prompt delete failed");
            write_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Couldn't delete the prompt — please try again. The gateway has logged the details.",
            )
        })?;
    Ok(StatusCode::NO_CONTENT)
}

#[tracing::instrument(skip(state, headers, body), fields(prompt_name = %name, tenant_id = tracing::field::Empty))]
async fn promote_handler(
    State(state): State<PromptRoutesState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<PromoteBody>,
) -> Result<(StatusCode, Json<PromotionDecisionDto>), WriteError> {
    let (tenant, actor) = actor_from_auth(&headers)
        .await
        .map_err(|(s, m)| write_err(s, m))?;
    tracing::Span::current().record("tenant_id", tenant.to_string());
    // unentitled tenant causes zero routing mutation.
    require_promotion_write(&state.entitlements, &tenant).await?;
    let from_env = parse_env(&body.from_env).map_err(|(s, m)| write_err(s, m))?;
    let to_env = parse_env(&body.to_env).map_err(|(s, m)| write_err(s, m))?;

    // eval gate and records a tamper-evident ManualOverride attributed to the
    // actor; otherwise the normal eval-gated path (which 409s until an eval run
    // is supplied). The Team+ entitlement gate above covers both.
    let override_reason = body
        .override_reason
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty());
    // Retain the tenant for the chained eval.verdict (promote() moves it).
    let chain_tenant = tenant.clone();
    let decision = match override_reason {
        Some(reason) => {
            state
                .router
                .promote_with_override(
                    tenant,
                    &name,
                    from_env,
                    to_env,
                    body.to_version_id,
                    &format!("user override by {actor}: {reason}"),
                )
                .await
        }
        None => {
            state
                .router
                .promote(
                    tenant,
                    &name,
                    from_env,
                    to_env,
                    body.to_version_id,
                    body.eval_run_id,
                )
                .await
        }
    }
    .map_err(|e| write_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Decision kind -> HTTP status:
    //   Promoted / ManualOverride -> 200 (the swap happened)
    //   BlockedByEval / BlockedByPolicy -> 409 Conflict (caller must
    //     resolve eval gate or escalate to override)
    let status = match decision.decision {
        DecisionKind::Promoted | DecisionKind::ManualOverride => StatusCode::OK,
        DecisionKind::BlockedByEval | DecisionKind::BlockedByPolicy => StatusCode::CONFLICT,
    };

    // Wedge item 3: chain the promotion decision as a signed eval.verdict.
    chain_eval_verdict(&state.audit_chain, chain_tenant, &actor, &decision).await;

    Ok((status, Json(decision.into())))
}

#[tracing::instrument(skip(state, headers, body), fields(prompt_name = %name, tenant_id = tracing::field::Empty))]
async fn rollback_handler(
    State(state): State<PromptRoutesState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<RollbackBody>,
) -> Result<Json<PromotionDecisionDto>, WriteError> {
    let (tenant, actor) = actor_from_auth(&headers)
        .await
        .map_err(|(s, m)| write_err(s, m))?;
    tracing::Span::current().record("tenant_id", tenant.to_string());
    require_promotion_write(&state.entitlements, &tenant).await?;
    let env = parse_env(&body.env).map_err(|(s, m)| write_err(s, m))?;
    let chain_tenant = tenant.clone();
    let decision = state
        .router
        .rollback(tenant, &name, env, body.to_version_id, &body.reason)
        .await
        .map_err(|e| write_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // Wedge item 3: chain the rollback decision as a signed eval.verdict.
    chain_eval_verdict(&state.audit_chain, chain_tenant, &actor, &decision).await;
    Ok(Json(decision.into()))
}

/// Body for `POST /v1/prompts/:name/observe` — a per-prompt-version metric
/// sample from the observability layer (post-hoc, NOT the gateway hot path).
/// The auto-rollback engine consumes it and, on objective drift in
/// production, flips the routing pointer back to the previous version.
#[derive(Debug, Deserialize)]
struct ObserveBody {
    /// dev | staging | production | canary. Auto-flip only acts on production.
    env: String,
    prompt_version_id: Uuid,
    cost_usd: f64,
    latency_ms: f64,
    #[serde(default)]
    error: bool,
    #[serde(default)]
    guardrail_fired: bool,
    /// Optional — populated by a post-hoc eval pass.
    #[serde(default)]
    accuracy: Option<f64>,
    /// Optional — populated by the SLM-judge hallucination score.
    #[serde(default)]
    hallucination: Option<f64>,
}

#[derive(Debug, Serialize)]
struct ObserveOutcomeDto {
    /// "auto" | "suggested" | null (no drift).
    mode: Option<&'static str>,
    trigger_metric: Option<&'static str>,
    trigger_value: f64,
    ewma_baseline: f64,
    sigma_drift: f32,
    /// Set only when an objective drift auto-flipped the production pointer.
    rolled_back_to: Option<Uuid>,
}

#[tracing::instrument(skip(state, headers, body), fields(prompt_name = %name, tenant_id = tracing::field::Empty))]
async fn observe_handler(
    State(state): State<PromptRoutesState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ObserveBody>,
) -> Result<Json<ObserveOutcomeDto>, WriteError> {
    let tenant = tenant_from_auth(&headers)
        .await
        .map_err(|(s, m)| write_err(s, m))?;
    tracing::Span::current().record("tenant_id", tenant.to_string());
    // ADR-009 Team+ gate as promote/rollback.
    require_promotion_write(&state.entitlements, &tenant).await?;
    let env = parse_env(&body.env).map_err(|(s, m)| write_err(s, m))?;
    let metrics = PromptMetrics {
        cost_usd: body.cost_usd,
        latency_ms: body.latency_ms,
        error: body.error,
        guardrail_fired: body.guardrail_fired,
        accuracy: body.accuracy,
        hallucination: body.hallucination,
    };
    // Retain the tenant for a chained auto-rollback eval.verdict (the call moves it).
    let chain_tenant = tenant.clone();
    let outcome = state
        .router
        .observe_and_maybe_rollback(tenant, &name, env, body.prompt_version_id, &metrics)
        .await
        .map_err(|e| write_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Wedge item 3: an AUTOMATED production flip is chained exactly like a
    // manual one, attributed to the system (no human actor). Only fires when a
    // flip actually happened (Some) — a drift that found no prior version does
    // not mutate the pointer, so nothing to record.
    if let Some(decision) = &outcome.auto_rollback_decision {
        chain_eval_verdict(
            &state.audit_chain,
            chain_tenant,
            "system:auto-rollback",
            decision,
        )
        .await;
    }

    let mode = match outcome.decision.mode {
        Some(RollbackMode::Auto) => Some("auto"),
        Some(RollbackMode::Suggested) => Some("suggested"),
        Some(RollbackMode::HumanConfirmed) => Some("human_confirmed"),
        Some(RollbackMode::HumanDismissed) => Some("human_dismissed"),
        None => None,
    };
    let trigger_metric = outcome.decision.trigger_metric.map(|m| match m {
        TriggerMetric::Cost => "cost",
        TriggerMetric::Latency => "latency",
        TriggerMetric::ErrorRate => "error_rate",
        TriggerMetric::GuardrailFire => "guardrail_fire",
        TriggerMetric::Accuracy => "accuracy",
        TriggerMetric::Hallucination => "hallucination",
    });
    Ok(Json(ObserveOutcomeDto {
        mode,
        trigger_metric,
        trigger_value: outcome.decision.trigger_value,
        ewma_baseline: outcome.decision.ewma_baseline,
        sigma_drift: outcome.decision.sigma_drift,
        rolled_back_to: outcome.rolled_back_to,
    }))
}

#[derive(Debug, Deserialize)]
struct HistoryQuery {
    /// Max entries (clamped 1..=500, defaults to 50).
    #[serde(default)]
    limit: Option<u32>,
}

#[tracing::instrument(skip(state, headers), fields(prompt_name = %name, tenant_id = tracing::field::Empty))]
async fn history_handler(
    State(state): State<PromptRoutesState>,
    Path(name): Path<String>,
    Query(q): Query<HistoryQuery>,
    headers: HeaderMap,
) -> Result<Json<Vec<crate::prompt_history::HistoryEntry>>, (StatusCode, String)> {
    let tenant = tenant_from_auth(&headers).await?;
    tracing::Span::current().record("tenant_id", tenant.to_string());
    let limit = q.limit.unwrap_or(50);
    let reader = state.router.history_reader();
    let entries = reader
        .read(&tenant, &name, limit)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(entries))
}

//
// Drives the REAL handlers (auth → entitlement gate → router) via the
// `tlane_` dev-stub auth path (debug-only: active when WORKOS_CLIENT_ID is
// observable end-states: the routing pointer either flipped or it did not.
#[cfg(test)]
#[cfg(debug_assertions)]
mod tests {
    use super::*;
    use crate::entitlement_cache::ResolvedEntitlements;
    use std::pin::Pin;

    // Env is process-global; serialize these tests' dev-stub env twiddle.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Runtime::new().unwrap()
    }

    /// Enables the debug `tlane_` dev-stub auth path (no WorkOS) and restores
    /// the prior env on drop so it can't leak across tests.
    struct DevAuthEnv {
        client: Option<String>,
        dev: Option<String>,
    }
    impl DevAuthEnv {
        fn enable() -> Self {
            let client = std::env::var("WORKOS_CLIENT_ID").ok();
            let dev = std::env::var("TRACELANE_DEV_AUTH").ok();
            unsafe {
                std::env::remove_var("WORKOS_CLIENT_ID");
                std::env::remove_var("TRACELANE_DEV_AUTH");
            }
            Self { client, dev }
        }
    }
    impl Drop for DevAuthEnv {
        fn drop(&mut self) {
            unsafe {
                match &self.client {
                    Some(v) => std::env::set_var("WORKOS_CLIENT_ID", v),
                    None => std::env::remove_var("WORKOS_CLIENT_ID"),
                }
                match &self.dev {
                    Some(v) => std::env::set_var("TRACELANE_DEV_AUTH", v),
                    None => std::env::remove_var("TRACELANE_DEV_AUTH"),
                }
            }
        }
    }

    /// A cache that resolves EVERY tenant to a fixed
    /// `f_prompt_promotion_write` grant.
    fn fixed_entitlement(granted: bool) -> Arc<EntitlementCache> {
        Arc::new(EntitlementCache::new(Arc::new(move |_tenant: Uuid| {
            Box::pin(async move {
                Ok(ResolvedEntitlements {
                    f_prompt_promotion_write: granted,
                    ..ResolvedEntitlements::deny_all()
                })
            })
                as Pin<
                    Box<
                        dyn std::future::Future<Output = anyhow::Result<ResolvedEntitlements>>
                            + Send,
                    >,
                >
        })))
    }

    fn auth_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer tlane_b074gateconftestkey0123456789"
                .parse()
                .unwrap(),
        );
        headers
    }

    /// Seed one registered prompt version and return `(state, version_id)`.
    fn seeded_state(entitlements: Option<Arc<EntitlementCache>>) -> (PromptRoutesState, Uuid) {
        let router = Arc::new(PromptRouter::new());
        let version_id = Uuid::from_u128(0xB074);
        router.register_version(crate::prompt_router::PromptVersion {
            prompt_version_id: version_id,
            prompt_id: Uuid::from_u128(0xB074_0001),
            version_number: 1,
            content: "You are the gate-test prompt.".into(),
            model_pin: None,
            sha256: [0u8; 32],
        });
        (
            PromptRoutesState {
                router,
                entitlements,
                audit_chain: Arc::new(AuditChain::new(100, None, None).unwrap()),
            },
            version_id,
        )
    }

    async fn call_promote(
        state: &PromptRoutesState,
        version_id: Uuid,
    ) -> Result<(StatusCode, Json<PromotionDecisionDto>), WriteError> {
        promote_handler(
            State(state.clone()),
            Path("gate-test".to_string()),
            auth_headers(),
            Json(PromoteBody {
                from_env: "staging".into(),
                to_env: "production".into(),
                to_version_id: version_id,
                eval_run_id: Some(Uuid::from_u128(0xEA71)), // PermissiveGate → Passed
                override_reason: None,
            }),
        )
        .await
    }

    async fn call_promote_override(
        state: &PromptRoutesState,
        version_id: Uuid,
        reason: &str,
    ) -> Result<(StatusCode, Json<PromotionDecisionDto>), WriteError> {
        promote_handler(
            State(state.clone()),
            Path("gate-test".to_string()),
            auth_headers(),
            Json(PromoteBody {
                from_env: "staging".into(),
                to_env: "production".into(),
                to_version_id: version_id,
                eval_run_id: None, // no eval run → normal path would 409
                override_reason: Some(reason.to_string()),
            }),
        )
        .await
    }

    async fn call_get_active(
        state: &PromptRoutesState,
    ) -> Result<Json<PromptVersionDto>, (StatusCode, String)> {
        get_active_handler(
            State(state.clone()),
            Path("gate-test".to_string()),
            Query(EnvQuery {
                env: Some("production".into()),
            }),
            auth_headers(),
        )
        .await
    }

    // authenticated tenant WITHOUT the Team+ grant must get a typed 403 AND
    // the routing pointer must not flip (zero mutation — the end-state).
    #[test]
    fn promote_without_entitlement_gets_403_and_no_routing_mutation() {
        let _g = ENV_LOCK.lock().expect("env lock");
        let _env = DevAuthEnv::enable();
        rt().block_on(async {
            let (state, version_id) = seeded_state(Some(fixed_entitlement(false)));

            let err = call_promote(&state, version_id)
                .await
                .expect_err("unentitled promote must be refused");
            assert_eq!(err.0, StatusCode::FORBIDDEN);
            let body = err.1.0.to_string();
            assert!(body.contains("entitlement_required"), "body: {body}");
            assert!(body.contains("prompt_promotion_write"), "body: {body}");
            assert!(body.contains("upgrade_url"), "body: {body}");

            // End-state: the production pointer never flipped.
            let read = call_get_active(&state).await;
            assert!(
                matches!(read, Err((StatusCode::NOT_FOUND, _))),
                "403'd promote must leave no routing pointer"
            );
        });
    }

    // A tenant WITH the grant promotes, and the pointer observably flips.
    #[test]
    fn promote_with_entitlement_flips_the_production_pointer() {
        let _g = ENV_LOCK.lock().expect("env lock");
        let _env = DevAuthEnv::enable();
        rt().block_on(async {
            let (state, version_id) = seeded_state(Some(fixed_entitlement(true)));

            let (status, Json(dto)) = call_promote(&state, version_id)
                .await
                .expect("entitled promote must succeed");
            assert_eq!(status, StatusCode::OK);
            assert_eq!(dto.decision, "promoted");

            // End-state: the promoted version now resolves in production.
            let Json(v) = call_get_active(&state)
                .await
                .expect("promoted version must resolve");
            assert_eq!(v.prompt_version_id, version_id);
            assert_eq!(v.content, "You are the gate-test prompt.");
        });
    }

    // path would 409), flips the pointer, and records an attributed
    // ManualOverride — the tamper-evident record that keeps this honest.
    #[test]
    fn promote_with_override_reason_flips_and_records_actor() {
        let _g = ENV_LOCK.lock().expect("env lock");
        let _env = DevAuthEnv::enable();
        rt().block_on(async {
            let (state, version_id) = seeded_state(Some(fixed_entitlement(true)));

            let (status, Json(dto)) = call_promote_override(&state, version_id, "prod hotfix")
                .await
                .expect("override promote must succeed");
            assert_eq!(status, StatusCode::OK);
            assert_eq!(dto.decision, "manual_override");
            // The reason is captured in the durable decision note (who + why).
            assert!(dto.notes.contains("override"), "notes: {}", dto.notes);
            assert!(dto.notes.contains("prod hotfix"), "notes: {}", dto.notes);

            // End-state: the production pointer flipped despite no eval run.
            let Json(v) = call_get_active(&state)
                .await
                .expect("override-promoted version must resolve");
            assert_eq!(v.prompt_version_id, version_id);
        });
    }

    // The override still respects the Team+ gate — an unentitled tenant is 403'd
    // before any routing mutation, override reason or not.
    #[test]
    fn promote_override_without_entitlement_still_403s() {
        let _g = ENV_LOCK.lock().expect("env lock");
        let _env = DevAuthEnv::enable();
        rt().block_on(async {
            let (state, version_id) = seeded_state(Some(fixed_entitlement(false)));
            let err = call_promote_override(&state, version_id, "sneaky")
                .await
                .expect_err("unentitled override must be refused");
            assert_eq!(err.0, StatusCode::FORBIDDEN);
            let read = call_get_active(&state).await;
            assert!(
                matches!(read, Err((StatusCode::NOT_FOUND, _))),
                "403'd override must leave no routing pointer"
            );
        });
    }

    // Fail closed: no entitlement source (no Postgres) → 503, no mutation.
    #[test]
    fn missing_entitlement_cache_fails_closed_503() {
        let _g = ENV_LOCK.lock().expect("env lock");
        let _env = DevAuthEnv::enable();
        rt().block_on(async {
            let (state, version_id) = seeded_state(None);
            let err = call_promote(&state, version_id)
                .await
                .expect_err("no entitlement source must fail closed");
            assert_eq!(err.0, StatusCode::SERVICE_UNAVAILABLE);
            let read = call_get_active(&state).await;
            assert!(matches!(read, Err((StatusCode::NOT_FOUND, _))));
        });
    }

    // rollback + observe are the same write workflow — both gated.
    #[test]
    fn rollback_and_observe_without_entitlement_get_403() {
        let _g = ENV_LOCK.lock().expect("env lock");
        let _env = DevAuthEnv::enable();
        rt().block_on(async {
            let (state, version_id) = seeded_state(Some(fixed_entitlement(false)));

            let rb = rollback_handler(
                State(state.clone()),
                Path("gate-test".to_string()),
                auth_headers(),
                Json(RollbackBody {
                    env: "production".into(),
                    to_version_id: version_id,
                    reason: "gate test".into(),
                }),
            )
            .await
            .expect_err("unentitled rollback must be refused");
            assert_eq!(rb.0, StatusCode::FORBIDDEN);
            assert!(rb.1.0.to_string().contains("entitlement_required"));

            let ob = observe_handler(
                State(state.clone()),
                Path("gate-test".to_string()),
                auth_headers(),
                Json(ObserveBody {
                    env: "production".into(),
                    prompt_version_id: version_id,
                    cost_usd: 0.01,
                    latency_ms: 50.0,
                    error: false,
                    guardrail_fired: false,
                    accuracy: None,
                    hallucination: None,
                }),
            )
            .await
            .expect_err("unentitled observe must be refused");
            assert_eq!(ob.0, StatusCode::FORBIDDEN);
            assert!(ob.1.0.to_string().contains("entitlement_required"));
        });
    }

    // ADR-009 Builder read-only: the READ surface stays open to an
    // authenticated tenant with NO write grant.
    #[test]
    fn read_path_stays_open_without_write_entitlement() {
        let _g = ENV_LOCK.lock().expect("env lock");
        let _env = DevAuthEnv::enable();
        rt().block_on(async {
            // Seed a production pointer directly on the router (the router
            // itself is not the gate — the HTTP write surface is).
            let (state, version_id) = seeded_state(Some(fixed_entitlement(false)));
            let tenant =
                crate::auth::validate_authorization("Bearer tlane_b074gateconftestkey0123456789")
                    .await
                    .expect("dev-stub auth")
                    .tenant_id;
            state
                .router
                .promote(
                    tenant,
                    "gate-test",
                    Env::Staging,
                    Env::Production,
                    version_id,
                    Some(Uuid::from_u128(0xEA71)),
                )
                .await
                .expect("direct router promote (test seed)");

            // Builder-tier read: resolves fine with the write grant denied.
            let Json(v) = call_get_active(&state)
                .await
                .expect("read surface must stay open (Builder read-only)");
            assert_eq!(v.prompt_version_id, version_id);
        });
    }
}
