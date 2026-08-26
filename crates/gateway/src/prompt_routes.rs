//! HTTP routes for B1 Prompt Promotion (per ADR-009 /).
//!
//! Always compiled; never a `cfg(feature)` flag or tier-string compare.
//!
//! ## Entitlement gate (/ ADR-009)
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
//! refused (503), mirroring the audit-export gate.
//!
//! Routes:
//!   GET  /v1/prompts                       -> list prompts + activity (ADR-054)
//!   GET  /v1/prompts/:name?env=production  -> resolved PromptVersion JSON
//!   DELETE /v1/prompts:name -> soft-delete (archive) a prompt (Builder;)
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
/// entitlement cache backing the ADR-009 Team+ write gate.
#[derive(Clone)]
pub struct PromptRoutesState {
    pub router: Arc<PromptRouter>,
    /// `None` only when Postgres is unset (no entitlement source) — the write
    /// gate then FAILS CLOSED (503), same posture as the audit-export
    /// gate. In production the cache is always present.
    pub entitlements: Option<Arc<EntitlementCache>>,
    /// The tamper-evident hash chain. Every promotion/rollback decision is
    /// appended as an `eval.verdict` event so the promotion record itself is
    /// chained + independently verifiable (wedge item 3). Shared with the chat
    /// hot path via `Arc`.
    pub audit_chain: Arc<AuditChain>,
    /// `EVL-05`. `None` when `CLICKHOUSE_URL` is unset — the eval routes then
    /// answer a typed `503` saying so, rather than 404ing as though the feature
    /// did not exist. A feature that is configured-off and a feature that is
    /// absent are different facts.
    pub eval: Option<Arc<crate::prompt_eval::PromptEvalEngine>>,
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
        // EVL-05 — the eval-runs writer. `POST` starts a run (202) because a
        // real run takes minutes; the two `GET`s poll it.
        .route(
            "/v1/prompts/{name}/evals",
            post(start_eval_handler).get(list_evals_handler),
        )
        .route("/v1/prompts/{name}/evals/{run_id}", get(get_eval_handler))
}

/// Input ceilings for prompt writes.
///
/// There is **no Tower layer on the prompt sub-router** — the only layer on the
/// whole app is `TraceLayer` — so nothing between the socket and these handlers
/// bounds a body. Every value here is enforced in the handler because there is
/// nowhere else for it to happen. Each cap is refused with a typed `400` naming
/// the limit, never silently truncated: a prompt that was quietly cut short
/// would be served to a model as if it were what the author wrote.
mod limits {
    /// Prompt body. Generous — long system prompts with embedded few-shot
    /// examples are normal — but bounded: `content` is stored verbatim in
    /// ClickHouse and returned on every read.
    pub const CONTENT_BYTES: usize = 256 * 1024;
    /// Declared template variables. They are stored and never substituted by the
    /// gateway, so a large array is pure storage cost.
    pub const TEMPLATE_VARS: usize = 64;
    pub const TEMPLATE_VAR_BYTES: usize = 128;
    /// Prompt name. It is a routing key and a UUIDv5 input, not free text.
    pub const NAME_BYTES: usize = 128;
}

/// Reject a prompt `name` that is not a routing key.
///
/// The name is one half of `prompt_id_for` (UUIDv5 over `"{tenant}:{name}"`) and
/// one third of the in-memory routing key, so it is an identifier rather than a
/// label. Restricting the charset keeps it printable in a URL path, a log line
/// and a ClickHouse `LowCardinality(String)` without escaping.
fn validate_prompt_name(name: &str) -> Result<(), (StatusCode, String)> {
    if name.is_empty() || name.len() > limits::NAME_BYTES {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "prompt name must be 1-{} bytes (got {})",
                limits::NAME_BYTES,
                name.len()
            ),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "prompt name may contain only ASCII letters, digits, '-', '_' and '.'".into(),
        ));
    }
    Ok(())
}

/// Error shape for the WRITE handlers: always a typed JSON body (machine-
/// readable `error` code), matching the gate + hard-cap 429 style.
type WriteError = (StatusCode, Json<serde_json::Value>);

fn write_err(status: StatusCode, msg: impl Into<String>) -> WriteError {
    let msg = msg.into();
    // Some callers hand us a fully-formed JSON OBJECT as a string —
    // `auth::role_forbidden_json` and the A13 scope refusal both do. Wrapping
    // one of those in `{"error": …}` DOUBLE-ENCODES it, so the client receives
    //
    //     {"error":"{\"error\":\"…\",\"required_scope\":\"admin\"}"}
    //
    // and the machine-readable fields those bodies exist to carry —
    // `required_scope`, `required_role`, `type` — arrive escaped inside a
    // string. `body.error.required_scope` is `undefined`; reading it needs a
    // second parse the caller has no reason to expect.
    //
    // OBSERVED ON PROD 2026-08-19, not inferred: a real `403` from the scope
    // gate came back nested. The tests could not see it because they assert
    // with `contains()`, which passes on either shape — the substring is
    // present either way. Only a live request showed it.
    //
    // Pass an object through untouched; wrap anything else.
    match serde_json::from_str::<serde_json::Value>(&msg) {
        Ok(v) if v.is_object() => (status, Json(v)),
        _ => (status, Json(serde_json::json!({ "error": msg }))),
    }
}

/// ADR-009 Team+ write gate. Checks `f_prompt_promotion_write` for
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
    /// entitlement gate (Team+) still applies.
    ///
    /// This comment previously said the gate "has no producer of `eval_runs`
    /// yet, so the non-override path 409s". That stopped being true when EVL-05
    /// landed: `prompt_eval.rs` IS the `eval_runs` writer and
    /// `POST /v1/prompts/{name}/evals` starts a run. So the non-override path
    /// now SUCCEEDS against a passing run and 409s only on `BlockedByEval`.
    /// The override remains available and is honest because every use writes a
    /// durable, attributed promotion record with `eval_run_id: null`.
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
    // A13 scope gate on the READ surfaces (`GET /v1/prompts`,
    // `GET /v1/prompts/{name}`, `.../history`). Prompt CONTENT is the tenant's
    // intellectual property; before this an `ingest`-scoped SDK key — the
    // credential that ships inside a customer's container image, default-on
    // since GWY-41 — could read every prompt in the workspace. That is the same
    // exfiltration shape B-230 closed on `tool_analytics`, `billing/usage` and
    // the audit routes, left open here.
    if !claims.allows_scope(crate::auth::scope::Scope::Read) {
        tracing::warn!(sub = %claims.sub, "api key lacks the `read` scope");
        return Err((
            StatusCode::FORBIDDEN,
            serde_json::json!({
                "error": "This API key is not scoped to read recorded data. It needs \
                          the `read` scope.",
                "type": "insufficient_scope",
                "required_scope": "read",
            })
            .to_string(),
        ));
    }
    Ok(claims.tenant_id)
}

/// Like [`tenant_from_auth`] but also returns the actor (JWT `sub`) — the
/// authenticated user id — so an override promotion records WHO bypassed the
/// eval gate in the tamper-evident decision.
/// The authorization half of [`actor_from_auth`], split out so each write
/// surface can be driven with real `viewer` / API-key claims in a test —
/// `validate_authorization` needs a signed token, and a gate that can only be
/// exercised through one is a gate that gets asserted by description.
fn authorize_write(claims: &crate::auth::Claims) -> Result<(), (StatusCode, String)> {
    if !claims.can_write_prompts() {
        return Err((
            StatusCode::FORBIDDEN,
            crate::auth::role_forbidden_json("owner"),
        ));
    }
    // A13 scope gate. THE ROLE GATE ABOVE IS NOT A SCOPE GATE, and until this
    // line the difference was load-bearing: `can_write_prompts` matches the
    // `role: None` arm for ANY `AuthMethod::ApiKey` without ever reading
    // `key_scope`, so every scoped key — including a `read`-only key, the one
    // `api_scope.rs:47-49` calls "the scope an external auditor should be given,
    // and nothing else" — could author versions, archive a prompt, promote to
    // production and roll back.
    //
    // B-230 audited this surface and fixed the ROLE half (a viewer JWT could
    // flip prod routing); the scope half survived that audit because the
    // structural guard `every_b230_route_gates_on_scope_after_authenticating`
    // checks the other five files for a scope needle and checks this one only
    // for `actor_from_auth`.
    //
    // `Admin` is the right scope, not `Chat`: these routes move production
    // traffic and mutate workspace configuration, which is what
    // `api_scope.rs`'s own doc defines `Admin` as. Blast radius measured
    // against prod before choosing it — 12 live keys are `scope IS NULL`
    // (`LegacyFullSurface`, allows everything, unchanged) and every
    // JWT-authenticated dashboard session is also `LegacyFullSurface`, so only
    // explicitly-scoped machine keys are narrowed.
    if !claims.allows_scope(crate::auth::scope::Scope::Admin) {
        tracing::warn!(
            sub = %claims.sub,
            "api key lacks the `admin` scope — refusing prompt write"
        );
        return Err((
            StatusCode::FORBIDDEN,
            serde_json::json!({
                "error": "This API key is not scoped to manage prompts. Promoting, \
                          rolling back, authoring and deleting change production \
                          routing; they need the `admin` scope. Mint a new key with \
                          it in Settings → API Keys.",
                "type": "insufficient_scope",
                "required_scope": "admin",
            })
            .to_string(),
        ));
    }
    Ok(())
}

/// Authenticate **and authorize** a prompt WRITE. One site, all FIVE write
/// surfaces (A8/EVL-18, 2026-08-11; `/observe` added 2026-08-13 by B-230).
///
/// Before this, the only gate was `require_promotion_write` — a *tenant
/// entitlement* asking whether the workspace paid, never whether the caller is
/// allowed. A `viewer` in a Team workspace could flip the production pointer.
///
/// Single-site by construction, following PL-9: `create_version` and `delete`
/// used to inline their own auth and were therefore easy to miss, and
/// `rollback` — a fourth write surface the finding did not name — flips the
/// production pointer just as `promote` does. **And `/observe` was a fifth,
/// missed again for the same reason: it does not look like a write.** It feeds
/// the auto-rollback engine, which moves the production pointer on its own.
/// Five call sites, one predicate.
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
    authorize_write(&claims)?;
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
    let (tenant_id, actor) = actor_from_auth(&headers)
        .await
        .map_err(|(s, m)| write_err(s, m))?;
    tracing::Span::current().record("tenant_id", tenant_id.to_string());
    validate_prompt_name(&name).map_err(|(st, m)| write_err(st, m))?;
    if body.content.trim().is_empty() {
        return Err(write_err(
            StatusCode::BAD_REQUEST,
            "content must not be empty",
        ));
    }
    if body.content.len() > limits::CONTENT_BYTES {
        return Err(write_err(
            StatusCode::BAD_REQUEST,
            format!(
                "content is {} bytes; the limit is {}",
                body.content.len(),
                limits::CONTENT_BYTES
            ),
        ));
    }
    if body.template_variables.len() > limits::TEMPLATE_VARS {
        return Err(write_err(
            StatusCode::BAD_REQUEST,
            format!(
                "at most {} template_variables (got {})",
                limits::TEMPLATE_VARS,
                body.template_variables.len()
            ),
        ));
    }
    if let Some(too_long) = body
        .template_variables
        .iter()
        .find(|v| v.len() > limits::TEMPLATE_VAR_BYTES)
    {
        return Err(write_err(
            StatusCode::BAD_REQUEST,
            format!(
                "template_variable is {} bytes; the limit is {}",
                too_long.len(),
                limits::TEMPLATE_VAR_BYTES
            ),
        ));
    }
    let v = state
        .router
        .create_version(
            &tenant_id,
            &name,
            body.content,
            body.model_pin,
            body.template_variables,
            &actor,
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

/// DELETE /v1/prompts/{name} — soft-delete (archive) a prompt.
/// **Builder-allowed** — the inverse of authoring (`create_version`), NOT the
/// Team+ promotion gate, so no `require_promotion_write`. Tenant from the JWT
/// claim only. Idempotent: deleting an already-gone prompt still returns 204.
#[tracing::instrument(skip(state, headers), fields(prompt_name = %name, tenant_id = tracing::field::Empty))]
async fn delete_handler(
    State(state): State<PromptRoutesState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, WriteError> {
    let (tenant_id, actor) = actor_from_auth(&headers)
        .await
        .map_err(|(s, m)| write_err(s, m))?;
    tracing::Span::current().record("tenant_id", tenant_id.to_string());
    state
        .router
        .delete_prompt(&tenant_id, &name, &actor)
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
    // ADR-009 Team+ write gate — BEFORE any parse/route work so an
    // unentitled tenant causes zero routing mutation.
    require_promotion_write(&state.entitlements, &tenant).await?;
    let from_env = parse_env(&body.from_env).map_err(|(s, m)| write_err(s, m))?;
    let to_env = parse_env(&body.to_env).map_err(|(s, m)| write_err(s, m))?;

    // An explicit override reason bypasses the (currently producer-less)
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
                    Some(actor.as_str()),
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
                    Some(actor.as_str()),
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
    // ADR-009 Team+ write gate.
    require_promotion_write(&state.entitlements, &tenant).await?;
    let env = parse_env(&body.env).map_err(|(s, m)| write_err(s, m))?;
    let chain_tenant = tenant.clone();
    let decision = state
        .router
        .rollback(
            tenant,
            &name,
            env,
            body.to_version_id,
            &body.reason,
            Some(actor.as_str()),
        )
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
    // B-230: `/observe` is the FIFTH prompt WRITE surface and it used
    // `tenant_from_auth` — authentication with NO role check — while the other
    // four use `actor_from_auth` -> `authorize_write`. Its own comment below
    // already says this feed drives auto-rollback, and auto-rollback FLIPS THE
    // PRODUCTION ROUTING POINTER. So a `viewer` could move production prompt
    // routing: exactly the hole A8/EVL-18 closed for promote/rollback/
    // create_version/delete, left open on the one surface that finding did not
    // enumerate. `actor_from_auth` is the single site — this is now its fifth
    // caller, and the doc above it has been corrected to say five.
    let (tenant, _sub) = actor_from_auth(&headers)
        .await
        .map_err(|(s, m)| write_err(s, m))?;
    tracing::Span::current().record("tenant_id", tenant.to_string());
    // The observe feed drives auto-rollback (a write workflow) — same
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

/// `POST /v1/prompts/{name}/evals` — start an eval run (EVL-05).
///
/// **Gated as a WRITE, not a read**, and that is deliberate: a run spends the
/// tenant's provider money, so it needs the same owner/machine role and `admin`
/// scope as promotion. It is NOT entitlement-gated — measuring is free, only
/// PROMOTING is the paid act, which matches `create_version`.
///
/// **`EVL-23` narrows that by exactly one capability, and the narrowing is the
/// point.** A run that asks for an `llm_judge` assertion needs
/// `f_prompt_promotion_write`; a run without one is untouched. The judge is a
/// SECOND provider call per case on the tenant's own key, so it is the new paid
/// capability — and gating it is not the same as gating the route.
///
/// **What was considered and rejected: gating the whole route.** `EVL-23` §2.7
/// proposed adding `require_promotion_write` unconditionally, arguing the module
/// header sells this surface as Team+. It does not — the header's Team+
/// enumeration is at `:9-10` and reads *"the PROMOTION workflow — promote /
/// rollback / observe … — is Team+"*, which excludes evals (re-verified
/// 2026-08-24, the one NEVER_TRUE finding of that pass). Doing it anyway would
/// have been a breaking authorization change to a shipped route, argued from a
/// misreading, on a money path item 9 had already capped with the workspace
/// budget below.
#[tracing::instrument(skip(state, headers, body), fields(prompt_name = %name, tenant_id = tracing::field::Empty))]
async fn start_eval_handler(
    State(state): State<PromptRoutesState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<crate::prompt_eval::EvalRunRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), WriteError> {
    let (tenant, _actor) = actor_from_auth(&headers)
        .await
        .map_err(|(s, m)| write_err(s, m))?;
    tracing::Span::current().record("tenant_id", tenant.to_string());
    let Some(engine) = state.eval.clone() else {
        return Err(write_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "eval runs need a ClickHouse connection and this gateway has none configured",
        ));
    };
    // ── THE MONEY CAP (spec `EVL-02` §2.5, founder ruling R83.2) ────────────
    //
    // A run is N real provider calls started by one request, and until now this
    // surface had no ceiling at all — not a rate limit, not a quota, not a
    // budget. The chat path has enforced the workspace budget since GWY-43; an
    // eval run spends from the SAME wallet and was simply not asked. Checked
    // BEFORE the slot is claimed and before a cent is spent, and the counter is
    // seeded from the durable ClickHouse total first (: an in-memory counter
    // alone is not a cap, because a redeploy forgives every dollar accrued).
    // ── `EVL-23`: the JUDGE is Team+, the eval route is not. ───────────────
    //
    // Checked BEFORE the budget seed and before the slot is claimed, so an
    // unentitled tenant is refused without a ClickHouse round trip and without
    // holding a slot. `require_promotion_write`'s `None` arm returns 503 rather
    // than granting — `.claude/rules/tenancy.md`, absent cache is the
    // unprivileged state — so no control plane means no judge, never a free one.
    if body.uses_judge() {
        require_promotion_write(&state.entitlements, &tenant).await?;
    }
    let budget_usd = crate::spend::workspace_budget_usd(state.entitlements.as_ref(), &tenant).await;
    if budget_usd.is_some() {
        crate::spend::seed_workspace(engine.clickhouse(), &tenant).await;
        let who = crate::spend::Subject::Workspace(*tenant.as_uuid());
        if let Some(body) = crate::spend::workspace_refusal(who, budget_usd) {
            return Err(write_err(StatusCode::PAYMENT_REQUIRED, body.to_string()));
        }
    }
    let ctx = crate::prompt_eval::RunContext {
        budget_usd,
        // A standalone run belongs to no experiment. `None` here is what keeps
        // `tracelane_experiment_id` off its spans, which is what lets the compare
        // and cost surfaces tell an experiment's spend from an ad-hoc run's.
        arm: None,
    };
    match engine.start_run(tenant, &name, body, ctx).await {
        Ok(started) => Ok((
            StatusCode::ACCEPTED,
            Json(serde_json::to_value(started).unwrap_or(serde_json::Value::Null)),
        )),
        // The message is the product here — every refusal from `start_run` names
        // what to do about it (add a key, supply cases inline, wait for the run
        // in flight), so it is surfaced rather than swallowed into a 500.
        Err(e) => {
            let msg = format!("{e:#}");
            let status = if msg.contains("already in flight") {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_REQUEST
            };
            Err(write_err(status, msg))
        }
    }
}

/// `GET /v1/prompts/{name}/evals` — recent runs for the tenant.
#[tracing::instrument(skip(state, headers), fields(prompt_name = %name, tenant_id = tracing::field::Empty))]
async fn list_evals_handler(
    State(state): State<PromptRoutesState>,
    Path(name): Path<String>,
    Query(q): Query<HistoryQuery>,
    headers: HeaderMap,
) -> Result<Json<Vec<crate::prompt_eval::EvalRunSummary>>, (StatusCode, String)> {
    let tenant = tenant_from_auth(&headers).await?;
    tracing::Span::current().record("tenant_id", tenant.to_string());
    let _ = &name;
    let Some(engine) = state.eval.clone() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "eval runs need a ClickHouse connection and this gateway has none configured".into(),
        ));
    };
    engine
        .list_runs(&tenant, q.limit.unwrap_or(50))
        .await
        .map(Json)
        .map_err(|e| {
            tracing::error!(error = format!("{e:#}"), "eval run list failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Couldn't read eval runs — the gateway has logged the details.".into(),
            )
        })
}

/// `GET /v1/prompts/{name}/evals/{run_id}` — one run and its per-case detail.
#[tracing::instrument(skip(state, headers), fields(prompt_name = %name, tenant_id = tracing::field::Empty))]
async fn get_eval_handler(
    State(state): State<PromptRoutesState>,
    Path((name, run_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tenant = tenant_from_auth(&headers).await?;
    tracing::Span::current().record("tenant_id", tenant.to_string());
    let _ = &name;
    let Some(engine) = state.eval.clone() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "eval runs need a ClickHouse connection and this gateway has none configured".into(),
        ));
    };
    match engine.get_run(&tenant, run_id).await {
        Ok(Some(v)) => Ok(Json(v)),
        Ok(None) => Err((StatusCode::NOT_FOUND, "no such eval run".into())),
        Err(e) => {
            tracing::error!(error = format!("{e:#}"), "eval run read failed");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Couldn't read that eval run — the gateway has logged the details.".into(),
            ))
        }
    }
}

// ADR-009 Team+ write gate -------------------------------------
//
// Drives the REAL handlers (auth → entitlement gate → router) via the
// `tlane_` dev-stub auth path (debug-only: active when WORKOS_CLIENT_ID is
// unset), same harness as the audit-export gate tests. Assertions are
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
    ///
    /// ASYNC, and the tenant is resolved through the SAME `tenant_from_auth`
    /// the handlers use rather than hardcoded. The registry is keyed by
    /// `(tenant, version_id)`, so a fixture that guessed the tenant would
    /// register the version under one identity and promote it under another —
    /// and the ownership guard would (correctly) refuse. Deriving it from the
    /// fixture's own credential makes the two agree by construction.
    async fn seeded_state(
        entitlements: Option<Arc<EntitlementCache>>,
    ) -> (PromptRoutesState, Uuid) {
        let router = Arc::new(PromptRouter::new());
        let version_id = Uuid::from_u128(0xB074);
        let tenant = tenant_from_auth(&auth_headers())
            .await
            .expect("fixture credential must authenticate");
        router.register_version(
            &tenant,
            crate::prompt_router::PromptVersion {
                prompt_version_id: version_id,
                prompt_id: Uuid::from_u128(0xB074_0001),
                version_number: 1,
                content: "You are the gate-test prompt.".into(),
                model_pin: None,
                sha256: [0u8; 32],
            },
        );
        (
            PromptRoutesState {
                router,
                entitlements,
                audit_chain: Arc::new(AuditChain::new(100, None, None).unwrap()),
                // These fixtures exercise the auth/entitlement gates, which run
                // before the engine is ever consulted. `None` also asserts the
                // typed 503 path is reachable rather than a panic.
                eval: None,
            },
            version_id,
        )
    }

    /// The prompt name is a UUIDv5 input (`prompt_id_for`), a routing-key
    /// component and a URL path segment — an identifier, not free text. These
    /// assert the rejections; the acceptances below assert it is a gate rather
    /// than a wall.
    #[test]
    fn prompt_name_validation_rejects_non_identifiers() {
        for bad in [
            "",               // empty
            "has space",      // whitespace
            "slash/es",       // would split the path segment
            "unicode-\u{e9}", // non-ASCII
            "semi;colon",
            "quote'd",
            "pct%20",
            "new\nline",
        ] {
            assert!(
                validate_prompt_name(bad).is_err(),
                "{bad:?} must be refused as a prompt name"
            );
        }
        // Over the byte ceiling.
        let too_long = "a".repeat(limits::NAME_BYTES + 1);
        assert!(validate_prompt_name(&too_long).is_err());
    }

    /// Every prompt name that exists in production today must still be valid —
    /// checked against prod before choosing the charset, not assumed.
    #[test]
    fn prompt_name_validation_accepts_real_names() {
        for good in [
            "demo1",
            "cc-item3-liveproof",
            "demoprompt2",
            "demo3",
            "support_bot.v2",
            &"a".repeat(limits::NAME_BYTES),
        ] {
            validate_prompt_name(good)
                .unwrap_or_else(|e| panic!("{good:?} must be accepted, got {e:?}"));
        }
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

    /// Promote via the override path — no eval run, an explicit reason.
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

    // The "curl the paywall" attack on the write workflow: an
    // authenticated tenant WITHOUT the Team+ grant must get a typed 403 AND
    // the routing pointer must not flip (zero mutation — the end-state).
    #[test]
    fn promote_without_entitlement_gets_403_and_no_routing_mutation() {
        let _g = ENV_LOCK.lock().expect("env lock");
        let _env = DevAuthEnv::enable();
        rt().block_on(async {
            let (state, version_id) = seeded_state(Some(fixed_entitlement(false))).await;

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
            let (state, version_id) = seeded_state(Some(fixed_entitlement(true))).await;

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

    // An override reason promotes to prod WITHOUT an eval run (the normal
    // path would 409), flips the pointer, and records an attributed
    // ManualOverride — the tamper-evident record that keeps this honest.
    #[test]
    fn promote_with_override_reason_flips_and_records_actor() {
        let _g = ENV_LOCK.lock().expect("env lock");
        let _env = DevAuthEnv::enable();
        rt().block_on(async {
            let (state, version_id) = seeded_state(Some(fixed_entitlement(true))).await;

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
            let (state, version_id) = seeded_state(Some(fixed_entitlement(false))).await;
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
            let (state, version_id) = seeded_state(None).await;
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
            let (state, version_id) = seeded_state(Some(fixed_entitlement(false))).await;

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

    // ---------------------------------------------------------------
    // A8 / EVL-18 — role gate on the FOUR prompt write surfaces.
    //
    // Before this, the only gate was `require_promotion_write`, a TENANT
    // entitlement: it asks whether the workspace paid, never whether the caller
    // is allowed. A `viewer` in a Team workspace could flip the production
    // pointer. One test per surface, each driving the exact function that
    // surface calls, with real claims rather than a description of them.
    // ---------------------------------------------------------------

    fn caller(
        auth_method: crate::auth::AuthMethod,
        role: Option<crate::auth::Role>,
    ) -> crate::auth::Claims {
        crate::auth::Claims {
            tenant_id: TenantId::from_jwt_claim(uuid::Uuid::nil()),
            sub: "a8-test".into(),
            exp: u64::MAX,
            auth_method,
            role,
            // These fixtures test the ROLE gate; scope is orthogonal here.
            key_scope: crate::auth::scope::KeyScope::LegacyFullSurface,
            budget_usd_monthly: None,
            rate_limit_rpm: None,
        }
    }

    /// Same fixture, but with an explicit A13 scope set — the dimension the
    /// `caller()` fixture deliberately pins to `LegacyFullSurface`.
    fn scoped_key(scopes: &[tracelane_shared::api_scope::Scope]) -> crate::auth::Claims {
        use std::collections::BTreeSet;
        let set: BTreeSet<_> = scopes.iter().copied().collect();
        crate::auth::Claims {
            key_scope: crate::auth::scope::KeyScope::Scoped(set),
            ..caller(crate::auth::AuthMethod::ApiKey, None)
        }
    }

    /// The refusal body must be a JSON OBJECT whose machine-readable fields are
    /// directly reachable — not a JSON string nested inside `{"error": …}`.
    ///
    /// This is the assertion the existing tests could not make. They check the
    /// body with `contains()`, which passes on BOTH shapes because the substring
    /// is there either way, so a double-encoded body sailed through the suite
    /// and was only caught by a real `403` from prod. `contains()` on a
    /// serialized body is a presence check, not a shape check.
    #[test]
    fn refusal_bodies_are_objects_not_nested_json_strings() {
        use tracelane_shared::api_scope::Scope;

        // The A13 scope refusal.
        let (status, Json(body)) = {
            let e = authorize_write(&scoped_key(&[Scope::Read])).expect_err("must refuse");
            write_err(e.0, e.1)
        };
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            body.get("required_scope").and_then(|v| v.as_str()),
            Some("admin"),
            "required_scope must be readable as `body.required_scope`, not escaped \
             inside a string; got body = {body}"
        );
        assert_eq!(
            body.get("type").and_then(|v| v.as_str()),
            Some("insufficient_scope")
        );

        // The pre-existing ROLE refusal had the same defect.
        let (_, Json(role_body)) = write_err(
            StatusCode::FORBIDDEN,
            crate::auth::role_forbidden_json("owner"),
        );
        assert_eq!(
            role_body.get("required_role").and_then(|v| v.as_str()),
            Some("owner"),
            "role_forbidden_json is also an object and must pass through intact"
        );

        // ...and a PLAIN message must still be wrapped, or every ordinary error
        // loses its envelope.
        let (_, Json(plain)) = write_err(StatusCode::BAD_REQUEST, "content must not be empty");
        assert_eq!(
            plain.get("error").and_then(|v| v.as_str()),
            Some("content must not be empty")
        );
    }

    /// THE SCOPE GATE MUST BLOCK. A `read`-scoped key is the credential
    /// `api_scope.rs:47-49` says to hand an external auditor "and nothing
    /// else"; before this gate it could promote to production, because
    /// `can_write_prompts()` matches the `role: None` arm for any API key
    /// without ever reading `key_scope`.
    #[test]
    fn read_scoped_key_cannot_write_prompts() {
        use tracelane_shared::api_scope::Scope;
        let err = authorize_write(&scoped_key(&[Scope::Read]))
            .expect_err("a read-scoped auditor key must NOT be able to write prompts");
        assert_eq!(err.0, StatusCode::FORBIDDEN);
        assert!(
            err.1.contains("insufficient_scope") && err.1.contains("admin"),
            "the refusal must name the missing scope so it is actionable, got: {}",
            err.1
        );
    }

    /// The default mint set is `[chat, read, ingest]` — a RUNTIME credential.
    /// It must not manage workspace configuration either. Measured against prod
    /// before choosing this: 3 live keys carry exactly this set.
    #[test]
    fn default_mint_set_key_cannot_write_prompts() {
        use tracelane_shared::api_scope::Scope;
        for s in tracelane_shared::api_scope::Scope::default_mint_set() {
            assert_ne!(s, Scope::Admin, "default mint set must not include admin");
        }
        assert!(
            authorize_write(&scoped_key(&Scope::default_mint_set())).is_err(),
            "a chat+read+ingest key must not be able to flip production routing"
        );
    }

    /// ...and the gate must OPEN for the scope that is meant to pass, or it is
    /// a wall rather than a gate.
    #[test]
    fn admin_scoped_key_can_write_prompts() {
        use tracelane_shared::api_scope::Scope;
        authorize_write(&scoped_key(&[Scope::Admin]))
            .expect("an admin-scoped key is exactly who may manage prompts");
    }

    /// NO REGRESSION FOR EXISTING CUSTOMERS. 12 live prod keys are
    /// `scope IS NULL` and every JWT dashboard session is also
    /// `LegacyFullSurface`; both must keep working unchanged.
    #[test]
    fn legacy_and_jwt_callers_are_unaffected_by_the_scope_gate() {
        use crate::auth::{AuthMethod, Role};
        authorize_write(&caller(AuthMethod::ApiKey, None))
            .expect("legacy NULL-scope key must keep working");
        authorize_write(&caller(AuthMethod::JwtBearer, Some(Role::Owner)))
            .expect("an owner dashboard session must keep working");
    }

    /// The READ surfaces are gated too: an `ingest`-scoped SDK key, which ships
    /// inside a customer's container image, must not be able to read prompt
    /// CONTENT. Exercised through the same predicate the read handlers use.
    #[test]
    fn ingest_scoped_key_is_refused_the_read_scope() {
        use tracelane_shared::api_scope::Scope;
        let ingest_only = scoped_key(&[Scope::Ingest]);
        assert!(
            !ingest_only.allows_scope(crate::auth::scope::Scope::Read),
            "an ingest-only key must not satisfy the read scope that \
             tenant_from_auth now requires"
        );
        let reader = scoped_key(&[Scope::Read]);
        assert!(reader.allows_scope(crate::auth::scope::Scope::Read));
    }

    /// Named per surface so a failure says WHICH write path regressed.
    fn assert_surface_gate(surface: &str) {
        use crate::auth::{AuthMethod, Role};

        // DENIED — the finding: a viewer could write.
        let viewer = caller(AuthMethod::JwtBearer, Some(Role::Viewer));
        let err = authorize_write(&viewer).expect_err(&format!(
            "{surface}: a VIEWER must not be able to write prompts"
        ));
        assert_eq!(err.0, StatusCode::FORBIDDEN);
        assert!(
            err.1.contains("role_forbidden"),
            "{surface}: a denial must be typed role_forbidden, not a generic failure —              a caller that cannot tell 'not allowed' from 'broken' retries forever"
        );

        // DENIED — member too, per the ruling.
        assert!(
            authorize_write(&caller(AuthMethod::JwtBearer, Some(Role::Member))).is_err(),
            "{surface}: a MEMBER must not be able to write prompts"
        );

        // DENIED — PL-9: an absent/unrecognised slug on a HUMAN token fails closed.
        assert!(
            authorize_write(&caller(AuthMethod::JwtBearer, None)).is_err(),
            "{surface}: a JWT with no recognised role must fail CLOSED (PL-9)"
        );

        // ADMITTED — the automation path. PL-9b demoted API keys out of admin, so
        // gating on can_admin would have silently broken CI-driven promotion.
        authorize_write(&caller(AuthMethod::ApiKey, None))
            .unwrap_or_else(|e| panic!("{surface}: an API KEY must still write prompts: {e:?}"));

        // ADMITTED — owner (and WorkOS `admin`, which maps to Owner).
        authorize_write(&caller(AuthMethod::JwtBearer, Some(Role::Owner)))
            .unwrap_or_else(|e| panic!("{surface}: an OWNER must be able to write prompts: {e:?}"));
    }

    #[test]
    fn create_version_denies_viewer_admits_api_key() {
        assert_surface_gate("create_version");
    }

    #[test]
    fn promote_denies_viewer_admits_api_key() {
        assert_surface_gate("promote");
    }

    #[test]
    fn delete_denies_viewer_admits_api_key() {
        assert_surface_gate("delete");
    }

    /// The fourth write surface, which the finding did not name — `rollback`
    /// flips the production pointer exactly as `promote` does.
    #[test]
    fn rollback_denies_viewer_admits_api_key() {
        assert_surface_gate("rollback");
    }

    /// STRUCTURAL: every write handler must reach the gate. Four near-identical
    /// behavioural tests prove today's handlers; this proves the NEXT one cannot
    /// quietly skip it — which is how `create_version` and `delete` ended up
    /// inlining their own auth and missing the check in the first place.
    #[test]
    fn every_write_handler_routes_through_the_single_gate() {
        let src = include_str!("prompt_routes.rs");
        for handler in [
            "async fn create_version_handler",
            "async fn promote_handler",
            "async fn delete_handler",
            "async fn rollback_handler",
        ] {
            let start = src
                .find(handler)
                .unwrap_or_else(|| panic!("{handler} not found"));
            // Body up to the next top-level `async fn`, or EOF.
            let rest = &src[start + handler.len()..];
            let end = rest.find("\nasync fn").unwrap_or(rest.len());
            let body = &rest[..end];
            assert!(
                body.contains("actor_from_auth("),
                "{handler} does not call actor_from_auth — it is a prompt WRITE surface                  with no role gate. Route it through the single site."
            );
        }
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
            let (state, version_id) = seeded_state(Some(fixed_entitlement(false))).await;
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
                    None,
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
